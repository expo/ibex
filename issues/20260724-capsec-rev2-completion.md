# Complete CapSec revision 2 and critical security features

**Status:** In Progress
**Severity:** P1
**Systems:** Security, Policy, Runtime, Engine, Host ABI, Module Loader, Build, CLI, CI
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0013, LLP 0014, LLP 0016, LLP 0021, LLP 0023, LLP 0039

Complete the CapSec revision-2 program defined by LLP 0021, prioritizing
security-critical enforcement gaps over catalog-only cleanup while retaining
the plan's exact-target conformance and legacy-retirement completion gates.
Work happens on branch `codex/capsec-rev2-completion` in the dedicated
`ibex-capsec-rev2` worktree. Because other work is landing concurrently, the
branch must regularly reconcile with the moving `main` branch at clean
milestones.

## Completion evidence

The authoritative completion audit is LLP 0021's eight completion criteria,
not the absence of TODOs or a narrow passing test. For every criterion, record
the current proving artifact or the remaining contradiction here before this
ticket closes.

## Milestone log

### 2026-07-24 — resumed and established an isolated completion worktree

- Created `/Users/ccheever/projects/ibex-capsec-rev2` on
  `codex/capsec-rev2-completion` from `main` at `86df42ba`.
- Read the root LLP and used `llp-orient` to identify LLP 0021 as the canonical
  revision-2 program, with LLP 0013/0014/0023/0039 as governing siblings.
- Confirmed the typed semantics, canonical-policy v2, arming ABI v2, legacy
  retirement map, and secure-mode rot guard exist.
- Confirmed completion is not yet proved: LLP 0021 remains Draft, the latest
  recorded exact-target report is intentionally incomplete, and multiple
  filesystem, network, audit-admission, bootstrap-floor, target-promotion, and
  legacy-window items remain open.
- Initial estimate: **45% complete for the full LLP 0021 completion contract;
  roughly 70% complete for the security-critical runtime mechanism set.**
  The difference is dominated by exact-target physical conformance,
  advertisements, residual public-surface evidence, and legacy-plane/window
  retirement.

### 2026-07-24 — closed prepared-graph backing-path disclosure (ENG-25424)

- Removed physical source paths from the canonical prepared-graph index. This
  brings the Rust publisher back into agreement with the existing strict v1/v2
  schemas, which already disallowed the extra `path` field.
- Carried the Host-authenticated VFS `SourceLabel` and virtual path through
  source and prepared graphs into native Hermes metadata. File modules expose
  only `file:///project/...` and `/project/...`; builtins expose no virtual
  filesystem path.
- Extended the regression to assert that neither native execution inputs nor
  serialized prepared artifacts contain the private fixture root.
- The newly reachable tail of that regression exposed a second trust-boundary
  defect: an attacker could replace executable carrier bytes and recompute the
  carrier manifest/index digests self-consistently. Writable-cache admission
  now reconstructs the deterministic per-principal publication from the
  independently authenticated inline graph and requires exact manifest,
  carrier-byte, record-artifact, entry, and carrier-index equality. The forged
  cache is refused even when every attacker-controlled digest agrees.
- Preserved the separate production refusal for authored call-time dynamic
  imports. Candidate tables exist, but eager link-time authorization is not a
  substitute for LLP 0026's invocation-time activation; the regression now
  proves this graph remains closed until that capability exists.
- Removed the only test exclusion from `scripts/check-secure-mode.sh` and
  reconciled LLP 0039's description of the gate.
- Test environment note: the isolated worktree does not contain the untracked
  Hermes framework/compiler cache. Tests use explicit read-only paths into the
  primary checkout's `ios/Frameworks` artifacts. Fleet validation stages the
  compiler at its standard repository-relative test path; making the test read
  a new process environment variable would itself add an unclassified startup
  surface to the generated CapSec registry.
- Verification: `./ref-check` passes (37 LLPs, 2,016 checked refs); the complete
  secure-mode gate passes with 629 library tests passed, 3 hosted/diagnostic
  tests intentionally ignored, and the behavioral denial smoke reporting every
  expected boundary as enforced.
- Estimate after this milestone: **47% complete for the full LLP 0021
  completion contract; roughly 74% complete for the security-critical runtime
  mechanism set.**

### 2026-07-24 — wired cold dependency reads through CapSec graph receipts

- Split production native-graph metadata resolution from executable-source
  acquisition. An authored dependency now yields an exact target identity
  before its source bytes can be read.
- The graph authorizer validates the exact request, target, resolution kind,
  conditions, attributes, principals, snapshot generations, and graph
  generation before entering the Host source-acquisition closure.
- Cold reads finalize their digest-bound `SourceAcquisition` receipt from the
  authenticated bytes and revalidate that receipt before releasing the loaded
  module to the producer. Receipts remain retained for the graph lifetime.
- The six-record source/prepared regression retains five dependency-access
  receipts; the entry is governed by its separate authenticated launch request.
  A denied-edge fixture proves the source closure is never entered.
- Scope remains honest: cache-hit and prepared-carrier reads are not yet wired
  through their corresponding access receipts, although the prepared cache now
  has exact deterministic byte equality from the prior milestone.
- Estimate after this milestone: **49% complete for the full LLP 0021
  completion contract; roughly 76% complete for the security-critical runtime
  mechanism set.**

### 2026-07-24 — reconciled the target-advertisement program from moving main

- Observed `main` advance from `86df42ba` to `f85443a3` while the source-access
  slice was in progress. Checkpointed the slice and rebased both security
  milestones cleanly onto the new tip.
- The landed LLP 0036/0037 program closes producer attestation, accepts the six
  gate-1 residual output rows by author decision, and reclassifies 3,727
  internal-invariant recipes under a separately auditable
  `internally-verified` disposition.
- No target is advertised yet. On Apple, gate 2 still has 18,266 reachable
  unresolved recipe rows after the reclassification (2,592 fully executable
  in the measured catalog); the new plan correctly frames the remainder as
  thousands of distinct public invocation shapes, not a cheap bulk-labeling
  exercise.
- Current rebased commits are `72a3b154` (prepared publication) and `d8380b9b`
  (source acquisition) on `codex/capsec-rev2-completion`.
- Reconciled estimate: **52% complete for the full LLP 0021 completion
  contract; roughly 76% complete for the security-critical runtime mechanism
  set.** The full-contract increase reflects landed promotion machinery and
  governed recipe-family authoring, not target promotion.

### 2026-07-24 — fleet-validated the rebased security milestones

- Staged the rebased worktree plus the exact Hermes framework/compiler inputs
  on the M4 fleet host (`100.106.94.95`). The advertised M5 host
  (`100.88.75.121`) currently refuses its documented SSH key, so it could not
  be used.
- The first M4 run found two diagnostic subprocess-transpiler failures because
  that host's `node` resolves to a deliberately non-invocable Volta shim. After
  placing the host's real Bun binary first in `PATH`, both race tests passed.
- The complete secure-mode gate then passed on the rebased source: 629 library
  tests passed, 3 hosted/diagnostic tests remained intentionally ignored, and
  the project-read/outside-read/outside-write/spawn/environment behavioral
  probes all reported the expected enforced outcomes.

### 2026-07-24 — receipt-gated prepared dependency carriers

- A retained `SourceAcquisition` receipt can now continue only into a
  `PreparedCarrierRead` for the same exact target and source integrity. The new
  receipt additionally binds the deterministic carrier digest, graph
  generation, snapshot digest, and all authority generations.
- Prepared dependency manifest/payload bytes are read only inside the
  revalidated carrier receipt closure, and the prepared graph retains the new
  receipt for its lifetime. A mismatch refuses before the access closure is
  entered.
- A carrier with no dependency receipt is admissible only if it contains the
  launch entry. That is not treated as an import edge: production prepared
  selection already follows the exact structured entry-request join.
- Armed transpilation is fresh and in-memory, so there is no persistent
  transpile-cache hit requiring a `CacheRead` receipt. The operation remains in
  the closed graph algebra for any future cache-bearing path.
- Verification: the focused prepared-cache regression passed on the M4,
  including forged-publication refusal and the retained carrier-receipt count.
  The M4's 228 GiB temporary volume then reached 100% while rebuilding the
  complete native archive; its exact 7.0 GiB disposable worktree `target/` was
  removed, restoring that space. The final local secure-mode gate passed with
  630 library tests, 3 intentional ignores, and every behavioral denial probe
  enforced. The generated CapSec registry check and `ref-check` also pass.
- Current estimate: **53% complete for the full LLP 0021 completion contract;
  roughly 78% complete for the security-critical runtime mechanism set.**

### 2026-07-24 — made the launch-entry join a required cache credential

- Replaced the prepared loader's prose-only dependency on production call
  ordering with an opaque `AuthenticatedEntryJoinV1`. The only production
  constructor is the complete structured-request/source-graph validation
  boundary.
- The join binds the entry's module and VFS identities, source integrity,
  snapshot digest, and producer digest after the request has also proved file
  ingress, defining principal, source goal, dialect, entry role, and main-entry
  status.
- Every prepared-cache load now requires that join and revalidates it against
  the current graph before reading `index.json`. A deliberately mismatched join
  against a nonexistent cache returns the join refusal rather than an I/O
  error, proving the no-probe ordering.
- The ordinary runtime and the source-bound conformance runner now carry the
  join explicitly into prepared selection. Test-only direct publisher fixtures
  use a separately named `cfg(test)` constructor; production builds cannot
  manufacture it.
- The authenticated-ingress registry now requires both join minting and
  pre-read consumption evidence. Registry, CapSec contract, runtime projection,
  LLP reference, and diff-hygiene checks pass; the registry digest rotation's
  canonical fixtures were regenerated and validated.
- The full secure-mode gate passes: the secure build compiles, all 630 library
  tests pass (3 ignored), and the behavioral smoke confirms project read plus
  outside-read/write, spawn, and environment-sentinel enforcement.
- Current estimate: **54% complete for the full LLP 0021 completion contract;
  roughly 79% complete for the security-critical runtime mechanism set.**

### 2026-07-24 — removed insecure mode from conformance evidence execution

- Found that every CapSec recipe/adapter/public-surface Cargo executor still
  inherited Cargo's default feature set after LLP 0039 added `insecure` to that
  set. The commands were therefore bypassing the production decision plane
  while naming their output as promotion evidence.
- Centralized the promotion-facing Rust command as
  `cargo test --bin ibex --no-default-features --features
  standard,capsec-conformance-observer,openssl-crypto ...` and migrated the
  recipe templates, direct batch commands, runner-local engine invocation, and
  inherited-intrinsic execution plan.
- Added both descriptor-wide and generated-catalog regressions requiring
  `--no-default-features`, the exact production observer feature set, and no
  `insecure` feature. Focused devtools verification passes 110 tests.
- Generated a fresh 24,613-row Apple recipe catalog and ran the callback
  mechanism smoke under the explicit secure observer profile. That exposed a
  real ordering defect hidden by the insecure bypass: a diagnostic submission
  installed the runtime-owned `$_` root before the one-shot Exact endowment,
  so secure root-disposition authorization rejected the endowment. The harness
  now installs the authenticated endowment before its first session
  submission, and the complete mechanism smoke passes.
- The full callback batch now fails at the honest next boundary: the generator
  supplies eight exact public mechanisms while stale internal bookkeeping
  expects 2,800 callback rows. This is not treated as a failure of the secure
  command slice or converted into synthetic evidence.
- Current estimate: **55% complete for the full LLP 0021 completion contract;
  roughly 81% complete for the security-critical runtime mechanism set.**

### 2026-07-24 — replaced internal-invariant labels with executed proof

- Audited the seven scenarios LLP 0036 had provisionally reclassified. Six have
  exact Rust enforcement mechanisms. `malformed-branch-facts` has none and is
  now unresolved rather than receiving catalog-only credit.
- Replaced the broad recipe-status predicate with a closed six-scenario
  vocabulary. Every internal recipe carries a digest-bound proof plan naming
  the exact mechanism, Rust source location, dedicated executor, and explicit
  secure Cargo command.
- Removed the report's `internally-verified` auto-credit. The new
  `capsec_internal_invariant_evidence_batch` executes all six mechanisms under
  the secure observer profile, records one runtime observation per
  scenario-class, and expands it into exact fixture-plan/binding/result
  evidence for every credited row. The report validates that evidence through a
  dedicated fail-closed path; a label without execution stays missing.
- Corrected the public callback batch to its actual eight authored public
  mechanisms. Internal scenarios no longer leak into public callback
  bookkeeping.
- Corrected portable recipe/public projection: internal rows retain their
  dedicated executor and are excluded from public-surface execution instead of
  being forced through a nonexistent public probe.
- Ran the committed secure internal batch against the reviewed Apple
  `hermesvm`: all six mechanisms executed, the Rust producer emitted all 3,068
  exact fixture records in 36.73 seconds, and the independent JavaScript
  validator accepted their bindings, plans, scenario membership, markers, and
  digests. The 37 MB evidence artifact and 146 MB recipe catalog remained
  temporary evidence outside the repository.
- Added the portable mapped-process producer for the internal executor. It uses
  a distinct internal plan schema, re-executes the six mechanisms inside the
  mapped observation, emits one detached portable artifact per internal row,
  and joins that process into the sole Phase-2 bundle validator. While testing
  this path, corrected both Rust portable-plan parsers to bind the
  conformance-runner identity already included by the JavaScript execution
  digest.
- The physical-promotion workflow test exposed a pre-existing profile split:
  the checked all-target Cargo set expanded `default` into `insecure`, while
  the workflow spelled a different default-enabled vector. The generator,
  checked catalog, and workflow now use one exact
  `--no-default-features` vector whose active feature closure excludes both
  `default` and `insecure`; focused post-link and ceremony tests pass.
- Current catalog measurements: Apple 2,602 fully executable, 3,068 internally
  verified, and 18,945 unresolved of 24,615; Windows 2,236 / 3,056 / 19,208 of
  24,500. The new binding/output environment controls add two honestly
  classified non-capability rows per target.
- Verification so far: 165 focused devtools tests pass; the CapSec contract
  validates all 26 schemas and 7,587 coverage edges; the secure Rust evidence
  target compiles and links against the reviewed `hermesvm` profile; the
  focused portable promotion/contract slice passes 118 tests and 111,009
  expectations. After refreshing the source-derived registry and embedded
  fingerprints, the complete secure-mode gate passes: secure compile, 630
  library tests (3 ignored), and the behavioral enforcement smoke. The exact
  physical-promotion all-target vector also compiles successfully with Cargo
  defaults disabled and no `insecure` feature.
- Current estimate: **57% complete for the full LLP 0021 completion contract;
  roughly 84% complete for the security-critical runtime mechanism set.**

### 2026-07-24 — moved authored call-time refusal ahead of target discovery

- LLP orientation reconciled the production graph with LLP 0024's dead-branch
  rule and LLP 0026's invocation-time dynamic-edge contract. The existing
  site-specific native tables prove exact selection only after a target record
  exists; they do not supply call-time policy, resolution, source acquisition,
  transformation, or linking.
- Found that the native linker guard ran only after source-graph construction
  had resolved and receipt-acquired every literal dynamic target and computed
  candidate. This could probe or read a dead target even though production
  would later refuse the graph.
- Added the same fail-closed boundary immediately after authoritative parsing
  of each requester and before any authored target resolution or source
  acquisition. Authored CommonJS `require()` receives the same ordering;
  generated exact builtin-to-builtin initialization fan-out remains the sole
  exception and is revalidated by the linker.
- Added a regression whose dead literal `import()` and `require()` point to
  absent sentinel targets. Both produce the activation refusal without target
  resolution output. The independent linker test continues to prove every
  authenticated native entry refuses before policy authorization.
- Reconciled the stale completed candidate-runtime ticket and LLP 0026's
  implementation-state prose. The full private, nonce/generation-bound,
  reentrant-safe in-drive activation design is now an explicit P1 filesystem
  issue rather than an implied property of eager lookup tables.
- Converted the prepared-cache security regression back to a four-record
  static closure. It continues to prove private-path suppression, complete
  prepared round-trip, native linking, receipt-gated carrier access, and
  self-consistent forged-cache refusal without depending on a deliberately
  unsupported dynamic edge.
- Verification: both call-time boundary tests and the prepared-cache
  round-trip pass. The complete secure-mode gate passes against the reviewed
  current Hermes framework, including its behavioral enforcement smoke
  (`project_read`, outside-read denial, outside-write denial, spawn denial,
  and environment-sentinel hiding). `ref-check` reports 39 LLP documents,
  2,039 checked references, zero errors, and one intentionally unchecked
  external reference.
- Current estimate: **57% complete for the full LLP 0021 completion contract;
  roughly 85% complete for the security-critical runtime mechanism set.**
  This closes a real no-probe defect but does not claim the larger activation
  feature complete.

### 2026-07-24 — established a post-drive dynamic-import activation mailbox

- Rejected same-stack Rust re-entry for `import()`: the native callback now
  mints only a fresh Promise and a private reached-site request, which Rust
  takes after the current JSI drive unwinds. This preserves the runtime's
  reentrancy guard while keeping dead branches completely outside resolution
  and acquisition.
- Added typed, length-bearing request transfer and one-shot completion across
  the public C ABI and safe Rust wrapper. Requests bind the runtime nonce,
  graph generation, exact requester record/source identity, literal versus
  computed site, and exact spelling.
- Added exact deferred tables for ESM and CommonJS `import()`. Absent literal
  spellings and absent `(site, spelling)` computed candidates reject inside
  Hermes without a mailbox or resolver probe. Concurrent reached imports mint
  distinct public Promises but can complete onto one target record and its
  stable internal evaluation Promise.
- Added an explicit deferred mode to the static graph plan and authenticated
  synchronous linker. It validates and authorizes the complete static closure,
  installs exact deferred declarations, and neither represents nor
  materializes a dynamic target.
- Focused real-Hermes tests prove dead-branch and candidate-miss no-probe,
  wrong-generation isolation, repeated/concurrent calls, one-shot
  completion/refusal, an authenticated target-absent initial graph, and the
  equivalent reached-site mailbox for CommonJS `import()`.
- Verification: `ref-check` passes with 39 LLP documents and 2,043 checked
  references. The complete secure-mode gate passes against the reviewed
  current Hermes framework: 634 library tests pass, 3 hosted/diagnostic tests
  remain intentionally ignored, and the behavioral smoke confirms project
  read plus outside-read/write, spawn, and environment-sentinel enforcement.
- This is intentionally a foundation checkpoint, not production activation:
  source-graph declaration ingestion, reached-edge authorization and
  receipt-bound acquisition, atomic incremental graph publication, async and
  prepared integration, teardown coverage, and synchronous authored
  CommonJS `require()` remain open.
- Current estimate remains **57% complete for the full LLP 0021 completion
  contract; roughly 85% complete for the security-critical runtime mechanism
  set.** The new private mechanism is substantial, but the fail-closed
  production ingress cannot be relaxed until the end-to-end bridge exists.

### 2026-07-24 — connected reached imports to receipt-authorized live graphs

- Authenticated source-graph construction now retains literal import
  attributes and exact computed-site declarations without resolving,
  acquiring, or reading any dynamic target. Authored synchronous CommonJS
  `require()` remains refused before target discovery.
- A reached ESM or CommonJS `import()` request authorizes its exact edge, uses
  that receipt to acquire only the target's static closure, and validates the
  expanded source plan before committing it.
- Native activation reuses existing record identities, stages and fully links
  only new records, then atomically publishes the complete batch. Failed
  partial batches can be discarded even while the graph generation is pinned.
- Synchronous and TLA graphs both support incremental publication. A prepared
  initial graph may add an inline reached target without probing a carrier or
  cache index before invocation.
- Foreground settlement retains the authenticated source graph and an opaque
  native record index for later timers and keep-alive ticks. Mailbox routing
  matches the exact requester handle, preventing equal source identities in
  different native graph incarnations from sharing activation authority.
- Focused verification passes for dead-target no-discovery, receipt-gated
  source-closure growth, synchronous and TLA publication, exact requester
  routing, generation teardown in both completion orderings, closed-window
  CommonJS refusal, and delayed ESM/CommonJS imports that settle after ordinary
  program quiescence.
- The complete secure-mode gate passes against the reviewed Hermes framework:
  637 library tests pass, 3 hosted/diagnostic tests remain intentionally
  ignored, and the behavioral smoke enforces project read plus outside-read,
  outside-write, spawn, and environment-sentinel boundaries. `ref-check`
  reports 39 LLP documents, 2,048 checked references, zero errors, and one
  intentionally unchecked external reference.
- Current estimate: **59% complete for the full LLP 0021 completion contract;
  roughly 87% complete for the security-critical runtime mechanism set.**
  Invocation-time prepared carriers, synchronous authored CommonJS
  `require()`, deeper activation failure matrices, and the larger exact-target
  evidence program remain open.

## Current hard parts

- Exact-target completion is deliberately all-or-nothing. Existing evidence
  must not be promoted from partial or diagnostic runs.
- The production surface is large; generated residual counts must be reduced
  through real source-bound executions or honest closure, never hand-labelled
  as passing.
- `main` is moving as old worktrees are landed, so generated CapSec artifacts
  and source-review identities can rotate during this effort.
- The default build is intentionally insecure per LLP 0039 while the secure
  feature is separately guarded; LLP 0021's original plain-execution wording
  needs a completion interpretation consistent with that later decision.
- Rich conformance now consumes executed internal-invariant proof, but portable
  promotion now has a distinct mapped-process producer for the dedicated
  internal executor and joins detached per-row artifacts through the Phase-2
  bundle validator. Physical execution remains pending an exact-revision
  portable engine artifact; the reviewed local framework reports no portable
  identity, so it cannot honestly produce that evidence.
- `malformed-branch-facts` has no owning-language proof and remains residual.
- Authored `import()` now has receipt-gated reached-site source activation and
  atomic live-graph publication. The remaining call-time module gap is the
  synchronous in-drive CommonJS `require()` capability, plus invocation-time
  prepared carriers and deeper failure-matrix coverage, tracked in
  `issues/20260724-native-call-time-module-activation.md`.
- The root/bootstrap mechanism seals correctly, but both builders still emit an
  empty `bootstrapAuthorityFloor`. Current bootstrap host inputs are
  authenticated projections consumed under the transparent runtime principal,
  so there is no evidenced root effect from which to derive a nonempty floor.
  Populating one by guess would add authority rather than close a gap. This
  needs either a named root-attributed bootstrap operation or a revised
  requirement before the requested real retained-callback fixture is honest.

## Next milestone

Run the full secure-mode gate and checkpoint the receipt-authorized live-graph
activation slice. Then address invocation-time prepared activation and the
synchronous CommonJS `require()` callback. Bootstrap-floor authorship and
`malformed-branch-facts` remain named gaps rather than unsafe local
substitutions.
