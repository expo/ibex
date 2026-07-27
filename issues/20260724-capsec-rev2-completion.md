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
- Additional production-ingress regressions pass for nested TLA imports,
  reached resolution failure isolated to its public Promise, and atomic
  publication/evaluation of a newly discovered static cycle. A declared
  computed site acquires only its chosen spelling, while an otherwise
  resolvable package with no authenticated dynamic-import edge rejects only
  the reached Promise and is never evaluated.
- The complete secure-mode gate passes against the reviewed Hermes framework:
  637 library tests pass, 3 hosted/diagnostic tests remain intentionally
  ignored, and the behavioral smoke enforces project read plus outside-read,
  outside-write, spawn, and environment-sentinel boundaries. `ref-check`
  reports 39 LLP documents, 2,048 checked references, zero errors, and one
  intentionally unchecked external reference.
- Current estimate: **59% complete for the full LLP 0021 completion contract;
  roughly 87% complete for the security-critical runtime mechanism set.**
  Invocation-time prepared carriers, synchronous authored CommonJS
  `require()`, and the larger exact-target evidence program remain open. The
  stronger activation matrix closes evidence gaps without inflating the
  mechanism estimate.

### 2026-07-24 — proved the synchronous literal-`require()` activation boundary

- Authenticated source construction now retains authored non-builtin literal
  `require()` spellings without resolving or reading their targets. Generated
  manifest-builtin fan-out remains eager and cannot enter the deferred path.
- Reaching an exact retained spelling authorizes and receipt-gates acquisition
  of only its target's static closure. Nested dead `require()` declarations
  remain deferred, and an undeclared spelling fails before resolver entry.
- Added a generation-scoped native provider token and exact requester
  handle/source/spelling callback. During the callback, only module
  construction, linking, declaration, rollback, and atomic publication may
  nest; public eval and the rest of the runtime drive surface remain
  reentrancy-closed.
- A real-Hermes ABI regression publishes a new CommonJS record inside the
  reached callback, evaluates it exactly once, and proves a second identical
  `require()` reuses the cached target binding. An attempted general `eval`
  from the callback is still refused as reentrant.
- This is a mechanism checkpoint, not production completion. The retained
  source/native graph state still needs to own the provider context before
  initial evaluation, and the provider must drive the real authorization,
  acquisition, transform, link, synchronous-closure, denial, and teardown
  paths.
- `main` remained at `f85443a3` at this checkpoint despite the expected
  concurrent branch landings.
- Current estimate remains **59% complete for the full LLP 0021 completion
  contract; roughly 87% complete for the security-critical runtime mechanism
  set.** The ABI proof removes the reentrancy uncertainty but does not count as
  a shipped security mechanism until production graph state owns it.

### 2026-07-24 — shipped synchronous `require()` activation in production

- Retained production graph state now owns the generation-scoped provider
  before any module body executes and mutates the same published native record
  index used by dynamic activation.
- Literal CommonJS `require()` validates the exact requester handle, source
  identity, generation, and retained spelling; authorizes before acquisition;
  receipt-acquires only the reached target's static closure; and publishes it
  atomically inside the existing runtime drive.
- Production tests cover CJS→CJS caching, CJS→synchronous ESM plus its static
  closure, and `ERR_REQUIRE_ASYNC_MODULE` before any target body or record is
  published.
- Failed synchronous and asynchronous activations now roll source-graph
  records, principals, matched candidates, and retained receipts back to their
  pre-request checkpoint. Native staging was already atomic, so failure leaves
  neither a require cache binding nor reusable graph authority.
- Reached `node:fs` exposed a latent eager-runner defect: generated builtin
  source references bootstrap-owned objects such as
  `internal/test/binding`, which are intentionally absent from the public
  manifest resolver. The generated bootstrap-internal list now produces a
  distinct private edge with no ModuleRecord target. Startup captures its
  resolver in native state and seals the temporary global before package
  execution; authored modules cannot enter this path.
- Both reached CJS→`node:fs` VFS execution and the existing eager ESM→`node:fs`
  callback-only TLA regression pass. A closed compatibility window now retains
  dead `import()` and literal `require()` as native call-time declarations.
- The generated gates found two review defects that narrower runtime tests did
  not expose. The temporary bootstrap-object capture hook was initially
  classified as a reachable root; it is now a named
  `trusted-module-loader` private consumer whose required armed disposition is
  absent. The new provider/disposer ABI was initially incomplete in the
  output-shape inventory; its callback directions, opaque handle schema, and
  aggregate disposal contract are now source-derived with no new unresolved
  host-ABI rows.
- CapSec generation now accounts for 7,602 coverage edges, 7,822 enforcement
  branches, 15,204 target cells, 13,331 source references, and 222 reviewed
  host-task ingress sites. The complete generated-drift chain and all focused
  coverage, surface-inventory, output-disposition, root-disposition, and
  host-task tests pass after the reviewed count/digest rotation.
- Verification also passes for 639 library tests with 3 intentional ignores,
  the six production `authenticated_commonjs_require_` integrations, five
  retained activation/rollback tests, the exact retained-import test,
  `cargo check` for the module-runner binary, `ref-check`, and diff hygiene.
- `main` remains at `f85443a3` while this production checkpoint is prepared.
- Current estimate: **61% complete for the full LLP 0021 completion contract;
  roughly 89% complete for the security-critical runtime mechanism set.**
  Invocation-time prepared activation and the broad cross-kind/failure matrix
  remain before this mechanism slice can be called complete.

### 2026-07-25 — closed the synchronous source-path activation matrix

- Nine production CommonJS `require()` integrations now cover exact CJS and
  synchronous ESM activation, VFS-backed builtins, async-taint refusal,
  CommonJS partial-export cycles, CJS→ESM→CJS cycle refusal, package-policy
  denial, failure/retry isolation, and bootstrap-internal denial.
- The mixed cycle fixture exposed a real native lifecycle defect: an ESM
  execute function remained `declared` while authored code was on its stack,
  and synchronous ESM closure evaluation treated a newly published CommonJS
  adapter as an ordinary executable ESM record. Execution now publishes
  `evaluating` before entering authored code, evaluates adapters through their
  CommonJS owners, and reports `ERR_REQUIRE_CYCLE_MODULE` on adapter re-entry.
- A prepared initial CommonJS carrier now runs end to end and activates its
  reached target as a fresh inline record without discovering that target
  while selecting the prepared entry.
- Owner-thread shutdown now clears retained provider registrations before
  destroying the native runtime. The native-provider regression drops and
  reinstalls the same generation token, proving the callback entry and borrowed
  bridge were removed before unpin.
- Focused verification passes for all 9 production `authenticated_commonjs_require_`
  tests, the prepared-initial activation test, and the native provider
  publication/teardown test.
- Current estimate: **62% complete for the full LLP 0021 completion contract;
  roughly 90% complete for the security-critical runtime mechanism set.**
  Invocation-time prepared-carrier discovery is now the remaining activation
  mechanism rather than an unbounded source-path state-machine gap.

### 2026-07-25 — completed invocation-time prepared activation

- Added an index-free prepared form for call-time activation. Each newly
  authenticated record derives its immutable carrier path directly from the
  exact `SourceId` and semantic digest beneath the selected deployment cache;
  there is no activation index to inspect early.
- The source graph retains an opaque cache-locator capability, but invokes it
  only after an exact reached edge has authorized and receipt-acquired its
  target closure. Undeclared ESM and CommonJS spellings return before resolver,
  filesystem, locator, or carrier access.
- Each carrier read derives `PreparedCarrierRead` from the matching record's
  retained source-acquisition receipt. The graph stages every member before
  changing any record to prepared, so cache absence, denial, stale identity, or
  malformed bytes leave the entire reached closure inline.
- Focused library fixtures cover literal ESM import, authored CommonJS require,
  zero-probe spelling misses, exact hits, retained receipts, repeated-binding
  no-reprobe, and atomic fallback for a two-record closure with one tampered
  carrier.
- The authenticated production fixture now begins with a prepared CommonJS
  entry, reaches its deferred `require()`, discovers the deployment cache once,
  publishes the prepared target into the live generation, and evaluates it
  successfully.
- The complete secure-mode gate passes: 642 library tests pass, 3 hosted or
  diagnostic tests remain intentionally ignored, and project read,
  outside-read/write, spawn, and environment-sentinel probes all report the
  expected enforced result.
- Current estimate: **64% complete for the full LLP 0021 completion contract;
  roughly 92% complete for the security-critical runtime mechanism set.**
  Invocation-time module activation is no longer an open mechanism slice; the
  remaining work is the secure/generated gate, issue closure, and the broader
  LLP 0021 exact-target, bootstrap-floor, and residual-evidence audit.

### 2026-07-25 — restored secure-by-default builds

- Removed `insecure` from Cargo's default feature closure. Plain `ibex` now
  compiles the complete secure posture and refuses before project code while
  no exact target advertisement exists.
- Kept both development alternatives explicit: `unadvertised-dev-arming`
  bypasses only target promotion while preserving enforcement, and `insecure`
  remains the separately named no-sandbox compatibility posture.
- The default library suite now executes armed-only refusal coverage that the
  former no-sandbox default compiled out: 642 tests pass, 3 intentional
  hosted/diagnostic tests are ignored.
- The binary regression proves implicit default enforcement and explicit
  `--capsec enforce` reach the identical portable-admission refusal. It now
  pins the current boundary that legacy v1 advertisements are diagnostic-only
  and remain closed.
- The explicit `insecure` binary still compiles. Generated CapSec artifacts,
  the 7,602-edge/15,204-cell contract, compiled environment profile,
  `ref-check`, and diff hygiene remain green.
- Current estimate: **66% complete for the full LLP 0021 completion contract;
  roughly 94% complete for the security-critical runtime mechanism set.**
  Silent ambient authority is no longer the ordinary build posture; exact
  target promotion and diagnostic legacy-plane retirement remain open.

## LLP 0021 completion-criteria audit

| Criterion | Status | Current evidence or contradiction |
|---|---|---|
| 1. Typed effect model is the only production plane | Implemented | Armed production hosts construct `VerifiedDecisionContext`; the legacy `PolicyFile` parser and all HostConfig policy/path/override inputs have been deleted. |
| 2. Every production surface has classification and target cell | Implemented | The generated registry currently validates 7,651 coverage edges and 15,302 target cells with zero drift. |
| 3. Canonical policy and snapshots are typed, deterministic, digest-bound, fail-closed | Implemented | Strict policy/snapshot schemas, canonical-JCS digests, protected-artifact joins, and mismatch/forgery suites pass in the secure gate. |
| 4. Filesystem/network bind used object or peer with staged authorization | Implemented | Every installed armed filesystem/network route is now either a typed staged operation bound to its retained object/verified peer or a residual route that returns `EPERM` before lookup, input acquisition, dispatch, or legacy capability probing. Retained VFS objects, symlink/race fixtures, verified-peer records, repeat-stage leases, Windows TCP, and worker-bound scalar/vector descriptor operations pass on their exact targets. |
| 5. Handles, dynamic authority, deputy intersection, import gating, and audit share immutable semantics | Implemented | Generated operation algebra, generation-bound receipts, graph authority contexts, handle/revocation suites, and structured evidence all pass. |
| 6. Plain `ibex` enforces and has no silent weakening path | Implemented | `insecure` is absent from Cargo defaults. Plain and explicit-enforce startup produce the same pre-code target-admission refusal; secure-development and no-sandbox postures require separately named compile-time features. |
| 7. Every advertised target has a passing generated report | Blocked, honestly closed | The advertisement set is empty. Apple and Windows are candidates only; current physical reports remain incomplete and cannot authorize promotion. |
| 8. Legacy code/docs/demos/stale claims removed or revised | Implemented | The string-policy parser, public module, HostConfig ingestion seams, policy-string mode parser, and readiness dependency are deleted. LLP 0013/0014 retain only explicitly superseded historical rationale; current demos use canonical policy v2 or the separately named policyless foreground audit. |

## Current hard parts

- Exact-target completion is deliberately all-or-nothing. Existing evidence
  must not be promoted from partial or diagnostic runs.
- The production surface is large; generated residual counts must be reduced
  through real source-bound executions or honest closure, never hand-labelled
  as passing.
- `main` is moving as old worktrees are landed, so generated CapSec artifacts
  and source-review identities can rotate during this effort.
- Plain builds have the secure fail-closed posture. Until a target is advertised
  they intentionally refuse before project code; usable development requires
  an explicit secure-development or insecure feature.
- Rich conformance now consumes executed internal-invariant proof, but portable
  promotion now has a distinct mapped-process producer for the dedicated
  internal executor and joins detached per-row artifacts through the Phase-2
  bundle validator. Physical execution remains pending an exact-revision
  portable engine artifact; the reviewed local framework reports no portable
  identity, so it cannot honestly produce that evidence.
- The input-ownership audit retired `malformed-branch-facts` from fixture
  obligations. Branch predicates are authenticated registry metadata, not a
  runtime/public input; registry validation plus real branch-selection and
  no-effect executions own the security claim.
- Authored `import()` and literal CommonJS `require()` now have receipt-gated
  reached-site source/prepared activation and atomic live-graph publication.
  The completed activation matrix is tracked in
  `issues/closed/20260724-native-call-time-module-activation.md`; the next risk is
  integration drift across the full secure/generated gate rather than a known
  activation state-machine gap.
- The root/bootstrap mechanism seals correctly, and both builders intentionally
  emit an empty `bootstrapAuthorityFloor`. Current bootstrap host inputs are
  authenticated projections consumed under the transparent runtime principal,
  so zero selectors are the exact least-authority declaration. The generic
  nonempty-floor/token/retained-context mechanism remains tested; a future
  root-attributed bootstrap effect must add its selector and callback denial
  fixture together.

### 2026-07-25 — retired the string-policy ingestion plane

- Deleted `src/host/policy.rs`, its public module export, and the unversioned
  `PolicyFile`, `ModulePolicy`, and `PackagePolicy` deserializers.
- Removed `HostConfig.policy_path`, `HostConfig.policy`, and the legacy
  allow/deny override vectors. Neither diagnostic embedders nor production
  arming can express the retired artifact now.
- Removed `CapabilityManager::apply_policy` and the policy-string
  `SecurityMode` parser. Historical import-memo and dynamic-permission algebra
  remains covered through private unit-test setters, without creating a live
  parser or configuration channel.
- Simplified readiness reporting so it no longer accepts a legacy policy
  object. Foreground audit remains policyless exactly as LLP 0030 requires;
  production dynamic authority comes from the immutable typed snapshot.
- Corrected the secure-mode script and full-matrix workflow comments that still
  claimed `insecure` was a Cargo default.
- Current demos were already migrated: production examples contain canonical,
  versioned, digest-bound policy v2 artifacts; the audit example has no policy
  file and uses `ibex capsec audit`.
- Validation is green: 641 library tests pass with 3 intentional ignores; the
  feature-minimal binary compiles; the behavior smoke proves project read,
  outside read/write, process spawn, and ambient environment handling; generated
  drift validates 7,602 edges and 15,204 cells; `ref-check` reports zero errors.
- Criterion 8 is now implemented. The full LLP 0021 estimate is **68%** and the
  security-critical mechanism estimate is **95%**; exact-target physical
  evidence and promotion are the dominant remaining completion gap.

### 2026-07-25 — exact Windows launch caught stale source evidence

- Built a clean Windows x64 fleet checkout from an immutable bundle at
  `2f8ba797`, installed the pinned Node, Bun, Java, Rust, PowerShell, Python,
  and patched no-debugger Hermes inputs, and verified the source revision and
  tool identities before launching conformance.
- The first credited command correctly failed before the physical matrix:
  `all-generated-drift` found that deleting the legacy policy ingestion seam
  shifted 35 source offsets in the reviewed runtime-environment inventory.
- Byte hashes and Git EOL metadata proved the macOS and Windows source files
  were identical. Regeneration on both hosts produced the same candidate, so
  this was a missed derived-artifact rotation rather than platform-dependent
  discovery.
- Regenerated the inventory and ran the complete non-writing generated-drift
  chain. It now validates 168 source-derived environment rows, 7,602 CapSec
  coverage edges, 15,204 target cells, 222 host-task ingress sites, all
  contracts and policy projections, both generated bundles, and the remaining
  checked-in generators.
- Hard part: exact-target work must treat every pre-matrix gate as evidence,
  even when it only uncovers a source-review bookkeeping defect. No physical
  command from the failed attempt is credited; the Windows run will restart
  from a new clean immutable revision.
- The next exact run passed every preflight and reached the loaded-engine
  attestation, where the Windows-only bin-test build found one remaining
  `HostConfig.allow` initializer in a broad Hermes test helper. The helper now
  keeps its capability-name inputs as documentation only and constructs the
  policyless host directly; it does not recreate an allowlist or parser seam.
- The exact attestation feature closure now compiles locally through the full
  `ibex` bin-test link. The next Windows revision can reuse the warm native
  build cache while still restarting command evidence from attempt one.
- That revision reached `link.exe` and exposed a 272-character reviewed import
  library path. The staged bytes and full digest-bound verbatim filename were
  correct, but the duplicated digest directory pushed the otherwise valid file
  beyond the linker's legacy path ceiling. Staging now uses
  `OUT_DIR/h/hermes-<sha256>.lib`: the full identity and byte revalidation stay
  intact while the exact fleet path remains consumable.
- The shortened path linked and launched successfully on the Windows fleet.
  Loaded-engine attestation then correctly refused Cargo's staged
  `target\debug\deps\hermesvm.dll`: its bytes match the reviewed artifact, but
  its mapped pathname is not the canonical selected artifact path. Pathname
  identity was not weakened. A promotable Windows run still needs an official
  portable source-A post-link runner selection that names the staged runtime.

### 2026-07-25 — reconciled invocation-time effects with module-runner evidence

- The arm64 exact run passed every preflight, loaded-engine attestation, typed
  adapter recipe, and the first two public batches before the native batch
  stopped at fixture 247. The old harness expected the entire module-runner
  graph execution to emit no typed decisions.
- Diagnostic capture proved the selected CommonJS record-creation ABI emitted
  no decision. The surrounding graph emitted only exact authenticated
  `require` resolution and source-read decisions, across
  requested/discovery/commit/repeat, all allowed and attributed to
  `surface.loader.require.resolve.12c9l9i` or
  `surface.native.op.exactreadfile.1cmzco7`.
- The harness now accepts only those two reviewed auxiliary edges, requires
  the exact observer session, nonempty gates, and allowed outcomes, and still
  credits zero decisions to the selected non-capability ABI fixture.
- The next fixtures exposed a pre-existing catalog contradiction: comments
  correctly said deferred dynamic/require edges cannot prove eager-link ABIs,
  but six such names remained in the generic executable allowlist. Those six
  are now honestly residual. The focused exact-Hermes batch passes all 19
  production-reachable module-runner lifecycle ABI fixtures.
- Refreshed exact counts are Apple: 24,654 required, 2,596 fully executable,
  3,092 internally verified, 18,966 unresolved; Windows: 24,539 required,
  2,230 fully executable, 3,080 internally verified, 19,229 unresolved.
- The 80-test recipe suite passes with 111,075 assertions. `ref-check` passes
  with 2,057 references.
- The complete unfiltered exact-Hermes native batch passes all 554/554
  eligible native, host-ABI, and module-loader public fixtures in 295.83
  seconds. The six residual eager-link ABIs are absent from the batch by
  authenticated recipe construction rather than skipped at execution time.
- A full runner restart passed all preflights, loaded-engine attestation,
  typed adapters, and public batches 000–004, including the repaired 554-row
  native batch. Batch 005 then exposed a Cargo-filter collision: the public
  callback test name was also the containing Rust module name, so its substring
  filter selected the callback smoke and separately bound internal-evidence
  producer too. The internal producer correctly refused without its owned
  binding input. The module now has a disjoint name so each evidence command
  selects only its intended test.
- The repaired public Cargo command selected exactly one test and passed its
  callback evidence batch (626 other tests filtered out). The corresponding
  internal command independently selected exactly one test and, with no recipe
  catalog supplied, took only its documented skip path. The focused recipe
  suite passes 82 tests with 111,102 assertions; generated drift, Rust format,
  and LLP reference validation also pass (39 documents, 2,058 refs, zero
  errors, one intentionally unchecked URL).
- The next full runner restart reached the real 554-row native public batch
  and the supervisor terminated it at 330.242 seconds: the authored
  300-second deadline plus its 30-second cleanup grace. The retained logs show
  no assertion failure, and a preceding complete run measured 295.83 seconds,
  leaving no useful scheduling margin. Suite timeout policy version 2 raises
  the public-fixture deadline to 390 seconds while keeping both target
  critical paths within their declared 375-minute outer bounds (373 minutes
  on arm64 and 369.5 minutes on Windows). The plan/supervisor regression suite
  passes 19 tests, and full generated drift plus LLP reference validation
  remain clean.
- With timeout policy v2, all eight public commands completed and the repaired
  callback batch passed in the full runner. Aggregate validation then exposed
  an older JavaScript exact-action-set check on `readFileSync`: the Rust
  producer already enforced LLP 0037 D2's accepted rule that declared
  `fs:read`/`fs:write` actions must be observed while the only permitted
  surplus is a proven ambient `fs:list` open traversal. The aggregate now
  mirrors that narrow rule, including D4's mixed allow-traversal/deny-operation
  outcome. All 2,596 retained fully executable arm64 observations revalidate,
  and the focused public-evidence suite passes 44 tests with 252 assertions.
- The next full runner crossed public aggregation and executed 1,089 default
  Rust tests. It found two stale promotion-gate expectations: both still
  expected the pre-v2 “no unique verified advertisement” refusal even though
  production correctly rejects the checked-in legacy v1 advertisement corpus
  as diagnostic-only. The tests now require that exact closed-v1 refusal while
  retaining their engine-authentication-before-promotion and
  policy-validation-before-promotion assertions.
- The exact all-scope Rust gate then exposed a pre-existing merge regression
  after 1,170 passing tests: a raw standalone `.cjs` entry was compiled to HBC
  and executed as a bare script, losing `module`, `exports`, `require`, and
  CommonJS top-level `this`. Restored LLP 0028's documented raw-CJS guard so
  only self-contained prepared bundle output is bytecode-eligible.
- The restored guard passes its real-binary end-to-end test. A repeated
  all-scope gate passed the 644-test library suite, 447-test binary suite, and
  integration suites through 1,138 passing tests before one nested
  child-process fixture hit its authored 30-second watchdog while unrelated
  Xcode, Bun/Vite, and filesystem scans saturated the primary host (the
  24-test suite took 599 seconds versus its earlier 181-second baseline). The
  exact timed fixture then passed alone in 18.6 seconds without a source
  change; no deadline or security behavior was weakened.
- The clean `6c2c51b1` conformance restart passed drift, LLP references,
  mapped-engine attestation, recipe generation, typed adapters, and the first
  two public commands. Its 554-row native public command then reached the
  390-second deadline and was terminated after the 30-second cleanup grace at
  420.263 seconds without an assertion failure. An unrelated Deno suite was
  consuming roughly eight cores, making a second deadline increase a poor
  substitute for the resource-isolated sharding LLP 0032 already permits.
- Timeout policy v3 splits that exact native/host-ABI/module-loader cohort by a
  SHA-256 fixture-ID partition into two disjoint secure Cargo commands. The
  current catalog balances 282/272 rows; both run against the same mapped
  engine and the existing aggregate requires exact command membership with no
  missing or duplicate fixture. Under the same contention the shards passed in
  116.98 and 100.98 seconds and merged to exactly 554 unique executions.
  The common public deadline returns to 300 seconds, maximum batch counts rise
  to nine Apple/eight Windows, and the complete worst-case target paths are
  reduced to 366/364 minutes inside the unchanged 375-minute outer bounds.
- The clean `aafab6f1` restart passed all nine public commands; both native
  shards completed in roughly 90 seconds. The full default Rust gate then
  traversed 1,223 tests in 1,251 seconds and reported 1,222 passed, one failed,
  and three ignored. The command supervisor retained only the stderr summary
  and cleaned its tee log, so an attempted aggregate-index mapping incorrectly
  pointed at `native_dns_pool`; Rust's per-target ordering makes that inference
  invalid. The resolver test nevertheless passed alone in 14.62 seconds and
  passed ten consecutive 16-lookup fanout repetitions in 9.02–19.62 seconds.
- A clean `fc902514` restart reproduced the same one-failure aggregate after
  every preflight, typed adapter, and public command passed. A direct exact
  `scripts/run-tests.sh -- --test-threads=1` replay that preserved both output
  streams identified the real failure:
  `module_semantics_baseline::current_loader_baseline_matches_exact_node_and_real_hermes`.
  The CapSec command supervisor now retains separately labelled stdout and
  stderr tails on failure, with a 15-test regression suite, so a later boundary
  cannot lose its owning test again.

### 2026-07-25 — structurally lowered compatibility dynamic imports

- The failing Phase-0 source-map entry took the standalone top-level-await
  path. SWC's CommonJS transform retained raw `import()` syntax, while the
  wrapper correctly skipped its retired source-text replacement because that
  replacement corrupted strings, regular expressions, and lookalike
  identifiers. Hermes therefore rejected the raw dynamic import before the
  fixture could execute.
- Added a SWC AST visitor that changes only a real dynamic-import callee to the
  existing compatibility `globalThis.require` route before CommonJS lowering.
  Its focused regression preserves the `thrower.mjs` regular expression and
  ternary while proving Hermes-incompatible `import()` syntax is absent.
- Regenerated the exact Node 24.13.1/current-Ibex compatibility baseline from
  the real binary. Three observational rows changed: the namespace and
  ESM-importing-CommonJS shapes returned to their exact current values, and the
  pre-WebGPU branch initially recorded the filename-specific source-map marker
  as `line=none`. After rebasing onto the forced-Module compatibility path, the
  exact binary reports original line 5, matching Node. The private resolver
  spelling is still not authenticated source identity; LLP 0026 keeps
  authenticated/native source-label evidence as the normative diagnostic gate.
- Baseline drift now prints the expected and actual observation for each
  changed fixture instead of only a generic mismatch.
- The exact integration gate passes all 12/12 module-semantics fixtures with
  pinned Node and real Hermes. Scanner/graph-shadow coverage passes, `ref-check`
  reports 2,061 checked references with zero errors, Rust formatting and diff
  hygiene pass, and full generated drift validates 7,602 coverage edges,
  15,204 target cells, 168 environment rows, and 222 host-task ingress sites.
  The registry/contract/example-policy digest rotations were regenerated from
  the reviewed AST-call-count change.

### 2026-07-25 — reconciled CapSec rev2 with the landed WebGPU stack

- `origin/main` advanced from `f85443a3` to `1407af0e` while this work was in
  flight, landing ten WebGPU integration commits with broad overlap in the
  runtime, host ABI, generated registries, and evidence gates. Rebased all 31
  CapSec commits onto that revision rather than freezing against the old base.
- The semantic merge preserves WebGPU's deferred owner-thread activation,
  compartment identity, site-aware dynamic-import keys, current
  CommonJS/ESM-cycle behavior, and generated production bundles. It also
  preserves CapSec's authenticated entry join, split resolve/source-acquisition
  authorization, receipt-gated prepared carriers, reached-edge dynamic and
  CommonJS activation, provider reentrancy refusal, and fail-closed secure
  default.
- Restored the complete production provider test that had been structurally
  interleaved with two new WebGPU module-runner tests during conflict replay.
  It proves one exact reached `require`, single target execution, refusal of
  general runtime reentrancy, provider teardown, and safe replacement
  registration. The merged Rust test corpus also exposed and fixed one moved
  `SourceId` in the combined lazy-require graph test.
- Invocation-time prepared activation now uses the same no-follow,
  regular-file, exact-size descriptor reads as initial prepared publication.
  Writable cache bytes remain acceleration only and cannot authorize
  themselves through raw filesystem reads.
- Regenerated the combined registry and contract from source: 7,627 coverage
  edges, 7,847 enforcement branches, 15,254 exact target cells, 13,371
  observed source references, 22 authenticated-ingress obligations, and 225
  host-task ingress sites. After retiring the ill-typed per-surface
  `malformed-branch-facts` obligation, exact recipe accounting is Apple 24,040
  required / 2,601 fully executable / 3,114 internally verified / 18,325
  unresolved; Windows 23,925 / 2,230 / 3,102 / 18,593. The 81-test recipe
  suite passes with 111,860 assertions and the 44-test public-evidence suite
  passes with 252 assertions.
- Before the moving-main rebase, a complete exact CapSec ceremony passed all
  preflights, loaded-engine attestation, typed adapters, all nine public
  batches, and both native shards. Its all-scope Rust gate passed the 642-test
  library and progressed through binary TLS test 16/24 before the outer
  resource deadline reached TLS 17/24 under unrelated host contention, with no
  assertion failure. The retained evidence is
  `target/capsec-suite-evidence-hXeoQl`, and failure supervision now preserves
  separately labelled stdout and stderr tails.
- Hard part: this was a high-overlap integration, so every generated count and
  identity had to be derived from the combined source rather than taking
  either conflict side. A post-rebase full ceremony is still required before
  promotion. `origin/main` remained `1407af0e` at the clean checkpoint after
  the rebase; it will be checked again before every later integration
  checkpoint.
- Post-rebase focused execution found and closed one integration defect:
  initial prepared-graph admission rejected its legitimate sibling
  `activation/` directory. Admission now permits only that fixed real-directory
  root, rejects a symlinked root, and still exact-byte-authenticates every
  reached carrier. The production prepared-initial-to-reached-CommonJS test,
  three activation-cache unit tests, provider lifecycle test, prepared-cache
  round-trip/symlink test, and exact 12/12 Node/Hermes module baseline pass.
- The combined source also required the WebGPU runtime carrier to be rebuilt
  after the moving-main merge. Regenerating with the repository-pinned Bun
  1.3.14 (rather than the host's older Bun 1.3.12) produced the deterministic
  committed artifact; the complete generated-drift gate now passes.
- Final focused proof for this checkpoint: registry logical-branch validation
  rejects subset/cross-fact predicates; the bootstrap floor is consumed exactly
  once across retained contexts; secure `cargo check --lib` passes; the exact
  recipe/obligation suite passes 84 tests with 111,870 assertions; and the
  public-evidence suite passes 44 tests with 252 assertions. `./ref-check`,
  `cargo fmt --check`, and `git diff --check` are clean.
- Completion estimate: important security mechanisms 96%; exact-target
  promotion evidence and ceremony 90%; the complete CapSec rev2/LLP closure
  70%; overall requested task about 86%. The two named model gaps are closed;
  remaining work is the real public-residual authoring/closure program,
  final combined drift/reference gates after these source changes, and a
  contention-free exact ceremony.

### 2026-07-25 — criterion 7 proof-boundary audit

- Audited the portable promotion bundle, checked report admission, target
  advertisement contract, and production Host arming path at exact target-cell
  granularity.
- A per-cell advertisement is not a mechanical shortcut in the current model.
  The recipe and public-execution completeness checks cover the entire target;
  the target-cell catalog requires one row per generated edge; and production
  arming independently refuses unless every edge is present with a `Complete`
  or `Closed` disposition.
- Treating an unproved row as closed would be an overclaim: many residual
  non-capability/public surfaces have no effect gate at which a target-cell
  denial could make them unreachable. A security-honest restricted target
  therefore has to actually remove or centrally close every omitted public
  surface and prove that closure. It cannot merely weaken the report predicate
  or relabel unsupported cells.
- Criterion 7 now has a product-level fork: retain the full public profile and
  complete the measured 18,325-row Apple authoring/closure program, or define a
  deliberately restricted advertised profile whose unproved surface is
  structurally absent/closed. The empty-advertisement state remains secure and
  fail-closed but is not treated as substantive completion.
- Continued against the original full-profile objective with the first new
  authoring tranche: `node:fs.accessSync`. One source-bound template fans out
  over all five effect scenarios. A deliberately failing reviewed-engine run
  exposed the real six-decision allow sequence
  (`requested, discovery, requested, repeat, repeat, repeat`); after pinning
  that observation, the complete 150-recipe builtin batch passed and emitted
  bound evidence. Apple moves from 2,596 to 2,601 fully executable rows and
  from 18,330 to 18,325 unresolved rows; Windows remains unchanged because its
  filesystem route is not independently typed.
- Hard part: even a clean family currently buys five rows because each public
  function has a distinct invocation and decision sequence. The engine-locked
  execution is about 45 seconds once compiled; source-derived catalog
  regeneration is about 20 seconds and produces a 142 MB temporary artifact.
  This confirms LLP 0036's cost model rather than revealing a missing bulk
  shortcut.
- Estimate: important enforcement mechanisms remain about 96% complete and the
  overall requested task remains about 86%; criterion 7's literal recipe
  denominator is now 5,715/24,040 (23.8%) proven by executable or
  internally-verified evidence, with 18,325 public residuals still open.

### 2026-07-25 — `realpathSync` target evidence

- Extended the literal full-profile authoring program with
  `node:fs.realpathSync`, promoting its five Apple effect scenarios without
  changing Windows's ambiguous filesystem-route disposition.
- Deliberately failing bound-engine runs exposed both real public paths. Allow
  emits twelve authenticated decisions: cwd request/commit, a four-decision
  lstat preflight, and a six-decision realpath operation. Denial emits the two
  ambient cwd decisions and then stops at the requested-stage lstat denial,
  never reaching realpath.
- Added an authenticated auxiliary-decision descriptor so the public harness
  validates the exact cwd/lstat edges and action sets without crediting them as
  the allow-path operation terminal. The same descriptor binds lstat as the
  sole fail-closed denial terminal. Any other helper edge, action, terminal,
  stage, authority stratum, or result still fails the batch.
- The complete 155-recipe builtin Hermes batch passes and emits bound evidence.
  Apple is now 24,040 required / 2,606 fully executable / 3,114 internally
  verified / 18,320 unresolved; Windows remains 23,925 / 2,230 / 3,102 /
  18,593. Criterion 7's literal denominator is 5,720/24,040 (23.8%) proven.
- The independent promotion aggregate now re-derives the auxiliary edges,
  actions, denial terminal, and source-route edge set from checked coverage.
  It accepts the five real executed observations and rejects an unbound helper
  action or substituted denial terminal. The combined recipe/public-evidence
  suite passes 126 tests with 112,235 assertions; complete generated drift,
  `./ref-check`, `cargo fmt --check`, and `git diff --check` are clean.
- Hard part: a public export's source-derived allow terminal need not be the
  terminal that rejects a denied call. Preserving both claims required modeling
  reviewed helper edges explicitly, rather than discarding their decisions or
  pretending the realpath terminal ran on denial.

### 2026-07-25 — pure `node:fs` value tranche

- Added bounded, source-keyed zero-decision calls for ten non-capability
  `node:fs` surfaces: `Stats`, `Dirent`, all seven `Dirent.is*` predicates, and
  `_toUnixTimestamp`. Constructors receive fixed in-memory values; predicate
  receivers are freshly constructed `Dirent` instances; no filesystem handle
  or path enters the invocation.
- Fresh exact-target catalogs move ten rows on each target: Apple is now
  24,040 required / 2,616 fully executable / 3,114 internally verified /
  18,310 unresolved, and Windows is 23,925 / 2,240 / 3,102 / 18,583.
  Criterion 7's Apple denominator is 5,730/24,040 (23.8%) proven.
- The complete non-capability builtin Hermes batch executes all 1,148 export
  recipes and passes; the independent promotion aggregate accepts each of the
  ten new engine observations as a source-bound normal return with zero typed
  decisions.
- The combined template/recipe/promotion-evidence suite passes 149 tests with
  112,444 assertions. Regenerating the runtime-environment inventory changed
  only the two source offsets moved by the Rust template allowlist; complete
  generated drift, `./ref-check`, `cargo fmt --check`, and `git diff --check`
  pass.
- Hard part: similarly named object predicates cannot be bulk-classified.
  `Dirent.is*` is generated as non-capability and can be proven on an in-memory
  receiver, while `Stats.is*` still inherits an effect classification in the
  current source graph and remains residual. This tranche promotes only the ten
  obligations whose generated classification and real execution agree.

### 2026-07-25 — `statfsSync` target evidence

- Extended the direct `fs:list` metadata family through
  `node:fs.statfsSync`, promoting its five Apple effect scenarios while
  preserving Windows's ambiguous filesystem-route disposition.
- A deliberately failing bound-engine run exposed the exact allow sequence:
  `requested, discovery, requested, repeat, repeat, repeat`, all on the
  source-derived `__exactStatfs` edge. Denial stops at the first requested
  decision. The complete 160-recipe builtin Hermes batch then passed across
  allow, deny, malformed, missing-attribution, and wrong-principal scenarios.
- The independent promotion validator accepted the five real engine
  observations. The combined template/recipe/promotion-evidence suite passes
  149 tests with 112,491 assertions.
- Apple is now 24,040 required / 2,621 fully executable / 3,114 internally
  verified / 18,305 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,735/24,040 (23.9%)
  proven.
- Hard part: even this simple single-terminal export requires catalog
  regeneration, a complete engine-locked family batch, and independent
  observation validation; the five-row gain does not materially change the
  remaining literal denominator. Important enforcement mechanisms remain
  about 96% complete and the overall requested task remains about 86%.

### 2026-07-25 — `existsSync` denial-return evidence

- Extended the direct `fs:list` family through `node:fs.existsSync`, promoting
  five Apple effect scenarios while preserving Windows's ambiguous
  filesystem-route disposition.
- Bound the API's unusual public result: an allowed lookup follows the
  six-decision `__exactAccess` sequence and returns boolean `true`; a denied
  lookup emits the requested-stage typed denial, catches the filesystem error,
  and returns boolean `false`. The producer and independent promotion validator
  both reject a true result after denial or a substituted route edge.
- The complete 165-recipe builtin Hermes batch passes. The combined
  template/recipe/promotion-evidence suite passes 150 tests with 112,546
  assertions; a dedicated aggregate test accepts allow/deny and rejects the
  false-positive denial result.
- Apple is now 24,040 required / 2,626 fully executable / 3,114 internally
  verified / 18,300 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,740/24,040 (23.9%)
  proven.
- Hard part: APIs that intentionally swallow authorization errors need
  value-bound evidence. Treating any normal return as success would erase the
  distinction between “allowed and present” and “denied,” so this tranche adds
  an exact boolean result contract rather than weakening denial validation.
  Important enforcement mechanisms remain about 96% complete and the overall
  requested task remains about 86%.

### 2026-07-25 — `truncateSync` retained-object mutation evidence

- Promoted the five Apple `node:fs.truncateSync` effect scenarios through the
  armed direct truncate implementation. The source-bound allow sequence is
  `requested, discovery, requested, repeat, commit, repeat`: the first four
  decisions authenticate and retain the exact target, commit gates `fs:write`,
  and the last repeat sits immediately before `ftruncate`.
- Denial reaches the same retained target but stops at the denied `fs:write`
  commit. The native batch now verifies the side effect as well as the decision
  sequence: allowed scenarios leave exactly the first two original bytes, while
  denial preserves the complete original file.
- The complete 170-recipe builtin Hermes batch passes. The independent
  promotion validator accepts all five real observations and derives
  `native-op:__exactTruncate`; its incidental-traversal allowance is restricted
  to the `fs-truncate:` operation identity rather than generalized to arbitrary
  `fs:write` calls.
- Apple is now 24,040 required / 2,631 fully executable / 3,114 internally
  verified / 18,295 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,745/24,040 (23.9%)
  proven.
- Hard part: `chmodSync` initially looked like another direct mutation, but LLP
  0023 and the native mutation guard deliberately close synchronous chmod before
  path conversion or capability probing in an armed runtime. Its zero-decision
  refusal was retained as a residual rather than mislabeled as effect evidence.
  `truncateSync` is different because its armed path is explicitly
  retained-object-bound. Important enforcement mechanisms remain about 96%
  complete and the overall requested task remains about 86%.

### 2026-07-25 — `appendFileSync` open/write mutation evidence

- Added all five Apple `node:fs.appendFileSync` scenarios to the reviewed
  open/write family. The allow sequence is `requested, requested, discovery,
  requested, repeat, commit, repeat`; denial retains the ambient traversal and
  stops at the denied `fs:write` commit.
- The complete 175-recipe builtin Hermes batch passes with byte-level
  postconditions. Allowed scenarios preserve the exact original prefix and
  append the complete literal suffix; denial preserves the original bytes.
  The producer and independent promotion validator both restrict incidental
  `fs:list` to the exact `appendFileSync`/`fs:write`/`fs-open:` tuple.
- The independent validator accepts all five real engine observations and
  derives `native-op:__exactFsOpen`. Apple is now 24,040 required / 2,636 fully
  executable / 3,114 internally verified / 18,290 unresolved. Windows remains
  23,925 / 2,240 / 3,102 / 18,583. Criterion 7's literal Apple denominator is
  5,750/24,040 (23.9%) proven.
- Hard part: the public export's source graph contains descriptor, flush, and
  dynamic fast-path alternatives. The fixed string/path/default-options
  invocation physically selects the ordinary retained open/write route, but
  the evidence still authenticates the complete source-derived edge allowlist
  and refuses any terminal outside it. Important enforcement mechanisms remain
  about 96% complete and the overall requested task remains about 86%.

### 2026-07-25 — `mkdirSync` retained-parent creation evidence

- Added all five Apple `node:fs.mkdirSync` scenarios using an absolute
  `/project` path and literal `{recursive: false}` options. Those source-owned
  arguments physically select the only directory-creation contract LLP 0023
  opens and exclude the relative-cwd metadata preflight and closed recursive
  mutation branch.
- The bound engine emits `requested, discovery, requested, requested,
  discovery` for every scenario. The first four decisions authenticate
  traversal under ambient `fs:list`; the final absent-create decision gates
  `fs:write` on `native-op:__exactMkdir`. Denial stops at that same boundary.
- The complete 180-recipe builtin Hermes batch passes. Its filesystem
  postconditions prove that allowed variants create exactly the expected
  directory and denial leaves it absent. The independent validator accepts all
  180 observations, including the five new `fs-mkdir:` operation traces.
- Apple is now 24,040 required / 2,641 fully executable / 3,114 internally
  verified / 18,285 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,755/24,040 (23.9%)
  proven.
- Hard part: the source graph conservatively includes `ensureFs`, `stat`, and
  `mkdir` terminals plus unresolved dynamic helpers. Promotion cannot erase
  those alternatives globally; it must bind a fixed invocation that makes the
  selected branch physically true, then authenticate the real terminal,
  operation identity, stages, and postcondition. Important enforcement
  mechanisms remain about 96% complete and the overall requested task remains
  about 86%.

### 2026-07-25 — `readlinkSync` authorization correction and target evidence

- Auditing the next public family found a substantive runtime defect:
  `fsReadlinkArmedWork` used stage code `5` with `needs_read = 0` immediately
  before `readlinkat`. The Host therefore treated stored link-byte disclosure
  as ambient `fs:list`, despite both the native and public coverage edges
  declaring `fs:read`.
- Corrected the shared sync/async worker to commit `fs:read` before the first
  `readlinkat` and repeat it before every buffer-growth retry. Link retention
  and target translation remain ambient `fs:list`; absence of `fs:read` now
  denies before any stored link byte is read.
- Added all five Apple `node:fs.readlinkSync` scenarios with a harness-owned
  relative symlink. Allow emits `requested, discovery, requested, repeat,
  commit, discovery, requested, repeat`; denial stops at the commit. All
  allowed variants return exactly `capsec-readlink-target.txt`, while denial
  returns no value and both the link and target bytes remain unchanged.
- The complete 185-recipe bound-Hermes batch passes. The independent aggregate
  accepts all 185 observations and rejects a substituted target string; the
  combined focused suite passes 154 tests with 112,644 assertions.
- Apple is now 24,040 required / 2,646 fully executable / 3,114 internally
  verified / 18,280 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,760/24,040 (24.0%)
  proven.
- Hard part: public-evidence work can expose an implementation/registry
  mismatch rather than merely an unexecuted row. Promoting the old trace would
  have normalized a real authority bypass. The safe response was to repair the
  effect boundary, prove denial before disclosure, and only then author the
  recipe. Important enforcement mechanisms remain about 96% complete and the
  overall requested task remains about 86%.

### 2026-07-25 — `openSync` flag branches and descriptor cleanup evidence

- Added fifteen Apple `node:fs.openSync` effect recipes: five scenarios each
  for literal `r` (`fs:read`), `a` (`fs:write`), and `r+` (conjunctive
  `fs:read` + `fs:write`). The three generated `branch-selection` rows remain
  unresolved because registry branch facts are not caller-supplied runtime
  input.
- Every branch binds the bound-engine six-stage sequence `requested,
  requested, discovery, requested, repeat, commit`. The five traversal
  decisions are ambient `fs:list`; the commit carries the exact selected floor
  effects. Successful multi-effect decisions now require one decisive
  authority row per effect, while a denied conjunction requires the one
  decisive denial row that blocks it.
- Every allowed result must be a numeric descriptor, which the harness closes
  before recording `closed-fs-file-descriptor`; the independent aggregate
  rejects missing or substituted cleanup. The harness also proves the fixture
  bytes remain unchanged for allow and denial.
- The complete 200-recipe bound-Hermes batch passes. The independent aggregate
  accepts all 200 observations, including all fifteen `openSync` rows; the
  combined focused suite passes 156 tests with 112,750 assertions.
- Apple is now 24,040 required / 2,661 fully executable / 3,114 internally
  verified / 18,265 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,775/24,040 (24.0%)
  proven.
- Hard part: `openSync` is one public export with three argument-selected
  authority shapes, and the read-write commit is genuinely multi-effect.
  Treating it like a single-capability export would either leak descriptors or
  under-validate the conjunction. Important enforcement mechanisms remain
  about 96% complete and the overall requested task remains about 86%.

### 2026-07-25 — `opendirSync` materialization and close evidence

- Added all five Apple `node:fs.opendirSync` scenarios against an exact empty
  directory. The empty input physically selects the source-derived
  `__exactReaddir` terminal and excludes the conservative per-entry
  `__exactLstat` alternative.
- Allow emits `requested, discovery, requested, repeat, repeat, repeat,
  repeat`; denial stops at the first requested-stage `fs:list` decision. The
  successful result binds the exact virtual path and calls `Dir.closeSync`
  before recording `closed-fs-directory`; the harness also proves the
  directory remains present and empty.
- The complete 205-recipe bound-Hermes batch passes, and the independent
  aggregate accepts all 205 observations while rejecting substituted paths,
  missing cleanup, and recipes that omit the cleanup contract. The combined
  focused suite passes 158 tests with 112,780 assertions on the M4 mini worker.
- Apple is now 24,040 required / 2,666 fully executable / 3,114 internally
  verified / 18,260 unresolved. Windows remains 23,925 / 2,240 / 3,102 /
  18,583. Criterion 7's literal Apple denominator is 5,780/24,040 (24.0%)
  proven.
- Auditing the adjacent mutation exports found that `unlinkSync`,
  `renameSync`, `chmodSync`, `copyFileSync`, `symlinkSync`, `linkSync`, and
  related paths are deliberately refused by `refuseClosedArmedFsMutation`
  before lookup or capability probing, while the current catalog still emits
  ordinary effect-allow obligations. Filed
  `issues/20260725-closed-armed-fs-mutations-coverage-model.md`; the runtime
  boundary must remain closed while coverage/recipe modeling is reconciled.
  Important enforcement mechanisms remain about 96% complete and the overall
  requested task remains about 86%.

### 2026-07-25 — reconciled wholly closed filesystem mutations

- Added the deny-only `fs:unbound-mutation` capability vocabulary required by
  LLP 0023 §4.1 and classified the exact reviewed inventory of 56 public
  `node:fs`/`node:fs/promises` mutation aliases plus 20 direct native mutation
  terminals as closed. The live-repository test binds all 76 rows exactly, so a
  typo, missing route, or accidental effect classification fails generation.
- Regenerated the contract and all 15 registry outputs. Apple now has 23,736
  required obligations and Windows 23,621: each target sheds 304 impossible
  allow/deny/malformed/etc. effect scenarios while gaining the honest
  deny-only closure obligation. This is a model correction, not evidence
  promotion; Apple remains 2,666 fully executable and 3,114 internally
  verified, while Windows remains 2,240 and 3,102.
- The contract and registry reproduce cleanly, the coverage model passes
  142 tests with 3,359 assertions, and the recipe suite passes 87 tests with
  108,751 assertions. The Apple catalog now reports 17,956 unresolved rows;
  Windows reports 18,279.
- Criterion 7's literal Apple denominator is now 5,780/23,736 (24.4%) proven.
  Hard part: the closure model is now honest, but none of these 76 exact public
  spellings has executable unchanged-filesystem evidence yet, and the mixed
  `__exactFsPathAsync`, `__exactFsFdAsync`, and recursive-`mkdir` dispatchers
  still need branch-local closure semantics. Important enforcement mechanisms
  remain about 96% complete and the overall requested task remains about 86%.

### 2026-07-25 — executed wholly closed filesystem mutation evidence

- Authored target-local closed-surface probes for all 76 reviewed mutation
  rows: 56 public `node:fs`/`node:fs/promises` exports, including the three
  `FileHandle` methods, and 20 direct native globals. Apple and Windows receive
  separate recipe plans; no Apple execution is reused as Windows evidence.
- The bound Apple Hermes batch passes all 684 closed-surface fixtures,
  including all 76 new rows. Every mutation returns the production `EPERM`
  refusal with the exact guard operation, emits zero typed and legacy
  decisions, and preserves the recursively captured filesystem bytes,
  directory entries, links, mode, owner, and timestamps.
- The independent public-evidence validator accepts all 684 records and
  rejects a changed filesystem digest or substituted error code. The recipe
  and validator suites pass 137 tests with 109,496 assertions on the clean M4
  mini worker. The full generated-drift chain is clean; the four checked
  example policies and vendored-source fingerprint now carry the regenerated
  vocabulary/registry identity without changing grants.
- Apple is now 23,736 required / 2,742 fully executable / 3,114 internally
  verified / 17,880 unresolved. Windows has an authored target-local plan at
  23,621 / 2,316 / 3,102 / 18,203, but its 76 mutation rows still require a
  Windows engine execution before they can count as physical target evidence.
  Criterion 7's literal Apple denominator is now 5,856/23,736 (24.7%) proven.
- Hard part: public `FileHandle.chmod/chown/utimes` have descriptor-style guard
  identities but receiver-local argument lists; using path-style arguments
  caused validation to reject before the guard. The producer and independent
  validator now bind the exact per-surface call shape and require the
  fail-before-lookup unchanged-state proof. The mixed `__exactFsPathAsync`,
  `__exactFsFdAsync`, and recursive-`mkdir` dispatchers remain the next
  branch-local modeling task. Important enforcement mechanisms remain about
  96% complete and the overall requested task remains about 86%.

### 2026-07-25 — closed mixed filesystem dispatcher branches

- Extended conditional coverage semantics so one callable can expose exact
  effect-bearing and deny-only logical branches. Closed branches carry an
  immutable branch predicate, deny-only capability, and rationale; they do not
  leak into the callable's effect union. LLP 0023's fail-before-lookup rule now
  covers the mixed path dispatcher, descriptor dispatcher, and recursive
  `mkdir` branch without closing their reviewed open siblings.
- Corrected implementation applicability for
  `src/engine/hermes_runtime_fs.cc`: the POSIX source is no longer treated as a
  cross-target default when `build.rs` compiles
  `hermes_runtime_fs_windows.cc` instead. Windows therefore receives exact
  target-absence recipes for POSIX-only globals rather than fictitious
  fallback implementation credit.
- Authored 17 Apple and 16 Windows target-local mixed-dispatcher closures. The
  bound Apple batch passes all 701 closed fixtures, including 93 armed
  filesystem mutation probes. Every mutation returns exact `EPERM`, emits zero
  typed and legacy decisions, and preserves the recursive filesystem snapshot.
  The independent validator accepts all 701 records with digest
  `sha256-ZfCnLdowsI7zb1eWfYzn0piATq6SueWXlCjgiBpAPSc`.
- Apple is now 23,723 required / 2,760 fully executable / 3,114 internally
  verified / 17,849 unresolved. Windows has an authored target-local plan at
  23,542 / 2,341 / 3,102 / 18,099; its physical Windows execution remains part
  of the broader target-promotion gap and is not inferred from Apple evidence.
  Criterion 7's literal Apple denominator is now 5,874/23,723 (24.8%) proven.
- The focused model, inventory, recipe, and evidence suite passes 407 tests on
  a fresh M4 mini worktree. The local recipe suite passes 88 tests, the
  CapSec-semantics crate passes 116 unit/integration tests, `ref-check` passes
  2,100 references, and the generated contract reproduces exactly.
- Hard part: target applicability is a security claim, not inventory
  decoration. Treating the POSIX implementation as a default silently lent
  nonexistent native routes to Windows, while treating a mixed dispatcher as
  wholly effectful invented impossible allow obligations. Important
  enforcement mechanisms remain about 96% complete and the overall requested
  task remains about 87%.

### 2026-07-25 — physical Windows closed-surface execution

- Built the pinned physical Windows Hermes runtime from source and executed
  the target-local closed batch against the exact loaded `hermesvm.dll`.
  Windows now has 23,378 required / 2,382 fully executable / 3,100 internally
  verified / 17,896 unresolved obligations. This remains an incomplete,
  unadvertised target rather than a promotion claim.
- Implemented Windows inline-producer authentication against the mapped Ibex
  image: a known producer code address identifies the loader module, the
  loader pathname is opened without following a final reparse point and with
  write/delete/rename sharing denied, its object identity and file state are
  retained across hashing, and both the loader mapping and pathname identity
  are revalidated. A physical Windows regression proves a replacement
  pathname cannot relabel the mapped producer.
- Corrected Windows verbatim-path parsing so `\\?\C:\...`, `\\?\UNC\...`,
  and slash-form verbatim prefixes are not truncated at the prefix `?` as
  though it were a URL query. The physical module-runner closure fixture now
  admits already-retained root-owned bytes directly against that authenticated
  producer, without pretending the still-unadvertised Windows resolver
  filesystem is available.
- The physical Windows closed batch passes all 680 catalog-derived fixtures.
  Its raw evidence SHA-256 is
  `d8934cdb21f24c0c190ecac28cc49915ba3900008dd66d7a2c0ca695c4cc4c89`
  and its recipe catalog digest is
  `sha256-msFhXZwfvhyKqXeH6Kl6N3xUQ2y95_hWeBLGAvlmP9w`.
  The independent public-evidence validator re-derived the exact 680-fixture
  command group, accepted every record, and produced
  `sha256-S0RZxMejzOrR_J4GERhyYDRuQr0M2-yYOJxau-rHPeA`. This final evidence
  rerun followed the last Windows-only source cleanup; the copied 4,123,880
  bytes match the physical Windows producer's SHA-256 exactly.
- All 680 executions passed with zero typed decisions. The batch includes 79
  filesystem-unbound mutation probes (42 sync, 18 callback, one deferred
  callback, 14 promise, two file-handle promise, and two sync-listener);
  every one returns the authored `EPERM` refusal, preserves the exact
  before/after filesystem digest, executes the engine, and executes no project
  code. It also physically covers 322 shared-runtime absences, 18 disabled
  debugger ABI rows, and 11 armed-native absences.
- Added and physically ran Windows VFS root-retention negatives. Armed session
  startup rejects a junction/reparse `/project` even when supplied that reparse
  object's identity, and a retained root detects a pathname replacement on
  its next cwd verification without leaking the backing path. The exact
  Windows VFS filter passes three tests. Five source-graph tests that require
  the still-unsupported deeper resolver are now honestly Unix-scoped, allowing
  the Windows library-test target to compile instead of referencing a
  Unix-only host helper.
- A fresh detached M4 worktree received a byte-for-byte verified copy of the
  complete patch. Its pinned Bun 1.3.14 drift replay is clean; the combined
  model, inventory, recipe, public-evidence, and root-global suites pass 409
  tests with 125,317 assertions. A native macOS `cargo check` of the secure
  conformance-observer profile passes against the explicitly bound legacy
  Hermes framework/compiler/header profile.
- Hard part: Windows startup must authenticate the image that actually
  contains the in-process producer; hashing `current_exe()` by pathname alone
  would permit a replacement path to be mistaken for the mapped image.
  Separately, reaching a closed native ABI must not smuggle in support for the
  unresolved Windows resolver. Important enforcement mechanisms remain about
  97% complete and the overall requested task remains about 88%.

### 2026-07-25 — retained Windows namespace and authenticated resolver

- Implemented ordinary Windows namespace traversal with handle-relative
  `NtCreateFile`, `FILE_OPEN_REPARSE_POINT`, delete-sharing retained handles,
  and exact object matching for every witnessed/reopened directory transition.
  Authenticated reads now carry the same requested, discovery, commit, and
  repeat stages as Unix and retain the final readable object through byte
  acquisition. Nested cwd retention uses the same root-relative transition
  and later root/object revalidation.
- The physical Windows VFS namespace filter passes all 25 tests. It covers
  nested read and cwd traversal, staged evidence, leaf replacement between
  discovery and commit, root replacement, reparse refusal, stable errno
  projection, and backing-path non-disclosure.
- Implemented the retained-boundary Windows Oxc filesystem for ordinary
  non-reparse files and directories. Verbatim drive/UNC spellings are projected
  only at the Oxc boundary and converted back to the authenticated canonical
  namespace before containment checks. Captured package manifests and explicit
  absences remain the only package-semantic inputs; `NODE_PATH` stays disabled.
  A platform-independent manifest regression also fixes deterministic
  `ENOTDIR` absence recognition by stable VFS code rather than a Unix errno
  number.
- The physical Windows authenticated-resolver filter passes 13 tests:
  direct-file grammar, captured-manifest absence and override semantics,
  package exports and `#imports`, exact outside-referrer bridging, ambient
  package isolation, boundary replacement refusal, and reparse refusal.
- Removed the Windows-only direct module-artifact exception from the closed
  module-runner fixture. Windows now constructs the same authenticated source
  graph, authorization plan, and `NativeSynchronousGraph` linkage as Unix
  before proving namespace inspection closed.
- Registered the nine new retained-boundary resolver surfaces in the
  source-derived coverage model and regenerated every dependent registry,
  contract, policy, and vendored identity. The refreshed Windows catalog is
  23,459 required / 2,382 fully executable / 3,106 internally verified /
  17,971 unresolved; Windows remains deliberately unadvertised.
- The post-regression physical Windows closed batch passes all 680 recipes.
  The copied 4,123,880 evidence bytes match the producing machine exactly at
  raw SHA-256
  `bf4ec9139345893339927144a1251ff0671766f7b5e685ce89d0bbef8af6e2fd`.
  The independent validator re-derived the exact 680-fixture command group,
  accepted every record with zero failures and zero typed decisions, and
  produced artifact digest
  `sha256-rf4EKebspXCb6H9IwT3hFawk-3n8jPtJpcbvT7Mfsjs` against catalog digest
  `sha256-j8ArBiH8rikk2nzBItak1kIYICunnfcRVL0-WRK3DVs`.
- The clean M4 verifier reproduces the generated registry and all downstream
  artifacts exactly. Its combined model, inventory, recipe, public-evidence,
  and root-global suite passes 409 tests with 125,969 assertions, and the
  secure conformance-observer `cargo check` passes against the explicitly
  bound Hermes framework, compiler, and headers.
- Hard parts: Windows and Unix expose different native numeric values for the
  same stable `ENOTDIR` result, and Windows canonicalization deliberately
  yields verbatim paths that Oxc cannot parse as module specifiers. Both are
  now explicit compatibility translations outside the authenticated identity
  model. Remaining important gaps are contained Windows reparse-target
  decoding/authorization and the separate typed retained-object backend for
  installed Windows filesystem effects. Important enforcement mechanisms are
  about 98% complete and the overall requested task is about 89% complete.

### 2026-07-25 — contained Windows reparse transitions

- Implemented contained Microsoft symlink and mount-point traversal without
  allowing the OS pathname parser to follow reparses. `FSCTL_GET_REPARSE_POINT`
  reads the target from the witnessed no-follow handle; only the Microsoft
  symlink and mount-point layouts are accepted. The same component is reopened
  without following it, object-matched, and read again, and both decoded
  payloads must agree because Windows permits in-place reparse-data mutation.
- NT-object-manager and verbatim drive/UNC substitute names are converted to
  ordinary spelling only for parsing. Relative and absolute targets normalize
  beneath the authenticated root, the complete pending tail is appended and
  authorized before target lookup, and traversal restarts from the retained
  root. Unsupported providers, malformed/changing payloads, outside targets,
  denied foreign-principal subtrees, and depth beyond the fixed bound fail
  closed. Successful VFS reads and Oxc resolutions expose the canonical target
  namespace and source identity rather than the alias spelling.
- The exact physical Windows patch passes 30 VFS tests and 16 authenticated
  resolver tests. Coverage now contains 7,643 edges and 15,286 target cells.
  The refreshed Windows catalog is 23,471 required / 2,382 fully executable /
  3,106 internally verified / 17,983 unresolved; Apple is 23,816 / 2,760 /
  3,120 / 17,936. The new bounded `read_link` route adds twelve honest
  unresolved exact-target scenarios and no inferred execution credit.
- The refreshed physical Windows closed batch passes all 680 target-local
  recipes with zero failures and zero typed or legacy decisions. Its 4,123,880
  evidence bytes have raw SHA-256
  `ddbbe68310b3392e37f1e36df74f19cb4d1f9bb635c8aebaa530ac06bf7bc042`.
  The independent validator re-derived the exact 680-fixture command group and
  accepted it with aggregate digest
  `sha256-jWnJkzTPRZJqgReQ219-9m450PZkGYo8VNdzrRzXcNU` against catalog digest
  `sha256-mz0t5Oigl3QgPIMznYIyB-wCp11Sbmo5SkFl9ybztHM`.
- Hard part: a retained Windows object identity does not freeze its reparse
  payload, and the kernel exposes target names in several NT/verbatim/ordinary
  spellings. The transition therefore needs both object matching and an
  identical second payload, followed by one lexical target-plus-tail check
  before any target component is opened. Windows remains deliberately
  unadvertised: case/Unicode/DOS-device/short-name alias canonicalization, the
  typed retained-object backend for installed filesystem effects, and 17,983
  public-evidence rows remain unresolved. Important enforcement mechanisms are
  about 99% complete and the overall requested task is about 90% complete.

### 2026-07-25 — digest-bound Windows ASCII case identity

- Added `windows-ascii-casefold-v1` as the only Windows bound-volume
  canonicalizer identity. Both authored selectors and occurrences require
  UTF-8 ASCII components, reject tilde spellings, and fold ASCII case into the
  same digest-bound authorization coordinate. Display paths and module
  `SourceId` remain lexical, and two separately named hard-link entries remain
  distinct.
- Applied the same comparison key before Oxc lookup to resolver boundaries,
  captured manifests, authenticated absences, denied principal subtrees, and
  their collision checks. A differently cased denied subtree cannot be entered
  through Windows' case-insensitive lookup, and `Package.json`/`package.JSON`
  cannot be recorded as contradictory independent facts.
- Every retained Windows root and intermediate traversal directory is queried
  with `FileCaseSensitiveInfo`. A case-sensitive flag or failed/unsupported
  query refuses before that handle can become a traversal root. The VFS,
  authenticated resolver, first-party source reader, and package inventory all
  share this rule. Reparse targets and direct retained opens reject non-ASCII
  and tilde components before native component lookup.
- Physical Windows verification passes the case-sensitive-directory test,
  case-folded denial/manifest tests, uppercase-path read with lexical SourceId,
  hard-link split, and semantic canonicalizer test. The complete focused
  filters pass 8 Windows VFS tests and 16 authenticated resolver/package tests;
  the two additional alias and hard-link filters pass separately.
- The physical candidate also exposed the honest remaining boundary:
  `fsutil 8dot3name query C:` reports volume state `0`, so 8.3 creation is
  enabled. Windows permits administrator-assigned legal short names that need
  not contain `~`; this patch does not pretend the tilde refusal covers them.
  LLP 0021/0023 now name a race-safe short-name table/state contract or a
  stronger volume/tree refusal as a remaining advertisement prerequisite.
- Registered four new resolver control-plane functions and their four live
  routes. The regenerated contract contains 7,651 coverage edges, 7,951
  enforcement branches, and 15,302 target cells. The Apple candidate is
  23,840 required / 2,760 fully executable / 3,136 internally verified /
  17,944 unresolved (catalog digest
  `sha256-N8XYrycvaDGNxxSSd2qy5eOrPluOWPCxwXVCXsPAthc`); Windows is
  23,495 / 2,382 / 3,122 / 17,991 (catalog digest
  `sha256-RWIFsBkp_S0ChP1SqvCIvx4kMYtjX6uNw4pUr5uacNg`).
- The clean M4 verifier reproduces every generated artifact, passes the
  five focused source/coverage/recipe/evidence suites with 397 tests and
  126,182 assertions, and passes the native
  `capsec-conformance-observer` Cargo check against the pinned Hermes inputs.
  Local generated drift and `ref-check` are clean.
- Hard part: Windows has three overlapping name systems here—ordinary
  case-insensitive names, opt-in case-sensitive directories, and mutable
  per-volume/per-file short-name state. Folding case without refusing
  case-sensitive directories would collapse distinct objects; rejecting only
  the customary `~` form would overclaim coverage of custom short names.
  Important enforcement mechanisms remain about 99% complete and the overall
  requested task remains about 90%.

### 2026-07-25 — race-closed Windows arbitrary short-name refusal

- Closed the custom 8.3 alias seam in the single retained Windows
  relative-open primitive. Before opening a child, the runtime queries the
  exact parent-directory entry as `FileIdExtdBothDirectoryInformation` and
  stages its long name, short name, and 128-bit file ID. The query uses a fresh
  directory handle whose ID is first matched to the retained parent.
- A request that selected the staged short name refuses, including a legal
  administrator-assigned alias with no tilde. Long-name access remains usable
  even when the object has a generated or custom short name; this avoids the
  impractical alternative of refusing every ordinary NTFS long-name entry.
- The child opens no-follow without delete sharing, preventing rename and
  `SetFileShortName` mutation while retained. The parent entry is queried again
  and the before/after snapshots plus opened child ID must agree. Unsupported
  directory information, malformed evidence, parent-path replacement, and
  entry replacement all fail closed.
- The physical Windows fixture successfully assigns `CSTMSEC.JS`, proves the
  long `long-security-document.js` entry still opens, and proves the custom
  alias refuses. A barrier fixture replaces `victim.js` with a different
  object after the first snapshot; the repeated snapshot/object match refuses
  it. The complete Windows filters pass 10 VFS tests and 16 authenticated
  resolver/package tests.
- This strengthens existing VFS/resolver enforcement routes rather than adding
  a public surface, so the generated contract remains 7,651 coverage edges,
  7,951 enforcement branches, and 15,302 target cells. Windows remains
  unadvertised because installed `node:fs`/native filesystem effects still
  lack the typed retained-object backend and 17,991 exact-target
  public-evidence rows remain unresolved.
- Hard part: querying the alternate name from the opened child once is not
  race-safe—an attacker can remove the alias between selection and query.
  Directory enumeration supplies both names and identity before open; removing
  delete sharing pins the selected entry while the second snapshot closes the
  stage-to-open gap. Important enforcement mechanisms remain about 99%
  complete and the overall requested task remains about 90%.

### 2026-07-25 — first installed Windows typed filesystem effect

- Promoted armed synchronous `__exactReadFile` without changing the unarmed
  compatibility path. The engine now derives the runtime nonce, actor, and
  canonical frame principal stack natively and passes only virtual path syntax
  plus an optional strict typed bearer to a private Host bridge.
- The bridge delegates to the cross-platform `RuntimeVfsSession` and retained
  `VirtualFileSystem::read_authenticated` state machine. Windows therefore
  authorizes requested/discovery `fs:list` and commit/repeat `fs:read` against
  the actual retained leaf. Its authenticated mount handle is structural
  session state, so this route honestly emits four semantic decisions rather
  than borrowing the POSIX adapter's six-observation shape.
- Armed failures never call `exactResolveVfsPath`,
  `requireReadCapability`, or `ex_host_fs_read_file`. Physical Windows engine
  tests prove exact returned bytes and all four typed stages on success; a
  no-list floor proves EACCES at requested before lookup, unchanged fixture
  bytes, and zero legacy decisions. The previously verified physical leaf-swap
  barrier proves replacement between discovery and commit is stale.
- Five exact-target Windows recipes are now executable. The catalog is 23,495
  required / 2,387 fully executable / 3,122 internally verified / 17,986
  unresolved with digest
  `sha256-KajKcQuGd6P4PSZsjBzyELC8g14uEyOrFhGaGC1OZ3I`; callable filesystem
  residuals fall from 182 to 177.
- This is intentionally bounded to synchronous whole-file reads and inherits
  the VFS input-size limit. Worker-backed `__exactFsReadFileAsync` remains
  legacy because a single pre-worker repeat cannot prove live authority between
  observable chunks. Descriptor, metadata, enumeration, mutation, and other
  installed Windows routes remain residual or closed.
- Independent M4 regeneration reproduces the 7,651-edge / 7,951-branch /
  15,302-cell contract, and its recipe suite passes 88 tests with 109,828
  assertions; `ref-check` and the native observer-feature build also pass.
  The expanded provenance suite exposed two stale assertions left by earlier
  branch work: a module-runner drift-test anchor still expected `auto result`,
  and one registry test still expected pre-expansion inventory totals. Both
  fixtures now bind the current reviewed source/artifact and pass locally and
  on the M4.
- Hard part: the POSIX direct reader records two authenticated-root walk
  observations in addition to the semantic retained-leaf lifecycle, while the
  cross-platform Windows VFS already owns the authenticated root as session
  structure. Requiring six would invent decisions; accepting four without
  target-bound recipe expectations would silently weaken evidence comparison.
  Important enforcement mechanisms remain about 99% complete and the overall
  requested task remains about 90%.

### 2026-07-25 — retained-object Windows stat metadata

- Promoted armed synchronous `__exactStat` through a private native bridge
  without changing unarmed compatibility. The engine derives the runtime
  nonce, actor, and canonical frame principal stack; JavaScript supplies only
  virtual path syntax and an optional strict typed bearer.
- Added `VirtualFileSystem::stat_authenticated`. It opens ordinary targets for
  metadata only, retains and object-matches the selected leaf, authorizes
  requested/discovery/repeat `fs:list`, and serializes Node-shaped metadata
  only after Repeat. `/project` is handled from the authenticated retained
  mount root itself and records no fabricated namespace parent.
- Armed errors return through the VFS mapper and never invoke
  `exactResolveVfsPath`, `requireReadCapability`, or `ex_host_fs_stat`.
  Physical Windows tests prove file and mount-root metadata, exact three-stage
  evidence, denial at Requested before lookup with unchanged bytes and zero
  legacy decisions, plus stale-identity refusal when the leaf is replaced
  between Discovery and retained open. The physical production library check
  and private ABI test also pass.
- Five more exact-target Windows recipes are executable. The catalog is 23,495
  required / 2,392 fully executable / 3,122 internally verified / 17,981
  unresolved with digest
  `sha256-WHPMYfNDttI6nbm2KtbAlL4dUoyNRAScPmmlfXl57RA`;
  `public-surface-filesystem-not-typed-on-target` falls from 177 to 172.
- Local and independent M4 recipe generation each pass 88 tests with 109,845
  assertions. Both machines reproduce generated artifacts and pass
  `ref-check` plus the observer-feature build against the pinned Hermes
  inputs; the local private ABI test also passes. A checksum dry run confirms
  the final scoped source and generated bytes match the M4 verifier.
- Hard part: stat is metadata disclosure governed wholly by `fs:list`, whose
  lifecycle is Requested, Discovery, then Repeat immediately before
  disclosure—adding Commit would invent an authorization stage. The
  authenticated mount root has a retained final object but no in-namespace
  parent, so the occurrence must represent `parent_object: None` instead of
  manufacturing a traversal observation. Important enforcement mechanisms
  remain about 99% complete and the overall requested task remains about 90%
  complete.

### 2026-07-25 — retained final-link Windows lstat

- Promoted armed synchronous `__exactLstat` through the shared private typed
  metadata bridge. Engine-derived runtime/principal identity, strict optional
  bearer parsing, explicit-length JSON ownership, and direct VFS error return
  match stat; armed execution never reaches `exactResolveVfsPath`,
  `requireReadCapability`, or `ex_host_fs_lstat`.
- Extended contained VFS discovery with an explicit follow-final mode.
  Ordinary stat/read callers pin that mode to true, preserving their reviewed
  behavior. Lstat follows authenticated ancestor transitions but stops at a
  final Windows reparse object, reopens it for metadata only relative to the
  retained parent, object-matches it, and authorizes
  requested/discovery/repeat `fs:list` under `no-follow-final`.
- Physical Windows tests prove returned `is_symlink` metadata from the final
  retained reparse rather than its target, stale-identity refusal when that
  entry is replaced after Discovery, exact three-stage public evidence, and
  EACCES at Requested with unchanged target bytes and zero legacy decisions.
  The production Windows library build and the shared private ABI test pass.
- Five more exact-target Windows recipes are executable. The catalog is 23,495
  required / 2,397 fully executable / 3,122 internally verified / 17,976
  unresolved with digest
  `sha256-iLscFvmIU_zfHoRR2xwtwqbxLVWvnG1RW6AOp9AKsWY`;
  `public-surface-filesystem-not-typed-on-target` falls from 172 to 167.
- The reviewed authenticated-read range changed only at the call site that now
  supplies `follow_final: true`; its existing traversal, commit, repeat, and
  byte-disclosure semantics are unchanged. After reviewing that exact range,
  its provenance digest was refreshed to
  `sha256-Ezbs1O6y8dNxd3T_voZtMHKhR12lGGDG2-IMLH7q9FA`.
- The clean M4 verifier independently reproduces the generated artifacts,
  passes 88 recipe tests with 109,862 assertions, passes `ref-check` and the
  observer-feature build, and passes both the retained Unix final-link test and
  the shared typed stat/lstat ABI test. A checksum dry run confirms that its
  scoped source and generated bytes match this worktree.
- Hard part: the shared retained-open helper historically rejected every final
  Windows reparse, correctly for follow-final read/stat but incorrectly for
  lstat. The new `LinkMetadata` access is the sole exception: it grants no
  data-read right, never decodes or follows the target, and still requires the
  reopened object's 128-bit identity to match Discovery. Important enforcement
  mechanisms remain about 99% complete and the overall requested task remains
  about 90% complete.

### 2026-07-25 — retained-object Windows directory enumeration

- Promoted armed synchronous `__exactReaddir` through a private typed bridge
  carrying the engine-derived runtime generation, actor, canonical constrained
  principals, and strict optional bearer. Armed calls return VFS errors
  directly and never reach `exactResolveVfsPath`, `requireReadCapability`, or
  `ex_host_fs_readdir`.
- Added `VirtualFileSystem::readdir_authenticated`. The authenticated mount
  root uses its retained object with no fabricated parent; a nested final
  directory is reopened relative to its retained parent with list access and
  without delete sharing, then object- and case-coordinate-matched before use.
  Windows enumeration queries `FileIdExtdBothDirectoryInformation` through
  that exact handle, emits only the long-name coordinate, validates but never
  emits its 8.3 short-name evidence, represents malformed UTF-16 explicitly,
  and returns a deterministic raw-name sort.
- Enumeration authorizes Requested before lookup, Discovery after retaining
  the exact directory, and Repeat once per member immediately before that name
  enters the returned listing. Physical Windows VFS tests prove the exact
  Requested/Discovery/Repeat/Repeat trace for two sorted entries, stale-identity
  refusal when the directory is replaced after Discovery and before any
  Repeat, and the synthetic `/` mount listing with zero filesystem decisions.
- Physical public Windows tests prove two-entry results with the same exact
  four-stage trace and zero legacy decisions. A requested-stage denial returns
  EACCES, emits one `fs:list` decision, performs no legacy authorization, and
  leaves fixture bytes unchanged. The production observer-feature library
  build passes together with all three focused VFS tests and both public
  engine tests.
- Five more exact-target Windows recipes are executable. The catalog is 23,495
  required / 2,402 fully executable / 3,122 internally verified / 17,971
  unresolved with digest
  `sha256-K5BnQ4OeVvDFw62RhtvCQtDkfSvuO1FH5emlyIqWlKs`;
  `public-surface-filesystem-not-typed-on-target` falls from 167 to 162. The
  recipe suite passes 88 tests with 109,898 assertions, and vendored
  regeneration succeeds.
- The clean M4 verifier independently reproduces vendored generation, the same
  88 recipe tests and 109,898 assertions, `ref-check`, and the
  observer-feature library build. It also passes the retained Unix final-link
  test and shared typed stat/lstat ABI test; a checksum dry run confirms that
  every source and generated file in this checkpoint matches this worktree
  byte for byte.
- Hard part: a directory member name is content disclosed by the retained
  directory object; it is not authorization to open the named child. The
  implementation therefore keeps the directory object fixed and repeats
  `fs:list` on that same occurrence before each name becomes observable,
  without reopening child pathnames. Windows long and short names are two
  coordinates for one entry, so the authenticated long name is the only
  result while the short name remains refusal evidence. Important enforcement
  mechanisms remain about 99% complete and the overall requested task remains
  about 90% complete.

### 2026-07-25 — retained Windows read descriptors and fstat

- Promoted the read-only branch of armed `__exactFsOpen`. Requested and
  Discovery authorize `fs:list`; Commit authorizes `fs:read` against the
  regular-file object actually opened. The private ABI returns that exact
  retained file together with its namespace, parent/final object identities,
  retained handle ID, canonical virtual path, and optional presented bearer.
- The Windows descriptor table now keeps the opaque retained file plus its
  engine-derived runtime and principal owner. The numeric JavaScript fd is
  only a monotonically allocated table key: guessing a number cannot create a
  file handle or cross runtime/owner boundaries.
- Promoted armed `__exactFsFstatSync` on those retained read descriptors. It
  validates the descriptor owner, authorizes one `fs:list` Repeat using the
  stored object/handle/bearer facts, and serializes metadata from the same
  retained file without resolving or reopening its original pathname.
  Replacement after Discovery fails as stale before Commit.
- Write/create/truncate/append opens and unsupported numeric flag bits remain
  deliberately closed. They return `EPERM` before virtual resolution, legacy
  capability checks, or host creation, while unarmed compatibility remains
  unchanged. Descriptor reads, durability, mutations, and worker-backed
  variants remain residual pending their own retained-operation protocols.
- Physical Windows verification passes the allowed public open/fstat trace
  (`Requested`, `Discovery`, `Commit`, `Repeat`), requested-stage denial with
  unchanged bytes and zero legacy decisions, write-open fail-closed with no
  file creation, both VFS retained-identity tests, the private ABI test, and
  the observer-feature production library check.
- Ten Windows exact-target rows are newly executable: six read-open rows and
  four fstat rows. The catalog is 23,495 required / 2,412 fully executable /
  3,122 internally verified / 17,961 unresolved with digest
  `sha256-zOOo9FfGLpjTW6btOL7RfvQbjxGcqbZBA6rdtivT7tc`;
  `public-surface-filesystem-not-typed-on-target` is now 156. The recipe suite
  passes 88 tests with 109,967 assertions.
- The M4 verifier independently regenerates the vendored artifacts, reproduces
  all 88 recipe tests and 109,967 assertions, passes both retained-descriptor
  VFS tests, the private typed ABI test, the observer-feature library check,
  and `ref-check`. Its checkout initially lacked the macOS Hermes SDK and
  compiler; installing the same pinned 20 MiB framework/header/tool set made
  the native verification self-contained.
- Hard part: a public numeric descriptor cannot be treated as authority or as
  stable object identity. Runtime/owner membership, the opaque retained file,
  original object identity, handle ID, bearer, and current generation must
  travel together through the private ABI and be rechecked at Repeat. This
  slice therefore promotes only operations that can use the same file object;
  it does not infer safety for reads or mutations merely because they accept
  the same fd number. Important enforcement mechanisms remain about 99%
  complete and the overall requested task remains about 90% complete.

### 2026-07-25 — retained Windows scalar descriptor reads

- Promoted armed synchronous `__exactFsRead` for retained read-only
  descriptors. The engine first enforces the numeric table key's runtime,
  principal owner, and readable-open state, then the private ABI authorizes one
  `fs:read` Repeat against the open-time namespace, parent/final object
  identities, retained handle ID, optional bearer, and current runtime
  generation. Armed execution reads the same opaque file and never consults
  the legacy path capability oracle.
- Added `VirtualFileSystem::read_descriptor_authenticated`. It checks the
  retained file identity before authorization and after I/O. Sequential reads
  advance the retained cursor; positional reads save and restore it, matching
  Node's `readSync` contract. The Windows boundary now validates descriptor,
  length, and position numbers before allocation or I/O.
- Physical Windows verification passes the production observer-feature
  library build, all three retained-descriptor VFS tests, the private typed ABI
  test, and the public open/read/fstat test. The public trace is
  `Requested`, `Discovery`, `Commit`, `Repeat`, `Repeat`, `Repeat` with actions
  `fs:list`, `fs:list`, `fs:read`, `fs:read`, `fs:read`, `fs:list`: one
  positional read returns `descriptor`, the following sequential read still
  begins at offset zero and returns `retained`, fstat reports the same
  19-byte object, and no legacy decision is observed.
- Four `__exactFsRead` scenarios are newly executable on both exact targets;
  the deny row remains explicitly residual because the current public harness
  cannot create its prerequisite descriptor under that denial scenario
  without weakening the proof. The Windows catalog is 23,495 required / 2,416
  fully executable / 3,122 internally verified / 17,957 unresolved with
  digest `sha256-y7G4uMp8Ti46XqsFFIPIJ5ylXsXvpb4yKEYhviPBDF4`.
  `public-surface-filesystem-not-typed-on-target` remains 156 because the four
  newly authored rows previously lacked public arguments rather than carrying
  that target-specific residual. The recipe suite passes 89 tests with
  110,081 assertions.
- The freed-space M4 verifier independently regenerates the vendored
  artifacts, reproduces all 89 recipe tests and 110,081 assertions, passes all
  three retained-descriptor VFS tests, the private typed ABI test, the
  observer-feature library check, and `ref-check`.
- Hard part: the fd number is only an owner-scoped table coordinate. The read
  decision must bind the open-time occurrence and retained-handle identity,
  happen before byte disclosure, and operate on the same native file. A
  pathname re-resolution would turn a safe retained descriptor into a new
  ambient lookup; an authorize-then-seek/read sequence that failed to restore
  the cursor would violate Node's positional-read semantics. Important
  enforcement mechanisms remain about 99% complete and the overall requested
  task remains about 90% complete.

### 2026-07-25 — retained Windows synchronous descriptor-vector reads

- Installed armed synchronous `__exactFsReadv` on Windows. The engine enforces
  terminal-session policy plus the numeric table key's runtime, principal
  owner, and readable-open state before inspecting vector destinations. It
  accepts at most 1,024 destinations with a `uint32` aggregate length, then the
  private Host ABI authorizes one `fs:read` Repeat against the open-time
  namespace, parent/final identities, retained handle ID, optional bearer, and
  current runtime generation.
- The VFS acquires the aggregate bytes from the same retained file and
  rechecks its identity after I/O. Positional vector reads restore the retained
  cursor. The engine scatters the owned result only after success, so denial or
  stale identity cannot partially modify caller buffers. Unarmed compatibility
  uses the same serialized retained native handle; armed execution has no
  pathname or legacy-capability fallback. The optional callback runs only
  after the per-file I/O mutex is released, avoiding a same-fd reentrant
  deadlock.
- The public physical-Windows fixture performs retained open, positional scalar
  read, positioned vector read into 3-byte and 5-byte destinations, sequential
  scalar read, and fstat. It returns
  `descriptor:8:retained:retained:19:true`, proving vector scatter and cursor
  restoration against the same 19-byte object. The typed trace is Requested,
  Discovery, Commit, four Repeats with exact open, scalar-read, vector-read,
  scalar-read, and fstat coverage edges; the legacy observer remains empty.
  The observer-feature library build and private ABI surface-binding test also
  pass on the physical Windows host.
- Added a source-owned `harness-uint8-array-list` public fixture. Four
  `__exactFsReadv` scenarios are executable on both exact targets; deny remains
  residual because the harness cannot create the required descriptor under the
  same denial without weakening the proof. Installing the Windows global
  replaces one executable target-absence row with five effect rows, so the
  Windows catalog is 23,499 required / 2,419 fully executable / 3,122
  internally verified / 17,958 unresolved. Apple is 23,840 / 2,768 / 3,136 /
  17,936. The Windows catalog digest is
  `sha256-F47b4gLEBDXTUfIqLbIQzV8wAWEz3t4bcJLa_qxWpEI`;
  `public-surface-filesystem-not-typed-on-target` remains 156. The recipe suite
  passes 90 tests with 110,192 assertions.
- The new enforcement branch changes the registry digest but not the authority
  vocabulary or any example grant. All four generated example policies were
  reviewed: only `registryDigest` and the consequent `policyDigest` change.
  The freed-space M4 verifier independently regenerates the registry and
  vendored artifacts, reproduces all 90 recipe tests and 110,192 assertions,
  passes the private ABI test and observer-feature library check, and then runs
  the policy, drift, and `ref-check` gates against the exact synchronized
  checkpoint.
- Hard part: vector buffers are output objects, so authorizing each native
  sub-read would both overcount effects and permit partial disclosure before a
  later failure. One aggregate retained-object acquisition makes the
  authorization boundary atomic from JavaScript's perspective, while the
  destination-count/length bounds prevent a forged sparse array from becoming
  an unbounded pre-authorization allocation. Important enforcement mechanisms
  remain about 99% complete and the overall requested task is about 91%
  complete.

### 2026-07-26 — retained existing-file Windows append descriptors

- Promoted the first armed Windows mutation route without widening the name-
  bound surface. Only exact string flag `"a"` is admitted, and only for an
  existing regular file. `fs:write` Requested precedes lookup;
  requested/discovery `fs:list` authenticates the existing leaf; native
  append-only access retains and object-matches that leaf; and `fs:write`
  Commit binds the final identity and authenticated package-source generation.
  An absent target returns `ENOENT`; the public `O_CREAT` spelling never reaches
  host creation. Numeric flags, `"as"`/`"ax"`, read-write, truncate,
  create-on-absence, and other writable branches still fail closed before the
  legacy oracle.
- Promoted armed scalar `__exactFsWrite` only for those append descriptors.
  Runtime/owner/access-class membership is checked before caller-controlled
  byte materialization. One `fs:write` Repeat occurs immediately before one
  native short write through the same retained file; identity is checked
  before authorization and after I/O. The JavaScript position argument cannot
  weaken append semantics, and a zero-length write emits no effect.
- Added unchanged-state evidence at every refusal boundary: requested denial
  happens before lookup and preserves the original bytes; Repeat denial happens
  before mutation; an absent open creates nothing; and a hard-link alias to
  authenticated package source is denied at Commit with a populated
  `final_object_generation`, preserving both names' bytes.
- The cross-platform package test initially failed on physical Windows because
  Windows deliberately refuses to build authenticated package-source state
  without an object-generation adapter. The proof is now split correctly:
  ordinary append/absence ABI behavior runs on both platforms, the
  object-generation hard-link guard runs on Unix-family adapters, and Windows
  retains its stricter fail-closed package-arming contract. The Host test
  helper now installs authenticated package-source state when constructing the
  decision context, rather than mutating the Host afterward and accidentally
  omitting its guards.
- Ten Windows rows become executable: six exact open-branch rows and four
  retained scalar-write rows. The Windows catalog is 23,499 required / 2,429
  fully executable / 3,122 internally verified / 17,948 unresolved with
  digest `sha256-yL9g24buQJ5oWlyHy1Yu_tiPTCzmKbylFTnzzR9D2Ug`;
  `public-surface-filesystem-not-typed-on-target` falls from 156 to 150.
  Apple remains 23,840 / 2,772 / 3,136 / 17,932 with digest
  `sha256-v1scTZfh0p1RtLuvQ1KNFkx0o4NnbHNjAelaKKcIYJ0`. The recipe suite
  passes 91 tests with 110,349 assertions.
- Local verification passes formatting/diff hygiene, `ref-check`, generated
  drift, the observer-feature library build, both retained-append VFS tests,
  the cross-platform private ABI test, and the Unix-family package-hard-link
  test. The physical Windows host passes the production library build and the
  secure-feature private/public tests for success, requested denial, and
  unsupported/no-create flags; the large OpenSSL PDB diagnostics are
  non-fatal linker warnings.
- The M4 Mini independently regenerates the vendored/CapSec artifacts,
  reproduces all 91 recipe tests and 110,349 assertions, passes `ref-check`,
  the observer build, all four focused VFS/ABI tests, and matches every one of
  the 12 changed source/generated/document files byte for byte.
- Hard part: Node's `"a"` spelling includes creation, but creation requires a
  distinct absent-object protocol and rollback/error contract. Treating that
  spelling as permission to call `CreateFile` would have silently widened the
  security surface. The retained adapter therefore recognizes the public
  spelling yet refuses its absent branch, and the exact trace intentionally has
  no Discovery decision for absence. Important enforcement mechanisms remain
  about 99% complete and the overall requested task is about **92% complete**.

### 2026-07-26 — worker-backed Windows whole-file reads

- Corrected the LLP 0021 completion audit: criterion 4 was not implemented for
  the whole supported runtime surface while installed Windows worker-backed
  filesystem and TCP routes still used legacy authorization. Those routes are
  unadvertised and fail closed where required, but that posture is not
  substantive completion.
- Promoted armed Windows `__exactFsReadFileAsync` for both path and retained
  descriptor inputs. One schedule-time runtime nonce, actor, constrained-
  principal stack, virtual input, and optional bearer now feed both the native
  worker-operation lease and the private typed ABI. The path branch performs
  Requested/Discovery `fs:list`, Commit `fs:read`, and generation-aware
  per-chunk Repeat entirely on the worker; requested denial happens before any
  lookup. No armed path is pre-resolved through `exactResolveVfsPath` or checked
  through the legacy capability oracle.
- Retained-descriptor whole-file reads hold the descriptor's I/O mutex from its
  current cursor through EOF. The worker reads in 64 KiB chunks through the
  exact retained VFS file, submits a fresh `fs:read` Repeat for each data chunk
  and EOF, and advances the cursor only after the corresponding decision
  succeeds. The 70 KiB physical fixture proves two data Repeats plus EOF and
  no pathname reopen or legacy observation.
- The coverage model now describes the real branch-local contract instead of
  flattening both inputs into a generic read: descriptors carry only
  `fs:read` Repeat, while paths carry requested/discovery `fs:list` plus
  commit/repeat `fs:read`. Contract, registry, example-policy, runtime-
  inventory, and vendored fingerprints were regenerated from that source of
  truth.
- Eleven Windows rows become executable: all six path scenarios and five
  retained-descriptor scenarios. Descriptor denial remains honestly residual
  because the same denied floor cannot construct its prerequisite retained
  handle. Windows is now 23,499 required / 2,440 fully executable / 3,122
  internally verified / 17,937 unresolved with digest
  `sha256-HQeZVZNVmqKNPQmlNPpBC6hId7H24FjEaro3Ehekbjs`. Apple is 23,840 /
  2,783 / 3,136 / 17,921 with digest
  `sha256-3xWwanXGuVSL5fmgUBzw5LQOmzX9N2uEsqk9-QWTGE4`. The recipe suite passes
  91 tests with 110,451 assertions.
- The physical Windows verifier passes the three path, descriptor-chunk, and
  denial tests under `IBEX_FAIL_ON_STALE_VENDORED=1`; the initial strict run
  correctly rejected 28 copied macOS `._*` sidecars, which were enumerated and
  removed from that disposable checkout before the successful rerun. The M4
  Mini independently regenerates all vendored and CapSec artifacts, passes the
  same recipe suite, full generated-drift chain, `ref-check`, and observer-
  feature library build; checksum-mode synchronization reports no content
  differences across the changed-file set.
- Hard part: an async Promise boundary is not an authorization boundary. A
  check on the runtime thread followed by arbitrary worker I/O would leave
  revocation and object identity unbound during disclosure. The worker must
  carry the exact captured principal lease and reauthorize the exact retained
  object between chunks, including EOF, while cursor serialization prevents
  concurrent operations from splitting one logical `readFile` result.
  Important enforcement mechanisms remain about **99% complete** and the
  overall requested task remains about **92% complete**; the audit correction
  prevents that estimate from hiding the remaining Windows scalar/vector
  worker and TCP boundaries.

### 2026-07-26 — worker-bound async scalar/vector descriptor reads

- Audited `__exactFsReadAsync` and `__exactFsReadvAsync` on both installed
  backends. Windows still used the legacy worker I/O path. POSIX emitted a
  typed-looking `Repeat` on the runtime thread and then performed the actual
  read later on a worker, so the observer trace alone had hidden the same
  timing gap.
- Both backends now validate the runtime/owner-bound readable descriptor, safe
  position, and bounded request shape before dispatch, then carry the exact
  captured principal stack in the worker operation lease. Scalar and vector
  reads each submit one exact-object `fs:read` Repeat immediately before their
  sole native acquisition. Empty requests acquire nothing and emit no
  decision.
- POSIX authorizes the retained parent plus duplicated descriptor on the
  worker immediately before `read`/`pread` or `readv`/`preadv`. Vector setup
  records at most 1,024 actual view lengths on the runtime thread and allocates
  the aggregate native destinations only after authorization.
- Windows holds the retained file's I/O mutex and calls async-surface-specific
  typed VFS bridges for scalar and aggregate vector acquisition. Both return
  owned bytes; Promise delivery and vector scatter happen only after success,
  so refusal cannot partially publish caller-visible output. Positioned reads
  restore the cursor.
- The cross-platform observer regression performs a positioned scalar read, a
  positioned vector read, and then a sequential scalar read. M4 macOS and
  physical Windows both return `descriptor:retained:retained`, emit exactly
  three `fs:read` Repeats on the two new surface edges, and never consult the
  legacy capability oracle. The physical Windows run also passes with
  `IBEX_FAIL_ON_STALE_VENDORED=1`; the copied tree contains zero `._*`
  sidecars. The JS regression mutates the caller's vector array while the
  Promise is pending and proves that all four bytes still publish into the
  prevalidated destination snapshot while the redirected buffer remains
  unchanged; its suite passes 37 tests and 425 assertions.
- Four scalar and four vector scenarios become executable on each exact
  target. Windows is now 23,499 required / 2,448 fully executable / 3,122
  internally verified / 17,929 unresolved with digest
  `sha256-x0r2Bx29pHVJLyj2SM20gT5K4hg2JQik1xR5kiWbMnw`. Apple is 23,840 /
  2,791 / 3,136 / 17,913 with digest
  `sha256-oh8YVBIFBwqNizBwNfUy8WwvRUl2hbGUGXfLLUp9BdU`. The recipe suite passes
  93 tests with 110,661 assertions; descriptor denial remains honestly
  residual because its denied floor cannot construct the prerequisite source
  descriptor.
- The M4 verifier independently regenerates the registry, contract, example
  policies, vendored builtins, and source fingerprint, then passes generated
  drift, `ref-check`, the 37-test JS suite, and the strict observer-feature
  native test. Checksum-mode comparison reports only timestamp differences
  across the local changed-file set and no content differences.
- Hard part: a correct typed trace does not prove that authorization happened
  on the effect side of an async boundary. The final decision must live in the
  worker closure immediately before the syscall, and vector code must not
  allocate or mutate caller-sized outputs before that decision. Important
  enforcement mechanisms remain about **99% complete** and the overall
  requested task remains about **92% complete**.

### 2026-07-26 — integrated lockdown override repair and refreshed evaluator evidence

- `main` advanced while this slice was in flight with the error-prototype
  override repair and its LLP 0013 update. The 62-commit branch rebased cleanly
  onto `143e0191`, but generated drift then failed closed at
  `native-op:global:AsyncFunction`: changing the checked-in lockdown script
  changed the source-derived taming identity even though the reachable
  evaluator set and engine profiles did not change.
- Reviewed the incoming error-family-only moderate override behavior against
  LLP 0013. It converts the selected error prototype data properties into
  frozen accessor pairs whose setters shadow only on a receiver, refuses
  mutation of the frozen prototypes themselves, and freezes displaced
  nonprimitive roots. It does not reopen `eval`, `Function`,
  `AsyncFunction`, or `GeneratorFunction`.
- Refreshed the production classifier, exported inventory identity, and model
  fixture together. The taming digest is now
  `sha256-db554fcb6c9c245527ee92fc34988671b3797dfa15676ad75e72a3734ffd6c5c`;
  the reviewed evaluator identity is
  `hermes-evaluators.08bb542867d4d29fabe8e67c64eae3b78d5605fc9259dafda2e0044c41c2beae`
  after composing the subsequently landed Hermes 0010/0011 classification
  headers with the reviewed lockdown change.
  Targeted inventory and semantic-classifier tests prove both the accepted
  identity and deliberate drift rejection.
- Regenerated the 7,651-edge / 15,302-cell registry, 168-row runtime
  inventory, 225-site host-task inventory, contract, policies, dispositions,
  and vendored artifacts. Full drift, formatting, diff hygiene, `ref-check`,
  the 93-test / 110,661-assertion recipe suite, and the 37-test /
  425-assertion JS suite pass locally.
- Exact-target counts remain unchanged. The identity-bound catalogs now have
  Apple digest `sha256-oh8YVBIFBwqNizBwNfUy8WwvRUl2hbGUGXfLLUp9BdU` and
  Windows digest `sha256-x0r2Bx29pHVJLyj2SM20gT5K4hg2JQik1xR5kiWbMnw`.
- The M4 verifier independently regenerates the policies, registry, contract,
  and vendored outputs, then passes drift, `ref-check`, the JS suite, the
  worker-bound async descriptor observer, and the incoming lockdown
  regression under strict stale-vendored enforcement. Checksum comparison
  across the tracked tree reports 299 timestamp-only entries and no content
  differences. Physical Windows contains zero `._*` sidecars and passes both
  native regressions with `IBEX_FAIL_ON_STALE_VENDORED=1`.
- Hard part: a source-derived evaluator review binds all code in the lockdown
  taming blob, not only syntax that directly names an evaluator. A safe,
  unrelated-looking prototype repair must therefore invalidate the old
  evaluator review and be semantically re-reviewed rather than mechanically
  copying its pin. Important enforcement mechanisms remain about **99%
  complete** and the overall requested task remains about **92% complete**.

### 2026-07-26 — typed Windows TCP connect, peer, and lifecycle boundary

- Replaced the armed Windows `__exactTcpConnect` legacy-oracle path with the
  typed network contract. `Requested` runs before DNS; the resolver result is
  canonicalized, sorted, and deduplicated into the complete candidate set;
  each attempted endpoint receives `Candidate`; and `Commit` requires the
  selected endpoint to equal the actual `getpeername` peer before the handle is
  published. IPv4-mapped IPv6 literals remain refused rather than acquiring an
  ambiguous address identity.
- Retained WinSock entries now bind a monotonic socket identity, runtime,
  owner, requested host/port, canonical candidates, selected candidate,
  verified peer, and exact connection id. Armed reads and writes verify the
  current peer, take a stable negative/dynamic/handle-generation bracket,
  submit a full `Repeat`, revalidate the exact registry entry and connection
  id, and hold the registry lock through `recv` or `send`. Close and numeric
  `SOCKET` reuse therefore cannot race the authorized effect. Empty writes
  still perform no effect and emit no decision.
- Kept release authority reducing. Close, reset, and shutdown require the
  exact runtime/owner-bound entry but not live policy authority. Once their
  loopback setup was bound to the installed Windows connect source, the three
  zero-decision lifecycle rows no longer needed their stale Windows
  prerequisite exception.
- Recipe generation now selects public invocation and nested setup descriptors
  from the implementation branch compiled for the exact target. This promotes
  five Windows connect scenarios plus the three lifecycle consumers without
  attributing the POSIX source to Windows or disturbing target-absence probes.
  Windows is now 23,499 required / 2,456 fully executable / 3,122 internally
  verified / 17,921 unresolved with digest
  `sha256-WKSyhVxCCwxqBksw5QzVyHxFlZ3gyPoSmRKxENblPCk`. Apple remains 23,840 /
  2,791 / 3,136 / 17,913 with digest
  `sha256-YgEmaptGoFnSBwa5_Ta7DQRvKMrqx9ODnuiZrxv7gVQ`. The recipe suite passes
  93 tests and 110,682 assertions.
- Physical Windows passes the strict staged connect/three-write observer and
  the ownership-only lifecycle regression with zero `._*` sidecars. A focused,
  digest-valid public catalog executes all eight promoted rows through the two
  production native shards: four connect outcomes plus close in the primary,
  and missing-attribution plus reset/shutdown in the secondary. The complete
  primary shard reaches an older unrelated `__exactFsOpen` write-denial row
  before the TCP rows and reports `fs:write` where that recipe expects
  `fs:list`; this pre-existing full-catalog blocker is not counted as TCP
  evidence and is tracked in
  `issues/20260726-windows-fs-open-write-denial-evidence.md`.
- The M4 verifier independently regenerates the complete vendored/CapSec
  artifact chain, passes generated drift, `ref-check`, all 93 recipe tests, and
  the existing typed Apple connect/peer observer. Checksum comparison across
  the changed files reports timestamp-only differences and no content
  differences. During the slice, `main` advanced to `b9558cf3`; the 63-commit
  branch rebased cleanly before documentation and final verification.
- Hard part: endpoint authorization is not one check around `connect`. The
  requested name, complete candidate set, attempted candidate, committed
  kernel peer, retained connection, and later I/O must stay in one identity
  chain while Windows can recycle numeric socket values. Binding the verified
  peer and holding the registry lock through I/O closes both rebinding and
  handle-reuse gaps. Important enforcement mechanisms remain about **99%
  complete** and the overall requested task remains about **92% complete**.

### 2026-07-26 — worker-bound descriptor writes and retained durability

- Audited scalar/vector async descriptor writes on both installed filesystem
  backends. POSIX authorized on the runtime thread before dispatch, leaving
  revocation separated from the eventual mutation; Windows still used the
  legacy worker path. Both now retain bounded caller input and submit one
  surface-specific exact-object `fs:write` Repeat on the filesystem worker
  immediately before the sole scalar or aggregate mutation. Empty writes
  return zero without a decision.
- POSIX duplicates the exact retained descriptor and performs its Repeat
  immediately before `write`/`pwrite` or `writev`/`pwritev`. Windows admits
  only an existing append-only retained file, holds its I/O mutex, and calls a
  typed VFS bridge that object-matches before and after one append. Vector
  inputs are capped at 1,024 views and flattened into one bounded aggregate,
  preserving one logical `writev` mutation without partially authorized
  component writes.
- Windows `__exactFsFsyncSync` and `__exactFsFdatasyncSync` now use the retained
  typed VFS file and authorize one `fs:write` Repeat immediately before
  `sync_all` or `sync_data`. The audit exposed a conformance-model defect:
  durability evidence had treated its prerequisite open decision as an allowed
  public-surface observation. Both backends now attribute durability Repeats
  to distinct `fsync` and `fdatasync` public edges, and the harness requires
  exactly that edge with open and cleanup outside the decision window.
- Eight async-write rows become executable on each exact target, and eight
  durability rows become executable on Windows. Apple is now 23,840 required /
  2,799 fully executable / 3,136 internally verified / 17,905 unresolved with
  digest `sha256-qhSEiwMOa6vxvfvfoLl9UbDLblZJn5lUEQOSgNjLMnQ`.
  Windows is 23,499 / 2,472 / 3,122 / 17,905 with digest
  `sha256-QLOnvoW4r1Lv07dGQ-wizReH4pqeQ28UgnazkwiJbHQ`. The recipe suite
  passes 94 tests and 110,894 assertions.
- The M4 verifier compiles the complete workspace with the pinned Hermes SDK,
  passes the expanded private typed-VFS unit test, and executes both halves of
  the 16-row Apple production catalog. Physical Windows compiles the actual
  Windows C++ translation unit under strict stale-vendored enforcement and
  executes both halves of the corresponding 16-row catalog. All four native
  shards pass. The local M5 control plane still lacks a usable macOS Hermes
  framework, so it is not counted as native production evidence.
- Hard part: mutation authorization must be on the effect side of the async
  boundary, but write input is caller-owned and can change before a worker
  runs. Snapshotting and bounding it before dispatch, then authorizing the
  exact retained object immediately before one mutation, closes both the
  authority-timing and partial-vector gaps. Durability also needs its own
  attribution even though it consumes pre-existing write authority. Important
  enforcement mechanisms are about **99.2% complete** and the overall
  requested task is about **93% complete**.

### 2026-07-26 — repaired Windows append-open evidence and full-shard honesty

- Reconciled the older Windows `__exactFsOpen` write-denial contradiction.
  LLP 0021 and the installed implementation agree that an append-capable open
  submits `fs:write` at Requested before lookup; only the generated recipe was
  wrong. The recipe now selects `fs:write` for the Windows write-denial branch
  while preserving `fs:list` for read denial.
- Running the complete physical Windows catalog exposed accumulated harness
  assumptions hidden by focused slices. Retained read/readv and async-read
  setup descriptors are now closed outside observation, target-absence rows
  never enter retained cleanup, and allowed auxiliary open edges are separated
  from the exact terminal actually observed. POSIX worker attribution remains
  distinct from Windows source-specific typed edges.
- LLP 0026 still advertises the native module runner only on macOS arm64 and
  Linux x64. The Windows catalog had nevertheless promoted 19 private native
  lifecycle ABI rows merely because their symbols compiled. Those rows are now
  honestly unresolved on compatibility-only Windows with the explicit reason
  `module-runner-native-abi-not-advertised-on-target`; the Apple native fixture
  and catalog are unchanged.
- The recipe suite passes 94 tests and 110,844 assertions. After the
  moving-main integration, Apple
  is 23,846 required / 2,799 fully executable / 3,136 internally verified /
  17,911 unresolved with digest
  `sha256-hzFaFp6ca8rOPfB-aswmofNj87HnLQAhzJZgbDPfvg0`. The corrected Windows
  catalog is 23,505 / 2,453 / 3,122 / 17,930 with digest
  `sha256-Pc_rPPo2gn0lrqXTz6uXaz_x-lpoHBLXPUpeIKmUU4M`. The six added
  `compat --probe` CLI rows are unresolved on both targets and do not change
  the executable filesystem shard.
- Physical Windows, using the exact committed branch snapshot and strict stale
  vendored enforcement, passes both complete production native shards: 255
  primary rows and 244 secondary rows. The M4 verifier passes
  `cargo check --workspace` and both halves of the existing 16-row Apple
  filesystem production catalog with the corrected validator. After the
  moving-main integration changed the reviewed patch-stack identity, both
  machines rebuilt their no-debugger Hermes artifacts from the exact 12-patch
  stack (`cd3dd1da3755`). Windows ran in a fresh Cargo target directory bound
  to the rebuilt DLL digest; the two evidence artifacts both bind catalog
  digest `sha256-Pc_rPPo2gn0lrqXTz6uXaz_x-lpoHBLXPUpeIKmUU4M`.
- An exact-snapshot complete Apple run found a separate committed
  `process.cwd` install-ID disagreement before reaching this slice. It is
  recorded in `issues/20260726-capsec-process-cwd-install-id-drift.md`; it is
  not treated as evidence for or against the filesystem repair.
- Before checkpointing, `origin/main` advanced to `002ba828`; the branch
  rebased across all three incoming commits. Their Hermes 0010/0011
  classification headers changed the source-derived evaluator identity
  without changing executable behavior. Composing those reviewed headers with
  the already reviewed lockdown repair yields
  `hermes-evaluators.08bb542867d4d29fabe8e67c64eae3b78d5605fc9259dafda2e0044c41c2beae`
  and resolves the incoming lockdown-identity drift ticket.
- Hard part: a source file being compiled on a target does not make its private
  lifecycle ABI an advertised public mechanism. Exact-target evidence must
  respect the platform contract, distinguish setup from the observation
  window, and never infer cleanup ownership from a function name alone.
  Important enforcement mechanisms remain about **99.2% complete** and the
  overall requested task remains about **93% complete**.

### 2026-07-26 — completed both Apple native public shards

- Removed the checked `process.cwd` install-ID split that stopped the complete
  Apple primary shard at fixture 3. Both the JavaScript evidence validator and
  the Rust native producer now join the exact public and private install IDs to
  the checked root-global disposition manifest. A regression rejects the
  retired hard-coded ID and any manifest/evidence disagreement.
- Reconciled retained POSIX filesystem evidence with the installed runtime.
  Scalar and vector descriptor reads retain their exact open terminal;
  descriptor `readFileAsync` retains both the open and its own worker terminal.
  Windows remains on its separate source-selected typed edges. The portable
  retained write fixture now uses the current-position sentinel because
  positional writes on an append descriptor differ between Darwin and Linux.
- The complete primary shard exposed an older deferred-module linkage defect.
  Static linkage no longer tries to discover a literal dynamic target for a
  source whose dynamic edges are explicitly call-time deferred. The next
  fixture exposed a separate CommonJS-provider boundary defect: a provider had
  proved an ESM target's complete graph synchronously eligible, but the native
  binding discarded that result and rejected the target as async. The binding
  now preserves the successful admission bit; async-tainted ESM is still
  refused by the Rust provider before publication. Focused M4 tests cover both
  regressions.
- The physical M4 verifier passed the exact complete Apple production shards:
  **281 primary fixtures** and **313 secondary fixtures**, with zero failures.
  Their evidence artifacts bind Apple aarch64 engine digest
  `sha256-afSytE7VsUfboE9brsH6q0m7LA-KNYrghjCVYL05-yQ` and catalog digest
  `sha256-egBjY2PSRxWBdGqh8Cib0Zau9Miin4QnnjD4Mh_y6LQ`
  (23,846 required / 2,799 fully executable). The evidence artifact SHA-256
  values are
  `8bbc4863f2c7a52620974d6288a2c1d3819e64982ad62f3e5a0fd56c25e6570c`
  and
  `c051f006636cc5f0a5afadd6156a15c7df3d3750008044258d79b3ae4200707c`.
  Cross-shard validation merged all **594/594** executions and produced
  aggregate digest
  `sha256-pjKQVJY9H5oqPUfAd-3At7dYhftHksIn1291nfpP3ms`.
- The newly added M5 MacBook Air independently ran the complete CapSec
  JavaScript family: 824 tests passed and 17 failed across 49 files. The
  changed recipe and public-surface suites passed. The failures are
  branch-wide stale corpus debt: hard-coded residual/output counts, a reviewed
  Hermes profile identity, toy-catalog summaries, and the generated host-task
  ingress inventory. The inventory failure was the deterministic six-line
  offset caused by this checkpoint's native binding comment and was
  regenerated locally. The inherited-alias profile pin was also reconciled
  after confirming the already-reviewed 12-patch Hermes profile still exposes
  exactly the same four evaluator families and that patch 0012 only adds the
  private WebGPU ArrayBuffer alias/detach interface. Its live profile digest is
  `sha256-76318d287e6d33e65b0f84d18fb91eda561a0e9caf432d1fb74c744964090de1`;
  all 114 source-inventory tests pass. The deterministic vendored refresh also
  rotated the stale evaluator disposition install IDs, exact-runtime-dependent
  WebGPU codec authority, REPL source identity, and final source fingerprint.
  The other 15 failures are not counted as green and remain inputs to the final
  generated-corpus audit.
- While the native shards ran, `origin/main` advanced from `002ba828` to
  `e4e9bca9` with the startup-performance work. It does not overlap this
  checkpoint's nine source files, but the complete branch must be rebased and
  reverified before the physical evidence can be treated as final-tip
  promotion evidence. The post-shard evaluator/vendored identity refresh also
  means the catalog must be regenerated and both physical shards rerun after
  that rebase; the 594/594 result remains exact evidence for the explicitly
  recorded v6 catalog and engine, not for an inferred successor identity.
- Hard part: exact-target evidence spans several independent identity joins.
  A source-derived install ID cannot be duplicated in validators, setup
  decisions cannot be mistaken for the terminal under observation, and a
  call-time module provider must carry its already-proved graph property across
  the native ABI without eagerly discovering the target. Important enforcement
  mechanisms are about **99.3% complete** and the overall requested task
  remains about **93% complete** pending moving-main replay, Windows route
  audit, stale-corpus reconciliation, and the LLP 0021 completion audit.

### 2026-07-26 — replayed the complete branch onto startup-performance main

- Checkpointed the Apple shard reconciliation as `aac37a02`, created the local
  safety ref `codex/capsec-rev2-pre-main-e4e9bca9`, and replayed all 67 branch
  commits onto `origin/main` `e4e9bca9`. Four conflict sites were semantic
  compositions rather than winner selection: authenticated entry joins,
  call-time dynamic activation, synchronous CommonJS activation, and prepared
  activation retain main's startup phase markers; Windows mapped-producer
  authentication retains main's secure/insecure compile-time split and the
  combined LLP 0005 revision history.
- Main's Linux Hermes builder now publishes the matching VM CLI beside
  `hermesc`, while the download path requires their HBC versions to agree.
  Reviewed that authority rotation: it changes only the Linux source-build
  digest to
  `sha256-af521ddda077302b82de42a024eba5e708b9072462d2c4e53c742d8cc473ea92`.
  The 12-patch stack, lockdown bytes, Android and Windows identities, and exact
  reachable evaluator set remain unchanged. The reviewed evaluator identity is
  now
  `hermes-evaluators.3e6954de6300cf7cbd32f27af9077c4a0a55dc951e106a44a991791846e9971f`.
- Re-reviewed the two authenticated-ingress ranges changed by startup timing
  instrumentation. The file-graph range still validates and consumes the
  authenticated entry join before cache selection; the native execution range
  still links before evaluation and retains both dynamic and CommonJS
  invocation-time activation. Their exact source digests are
  `sha256-CFLFhkyRPRa2_Eu2bZJMb3O57Ulo8LeD7fTM5Inc2ZA` and
  `sha256-bA65eLY2kZALZnUkHwbNyg-teFvNI0-xYiJ3wpGEBCw`.
- Regenerated the complete registry, root-global dispositions, runtime
  inventory, policies, contract fixtures, embedded bundles, WebGPU identity
  artifacts, and source fingerprint. Generated drift passes with 7,657
  coverage edges, 15,314 target cells, 225 host-task ingress sites, and 22
  authenticated-ingress obligations. The focused recipe/public/evaluator
  suites pass 172 tests with 111,284 assertions; all 114 live source-inventory
  tests pass; `cargo fmt`, diff hygiene, and `ref-check` pass.
- Hard part: a performance-only build or timing change can still alter a
  reviewed security identity. The correct replay preserves both control flows,
  reviews the exact authority-byte change, and rotates every derived artifact;
  it does not copy an old trust pin because evaluator reachability happened to
  stay constant. Important enforcement mechanisms remain about **99.3%
  complete** and the overall requested task remains about **93% complete**.

### 2026-07-26 — reconciled the expanded CapSec corpus after the replay

- The M5 MacBook Air broad sweep measured the rebased corpus at 853 passing
  tests and 16 failures. Every failure was an independent expectation or toy
  fixture left behind by the already validated 7,657-edge coverage expansion;
  the coverage, ingress, registry, evaluator, and LLP contract validators
  themselves passed.
- Reconciled the exact current partitions rather than weakening validation.
  Thirty-nine filesystem rows moved from the generic effects author into the
  retained-filesystem author, leaving 565 generic effect-call rows. The
  non-capability/closed residual author now accounts for 512 rows, including
  42 newly closed callables with the honest
  `no-bounded-source-owned-receiver` reason. Output-shape accounting now binds
  all 6,569 rows and all 1,704 structural-only surfaces.
- Updated the target-absence toy catalog to carry the required
  `internallyVerifiedFixtures` summary field, and refreshed the nine-observation
  pilot's exact incomplete-report counts. These fixtures still fail closed on
  digest, target, summary, source, and plan tampering.
- The complete local CapSec JavaScript family now passes **869/869 tests
  across 49 files with 165,166 assertions**. The strengthened Host-ABI
  partition regression compares the tampered partition against the current
  59 target-absence / 508 executable / 56 residual baseline, not its retired
  predecessor.
- The Air independently generated the same rebased Apple catalog as the M4:
  digest `sha256-XKT-SU_PYWl_kSIRKNKF0-FVyQZEZvaMB6L4NWYWBoY`, with 23,846
  required / 2,799 fully executable / 3,136 internally verified / 17,911
  unresolved rows. It also completed a fresh exact 12-patch, no-debugger
  release Hermes build under the new Linux build-authority identity. The build
  gate confirms that the selected framework exports no debugger symbols, and
  the focused authenticated call-time edge plus synchronous CommonJS/ESM
  provider regressions pass against that physical engine.
- Both complete production native shards pass on the Air: **281 primary and
  313 secondary fixtures**. The evidence artifacts bind engine digest
  `sha256-3_7KDIgLCqYJI7BYS4h1rMub5L7IkAyMPBsC3IZi4yk` and catalog digest
  `sha256-XKT-SU_PYWl_kSIRKNKF0-FVyQZEZvaMB6L4NWYWBoY`; their file SHA-256
  values are
  `9b39d68921a5ec212a2e563f1b52bb375c10310fffa20da4bd412183c806ffcc`
  and
  `7b79d7a09e4b5f42e89137e0aff6aa66d3dfeec205e01774ac5268fc49f8f050`.
  Independent cross-shard validation accepts all **594/594** executions.
- After the corpus-only checkpoint, the Air advanced to exact source
  `88fe1a3339916ed7f1223dd0e51d1482f8014049` and independently regenerated
  the identical catalog digest. Rebinding the already validated physical
  batches to that clean source tree yields aggregate public-surface digest
  `sha256-sd5mN86p6W5Rv6jm0RSgV51_-AI2G0cmfCc6QPPhIfc`; no product, recipe, or
  engine bytes changed between the shard execution and that checkpoint.
- Hard part: large generated-corpus shifts can make stale assertions look like
  implementation failures, but replacing assertions with looser inequalities
  would erase the independent partition check. Each new number was derived
  from the validated source corpus, and route-specific tests still prove that
  rows moved to the intended stricter author. Important enforcement mechanisms
  remain about **99.3% complete** and the overall requested task is about
  **94% complete**, pending the remaining Windows route audit and the LLP 0021
  completion audit.

### 2026-07-26 — closed the residual Windows filesystem route plane

- Audited every filesystem global installed by the Windows engine against LLP
  0021 WP5. The retained-object routes remain typed and effectful. All other
  installed routes now refuse armed execution through one structured `EPERM`
  boundary: `__exactWriteFile`, `__exactMkdir`, `__exactRealpath`,
  `__exactReadlink`, `__exactAccess`, `__exactTruncate`, `__exactStatfs`,
  both path and descriptor `__exactFsWriteFileAsync`, every operation selected
  by `__exactFsPathAsync`, and every path/descriptor kind selected by
  `__exactFsStatAsync`.
- Each refusal precedes path conversion, descriptor lookup, caller-buffer
  acquisition, worker dispatch, and the legacy capability oracle. The
  JavaScript `writevSync` fallback also invokes its bootstrap-captured armed
  guard before splitting a logical vector write into scalar mutations on
  targets without `__exactFsWritev`. Unarmed compatibility behavior is
  unchanged.
- Physical Windows production verification executed fifteen representative
  route attempts across synchronous/async, path/descriptor,
  mutation/disclosure, existing/absent targets. All fifteen returned `EPERM`,
  neither the typed nor legacy observer recorded a row, the existing file
  remained byte-identical, absent file/directory targets stayed absent, and
  the existing directory survived. Two exact source-order contracts passed on
  both Windows and the M5 Air.
- The first full Windows integration build exposed a current production compile
  defect independent of the closure logic: non-test Windows history code uses
  `OpenOptions`, but its import was test-only. Extending the import cfg to
  Windows restored the strict production-feature build; the physical runtime
  regression and both integration contracts then passed.
- Regeneration confirms 7,657 coverage edges / 7,958 enforcement branches /
  15,314 target cells. The broad sweep exposed exact assertions that still
  described the branch's pre-expansion corpus; they were updated from the
  already validated generated results rather than weakened. The portable
  authority corpus also exposed that the
  authenticated `--no-default-features` Cargo command has eight arguments
  while its schema retained the old seven-item ceiling; the schema now admits
  the generator/workflow's exact command.
- The M5 Air independently passes the complete devtools script corpus:
  **1,294/1,294 tests across 89 files with 229,354 assertions**. Local generated
  drift, formatting, diff hygiene, `ref-check`, and the 60-test filesystem
  builtin compatibility slice pass.
- Criterion 4 is now implemented: every effectful installed Windows route is
  typed and retained-object/verified-peer bound, while every still-residual
  installed route closes before it can inspect or use an effect target.
- Hard part: a residual public operation is not safe merely because it lacks a
  promotable recipe. Dispatch families can still convert paths, look up
  descriptors, snapshot caller buffers, or queue workers before reaching an
  operation-specific branch. Closure therefore belongs at the common installed
  route boundary, before any of those inputs, while the already typed branches
  stay available.
- Important enforcement mechanisms are about **99.6% complete** and the
  overall requested task is about **95% complete**. The remaining work is the
  final eight-criterion LLP 0021 audit and the exact-target advertisement/report
  contradiction, not a known open Windows filesystem or network effect path.

### 2026-07-26 — closed process-wide diagnostics and domain builtin registries

- The final LLP 0021 audit found that two wholly closed builtin source
  families remained importable whenever an authenticated snapshot listed them.
  `node:diagnostics_channel` exposes a process-wide publication registry, and
  legacy `node:domain` exposes process-wide execution-context mutation. Their
  roots and every inventoried export are closed, so neither family has a
  supported operation that an armed principal must retain.
- The artifact-independent armed import boundary now denies both bare and
  `node:` spellings before module evaluation, even under a deliberately
  overbroad authenticated snapshot. The direct closure harness covers all 15
  diagnostics-channel and all 16 domain source/alias facets. This raises the
  exact terminal-builtin tranche from 106 to **137** rows on both targets.
- This is intentionally not a mechanical conversion of every closed builtin
  root into an import denial. Mixed modules such as `assert`, `crypto`, and
  `events` still contain supported export operations; their remaining
  import-time and export-route work must be separated or guarded without
  deleting supported capability-bearing APIs.
- The M5 MacBook Air generated the Apple catalog with digest
  `sha256-5GGNB3f6QWE6GbBW39e_wa7VFpez2_-ckfZJQ-0Dpu4`: 23,846 required /
  2,830 fully executable / 3,136 internally verified / 17,880 unresolved.
  Its loaded-engine closed batch passes **732/732**, including **137/137**
  terminal rows, with no typed or legacy authorization observation. The
  evidence file SHA-256 is
  `97de44d4e0eac2ceacd5554126e4e3139a067de2a8fe67626e1348c515db361d`.
- The physical Windows NucBox independently generated digest
  `sha256-yKG3PBJ7PdtstDTf-cgVTdVn7DEYAzp_uvebgF7LWPU`: 23,505 required /
  2,484 fully executable / 3,122 internally verified / 17,899 unresolved.
  Its no-debugger patched Hermes batch passes **711/711**, including
  **137/137** terminal rows and the exact 15/16 diagnostics/domain split, with
  zero typed and zero legacy observations. The engine digest is
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence file
  SHA-256 is
  `3fb49ce993cba10bd0207944b7861780978a58eb8874157d27d620831d2b40d4`.
- The eight-criterion audit now has current implementation evidence for
  criteria 1–6 and 8. Criterion 7 is not complete under the plan's publication
  intent: the advertisement set is empty, and LLP 0021 requires the ordinary
  supported command to flip only after at least one exact advertised target
  has a complete source-, engine-, and report-bound conformance result. Empty
  advertisements are fail-closed safety, not vacuous completion evidence.
- Hard part: a source-derived `closed` label does not by itself justify
  deleting an entire module. Module-wide closure is sound only when every
  public operation in the source family is closed and the import itself is the
  terminal; mixed modules require route-level enforcement. Important
  enforcement mechanisms are about **99.7% complete** and the overall
  requested task remains about **95% complete**, with exact-target public
  report completion now the dominant remaining program.

### 2026-07-26 — authenticated decision-free global callable evidence

- Static discovery had 600-plus deterministic decision-free global callable
  routes per target, but a route label alone was not execution evidence. The
  new `capsec_public_global_callable_batch` reaches each selected callable in
  one authenticated armed engine, drives the event loop to an authored
  one-second quiescence bound, drains authenticated publications, proves the
  exact source descriptor and cleanup, and rejects any typed or legacy CapSec
  decision.
- Promotion remains deliberately narrower than discovery. Compatibility
  routes that request environment authority remain residual. Armed startup
  does not endow the source-derived `Bun.*` aliases. Physical Apple execution
  found that `crypto.getRandomValues` and `crypto.randomUUID` currently
  terminate the process with `SIGSEGV`, and returned-object member routes fail
  before reaching their selected operation. Physical Windows execution also
  proved that its target profile does not endow the `WebSocket` receiver used
  by 14 source-derived member routes. Each of these rows remains unresolved;
  none is converted into completion evidence by weakening the harness.
- Ordinary JavaScript throws are valid source completions only when they carry
  a non-empty stable error code or error name. This matters for standard
  `TypeError` results, which generally have a stable name but no Node-style
  `.code`; anonymous throw envelopes are still rejected.
- The M5 MacBook Air generated Apple catalog digest
  `sha256-2tdkpQCnt_XpV5abe-vTl_txqPShi07-fnD9IFjmy5o`: 23,846 required /
  **3,405 fully executable** / 3,136 internally verified / 17,305 unresolved.
  Its loaded-engine callable batch passes **575/575** with engine digest
  `sha256-NKl8KlB4WVQOzjSDsuKpg1Cgez1uX0gsOqmSa0QWYAE`. The evidence file
  SHA-256 is
  `382fbaafb8acb5acc5e586fe51d76c10c2aefa44e5f93fd0ddaab84208ce509c`,
  and independent JavaScript validation produced execution digest
  `sha256-AJMqoNHau8nc2ZtmCc4dfz3V9Bh0zPp3RCrdqOxCUnY`.
- The physical Windows NucBox generated catalog digest
  `sha256-0fQLHAjYooQhB_6Ua5Lb1G4XOSBFtoZoLcc2o-BH-kY`: 23,505 required /
  **3,045 fully executable** / 3,122 internally verified / 17,338 unresolved.
  Its current no-debugger patched Hermes callable batch passes **561/561**
  with engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. The evidence file
  SHA-256 is
  `5f93dc65ee2527aa4dd8c55ad22d5977b3826ecc5d4af5fb6380285e266807bb`,
  and independent validation produced execution digest
  `sha256-9vtV6OGHuKxKLQZ0ftybT36pXX8tGKMBmqowfpQQuTw`.
- The focused recipe/evidence suite passes 145 tests with 114,743 assertions;
  generated drift, Rust formatting, and all local LLP references also pass.
  Hard part: executable public evidence must distinguish a source operation
  that throws from receiver/setup failure and from a process-terminating native
  defect. Treating all three as equivalent would silently promote static
  intent instead of runtime fact.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task is about **96% complete**. Criterion 7 is still not
  satisfied: advertisements remain empty until every required public
  obligation for at least one exact target is source-, engine-, and
  report-bound.

### 2026-07-26 — authenticated principal environment overlay evidence

- Promoted the dynamic `process.env` property surface only through the
  source-derived `Process.prototype.env` / `createEnvProxy` contract. The six
  new exact-target recipes cover read and write across allow, deny, and
  branch-selection. Reads bind `env:read` to `__exactGetEnv`; writes bind
  `env:write` to `__exactSetEnv`. The package-denied read must return the
  proxy's deliberate absent value, while the package-denied write must throw
  the production permission error.
- This slice does not generalize from an environment variable name or a native
  bridge label. Its authoring verifies the committed Proxy traps, source refs,
  selected bridge, carrier edge, exact overlay name, typed resource,
  constrained principal, and outcome. Malformed, missing-attribution,
  wrong-principal, and other unexecuted variants remain residual. The
  `NODE_PENDING_DEPRECATION` startup read was considered and rejected because
  its current use is reachable only through bootstrap-internal
  `internal/options`, not an honest production public route.
- The M5 MacBook Air generated Apple catalog digest
  `sha256-WWGvnH8dWs0jgjOez0klXutau66P6hSSUrsL32KQExs`: 23,846 required /
  **3,411 fully executable** / 3,136 internally verified / 17,299 unresolved.
  Its static-Hermes loaded-engine startup-environment batch passes **15/15**,
  including all **6/6** principal-overlay rows, with engine digest
  `sha256-6QbQa9TGsqzL8nSNcr0dd533hlfzk-sFoA16Nc5xYXc`. The evidence file
  SHA-256 is
  `1fc1f8556ab4d0179b07c5d3f33e419b0f01e8ee90020c265ed5004120bde424`;
  independent JavaScript validation produced execution digest
  `sha256-iIAcEA0hm2lB7F6SE-pw0AWyw7GvarGkv5POYmJ8s3Y`.
- The physical Windows NucBox generated catalog digest
  `sha256-NJWgX5eqErZul0u83h3GiJA0NFMF_W1JnZafEPRA1Rs`: 23,505 required /
  **3,051 fully executable** / 3,122 internally verified / 17,332 unresolved.
  Its strict stale-vendored, no-debugger patched-Hermes batch also passes
  **15/15**, including all **6/6** new rows, with engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. The evidence file
  SHA-256 is
  `a65ac848f69e4f4a43efc56f306a89e67ce027e8e6bd4bacaf53cc179747175c`;
  independent validation produced execution digest
  `sha256-evVn8Y8Kg_REeYGRsmTPW3NHw3WNwjZjsqr53tBAz1s`.
- The focused recipe/evidence suite passes 146 tests with 114,802 assertions.
  Generated drift validates 7,657 coverage edges and 15,314 target cells;
  Rust formatting, diff hygiene, and all local LLP references pass.
- Hard part: evaluating `require('image-lib')` before the `process.env`
  argument activates the package frame before argument evaluation, making the
  package-scoped global intentionally unavailable. The public harness must
  capture the real `process.env` facade first, then pass it into package code;
  the Proxy trap still derives the actual read or write principal from that
  package frame. This preserves both the public source route and exact
  principal attribution.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open: the six new physical rows reduce the residual corpus but do not make
  either exact target complete, and advertisements remain empty.

### 2026-07-26 — completed the principal environment scenario matrix

- Extended the same source-bound dynamic `process.env` carrier to the three
  remaining adapter scenarios for both actions: malformed attribution,
  missing attribution, and wrong principal. The typed adapter continues to own
  and test those invalid-input semantics. Each corresponding public receipt
  independently executes the real root-authorized Proxy route and observes its
  exact typed read or write terminal, matching the established split used by
  the effect-builtin matrix. No invalid adapter input is relabeled as a public
  engine outcome.
- The dynamic principal-overlay terminal now has executable evidence for all
  **12/12** required rows. Apple catalog digest
  `sha256-J0jMB8q7NYkDuznFOIimnFc2MpitYipuhrR9ON7OQtY` reports 23,846 required /
  **3,417 fully executable** / 3,136 internally verified / 17,293 unresolved.
  Its M5 Air batch passes **21/21**, binds engine digest
  `sha256-UN1zcVKAP0pi3H5IQblR23RMkf4d8xgueRUvege2GF4`, and has evidence-file
  SHA-256
  `544933e293f1015afbe10ec3b5cdaa98a16c668cf9c23a5329775a82dd92563b`.
  Independent validation produced execution digest
  `sha256-b1PjMQLfBma9p1jHOEN9V8RQoRGa5GIkiYz-PW1tcXo`.
- Windows catalog digest
  `sha256-_xEeVmEtfn8vN7Gxsh-5vQW-nqBl-xRAQLgVFw-AG78` reports 23,505 required /
  **3,057 fully executable** / 3,122 internally verified / 17,326 unresolved.
  The physical strict stale-vendored batch passes **21/21**, including all
  **12/12** overlay rows, against engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. Its evidence-file
  SHA-256 is
  `d68f380482f5def6767a37643eebcf7cf947b2d28ec723a1fc63293ef915ceb5`,
  and independent validation produced execution digest
  `sha256-1hx2YA4ejH2ueYl6TxfqqTCABhdezARoZINBAOVN73U`.
- The focused recipe/evidence suite remains 146/146 and now performs 114,859
  assertions. Hard part: adapter-case coverage and loaded-engine public
  execution are complementary proofs, not interchangeable labels. Promotion
  requires both the scenario's adapter fixture and a separately authenticated
  execution of the source-selected public terminal.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — completed three pure-read startup environment matrices

- Extended the three already curated startup environment source carriers
  (`startup:env:NODE_DEBUG`, `startup:env:EXACT_DEBUG_EMIT_LISTENER`, and
  `startup:env:TZ`) from allow/deny/branch-selection to the complete six-scenario
  public-evidence matrix. All **18/18** pure `env:read` absent-branch recipes
  are now executable; the same batch retains the previously completed
  **12/12** dynamic principal-overlay rows.
- Promotion remains source- and action-specific. The author verifies each
  committed source descriptor, exact environment name, absent branch, native
  `__exactGetEnv` carrier, typed resource, and expected outcome. Mixed-action
  startup sites that also require `stdio:write` or `sys:read` remain residual;
  a pure-read proof is not used to promote those additional terminals. The
  three curated carriers retain six honest residual rows apiece.
- Apple catalog digest
  `sha256-z6G-WjNj134dtSYv0Y-PrO4pIz3cSJ4C5xH-8pewSu8` reports 23,846 required /
  **3,426 fully executable** / 3,136 internally verified / 17,284 unresolved.
  The physical M5 MacBook Air static-Hermes batch passes **30/30**, binds
  engine digest
  `sha256-Ine2_Krvm-pHkSdQUQbvCH3qWYsejXCOvvbceDA72_w`, and has evidence-file
  SHA-256
  `c7d7c45c84d40590eab372c686e0de5eec017e11910c5391cb5a6c8da1e1b733`.
  Independent validation produced execution digest
  `sha256-qSvS_YPcLgXXG_izUEtrBgiuym2HtmSEULGkX04LekU`.
- Windows catalog digest
  `sha256-1fU3hW81_Hg67qM12J0iSJGiBnHRWE8XXVl0ksfbV_o` reports 23,505 required /
  **3,066 fully executable** / 3,122 internally verified / 17,317 unresolved.
  The physical NucBox strict stale-vendored batch passes **30/30** against
  engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. Its evidence-file
  SHA-256 is
  `23d8c9e21736ee4e2f2ecb49ee63da39eae7041ab9dc558f77f66be0e8b26f53`,
  and independent validation produced execution digest
  `sha256-8meS0hTiHFcydMsaVP9d6u38RkDuPuZAOTnJEnMiYsc`.
- The focused recipe/evidence suite passes 146 tests with 114,976 assertions.
  Hard part: malformed, missing-attribution, and wrong-principal are adapter
  inputs that the public JavaScript route cannot honestly manufacture. As with
  the principal-overlay and effect-builtin matrices, each row therefore
  requires both its exact adapter-case proof and a separate loaded-engine
  execution of the normal source-selected typed terminal. Neither half is
  represented as the other.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — bound paired stream-debug environment reads

- Promoted the absent branches for `startup:env:EXACT_PIPELINE_DEBUG` and
  `startup:env:EXACT_PIPELINE_STATE_DEBUG` through the real `node:stream`
  module initialization. That source unavoidably reads both names in order, so
  every recipe binds the complete two-name source-owned resource set and every
  typed decision rather than presenting either read as an isolated operation.
  All **12/12** absent-branch rows now have executable evidence.
- The source descriptor pins both committed `stream.js` occurrences, the exact
  module and preloads, both environment selectors, the native
  `__exactGetEnv` carrier, and the package/root principal mode. A new negative
  validator regression replaces the companion resource on the third typed
  decision and proves the evidence is rejected. The two present branches
  remain residual because they also select `stdio:write`; the pure-read source
  proof is not reused for that effect.
- Apple catalog digest
  `sha256-zJsybqnXCKiaWdYWYwUq5a6LGIYFU3t8T2oPmbyRxhw` reports 23,846 required /
  **3,438 fully executable** / 3,136 internally verified / 17,272 unresolved.
  The physical M5 MacBook Air batch passes **42/42**, including all 12 paired
  stream rows and the prior 30 startup/principal rows, with engine digest
  `sha256-KheKyPAs4QTgQqDiiy-5NMRjU8US9QwenE9JSe69nPs`. The evidence-file
  SHA-256 is
  `3bb7652659aba3ee7a5db4f3a53d8f9983969ed75fbe86e4ff9a4c5c2da49908`;
  independent validation produced execution digest
  `sha256-IBW9SEkjOKanKXmnwF8ggN39R99UD-uRQ0d6QHL05T8`.
- Windows catalog digest
  `sha256-Y6lmlPVOGp9OY8yiqO9emGhSe9-3j_F9hEd_7zuqt-8` reports 23,505 required /
  **3,078 fully executable** / 3,122 internally verified / 17,305 unresolved.
  The physical NucBox strict stale-vendored batch passes **42/42** against
  engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. Its evidence-file
  SHA-256 is
  `2485a04ff7a93a49555788f6f00f19c23076eb20a6f82f08dbe49334394226d7`,
  and independent validation produced execution digest
  `sha256-eylc8N4abHt50jOYBdKEzgbX5dmq2LUSw1NcFL7cxpM`.
- The focused recipe/evidence suite passes 146 tests with 115,139 assertions.
  Hard part: the paired denial legitimately emits two denial outcomes. The
  first physical artifact exposed a harness label that recognized only the
  old one-element denial vector; independent artifact validation rejected it.
  The corrected harness requires every outcome to be denied, and the
  regenerated physical artifacts pass. This is why execution generation and
  independently implemented validation remain separate gates.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — bound paired TTY-size environment reads

- Promoted the absent branches for `startup:env:COLUMNS` and
  `startup:env:LINES` through the public `node:tty`
  `WriteStream.prototype._refreshSize` route. The harness preloads the builtin
  outside observation, invokes the real prototype method on a harness-owned
  receiver, and binds its exact ordered `COLUMNS`/`LINES` resource set. All
  **12/12** absent-branch rows now have loaded-engine evidence.
- Both targets prove root allow and package denial attribution for the paired
  reads. The receiver remains unchanged when both values are absent. The
  present branches remain residual because their inventory obligation also
  selects `stdio:query`; the environment-only execution does not promote that
  additional effect.
- Apple catalog digest
  `sha256-6c20BVnjScUZH4m63tl47GY1RqtBc5Gb0yHcp05e0-A` reports 23,846 required /
  **3,450 fully executable** / 3,136 internally verified / 17,260 unresolved.
  The physical M5 MacBook Air batch passes **54/54**, including all 12 new TTY
  rows, with engine digest
  `sha256-f8Jb08iKLGJTA1w83zNARMfU_WhHjptQV56PZs1BmSQ`. The evidence-file
  SHA-256 is
  `5c8d8c8424b48baa33726ef936ac057d28aec91f065b6109fea5447bcd3348d1`;
  independent validation produced execution digest
  `sha256-6EjuwTVvhHmbY5eewZvhSPi0kDlSjctG2edr4A4dqDg`.
- Windows catalog digest
  `sha256-O3ojTNTD8AOT9AVZtf1PNjl1kVlt3lAydHtkas1Ytgg` reports 23,505 required /
  **3,090 fully executable** / 3,122 internally verified / 17,293 unresolved.
  The physical NucBox strict stale-vendored batch passes **54/54** against
  engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. Its evidence-file
  SHA-256 is
  `a331edfc1c45a2399b093419e02333b22907ae23924339a1ee89ad7423d85a1c`,
  and independent validation produced execution digest
  `sha256-F1dlyH72aOSSkerYSCBHRdIcwRrqjANu0xPhVeDp_-0`.
- The focused recipe/evidence suite passes 146 tests with 115,299 assertions.
  Hard part: constructing a full `WriteStream` would also enter socket setup
  and conflate unrelated behavior with the two environment reads. Invoking the
  exported prototype method on an owned receiver reaches the exact production
  source while bounding the operation to its two reads and observable size
  result.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — bound the repeated TTY-color environment sequence

- Promoted the absent branches for `startup:env:FORCE_COLOR` and
  `startup:env:COLORTERM` through the public `node:tty`
  `WriteStream.prototype.getColorDepth` route. Its safe absent path performs
  five reads in exact source order: `NO_COLOR`, `FORCE_COLOR`, `COLORTERM`,
  `COLORTERM`, and `TERM`. The evidence schema now binds both the canonical
  four-name resource set and this ordered access sequence, including the
  repeated lookup.
- All **12/12** exact `tty.js` carrier rows for `FORCE_COLOR` and `COLORTERM`
  now have loaded-engine evidence. The companion `NO_COLOR` and `TERM` reads
  are recorded but not promoted: their selected inventory terminals include
  different source carriers. The present branches also remain residual because
  they add `stdio:write`.
- Apple catalog digest
  `sha256-knmVvX2l4_ZJnn8pRQuGsngY0_d0v9SO4lekwf2eyKM` reports 23,846 required /
  **3,462 fully executable** / 3,136 internally verified / 17,248 unresolved.
  The physical M5 MacBook Air batch passes **66/66**, with up to ten typed
  decisions per color recipe and engine digest
  `sha256-XkI3ntNk3zPGfwUpBuS-SUSsB3m6iDlfRxQAJhNouf0`. The evidence-file
  SHA-256 is
  `c14f24ce27f53f6823167709140256ed80516652d1a5b6af2193a61d676970ca`;
  independent validation produced execution digest
  `sha256-7L7kmVBlcjHqDnoljuFxvVYDWy3jBoJ155s2nph6-Mw`.
- Windows catalog digest
  `sha256-B8BxoYbsc_7dWnQkUeHJX57OacyoGuYLBfsIKLxBjOU` reports 23,505 required /
  **3,102 fully executable** / 3,122 internally verified / 17,281 unresolved.
  The physical NucBox strict stale-vendored batch passes **66/66** against
  engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`. Its evidence-file
  SHA-256 is
  `d93c58ddb273c0106d31b6f78c38edd6111c94a39a088b266d76d9c023619081`,
  and independent validation produced execution digest
  `sha256-Xx62D56Clpb1f7ZN1ZUj4gkIhC0Zz9BKc1veUuhuhso`.
- The focused recipe/evidence suite passes 146 tests with 115,459 assertions.
  Hard part: a unique resource set cannot prove a source that reads the same
  resource twice. The verifier now separately binds the canonical authority
  set and the ordered access sequence, then maps every requested/commit or
  denied decision to the corresponding access. Removing, reordering, or
  relabeling the second `COLORTERM` read invalidates the artifact.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — executed bounded builtin output routes and retired crash claims

- Reused the independently authored output-shape operations for a deliberately
  narrow set of non-capability builtin exports. Each conformance receipt binds
  the exact source descriptor and inner call/construct/get route, then requires
  one normal source return, route-owned cleanup, one-second event-loop
  quiescence, and zero legacy or typed CapSec decisions. The conformance author
  never reads or trusts the reviewed output disposition.
- Physical execution admits exactly **54** new routes across ten source
  families: `exact_process`, `node_buffer`, `node_console`, `node_events`,
  `node_perf_hooks`, `node_string_decoder`, `node_timers`,
  `node_timers_promises`, `node_url`, and `node_util`. The split is 38 calls,
  9 constructions, and 7 property gets. The independent aggregate revalidates
  the source/coverage join, descriptor access, concrete runtime value shape,
  cleanup, quiescence, and zero-decision result rather than accepting the
  runner's normalized label.
- The first broad physical run exposed an important pre-existing honesty bug:
  several ordinary builtin recipes had been generated but never survived the
  bound static-Hermes process. Crypto key/prime generation, synchronous KDFs,
  `Hmac.digest`, and the random family terminated the process. Zlib one-shots
  and native-processing stream methods also terminated it. Illegal
  `perf_hooks` constructors threw, and `node:v8` serialize/deserialize returned
  `ERR_METHOD_NOT_IMPLEMENTED`. Those rows are now residual. The executable
  count therefore decreases despite adding 54 real receipts: this checkpoint
  removes claims that static argument authoring could not substantiate.
- Apple catalog digest
  `sha256-zw0z_3pbjsuwzxFjhx-rrxNhnUaa1KYB2-5-b5YkUx8` reports 23,846 required /
  **3,415 fully executable** / 3,136 internally verified / 17,295 unresolved.
  The M5 MacBook Air static-Hermes batch passes **1,135/1,135**: 34 isolated
  module imports, 1,047 established export routes, and all 54 captured routes.
  It binds engine digest
  `sha256-GY41wqT-o2FQKLtIAN_Jvaepc4b0fhdgo4wRqbzVwtc`; the evidence-file
  SHA-256 is
  `28f93a6a0cc2543b01b6e8a407d052d31841a05cbc67c724ad760a1ea4a34f16`,
  and independent validation produced execution digest
  `sha256-Er20K0TmndcXTv_eoWlrH9s0l8epjeehv4NaQsDKdXs`.
- Windows catalog digest
  `sha256-q1CMvM3BqyZT0mElimLGvbDSRFMi6GZuwythDEXw2aE` reports 23,505 required /
  **3,074 fully executable** / 3,122 internally verified / 17,309 unresolved.
  The physical NucBox strict stale-vendored batch passes **1,099/1,099**: 34
  isolated imports, 1,011 established exports, and all 54 captured routes. It
  binds engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `9904de6ff3ade87292eb0cb6312a1d65abcb8198024ec79e58e1780f342c2a83`,
  and independent validation produced execution digest
  `sha256-gOk8IiqExqC9ztojIMtMo1oXer6uHgvmqJTIhzFakM8`.
- The focused recipe/template/evidence suite passes **152/152** tests with
  124,399 assertions. Generated drift validates 7,657 coverage edges and
  15,314 target cells; Rust formatting, diff hygiene, and all local LLP
  references pass.
- Hard part: an output recipe is an operation author, not execution evidence.
  Opening hundreds of statically plausible routes immediately produced a
  process crash; even the narrower run reached stale recipes in the older
  standard phase before it reached the new captured phase. Progress required
  isolating each terminating public route, residualizing the complete unsafe
  family where lifecycle behavior was shared, and rerunning the entire family
  on both physical targets. A crash, deliberate throw, or unimplemented method
  is never converted into normal-return evidence.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open: both exact catalogs still have large honest residual sets, and both
  advertisement sets remain empty.

### 2026-07-26 — executed get-only stream state evidence

- Added the next operation-scoped captured-output tranche: **41** property
  reads on harness-owned `Duplex`, `PassThrough`, `Readable`, `Transform`, and
  `Writable` instances. The policy admits only `get` routes for `node_stream`;
  its 44 remaining call routes and constructor route stay residual. Each read
  binds the exact inherited/exported property descriptor, destroys the owned
  stream, reaches one-second quiescence, and observes zero CapSec decisions.
- The 41 rows cover the eight readable state properties on each of four
  readable owners and the nine writable state properties on `Writable`. Data,
  accessor, and source-unknown inventory shapes are accepted only when the
  authored operation is a property get and the physical descriptor proof
  matches the exact access path.
- Apple catalog digest
  `sha256-Be18qOUto6Lq0UJzVt90w2uy9vtqZR57JwgdZ7OsUnI` reports 23,846 required /
  **3,456 fully executable** / 3,136 internally verified / 17,254 unresolved.
  The M5 MacBook Air batch passes **1,176/1,176**: 34 isolated imports, 1,047
  established exports, and 95 captured routes including all 41 stream gets.
  It binds engine digest
  `sha256-GY41wqT-o2FQKLtIAN_Jvaepc4b0fhdgo4wRqbzVwtc`; the evidence-file
  SHA-256 is
  `7db3b44aa3de5bf5a2edc92f86316d2e1a18aaa3f65df687d09fb0eb0be0e65d`,
  and independent validation produced execution digest
  `sha256-EkuhWUnNa_tZIgJC8VBR7O4zf9bwBODphTVV2Y_9SVU`.
- Windows catalog digest
  `sha256-HTO17Y6uyDgmUyL1OuGT8IuelzzYD48brJ31RDu4wek` reports 23,505 required /
  **3,115 fully executable** / 3,122 internally verified / 17,268 unresolved.
  The physical strict stale-vendored batch passes **1,140/1,140**: 34 isolated
  imports, 1,011 established exports, and the same 95 captured routes. It binds
  engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `34ace5cedaffcd6debc8ed15e25831bb494ac33f9ef86201b27c2bab4a58b5c9`,
  and independent validation produced execution digest
  `sha256-XvsHLKUe2vxHL4K7qUahQ3YfgHke-_96eEJ1E17_xU4`.
- The focused recipe/template/evidence suite remains **152/152** and now
  performs 125,016 assertions.
- Hard part: a source-family allowlist would also have opened stream
  composition, piping, async iteration, and deferred promise routes. The
  conformance policy therefore binds both source family and operation class;
  physical proof for passive state reads cannot promote lifecycle-changing
  calls that happen to share the same module.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — executed exact HTTP value routes without opening network lifecycles

- Added nine captured-output routes by exact source, export, and operation:
  the four pure `node:http` header helpers, `CloseEvent`, `MessageEvent`,
  `HTTPParser`, and the two `node:http2` settings codecs. The constructors use
  no socket or server, and every route must still prove one normal inner source
  return, cleanup, one-second quiescence, and zero typed or legacy decisions.
- The admission policy does not allow either HTTP source family generally.
  `createServer`, `createSecureServer`, agents, client requests, server
  close/ref/unref methods, and every other connection-owned route remain
  residual. The captured set is now **104** routes: 44 calls, 12
  constructions, and 48 property gets across 13 source families.
- Reconciled three additional `main` landings before checkpointing. The composed
  reviewed evaluator identity, range affirmations, and generated corpus pass
  the full drift chain at 7,658 coverage edges, 15,316 target cells, 169
  environment rows, and 225 host-task ingress sites. The newly reviewed
  producer-hold startup environment row is honestly residual and adds one
  required fixture on each target. Both physical engines and catalogs were
  rebuilt after the two corpus-affecting merges; the final docs-only landing
  changed no catalog or physical-engine input, and no pre-merge evidence is
  cited below.
- Apple catalog digest
  `sha256-y3iSHPHz5I3c7JTXlN8wES10zftbMaO8p0IhDNcLAgA` reports 23,847 required /
  **3,465 fully executable** / 3,136 internally verified / 17,246 unresolved.
  The M5 MacBook Air static-Hermes batch passes **1,185/1,185**: 34 isolated
  module imports, 1,047 established exports, and all 104 captured routes. It
  binds engine digest
  `sha256-KxH8T10HAD6aW2BDb-NpVJxOnM5HuDZK-FrBuaDBo0w`; the evidence-file
  SHA-256 is
  `be0d284094c920f5c7d163ad4ed520e5e11424e7f1af27628235ab7ce92329f9`,
  and independent validation produced execution digest
  `sha256-tdytjFKyEu-MvdbddUrsUsGtsdlgxFxNA56Wdrk9lL8`.
- Windows catalog digest
  `sha256-eENwflh_0LAyycHqAPVXnLJUJrxnm2B7lkuXSItZ2No` reports 23,506 required /
  **3,124 fully executable** / 3,122 internally verified / 17,260 unresolved.
  The NucBox strict stale-vendored batch passes **1,149/1,149**: 34 isolated
  imports, 1,011 established exports, and the same 104 captured routes. It
  binds engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `d73fbdaeaacbb84f8578602d076531bcf5afb8c5c6401c9729101178c41d8b8d`,
  and independent validation produced execution digest
  `sha256-392XVsdbkAP67cVjrvyc27d9kvbLO9WBvN1v4f2oXsk`.
- The focused recipe/template/evidence suite passes **152/152** with 125,152
  assertions.
- Hard part: operation-class admission is still too broad for a module that
  mixes pure value transforms with external lifecycle ownership. `call` would
  include server factories and request teardown, while `construct` would
  include live servers. The policy therefore names the nine exact
  export/operation pairs; physical success for an HTTP settings codec cannot
  promote an unrelated network route.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — executed exact in-memory SQLite value routes

- Added 17 captured-output routes by exact `exact_sqlite` export and operation.
  Fresh harness-owned `:memory:` databases prove `_checkClosed`, `_closed`, and
  `inTransaction` on both the `Database` and default public owners. Fresh
  `SELECT 1 AS value` statements prove `as`, `_checkFinalized`,
  `_normalizeParams`, `finalize`, `toString`, `columnTypes`, `declaredTypes`,
  `_finalized`, and `native`; the harness executes the statement before the
  `declaredTypes` read and always finalizes the statement and closes its
  database. `SQLiteError` and its inventoried constructor route use standalone
  bounded values.
- The admission policy names all 17 export/operation pairs. It does not admit
  `exact_sqlite` generally, file-backed databases, extension loading, cr-sqlite
  enablement, or any query/mutation family. The captured set is now **121**
  routes: 51 calls, 14 constructions, and 56 property gets across 14 source
  families.
- Apple catalog digest
  `sha256-XyEf2X86unMP8y_QcD6XcENbYMSRZGa_VSkY1XNCjCA` reports 23,847 required /
  **3,482 fully executable** / 3,136 internally verified / 17,229 unresolved.
  The M5 MacBook Air static-Hermes batch passes **1,202/1,202**: 34 isolated
  module imports, 1,047 established exports, and all 121 captured routes. It
  binds engine digest
  `sha256-KxH8T10HAD6aW2BDb-NpVJxOnM5HuDZK-FrBuaDBo0w`; the evidence-file
  SHA-256 is
  `8c1dfc3064d579b3bb78d76ab879ff1d77f71fe25ca23de8df3e34390a04efa6`,
  and independent validation produced execution digest
  `sha256-ZUW9Zj6BN1BIytVGPX0TBcUbOVBaZGi7YFm2-2FvYV0`.
- Windows catalog digest
  `sha256-pngQJx_ssIHmfNrwygkua1ZoWMozAODgQGaQxAlaVuE` reports 23,506 required /
  **3,141 fully executable** / 3,122 internally verified / 17,243 unresolved.
  The NucBox strict stale-vendored batch passes **1,166/1,166**: 34 isolated
  imports, 1,011 established exports, and the same 121 captured routes. It
  binds engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `dd14fddb3a20fe8476d4691f82541da48bd817faad01e71019d2d768dd83a9be`,
  and independent validation produced execution digest
  `sha256-IVaVfpNX12FHVyGJnX_nbwNNJ5-S6V93Zi64rfH4ZEw`.
- Both independent aggregates bind source revision
  `973712aafe2f4ca7b259f38b0f7f43351d507a8b` and tree digest
  `sha256-Yac62hDty1ld2gu8kAYlGHmxxJJDbGsBLyT9aIw5szc`. The focused
  recipe/template/evidence suite passes **152/152** with 125,408 assertions.
- Hard part: the first physical tranche deliberately included the statically
  bounded `deserialize` route. Both the route author and catalog accepted its
  empty byte input, but the loaded Apple engine returned the explicit error
  `Database deserialization not supported`. A deliberate throw is not a
  normal-return proof, so `deserialize` was removed from the allowlist and
  remains residual; both target batches were regenerated and rerun with the
  exact 17-route set.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — executed exact TLS value and context helpers

- Added six captured-output routes by exact `node_tls` export and operation:
  `checkServerIdentity`, `convertALPNProtocols`, `createSecureContext`,
  `getCACertificates`, `SecureContext`, and `translatePeerCertificate`.
  Inputs are bounded hostnames, certificate-shaped data, ALPN values, or an
  empty context configuration. None of the recipes creates a socket, server,
  client, handshake, or peer lifecycle.
- The admission policy names the six export/operation pairs instead of
  admitting `node_tls` generally. Every connection-owned TLS surface remains
  residual. The captured set is now **127** routes: 56 calls, 15
  constructions, and 56 property gets across 15 source families.
- Apple catalog digest
  `sha256-jorAAIHinwwVJAzDX1S3HoqPsANH0mnV5-s3_lY0MKk` reports 23,847 required /
  **3,488 fully executable** / 3,136 internally verified / 17,223 unresolved.
  The M5 MacBook Air static-Hermes batch passes **1,208/1,208**: 34 isolated
  module imports, 1,047 established exports, and all 127 captured routes. It
  binds engine digest
  `sha256-KxH8T10HAD6aW2BDb-NpVJxOnM5HuDZK-FrBuaDBo0w`; the evidence-file
  SHA-256 is
  `59eb641d7625db9aa21a34f5b2abbedbc8e03005afd7cfed1982c31b292d9fc3`,
  and independent validation produced execution digest
  `sha256-4nEzRtylnWSCPE6mmh4V_7VXv-_hSJsG2HBl5F1eC5E`.
- Windows catalog digest
  `sha256-WOa2OYe3hWmbbXJiVbz_0cWA3C5Ae8K7P7islt4xpc8` reports 23,506 required /
  **3,147 fully executable** / 3,122 internally verified / 17,237 unresolved.
  The NucBox strict stale-vendored batch passes **1,172/1,172**: 34 isolated
  imports, 1,011 established exports, and the same 127 captured routes. It
  binds engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `fe3963b3825c2b46c5ed07dbee973051d51edfe72a7c9f4a45bcb3849070ecd8`,
  and independent validation produced execution digest
  `sha256-GQECzM81QBK5tHt_JXyDa_gVLnhQWOq-j_YFUAqFEDU`.
- Both independent aggregates bind source revision
  `f672d58c4fed34f7e00ebbb668e164158b8894c2` and tree digest
  `sha256-6NIZWW2LKa4D5pimQWiaVaPxDBa7-kcmeUMp3Gagt8Q`. The focused components
  pass **152/152** with 125,499 assertions. One combined invocation spent 65.7
  seconds constructing both target catalogs and exceeded its 60-second setup
  limit after the other 55 tests passed; the isolated 97-test recipe rerun
  completed green in 36.3 seconds.
- Hard part: `node_tls` is mostly an external lifecycle family, so a
  source-family exception would silently promote clients, servers, sockets,
  and handshakes. The six value/context helpers are the narrow exception:
  physical execution on both target engines proved a normal source return,
  cleanup, quiescence, and zero decisions without using a peer.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — executed exact assert promise validators

- Added exactly two captured `node_assert` calls: `doesNotReject` receives a
  harness-owned resolved promise, and `rejects` receives a harness-owned
  rejected promise whose rejection is consumed by the public validator. Both
  routes must return normally, reach one-second event-loop quiescence, clean up,
  and emit zero legacy or typed CapSec decisions.
- `assert.fail` is deliberately absent from the allowlist: its authored public
  behavior is to throw. The admission policy names only the two promise
  validators, leaving every other assert route unchanged. The captured set is
  now **129** routes: 58 calls, 15 constructions, and 56 property gets across
  16 source families.
- Apple catalog digest
  `sha256-NcAfJZRhbklSkS1AUm7qpZXivrkR-XJJsZoNOxnBH1Y` reports 23,847 required /
  **3,490 fully executable** / 3,136 internally verified / 17,221 unresolved.
  The M5 MacBook Air static-Hermes batch passes **1,210/1,210**: 34 isolated
  module imports, 1,047 established exports, and all 129 captured routes. It
  binds engine digest
  `sha256-KxH8T10HAD6aW2BDb-NpVJxOnM5HuDZK-FrBuaDBo0w`; the evidence-file
  SHA-256 is
  `19aa823f86c314ad0019ae8b01252af6d1877904198aa621917bd52bb760c68c`,
  and independent validation produced execution digest
  `sha256-51sPezmhB-egK2_UljD6HUPgjN4NB5gaPTK6sx-n2jM`.
- Windows catalog digest
  `sha256-PFauzdJ6M2OIlmEecIAxOEBI1MLxHNxbAP9lAanEJ2A` reports 23,506 required /
  **3,149 fully executable** / 3,122 internally verified / 17,235 unresolved.
  The NucBox strict stale-vendored batch passes **1,174/1,174**: 34 isolated
  imports, 1,011 established exports, and the same 129 captured routes. It
  binds engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `295c9c7d391633eca0d9cb54fe6db445e7b7ada004ce1992054f1cd1fd922dd5`,
  and independent validation produced execution digest
  `sha256-erbVb9KN6kJQW2fHUPNpZR7B0EEATGIEOyvmAGr7Ojg`.
- Both independent aggregates bind source revision
  `3c07dfe5af2d9a6ff5783b274fdb46d6b7f606df` and tree digest
  `sha256-SboysAN7CTyH8NuyDM8gYbENvyQU39ZfZPSc5VXZgB8`. The split focused runs
  pass **152/152** with 125,530 assertions.
- Hard part: static route authoring offers three nearby assert calls, but one
  is definitionally incompatible with the normal-return evidence contract.
  Selecting the module family or operation class would promote `fail` merely
  because the two promise validators succeeded. The exact export-pair policy
  keeps the deliberate throw residual without weakening the runtime evidence
  schema to accept exceptions.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

### 2026-07-26 — executed harness-owned filesystem object lifecycles

- Added five exact filesystem lifecycle routes without opening a real path or
  descriptor: `node_fs` synthetic `Dir.close`/`closeSync`, construction and
  immediate cleanup of an unstarted `FSWatcher`, and `node_fs_promises`
  construction/cleanup plus `close` on a null-backed `FileHandle`. Each route
  binds the inventoried descriptor, proves a normal return and owned cleanup,
  reaches quiescence, and records zero decisions.
- The exact policy excludes top-level `close(-1)` and `closeSync(-1)`, whose
  authored purpose is an invalid-descriptor error. It also excludes
  `FileHandle.emit` and `FileHandle.on`: the first physical Apple tranche
  proved that both inventoried members are absent from the loaded public
  descriptor. The captured set is now **134** routes: 61 calls, 17
  constructions, and 56 property gets across 18 source families.
- Apple catalog digest
  `sha256-Pgm5GFnHN4XkwW0HEppADA3fyEGRmmUKCuPlwhjbwBQ` reports 23,847 required /
  **3,495 fully executable** / 3,136 internally verified / 17,216 unresolved.
  The M5 MacBook Air static-Hermes batch passes **1,215/1,215**: 34 isolated
  module imports, 1,047 established exports, and all 134 captured routes. It
  binds engine digest
  `sha256-KxH8T10HAD6aW2BDb-NpVJxOnM5HuDZK-FrBuaDBo0w`; the evidence-file
  SHA-256 is
  `a42d98702fe1996923e44a7bbfb7f42b0ce189423ab8592205e93284e75e4569`,
  and independent validation produced execution digest
  `sha256-s_f5jZxwiYQUjyJFE_Ab2PwzW9OGFH5IKjzVytY0pb0`.
- Windows catalog digest
  `sha256-pZFBFmPVlxnLDiaeyd9exWrZ3PYjy_qm9Vn81Gcfvbs` reports 23,506 required /
  **3,154 fully executable** / 3,122 internally verified / 17,230 unresolved.
  The NucBox strict stale-vendored batch passes **1,179/1,179**: 34 isolated
  imports, 1,011 established exports, and the same 134 captured routes. It
  binds engine digest
  `sha256-xqWHmqF0mGjVqhS8bUI7Av9fiP84rE8Zj23kOq9JJw8`; the evidence-file
  SHA-256 is
  `e1bff282f852b7786a3d272c5c1d71a9b02ff5ee8fa9461911dea11eba37cee2`,
  and independent validation produced execution digest
  `sha256-i9HVRRUeW37SEsIBo3uYRpiCcp8Agjm15qANxk1TT8w`.
- Both independent aggregates bind source revision
  `97e1f3aa1a7819f554e844fdc7a1fe7f02f5ff1a` and tree digest
  `sha256-Twbj7bfACdWZIHDFETy24FShvnLLcFoqDBatKiuZtHg`. The split focused runs
  pass **152/152** with 125,606 assertions.
- Hard part: source inventory is an obligation, not a claim that a property
  exists on every loaded public implementation. The two FileHandle event
  members looked bounded and source-authored, but the physical descriptor
  proof returned `absent`; accepting that as a normal call would conflate
  target absence with execution. They remain residual while the five exact
  routes with real loaded descriptors are promoted.
- Important enforcement mechanisms remain about **99.7% complete**, and the
  overall requested task remains about **96% complete**. Criterion 7 remains
  open and both advertisement sets remain empty.

## Next milestone

Continue the exact-target report program without advertising either target:
select the highest-leverage residual public-evidence family, add a
source-bound executor only where it reaches the real production route, and
regenerate both target catalogs. Continue separating remaining startup,
environment, and loader operations that can be safely executed from those that
must remain closed. Do not treat the empty advertisement set as criterion 7
completion, and do not convert catalog labels or generic failed imports into
public execution evidence.
