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
| 2. Every production surface has classification and target cell | Implemented | The generated registry currently validates 7,602 coverage edges and 15,204 target cells with zero drift. |
| 3. Canonical policy and snapshots are typed, deterministic, digest-bound, fail-closed | Implemented | Strict policy/snapshot schemas, canonical-JCS digests, protected-artifact joins, and mismatch/forgery suites pass in the secure gate. |
| 4. Filesystem/network bind used object or peer with staged authorization | Implemented for the supported runtime surface | Retained VFS objects, symlink/race fixtures, verified-peer records, and repeat-stage leases pass. Residual operations remain closed rather than entering an advertised profile. |
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

## Next milestone

Attack criterion 7's exact-target evidence gap through real public-surface
authoring or honest closure, then run the combined ceremony to completion.
