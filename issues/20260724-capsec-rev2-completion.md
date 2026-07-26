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
| 4. Filesystem/network bind used object or peer with staged authorization | In progress; unproved routes remain unadvertised or fail closed | Retained VFS objects, symlink/race fixtures, verified-peer records, and repeat-stage leases pass for promoted routes. The audit previously overstated this criterion: installed Windows worker-backed scalar/vector filesystem I/O and TCP still use legacy paths, while residual operations remain outside every advertised profile. |
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

## Next milestone

Continue criterion 4 with the next installed Windows worker boundary. The
leading candidate is scalar/vector `__exactFsReadAsync` /
`__exactFsReadvAsync`: each must retain owner/principals/object/bearer, define
atomic caller-buffer publication, and recheck the current generation at the
actual worker acquisition boundary. The Windows typed TCP peer path remains
the other named criterion-4 gap. Do not advertise Windows while installed
legacy routes or 17,937 exact-target public-evidence rows remain unresolved,
and do not convert catalog labels into completion evidence.
