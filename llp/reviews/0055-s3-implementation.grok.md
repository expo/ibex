# Review: LLP 0055 S3 implementation — grok (code round 1)

**Reviewer:** grok-4.6, effort xhigh, headless (`--prompt-file`, `--output-format plain`), full repository access, same commissioning prompt as the codex round (mutually blind).
**Date:** 2026-08-25. **Requested by:** the LLP 0055 S3 lane (dual-family code round).
**Verdict:** READY, no materials; six minors recorded (1 and 3 subsumed by the fix round; 2, 4, 5, 6 recorded as accepted nits/incompleteness for later slices).

---

I'll review the LLP 0055 S3 implementation against the spec: first the review skill and governing spec, then the four-commit diff and the load-bearing claims.The four-commit range is `origin/main..HEAD`. I'll load the governing spec, collect the full diff, and verify each load-bearing claim against the source.The branch is four commits ahead and nine behind `origin/main`; I’ll separate the S3 commit range from the tree-diff noise and inspect the implementation files next.I'll review the four-commit merge-base range and pull the load-bearing implementation files plus targeted diffs.The spec and surface are in place. Next I’ll inspect the engine commit ABI, pipeline decoupling, loader invalidator, and the f5/f7 fixtures in parallel.Subagents are covering the six claims. I'll keep reading the engine commit path, pipeline decoupling, and fixtures so I can cross-check their findings.I'll start by locating `resolveLiveModuleRecordI'll verify` the D2 claim and the commit ABI by reading the invalid, then classify everyator call, site capture against the forwarding-bridge seals vs, commit exact ABI-record-, andbound claim occupancy paths with. citations.I'll verify the decoupling claim by reading the pipeline and pin paths, then checking the branch diff and remaining derivation sites.Next I’ll read the resolver, all call-site neighborhoods, and the commit ABI so we can classify READ vs WRITE.Next I’ll readI'll the inspect pipeline’s generation plumbing and the caller pin the hot paths-revision surface,, generation extraction, and then compare spec them §5.2 against the three- against the claimed invariantsdot diff..I'll locate the f5/f7/fence tests and generation fixtures first, then compare them against the claimed assertions and boot/prepared/production diffs.Next I’ll read the generation methods and spec §5.2, then compare the extraction diff for any drift.The `.git` pointer and the runner fixtures are next; I'll read the f5/f7/fence tests in full and locate a merge-base comparison for the generation floor.I’ll reconstruct the `generation.rs` extraction from git history and the spec’s preflight vs commit wording.There's a `0055-s3-mainbase` tree I can use as origin/main. Next I’ll compare generation tests and the boot/prepared/production diffs against it.Found origin/main in `0055-s3-mainbase`; I’ll compare `commit_revision` there to the extracted helper.I’ll inspect snapshot generation defaults, candidate-table generation, and the branch commits so we can compare behavior against origin/main.I’ll now hunt write/completion paths and helpers like `callbackRecordFor`, TLA, CJS/artifact caches, and binding updates.Generated artifacts may have changed; I'll re-read the header, manifest, mixed-provenance spec, and remaining occupancy/commit paths.The remaining risk is whether the authorizer still ties `graph_generation` to snapshot dynamic counters — I’ll check that next.Origin/main pins `max(dynamic, 1)`; I’ll compare that path in HEAD and inspect the remaining boot/prepared/production call sites.**VERIFIED**

H1 §1 is implemented: the module pipeline no longer mints an execution coordinate from `snapshot.generations().dynamic`; pin, `native_execution_inputs`, and `GraphAuthorityContext` rows share one caller-supplied `ExecutionGeneration`; boot/prepared/production still pin `ExecutionGeneration::INITIAL` (value `1`) once for the runtime’s life.

Worktree log shows the four S3 commits on `agent/0055-s3` (HEAD `bf8faca9`), starting with S3(A) “decouple ExecutionGeneration from the authority counter.” I could not run `git diff origin/main...HEAD` (no shell in this review lane). Facts below are from current HEAD sources plus repo-wide greps, not from a generated patch.

### Pipeline no longer derives from the authority counter

`build_authenticated_source_graph_v1*` now take an explicit `ExecutionGeneration`. The armed snapshot is still loaded for authorization; the execution coordinate is `execution_generation.get()`.

```2106:2150:/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/runner_pipeline.rs
pub fn build_authenticated_source_graph_v1(
    entry: &Path,
    producer_binary_digest: Digest,
    execution_generation: ExecutionGeneration,
) -> Result<SourceModuleGraphBuildV1> {
    // ...
}

fn build_authenticated_source_graph_v1_with_host(
    // ...
    // @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — execution coordinate is session-minted, never the authority counter.
    execution_generation: ExecutionGeneration,
) -> Result<SourceModuleGraphBuildV1> {
    let snapshot = host.snapshot()?;
    let authorizer = ModuleGraphAuthorizer::new(snapshot.as_ref());
    let graph_generation = execution_generation.get();
```

That value is stored on the graph (`execution_generation` at `/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/runner_pipeline.rs:367`, `:435-437`, `:2480`) and used for build-time `GraphAuthorityContext` rows (`:2381-2388` → `:2084-2091`).

Prepared load copies the same field (`:4252`). Committed admission also takes the coordinate as a parameter (`:3516-3522`, `:3566-3569`), it does not recompute it from the snapshot.

Repo grep (excluding `llp/reviews/`): **no** remaining `dynamic.get().max(1)` in Rust. The only remaining `snapshot.generations().dynamic.get()` uses are CapSec grant/ABI authority clocks, not the module execution coordinate:

- `/Users/ccheever/projects/ibex-wt/0055-s3/src/host/mod.rs:1182-1184`, `:1233-1235`, `:1485-1487`
- `/Users/ccheever/projects/ibex-wt/0055-s3/src/host/abi.rs:8031`

`ArmedSnapshot::snapshot_generations()` still returns the authority set (`/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/security.rs:329-336`). That is the immutable-ceiling compare (`generation.rs` `validate_authority`), not execution minting. Spec §1 allows that.

`ExecutionGeneration::INITIAL` is `1` (`/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/generation.rs:27-41`).

### One session-minted coordinate on pin, inputs, and authority rows

`native_execution_inputs` rejects a caller coordinate that is not the graph’s stored execution generation, then stamps both `GraphEvaluationContext` and `GraphAuthorityContext` with that same `u64`:

```1189:1286:/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/runner_pipeline.rs
        if graph_generation != self.execution_generation.get() {
            bail!(/* mismatch */);
        }
        // ...
                GraphEvaluationContext::new(..., graph_generation)?,
        // ...
                super::security::GraphAuthorityContext::new(..., graph_generation)?,
```

Covered by `/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/runner_pipeline.rs:4995-5034` (generation `7` binds; `native_execution_inputs(1)` refuses).

Engine pin uses the graph’s coordinate, not a hardcoded `1` and not `snapshot.dynamic`:

```2712:2726:/Users/ccheever/projects/ibex-wt/0055-s3/src/bin/ibex/engine/hermes.rs
        // @ref LLP 0055#1 — execution coordinate is session-minted, never the authority counter.
        let generation = graph.execution_generation().get();
        let nonce = unsafe { ex_hermes_runtime_nonce(raw) };
        runtime.ensure_module_generation_pinned(&lease, nonce, generation)?;
        // ...
            let (configs, authority_contexts) = graph.native_execution_inputs(generation)?;
```

`ensure_module_generation_pinned` (`:1925-1950`) calls `ex_hermes_module_pin_generation` only when `module_generation_pinned == 0`; a later call with a different generation fails; a later call with the same generation is a no-op (avoids the native ABI’s “insert once” refusal at `/Users/ccheever/projects/ibex-wt/0055-s3/src/engine/hermes_module_runner.cc:2908-2919`). Production never unpins (`unpin` is tests/FFI only).

Activation stays on that same coordinate: request/native-graph generation → `activate_*` → `native_execution_inputs` (`hermes.rs:1699-1708`, `:1743-1750`, `:1986-2026`).

### Production / boot still pin INITIAL exactly once

Boot/source:

```3297:3303:/Users/ccheever/projects/ibex-wt/0055-s3/src/bin/ibex/runtime.rs
        // @ref LLP 0055#1 — v1 boot mints INITIAL; the producing-session mint arrives with Exact H2 wiring.
        let mut graph = match build_authenticated_source_graph_v1_for_host(
            ...
            ExecutionGeneration::INITIAL,
```

Committed prepared: `/Users/ccheever/projects/ibex-wt/0055-s3/src/bin/ibex/runtime.rs:3516-3522` also passes `INITIAL`.

Conformance/startup/closed/prepared test seams all pass `INITIAL` (`capsec_public_startup_batch.rs:555-560`, `capsec_conformance_batch.rs:5233-5238`, `capsec_public_closed_batch.rs:1132-1137` and `:5860-5863`).

Native pin is once per runtime: `module_generation_pinned` starts at `0` (`hermes.rs:1864`), first evaluate pins, later evaluates reuse. Comment at `hermes.rs:1770-1772` still describes keep-alive as “generation 1 pinned until teardown,” which matches `INITIAL`.

### Observable change on lanes that never invoke a new session mint (boot, prepared, production)

**None that I can substantiate.**

Example armed snapshots have `"dynamic": 0` (`/Users/ccheever/projects/ibex-wt/0055-s3/capsec/examples/armed-snapshot.canonical.json:341-346`). Old `dynamic.get().max(1)` was `1`. New boot mints `INITIAL` (`1`). Spec already said the executable path hardcoded pin `1`; it now reads `graph.execution_generation().get()`, which is still `1` on these lanes.

`native_execution_inputs` now fail-closes on mismatch. Boot/prepared/production always pass the graph’s stored `INITIAL`, so that is a tighter invariant, not a different generation.

### MATERIAL issues

None found for this claim.

### Minor (not claim-breaking)

- Closed-batch unpin still hardcodes `1` while pin uses `graph.execution_generation().get()` (`capsec_public_closed_batch.rs:5889-5922`). Fine today because that graph is `INITIAL`.
- Host tests still call `native_execution_inputs(1)` (`host/mod.rs:11852`, `:12010`) after building with `INITIAL`; they do not go through `execution_generation().get()`. Behavior matches.
- `native_execution_inputs` / activation still take `u64` rather than `ExecutionGeneration`. They are checked against the stored coordinate; this is API shape, not leftover authority derivation.**VERIFIED**

D2 holds: the loader invalidator is descriptor-only trusted JS over null-prototype maps, the capture bridge matches the sealed outbound pattern (including generated disposition rows), commit is an in-fence JSI call that maps throws to `ENGINE_ERROR`, and occupancy counts carrier records only.

### 1. Invalidator: no user code, no capture/quarantine re-entry

`__privInvalidateHotRevisionRecords` only uses bootstrap-captured intrinsics, GOPD data-property reads, `Object.create(null)`, and `delete` on loader-private maps.

```159:163:src/engine/bootstrap/module-loader.js
  function devServedDataValue(object, key) {
    var descriptor = __privObjectGetOwnPropertyDescriptor(object, key);
    if (!descriptor || !('value' in descriptor)) return undefined;
    return descriptor.value;
  }
```

```730:730:src/engine/bootstrap/module-loader.js
  const cache = Object.create(null);
```

```5978:6025:src/engine/bootstrap/module-loader.js
  var __authenticatedResolutionMemo = Object.create(null);
  // @ref LLP 0055#53-the-commit-bundle-atomic-owner-thread-no-fail
  function __privInvalidateHotRevisionRecords(cacheKeys) {
    ...
    cacheKeys = __privObjectFreeze(cacheKeys);
    ...
    var replaced = __privObjectCreate(null);
    for (var index = 0; index < length; index++) {
      var cacheKey = devServedDataValue(cacheKeys, index);
      ...
      delete cache[cacheKey];
    }
    ...
        delete __authenticatedResolutionMemo[routeKey];
```

Accessor descriptors are skipped (`'value' in descriptor`); getters are never invoked. Native supplies a fresh JSI array; it is frozen before any key read.

Capture/quarantine tables **named and not referenced** by the invalidator:

| Surface | Role | Invalidator refs? |
|---|---|---|
| `__devServedTable` / `__devServedIds` | captured frozen module table | no |
| `__ibexCaptureDevServedModuleTable` / `captureDevServedModuleTable` | boot capture hatch | no |
| `__privQuarantineDevServedModuleTable` / `quarantineDevServedModuleTable` | quarantine bridge | no |
| `__exactCaptureDevServedModuleTableLifecycle` | lifecycle capture | no |

Those names live only in the capture/lifecycle block (`141:245:src/engine/bootstrap/module-loader.js`) and in `resolveDevServedModule` (`6396:6421:src/engine/bootstrap/module-loader.js`), which the invalidator never calls. The JS test drives post-commit require after invalidation and asserts quarantine stays at 0 (`331:361:packages/ibex-runtime-js/src/module-loader-provenance-llp0023.test.ts`).

Native commit restates the same isolation:

```3320:3325:src/engine/hermes_module_runner.cc
      // Direct invocation is part of the fenced publication bundle: no host
      // task scope, microtask drain, host poll, or timer slice is opened. The
      // loader-private function mutates only its null-prototype cache maps and
      // never consults the boot-only __devServed capture table or quarantine.
      runtime->hot_revision_record_invalidator->call(rt, sourceIds);
```

### 2. Capture bridge follows the sealed-global pattern

Install is the same one-shot host-function rendezvous as other `__exactCapture*` bridges (compare `__exactCaptureDevServedModuleTableLifecycle` at `4704:4726:src/engine/hermes_runtime.cc`):

```4745:4769:src/engine/hermes_runtime.cc
  auto captureHotRevisionRecordInvalidator =
      facebook::jsi::Function::createFromHostFunction(
          ...
            handle->hot_revision_record_invalidator =
                std::make_unique<facebook::jsi::Function>(...);
            return facebook::jsi::Value(true);
          });
  rt.global().setProperty(
      rt,
      "__exactCaptureHotRevisionRecordInvalidator",
      std::move(captureHotRevisionRecordInvalidator));
```

Loader consume-and-delete: `6027:6034:src/engine/bootstrap/module-loader.js`.

**Seal lists / hatch self-tests**

- Hardening hatch delete: `6629:6634:src/engine/hermes_runtime.cc`
- `kSealedGlobals`: `9844:9849:src/engine/hermes_runtime.cc`
- Session-bridge delete: `9323:9324:src/engine/hermes_runtime.cc`
- Startup hatch assertion: `334:341:src/bin/ibex/engine/capsec_public_startup_batch.rs`
- Post-lockdown hatch assertion: `1930:1931:src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs`

**Disposition source + regenerated artifacts**

- Private consumer: `39:42:packages/ibex-devtools/src/scripts/capsec-root-global-dispositions.mjs`
- Coverage native-op + WP4 classification: `154:154` and `14628:14630:packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs`
- Generated header: `136:136` and `721:721:src/engine/root_global_disposition.generated.h` (`private` / `absent` / `trusted-module-loader`)
- Manifest row: `32013:32042:capsec/generated/root-global-disposition-manifest.json`

**Fail-closed if module runner retained without invalidator**

`module_function_constructor` is the retained module-runner evaluator (`6521:6523:src/engine/hermes_runtime.cc`). Final private-bridge capture refuses if that handle exists without the invalidator:

```9285:9288:src/engine/hermes_runtime.cc
    if (handle->module_function_constructor &&
        !handle->hot_revision_record_invalidator) {
      throw std::runtime_error(
          "hot-revision record invalidator was not captured");
```

Loader-less lanes may leave the pointer null; commit then skips (`3332:3335:src/engine/hermes_module_runner.cc`). Armed/module-runner boots cannot.

### 3. Commit path: in-fence JSI, no host task, no microtask drain

`ex_hermes_module_commit_hot_revision` takes a plain `ExactRuntimeDriveGuard` (`3179:3181:src/engine/hermes_module_runner.cc`). That guard does not open `ScopedRuntimeExtensionHostTask` (the host-task / microtask checkpoint class at `1086:1094:src/engine/hermes_runtime_internal.h`; used by compile/load, **not** commit). Destructor only restores drive/context (`3045:3067:src/engine/hermes_runtime.cc`).

Invalidator `Function::call` is inside the same owner-thread bundle. Throw → `EXACT_RUNTIME_DRIVE_ENGINE_ERROR` (`3326:3330:src/engine/hermes_module_runner.cc`), the engine-invariant / recreate class (`231:231:include/exact_runtime.h`), documented as a quarantine/recreate signal.

### 4. Occupancy: records, not `shared_ptr`; no underflow; release at zero; unpin isolation

Tables vs counts are separate; the memo `shared_ptr` is not occupancy:

```859:866:src/engine/hermes_runtime_internal.h
  std::map<CarrierTableKey, std::shared_ptr<facebook::jsi::Object>>
      prepared_carrier_tables;
  // Live carrier-provenance records are the only occupancy unit. Neither the
  // memo's own shared_ptr nor extracted ModuleFactoryEntry functions retain a
  // logical table reference.
  std::map<CarrierTableKey, uint32_t> prepared_carrier_occupancy;
```

Factory load memoizes the table and does **not** increment occupancy (`2291:2324:src/engine/hermes_module_runner.cc`). Inline `compile_factory` never sets `carrier_key` (`2094:2104:src/engine/hermes_module_runner.cc`).

Increment only when creating a record whose factory carried a key (`3515:3550:src/engine/hermes_module_runner.cc`).

Decrement + refuse underflow + erase table at zero:

```244:260:src/engine/hermes_module_runner.cc
bool retirePreparedCarrierRecord(...) {
  ...
  if (occupancy == runtime->prepared_carrier_occupancy.end() ||
      occupancy->second == 0) {
    return false;
  }
  --occupancy->second;
  if (occupancy->second == 0) {
    runtime->prepared_carrier_tables.erase(*carrierKey);
    runtime->prepared_carrier_occupancy.erase(occupancy);
  }
```

Callers of retire (all fail closed with `ENGINE_ERROR` on false):

- commit (`3336:3338`)
- unpin (`3010:3012`)
- `release_handle` (`3055:3057`)
- `discard_unpublished_record` (`3368:3369`, adapter `3396:3397`)

Preflight also refuses a retirement count that would underflow (`230:241`, used at commit `3276:3278` and unpin `2952:2954`).

Unpin drains only that generation’s records (`2939:3015:src/engine/hermes_module_runner.cc`). Tests: factory load does not count; last retirement drops the table; reload rememoizes at occupancy 0; unpin of gen 60 leaves gen 61 (`9630:9886:src/engine/module_runner.rs`).

### 5. Mixed-provenance boot admission unchanged; carrier successors refuse at commit

Boot/rejoin still rejects mixed inline/prepared graphs:

```1153:1158:src/module_loader/runner_pipeline.rs
        if self
            .records
            .values()
            .any(|record| record.prepared.is_none())
        {
            bail!("module graph cannot mix inline and prepared factories");
```

Commit preflight refuses a **carrier-provenance successor** (`carrier_key.has_value()` → `INVALID`) while allowing an inline successor to replace a carrier prior (`3226:3233:src/engine/hermes_module_runner.cc`). That is the sanctioned post-boot provenance switch (LLP 0055 §5.4); boot admission is not relaxed.

No MATERIAL holes: user callbacks are not on the invalidator path, capture/quarantine tables are not re-entered, occupancy cannot wrap, the table `shared_ptr` is not counted, and the seal/disposition pattern is complete.## VERIFIED

The §5.2 surface matches the claimed invariants. The `generation.rs` extraction is a borrow/struct split of the landed S2 candidate body; check order and refusal strings are unchanged.

### 1. Single-flight + RAII

Busy is checked **before** `begin_revision`. The flag is set **only after** `begin_revision` succeeds. A failing `begin_revision` never touches `in_flight` (and nonce bump is last-before-`Ok`, so refusals do not mint a transaction).

```93:108:src/module_loader/hot_revision.rs
        if self.in_flight.get() {
            bail!("hot revision surface is busy");
        }
        let transaction = self
            .generations
            .begin_revision(policy, origin, base, invalidated)?;
        let guard = HotRevisionFlightGuardV1 {
            in_flight: Rc::clone(&self.in_flight),
        };
        self.in_flight.set(true);
        Ok(HotRevisionBegunV1 {
            state: HotRevisionStateV1 {
                transaction,
                _guard: guard,
            },
        })
```

```145:148:src/module_loader/hot_revision.rs
impl Drop for HotRevisionFlightGuardV1 {
    fn drop(&mut self) {
        self.in_flight.set(false);
```

- Guard constructed with flag still `false`, then `set(true)`, then `Ok(Begun)`. If that `Ok` panics, `Drop` clears a flag that was set; if construction panics **before** `set(true)`, `Drop` writes `false` onto an already-false cell. Harmless.
- Every consuming stage takes `self` / `mut self`. `?` / `bail!` drops the value, so the guard runs on stage, preflight, evaluated-settlement, and commit-time algebra refusal.
- Successful `commit` keeps `_guard` live through `apply()`, then drops it on return, freeing the surface.

Pinned by `single_flight_drop_releases_the_surface` and `preflight_refusal_drops_staged_rows_and_frees_the_surface`.

### 2. Commit only from `ReadyToPublish` (surface, type-level)

`HotRevisionSurfaceV1::commit` takes `HotRevisionReadyToPublishV1` by value. States are distinct, field-private, non-`Clone` structs; transitions consume `self`. No skip, no cloned ready token, no public constructor for ready.

`ModuleExecutionGenerationsV2::commit_revision` remains `pub` (S2 tests / `HotRevisionSlotV1`). That is **not** a hole in the surface: `generations` and `transaction` are private on the surface types, so a `HotRevision*V1` value cannot be smuggled onto the algebra.

### 3. Activation token: once, only in `commit`, never before

```254:282:src/module_loader/hot_revision.rs
/// Linear, transaction-bound consumer activation prepared before publication.
/// The action is private so it can run only from [`HotRevisionSurfaceV1::commit`].
pub struct ActivationTokenV1 {
    action: ActivationActionV1,
}
// ...
    fn apply(self) {
        if let ActivationActionV1::Flip(action) = self.action {
            action();
        }
    }
```

```119:137:src/module_loader/hot_revision.rs
        let HotRevisionReadyToPublishV1 {
            state,
            activation_token,
        } = ready;
        let HotRevisionStateV1 {
            transaction,
            _guard,
        } = state;

        let commit = self.generations.commit_revision(policy, transaction)?;
        // Engine §5.3 step 3 mounts immediately before this activation flip.
        activation_token.apply();
        // Engine §5.3 steps 5 and 6 mount immediately after this flip.
        Ok(commit)
```

- `apply` is module-private; only this call site uses it.
- Destructure **before** `commit_revision`. On `Err`, `activation_token` is dropped. There is **no** `Drop` on `ActivationTokenV1`, so the flip does not run on refusal.
- `FnOnce` + by-value `apply` ⇒ at most once on the success path.
- `full_happy_path_advances_only_invalidated_slots_and_flips_at_commit` asserts the counter is 0 until after `commit`.

**Panic after graph adopt (check 5):** `commit_revision` assigns `self.current` then returns; `apply()` runs after that. A panic in the user `Flip` closure leaves the graph published and the token incomplete. Spec §5.3.4: flip is no-fail or quarantine. Guard still drops, so `in_flight` clears on unwind. Not a logic bug in the success protocol; quarantine-class if a closure panics.

### 4. Preflight vs commit vs S2 extraction

Shared body is `validate_revision_candidate`. `as_ref()` vs S2’s `transaction.replacements` **move** is the only structural change, so the helper can run twice. Candidate construction still `record.clone()`s into a new map; `typed_rows_equal` / export-shape / CJS / ceiling are the same.

**`preflight_revision`** (`1290:1294:src/module_loader/generation.rs`): manager-identity, then `validate_revision_candidate`.

**`commit_revision`** (`1297:1344:src/module_loader/generation.rs`): manager-identity, then item-8 TOCTOU (authority snapshot, stamp, base, builtin principal), **then the same** `validate_revision_candidate`.

That matches spec §5.2 item 5 vs item 8: preflight is admission; commit re-runs the shared sequence after backstops. It is **not** that preflight ≡ the entire `commit_revision` function.

`begin_revision` is byte-identical to origin/main (`0055-s3-mainbase` @ `397cac57`). No extra clones that change equality; `HotRevision::next()` is pure `Copy` arithmetic, so preflight+commit calling it twice is the same value.

### 5. §5.2.5 specific-first order (unchanged from S2)

Inside `validate_revision_candidate` (`1191:1276:src/module_loader/generation.rs`):

1. converse: changed outside invalidation  
2. replacement-set hygiene (outside set / missing replacement) — S2 already had these between converse and no-op  
3. no-op: empty changed (`"hot revision changed nothing; nothing to apply"`)  
4. export-shape  
5. CJS boundary  
6. ceiling `validate_graph`

Refusal strings match origin/main.

---

### MATERIAL

None relative to this claim.

### Minors

- **S2 algebra still public:** `ModuleExecutionGenerationsV2::begin_revision` / `commit_revision` have no busy flag and no activation token. Surface-only invariant.
- **`begin` is `&self` + `Cell`, not a lifetime-locked `&mut`:** live `publish` / `install_revision` remain callable during an in-flight revision (last-good graph; install revisions not advanced). Spec’s “exclusive (`&mut`)” is fully honored only at `commit`.
- **Comment nit:** `commit_revision` says it “re-runs preflight” as the item-8 backstop (`1342:1343:src/module_loader/generation.rs`). Item 8 is the TOCTOU compares; the shared helper is the §5.2.5 sequence. Behavior is right.
- **Panic in `apply()`:** graph already swapped; `in_flight` released on unwind. Quarantine, not ordinary refusal.

**Extraction drift vs origin/main `commit_revision` candidate body:** none in order, strings, or equality. Only `replacements` by-ref, result struct, `preflight_revision`, and `pub(crate)` transaction accessors.**VERIFIED** — with two residual caveats (invalidator-after-publish, carrier occupancy on that path). No write/completion path calls `resolveLiveModuleRecord`. The native mutation loop does not throw via JSI, does not erase-while-iterating the maps it walks, and reserves forwarding before insert.

---

### 1. `resolveLiveModuleRecord` — definition and every call site

Definition (`src/engine/hermes_module_runner.cc:310-330`): one hop through `module_record_forwarding`, then exact `module_records` lookup. Comment states writes/completions stay exact-record-bound.

| Line | Site | Class |
|---|---|---|
| 991–994 | `readBinding` export-alias follow | **READ** — must forward |
| 1611–1616 | `dynamicEvaluationPromise` entry | **READ** of live target identity (then writes use the resolved exact id) |
| 1703–1714 | CJS-adapter `dynamicCommonJsAdapterNamespace` | **READ** namespace |
| 1873–1884 | `dynamicModuleNamespace` | **READ** namespace |
| 4142–4152 | namespace getter | **READ** |
| 4226–4238 | `importValue` target | **READ** |
| 4347–4363 | ESM `dynamicImport` target | **READ** |

Those are the four cross-module read surfaces (alias, `importValue`, namespace, dynamic import). The three dynamic-import call sites are one surface.

`callbackRecordFor` (`944-956`) is exact `module_records.find(recordId)` — **no** forwarding. That is the write/completion helper.

---

### 2. Write / completion paths are exact-record-bound

None of these call `resolveLiveModuleRecord`:

| Path | How the record is chosen | Lines |
|---|---|---|
| `$export` cell write | `callbackRecordFor(..., recordId)` captured at instantiate | 4170–4199 |
| TLA fulfill / reject | same; no-op if record already erased | 1098–1138 |
| `beginRecordExecute` / `run_execute` | `recordFor` + exact `recordId` | 1034–1156, 4533–4549 |
| Instantiate / declare / execute errors | `recordFor` → `rememberRecordError(*entry)` | 4436–4444, 4495–4503, 4558–4566 |
| Publish | `module_records.find(handle.opaque[2])` | 3105–3163 |
| Link export / import / deps / dynamic | `recordFor` + `target_record.opaque[2]` | 3564–3738 |
| Dynamic-activation **bind** | `target_record.opaque[2]` after `recordFor` proves the record still exists | 3895–4016 |
| Dynamic SCC evaluation + error | `callbackRecordFor` on ids from `collectDynamicEvaluationOrder` (`module_records.find`, no hop) | 1158–1182, 1804–1833 |
| CJS adapter export snapshot + namespace | `module_records.find(adapter_record_id)` | 407–450 |
| CJS require cache | `require_bindings.emplace(..., targetHandle.opaque[2])`; later `commonjs_records.find` / `evaluateCommonJsRecord` / `evaluateSynchronousRequiredEsm` on that id | 634–703, 1409–1492 |
| Artifact / loader cache | not a record write; post-publish `hot_revision_record_invalidator->call` | 3309–3331 |
| Fence after commit | `prior.run_execute()` → `recordFor` STALE (`-2`) | `module_runner.rs:9965-9966` |

`dynamicEvaluationPromise` **does** hop first, then evaluates **the live id**. That is slot-read then exact write to the successor, not a stale completion redirected onto the successor. Retired TLA still uses the pre-commit `recordId`; after `module_records.erase` the callbacks see `nullptr` and refuse to publish into the successor.

CJS `require(ESM)` is **not** one of the four live-read surfaces: leftover bindings to a retired ESM id go stale rather than hop. That matches “cache/write is exact.”

---

### 3. Namespace identity is slot-owned and transferred

Stored as `NativeModuleRecordEntry::namespace_object` (`shared_ptr<jsi::Object>`). Instantiation:

```4118:4168:src/engine/hermes_module_runner.cc
    const auto occupiedSlot = runtime->module_source_slots.find(
        std::make_pair(graphGeneration, entry->source_id));
    // A staged successor must not retain a second namespace facade. Commit
    // moves the already-exposed slot-owned object from the prior incarnation.
    const bool retainNamespace =
        occupiedSlot == runtime->module_source_slots.end() ||
        occupiedSlot->second == recordId;
    // ... getters close over recordId, then resolveLive on get ...
    if (retainNamespace) {
      entry->namespace_object =
          std::make_shared<facebook::jsi::Object>(std::move(namespaceObject));
    }
```

Successor behind an occupied slot still **constructs** a getter object, then drops it — it is not stored, not passed into the factory, not exposed. Commit moves the prior object:

```3300:3302:src/engine/hermes_module_runner.cc
    if (pair.prior->namespace_object) {
      pair.successor->namespace_object =
          std::move(pair.prior->namespace_object);
    }
```

Getters close over the **prior** id and hop via `resolveLive`, so JS object identity is stable (`f5`: `namespace === __f5Namespace` stays true). Dual-namespace is preflight-rejected (`3231-3232`).

---

### 4. `ex_hermes_module_commit_hot_revision` (`3172-3341`)

**Preflight (no semantic map mutation; `reserve` only allocates buckets), all before the pair loop:**

1. Drive guard; `graph_generation != 0`, `pair_count != 0`, non-null arrays (`3183-3186`)
2. Generation pinned (`3187-3189`)
3. Per pair: nonzero distinct ids; unique priors; unique successors (`3213-3216`)
4. Both records exist, same generation (`3218-3224`)
5. Prior published; successor unpublished; successor `state >= Instantiated`; same `source_id`; successor has no `carrier_key`; unique `source_id`s; not both namespaced (`3226-3233`)
6. Slot `(generation, source_id)` exists and points at **prior** (`3235-3239`)
7. New forwarding node planned only if prior is not already a key (`3241-3243`)
8. Carrier retirement counts, overflow-checked (`3244-3252`)
9. No in-flight dynamic activation whose **requester** is a prior (`3262-3267`)
10. Forwarding `max_size` room + `reserve(size + new nodes)` (`3269-3275`)
11. `preparedCarrierRetirementsAreValid` (`3276-3278`)
12. Any exception → `ENGINE_ERROR`, maps untouched (`3280-3282`)

Not checked (minor, not a live forwarding bug): successor may be `Evaluating` or `Errored` (`Errored > Instantiated`); pending activations whose **target** is a prior (complete then `recordFor` → STALE). Unique `source_id` + `prior.source_id == successor.source_id` implies prior-set ∩ successor-set = ∅, so a successor cannot also be a prior in the same batch.

**Mutation loop (`3284-3307`) — no JSI:**

- `successor->published = true`
- `*slot_record_id = successor` (pointer into `std::map` value; no slot insert/erase)
- flatten: every forwarding **value** equal to prior → successor
- write/overwrite forwarding **key** prior → successor (`extract` + `insert` of a prebuilt node, or assign)
- `namespace_object` move
- `releaseContextReference` then `module_records.erase(prior)`

`releaseContextReference` (`222-228`) is find / decrement / erase — no JSI.

**Iterator / pointer invalidation:** the loop iterates `pairs` (vector), not `module_records`. Inner range-for mutates forwarding **values** only, then `find`/insert **after** that range-for ends. `unordered_map` erase of prior invalidates only the erased node; successors are a disjoint set, so `pair.successor*` stays valid. No erase-of-current-while-iterating a map.

**Reserve-before-mutate:** `pairs.reserve` / `forwardingNodes.reserve` (`3205-3206`); `module_record_forwarding.reserve(size + N)` before any insert. `module_source_slots` is `std::map` and is only retargeted, not grown.

**Exception safety:** the mutation loop has no `try`. It also has no Hermes/JSI. The JSI call is **after** the loop (`3309-3331`). If the invalidator throws, native slots/forwarding/records are already published and the ABI returns `ENGINE_ERROR` (quarantine/recreate). **Caveat:** that `return` skips the carrier-occupancy retirement loop (`3336-3340`), so occupancy can leak until recreate. That is D2-shaped, not a mid-loop throw.

---

### 5. Single-hop forwarding; chains cannot survive commit

`resolveLive` follows **one** hop and does not flatten on read (`319-323`).

Commit flattens every existing value that pointed at the retired id, then sets `forwarding[prior] = successor` (`3287-3298`). A later commit `B→C` rewrites `A→B` to `A→C` and adds `B→C`. After commit, every key that used to name a retired record points at the live successor.

A same-batch chain `A→B` and `B→C` is rejected by unique `source_id`. A live record is erased when it becomes a prior, so it is not both a forwarding key and a live `module_records` entry.

---

### 6. Unpin teardown (`2922-3016`)

For the generation: drop pin, CJS require providers, dynamic-activation requests/queue, **all** `module_source_slots` with `slot.first.first == graph_generation` (`2975-2981`), then **forwarding** whose target is missing or in that generation (`2983-2991`), then CJS records, then ESM records. Matches `f5_unpin_generation_clears_hot_revision_slots_and_forwarding`.

---

**Not material:** temporary unretained namespace object during successor instantiate (never stored). **Residual, acknowledged:** invalidator JSI after publish; occupancy skip if that call throws. Neither is a forwarding write, an incomplete preflight of the native maps, or map iterator invalidation.## Claim 5: **REFUTED** (names overclaim; TLA surface missing; 23-floor itself holds)

“Every surface / capture-table / no-partial-records” is **not** what the fixtures actually prove. Occupancy, `===`, refusal atomicity, and stale-execute fencing **are** present. The 23-count in `generation/tests.rs` is real and the original four tests were not weakened.

### How 23 is counted

`23` = number of `#[test]` functions in `/Users/ccheever/projects/ibex-wt/0055-s3/src/module_loader/generation/tests.rs`.

Compared to `/Users/ccheever/projects/ibex` (`refs/heads/main` = `cc540194`, treated as `origin/main`):

- `src/module_loader/generation/tests.rs` **does not exist** on main. Tests lived in `generation.rs` (`mod tests`) and there were **4** `#[test]`s.
- HEAD has those same 4 names plus 19 new ones = **23**.
- Test names on HEAD vs `0055-s3-mainbase` are the same 23; both files end at line 2267 with the same last assertions.

Original four (moved, not weakened) match main’s assertions: `first.previous.get()==1`, `generation==2/3`, publish of stale token `is_err()`, concurrent loser `is_err()`, package-edit `"restart"`, production `INITIAL` + `begin_update` `is_err()`, slot swap `retired=="native-graph-1"`.

I could not run `git log -p` / `git diff` (no shell). File-vs-main comparison found **no deleted `assert` lines** in those four tests. No `generation/tests.rs` diff vs main is possible because the file is new.

### Engine fixtures (`src/engine/module_runner.rs`)

| Test | Name claims | What it actually asserts |
|---|---|---|
| `f5_cross_surface_slot_switch_observes_successor` (9514) | successor on every use surface + `===` | After `commit_hot_revision`, `__f5ReadNamed()` and `__f5Namespace.named` go `1→2`; reexport `namespace_json` goes `named/star` `1→2`; dynamic-import ns is `=== __f5Namespace` and `=== __f5DynamicBefore` (`"2:true:true"`). Importer is **not** in the commit pair (unchanged importer). |
| `f5_refused_commit_mutates_nothing` (9519) | refusal atomicity | Wrong `SourceId` successor → `commit.is_err()`; target/reexport still `named:1`; static+dynamic still `"1:1"` / `"1:true"`. Retired handle is **not** checked (commit never published). |
| `f5_unpin_generation_clears_hot_revision_slots_and_forwarding` (9984) | named `f5` but not F5 surfaces | Two commits then unpin; **re-pin same numeric generation** and a fresh record publishes `value:4`. Slot/forwarding drain, not successor observation. |
| `f7_live_discard_leaves_no_reachable_state` (9524) | no partial records / no capture table | `discard_unpublished_record` → discarded `namespace_json` `(-2)`; prior still `value:1`; later commit of a different successor `value:3`. **No capture table.** **No refused-commit staging census.** |
| `f7_carrier_occupancy_retires_at_zero` (9629) | occupancy retire / shared table / unpin drain | Occupancy `(2,true)→(1,true)` after first retire; factory load does not count; second retire `(0,false)`; reload memoizes `(0,true)`; unpin 60 keeps gen 61 `(1,true)`; unpin 61 `(0,false)`. Matches occupancy/unpin claims. |
| `fence_stale_write_refuses_after_commit` (9911) | stale write/completion does not redirect | After commit, `prior.run_execute()` errors `(-2)`; successor still `{"value":2}`. That is **stale completion refused**, not a leftover `$export` closure. |

**Typed-graph `f7` (different fixture):** `generation/tests.rs` `f7_ceiling_and_converse_refusals_leave_live_state_unchanged` (1608) asserts ceiling/missing/extra-row refusals leave `live_snapshot` unchanged. Not occupancy, not capture table.

**JS `f7`:** `packages/ibex-runtime-js/src/module-loader-provenance-llp0023.test.ts` `f7_live_post_commit_resolution_skips_capture_table` (331) — post-invalidation `require('a.js')` is a new object, `__originalRuns.a==2`, `devServedQuarantineCalls()==0`. **Not on main.** This is the only capture-table test.

### Missing F5 surfaces (spec §F5 at `llp/0055-…spec.md:954`)

Covered: namespace getter (`importValue('*')`), static named (`importValue('named')` via stored getter), re-export (`link_export` + `namespace_json`), star (star import + reexport `"star"`), dynamic-import namespace, `===` across commit, refused commit leaves old bindings.

**Missing:** **TLA continuation in an unchanged importer.** Importer `execute` is synchronous; there is no pending `await` / `.then` that resumes after commit. Dynamic-import `.then` is a post-commit **new** call, not a continuation parked across the fence.

Also not a SES `import * as ns` binding distinct from `importValue('*')`.

---

## Claim 6: observable boot / prepared / production changes

Production pin is still **once, value 1** on the success path. Several **API / coordinate** changes are still observable.

### MATERIAL

1. **Graph construction no longer uses `snapshot.generations().dynamic.max(1)`.**  
   Main (`runner_pipeline.rs:2063`): `let graph_generation = snapshot.generations().dynamic.get().max(1);`  
   HEAD (`runner_pipeline.rs:2145–2150`): `execution_generation` argument; boot/prepared/production pass `ExecutionGeneration::INITIAL`.  
   That value is stamped into `GraphAuthorityContext` at `graph_edge_decision` (`2084–2091`) and into native configs (`1261–1284`).  
   **If any production snapshot has `dynamic > 1`, authorization `graph_generation` changes  N→1.** In-repo canonical snapshot is `"dynamic": 0` (`capsec/examples/armed-snapshot.canonical.json:344`); no snapshot JSON with `"dynamic": [1-9]`. So **in-repo production stays 1**, but the old `max(dynamic,1)` path **could** have been `>1`.

2. **`native_execution_inputs` mismatch check is new and can refuse old callers.**  
   HEAD `runner_pipeline.rs:1196–1201` bails if `graph_generation != self.execution_generation.get()`.  
   Main had no stored execution generation; `native_execution_inputs(1)` worked for any built graph (candidate tables are hardcoded `generation: 1` on both trees, `1613` / main `1532`).  
   Callers that passed **1** to an INITIAL graph still work. Callers that passed **any other** generation (main performance loop used `generation_offset + sample + 1` without binding the graph) would now fail unless they also mint that generation at build time (HEAD `host/mod.rs:12223–12238` was updated to do that).  
   Witness test: `authenticated_source_graph_binds_native_inputs_to_its_execution_generation` (`4995–5034`) — `native_execution_inputs(1)` on a gen-7 graph is an error.

3. **Pin is moved after admit/prepare.**  
   Main `hermes.rs:2572–2574`: `let generation = 1;` then pin, **then** lease + admit.  
   HEAD `hermes.rs:2632` lease first; pin only after native admission at `2713–2715` with `graph.execution_generation().get()`.  
   Success path still pins **1** once. **Failure path differs:** a failed prepare on main already pinned 1; on HEAD the runtime stays unpinned.

### Not MATERIAL (success path, these lanes never call `commit_hot_revision`)

| Site | Change | Class |
|---|---|---|
| `hermes.rs:2713–2715` | pin uses `graph.execution_generation()` instead of literal `1` | Not material while callers pass `INITIAL` |
| `hermes.rs:1925–1950` | pin takes `OwnerRuntimeLease` + raw-pointer check | Internal; happy path same |
| `runtime.rs:3303`, `3522`, `14786` | extra `INITIAL` arg | Same coordinate 1 |
| `host/mod.rs:11827`, `11958`, `12204` | tests pass `INITIAL`; execute still `native_execution_inputs(1)` | Same |
| `capsec_public_startup_batch.rs:560`, `capsec_public_closed_batch.rs:1137/5863`, `capsec_conformance_batch.rs:5238` | `INITIAL` into graph build; closed batch pins `graph.execution_generation()` then unpins `1` (`5889–5919`) | Same 1 |
| `capsec_host_abi_output_batch.test.rs:365,4304` | **new** `ex_hermes_module_commit_hot_revision` harness branch (count 0, gen 1) | Test ABI surface only; pin probe still gen 1 (`4301–4302`) |
| `generation.rs:789` | `ModuleExecutionGenerationsV1::new` already used `INITIAL` on main (`generation.rs:272`) | Unchanged |
| Candidate tables | still `generation: 1` | Unchanged |

`commit_hot_revision` is declared in `hermes.rs:617` but not invoked on boot/prepared/production evaluate paths.

---

## Weakened / deleted assertions

**None found** in:

- the original 4 generation tests (main `generation.rs:636–789` vs HEAD `generation/tests.rs:358–511`);
- sampled pre-existing runner tests (`verified_factory_context_and_record_are_generation_scoped`, `linked_records_observe_live_binding_updates` factories/asserts);
- existing pin/unpin witnesses (gens 23/24/41/1 unchanged).

Could not enumerate `git log -p origin/main...HEAD -- '*test*'` `-    assert` hunks without git. HEAD adds tests (`frozen_composition_linker_seam_fails_closed` + six hot-revision tests); it does not drop main’s 42 runner test names.I'll pull the subagent results in so their findings are folded into the verdict.The four S3 commits match the spec on the load-bearing claims. I reviewed `origin/main...HEAD` (merge-base of the four commits). `origin/main..HEAD` also inverts nine later main commits (LLP 0056 composition, prepared-composition fixtures); those are not this implementation.

## Overall Assessment

Slice A stops minting the execution coordinate from `snapshot.generations().dynamic`. Boot, prepared, and production still pass `ExecutionGeneration::INITIAL` and pin that value once. Slice B/C extracts the S2 candidate checks into `validate_revision_candidate` without changing order or refusal strings, and `HotRevisionSurfaceV1` is a consuming-state, single-flight seam that applies the activation token only inside `commit`. Slice D1 adds a slot table, one-hop forwarding on the four cross-module reads, exact-record writes/completions, and a no-mutation-then-infallible-native-loop commit ABI. Slice D2 adds the sealed `__privInvalidateHotRevisionRecords` bridge and record-counted carrier occupancy. Production evaluate never calls `ex_hermes_module_commit_hot_revision`. Residual gaps (F5 TLA continuation not parked, pin-after-admit on failure, occupancy skipped if the invalidator throws) are real but not success-path correctness breaks on lanes that do not invoke the new ABI.

## Verdict

READY

## Material Findings

None.

## Minor Findings

1. **F5 does not park a TLA continuation.** `run_f5_slot_switch_fixture` (`src/engine/module_runner.rs:9318`) covers namespace getter, static `importValue`, re-export, star, and dynamic-import namespace with `===` identity. Spec §11 F5 also names a TLA continuation in an unchanged importer. The importer execute is synchronous; the post-commit `dynamicImport().then(...)` is a new call, not a continuation that resumed across the fence.

2. **Pin now happens after native admit/prepare.** Merge-base `hermes.rs` pinned `generation = 1` before `admit_prepare_authenticated_module_graph`. HEAD pins at `src/bin/ibex/engine/hermes.rs:2712-2715` only after a native graph is admitted. Failed prepare, and the legacy admission return at `2708-2709`, no longer leave generation 1 pinned. Success path for native evaluate still pins `INITIAL` (1) once. Not app-visible on the happy path.

3. **Invalidator throw after native publish skips occupancy retirement.** `ex_hermes_module_commit_hot_revision` publishes slots/forwarding/records (`src/engine/hermes_module_runner.cc:3284-3307`), then calls the invalidator (`3309-3331`). A throw returns `EXACT_RUNTIME_DRIVE_ENGINE_ERROR` and skips `retirePreparedCarrierRecord` (`3336-3340`). Spec §5.3 wants quarantine/recreate for a mid-bundle invariant; occupancy then leaks only until teardown. Production does not call this ABI (`hermes.rs:616-617` is `#[allow(dead_code)]`).

4. **`HotRevisionSurfaceV1::begin` is `&self` + `Cell`.** Spec §5.2 says exclusive `&mut`. Live `publish` / `install_revision` remain callable during an in-flight revision (last-good graph). Single-flight and commit exclusivity still hold. `ModuleExecutionGenerationsV2::{begin,commit}_revision` stay public without the busy flag; the surface types keep `generations` private.

5. **`evaluated()` does not require shadow TLA.** It only checks `Evaluation` or `CommonJsCache` (`src/module_loader/hot_revision.rs:200-214`). Spec §5.2.6 still wants settled shadow TLA. Expected incompleteness for this slice’s host-driven evaluation.

6. **Closed-batch unpin still hardcodes `1`.** `src/bin/ibex/engine/capsec_public_closed_batch.rs:5889` pins `graph.execution_generation()` and `5919` unpins `1`. Fine while graphs are `INITIAL`.

## Verified Claims

### 1. §1 decoupling — VERIFIED

No remaining `dynamic.get().max(1)` execution mint in the module pipeline. Authority `dynamic` is still compared only as the CapSec clock (`src/host/mod.rs:1184`, `src/module_loader/generation.rs:612-618`).

- Pipeline takes a session-minted coordinate: `src/module_loader/runner_pipeline.rs:2145-2150` (`graph_generation = execution_generation.get()`), stored at `367` / `2480`.
- `native_execution_inputs` refuses a mismatch and stamps `GraphEvaluationContext` and `GraphAuthorityContext` with that same `u64`: `1189-1201`, `1261-1285`.
- Engine pin uses the graph’s coordinate, once: `src/bin/ibex/engine/hermes.rs:2712-2715` and `1925-1950`; native insert-once at `src/engine/hermes_module_runner.cc:2908-2919`.
- Boot / committed prepared / tests pass `ExecutionGeneration::INITIAL`: `src/bin/ibex/runtime.rs:3297-3303`, `3516-3522`. In-repo armed snapshots have `"dynamic": 0`, so old `max(dynamic,1)` was already 1.

### 2. §5.2 surface — VERIFIED

- **Single-flight:** busy before algebra (`src/module_loader/hot_revision.rs:93-95`, string `"hot revision surface is busy"`). Flag set only after `begin_revision` succeeds (`96-108`). `HotRevisionFlightGuardV1::drop` clears it (`145-148`). Consuming `self` on stage/preflight/evaluated/commit means every `?` path drops the guard. Tests: `497-531`, `565-612`.
- **Commit only from `ReadyToPublish`:** `commit` takes `HotRevisionReadyToPublishV1` by value (`119-123`). States are field-private, non-`Clone`, consume `self`.
- **Token applied once, only in commit:** `ActivationTokenV1::apply` is private (`278-282`). Sole call site is after successful `commit_revision` (`133-135`). Destructure happens first; a failed `commit_revision` drops the token without running the `FnOnce`. Happy-path test asserts the flip count stays 0 until after `commit` (`552-561`).
- **Preflight ≡ commit’s shared sequence, S2 strings preserved:** `preflight_revision` is manager identity + `validate_revision_candidate` (`1290-1294`). `commit_revision` runs the item-8 TOCTOU backstops, then the same helper (`1297-1344`). Extraction vs merge-base only changes `replacements` to `as_ref()` and returns a struct. Order inside the helper is still converse → replacement hygiene → no-op `"hot revision changed nothing; nothing to apply"` → export-shape → CJS → ceiling (`1191-1276`).

### 3. §2.2 / §2.3 engine half — VERIFIED

**Four READ surfaces go through one-hop `resolveLiveModuleRecord` (`310-330`):**

| Surface | Site |
|---|---|
| Namespace getter | `4142-4152` |
| Static `importValue` | `4226-4238` |
| Export-alias chase in `readBinding` | `991-1001` |
| Dynamic-import target / namespace | `1611-1616`, `1703-1714`, `1873-1884`, `4347-4352` |

**Write / completion paths are exact-record-bound** (`recordFor` / `callbackRecordFor` / `commonJsRecordFor`; none call `resolveLiveModuleRecord`):

- `$export` cell write: `4170-4199` (`callbackRecordFor`)
- TLA fulfill/reject: `1098-1138` (`callbackRecordFor`; no-op if the prior was erased)
- `run_declare` / `run_execute` / errors: `4472`, `4533`, `rememberRecordError`
- Link import/export/deps/dynamic: `3598-3738` (stores `target_record.opaque[2]`)
- Publish: `3105-3163`
- CJS require-activation bind: `647-664` (`recordFor` / `commonJsRecordFor`)
- Dynamic SCC evaluation: `1804-1808` (`callbackRecordFor`)

**Namespace identity is slot-owned:** instantiate skips storing a facade when the slot is occupied by another id (`4118-4168`). Dual-namespace is preflight-`INVALID` (`3231-3232`). Commit moves the object (`3300-3303`). Getters close over the prior id and hop, so `===` holds (`module_runner.rs:9479-9486`).

**Commit ABI preflight is complete before mutation** (`3172-3282`): pinned generation, pair shape, unique ids, published/unpublished, source agreement, slot occupancy, no carrier successor, pending-activation requester refusal, forwarding `reserve`, occupancy preflight. The mutation loop (`3284-3307`) is non-JSI: publish flip, slot retarget (`std::map` pointer, no insert), flatten values then insert a reserved node, namespace move, `erase(prior)`. `unordered_map::erase` invalidates only the erased node; priors and successors are disjoint by `source_id`. JSI starts only after that loop.

Unpin erases that generation’s slots and forwarding whose target is missing or in-generation (`2975-2991`).

### 4. §5.3 items 5–6 (D2) — VERIFIED

- Invalidator (`src/engine/bootstrap/module-loader.js:5987-6025`) uses `devServedDataValue` (GOPD data-property only, `159-163`), `Object.create(null)` cache (`730`) and route memo (`5985`), and `delete`. It never names `__devServedTable`, `captureDevServedModuleTable`, or `quarantineDevServedModuleTable`.
- Capture follows the sealed outbound pattern: install `src/engine/hermes_runtime.cc:4745-4769`; consume-and-delete `module-loader.js:6027-6034`; `kSealedGlobals` `9844-9849`; session-bridge delete `9323-9324`; hardening hatches `6629-6634`; startup hatch `capsec_public_startup_batch.rs:340`; callback-invariant hatch `capsec_public_callback_invariant_batch.rs:1930`; disposition `capsec-root-global-dispositions.mjs:42`; coverage WP4 `capsec-coverage-model.mjs:14628-14630`; regenerated header `root_global_disposition.generated.h:136,721`.
- Fail-closed: if `module_function_constructor` is retained without the invalidator, finalization throws (`hermes_runtime.cc:9285-9288`).
- Commit calls the invalidator in-fence, no `ScopedRuntimeExtensionHostTask` (`hermes_module_runner.cc:3179-3181`, `3320-3325`).
- Occupancy counts records, not the table `shared_ptr` (`hermes_runtime_internal.h:859-866`). Increment only in `create_record` (`3515-3550`). Factory load does not increment. `retirePreparedCarrierRecord` refuses missing/zero (`244-260`). Release at zero. Unpin drains one generation (`2937-3015`). Carrier successors refused at commit preflight (`3226-3233`). Boot mixed-provenance rule unchanged (`runner_pipeline.rs:1153-1158`).

### 5. Test honesty — VERIFIED

- **f5 successor + `===`:** `module_runner.rs:9399-9490` — named import, namespace getter, re-export, star, dynamic namespace `=== __f5Namespace === __f5DynamicBefore`. Refusal path (`9519-9521`, wrong `SourceId`) keeps `"1:1"` / `"1:true"` / `named:1`.
- **f7 discard:** `9525-9609` — discarded handle is `(-2)`, live prior stays, successor commit works.
- **f7 capture table:** `module-loader-provenance-llp0023.test.ts:331-361` — post-invalidation require re-runs, `devServedQuarantineCalls()==0`, rendezvous globals gone.
- **f7 occupancy:** `9630-9886` — `(2,true)→(1,true)` on first retire, factory load does not count, `(0,false)` on second, rememoize `(0,true)`, unpin 60 keeps gen 61, unpin 61 `(0,false)`.
- **Fence:** `9912-9967` — `prior.run_execute()` is `(-2)` after commit; successor still `{"value":2}`.
- **No weakened/deleted asserts in the four-commit range:** `git diff origin/main...HEAD` has no removed `assert!`/`assert_eq!` lines. `src/module_loader/generation/tests.rs` is not in that diff; `#[test]` count is 23 on merge-base and 23 on HEAD.

TLA continuation is the coverage gap in minor 1, not a deleted assertion.

### 6. Boot / prepared / production (no new ABI) — VERIFIED, no material success-path change

`ex_hermes_module_commit_hot_revision` is not invoked on evaluate (`hermes.rs:616-617` dead-code). Boot/prepared still pass `INITIAL` and pin once. `publish_records` now fills `module_source_slots` (`3124-3165`); boot instantiate-before-publish of one record per `SourceId` still retains a namespace (`occupiedSlot` empty or same id, `4123-4125`). Occupancy on prepared `create_record` is drained by unpin in the same count. The new `native_execution_inputs` mismatch check (`1196-1201`) is fail-closed; production passes `graph.execution_generation()`, which is `INITIAL`. Pin-after-admit is the failure-path difference in minor 2, not a change to the native evaluate happy path.

---

# Delta round (post-fix-round verification)

**Reviewer:** grok-4.6, effort xhigh, headless, same commission as the codex delta (mutually blind). **Date:** 2026-08-25.
**Verdict:** READY — all 8 prior materials RESOLVED; 6 minors recorded, none actioned as blocking.

I'll start the delta round by reading the spec and the fix-commit plus the branch diff, then check each of the eight prior findings against the current tree.The tip is `2ae25af72`. Next I’ll pull the spec, the fix commit, and the branch-vs-main diffs that the eight findings depend on.Composition.rs vs `origin/main` is empty. I’ll pull the fix diff and locate the ABI, occupancy, quarantine, and fixture code for the remaining checks.The ABI and occupancy hooks are in place. Next I’ll read the commit preflight, invalidation, and fixture implementations against the spec constraints.## Delta Assessment

Reviewed tip `2ae25af727923d3f20d4ae87cc1bf52eb41ec547` (`LLP 0055 S3: dual-family review fix round…`) and spot-checked `git diff origin/main..HEAD`. Spec `llp/0055-hot-revision-intra-generation-updates.spec.md` is Accepted. `llp/reviews/` was not read.

The eight prior materials are implemented in the current tree. The fix commit is the one that actually closes them: two-list invalidation, CJS occupancy, CJS preflight refusal, `Evaluated`-exact settlement, no-fail fence + quarantine latch, armed/attribution gates, and the F5 TLA leg.

**Non-ABI lanes.** Prepared-composition admission is byte-identical to `origin/main`. Lanes that never call `ex_hermes_module_commit_hot_revision` do not pick up commit semantics. The only extra-ABI change in the fix is prepared-carrier occupancy on CommonJS create/unpin/release/discard — that is the intended finding-3 repair, not a silent boot/eval change. Empty `__hotRetiredDevServedIds` makes the new resolution checks no-ops.

**Fix-diff scan.** No new memory-safety, exception-safety, or state-machine hole in the commit ABI. Preflight is a no-mutation `try` that returns `INVALID`; the mutation `try` quarantines on failure. Pointers into `module_records` / slots are used only before erase. Test fixtures assert the diagnostics they claim (INVALID `-1`, ENGINE_ERROR `-5` + quarantine `-6`, TLA run count `1`).

## Verdict

READY

## Material Findings

None.

## Minor Findings

1. **Dev-served bun fixture uses the same string for both lists.** `mod.rs` `hot-revision-retired` calls `hotRevisionInvalidator([cacheKey], [cacheKey])` with `cacheKey = '/src/dep.ts'`. That proves cache-row deletion + retired-id refusal + no quarantine, but would still pass if the two arguments were swapped. Independence is in the native ABI (`exact_runtime.h:846-860`, `hermes_module_runner.cc:3392-3422`), not in that fixture.

2. **Suffix lookup reads the boot id list first.** `resolveDevServedModule` checks `__hotRetiredDevServedIds` before `__devServedTable` on the candidate path (`module-loader.js:6458-6466`). The suffix fallback (`findDevServedBySuffix` → `module-loader.js:6468-6473`) walks `__devServedIds` first, then refuses before serving source bytes. No re-serve, no quarantine.

3. **Armed-runtime fixture is observer-gated.** `armed_runtime_structurally_refuses_hot_revision_commit` is `#[cfg(feature = "capsec-conformance-observer")]` (`module_runner.rs:10601-10633`) because `ex_hermes_create_armed` lives there. The C++ gate (`hermes_module_runner.cc:3273-3280`) is unconditional.

4. **Successor fixture covers Declared vs Evaluated, not Errored/Evaluating as separate cases.** The predicate is a single `!= Evaluated` (`hermes_module_runner.cc:3323`); `hot_revision_successor_must_be_fully_evaluated` (`module_runner.rs:9921-9982`) is enough to close the old `state < Instantiated` hole.

5. **Commit-message “drop-flag” vs latch-on-entry.** `HotRevisionSurfaceV1::commit` sets `quarantined = true` before any backstop and clears it only after success (`hot_revision.rs:129-146`). There is no `Drop` guard. Panic-safety is still real (`activation_flip_panic_quarantines_the_surface`, `hot_revision.rs:574-605`).

6. **Non-commit erase paths can still return `ENGINE_ERROR` without quarantine.** Unpin/release/discard CJS occupancy retire (`hermes_module_runner.cc:3076-3078`, `3149-3150`, `3532-3533`) follows the pre-existing ESM pattern. That is outside the commit-ABI claim (“`ENGINE_ERROR` from this ABI means exactly quarantine”).

## Resolution Check

### 1. Prepared-composition admission — RESOLVED

`git diff origin/main..HEAD -- src/module_loader/composition.rs` is empty (0 bytes). Blob ids match:

- `src/module_loader/composition.rs`: `b49d2f49218e1fb41992fb6de0cf076544ebedd7` on both `origin/main` and `HEAD`
- `src/module_loader/composition/driver_tests.rs`: `ce0d53b16ba90b9981384a7574d61b427599c98b` on both

No composition, carrier-v3, or driver-test path appears in `origin/main..HEAD`. The earlier “removal” was a stale-base artifact.

### 2. Dev-served invalidation — RESOLVED

Commit ABI takes two caller-owned lists, not derived source ids:

```843:860:include/exact_runtime.h
/// `cache_keys` and `retired_dev_served_ids` are independent, caller-owned
/// pointer/length lists forwarded verbatim to the private loader invalidator;
/// zero-count lists may use null pointer and length arrays.
int32_t ex_hermes_module_commit_hot_revision(
    ...
    const uint8_t* const* cache_keys,
    const size_t* cache_key_lengths,
    size_t cache_key_count,
    const uint8_t* const* retired_dev_served_ids,
    const size_t* retired_dev_served_id_lengths,
    size_t retired_dev_served_id_count);
```

Preflight materializes both JSI arrays (`hermes_module_runner.cc:3392-3422`); the fenced call forwards both (`3454-3462`). Loader surgery deletes named cache/memo rows, then records retired ids (`module-loader.js:6034-6056`). Resolution throws **before** reading table source:

```6458:6473:src/engine/bootstrap/module-loader.js
      if (devServedDataValue(__hotRetiredDevServedIds, candidates[index]) === true) {
        throw new Error(
          'dev-served module was replaced by a hot revision and cannot re-serve boot bytes');
      }
      if (devServedDataValue(__devServedTable, candidates[index])) {
```

Real bun fixture: capture a frozen table, `require('/src/dep.ts')` once, invalidate, `require` again — exact message, `quarantines === 0`, `__devRuns === 1`, `nativeResolves === 0` (`src/module_loader/mod.rs:8199-8221`).

### 3. CJS carrier occupancy — RESOLVED

```344:347:src/engine/hermes_runtime_internal.h
  // CommonJS backing records, not their ESM adapters, are carrier occupancy
  // units and retire the reference on every record-erasure path.
  std::optional<CarrierTableKey> carrier_key;
```

Creation copies the factory key and increments occupancy (`hermes_module_runner.cc:2480-2509`). Retirement on unpin (`3015-3024`, `3076-3078`), unpinned release (`3149-3150`), and unpublished discard (`3532-3533`). Adapters do **not** copy `carrier_key`, so they do not double-count.

Mixed fixture: one prepared ESM + one prepared CJS occupy `(2, true)`; unpin drains to `(0, false)` (`module_runner.rs:10238-10276`). Same test also proves CJS release and discard retire occupancy (`10358-10402`). Shared-table survive/evict across ESM commits is the first half of the same test (`10145-10212`).

### 4. CJS-implicated pairs refuse in no-mutation preflight — RESOLVED

```3334:3347:src/engine/hermes_module_runner.cc
      bool commonJsImplicated =
          prior->second.source_goal == 1 || successor->second.source_goal == 1;
      if (!commonJsImplicated) {
        for (const auto& [_, commonjs] : runtime->commonjs_records) {
          if (commonjs.adapter_record_id == priorId ||
              commonjs.adapter_record_id == successorId) {
            commonJsImplicated = true;
            break;
          }
        }
      }
      if (commonJsImplicated) {
        return EXACT_RUNTIME_DRIVE_INVALID;
      }
```

`source_goal == 1` is `SourceGoalV1::CommonJS` (`module_runner.rs:1474-1478`). Adapters copy that goal (`hermes_module_runner.cc:2928`) and are also caught by `adapter_record_id`. This is inside the preflight `try` that returns before any slot/forwarding/erase mutation (`3300-3426`). Fixture `cjs_implicated_hot_revision_pair_refuses_without_mutation` commits adapter ids, asserts `(-1)`, and checks both namespaces unchanged (`module_runner.rs:9774-9794`). Whole-closure CJS engine commit remains the named H1 residual.

### 5. Successor settlement requires `Evaluated` exactly — RESOLVED

Old predicate was `state < Instantiated` (only `New` refused). Now:

```3322:3323:src/engine/hermes_module_runner.cc
      if (!prior->second.published || successor->second.published ||
          successor->second.state != NativeModuleRecordState::Evaluated ||
```

`NativeModuleRecordState` is `New, Instantiated, Declared, Evaluating, Evaluated, Errored` (`hermes_runtime_internal.h:259-266`), so uninitialized, mid-evaluation, and errored all refuse. Fixture instantiates+declares (not yet `Evaluated`) → `(-1)`; after `run_execute` the same pair commits (`module_runner.rs:9960-9983`).

### 6. No-fail fence + quarantine — RESOLVED

Fallible work (pair vectors, forwarding reserve, JSI arrays, UTF-8 strings) is in the first `try`; failure is `INVALID` (`hermes_module_runner.cc:3300-3426`). After the first mutation, failures call `exactRuntimeQuarantine` and return `ENGINE_ERROR` (`3467-3475`). DriveGuard never yields `-5`; the only `-5` paths in this ABI are those two post-mutation returns. Rust maps `-5` only:

```1062:1066:src/engine/module_runner.rs
        if status == -5 {
            bail!(
                "native hot-revision commit failed after publication; runtime is quarantined; recreate the runtime"
            );
```

Engine fixture: throwing invalidator after publication → that exact string, then `ex_hermes_module_pin_generation` returns `-6` (`QUARANTINED`) (`module_runner.rs:10563-10588`).

Rust surface latch is armed on commit entry, cleared only after graph adoption + activation flip (`hot_revision.rs:129-146`); `begin` refuses while latched (`95-97`). Panic fixture (`574-605`) and successful-commit-clears-latch (`608-632`) prove surface behavior.

### 7. Structural production gate + attribution parity — RESOLVED

```3271:3280:src/engine/hermes_module_runner.cc
  // @ref LLP 0042#development-commitment — mutable dev publications are not
  // an armed production-runtime operation.
  if (runtime->armed || graph_generation == 0 || pair_count == 0 ||
      prior_record_ids == nullptr || successor_record_ids == nullptr ||
      ...
    return EXACT_RUNTIME_DRIVE_INVALID;
```

Armed fixture calls the ABI with dummy ids and asserts `-1` “before record lookup” (`module_runner.rs:10614-10630`).

Records retain factory principal + compartment (`hermes_module_runner.cc:3656-3658` ESM, `2475-2478` CJS, `2929-2931` adapter). Preflight requires parity (`3325-3327`). Cross-principal construction is not a public path; the check is defense in depth, as the fix described.

### 8. F5 unchanged-importer TLA continuation — RESOLVED

`f5_unchanged_suspended_tla_importer_resumes_on_the_successor` (`module_runner.rs:9569-9679`): importer `execute` increments `__f5TlaImporterRuns` once and returns a Promise; only the **target** is committed; resume observes successor value `2`; final assert is `"1:2:2"` (run count still one, live `importValue` is 2). `context.importValue` goes through `resolveLiveModuleRecord` forwarding (`hermes_module_runner.cc:4371-4374`, `310-323`), so this is a real slot switch, not a re-run.
