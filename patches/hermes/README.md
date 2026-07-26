# Carried Hermes patch stack (LLP 0013)

The Ibex Hermes pin (`scripts/hermes-version.sh`, currently
`260318099.0.0-stable`) **plus this ordered patch series is the fork** — the
Electron model at small scale. There is no separate long-lived fork repository.
`scripts/apply-hermes-patches.sh` applies the series after clone/checkout in
every `build-hermes*.sh`; it is idempotent and fails loudly if a patch stops
applying (the drift signal).

## Patch identity discipline

Every `diff --git` section carries exactly one authoritative `index` line with
full 40-hex preimage and postimage blob IDs. Additions use 40 zeroes for the
absent preimage; deletions use 40 zeroes for the absent postimage. The
corresponding unchanged, new-file, deleted-file, or old/new mode directives are
authoritative too.

`scripts/apply-hermes-patches.sh` snapshots every regular patch file once, then
uses only those read-only bytes to replay the complete ordered series into a
temporary Git index before touching the working tree. It checks each old blob
and mode, applies one patch to that isolated index, checks each new blob and
mode, and records the resulting prefix tree. The public patch bytes are
re-hashed before and after materialization so a concurrent authority edit fails
closed. It then applies only the suffix missing from the working tree and
compares the complete tracked checkout plus every ignored or non-ignored
untracked input with the selected prefix and final trees, without changing the
checkout's real index. Source builders therefore clean build outputs before
verification. A patch-body edit requires re-deriving its postimage IDs and
every affected downstream pre/postimage from the pinned source; a context-clean
`git apply` by itself is not sufficient evidence.

Each patch is classified in its header:

- **Class A — additive files** (new `.cpp`/`.h`, new JSI surface): rebase cost ~zero.
- **Class B — insertion points** (an `#include`, a call, a field at a marked site): rebase cost minutes; conflicts mechanical.
- **Class C — surgical semantic changes** (the interpreter `GetGlobalObject`/`this` cases, `eval`/`Function` binding): the only patches that can conflict meaningfully. Budgeted at single digits total.

A cross-cutting rewrite (realm-shaped) is prohibited by this discipline — that
is the line between "carrying patches" and "maintaining a divergent engine."

## Applied patches (Phases 2, 3 + 5, structured evaluation)

| # | File | Class | What |
|---|---|---|---|
| 0001 | `0001-domain-package-principal.patch` | B | Adds `Domain::packageId_` (a POD `uint32_t`; no metadata-builder change) + `get/setPackageId()`. The capability principal that owns a Domain's code. |
| 0002 | `0002-frame-attribution-helper.patch` | A (+1 B CMake line) | Adds `VM::getCurrentPackageId(Runtime&)` (nearest *user* frame's `packageId`, skipping native frames and runtime-internal deputy frames — principal `0xFFFFFFFF`), `VM::collectStackPackageIds` (the distinct user principals on the stack, innermost-first — the Phase 5 substrate), and the exported `extern "C"` bridge (`ex_hermes_vm_current_package_id` / `collect_package_ids` / `set_pending_package_id` / `set_default_package_id`) reachable through `IHermes::getVMRuntimeUnsafe()`. |
| 0003 | `0003-capability-bridge-exports.patch` | B (+1 C site) | Adds `Runtime::{setPendingPackageId,setDefaultPackageId,consumePendingPackageId}` + backing fields, and the single semantic insertion in `runBytecode` that stamps each fresh `Domain` with the pending-or-default principal. |
| 0004 | `0004-native-compartment-globals.patch` | B (+4 C sites) | Native per-package compartment globals (Phase 3). Adds `Domain::compartmentGlobal_` (GC-traced, with metadata field) + accessors, the native `__exactSetCompartmentFor(fn, obj)` in `initGlobalObject`, and re-points the interpreter's `GetGlobalObject`/`CoerceThisNS`/`LoadThisNS` — and top-level `var` declarations (`DeclareGlobalVar` / `Interpreter::declareGlobalVarImpl`) — through the frame's compartment global (`globalForFrame(runtime, curCodeBlock)`). Bare globals, sloppy-`this`, and top-level `var` declarations resolve through the frame's compartment when set — no build-time source rewrite. |
| 0005 | `0005-native-compartment-refinements.patch` | B (+1 C site) | Phase 3 refinements: a `Runtime::anyCompartmentActive_` hot-path guard so non-compartment code skips the Domain walk; the native `__exactNativeFreeze(obj)` freeze primitive; and `getCurrentCompartmentGlobal` (the helper for the eval/Function call-site binding). |
| 0006 | `0006-eval-binding-and-native-deep-freeze.patch` | B (+1 A export) | `eval`/`Function` compartment binding + native deep-freeze (Phase 3). `evalInEnvironment` captures the caller's principal + compartment (frame still current there) into a GC-rooted `Runtime::pendingCompartment_`; `runBytecode` stamps both onto the minted Domain, so eval/`new Function` code inherits the caller's compartment and cannot escape it. Adds `clearPendingPackageId()` / `ex_hermes_vm_clear_pending_package_id` (clearing ≠ pinning 0). Adds `__exactDeepFreeze(obj)` — a native SES-style transitive freeze that walks descriptors (getters/setters read without invoking) + prototype via an iterative worklist with an explicit visited set (GC-safe; distinct from the frozen bit; no recursion-depth cap) — for a native boot-time lockdown (`IBEX_NATIVE_LOCKDOWN`). |
| 0007 | `0007-fail-closed-async-deputy-attribution.patch` | B | Fails closed on the async/deputy attribution boundary. `getCurrentPackageId` now returns a distinct `kNoUserPrincipal` (`0xFFFFFFFE`) when the walk finds NO user frame (vs. the old `0`, which the host trusts as first-party root) — so a package cannot launder a deputy op detached from its own frame (`Promise.resolve(x).then(fs.readFileSync)`) into trusted root. And the internal bytecode (Hermes's JS Promise impl) is stamped with the runtime principal at load, so its reaction trampoline (`tryCallOne`) is skipped as a deputy instead of appearing as packageId 0 on every microtask. |
| 0008 | `0008-schedule-time-principal-capture.patch` | B | Completes 0007 for the deputy-class case (ENG-22631). 0007 fails closed only when the detached callback is *native* (empty stack); a detached JS deputy method (`Promise.resolve(x).then(deputy.readFor)` under `deputyClasses`) drains with the deputy's own frame live, so `collectStackPackageIds` returns `[deputy]` (len 1) and the stack-AND is skipped. This patch captures the SCHEDULING principal at `enqueueJob` (the scheduler's frame is still live there), carries it in a `jobSchedulerQueue_` kept in lockstep with `jobQueue_`, restores it as ambient `Runtime` state across `drainJobs`, and has `collectStackPackageIds` APPEND it — so the detached read collects `[deputy, scheduler]` and the AND denies for an ungranted scheduler while a granted package's own continuation (scheduler == running principal) collapses and is not false-denied. Ibex arms capture whenever the patched engine is present because deputy classes may be configured after engine creation and native-resolved continuations may otherwise report `kNoUserPrincipal`; the host consumes the captured scheduler for live deputy stacks and that no-user fallback. |
| 0009 | `0009-raw-throw-capture.patch` | B | Adds an owner-thread scoped Hermes control that suppresses `.message` / `.stack` property reads and `String` coercion while a pending exception crosses JSI. The structured evaluator can therefore retain the exact thrown value without invoking project code; legacy evaluation keeps Hermes' default diagnostics. |
| 0010 | `0010-completion-record-discriminator.patch` | B | Preserves the VM's `Empty` completion discriminator across the JSI conversion that otherwise collapses it into `undefined`. Structured evaluation can now distinguish a declaration/empty completion from the JavaScript value `undefined` without a syntactic last-expression heuristic. |
| 0011 | `0011-structured-async-failure-provenance.patch` | B | Captures Promise-job scheduler, job identity, and associated evaluation at enqueue time; exposes failed-job context to the host; adds a poll-checkpoint rejection tracker that cancels by Promise identity; extracts a closed Error class from internal direct-prototype identity; and source-bounds Stage-1 primitive text plus Error message/stack to 16 KiB of valid UTF-8 including an explicit trusted truncation marker, without invoking project code or first materializing attacker-sized text. |
| 0012 | `0012-keyed-external-arraybuffer-alias.patch` | B | Adds an extension-neutral construction-private Hermes interface that mints overlapping `ArrayBuffer` aliases over one source byte block, promoting an internal source's existing allocation to shared external ownership in place without copying or replacing the source. It tags aliases with a private keyed-external detach capability, refuses ordinary transfer, and detaches them only through the matching native key. The engine API is not a JavaScript intrinsic; embedders negotiate it through the runtime-extension SDK. |

All twelve apply clean from pristine (`scripts/apply-hermes-patches.sh`) to
tree `a6e9b222128ab97f9b740839e354f8edd357a388` and
compile into a working `hermesvm.framework` exporting the `ex_hermes_vm_*`
symbols (`current_package_id`, `set_pending_package_id`, `clear_pending_package_id`,
`set_default_package_id`, `collect_package_ids`, `set_job_scheduler_capture`,
`current_job_scheduler_principal`, `current_job_identity`,
`current_job_associated_evaluation`, `set_job_associated_evaluation`,
`set_embedder_job_scheduler_principal`, and `take_failed_job_context`),
verified against the pinned checkout (`ac8c6e6c80ec…`, HEAD of
`origin/260318099.0.0-stable`).

### Phase 2 integration — DONE (Ibex-side, no Hermes patch)

1. **Set the principal.** The module loader (`src/engine/bootstrap/module-loader.js`)
   assigns each package a principal id (`packagePrincipalFor`), registers id→name
   via `__exactRegisterPackage` → `ex_host_register_module_package`, and stamps
   each module's Domain by calling `__exactSetPendingPackageId` right before
   `new Function(body)` (`compileModuleBody`). Builtin modules (`node:fs`, …) get
   the runtime principal `0xFFFFFFFF` so they are transparent deputies. The
   bootstrap default principal is set to `0xFFFFFFFF` during boot and reset to 0
   before user code runs (`src/engine/hermes_runtime.cc`).
2. **Read the principal.** `checkCapability` (`hermes_runtime_internal.h`) calls
   `currentPrincipalId()` → `ex_hermes_vm_current_package_id` when
   `EXACT_HAVE_FRAME_ATTRIBUTION` is set (build.rs probes the framework for the
   symbol; unpatched engines fall back to the thread-local and still link).
   Demonstrated on an armed runtime by
   `capsec_public_callback_invariant_batch::capsec_callback_invariant_mechanisms_smoke`
   (package callback attribution, generation recheck, and root restoration).

   *Deputy caveat (RFC Open-Q3).* Ibex's high-level host surfaces are JS modules
   layered over the native `__exact*` functions. Attribution reaches through them
   only because those deputy Domains carry the runtime principal (skipped by the
   walk). `process.env` is an eager snapshot (never capability-checked), and
   `fs.writeFileSync` fires an `fs:read` but not an `fs:write` check in the
   current runtime — the conformance test therefore discriminates on
   `fs.readFileSync`.

### Phase 5 integration — DONE

`collectStackPackageIds` feeds `ex_host_check_capability_stack`; `checkCapability`
uses it only when `ex_host_has_deputy_classes()` (policy `deputyClasses`). See
`capsec_semantics::decision::tests::mixed_principal_order_and_package_root_owner_preserve_deputy_intersection`
and the armed callback invariant smoke test.

## Phase 3 — native compartments

- **`GetGlobalObject` per-frame resolution — DONE (patch 0004).** The three
  interpreter sites resolve through `globalForFrame(runtime, curCodeBlock)`;
  `Domain::compartmentGlobal_` + accessors + metadata field land in the same
  patch, and the loader binds each package's Domain via the native
  `__exactSetCompartmentFor`. Demonstrated by
  `capsec_public_callback_invariant_batch::capsec_callback_invariant_mechanisms_smoke`
  (bare `process`, authority globals, dynamic evaluators, and the sloppy-`this`
  escape are withheld from an authenticated package callback). Perf note: the added branch is on the hottest opcode; the
  compartment-present fast-flag (`anyCompartmentActive_`, patch 0005) makes it a
  single predicted-not-taken branch when no compartment is bound. Measured with
  `benches/compartment_overhead.rs` (A/B on the guard, hot loop in root): the
  steady-state overhead is within noise (≈0%, well under the Goal 3 ≤1% budget).

Landed refinements (patch 0005): the `anyCompartmentActive_` hot-path guard and
the native `__exactNativeFreeze` freeze primitive.

- **`eval`/`Function` compartment binding — DONE (patch 0006).** The capture
  happens in `evalInEnvironment` (`lib/VM/JSLib/eval.cpp`), where the caller's
  frame is still on the stack — unlike `runBytecode`, where it is gone. It reads
  `getCurrentPackageId` + `getCurrentCompartmentGlobal` and stashes them as
  pending (the compartment in the GC-rooted `Runtime::pendingCompartment_`);
  `runBytecode` stamps both onto the Domain it mints. So `eval` and `new Function`
  produced code inherits the caller's compartment (cannot escape to the root
  realm) and its attribution. The capture is skipped when a principal was already
  labelled explicitly, so the loader's own module compiles keep their principal;
  the loader `clearPendingPackageId()`s (rather than pinning 0) after each compile
  so the next eval is seen as unlabelled and inherits its caller. Demonstrated by
  the armed callback invariant smoke test and the closed public evaluator batch;
  package compartments withhold the constructors, while the root copies are
  structurally tamed and cannot evaluate source.
- **Native deep-freeze — DONE (patch 0006).** `__exactDeepFreeze(obj)` is a
  native SES-style transitive freeze: each object frozen via `JSObject::freeze`,
  walking property *descriptors* (data values + accessor getter/setter
  functions, read WITHOUT invoking getters) and the prototype. The walk is an
  iterative worklist with an explicit visited set — distinct from the frozen bit
  (so an object someone already shallow-froze is still descended into and
  deep-frozen, per SES `harden`), and iterative rather than recursive (so there
  is no native-stack depth cap silently truncating deep graphs). Getter and
  setter are rooted in handles before either is enqueued, so the moving young-gen
  collector cannot leave the `PropertyAccessor` pointer dangling mid-walk
  (ENG-22946). The armed lockdown harness (`hermes_runtime.cc`)
  freezes each intrinsic root with `__exactDeepFreeze` instead of the userland
  `harden` graph walk. Demonstrated by
  the callback invariant smoke test: intrinsics are frozen without invoking
  project code, mutation is blocked, and both native freeze primitives are
  sealed before the package callback runs.

## Pin-bump runbook

1. Update `IBEX_HERMES_SOURCE_REF` (branch) and `IBEX_HERMES_SOURCE_COMMIT`
   (the commit the build scripts actually check out — ENG-23092) in
   `scripts/hermes-version.sh`.
2. Build (the build scripts re-apply this series automatically). Class A/B
   resolve mechanically; for a Class C conflict, re-read the surrounding
   upstream change before resolving. Re-derive full blob/mode identities for
   every changed and downstream-affected diff, then require the verifier to
   print the reviewed final tree without modifying the checkout index.
3. Run `scripts/apply-hermes-patches.test.sh` (optionally point
   `IBEX_HERMES_TEST_SOURCE_REPO` at a local Hermes object cache), followed by
   the full CapSec conformance matrix, including the armed callback and
   closed-evaluator batches, `cargo test --test llp0013_compartments` (the
   checked legacy-retirement join plus migrated native regressions), the runtime
   tests, and perf gates.
4. Land the pin bump + any patch updates in one commit; note in LLP 0013's
   revision log if semantics moved.

Target: routine bump ≤ half a day. Two consecutive bumps exceeding ~2 days each
is the signal to drop the costliest Class C patches back to their Phase 1
userland equivalents and keep A/B (see LLP 0013 §Contingencies).
