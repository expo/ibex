# LLP 0002: The Host / Embedding ABI

**Type:** Spec
**Status:** Draft
**Systems:** Host ABI, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-16 (adds the target-local Exact GPU artifact builder, the optional versioned GPU service registration seam, and an additive multi-capability construction transaction; the checkpoint publishes no WebGPU JS surface); 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the public Exact-bound artifact preparer)
**Revised:** 2026-07-15 (ENG-25061 adds live indirect/star/namespace export links to native ModuleRecords); 2026-07-15 (ENG-25060 adds the generation-bearing native module-runner ABI and common eval/poll/runner/destroy drive gate); 2026-07-15 (LLP 0026 adopts owner-thread-only serialized runtime-driving entry points); 2026-07-14 (ENG-24933 adds the dedicated binary Exact app/agent ingress and records the UI-worklet non-endowment; earlier source-derived capability inventory reconciliation with the complete typed worklet/Motion ABI); 2026-07-13 (the optional restricted-worklet surface now has an explicit source-artifact + typed-capture installer, fixed f32 invoke/output slots, a bounded typed app-runtime drain, and fixed rated-publish dispatch; earlier that day SharedValues moved from a raw slab pointer to typed validating callbacks); 2026-07-13 (`allowed_hosts` is an outbound remote-host fence and no longer gates independent `network:listen` authority — ENG-24285); 2026-07-12 (armed runtimes reject the generic sync/async host-call bridge and its resolver before any callback/global/pending-state mutation); 2026-07-12 (production construction now requires a runtime-scoped armed Host context; the legacy constructor is non-executable and native fd/socket ownership is runtime-namespaced — ENG-24237, ENG-24244, ENG-24245); 2026-07-09 (host-boundary constraints: `root_dir`/`allowed_hosts` are now enforced fences, ENG-23876; previously 2026-07-07 for the capsec mode collapse); 2026-07-11 (generated capsec ABI inventory — ENG-24145); 2026-07-11 (immutable armed-snapshot install and Hermes handshake — ENG-24148)
**Related:** LLP 0000; LLP 0003 (Hermes engine bridge); LLP 0026 (module-runner owner-thread contract)

## Summary

This document describes the boundary that consumers (Exact, Snapback) link
against to embed Ibex. There are two halves: a small **C ABI** exposed from the
C++ Hermes adapter (`ex_hermes_*`) that creates and drives a runtime instance,
and a **Rust host surface** (`host::{install_host, Host}` plus the `ex_host_*` C
functions) that the engine calls back into for native capabilities. The
"narrow, stable contract" the root document names is the subset of this surface
treated as semver-major: the lifecycle/eval functions plus the host-call bridge
installer. The installer is executable only for explicitly unarmed diagnostic
embedders; its symbol and void signature remain stable, while armed runtimes
silently reject the generic channel. The full `ex_host_*` callback surface is
broader but is an implementation detail of how the engine reaches native
services.

This doc records what is observable in the extracted repo and owns the local
Ibex embedding contract map.

## The narrow consumer contract (semver-major)

The root document (LLP 0000 §Key invariants) names five C functions as the
stable contract. All five are declared in
`include/exact_runtime.h` and defined in `src/engine/hermes_runtime.cc`:

- `ExactHermesRuntime* ex_hermes_create(void)` is retained as the historical
  symbol but deliberately always returns NULL. Production construction is
  `ex_hermes_create_armed(snapshot_digest)`, which atomically claims the exact
  authenticated Host context and verifies structural lockdown, compartments,
  bootstrap seals, and frame attribution before returning a handle.
  `ex_hermes_create_diagnostic()` is an explicitly non-production constructor
  for isolated tests and foreground audit.
- `void ex_hermes_destroy(ExactHermesRuntime*)` `[observed]`
  (`include/exact_runtime.h:41`; `src/engine/hermes_runtime.cc:1455`).
- `int ex_hermes_eval(runtime, data, len, source_url, is_bytecode, out_value)`
  `[observed]` (`include/exact_runtime.h:56`; `src/engine/hermes_runtime.cc:1464`) —
  evaluates UTF-8 JS source or Hermes bytecode; on success `out_value` points to
  a malloc'd result string (or NULL for `undefined`); returns 0 on success,
  non-zero on error with the message in `out_value`.
- `void ex_hermes_free_string(char*)` `[observed]`
  (`include/exact_runtime.h:65`; `src/engine/hermes_runtime.cc:1809`) — frees any string the
  ABI returns; it is a thin wrapper over `free()`.
- `void ex_hermes_set_host_call(runtime, callback)` `[observed]`
  (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`) — installs the
  generic `__hostCall(op, argsJson)` JS function for an unarmed diagnostic
  runtime. It is a silent no-op for an armed runtime.

Treating these as the semver-major contract is asserted in LLP 0000; this doc
does not re-derive the inherited rationale `[inferred: the five are singled out
because they are the minimum surface a host must call to stand up and drive a
runtime — everything else is either a richer convenience (poll, timers,
debugger) or a callback the engine makes, not one the host makes]`.

## What actually crosses the boundary

The header `include/exact_runtime.h` declares far more than five functions
`[observed]` — runtime lifecycle, an event-loop poll API
(`ex_hermes_poll`, `ex_hermes_next_timer`, `ex_hermes_has_pending_tasks`,
`ex_hermes_notify_callback`, `include/exact_runtime.h:76-98`), iOS rendering
callbacks (`ex_hermes_set_dispatch_callback` and siblings,
`include/exact_runtime.h:109-195`), a
debugger surface (`include/exact_runtime.h:216-249`), and GC/heap introspection
(`include/exact_runtime.h:256-264`).
These are part of the embedding API but are convenience/optional layers, not the
minimal contract `[inferred]`.

### Runtime-driving thread contract

Every entry point that drives one Hermes runtime — including creation,
`ex_hermes_eval`, event-loop polling and callback delivery, module-runner
ingresses, and destruction — is owner-thread-only and serialized per runtime.
An off-owner or concurrent drive refuses with a stable error before touching
JSI, graph state, or event-loop state. Same-thread nesting into a *different*
runtime remains permitted and restores the outer runtime's attribution context
on unwind; recursive or overlapping drive of the same runtime is not.

This is the normative contract adopted with LLP 0026. ENG-25060 applies one
registry-backed refusal guard to eval, poll, module-runner operations, and
generation-bearing destruction. It checks liveness and nonce without first
dereferencing the caller's pointer, then owner thread and same-runtime active
drive. Same-thread nested different-runtime entry remains valid because active
drive state is per registry generation. The remaining public JSI-mutating
setter inventory must either use this gate or retain an equivalent explicit
owner check; the generated ABI inventory prevents an unreviewed new route.

### Native module-runner ABI

The provisional `ex_hermes_module_*` and `ex_hermes_graph_context_*` family is
native-only: no symbol is installed on the JavaScript global. Its fixed
`ExactModuleRunnerHandle` payload is an opaque `(runtime nonce, graph
generation, registry id)` capability. Every use checks all three before JSI;
release, wrong-runtime use, destroy/recreate, and address reuse therefore fail
without dereferencing stale payload state.

Rust's safe compiler entry accepts only `VerifiedModuleArtifactV1`, then passes
the admitted semantic digest and factory bytes to the C ABI. Principal,
compartment, generation, and `GraphEvaluationContext` come from native graph
state rather than artifact JavaScript. The engine captures the real Function
constructor and Domain binder before lockdown, never republishes them, and
compiles package bytes through a trampoline whose authenticated Domain is bound
before invocation. Hermes consequently propagates both principal and
compartment to the package factory before compiling it. Opaque factory,
context, and ModuleRecord handles own all JSI values and are destroyed on the
runtime owner thread.

ModuleRecord setup is deliberately split into native-only operations:
declare the record's canonical export-cell set, link indirect, resolved-star,
and namespace exports as live views of authenticated target record/cell
handles, bind authenticated imports to those handles, instantiate the factory,
then run `declare` and `execute`. Instantiation creates one stable
null-prototype, non-extensible
namespace whose enumerable getters read checked cells. Uninitialized reads
throw the TDZ error; export updates mutate the same cells, so later importer
and re-export reads observe live values. Package factories cannot write through
an indirect export. Import lookup keys and all link targets are installed by
the native graph owner rather than accepted from package JavaScript.

CommonJS uses a distinct native record kind and a source-goal-stamped factory
handle. Record creation publishes the initial `module.exports` object before
body execution; `require` can reach only native-installed CommonJS record
links, and re-entry reads the target's current `module.exports`, including an
early replacement. Success retains the final value. A throw deletes the native
record, releases its context reference, and makes its opaque handle stale so a
later request must create a fresh record. After success, one native operation
creates an ESM adapter ModuleRecord whose `default` and `module.exports` cells
hold the final value and whose detector-approved named cells are snapshots.

The CapSec registry classifies graph/context construction and link setup as
authority-control-plane operations, release as authority release, factory
compile/instantiate/declare/execute, CommonJS evaluation, and CommonJS adapter
creation as closed `vm:evaluate`, and diagnostic namespace serialization as
closed `runtime:inspect`. The experimental runner
cannot silently acquire evaluator or inspection authority before ENG-25062
lands its exact graph authorization profile.

This family is a provisional extension, not an addition to LLP 0000's five-
function semver-major minimum. `ex_hermes_try_destroy(runtime, nonce)` is the
generation-bearing, status-returning lifecycle companion; the legacy void
destroy symbol delegates to it and reports owner/reentrancy refusal.

### Restricted-worklet SharedValue access

The optional UI-worklet embedding surface no longer exports or retains a raw
pointer to Exact's SharedValue storage. The embedder installs
`ExWorkletSharedValueReadCallback` and
`ExWorkletSharedValueWriteCallback` with
`ex_worklet_bind_shared_value_accessors`; every access carries the typed
`(slot, generation, epoch)` identity and any nonzero host verdict is a defined
stale/no-op `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime_worklet.cc`). The
callbacks execute synchronously on the restricted runtime's owning UI thread;
they must not enter the app runtime or block on another domain. This is an
optional convenience surface, not part of the five-function semver-major
contract above.

### Restricted-worklet typed Motion ABI

The optional M6 embedding surface admits one explicit artifact format:
`EX_WORKLET_INSTALL_SOURCE_UTF8`. `ex_worklet_install_typed` evaluates a
function expression with an install-time vector of finite f32/boolean captures
or complete SharedValue identities and returns a stable content+capture hash;
same-generation reinstallation reuses the resident function `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime_worklet.cc`). Unknown
formats and capture kinds fail closed. The source decision belongs to Exact's
LLP 0099/0297 contract; Ibex keeps the format discriminant explicit so adding
HBC later is an additive, testable ABI choice rather than byte sniffing.

`ex_worklet_invoke_typed` accepts at most 16 caller-owned f32 inputs and 16
caller-owned output slots. Worklet code writes output with
`worklet.output(index, value)` and can enqueue at most eight finite f32
arguments with `worklet.runOnJS(callbackIdentity, ...args)`. The successful
host path allocates no strings, JSON, or result container. Scheduled calls sit
in a fixed 256-record ring; overflow drops the oldest record and increments the
read-and-clear diagnostic counter. Each record carries stable source identity,
per-source sequence, and runtime generation `[observed]` (same sources).

The embedder drains those records into caller-owned storage, then calls
`ex_hermes_dispatch_worklet_calls` only on the app runtime's owning thread.
Compatibility JSON batches use `ex_hermes_dispatch_worklet_json_batch`. Both
look for app-installed dispatcher functions and return the standard defined
no-op result when absent. `ex_hermes_dispatch_motion_rated_publish` similarly
forwards one fixed, finite eight-value sample to the app-installed rated
publication dispatcher; pacing and lifecycle fencing remain embedder policy.
These are optional convenience surfaces, not additions to the five-function
semver-major contract.

### Capability-security ABI inventory

LLP 0021 adds a source-derived security inventory across the public ABI
families: the Rust/native `ex_host_*` callbacks, the `ex_hermes_*` embedding
surface, the `ex_worklet_*` surface, and the Android Java/JNI bridge. The
current generator finds 126, 55, and 15 symbols in the first three families,
plus one `ex_android_*`, 39 Java, and 8 JNI routes (244 total). It groups source
definitions by target variant, including weak/default stubs, rather than
maintaining a copied symbol list `[observed]`
(`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`). Those rows
are classification and fixture obligations, not a conformance claim; every WP1
target cell remains unsupported.

### The `__hostCall` bridge — the generic host channel

On an unarmed diagnostic runtime, `ex_hermes_set_host_call` installs a JSI host
function named `__hostCall` on the global object `[observed]`
(`src/engine/hermes_runtime.cc`). It is the generic, string-typed channel from
JS to the host:

- JS calls `__hostCall(op, argsJson)` with two strings `[observed]`
  (`src/engine/hermes_runtime.cc:1773-1774`).
- The host callback returns a malloc'd C string whose **first byte is a status
  sigil**: `+` = success (the remainder is a JSON payload), `-` = error (the
  remainder is the message, raised as a `jsi::JSError`) `[observed]`
  (`src/engine/hermes_runtime.cc:1781-1804`). A NULL or empty return becomes JS `null`.
- The C++ side frees the returned string with `free()` and `JSON.parse`s the
  success payload back into a JS value `[observed]` (`src/engine/hermes_runtime.cc:1785,
  1802-1804`).

On the JS side, the runtime wrapper calls `globalThis.__hostCall` directly and
throws if it is not installed `[observed]`
(`packages/ibex-runtime-js/src/core/host-call-bridge.ts:1-16`).

Armed runtimes never expose `__hostCall` or `__hostCallAsync`. Both void setter
ABIs return before storing the callback or mutating the global object, so a
post-lockdown replacement attempt is also a silent no-op. Likewise,
`ex_hermes_resolve_host_call` checks liveness and the armed bit while the
runtime registry is pinned and returns before looking up, removing, or invoking
a pending callback. These functions keep their existing void signatures: the
fail-closed result is intentionally observable as absence/no completion, not a
new ABI return code. Production callers must use dedicated, capability-aware
native APIs. Existing camera and accessibility wrappers already treat an absent
generic bridge as unavailable rather than granting fallback authority
`[observed]` (`src/engine/hermes_runtime.cc`;
`packages/ibex-runtime-js/src/camera/index.ts`;
`packages/ibex-runtime-js/src/core/accessibility.ts`).

### The Exact embedder ingress

Exact app and agent isolates use a dedicated binary channel rather than the
diagnostic string bridge. The native host calls
`ex_hermes_set_exact_host_call_async` once with an explicit context kind and a
strictly increasing set of nonzero 32-bit operation IDs plus the tagged digest
of Exact's operation manifest. In an armed runtime, the snapshot must carry an
`exact/host-operation-endowments/1` binding and protect the manifest as the
conditional `exact-operation-manifest` artifact. Ibex compares the manifest
digest, context kind, and complete canonical ID set against that authenticated
binding before storing native callback state, mutating JSI, or finalizing the
package baseline. A generic armed snapshot without the binding, a mismatched
digest, and narrowed or widened endowments all return `-8` before publication.
The runtime then
exposes only
`exact.invokeHostAsync(operationId, ArrayBuffer | ArrayBufferView) ->
Promise<Uint8Array>`.
Operation names and JSON envelopes do not cross Ibex's boundary, and a JS
caller cannot ask for an operation absent from its immutable endowment set.
Ibex creates one stable lowercase `exact` object before the package baseline is
captured. Successful installation defines `invokeHostAsync` as non-writable and
non-configurable on that shared object and, when the compartment finalizer is
still pending, completes that one-shot finalization in the same owner-thread
setter call. The finalizer hook is then deleted, so package code cannot refresh
or substitute the baseline. A failed refresh leaves no replaceable method.
The setter rejects malformed or duplicate/reordered endowments and rejects any
attempt to replace a successful installation `[observed]`
(`capsec/schema/armed-snapshot.schema.json`; `include/exact_runtime.h`;
`src/engine/hermes_runtime.cc`; `src/host/abi.rs`).
Because installation creates and publishes JSI values, the setter is an
owner-runtime-thread operation. An off-owner call returns `-7` before reading
or mutating JSI or publishing any endowment `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`).
The source inventory nevertheless classifies the JS invocation as closed
`ipc:channel` until the native set and its app/agent context are authenticated
by the armed artifact; the existence of a caller-selected allowlist is not
conformance evidence.

`ex_hermes_resolve_exact_host_call` is the only completion route for this
channel. Its call IDs are runtime-generation-scoped, single-use capabilities;
unknown, stale, replayed, and already-completed IDs are ignored. Completion
copies binary bytes onto the runtime thread through the ordinary native-worker
pin and callback queue. This route is valid for armed runtimes and does not
make either generic `__hostCall` global reachable again.

The channel is bounded to 1,024 pending calls and 16 MiB in either direction.
The native callback runs inline on the runtime owner thread, borrows its input
bytes only for that invocation, and must return promptly. Its callback and
opaque context live until runtime destruction; the embedder cancels outstanding
native work at destruction and never resolves using a destroyed runtime
pointer. Malformed/oversized completions consume and reject the call rather
than stranding its Promise.

The context model is deliberately closed:

- an **app** runtime receives the exact app operation-ID set authenticated by
  its armed artifact (or selected by its explicitly diagnostic host);
- an **agent** runtime receives the separately authenticated agent operation-ID
  set;
- a **UI worklet** cannot install this ingress at all. Its complete endowment
  remains the typed SharedValue/Motion ABI described above.

The native callback remains part of the trusted embedder. Exact owns the
operation registry, payload schemas, and the narrower app/agent sets. Ibex now
authenticates their opaque manifest digest and numeric projection; the normal
Ibex-to-Exact packaging path must supply that protected binding before an Exact
target may advertise. The
existence of this ABI by itself is not target-conformance evidence and does not
relax the unsupported-target refusal.

`ex_host_prepare_exact_armed_embedder_artifacts` is the target-local binding
step. It accepts an already-authenticated generic Ibex template pair plus the
raw Exact operation-manifest bytes, validates the manifest's schema, operation
ordering and uniqueness, exhaustive one-context projection, four exact agent
control operations, nonempty app set, and empty UI-worklet set, then
materializes those exact bytes as an immutable content-addressed fifth
artifact. It derives every endowment from those bytes, freshens the nonce and
paired digest, and re-authenticates the result. This step runs after app
installation: filesystem object identities for the mapped engine and protected
files cannot truthfully be minted on a different packaging machine. It still
cannot advertise or install an unsupported target.

`ex_host_build_exact_armed_embedder_artifacts` is the normal installed-app
producer. It accepts only the installed project-root path and the same raw
manifest bytes, loads the actual mapped engine identity and checked CapSec
identities, authors Exact's canonical empty package policy/graph, binds the
installed project and cache roots, materializes policy, graph, registry, and
manifest as immutable content-addressed artifacts, includes the engine as the
fifth protected object, and returns a construction-fresh authenticated pair.
The producer deliberately does not accept caller-authored identity or package
facts. Exact's current application is a single bundled root; a future
package-bearing application must pass Ibex's canonical generated policy through
a separately specified input rather than being flattened by this API.

`ex_host_build_exact_gpu_armed_embedder_artifacts` is the additive GPU-capable
producer. It accepts the legacy builder's two inputs plus one strict
`exact/webgpu-provider/1` binding and the exact WebGPU profile bytes named by
that binding. It validates the complete provider identity, verifies the profile
digest before publishing anything into the content-addressed cache, records the
binding as `exactGpuProvider`, and materializes the profile as the independent
sixth `exact-webgpu-profile` protected artifact. The returned pair is
re-authenticated through the ordinary armed-snapshot loader. Like the legacy
producer, it cannot advertise a target; installation retains the report-derived
gate.

These six new symbols (`ex_hermes_set_exact_host_call_async`, its resolver,
`ex_host_prepare_armed_embedder_artifacts`, and
`ex_host_prepare_exact_armed_embedder_artifacts`, plus
`ex_host_build_exact_armed_embedder_artifacts` and
`ex_host_build_exact_gpu_armed_embedder_artifacts`) are a public, provisional
extension for the pinned Exact consumer, not an expansion of LLP 0000's five-
function semver-major minimum. Until this Draft spec is accepted, a breaking
change requires an atomic Ibex commit plus Exact submodule/consumer update; it
must never silently preserve an older ambient bridge.

### The optional Exact GPU service registration seam

Ibex exposes a versioned, optional registration boundary for an Exact-owned GPU
service. This is deliberately **not** the physical wgpu-native API. Raw
`WGPUDevice`, `WGPUQueue`, provider function pointers, and provider-owned Rust
types never cross the Ibex boundary. Exact remains responsible for GPU
accounts, authority contexts, semantic validation, sequencing, and physical
provider generations; Ibex sees only opaque realm/account tokens and a copied
`ExactGpuServiceApiV1` table `[observed]` (`include/exact_runtime.h`;
`src/engine/hermes_runtime_gpu.cc`).

`ExactHermesGpuProviderDescriptorV1` binds ABI version, profile identity, the
WebGPU C-vocabulary digest, operation-set digest, semantic-program digest,
topology, and the complete sorted operation-ID set. An armed snapshot may name
the same `exact/webgpu-provider/1` identity and conditionally protects its
profile artifact as `exact-webgpu-profile`. Ibex compares the whole descriptor
through the runtime-scoped Host context before retaining the service or calling
`open_realm`; a generic armed snapshot cannot acquire the seam after creation.
Diagnostic runtimes keep their explicit unarmed test posture. The
`webgpu-binding` Cargo feature controls whether a descriptor can be installed;
the ABI symbols and version query remain present when it is off, and installation
returns the stable unsupported result.

The service owns no Hermes or JSI value. `open_realm` receives a ref-counted
plain-native client sink. It may call `retain_client`/`release_client` while
opening, and it must retain the sink before storing the sink/context beyond
that call, but it may neither call `on_event` nor publish an event-producing
path yet. After a successful open, Ibex validates the returned identities and
enters `Activating` immediately before invoking the required one-way
`activate_realm` hook. `Activating` admits only a synchronous callback on the
runtime owner thread; after the hook returns, Ibex publishes `Live` and admits
service-thread delivery. An earlier callback, including a competing
service-thread callback before the hook returns, is an unambiguous protocol
violation. This explicit handshake closes the race between `open_realm`
returning and asynchronous event admission. This foundation
checkpoint records and discards those plain events only; it does not install
`navigator.gpu`, `createImageBitmap`, or any other JavaScript API. Presence of
the C ABI is therefore neither WebGPU support nor conformance evidence.

The previous Exact setter finalized the package baseline immediately because it
was the only package-visible native addition. Multi-capability embedders use an
additive owner-thread transaction:

1. `ex_hermes_begin_embedder_capabilities_v1` enters `Configuring` before user
   evaluation. A runtime that has already entered eval, poll, debugger eval, or
   native event dispatch cannot begin a transaction.
2. The embedder installs the Exact operation ingress and any authenticated GPU
   service in either order. Setters publish only removable provisional state;
   GPU registration copies the function table and retains the service but does
   not open a realm.
3. `ex_hermes_finalize_embedder_capabilities_v1` verifies that the installed
   capability set exactly equals the armed snapshot, opens the GPU realm with
   the now-final app/agent context, refreshes the compartment baseline once,
   and seals the Exact method. Thus GPU-first and Exact-ingress-first
   installation cannot select different realm identities.

Every user-code-driving entry point refuses while the transaction is
`Configuring` or failed; poll preserves queued callbacks without executing
them.
Finalization failure rolls back the provisional Exact method, closes any opened
GPU realm, and is terminal for that runtime. Existing Exact-only consumers that
do not call `begin` retain the legacy single-setter auto-finalization behavior;
an armed snapshot that expects more than that Exact ingress cannot use the
legacy path.

GPU teardown is a nonblocking release path. Runtime destruction changes the
plain callback mailbox to `Closing`, calls `close_realm` once, changes the
mailbox to `Detached`, releases its service reference, and proceeds without
waiting for a provider terminal event.
The service may finish or quarantine backend work in native state and release
its retained mailbox later. Late callbacks observe `Detached` and are discarded
without dereferencing a runtime address. No realm-long native-worker pin is
permitted; a later JS binding may take only a short generation pin while
enqueueing one owner-thread drain. Release, cancel, retire, and realm close stay
available independently of positive GPU authority.

These GPU and construction-transaction symbols are provisional extensions for
the pinned Exact consumer. Registration/finalization are classified as CapSec
authority-control and the two ABI queries as runtime-bootstrap state; teardown
continues through the existing runtime release path. Every future public GPU
operation remains unsupported until generated operation inventory, typed
effects, fixtures, and target cells are complete.

## The Rust host surface

The engine declares the `ex_host_*` callbacks as `extern "C"` functions on the
C++ side `[observed]` (`src/engine/hermes_runtime.cc`). They are implemented in
Rust in `src/host/abi.rs`. A compatibility Host remains process-visible for
unscoped diagnostic calls, but each live Hermes runtime owns a claimed immutable
Host-context ID. Engine entries and worker callbacks select that context for
their dynamic scope, so installing runtime B cannot replace runtime A's policy.

### Installing the host

- `host::install_host(host: Host)` updates the compatibility default and adds
  an immutable context row. Runtime construction claims one row; engine entry,
  asynchronous completion, and native-resource checks use that runtime's
  context rather than whatever was installed most recently.
- `ex_host_install()` installs only a closed, unarmed compatibility host. A
  production embedder must replace it with `ex_host_install_armed(...)` and
  create Hermes with the authenticated digest; absence or mismatch refuses.
- `EXACT_HOST_ABI_VERSION` is `1`, returned by `ex_host_version()` `[observed]`
  (`src/host/abi.rs:62, 579-581`).

### The `Host` type

`Host` (`src/host/mod.rs:71-76`) holds a `HostConfig`, an
`Arc<CapabilityManager>`, and an `Arc<ModuleLoader>` `[observed]`. Constructors
include `Host::new(config)` and `Host::new_armed(...)`; the latter is the
production constructor. `HostConfig` and `ex_host_install()` are closed by
default and do not parse a policy path. `Host` exposes
`check_capability`, `is_allow_all`, and `resolve_module` `[observed]`
(`src/host/mod.rs:146-174`). `SecurityMode` is `Permissive | Audit | Enforce`
`[observed]` (`src/host/mod.rs:37-45`); the legacy `strict`/`capability`
strings parse to `Enforce` for compatibility. The C++ bridge short-circuits
capability checks when `ex_host_is_allow_all()` returns 1 `[observed]`
(`src/host/abi.rs:597-599`).

### Host-boundary constraints

`HostConfig.root_dir` and `HostConfig.allowed_hosts` are the embedder's
**host-boundary fence** — a restriction plane distinct from the LLP 0013
capability policy (`src/host/mod.rs`, `src/host/capability.rs::fence_denial`,
ENG-23876; both fields were previously stored but never consulted, a fail-open
embedding API):

- `root_dir`: every `fs:*` capability value must name a path inside this root
  (compared symlink-resolved on both sides, same normalization as path-scoped
  grants). Module loading is included: the `module-loader` principal's reads
  are fenced like everyone else's.
- `allowed_hosts`: every outbound `network:*` capability value must name a
  listed remote host. Entries are `host` or `host:port`; a port-less entry
  covers the host across ports via the same scope-specific endpoint matcher
  grants use. This compatibility fence does not gate `network:listen`: local
  bind authority remains an independent policy decision. An empty list denies
  all outbound network access `[observed]` (ENG-24285).

Composition with the capability policy: the fence is checked first and is a
**hard ceiling** — policy grants compose *within* it and cannot widen past it,
it applies to every principal (root and `module-loader` included), and it
denies in **every** `SecurityMode`. Permissive does not bypass it
(`Host::is_allow_all()` returns false whenever a fence is configured, so the
C++ boundary's short-circuit stays off), and Audit does not observe-and-proceed
past it the way it does for policy would-denies: a fence miss is a real denial
in all modes, recorded in the audit log with a `host-boundary:root_dir` /
`host-boundary:allowed_hosts` constraint tag. A capability outside the fence is
also not acquirable through the dynamic-permission prompt path
(`grant_status` reports 0) and cannot be minted into a passable handle.

The CLI does not set these fields (`src/bin/ibex/runtime.rs` passes `None`);
they exist for embedders. Resource-less class values (`fs:read`,
`network:fetch`) claim unbounded authority and are denied whenever the
corresponding fence is configured.

### What the host backs

The `ex_host_*` functions in `src/host/abi.rs` implement, against std/rusqlite/
getrandom: filesystem ops (`ex_host_fs_*`, `src/host/abi.rs:601-1262`), SQLite
(open/prepare/all/get/run/exec, `src/host/abi.rs:1264-1698`), env/time/random
(`src/host/abi.rs:1700-1737`), console mirroring (`ex_host_console_log`,
`src/host/abi.rs:1739`), capability check/grant/log
(`src/host/abi.rs:661-727`), and module resolution (`ex_host_module_resolve`
plus the metadata-only `ex_host_module_resolve_meta` that backs `require.resolve`
without reading/transpiling the body, ENG-23007,
`src/host/abi.rs:730-779` — see [LLP 0004](./0004-module-loading-and-builtins.explainer.md)).
Strings returned to C are malloc'd via `CString::into_raw` and freed by
`ex_host_free_string`/`ex_host_free_buffer` `[observed]`
(`src/host/abi.rs:781-789, 650-659`).

### Memory ownership rules (observed)

- Strings out of the `ex_hermes_*` API are freed with `ex_hermes_free_string`
  `[observed]` (`include/exact_runtime.h:64-65`).
- Strings out of the `ex_host_*` API are freed with `ex_host_free_string`; raw
  buffers from `ex_host_fs_read_file` are freed with `ex_host_free_buffer`
  `[observed]` (`src/host/abi.rs:650-659, 781-789`).
- The `__hostCall` callback's returned string is freed by the C++ side, not the
  host `[observed]` (`src/engine/hermes_runtime.cc:1785`).

## Lifecycle (observed)

The typed production path adds an explicit authenticated lifecycle alongside
the legacy entry points: `ex_host_install_armed(snapshot, expected_identity)`
strictly parses and authenticates caller-owned bytes, copies them into an
immutable host decision context, and `ex_hermes_create_armed(digest)` creates
Hermes only when that installed context has the exact digest. Mismatch or
absence returns failure before a runtime exists. The ordinary
`ex_host_install` entry point installs a closed unarmed placeholder, not an
allow-all production runtime.

1. Host installs itself first: a Rust embedder can call
   `install_host(Host::new(...))`; the local `ibex` binary does this from CLI
   security configuration, while the C entry point `ex_host_install()` installs
   only the closed placeholder; production uses `ex_host_install_armed`
   (`src/host/abi.rs:107-121, 586-592`). The CLI/iOS split is recorded in a
   source comment and now in the local binary implementation `[observed]`
   (`src/host/abi.rs:586-588`; `src/bin/ibex/runtime.rs`;
   [LLP 0010](./0010-ibex-binary-ownership.decision.md)).
2. `ex_hermes_create()` builds the Hermes runtime, installs globals and runs
   bootstrap (see [LLP 0003](./0003-hermes-engine-bridge.explainer.md)).
3. An unarmed diagnostic embedder may call `ex_hermes_set_host_call()` to wire
   `__hostCall`; the same call on an armed runtime is a silent no-op.
4. The host drives execution via `ex_hermes_eval` and may pump the loop with
   `ex_hermes_poll(now_ms)` `[observed]` (`include/exact_runtime.h:71-91`;
   `src/engine/hermes_runtime.cc:1815-1949`). Source comments document a
   `cli-notify` replacement for the default callback path `[observed]`
   (`src/engine/mod.rs:18-37`).
   A host retaining a runtime for an asynchronous watchdog must snapshot its
   nonce with `ex_hermes_runtime_nonce()` while it owns the live handle and
   call `ex_hermes_schedule_watchdog_heartbeat_for_generation()`. The legacy
   raw-pointer-only watchdog symbol remains ABI-compatible but fails closed;
   it cannot safely infer which generation an address once named `[observed]`
   (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`).
5. `ex_hermes_destroy()` must run on the runtime's owner thread. It marks the
   pointer-plus-nonce registry identity closing, unregisters/cancels native
   callback sources, drains generation-scoped producer pins, and destroys
   queued JSI captures on that owner thread before deleting Hermes. Registry
   removal happens only after the drain, so delayed work cannot enter a later
   runtime whose handle reuses the same address `[observed]`
   (`src/engine/hermes_runtime.cc`; [LLP 0003](./0003-hermes-engine-bridge.explainer.md#the-event-loop)).

## Notes / boundaries

- The Rust crate is named `ibex-runtime`. Many C ABI symbols and JavaScript
  internals remain `ex_`/`EXACT_`-prefixed for compatibility `[observed]`
  (`Cargo.toml:2`; LLP 0000 §Architecture).
- This is a Spec of the *observed* contract surface; changes to the narrow
  consumer contract should update this document and LLP 0000 together.
