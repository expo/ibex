# LLP 0002: The Host / Embedding ABI

**Type:** Spec
**Status:** Draft
**Systems:** Host ABI, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-18 (adds the authenticated production-private `GPUDevice.createBuffer` Web IDL conversion, bounded structural transport, six-field wrapper target, wrapper-local immutable `usage`/`mapState` metadata, ordered semantic boundary, dual-ledger accounting evidence, and 21-call positive/adversarial corpus without installing native execution or a CapSec edge); 2026-07-18 (adds the authenticated production-private `GPUDevice.createPipelineLayout` Web IDL, full-reference transport, semantic-boundary program, wrapper target, and positive/adversarial corpus without installing native execution); 2026-07-18 (separates the complete post-WebIDL bind-group-layout structural transport type from the post-decode TypeGPU workload predicate); 2026-07-18 (consumes Exact-generated wrapper pins as the sole normalized digest/route authority and classifies the immutable 25-operation triangle separately from explicit TypeGPU graduates)
**Revised:** 2026-07-18 (derives all 101 `GPUTextureFormat` values from pinned `@webgpu/types@0.1.71`, preserves them through bind-group-layout structural transport, and adds the zero-resource semantic-boundary corpus witness); 2026-07-18 (repairs observable `GPUDevice.createBindGroupLayout` Web IDL ordering, Get-once sequence conversion and EnforceRange behavior, and carries canonical WebIDL-valid descriptor variants through the bounded transport so the pinned TypeGPU predicate runs after decode); 2026-07-18 (adds the authenticated `GPUDevice.createBindGroupLayout` payload-codegen program for the exact pinned TypeGPU descriptor closure, wrapper-allocated target joins, and positive/adversarial corpus without installing a native codec or provider); 2026-07-17 (adds the authenticated `GPUDevice.createShaderModule` payload-codegen program, exact converted descriptor, wrapper-allocated target joins, and semantic-terminal mapping without installing a native codec or provider); 2026-07-17 (adds the authenticated `GPUDevice.destroy` payload-codegen program, authoritative sealed-record shape, and exact semantic-terminal/device-error mapping without installing a native codec or provider); 2026-07-17 (adds the requestDevice payload-codegen prerequisite, native-owned descriptor/result derivations, and ASSIGNED_DETACHED without installing a native codec or provider); 2026-07-17 (adds the authenticated requestAdapter payload-codegen program and carrier-projected positive interoperability vectors without installing a native payload codec); 2026-07-17 (authenticates the injection-only IBGQ/IBGR/IBGL codec layout in the C-vocabulary projection, generates a language-neutral manifest/corpus from the executable converter, and preserves unknown post-WebIDL adapter feature levels for the local-null semantic branch); 2026-07-17 (records the pinned TypeGPU workload closure as private staging metadata while keeping its 30 operations beyond the reviewed triangle unroutable and absent from prototypes); 2026-07-16 (makes ASSIGNED + NOT_ADMITTED requestDevice results self-contained detached-loss operation terminals without lifecycle tombstones); 2026-07-16 (ENG-25087 adds the production-private 25-operation wrapper factory and executable-codec install gate; the embedded codec authority remains absent, so no public WebGPU surface is installed); 2026-07-16 (adds the additive Exact GPU ABI V2 typed carrier, authenticated runtime-routing digest, any-thread typed lifecycle mailbox, service-entry/realm-close linearization, and construction-private V2 bridge; V1 remains unchanged); 2026-07-16 (adds the construction-private low-level GPU bridge, bounded receipt mailbox/drain, and cancellation/retirement lifecycle without publishing `navigator.gpu` or claiming WebGPU support); 2026-07-16 (adds the target-local Exact GPU artifact builder, the optional versioned GPU service registration seam, and an additive multi-capability construction transaction); 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the public Exact-bound artifact preparer)
**Revised:** 2026-07-16 (defines synchronous GPU callback followed by provider rejection as a quarantining protocol contradiction); 2026-07-15 (ENG-25061 adds live indirect/star/namespace export links to native ModuleRecords); 2026-07-15 (ENG-25060 adds the generation-bearing native module-runner ABI and common eval/poll/runner/destroy drive gate); 2026-07-15 (LLP 0026 adopts owner-thread-only serialized runtime-driving entry points); 2026-07-14 (ENG-24933 adds the dedicated binary Exact app/agent ingress and records the UI-worklet non-endowment; earlier source-derived capability inventory reconciliation with the complete typed worklet/Motion ABI); 2026-07-13 (the optional restricted-worklet surface now has an explicit source-artifact + typed-capture installer, fixed f32 invoke/output slots, a bounded typed app-runtime drain, and fixed rated-publish dispatch; earlier that day SharedValues moved from a raw slab pointer to typed validating callbacks); 2026-07-13 (`allowed_hosts` is an outbound remote-host fence and no longer gates independent `network:listen` authority — ENG-24285); 2026-07-12 (armed runtimes reject the generic sync/async host-call bridge and its resolver before any callback/global/pending-state mutation); 2026-07-12 (production construction now requires a runtime-scoped armed Host context; the legacy constructor is non-executable and native fd/socket ownership is runtime-namespaced — ENG-24237, ENG-24244, ENG-24245); 2026-07-09 (host-boundary constraints: `root_dir`/`allowed_hosts` are now enforced fences, ENG-23876; previously 2026-07-07 for the capsec mode collapse); 2026-07-11 (generated capsec ABI inventory — ENG-24145); 2026-07-11 (immutable armed-snapshot install and Hermes handshake — ENG-24148)
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
provider generations. ABI V1 keeps its opaque realm/account tokens and copied
`ExactGpuServiceApiV1` table unchanged. The additive ABI V2 uses exact-size,
generation-bearing realm/account/device/object records and a copied
`ExactGpuServiceApiV2` table `[observed]` (`include/exact_runtime.h`;
`src/engine/hermes_runtime_gpu.cc`; `src/engine/hermes_runtime_gpu_v2.cc`).

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

`ExactHermesGpuProviderDescriptorV2` is selected only by the exact V2 ABI
version; V1 never accepts or aliases it. It adds a mandatory
`runtime_routing_digest` over the operation-selected public/service codecs,
public-wrapper-to-service receiver projection, target kind, timing,
dispatch/provider mode, result shape, and typed error tags. Descriptor, service
table, event envelope, and selected event record all require their exact
compiled sizes: neither undersized nor oversized prefix compatibility is
accepted. The armed snapshot carries the routing digest only for ABI V2, and
the Host authorization comparison includes it before the service is retained.

The service owns no Hermes or JSI value. `open_realm` receives a ref-counted
plain-native client sink. It may call `retain_client`/`release_client` while
opening, and it must retain the sink before storing the sink/context beyond
that call, but it may neither call `on_event` nor publish an event-producing
path yet. After a successful open, Ibex validates the returned identities and
enters `Activating` immediately before invoking the required one-way
`activate_realm` hook. That invocation boundary, represented by the
`Installing -> Activating` transition, is the callback-admission linearization
point: once it has been crossed, `Activating` admits callbacks from any provider
thread, including a worker that wins the race after the hook returns but before
Ibex publishes `Live`. A callback observed while still `Installing` is an
unambiguous protocol violation. This explicit handshake closes the race between
`open_realm` returning and asynchronous event admission without imposing a
provider-thread-affinity requirement.

The Ibex binding does own owner-thread-only JSI roots for the low-level bridge
and pending Promise resolvers. During successful construction, runtime-js
installs a one-shot non-enumerable capture callback. Native finalization passes
the bridge object directly to that callback, verifies the callback deleted
itself, and retains the returned revoker. No app/module/eval/debugger entry can
run while the callback is open: the common user-execution fence closes an
unused callback first, and the native module-runner compile/carrier/instantiate/
declare/execute and CommonJS-record evaluation entries use that same fence.
Closing is verified, not best effort: successful capture, feature-off and
no-provider finalization, provider rollback, and the common user-entry fence
all prove that the construction property is absent. A throwing, non-callable,
or non-configurable hostile replacement marks capability construction failed
and leaves `user_execution_started` false. The captured value lives only in the
bootstrap module graph. `@ibex/runtime-js` exports no accessor, and Ibex's app
module loader rejects package-deep and filesystem paths into `src/webgpu/`.
The production-private WebGPU factory imports this same bundled slot and binds
the wrapper revoker to the native bridge revoker rather than acquiring a
second bridge or extending bridge lifetime.

The private factory implements only the reviewed 28-operation wrapper shape
and consumes a generated route plan. Installation is a separate fail-closed
step requiring all of: the authenticated V2 bridge, the app realm, an
unoccupied public surface, and an exact executable codec bundle whose four
authority digests and operation IDs match that plan. The generated
injection-only codec bundle, language-neutral manifest, and byte corpus derive
from the same reviewed authority. Manifest schema 2 also carries authenticated,
machine-readable payload-codegen programs for `GPU.requestAdapter`,
`GPUAdapter.requestDevice`, `GPUDevice.createBindGroupLayout`,
`GPUDevice.createBuffer`,
`GPUDevice.createPipelineLayout`,
`GPUDevice.createCommandEncoder`,
`GPUDevice.createShaderModule`, and `GPUDevice.destroy`: ordered primitive and
recursive layouts, the closed
post-WebIDL option dictionary, route-selected catalog tags, every duplicated
`ExactGpuSemanticCallV2` join, and the distinct empty-NULL and IBGR-object
completion-payload programs. The requestDevice request carries only the
untrusted WebIDL-converted descriptor as semantic-service ingress. The native
payload codec preserves unknown non-undefined `requiredLimits` names as own
dictionary entries (including names such as `__proto__`); the semantic service,
not conversion or payload decoding, rejects them with the specified Promise
`OperationError` before provider admission. The native
semantic service must derive the exact logical provider descriptor and allocate
the result-selection identity, cross-link those native-owned results to the
authenticated carrier and completion payload, and keep the raw descriptor out
of the provider boundary. The five device-object creation requests admit a
bounded canonical sealed-local-timeline sequence as comparison input, join a
wrapper-allocated target with the authenticated device provenance, and accept
only their reviewed converted descriptor. The command encoder accepts
`{label: string}` and the shader module accepts `{label: string, code: string}`.
The buffer converter performs each observable Get and conversion exactly once
in inherited Web IDL order — `label`, `mappedAtCreation`, required `size`, then
required `usage` — and stops before later Gets on failure. Its closed structural
descriptor carries an owned label, defaulted boolean, safe integer size through
256 MiB, and u32 usage flags; the 16 MiB payload limit does not cap the numeric
allocation size. The wrapper target carries kind plus object, logical-device,
and provider generations. `GPUBuffer.usage` and `mapState` are immutable
wrapper metadata reads (`mapped` only when created mapped, otherwise
`unmapped`) and never dispatch. The corpus pins 21 reviewed calls totaling
49,545,804 resource bytes. A mapped extent records the same backing without a
second resource charge, staging starts at zero, and any distinct later staging
allocation must win an atomic leaf-plus-envelope top-up before publication.
The bind-group-layout Web IDL converter performs inherited and lexicographic
dictionary-member conversion in observable order, converts each sequence
member before requesting the next, and carries the complete canonical WebIDL
structural vocabulary through the generic transport. This checkpoint still
imposes the authenticated carrier's global 1,024-member and 16 MiB bounds; it
does not claim an unconstrained browser WebIDL surface. The authenticated
transport type therefore admits zero through 1,024 entries, any subset of the
five optional resource-layout members (including zero or multiple members),
the complete buffer/sampler/texture/storage enum vocabularies, all six texture
view dimensions for both texture layouts, the 101 formats derived from pinned
`@webgpu/types@0.1.71`, and `GPUSize64` values in Web IDL's nonnegative
JavaScript-safe integer range. It carries no TypeGPU workload constraints;
those belong exclusively to the semantic-service predicate. After decode, the
semantic service admits only a UTF-8 label of at most 57 bytes and one through
five entries whose bindings are the unique contiguous prefix in array order,
whose visibility is exactly 2, 6, or 7, and whose entry has exactly one of the
pinned buffer, sampler, texture, or storage-texture layouts. That semantic
predicate rejects external textures, comparison samplers,
dynamic/nonzero-min-size buffers, non-float/non-2d/multisampled textures, and
storage textures other than write-only `rgba16float` 2d. Logical descriptor
validation precedes handle and aggregate-envelope reservation. All four map
the same semantic terminal
classes: synchronous Web IDL rejection produces no service call, later
predicate rejection produces a typed device-error event, and admitted success
produces an empty RESULT_NONE terminal receipt.

The pipeline-layout Web IDL converter separately preserves the structural
`GPUPipelineLayoutDescriptor` domain. It performs inherited dictionary
conversion exactly once in observable `label`, required `bindGroupLayouts`,
then `immediateSize` order; sequence element conversion uses branded nullable
`GPUBindGroupLayout` references and closes the iterator if branding throws.
The canonical descriptor transports every non-null layout as the full object
reference tuple (kind plus object, logical-device, and provider generations),
while allowing empty sequences, null positions, up to the carrier's 1,024
members, any `GPUSize32` immediate value, and labels up to the generic payload
bound. Those are structural facts, not semantic admission. After decode the
semantic service authenticates each reference against the current live,
nonexclusive device object table, requires the reviewed one-to-two non-null
groups and the logical `maxBindGroups`, concatenates retained bind-group-layout
binding metadata, and checks per-stage uniform/storage buffers, samplers,
sampled/storage textures, and dynamic uniform/storage counts against the
logical limits. It also enforces immediate-size alignment and
`maxImmediateSize`, the reviewed 43-byte UTF-8 label bound, and target/account
reservation before provider admission. Foreign, stale, exclusive, null,
empty, oversized, aggregate-limit, immediate, and label failures therefore
remain device-timeline semantic rejections after successful Web IDL conversion
and payload decode.

The closure comes from replaying both pinned TypeGPU 0.11.9 workloads: 16 creation
calls and 43 entries, with at most five entries per call. The replay pins the
lowered workload source SHA-256
`cfa48b472c11025e8cad97e1976da118d59011b5be1d95bea1495f958aac0933`;
all observed labels were ASCII and the longest encoded to 57 bytes. No observed
entry used an external texture, comparison sampler, dynamic buffer, nonzero
minimum binding size, alternate texture shape, or alternate storage-texture
format/access/dimension.

The destroy request admits a bounded canonical
sealed-local-timeline sequence only as untrusted comparison input. Each real
record uses the normalized wrapper authority's numeric wire `operationId`,
`operationName`, nonzero wrapper-local `operationInstanceId`, full
`receiverRef`, nullable `wrapperAllocatedTargetRef`, `argumentBody`, optional
logical error, and device-ingress/captured-scope provenance; wrapper-local
properties that the authority marks not-carried are not timeline records. The
semantic service still authenticates the contiguous prefix and owns lifecycle,
idempotence, cleanup-predicate, provider-admission, and physical-sequence
decisions. The completion program maps the three exact semantic terminals:
`repeat-cleanup-noop` is a NOT_ADMITTED/zero-sequence RESULT_NONE operation
result, `first-cleanup-provider` is an ADMITTED/nonzero-sequence RESULT_NONE
operation result, and `first-cleanup-rejection` is a typed device-error event
that is explicitly ineligible for the completion-payload encoder.

The program's scope is deliberately narrower than the V2
carrier: it owns the selected request/completion payload layouts and their
operation-specific joins only. It does not construct or validate a complete
`ExactGpuSemanticCallV2` or `ExactGpuServiceEventV2`. The existing authenticated
V2 carrier performs structural call validation before payload decoding and the
remaining stateful route/object validation before semantic execution or
provider admission. It must validate the full completion envelope,
retained-submission provenance,
provider-admission/physical-sequence relationship, result shape, and payload
bounds before wrapper exposure. A generated native completion encoder therefore
produces only result-kind plus completion-payload bytes from an authenticated
retained call and service-owned operation result; constructing a valid full
event and provenance record remains a separately audited semantic-service
responsibility. This is codegen input, not a native implementation or an
installation claim. The authenticated C-vocabulary projection
owns the IBGQ/IBGR/IBGL magic, version, header/reference/tail shapes, catalog
tag rule, generic value tags, dictionary canonicalization, and bounds; the
manifest derives object-kind numbers from `ExactGpuObjectKindV2` in the pinned
C header. Dictionary keys are well-formed UTF-8 and sort by their unsigned
encoded bytes, with a shorter prefix first; the corpus carries a non-BMP vector
that distinguishes this rule from ECMAScript UTF-16 code-unit ordering.
Completion-payload decoders join duplicated provider and logical-device
provenance to the already carrier-validated service event before exposing a
wrapper. The corpus executes
WebIDL conversion and the real encoder/decoder. It records default,
high-performance, and compatibility/low-power request bytes plus the exact
operation-specific carrier fields plus global V2 carrier examples; object and
null vectors likewise record operation-result fields and admission examples.
RequestDevice vectors cover the converted request, a live admitted device, and
self-contained detached devices with both NOT_ADMITTED/zero and
ADMITTED/nonzero physical-sequence provenance.
The device-object creation vectors cover the bind-group-layout, buffer,
pipeline-layout, command-encoder, and shader-module target/reference joins, converted
descriptors, admitted carrier projections, and empty successful terminal
receipts. Bind-group-layout vectors additionally cover all four admitted
resource variants and fail-closed witnesses for descriptor bounds, binding
gaps, excluded variants/options, zero or multiple resource members, and UTF-8
label length.
Buffer vectors carry all 21 reviewed calls, exact 49,545,804-byte aggregate
evidence, per-call resource/mapped-extent/staging accounting, the 14-step
transport-plus-semantic order, and one first-failure mutation for every step.
Pipeline-layout vectors preserve the six-field bind-group-layout references
and additionally witness null, empty, three-group, logical max-bind-groups,
foreign, stale, exclusive, aggregate-binding-limit, immediate-alignment,
immediate-limit, and UTF-8 label semantic rejections as structurally valid
encoded requests.
The destroy vectors use distinct wrapper-object and logical-device identities,
one authoritative zero-target recording record, and both eligible semantic
operation-result terminals; the device-error terminal is pinned as an explicit
non-completion mapping.
These interoperability vectors are not a complete synthetic ABI record. The
bind-group-layout rejection vectors are semantic-boundary witnesses rather
than malformed carrier bytes; broader hostile/malformed coverage remains in
the executable generator/runtime tests. The vectors make the program joins,
defaulted fields, and reviewed closure language-neutral instead of relying on
a hand-authored hex example. Unknown
post-WebIDL `featureLevel` strings remain strings and resolve to `null` locally
without provider work, as required by the semantic program. The bundled graph
contains the generated injection codec for conformance and wrapper tests, but
no executable codec is bound to `EMBEDDED_EXECUTABLE_WEBGPU_CODECS` or otherwise
installable by production construction. No native request-payload decoder or
completion-payload encoder is implemented inside Ibex from these programs, and no
matching semantic provider method is installed, so native construction
installs no `navigator.gpu`, interface
globals, constants, or `createImageBitmap`. Tests may explicitly inject a
digest-matched codec
bundle into the private factory to verify routing, conversion timing, local
command recording, receiver projection, identity, revocation, and loss
settlement. Such injection and the generated corpus are conformance evidence
for the private boundary only, not native WebGPU support.

The pinned TypeGPU Genetic Racing and Jelly Slider source audit is projected
into the generated private plan as a second, explicitly **staged** inventory.
It records the immutable 25-operation triangle, explicit TypeGPU graduates,
and the audited workload closure with its additional operations, properties,
constants, and Exact host dependencies. A graduate is active only when it is
also present in the normalized wrapper authority; listing an additional member
alone creates no wrapper route, executable codec, prototype entry, interface
publication, or install path. Every remaining member stays
`staged-unroutable-no-prototype-member` until Exact supplies its ordered logical
semantic program, executable public/service codecs, matching native
decoder/provider method, generated CapSec edge and supported target cell, and
native evidence. The embedded codec slot remains undefined. This staging
projection prevents the next profile expansion from being guessed without
weakening the current fail-closed surface.
The sole metadata-only exception is `GPUBuffer.usage` and
`GPUBuffer.mapState`: the private factory may expose those exact local reads for
its wrapper-allocated buffer while they remain absent from the dispatch table,
public construction, embedded codec slot, and CapSec inventory.

The bridge accepts only an authenticated operation ID, canonical decimal
uint64 strings for device/queue/account identities, and an ArrayBuffer or view
bounded to 16 MiB. It publishes no `navigator.gpu`, `createImageBitmap`, global
bridge, or other app API. Presence of either the C ABI or this private bridge
is therefore neither WebGPU support nor conformance evidence.

The V2 construction-private object is separately classified and contains
`submit`, `cancel`, `retire`, and the one-shot `setEventSink`. Every method is a
closed CapSec `ipc:channel` edge and exists only inside the authenticated
capture. V2 `submit` carries one full typed receiver and an optional typed
target. A realm-level public wrapper may have no public handle, but its
authenticated runtime-routing record must project that fact to the service's
typed GPU singleton; callers may not fabricate a singleton or select a
service-receiver kind ad hoc. Ibex validates the resulting full object record
generically and does not special-case an operation ID.

Each `ExactGpuSemanticCallV1.completion_id` that reaches the provider is
nonzero and strictly increasing within its realm. Completion, cancellation,
provider admission rejection, and retirement never make an earlier value
reusable. Validation that rejects before the provider call does not allocate
an ID. This is a bounded anti-ABA identity allocator contract; it does not
stand in for the independent realm, device, queue, or physical-provider
sequencing domains owned by Exact.

V2 allocates independent, strictly increasing operation-instance and Promise
IDs. Its semantic call carries exact realm, account, ingress-device,
provider-generation, scope/adapter/device/queue ordinals, receiver/target, and
an Ibex-captured caller-attribution digest. JavaScript cannot supply or
override that digest. It is provenance rather than positive operation
authority: the semantic service still joins the authenticated operation
routing program, effects, stages, target, and handle lineage before provider
admission. A V2 cancellation repeats the complete immutable call key; retire
uses complete generation-fenced owned-object references. No identity is
recovered from ambient provider state.

Before either the pending maps or provider can observe an accepted call, Ibex
fully materializes the Promise success carrier (`completionId`, zero admission
status, and receipt). Promise resolvers and the mailbox submission record are
then installed before calling the provider, so a synchronous `on_event` cannot
race an absent receipt. If the provider admits the call, publishing the already
constructed carrier is the only remaining JSI step and is non-fallible; no
post-admission property allocation can turn accepted native work into a thrown
JavaScript call. Allocation failure before admission reaches neither the maps
nor the provider, while provider rejection first rolls back both records and
then constructs its failure carrier. A provider that synchronously calls
`on_event` and subsequently returns nonzero has contradicted its own admission
signal. Ibex detects the queued event, returns a separately prebuilt `-8`
protocol carrier without allocating, and leaves the receipt/submission for the
already-scheduled owner drain. That drain purges the event payload, reduces
authority once, cancels outstanding work, closes the realm, and rejects the
receipt once as `protocol-violation`; it does not take the ordinary
admission-rejection/discard path. The completion is recorded terminal, so late
duplicates are discarded without another reduction or settlement. `on_event` performs
prefix/realm/operation/completion validation,
copies bounded payload bytes into plain-native storage, and takes only a short
generation pin while enqueueing at most one owner-thread drain. If retaining the
mailbox, pinning the runtime generation, materializing the callback, or
publishing it to the callback queue fails, the callback never throws across the
C ABI or discards the accepted event: it poisons authority, raises a durable
allocation-free owner-drain flag, wakes the host, and makes that flag visible to
pending-work/backlog probes. Owner polling consumes the flag and settles every
receipt; teardown is the final on-owner settler if the generation is already
closing. The ordinary or fallback drain settles each receipt exactly once.
Duplicate/stale/wrong-realm events are
discarded; malformed future IDs, mismatched operations, invalid prefixes, or
budget overflow poison the realm and reject/cancel all pending receipts.
Pending receipts, queued events, queued bytes, recent terminal IDs, retire
batches, and per-event payloads all have fixed bounds.

V2 replaces the V1 generic completion shape with an exact typed union:
operation result, device error, provider loss, logical-device loss, account
close, and realm close. Operation terminals carry the full immutable
provenance key, provider-admission verdict, physical sequence, and device
transition. Result payload canonicality is selected by `result_kind`; device
errors cannot assign devices. `ASSIGNED` means only a live attached device on
an ADMITTED terminal. `ASSIGNED_DETACHED + OBJECT` is the self-contained
service-detached already-lost requestDevice terminal. Its full retained call
key authenticates the fresh result identity and preserves either NOT_ADMITTED
with physical sequence zero or ADMITTED with a nonzero physical sequence,
without diagnostic inference. It consumes no realm-lifetime lifecycle tombstone. The
owner delivers that terminal to the private wrapper sink before resolving its
receipt; the wrapper keeps the object out of its strong live-device registry
and settles the stable `device.lost` Promise, enqueueing that reaction before
the outer requestDevice reaction. Actual service-attached device loss remains
a `LOGICAL_DEVICE_LOST` lifecycle record with ordinary replay authority.

Lifecycle tombstones are realm-lifetime, bounded replay authority. Exact
replay is discarded even after its initiating operation ages beyond the
2,048-entry recent-operation ring; a same-key mutation is a protocol
violation. Distinct lifecycle overflow also quarantines rather than evicting
replay authority. Operation-terminal payload eviction releases backing
capacity as well as decrementing logical byte accounting, so rotating a large
payload cannot accumulate hidden capacity.

Submit, cancel, and retire reserve a service entry under the same mailbox mutex
used by realm-close callback admission, then release the mutex before invoking
provider code. A service call may cross after wall-clock close only if that
exact entry reserved first. Once REALM_CLOSED is accepted, new submit/cancel/
retire/setEventSink entries fail closed immediately. A synchronous malformed
callback during any of the three provider calls makes protocol reduction
dominate the provider return; pending receipts remain for that reduction rather
than settling as ordinary rejection or cancellation.

A terminal device-loss, realm-close, or protocol event may fan out to all 1,024
pending receipts. The owner drain materializes its at-most-16-MiB opaque
diagnostic payload exactly once and attaches that same read-only-by-contract JSI
value to every structured Error, so fanout is O(payload bytes + receipts), not
O(payload bytes × receipts). If that one optional diagnostic allocation fails,
each Error carries `payload: undefined`; rejection and cancellation still run
exactly once and the drain never retries the large allocation per receipt.

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
   the now-final app/agent context, captures and deletes the construction-only
   runtime-js bridge handoff, refreshes the compartment baseline once, and
   seals the Exact method and private bridge. Thus GPU-first and
   Exact-ingress-first installation cannot select different realm identities.

Every user-code-driving entry point refuses while the transaction is
`Configuring` or failed; poll preserves queued callbacks without executing
them.
Finalization failure rolls back the provisional Exact method, closes any opened
GPU realm, and is terminal for that runtime. Existing Exact-only consumers that
do not call `begin` retain the legacy single-setter auto-finalization behavior;
an armed snapshot that expects more than that Exact ingress cannot use the
legacy path.

GPU teardown is a nonblocking release path. Runtime destruction revokes the
runtime-js module slot and reserves `Closing` under the callback-admission
mutex. If teardown wins, it clears queued events, calls `cancel` once for each
pending completion outside internal locks, rejects each receipt on the owner
thread, calls `close_realm` once, changes the mailbox to `Detached`, and
proceeds without waiting. If a service REALM_CLOSED callback wins that mutex,
the accepted service terminal owns cleanup immediately—even before owner poll—
and teardown must not synthesize per-operation cancellations or echo
`close_realm`. Exact replay is discarded; a mutated replay quarantines without
issuing another close.
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
