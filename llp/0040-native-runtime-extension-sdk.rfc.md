# LLP 0040: Native Runtime Extension SDK

**Type:** RFC
**Status:** Review
**Systems:** Engine, Runtime, Host ABI, Capability Security, Build, Verification
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-25
**Revised:** 2026-07-25; 2026-07-26 (registered conformance and shared-toolchain enforcement); 2026-07-26 (Windows profile qualification boundary and fail-closed lifecycle capability probe)
**Related:** LLP 0000 (Ibex root), LLP 0002 (host embedding ABI), LLP 0003 (Hermes engine bridge), LLP 0006 (design principles), LLP 0012 (runtime identity), LLP 0013 / 0021 (capability security), LLP 0025 (terminal session ownership and lifecycle); Exact LLP 0405 (native runtime extensions)

## Summary

Ibex exposes a generic, versioned, source-linked C++ SDK for trusted native
runtime extensions. An embedder supplies one immutable descriptor table when it
constructs a runtime. Ibex validates the table before user code can run,
installs descriptors in stable ID order during a fixed trusted bootstrap
window, schedules extension completions on the runtime owner, and drives
quiesce and close in reverse install order.

The SDK is a pinned-toolchain source contract, not a stable binary plugin ABI.
Version 1 accepts statically linked descriptors only. It performs no dynamic
library discovery or loading and contains no Exact-, WebGPU-, or
provider-specific vocabulary.

## Context

Ibex intentionally exposes narrow embedding surfaces. Ordinary host
capabilities use typed data boundaries, while the armed runtime rejects the
historical generic host-call bridge. That is the correct default, but a small
class of APIs must participate directly in the JavaScript realm:

- install a standard global before application code;
- create native-backed JSI object graphs with local synchronous semantics;
- settle promises and publish events from background producers;
- retain and revoke handles by runtime identity and generation; and
- release JSI and provider state deterministically during failed construction,
  hot reload, and teardown.

Putting each such binding in `hermes_runtime.cc` would make Ibex core an
application-extension catalog. Routing it through synchronous module calls
would violate the runtime owner-thread model. A dynamic plugin ABI would make
toolchain and engine compatibility less honest, not more.

Exact LLP 0405 defines the product-facing tier and assigns Ibex the generic
engine substrate. This companion RFC records the Ibex-side contract and the
required amendments to the current bootstrap and teardown sequence.

### Amendments to the earlier corpus

This RFC supersedes only the WebGPU-specific Ibex mechanisms previously
described by LLPs 0002, 0003, and 0005. Their generic host, engine, and build
contracts remain authoritative. In particular:

- LLP 0002's Exact GPU artifact builder, provider registration, private GPU
  bridge, and deferred `ex_hermes_activate_webgpu_runtime_v1` transaction are
  retired. The generic v2 constructors, descriptor registry, authority
  finalizer, and runtime-extension artifact builder defined here replace them.
- LLP 0003's `hermes_runtime_gpu*.cc` mailbox and embedded WebGPU activation
  bundle are retired. `hermes_runtime_extension.cc` owns the generic lifecycle,
  operation membrane, completion tokens, and selected bootstrap evaluation.
- LLP 0005's `webgpu-binding` build feature and Ibex-owned deferred WebGPU
  source/HBC artifact are retired. Ibex vendors only its core runtime bundle;
  authenticated extension bootstrap bytes are package-owned inputs carried by
  the generated registry.
- Exact owns every WebGPU name, wrapper, operation profile, provider service,
  and conformance artifact under Exact LLP 0115/0402. Production Ibex source
  and generated CapSec data contain no WebGPU-specific vocabulary.

Historical prose below the explicitly marked superseded headings in those
documents records the pre-extraction implementation only. It is neither a
current API promise nor an alternate construction path.

## Decision

### 1. Source-linked SDK and immutable descriptor table

Ibex publishes the C descriptor ABI in
`include/ibex_runtime_extension.h` and the source-linked authoring facade in
`include/ibex/runtime_extension.hpp`. The v1 public surface is a C++17 source
contract built with the same pinned Hermes/JSI headers, compiler settings, C++
runtime, and Ibex revision as the runtime. It defines:

- `RuntimeExtensionDescriptorV1`, a data-only descriptor;
- `RuntimeExtensionRegistryV1`, an immutable span plus set identity;
- `RuntimeExtensionInstallContextV1`, an owner-thread install context;
- `RuntimeExtensionHandleV1`, an opaque instance returned by install;
- lifecycle callbacks for `install`, owner-thread `checkpoint`, `quiesce`,
  and `close`;
- owner-executor and completion-token helpers; and
- extension-scoped authorization helpers.

The descriptor table is supplied explicitly to new constructor variants. The
existing constructors remain source- and ABI-compatible and behave as though
they received the canonical empty registry.

The registry and every string or array reachable from it must remain valid
through construction. Ibex validates and copies all runtime-needed metadata
before invoking extension code. The table is never populated by process-wide
registration side effects, static constructors, environment variables, or
directory scanning.

Each install context exposes its copied provider binding through an immutable
per-instance data-only view that remains stable through lifecycle close. A
provider lookup in another context cannot overwrite an earlier view.

### 2. Descriptor identity and validation

Every descriptor declares:

- a stable extension ID and extension version;
- the exact SDK version;
- supported realm kinds and install phase;
- a manifest digest;
- declared global paths and their object/function kinds, plus module
  specifiers;
- required SDK feature bits;
- a provider ABI ID and minimum version, or no provider;
- a closed operation table and callbacks tied to those operations, including
  producer affinity, fixed runtime-owner delivery, and bounds; and
- an install/lifecycle vtable.

The registry declares an extension-set digest, authority-capsule digest, and
executable-selection identity. Ibex rejects the complete registry before
creating a user-observable realm when:

- the SDK major version is unsupported;
- IDs are empty, duplicated, or not in canonical bytewise order after sorting;
- a descriptor declares an unsupported realm or install phase;
- required features are unavailable;
- strings, lists, vtables, or digests are malformed;
- global paths overlap ambiguously, including a path nested below another
  descriptor's declared path;
- a required provider token is absent or has the wrong ABI/version;
- the table does not match the authenticated selection identity supplied by an
  armed host context; or
- an extension dependency is declared in v1.

Installation order is canonical bytewise extension-ID order. Teardown order is
the exact reverse of the subset that reached `Active`.

### Authenticated construction projection

Code generation emits a non-armable authority template. The template binds the
declared extension set, operation profile, SDK and provider requirements, and
build-declared artifact facts, but it cannot authenticate its own executable
bytes. Ibex recomputes the template's declaration-selection identity instead
of trusting an opaque digest. The launcher separately observes the final
loaded executable path, file-object facts, and the complete generated
table/lifecycle/provider/bootstrap anchor inventory.

Exact-side package host-service factory tables and non-extension support
archives are build-composition facts, not `RuntimeExtensionDescriptorV1`
fields. They therefore add no executable-anchor role in v1. The embedder
closes them through generated per-target link inputs and build receipts, and
their direct generated references and bytes are covered by the pinned
complete-executable hash. A future host-service-factory anchor requires an
authenticated descriptor/schema revision before a generator may emit it.

Before Hermes construction, Ibex opens that observed executable without
following links, verifies that it is the current executable, rechecks the file
object, length, and change metadata around two identical complete-file hashes,
and requires the anchor-role set implied by the authenticated descriptors.
Only then does it finalize the authority capsule and executable-selection
identity. The non-armable template, launcher observation, finalized capsule,
and loaded-executable file identity are distinct strict documents; none may
substitute for another.

The armed Host projection accepts only the finalized capsule and mapped
executable pair whose digests match the authenticated runtime-extension
registry projection. The registry's capsule digest and every selected
descriptor's `authority_capsule_digest` must be valid and byte-for-byte equal;
the registry projection authenticates the digest once at the top level and
again on every descriptor row, and its strict parser rejects any disagreement
before Hermes allocation. A descriptor-authored filename, symbol, or digest
label is evidence to validate against the observed executable, never authority
by itself.

The `mapped-executable` wire name is retained for schema stability, but v1
does not hash relocated in-memory executable pages. It pins and hashes the
current executable file and proves that every generated callable/data anchor
belongs to one loaded image. Static-archive membership and source provenance
remain trusted-build facts corroborated by link-map/symbol receipts. Native
source, code generation, linking, and platform signing are inside the trusted
build boundary; an internally consistent malicious clean rebuild is not a
threat this runtime can or claims to detect.

### 3. Fixed bootstrap window

The current engine bootstrap is amended into explicit stages:

1. create Hermes and the runtime handle;
2. install Ibex's native and JavaScript bootstrap surface;
3. install optional Ibex-owned polyfills;
4. validate and install native runtime extensions;
5. capture/finalize the package-compartment global baseline;
6. verify the armed posture;
7. register the runtime as user-executable; and
8. evaluate user code.

Extension installation therefore runs after Ibex's trusted primitives exist
but before package baseline capture, lockdown finalization, and any user code.
An extension may define only its declared global paths and module specifiers.
Ibex snapshots the relevant property-descriptor graph before and after each
installer and rejects undeclared additions, removals, or replacements.
The module loader's construction registrar and its private registry inspector
are captured into owner-only native JSI state, and the registrar's sole global
reference is deleted before the first extension bootstrap payload executes.
`defineModule` invokes only that captured registrar. After each descriptor,
Ibex compares the loader's actual module-name set with the prior set plus that
descriptor's exact declarations; the installer-local publication ledger is an
additional check, not the registry authority.

No late install API exists in v1. A failed install transitions the descriptor
to `Quiescing`, invokes cleanup for the partially constructed instance, and
closes prior successful instances in reverse order. The runtime is never
registered and user code is never evaluated.

### 4. Runtime identity and lifecycle

Ibex owns the state machine:

`Declared -> Installing -> Active -> Quiescing -> Closed`

Each runtime instance carries the existing `(runtime pointer, creation nonce)`
identity plus a monotonically allocated extension generation. Extension
handles, completion tokens, and provider leases are valid only when all three
components match and the instance is `Active`.

`checkpoint` is an owner-thread, non-blocking host-task boundary invoked while
the instance is `Active`; it lets an extension advance already-ready local
service work without inventing a private poll loop or synchronous wait.
`quiesce` revokes new work and cancels or detaches producer sources. `close`
runs on the runtime owner after admitted producers and owner callbacks have
drained, and before Hermes or any JSI-bearing capture is destroyed. All
lifecycle callbacks must be idempotent where repeat invocation is possible
and non-throwing at their ABI boundary. Native object finalizers may release
local storage but are advisory: correctness and provider cleanup may not
depend on garbage collection.

Failed construction uses the same lifecycle driver as ordinary destruction.
Ibex never asks an extension to destroy JSI values from a producer thread.
After reverse lifecycle rollback, it releases the prepared extension state,
owner-only loader functions, callback slots, and Host leases while Hermes and
the authenticated Host context are still live, before unbinding the VFS or
tearing down any other native registry.

### 5. Owner executor and completion tokens

Installers run on the runtime owner and receive direct `jsi::Runtime&` access.
This keeps branded objects, prototypes, local validation, and command encoding
local to the realm. The SDK also supplies guarded helpers for global
definition, module registration, authorization, and async delivery; raw JSI
access does not confer provider authority.

Every authorized operation lease has two ownership halves. Public,
callback-retained, and provider-retained copies share one producer-safe lease
implementation containing only copied identity facts, atomics, and a runtime
wake handle. A separate owner-only slot retains the Host context/lease IDs and
the same atomic retirement state, but never the public implementation.
Destroying the last public copy on any thread publishes retirement and a wake;
it never enters `HOST_CONTEXTS`, reads a runtime or extension `Instance`,
touches JSI, or performs Host revocation. This preserves WebGPU-style
owner-side session retention: the Host lease remains current until the last
provider/callback holder releases it.

The next owner authorization opportunistically reaps prior requested slots so
a long synchronous host task cannot exhaust the bounded table; otherwise the
next owner checkpoint consumes the durable pending bit, revokes requested Host
leases, and erases their slots. If the wake hook throws, the bit remains
visible to pending-task queries and is cleared by the next owner checkpoint
after revocation, rather than spinning or losing retirement. Teardown does not
depend on another poll: after provider close and callback-slot destruction it
synchronously revokes every remaining owner slot and clears both retirement
bits. A public copy that outlives runtime destruction retains only already
revoked producer-safe state; its eventual last-copy destruction remains an
atomics-and-wake no-op with respect to freed runtime state.

Background work receives an opaque, copyable completion token rather than a
runtime pointer or `jsi::Runtime&`. A token may be minted only while its
descriptor-linked operation wrapper is active. It captures runtime identity,
extension ID, generation, callback class, and the complete constrained-
principal context captured at acquisition. Enqueuing:

- is non-blocking and fail-fast under registry, callback-queue, Host-context,
  or typed-generation contention;
- fails after quiesce or identity mismatch;
- admits the runtime pointer only while holding a successful try-lock on the
  pointer-plus-nonce registry and the callback queue;
- returns bounded capacity refusal rather than waiting when either lock or an
  authority-generation read is contended;
- runs its callback only on the runtime owner; and
- may run an accepted callback before the producer's `post()` call returns, so
  producers publish every completion-visible state before calling `post()`; and
- destroys every JSI-bearing capture on the runtime owner, including the
  rejected or teardown path.

The callback slot retires when the last public token copy is destroyed.
Already-admitted posts keep that slot alive until their disposition runs.
Public tokens retain only copied producer-safe identity/authority facts and
atomics; the owner-side callback slot retains the revocable Host lease and all
JSI values. Last-copy destruction on an arbitrary producer publishes a durable
retirement bit and wake without consulting the runtime registry, Host,
callback queue, native-worker state, or callback-slot mutex. An accepted queue
entry is itself the generation handoff: teardown first changes the registry
state to `Closing`, preventing new admission, then invokes or discards every
accepted entry on the owner before closing extension instances. The terminal
disposition retires its slot there. No completion entry owns a native-worker
pin, so teardown cannot wait on an unpolled completion.

Both producer admission and owner delivery revalidate the exact Host lease,
runtime nonce, extension generation, namespace, and operation. Producer reads
use try-locks and report contention as capacity refusal. An already accepted
owner delivery waits only for the Host's context-local lease lookup and
immutable policy/generation snapshot to become stable; transient contention is
not revocation, while a stable stale result rejects delivery. The wait is
runtime-owner-only. No provider callback, external callback, worker dispatch,
runtime drive, or effectful Host API runs while acquiring or holding that
guard, and no producer or other cross-thread SDK path uses it.

There is no synchronous cross-thread dispatch, semaphore bounce,
`callModuleSync`, or generic `__hostCall` escape hatch.

Carried Hermes patch 0013 is the extension-neutral continuation primitive for
that full context. Promise construction, resolution/thenable assimilation,
adoption aliases, settlement, handler registration, and each queued reaction
carry bounded, immutable constrained-principal sets in addition to the scalar
scheduler identity used by structured failure receipts. Native owner callbacks
publish the acquisition set while settling or invoking JavaScript. Hermes
retains the tokens in private Promise state, unions prior, settlement,
registration, and enqueue-time contexts monotonically, and propagates the
result into downstream and aggregate settlement, including handlers attached
after a Promise has already settled. The authenticated runtime-extension
profile requires Hermes' engine microtask queue and refuses a non-empty
registry before installation when that configuration surface is absent. The
`setImmediate` fallback remains an ordinary Promise compatibility path, but is
not runtime-extension confinement evidence. Missing or malformed context
collapses to the no-user principal. Scalar `Promise.resolve` calls produce
acquisition-branded Promises rather than shared bootstrap singletons, because
a global neutral singleton would erase the caller context. Promise
settlement/adoption state and handler queues also live in private lexical
WeakMap records rather than writable underscore properties; legacy underscore
fields and rejection hooks are non-semantic compatibility mirrors. Private
brands cannot be minted through `Promise.call`, frozen mirrors cannot interrupt
finalization, and mutable `_B` / `_C` / `_D` properties cannot replace the
lexical hooks or no-op resolver.

Observable `then` and `constructor` getters, thenable calls, subclass
construction, and the dynamic `then` calls required by aggregate methods run
under the monotonic source/current union. An unbranded callable thenable has no
authenticated origin and therefore executes and settles fail-closed under the
no-user principal; a plain object with no callable `then` remains ordinary data
and retains its real resolver context. Async/await uses private
`PerformPromiseThen` after captured intrinsic `PromiseResolve`, while
async-generator iteration Promises merge the opaque principal token captured
when the package-defined generator wrapper is created. Public `catch` and
`finally` preserve dynamic behavior but retain the source token on any
privately branded Promise result. Thus neither copying Promise-shaped fields,
installing an own `then` override, returning a pre-existing clean Promise from
a subclass/custom method, nor deferring a subclass executor can bypass the
carrier. The frame collector appends every distinct member at the next effect
boundary. Sets are per Promise/job, never per poll batch, so a compromised
completion cannot contaminate an unrelated root completion and a root
completion cannot erase a compromised deputy. A frame-attributing engine that
lacks the patch export refuses a non-empty runtime-extension registry before
installation.

The embedder carrier and the Promise/job carrier are separate runtime slots.
Entering or leaving a typed-principal scope synchronizes only the embedder
slot; Hermes snapshots that slot into jobs without letting a later scope erase
Promise-owned history. The generic runtime callback queue stores the complete
immutable acquisition set alongside the structured-failure identity and
restores it around owner delivery. Extension completions and ordinary native
async completions, including filesystem delivery on POSIX and Windows, thereby
enter Promise settlement under the same carrier. Nested runtime drives restore
the prior engine and carrier on unwind.

An active authenticated carrier is mandatory authority for every capability
class, independently of LLP 0013's opt-in synchronous deputy-class policy.
Ibex sends the complete collected set through distinct constrained-stack Host
ABI gates; each member must pass the capability decision and every host
boundary fence, including no-follow-final filesystem normalization. An empty
active collection, an explicit no-user member, malformed input, unsupported
engine state, or symbol-probe ambiguity denies. The ordinary synchronous stack
gates retain their existing deputy semantics.

Build selection probes exact defined symbols rather than substring matches or
undefined references. Structured async provenance requires both carrier
exports in addition to the existing scheduler/job exports on macOS, Linux, and
Windows. The symbol parser is shared by `build.rs` and its platform-neutral
regressions; tool failure and prefix/suffix collisions fail closed.

The feature-only authenticated conformance constructor binds the same
capsule-authenticated VFS generation as production before trusted bootstrap.
Its diagnostic Hermes posture does not reopen ambient native storage: trusted
bootstrap carries a closed-storage sentinel into the shared runtime, so an
empty authenticated environment cannot fall through to host `/tmp`. A genuine
Android storage projection, when present, remains the authoritative root.

### 6. Capability mediation

Ibex owns the security meaning; generated product data supplies vocabulary.
For each selected descriptor, the embedder provides an authenticated,
namespaced, data-only fragment containing:

- exact extension ID / authority-class operation rows over Ibex's one generic
  `runtime-extension:invoke` resource kind;
- callback classes; and
- provider ABI requirements.

Fragments contribute no executable matchers, normalizers, or new resource
semantics. Ibex validates them against
`ibex/runtime-extension-authority-fragment/1` and combines them with its
generated CapSec tables. Extensions authorize through descriptor-closed SDK
operation IDs, not caller-supplied capability strings. A decision intersects
the full live constrained-principal set with the principal context captured
when the handle or completion token was acquired. Provider access requires a
runtime-scoped, extension-scoped token minted only after authorization.
Possessing a native handle alone does not authorize its exercise.

The production embedder-artifact builder derives the owning root principal's
static floor and immutable ceiling from the validated capsule: one exact
`runtime-extension:invoke` selector for every unique
`(extension ID, authority class)` pair. The action definition is Ibex's fixed
semantic-core overlay and exists only when an authenticated extension capsule
is armed; capsule data cannot introduce vocabulary or normalization behavior.

The generic SDK does not know individual resources such as `gpu:*`. Adding an
extension-specific authority class requires generated data and an
extension/provider implementation, not a handwritten Ibex enum or switch.
Finer resource attenuation requires a separately reviewed Ibex semantic-core
revision.

Raw JSI is available for pure branded values, prototypes, and local object
graphs only. Every effectful HostFunction, HostObject trap, accessor,
constructor hook, finalizer side effect, and external-buffer hook must pass
through a generated SDK operation wrapper. Protected-source and source-
inventory checks enforce that trusted-source rule; global-delta verification
is not represented as a native-code sandbox.

The authenticated closed projection is
`ibex/runtime-extension-authority-capsule/1`. Its canonical
`sha256-<base64url-no-padding>` digest binds every manifest and descriptor,
globals/modules/operations/callbacks, CapSec fragment, provider ABI identity,
trusted JS/HBC bootstrap bytes and evaluation mode, selected target and
feature set, the build-declared linked archive/object identities, and the
pinned loaded-executable file identity/hash plus the complete
descriptor-implied registry/lifecycle/provider/bootstrap anchor inventory.
Extra roles are rejected just like missing roles. The armed snapshot carries
the capsule digest and projection. The new Host claim matches it exactly before
Hermes allocation; legacy Host claims accept only the canonical empty
projection.

### 7. Memory

SDK v1 provides a copy-in/copy-out buffer path by default. It also defines one
optional, WebGPU-neutral keyed-external-buffer feature. When the pinned engine
advertises it, aliases carry allocation identity, runtime pointer/nonce,
extension generation, and a non-reusable revocation key. One key may own
multiple overlapping aliases; revocation detaches all of them before provider
memory can be reclaimed. Teardown or provider loss revokes every remaining
key. Revocation is transactional across engine detach exceptions: successful
aliases are removed, but a throwing alias and its key remain strongly retained
in a `revoking` state that rejects key reuse. A later explicit revoke or the
teardown pass retries the retained alias. Teardown makes one additional
bounded detach pass; if detachment still throws, Ibex suppresses provider
`close` and deliberately retains/leaks that provider instance rather than
reclaiming storage beneath a possibly attached JavaScript view.

Hermes patch 0012 is generalized as
`0012-keyed-external-arraybuffer-alias.patch`; neither its interface,
detach-key field, tests, nor patch filename contains an API/extension name.
Targets whose engine does not implement the negotiated interface reject a
requiring descriptor before installation. There is no WebGPU-specific
copy-and-shadow exception.

Mapped or externally owned memory is never implied merely by receiving a raw
pointer. Extensions must declare the feature, and unsupported selected builds
fail before user code.

### 8. Introspection

Ibex exposes data-only runtime inspection for:

- SDK version and supported feature bits;
- selected extension IDs, versions, and manifest digests;
- extension-set and executable-selection identities;
- current lifecycle state and generation;
- provider ABI identity;
- admitted/rejected callback counters; and
- teardown/refusal diagnostics.

Inspection must not expose a mutable registry or raw provider/runtime pointer.

## Public API shape

`include/ibex_runtime_extension.h` is the exact public authority. It publishes
size/versioned C structs rather than an opaque forward declaration:

- `IbexRuntimeExtensionDescriptorV1` carries the manifest and authority-capsule
  identities, realm/install/features, globals, modules, bootstraps, operations,
  callbacks, provider requirements, and lifecycle table;
- `IbexRuntimeExtensionRegistryV1` carries the authenticated whole-set
  identities, descriptor span, and provider-binding span;
- `IbexArmedRuntimeOptionsV2` and `IbexDiagnosticRuntimeOptionsV2` carry the
  immutable registry into `ibex_runtime_create_armed_v2` and
  `ibex_runtime_create_diagnostic_v2`; and
- the legacy constructors remain canonical empty-registry wrappers.

`include/ibex/runtime_extension.hpp` is the C++17 source-authoring facade over
that C surface. The explicit structs let C, Swift, Kotlin/JNI, and Win32 hosts
pass generated immutable data without becoming extension catalogs. They are
versioned embedding ABI for the pinned Ibex revision, not a promise that an
arbitrary precompiled third-party extension remains binary-compatible across
Ibex/Hermes toolchains.

## Verification

Ibex ships a standalone conformance extension whose global, module, provider,
callback, and lifecycle behavior is intentionally generic. Exact’s registered
`runtime-extension-ibex-conformance` gate runs the complete feature-gated
engine module with default/insecure features disabled, requires a nonzero
fixture floor, and separately requires the target-local production
package-policy refusal. It selects the one compiler pinned by both Exact and
Ibex; current-source Ibex workflows consume `scripts/install-rust-toolchain.sh`
rather than carrying another literal toolchain pin.

The legacy Windows header/import-library SDK selected by Exact's explicit
compile-only profile is not a runtime-extension or native-conformance input.
It may type-check the Windows target, but it cannot execute or link a native
host and cannot produce runtime, CapSec, extension, or platform-qualification
evidence. A qualifying Windows native build must instead use the authenticated
Ibex `windows-source-patched` Hermes profile and its provenance receipt.
`build.rs` probes the selected `hermes.h` for
`HermesRuntime::asyncTriggerTimeout`; when that capability is absent, an armed
structured-lifecycle request throws before recording the request and the
native structured-cancellation ABI returns `UNAVAILABLE`. There is no
best-effort interrupt fallback. These guards preserve, rather than revise,
LLP 0025's normative lifecycle and cancellation contract.

Tests must cover:

1. canonical install and reverse close order;
2. duplicate IDs, malformed digests, unsupported features, provider mismatch,
   authenticated set-identity mismatch, and a valid descriptor capsule digest
   that differs from its authenticated registry capsule digest;
3. undeclared root or nested global mutation, prototype mutation, replacement
   of the reflection intrinsics used by verification, positive declared nested
   installation, and overlapping nested global declarations;
4. refusal before user code or runtime registration;
5. partial-install cleanup;
6. callbacks delivered on the owner thread;
7. callbacks racing quiesce, destroy, and allocator-address reuse;
8. stale runtime nonce and stale extension generation rejection;
9. JSI-bearing callback destruction on the owner thread;
10. repeated abandonment of copied tokens beyond the callback-slot budget, and
    destruction with an accepted but unpolled completion;
11. repeated create/destroy and failed-create stress;
12. copy-buffer behavior, optional external-buffer revocation, and injected
    detach failure retaining the alias/key for a successful retry;
13. full constrained-principal intersection and handle-acquisition
    attribution, including a real native completion, handlers attached after
    native and downstream settlement, adoption of an already-settled root-clean
    Promise, `Promise.all` over an already-settled constrained Promise, a
    forged Promise-shaped adopter, a branded Promise with an authority-
    laundering own `then` exercised through both `Promise.all` and `await`, a
    generic thenable and `then` getter borrowing root functions, mutable
    Promise compatibility hooks, a constructor that returns a pre-existing
    clean Promise, a multi-hop Promise chain, a plain-object non-thenable
    control, and concurrent root/compromised jobs proving per-job isolation;
14. empty-registry compatibility for existing constructors;
15. a standalone Ibex build with no Exact source or generated Exact table;
16. deterministic producer post and last-copy destruction while the runtime
    registry, callback queue, native-worker, callback-slot, Host-context, and
    typed-generation locks are held;
17. injected allocation failure before callback-disposition allocation and
    callback-queue closure allocation, with exact capacity refusal and
    recovery;
18. bootstrap attempts to call the deleted module registrar, plus actual
    loader-registry delta equality; and
19. production artifact construction deriving exact capsule-authenticated root
    floor/ceiling selectors and authorizing every selected operation through
    an armed Host;
20. an already accepted owner callback surviving deterministic transient
    Host-context contention without weakening the producer's fail-fast path;
    and
21. authenticated desktop native storage remaining closed with an empty
    environment, while a genuine Android projection remains authoritative;
22. deterministic owner delivery completing before producer `post()` returns,
    including immediate retirement of the terminal callback slot;
23. last operation-lease destruction completing on a producer while
    `HOST_CONTEXTS` is write-locked, followed by owner-checkpoint revocation;
24. teardown revoking the owner-held lease slot without a later poll, followed
    by last public-copy destruction on a producer after runtime destruction;
25. the generic native callback queue restoring the complete typed-principal
    carrier before Promise settlement, with the legacy generic capability gate
    denying a root callback whose acquisition set contains an ungranted
    package; and
26. exact defined-symbol probing for the Hermes constrained-principal setter
    and active-query exports on Mach-O, ELF, and PE/COFF listings, including
    undefined-only, prefix/suffix-collision, and tool-failure refusals.

Before any extension bootstrap or installer runs, Ibex retains the pristine
`Object.getOwnPropertyNames`, `Object.getOwnPropertySymbols`,
`Object.getOwnPropertyDescriptor`, and `Object.getPrototypeOf` functions. For
each installer it snapshots a bounded, cycle-safe identity graph starting at
the global object and following only own data-descriptor object/function
values and prototypes. Verification uses only the retained functions and
requires every pre-existing object's complete string-and-symbol descriptor
set, descriptor attributes and value/getter/setter identities, and prototype
identity to remain unchanged. The only permitted new descriptors are the exact
declared property-path edges; a newly published declared leaf may root its own
new subgraph. Accessors are recorded but never invoked. Reflection over a
trusted bootstrap-created lazy Proxy may materialize its backing graph, so
Ibex requires the pre-install graph to reach a bounded fixed point before
recording the protected baseline. Object, property, key-byte, and
stabilization-pass bounds are hard construction failures rather than partial
coverage.

Source-contract tests additionally forbid product vocabulary in the generic
SDK and forbid synchronous cross-thread wait primitives in extension paths.

## Rollout

1. Land this RFC and the generic descriptor/lifecycle substrate with the
   conformance extension.
2. Add authenticated security-fragment projection and provider-token plumbing.
3. Add owner-executor, identity-race, and memory fixtures.
4. Migrate WebGPU without retaining WebGPU-specific code or patch names in
   Ibex core.
5. Exercise a second independently motivated consumer before presenting the
   SDK as a general third-party surface.

## Consequences

- Ibex gains one generic trusted extension seam without becoming a product
  plugin catalog.
- Runtime startup and teardown have explicit extension stages.
- Embedders can select linked capabilities without handwritten engine-shell
  edits per extension.
- Raw JSI remains source-linked and toolchain-pinned; binary compatibility is
  not overstated.
- Security decisions remain in Ibex even when the resource vocabulary is
  generated by an embedder.
- Every selected extension increases the trusted native computing base and
  must be visible in build and runtime introspection.

## Non-goals

- dynamic native-code loading;
- a stable third-party binary ABI;
- untrusted or app-downloaded extensions;
- runtime installation after user code;
- replacement of ordinary modules or native views;
- a generic synchronous host-call bridge; or
- automatic extension dependency resolution.

## Open questions

- Whether worker realms should accept a separate descriptor subset in v2.
- What review and signing policy would be required before accepting
  third-party extension source.
