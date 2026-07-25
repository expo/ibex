# LLP 0027: Native Runtime Extension SDK

**Type:** RFC
**Status:** Draft
**Systems:** Engine, Runtime, Host ABI, Capability Security, Build, Verification
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-25
**Revised:** 2026-07-25
**Related:** LLP 0000 (Ibex root), LLP 0002 (host embedding ABI), LLP 0003 (Hermes engine bridge), LLP 0006 (design principles), LLP 0012 (runtime identity), LLP 0013 / 0021 (capability security); Exact LLP 0394 (native runtime extensions)

## Summary

Ibex will expose a generic, versioned, source-linked C++ SDK for trusted native
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

Exact LLP 0394 defines the product-facing tier and assigns Ibex the generic
engine substrate. This companion RFC records the Ibex-side contract and the
required amendments to the current bootstrap and teardown sequence.

## Decision

### 1. Source-linked SDK and immutable descriptor table

Ibex publishes `include/ibex_runtime_extension.hpp`. The v1 public surface is a
C++17 source contract built with the same pinned Hermes/JSI headers, compiler
settings, C++ runtime, and Ibex revision as the runtime. It defines:

- `RuntimeExtensionDescriptorV1`, a data-only descriptor;
- `RuntimeExtensionRegistryV1`, an immutable span plus set identity;
- `RuntimeExtensionInstallContextV1`, an owner-thread install context;
- `RuntimeExtensionHandleV1`, an opaque instance returned by install;
- lifecycle callbacks for `install`, `quiesce`, and `close`;
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

### 2. Descriptor identity and validation

Every descriptor declares:

- a stable extension ID and extension version;
- the exact SDK version;
- supported realm kinds and install phase;
- a manifest digest;
- declared global paths and module specifiers;
- required SDK feature bits;
- a provider ABI ID and minimum version, or no provider;
- declared callback classes and effect resource IDs; and
- an install/lifecycle vtable.

The registry declares an extension-set digest and executable-selection
identity. Ibex rejects the complete registry before creating a user-observable
realm when:

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

`quiesce` revokes new work and cancels or detaches producer sources. `close`
runs on the runtime owner after admitted producers and owner callbacks have
drained, and before Hermes or any JSI-bearing capture is destroyed. Both
callbacks must be idempotent and non-throwing at their ABI boundary. Native
object finalizers may release local storage but are advisory: correctness and
provider cleanup may not depend on garbage collection.

Failed construction uses the same lifecycle driver as ordinary destruction.
Ibex never asks an extension to destroy JSI values from a producer thread.

### 5. Owner executor and completion tokens

Installers run on the runtime owner and receive direct `jsi::Runtime&` access.
This keeps branded objects, prototypes, local validation, and command encoding
local to the realm. The SDK also supplies guarded helpers for global
definition, module registration, authorization, and async delivery; raw JSI
access does not confer provider authority.

Background work receives an opaque, copyable completion token rather than a
runtime pointer or `jsi::Runtime&`. A token captures runtime identity,
extension ID, generation, callback class, and the constrained-principal
context captured at acquisition. Enqueuing:

- is non-blocking;
- fails after quiesce or identity mismatch;
- pins the admitted producer generation through callback disposition;
- runs its callback only on the runtime owner; and
- destroys every JSI-bearing capture on the runtime owner, including the
  rejected or teardown path.

There is no synchronous cross-thread dispatch, semaphore bounce,
`callModuleSync`, or generic `__hostCall` escape hatch.

### 6. Capability mediation

Ibex owns the security meaning; generated product data supplies vocabulary.
For each selected descriptor, the embedder provides an authenticated,
namespaced, data-only fragment containing:

- extension resource IDs;
- operation-to-resource mappings;
- target normalization rules;
- callback classes; and
- provider ABI requirements.

Ibex validates fragments against a fixed schema and combines them with its
generated CapSec tables. Extensions authorize through SDK operation IDs, not
free-form capability strings. A decision intersects the full live constrained
principal set with the principal context captured when the handle or completion
token was acquired. Provider access requires a runtime-scoped, extension-
scoped token minted only after authorization. Possessing a native handle alone
does not authorize its exercise.

The generic SDK does not know individual resources such as `gpu:*`. Adding an
extension-specific resource requires generated data and an extension/provider
implementation, not a handwritten Ibex enum or switch.

### 7. Memory

SDK v1 provides a copy-in/copy-out buffer path by default. It may advertise a
separate keyed external-buffer feature when the pinned engine and host support
safe detach/revocation. External buffers must carry runtime identity,
extension generation, provider allocation identity, and a revocation key.
Teardown or provider loss revokes the key before memory reclamation.

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

The implementation may refine names without changing these semantics:

```cpp
namespace ibex::runtime_extension::v1 {

struct RuntimeExtensionDescriptor {
  const char* id;
  const char* version;
  const char* manifest_digest;
  uint64_t realm_mask;
  uint64_t required_features;
  const char* provider_abi_id;
  uint32_t provider_abi_min_version;
  const char* const* global_paths;
  size_t global_path_count;
  const char* const* module_specifiers;
  size_t module_specifier_count;
  const LifecycleVTable* lifecycle;
};

struct RuntimeExtensionRegistry {
  uint32_t sdk_version;
  const char* extension_set_digest;
  const char* executable_selection_identity;
  const RuntimeExtensionDescriptor* descriptors;
  size_t descriptor_count;
};

} // namespace ibex::runtime_extension::v1
```

The C embedding header forward-declares the registry and adds explicit
`*_with_extensions` constructors. This does not make the C++ descriptor a
stable C ABI; it gives C, Swift, Kotlin/JNI, and Win32 hosts one opaque pointer
to pass through without becoming extension catalogs.

## Verification

Ibex ships a standalone conformance extension whose global, module, provider,
callback, and lifecycle behavior is intentionally generic. Tests must cover:

1. canonical install and reverse close order;
2. duplicate IDs, malformed digests, unsupported features, provider mismatch,
   and authenticated set-identity mismatch;
3. undeclared global mutation and overlapping nested global declarations;
4. refusal before user code or runtime registration;
5. partial-install cleanup;
6. callbacks delivered on the owner thread;
7. callbacks racing quiesce, destroy, and allocator-address reuse;
8. stale runtime nonce and stale extension generation rejection;
9. JSI-bearing callback destruction on the owner thread;
10. repeated create/destroy and failed-create stress;
11. copy-buffer behavior and optional external-buffer revocation;
12. full constrained-principal intersection and handle-acquisition attribution;
13. empty-registry compatibility for existing constructors; and
14. a standalone Ibex build with no Exact source or generated Exact table.

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

- Whether the public v1 helper facade should further narrow raw JSI access
  after two real consumers establish common operations.
- Which pinned Hermes configurations can support keyed external buffers
  without an engine patch.
- Whether worker realms should accept a separate descriptor subset in v2.
- What review and signing policy would be required before accepting
  third-party extension source.
