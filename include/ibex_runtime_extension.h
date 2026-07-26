/*
 * ibex_runtime_extension.h
 *
 * Source-linked native runtime extension ABI.
 *
 * Version 1 is a construction-time, statically linked contract. It is not a
 * dynamic-plugin ABI and does not promise compatibility across Ibex/Hermes
 * revisions or C++ toolchains. Descriptor data is plain C so generated tables
 * can be passed through Swift, JNI, Win32, or Rust hosts without teaching
 * those hosts about individual extensions.
 *
 * @ref LLP 0040
 */

#ifndef IBEX_RUNTIME_EXTENSION_H
#define IBEX_RUNTIME_EXTENSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ExactHermesRuntime;

#define IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1 1u
#define IBEX_RUNTIME_CREATE_OPTIONS_VERSION_V2 2u

typedef enum IbexRuntimeExtensionStatusV1 {
  IBEX_RUNTIME_EXTENSION_OK = 0,
  IBEX_RUNTIME_EXTENSION_INVALID_ARGUMENT = 1,
  IBEX_RUNTIME_EXTENSION_UNSUPPORTED_SDK = 2,
  IBEX_RUNTIME_EXTENSION_UNSUPPORTED_FEATURE = 3,
  IBEX_RUNTIME_EXTENSION_CONFLICT = 4,
  IBEX_RUNTIME_EXTENSION_AUTHENTICATION_FAILED = 5,
  IBEX_RUNTIME_EXTENSION_INSTALL_FAILED = 6,
  IBEX_RUNTIME_EXTENSION_GLOBAL_DELTA_MISMATCH = 7,
  IBEX_RUNTIME_EXTENSION_PROVIDER_MISMATCH = 8,
  IBEX_RUNTIME_EXTENSION_WRONG_THREAD = 9,
  IBEX_RUNTIME_EXTENSION_INVALID_STATE = 10,
  IBEX_RUNTIME_EXTENSION_STALE_GENERATION = 11,
  IBEX_RUNTIME_EXTENSION_QUIESCING = 12,
  IBEX_RUNTIME_EXTENSION_QUEUE_FULL = 13
} IbexRuntimeExtensionStatusV1;

typedef enum IbexRuntimeExtensionRealmV1 {
  IBEX_RUNTIME_EXTENSION_REALM_MAIN = 1u << 0,
  IBEX_RUNTIME_EXTENSION_REALM_WORKER = 1u << 1
} IbexRuntimeExtensionRealmV1;

typedef enum IbexRuntimeExtensionFeatureV1 {
  IBEX_RUNTIME_EXTENSION_FEATURE_OWNER_EXECUTOR = UINT64_C(1) << 0,
  IBEX_RUNTIME_EXTENSION_FEATURE_OPERATION_MEMBRANE = UINT64_C(1) << 1,
  IBEX_RUNTIME_EXTENSION_FEATURE_COPIED_BUFFERS = UINT64_C(1) << 2,
  IBEX_RUNTIME_EXTENSION_FEATURE_KEYED_EXTERNAL_BUFFERS = UINT64_C(1) << 3,
  IBEX_RUNTIME_EXTENSION_FEATURE_NATIVE_MODULES = UINT64_C(1) << 4,
  IBEX_RUNTIME_EXTENSION_FEATURE_INTROSPECTION = UINT64_C(1) << 5
} IbexRuntimeExtensionFeatureV1;

typedef enum IbexRuntimeExtensionInstallPhaseV1 {
  IBEX_RUNTIME_EXTENSION_INSTALL_BEFORE_USER_CODE = 1
} IbexRuntimeExtensionInstallPhaseV1;

typedef enum IbexRuntimeExtensionLifecycleStateV1 {
  IBEX_RUNTIME_EXTENSION_DECLARED = 0,
  IBEX_RUNTIME_EXTENSION_INSTALLING = 1,
  IBEX_RUNTIME_EXTENSION_ACTIVE = 2,
  IBEX_RUNTIME_EXTENSION_QUIESCING_STATE = 3,
  IBEX_RUNTIME_EXTENSION_CLOSED = 4
} IbexRuntimeExtensionLifecycleStateV1;

typedef enum IbexRuntimeExtensionCallbackAffinityV1 {
  IBEX_RUNTIME_EXTENSION_CALLBACK_RUNTIME_OWNER = 1,
  IBEX_RUNTIME_EXTENSION_CALLBACK_BACKGROUND_PRODUCER = 2,
  IBEX_RUNTIME_EXTENSION_CALLBACK_PROVIDER_THREAD = 3
} IbexRuntimeExtensionCallbackAffinityV1;

typedef enum IbexRuntimeExtensionCallbackDeliveryV1 {
  IBEX_RUNTIME_EXTENSION_CALLBACK_DELIVERY_RUNTIME_OWNER = 1
} IbexRuntimeExtensionCallbackDeliveryV1;

typedef enum IbexRuntimeExtensionGlobalKindV1 {
  IBEX_RUNTIME_EXTENSION_GLOBAL_OBJECT = 1,
  IBEX_RUNTIME_EXTENSION_GLOBAL_FUNCTION = 2
} IbexRuntimeExtensionGlobalKindV1;

typedef enum IbexRuntimeExtensionBootstrapFormatV1 {
  IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SOURCE = 1,
  IBEX_RUNTIME_EXTENSION_BOOTSTRAP_HERMES_BYTECODE = 2
} IbexRuntimeExtensionBootstrapFormatV1;

typedef enum IbexRuntimeExtensionBootstrapEvaluationModeV1 {
  IBEX_RUNTIME_EXTENSION_BOOTSTRAP_SCRIPT_GLOBAL = 1
} IbexRuntimeExtensionBootstrapEvaluationModeV1;

/*
 * Authenticated extension-local JavaScript evaluated in the fixed trusted
 * construction window. The registry and authority capsule bind the metadata
 * and digest; the linked executable identity binds the byte pointer itself.
 * Ibex copies every row and byte before creating Hermes.
 */
typedef struct IbexRuntimeExtensionBootstrapV1 {
  uint32_t struct_size;
  const char* id;
  uint32_t format;
  uint32_t evaluation_mode;
  const char* content_digest;
  const char* source_url;
  const uint8_t* bytes;
  size_t byte_length;
} IbexRuntimeExtensionBootstrapV1;

typedef struct IbexRuntimeExtensionGlobalV1 {
  uint32_t struct_size;
  const char* path;
  uint32_t kind;
} IbexRuntimeExtensionGlobalV1;

typedef struct IbexRuntimeExtensionOperationV1 {
  uint32_t struct_size;
  const char* id;
  const char* authority_class;
  /* Ibex-owned coverage semantics and decision-stage vocabulary. */
  const char* semantics;
  const char* stage;
  const char* atomicity_group;
  /* Sorted, duplicate-free Ibex resource-kind inventory. */
  const char* const* resource_kinds;
  size_t resource_kind_count;
  /* Complete JS-triggerable native entry path, e.g. AcmeDevice.submit(). */
  const char* js_entry_path;
  uint32_t flags;
} IbexRuntimeExtensionOperationV1;

typedef struct IbexRuntimeExtensionCallbackV1 {
  uint32_t struct_size;
  const char* id;
  const char* operation_id;
  uint32_t producer_affinity;
  uint32_t delivery;
  uint32_t max_pending;
} IbexRuntimeExtensionCallbackV1;

/*
 * Provider state is supplied per runtime construction. The provider table is
 * extension-defined and source-linked; Ibex treats it as opaque and exposes it
 * only to the matching installer after exact ABI/version/digest validation.
 */
typedef struct IbexRuntimeExtensionProviderBindingV1 {
  uint32_t struct_size;
  const char* extension_id;
  const char* abi_id;
  uint32_t abi_version;
  uint32_t provider_struct_size;
  const char* identity_digest;
  const void* vtable;
  void* context;
} IbexRuntimeExtensionProviderBindingV1;

typedef int32_t (*IbexRuntimeExtensionInstallFnV1)(
    void* install_context,
    void** out_instance);
typedef int32_t (*IbexRuntimeExtensionCheckpointFnV1)(
    void* install_context,
    void* instance);
typedef void (*IbexRuntimeExtensionQuiesceFnV1)(
    void* install_context,
    void* instance);
typedef void (*IbexRuntimeExtensionCloseFnV1)(
    void* install_context,
    void* instance);

typedef struct IbexRuntimeExtensionLifecycleVTableV1 {
  uint32_t struct_size;
  IbexRuntimeExtensionInstallFnV1 install;
  IbexRuntimeExtensionCheckpointFnV1 checkpoint;
  IbexRuntimeExtensionQuiesceFnV1 quiesce;
  IbexRuntimeExtensionCloseFnV1 close;
} IbexRuntimeExtensionLifecycleVTableV1;

typedef struct IbexRuntimeExtensionDescriptorV1 {
  uint32_t struct_size;
  uint32_t sdk_version;
  const char* id;
  const char* version;
  const char* manifest_digest;
  /* Must exactly equal the enclosing registry's authenticated digest. */
  const char* authority_capsule_digest;
  uint32_t realm_mask;
  uint32_t install_phase;
  uint64_t required_features;
  const char* provider_abi_id;
  uint32_t provider_abi_min_version;
  uint32_t provider_struct_size;
  const IbexRuntimeExtensionGlobalV1* globals;
  size_t global_count;
  const char* const* module_specifiers;
  size_t module_specifier_count;
  const IbexRuntimeExtensionBootstrapV1* bootstraps;
  size_t bootstrap_count;
  const IbexRuntimeExtensionOperationV1* operations;
  size_t operation_count;
  const IbexRuntimeExtensionCallbackV1* callbacks;
  size_t callback_count;
  const IbexRuntimeExtensionLifecycleVTableV1* lifecycle;
} IbexRuntimeExtensionDescriptorV1;

typedef struct IbexRuntimeExtensionRegistryV1 {
  uint32_t struct_size;
  uint32_t sdk_version;
  const char* extension_set_digest;
  /* Every descriptor repeats this exact authenticated digest. */
  const char* authority_capsule_digest;
  const char* executable_selection_identity;
  const IbexRuntimeExtensionDescriptorV1* descriptors;
  size_t descriptor_count;
  const IbexRuntimeExtensionProviderBindingV1* provider_bindings;
  size_t provider_binding_count;
} IbexRuntimeExtensionRegistryV1;

typedef struct IbexArmedRuntimeOptionsV2 {
  uint32_t struct_size;
  uint32_t abi_version;
  const char* armed_snapshot_digest;
  const IbexRuntimeExtensionRegistryV1* extension_registry;
} IbexArmedRuntimeOptionsV2;

typedef struct IbexDiagnosticRuntimeOptionsV2 {
  uint32_t struct_size;
  uint32_t abi_version;
  const IbexRuntimeExtensionRegistryV1* extension_registry;
} IbexDiagnosticRuntimeOptionsV2;

typedef struct IbexRuntimeExtensionInspectionV1 {
  uint32_t struct_size;
  const char* id;
  const char* version;
  const char* manifest_digest;
  uint64_t generation;
  uint32_t lifecycle_state;
  uint64_t callbacks_admitted;
  uint64_t callbacks_rejected;
} IbexRuntimeExtensionInspectionV1;

uint32_t ibex_runtime_extension_sdk_version_v1(void);
uint64_t ibex_runtime_extension_supported_features_v1(void);

/*
 * The armed constructor verifies the registry's authority-capsule digest
 * against the authenticated Host context before allocating Hermes. Existing
 * ex_hermes_create_armed/ex_hermes_create_diagnostic constructors are canonical
 * empty-registry wrappers.
 */
struct ExactHermesRuntime* ibex_runtime_create_armed_v2(
    const IbexArmedRuntimeOptionsV2* options);
struct ExactHermesRuntime* ibex_runtime_create_diagnostic_v2(
    const IbexDiagnosticRuntimeOptionsV2* options);

size_t ibex_runtime_extension_count_v1(
    struct ExactHermesRuntime* runtime);
int32_t ibex_runtime_extension_inspect_v1(
    struct ExactHermesRuntime* runtime,
    size_t index,
    IbexRuntimeExtensionInspectionV1* out_inspection);

/*
 * Returns malloc-owned UTF-8 JSON, released with ex_hermes_free_string().
 * The report is data-only and never exposes provider, registry, or runtime
 * pointers.
 */
char* ibex_runtime_extension_report_json_v1(
    struct ExactHermesRuntime* runtime);

#ifdef IBEX_RUNTIME_EXTENSION_CONFORMANCE
/* Test-only fixture registry; absent from ordinary artifacts. */
const IbexRuntimeExtensionRegistryV1*
ibex_runtime_extension_conformance_registry_v1(void);
const IbexRuntimeExtensionRegistryV1*
ibex_runtime_extension_conformance_failing_registry_v1(void);
/*
 * Bind the fixture's structurally fixed descriptor table to the authenticated
 * digests computed by the Rust conformance Host. Returned storage is
 * thread-local and remains valid until the next call on the same thread.
 */
const IbexRuntimeExtensionRegistryV1*
ibex_runtime_extension_conformance_bound_registry_v1(
    const char* extension_set_digest,
    const char* authority_capsule_digest,
    const char* executable_selection_identity);
/*
 * Same authenticated fixture, except the first descriptor carries a valid
 * digest that differs from the enclosing registry capsule digest.
 */
const IbexRuntimeExtensionRegistryV1*
ibex_runtime_extension_conformance_bound_registry_descriptor_digest_mismatch_v1(
    const char* extension_set_digest,
    const char* authority_capsule_digest,
    const char* executable_selection_identity);
/*
 * Feature-only authenticated substrate fixture. It consumes the same armed
 * capsule/registry projection, VFS generation, closed native-storage posture,
 * and real Host lease path as production, but intentionally runs a diagnostic
 * Hermes bootstrap so its report mode cannot be mistaken for proof of full
 * native armed startup.
 */
struct ExactHermesRuntime*
ibex_runtime_extension_conformance_create_authenticated_fixture_v1(
    const IbexArmedRuntimeOptionsV2* options);
/*
 * Evaluate fixture source under one explicit authenticated principal stack.
 * This is a feature-only adversarial test control for continuation/deputy
 * conformance and is absent from ordinary artifacts. Principal IDs must be
 * sorted, unique, and registered in the fixture Host.
 */
int32_t ibex_runtime_extension_conformance_eval_with_principals_v1(
    struct ExactHermesRuntime* runtime,
    const uint64_t* principal_ids,
    size_t principal_count,
    const uint8_t* source,
    size_t source_length,
    const char* source_url,
    char** out_value);
/* Bit 0 means the production armed Promise-rejection checkpoint hook exists. */
uint64_t ibex_runtime_extension_conformance_armed_prerequisites_v1(void);
/*
 * Malformed/failing registry variants:
 * 1 duplicate id; 2 overlapping global; 3 SDK ABI mismatch;
 * 4 undeclared global; 5 undeclared effect; 6 partial install failure;
 * 7 malformed digest; 8 unsupported feature; 9 provider mismatch;
 * 10 successful ordered pair; 11 nested mutation; 12 prototype mutation;
 * 13 reflection replacement; 14 declared nested global;
 * 15 undeclared bootstrap module injection.
 */
const IbexRuntimeExtensionRegistryV1*
ibex_runtime_extension_conformance_registry_variant_v1(uint32_t variant);
uint64_t ibex_runtime_extension_conformance_counter_v1(uint32_t counter);
void ibex_runtime_extension_conformance_reset_v1(void);
void ibex_runtime_extension_conformance_set_off_owner_retire_delay_v1(
    uint32_t delay_ms);
void
ibex_runtime_extension_conformance_hold_next_operation_lease_retirement_v1(
    void);
int32_t
ibex_runtime_extension_conformance_operation_lease_retirement_is_held_v1(
    void);
void
ibex_runtime_extension_conformance_release_operation_lease_retirement_v1(
    void);
size_t ibex_runtime_extension_conformance_operation_lease_slot_count_v1(
    struct ExactHermesRuntime* runtime);
void ibex_test_runtime_extension_arm_keyed_external_detach_fault_v1(void);
typedef void (*IbexRuntimeExtensionConformanceLockedBodyV1)(void* context);
int32_t ibex_test_runtime_extension_with_registry_lock_v1(
    IbexRuntimeExtensionConformanceLockedBodyV1 body,
    void* context);
int32_t ibex_test_runtime_extension_with_callback_queue_lock_v1(
    struct ExactHermesRuntime* runtime,
    IbexRuntimeExtensionConformanceLockedBodyV1 body,
    void* context);
int32_t ibex_test_runtime_extension_with_native_worker_lock_v1(
    struct ExactHermesRuntime* runtime,
    IbexRuntimeExtensionConformanceLockedBodyV1 body,
    void* context);
int32_t ibex_test_runtime_extension_with_callback_slot_lock_v1(
    struct ExactHermesRuntime* runtime,
    IbexRuntimeExtensionConformanceLockedBodyV1 body,
    void* context);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* IBEX_RUNTIME_EXTENSION_H */
