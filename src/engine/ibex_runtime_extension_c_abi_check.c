#include "ibex_runtime_extension.h"

#include <stddef.h>
#include <stdint.h>

_Static_assert(
    IBEX_RUNTIME_EXTENSION_SDK_VERSION_V1 == 1u,
    "runtime extension SDK version changed");
_Static_assert(
    offsetof(IbexRuntimeExtensionDescriptorV1, id) <
        offsetof(IbexRuntimeExtensionDescriptorV1, lifecycle),
    "descriptor layout is not C-compatible");
_Static_assert(
    offsetof(IbexRuntimeExtensionRegistryV1, descriptors) <
        offsetof(IbexRuntimeExtensionRegistryV1, provider_bindings),
    "registry layout is not C-compatible");
_Static_assert(
    sizeof(((IbexRuntimeExtensionDescriptorV1*)0)->required_features) ==
        sizeof(uint64_t),
    "feature mask width changed");
_Static_assert(
    offsetof(IbexRuntimeExtensionBootstrapV1, bytes) <
        offsetof(IbexRuntimeExtensionBootstrapV1, byte_length),
    "bootstrap layout is not C-compatible");
_Static_assert(
    offsetof(IbexRuntimeExtensionLifecycleVTableV1, install) <
        offsetof(IbexRuntimeExtensionLifecycleVTableV1, checkpoint),
    "checkpoint must follow global installation");
_Static_assert(
    offsetof(IbexRuntimeExtensionLifecycleVTableV1, checkpoint) <
        offsetof(IbexRuntimeExtensionLifecycleVTableV1, quiesce),
    "checkpoint must precede quiescence");
_Static_assert(
    sizeof(((IbexRuntimeExtensionLifecycleVTableV1*)0)->checkpoint) ==
        sizeof(IbexRuntimeExtensionCheckpointFnV1),
    "checkpoint callback type changed");

void ibex_runtime_extension_c_abi_check(void) {
  uint32_t (*sdk_version)(void) = ibex_runtime_extension_sdk_version_v1;
  uint64_t (*features)(void) =
      ibex_runtime_extension_supported_features_v1;
  struct ExactHermesRuntime* (*create_armed)(
      const IbexArmedRuntimeOptionsV2*) = ibex_runtime_create_armed_v2;
  struct ExactHermesRuntime* (*create_diagnostic)(
      const IbexDiagnosticRuntimeOptionsV2*) =
      ibex_runtime_create_diagnostic_v2;
  size_t (*count)(struct ExactHermesRuntime*) =
      ibex_runtime_extension_count_v1;
  int32_t (*inspect)(
      struct ExactHermesRuntime*,
      size_t,
      IbexRuntimeExtensionInspectionV1*) =
      ibex_runtime_extension_inspect_v1;
  char* (*report)(struct ExactHermesRuntime*) =
      ibex_runtime_extension_report_json_v1;
#ifdef IBEX_RUNTIME_EXTENSION_CONFORMANCE
  const IbexRuntimeExtensionRegistryV1* (*bound_fixture)(
      const char*,
      const char*,
      const char*) =
      ibex_runtime_extension_conformance_bound_registry_v1;
  const IbexRuntimeExtensionRegistryV1* (*fixture_variant)(uint32_t) =
      ibex_runtime_extension_conformance_registry_variant_v1;
  struct ExactHermesRuntime* (*create_authenticated_fixture)(
      const IbexArmedRuntimeOptionsV2*) =
      ibex_runtime_extension_conformance_create_authenticated_fixture_v1;
  int32_t (*eval_fixture_with_principals)(
      struct ExactHermesRuntime*,
      const uint64_t*,
      size_t,
      const uint8_t*,
      size_t,
      const char*,
      char**) =
      ibex_runtime_extension_conformance_eval_with_principals_v1;
  uint64_t (*armed_prerequisites)(void) =
      ibex_runtime_extension_conformance_armed_prerequisites_v1;
#endif

  (void)sdk_version;
  (void)features;
  (void)create_armed;
  (void)create_diagnostic;
  (void)count;
  (void)inspect;
  (void)report;
#ifdef IBEX_RUNTIME_EXTENSION_CONFORMANCE
  (void)bound_fixture;
  (void)fixture_variant;
  (void)create_authenticated_fixture;
  (void)eval_fixture_with_principals;
  (void)armed_prerequisites;
#endif
}
