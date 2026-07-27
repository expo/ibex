#ifndef IBEX_HERMES_RUNTIME_EXTENSION_INTERNAL_H
#define IBEX_HERMES_RUNTIME_EXTENSION_INTERNAL_H

#include "../../include/ibex_runtime_extension.h"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

struct ExactHermesRuntime;

namespace ibex::runtime_extension::internal {

struct RuntimeState;

std::shared_ptr<RuntimeState>
prepare(uint64_t host_context_id, bool authenticate_registry,
        const char *report_mode, const IbexRuntimeExtensionRegistryV1 *registry,
        std::string *error);

void bind(const std::shared_ptr<RuntimeState> &state,
          ExactHermesRuntime *runtime);

void install(ExactHermesRuntime *runtime);
void activate(ExactHermesRuntime *runtime);
bool checkpoint(ExactHermesRuntime *runtime) noexcept;
bool hasPendingOwnerRetirements(const ExactHermesRuntime *runtime) noexcept;
void quiesce(ExactHermesRuntime *runtime) noexcept;
void close(ExactHermesRuntime *runtime) noexcept;

std::unordered_set<std::string>
declaredRootKeys(const ExactHermesRuntime *runtime);
std::unordered_set<std::string>
declaredNativeKeyPairs(const ExactHermesRuntime *runtime);
std::vector<std::string> declaredGlobalPaths(const ExactHermesRuntime *runtime);
bool declaredLogicalPath(const ExactHermesRuntime *runtime,
                         const std::string &path);

#if defined(IBEX_RUNTIME_EXTENSION_CONFORMANCE)
void armAcceptedPostReturnHoldForTest(bool armed) noexcept;
bool acceptedPostReturnHeldForTest() noexcept;
size_t callbackSlotCountForTest(ExactHermesRuntime *runtime) noexcept;
size_t operationLeaseSlotCountForTest(ExactHermesRuntime *runtime) noexcept;
#endif

} // namespace ibex::runtime_extension::internal

#endif
