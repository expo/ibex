#ifndef EXACT_RUNTIME_PLAN_SEAM_BENCHMARK_H
#define EXACT_RUNTIME_PLAN_SEAM_BENCHMARK_H

// Private LLP 0517 section 10 measurement ABI. Product consumers include
// exact_runtime.h and never receive this surface. Definitions are emitted
// only by an Ibex build with the non-default `plan-seam-benchmark-abi` Cargo
// feature (`IBEX_PLAN_SEAM_BENCHMARK_ABI` in the C++ translation unit); only
// the benchmark driver and implementation include these declarations.
#include "exact_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { EX_HERMES_PLAN_SEAM_BENCHMARK_ABI_VERSION_V1 = 1 };

typedef struct ExHermesPlanSeamBenchmarkCreateTimingV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint64_t artifact_load_compile_instantiate_ns;
  uint64_t registry_admission_ns;
} ExHermesPlanSeamBenchmarkCreateTimingV1;

typedef struct ExHermesPlanSeamBenchmarkDirectBatchResultV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint64_t batch_latency_ns;
  uint64_t actual_calls;
} ExHermesPlanSeamBenchmarkDirectBatchResultV1;

typedef struct ExHermesPlanSeamBenchmarkAdapterCountersV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint64_t argument_bytes_copied;
  uint64_t result_bytes_copied;
  uint64_t adapter_allocations;
} ExHermesPlanSeamBenchmarkAdapterCountersV1;

/// Benchmark-build constructor. It performs the production create unchanged,
/// reports HBC buffer load/evaluation/instantiation and production registry
/// admission as its two cold phases, then requires the HBC's private benchmark
/// roots outside both clocks. The roots are inaccessible to authored plan
/// calls and are dropped with the ordinary restricted realm.
int32_t ex_hermes_plan_seam_create_benchmark_v1(
    const ExHermesPlanSeamOptionsV1 *options,
    ExactHermesPlanSeamRuntimeV1 **out_runtime,
    ExHermesPlanSeamCreateDiagnosticV1 *out_diagnostic,
    ExHermesPlanSeamBenchmarkCreateTimingV1 *out_timing);

/// Runs registry-owned benchmark cases through the admitted provider entries
/// without callSync, either boundary codec, or the plan engine. `case_ids`
/// names the exact fixture sequence. One monotonic duration is written for
/// every actual direct invocation. When `project_tick` is 1, the registry's
/// benchmark-only two-board/visible-row projection runs after the calls and
/// before the containing batch clock stops. Provider results and the optional
/// projection are asserted after timing stops. `project_tick` must be 0 or 1.
int32_t ex_hermes_plan_seam_benchmark_direct_batch_v1(
    ExactHermesPlanSeamRuntimeV1 *runtime,
    const uint32_t *case_ids,
    size_t case_count,
    uint8_t project_tick,
    uint64_t *out_call_latency_ns,
    ExHermesPlanSeamBenchmarkDirectBatchResultV1 *out_result);

/// Arms retained-only actual-site telemetry after benchmark warmup.
int32_t ex_hermes_plan_seam_benchmark_reset_adapter_counters_v1(
    ExactHermesPlanSeamRuntimeV1 *runtime);

/// Takes and disarms C++ plus generated TypeScript codec telemetry.
int32_t ex_hermes_plan_seam_benchmark_take_adapter_counters_v1(
    ExactHermesPlanSeamRuntimeV1 *runtime,
    ExHermesPlanSeamBenchmarkAdapterCountersV1 *out_counters);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // EXACT_RUNTIME_PLAN_SEAM_BENCHMARK_H
