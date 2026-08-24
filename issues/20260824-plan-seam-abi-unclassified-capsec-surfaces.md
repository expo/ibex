# Plan-seam ABI surfaces are unclassified in the capsec coverage model (check:drift red on main)

**Status:** Open
**Severity:** P2
**Systems:** Engine, CapSec, Devtools
**Author:** Claude (Fable 5)
**Date:** 2026-08-24
**Related:** LLP 0514 M7/M8 lanes (Exact), `src/engine/hermes_plan_seam.cc`, `include/exact_runtime_plan_seam_benchmark.h`, `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs`

## Problem

`bun run check:drift` fails on main at `check:root-global-dispositions`:

```
Error: unclassified observed surface host-abi:ex_hermes_plan_seam_apply_facet_host_inputs_v1
```

The LLP 0514 M7/M8 landing (`73efdcb94`, `e079cfae1`) added 13
`ex_hermes_plan_seam_*` public ABI functions (including the four
feature-gated `*_benchmark_*` entries) without adding classification rows
to the capsec coverage model, so `classifyObservedSurface` throws and the
root-global disposition artifacts cannot regenerate. The full set:

- ex_hermes_plan_seam_apply_facet_host_inputs_v1
- ex_hermes_plan_seam_benchmark_direct_batch_v1
- ex_hermes_plan_seam_benchmark_reset_adapter_counters_v1
- ex_hermes_plan_seam_benchmark_take_adapter_counters_v1
- ex_hermes_plan_seam_call_v1
- ex_hermes_plan_seam_create_benchmark_v1
- ex_hermes_plan_seam_create_v1
- ex_hermes_plan_seam_destroy_v1
- ex_hermes_plan_seam_executor_identity_v1
- ex_hermes_plan_seam_read_reactive_v1
- ex_hermes_plan_seam_registry_receipt_v1
- ex_hermes_plan_seam_release_result_v1
- ex_hermes_plan_seam_shutdown_v1

Classifying capsec surfaces carries security-review judgment (dispositions,
obligations, source refs), so this is deliberately NOT patched mechanically
by an unrelated lane. The 0514 plan-seam owner should add the reviewed
classification rows and regenerate (`bun run regenerate:vendored`).

Two neighboring main reds WERE repaired in the commit that files this
ticket: the Preflight ref-check failures from the same landing (cross-repo
`@ref Exact ...` targets; frozen `.patch` annotation), the missing
declared-ABI parity source for the private benchmark header, and the stale
`vendored-generated/source-fingerprint.generated.txt` stamp from
`b0b146890` (bundle regenerated there, stamp not; rebuild verified
zero-diff today). After that commit, `check:drift` is red ONLY on the
classification gap above.
