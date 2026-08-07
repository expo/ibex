# Windows `rust-default-full` CapSec CI leg is broadly red, pre-existing

**Status:** Open
**Severity:** P2
**Systems:** CI, Windows, Module Loader, VFS, Host
**Author:** Claude (Sonnet 5), directed by Charlie Cheever
**Date:** 2026-08-05

## The problem

The Windows x64 leg of the "CapSec full matrix and evidence" workflow's
`verify:capsec-conformance` step fails at `rust-default-full` with ~24
consistently-failing tests, spanning several unrelated modules:

- `engine::portable_identity::tests::aslr_local_mapping_changes_do_not_change_portable_identity`
- `engine::portable_identity::tests::mapped_identity_type_and_domain_digest_match_the_frozen_vector`
  (`"mapped engine runtime path is not one absolute canonical path"`)
- `host::portable_target_admission::tests::*` (12 tests, all panicking at
  `src/host/portable_target_admission.rs:1756:27`, same root message)
- `host::tests::alias_volume_topology_refuses_a_nested_cross_volume_mount`
- `host::tests::authenticated_bound_package_uses_nested_manifest_for_exported_js_kind`
- `host::tests::metadata_only_package_resolution_refuses_manifest_mutation_after_arming`
- `module_loader::tests::authenticated_resolver_follows_contained_windows_reparse`
- `module_loader::tests::authenticated_resolver_refuses_replaced_boundary_before_lookup`
- `module_loader::tests::subprocess_transpile_consumes_staged_exact_source_across_aba_mutation`
  (TypeScript transpile subprocess exits `0xc0000409`)
- `module_loader::tests::subprocess_transpile_rejects_live_helper_mutation` (same)
- `restricted_worker::tests::native_broker_round_trip_uses_only_the_opaque_worker`
- `vfs::tests::contained_symlinks_reauthorize_targets_and_canonicalize_source_identity`
- `vfs::tests::runtime_vfs_chdir_is_atomic_detects_stale_base_and_recovers`
  (`"The process cannot access the file because it is being used by another process."`)
- `vfs::tests::symlink_escape_depth_and_link_object_races_fail_closed`
- `vfs::tests::symlink_substitution_is_safe_at_every_authorization_boundary`
- `vfs::tests::windows_reparse_escape_is_refused_before_target_lookup`

## Confirmed pre-existing, not a regression

The identical failure list (same test names, same panic sites) appears on
run 31020930069 (`main` at `8028f9d1`, **before** the 2026-08-05 CapSec/Oxc/
network-hardening merge landed) and reproduces deterministically on rerun
(run 31042260146, twice). This is not flaky — it is a stable, systemic
Windows-only breakage that predates this session's work.

Several failure messages point at a Windows path-canonicalization problem
(`"mapped engine runtime path is not one absolute canonical path"`,
symlink/reparse-point handling in `vfs`, subprocess transpile crashing with
`STATUS_STACK_BUFFER_OVERRUN`-class exit code `0xc0000409`, and a file
still being held open by another process during `chdir`), suggesting one or
a small number of root causes (a Windows runner image change, a path-mapping
regression, or a genuine cross-platform bug in the affected modules) rather
than 24 independent defects.

## What to do

1. Bisect when this started (last known-green Windows `rust-default-full`
   run) to narrow the introducing change.
2. Investigate whether the path-canonicalization failures share a root
   cause with the `vfs`/`module_loader` symlink and subprocess failures.
3. Re-run once fixed to confirm the full list clears together, not
   test-by-test.

**Done when:** Windows `rust-default-full` passes cleanly in the CapSec full
matrix workflow, or each surviving failure has its own tracked ticket with a
distinct root cause.
