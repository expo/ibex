# Implement audit-admission (audit source execution via the producer)

**Status:** Open
**Severity:** P2
**Systems:** Security, Module Loader, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4b
**Depends-on:** oxc-audit-admission-spec

Implement the accepted audit-admission Spec so snapshotless
audit/diagnostic runtimes execute source through the graph producer
under the contract's fences (or, if the fallback was chosen, refuse
source entries and accept only prepared carriers). Includes the
denied/missing/cross-principal fixtures and a fixture proving
`ibex capsec audit` executes source entries via the Oxc path
post-migration.

**Done when:** compat evaluator no longer reachable from audit
runtimes; contract fixtures green; the repointed loader conformance
runner passes under audit.
