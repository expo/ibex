# Native computed dynamic import execution (graph + ABI plumbing)

**Status:** Complete
**Severity:** P2
**Systems:** Module Loader, Engine, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §2, LLP 0026 §6
**Depends-on:** oxc-candidate-table-contract

Runtime side: the graph currently reduces computed sites to a
per-module boolean (`graph.rs`) and the factory emits
`dynamicImport(expr)` without the site. Plumb site identity across the
factory and native ABIs (this rotates the ABI fingerprint component —
manifest-driven, stale-tested), look up the invoked site's candidate
row, admit only exact authenticated spellings, and reject
out-of-candidate spellings at invocation without resolution or
filesystem probing. Candidate tables compose with prepared graphs and
HMR generations (all candidates prepared; tables keyed on generation).

**Done when:** LLP 0026 §6 semantics hold end-to-end on both advertised
tuples, source and prepared; per-site non-escalation proven at runtime;
`LegacyRequired` no longer raised for labeled computed imports.

## Completion evidence — 2026-07-18

The factory ABI carries computed site identity plus original-source span and
an invocation guard. Separate ESM/CommonJS native link entry points bind exact
`(site, spelling)` rows, and missing/cross-site spellings reject fresh promises
without a resolver or filesystem probe. Source, prepared-cache, embedded-graph,
SFE, and compiled-stub paths validate requester/target integrity and graph
generation before linking. The real-Hermes test proves disjoint candidates,
guarded option rejection, and requester/original-span diagnostics; the CapSec
public conformance graph observes both new ABI entry points in source and
prepared execution.
