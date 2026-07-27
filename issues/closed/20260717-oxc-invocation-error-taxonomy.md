# Three-class failure taxonomy (generation / admission / invocation)

**Status:** Closed
**Resolution:** Closed from the completion evidence recorded in f5688afb: generation, admission, and invocation failures now have the pinned timing and diagnostic split.
**Severity:** P2
**Systems:** Module Loader, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §2, LLP 0024, LLP 0027

Implement the normative failure classes: (1) source-generation
diagnostics that never block dead-branch sites — with the one stated
exception that source-authored reserved policy keys (LLP 0014 grant
vocabulary, incl. `authorities`) are unconditional generation errors;
(2) artifact-admission failures for malformed/reserved wire data,
before execution, per LLP 0027; (3) invocation failures for reached
guarded sites — computed `require`, unknown/non-literal option bags,
candidate-less computed sites — as rejected promises / thrown errors
preserving evaluation order, naming the module and **original-source**
site (fixes the transformed-byte-offset defect and the build-time
options rejection). Vocabularies derive from the canonical LLP 0014
schema, never hand-copied lists; every ingress tested.

**Done when:** fixture matrix pins the key/timing split (reserved key
in dead branch → generation error; unknown key in dead branch → loads;
same malformed bag in wire bytes → admission failure); computed-require
dead-branch load + invocation-error fixtures green; error-index entries
for the stable codes.

## Completion evidence — 2026-07-18

The Oxc producer now emits guarded dynamic-import and computed-`require`
factory calls with producer-owned original-source spans. Reserved policy keys
remain generation errors; non-reserved option defects and absent candidate
rows fail only if reached. Computed `require` no longer produces
`LegacyRequired`: dead branches load, authored arguments evaluate first, and
the native CommonJS callback throws `IBEX_LEGACY_COMPUTED_REQUIRE` naming the
authenticated requester and original byte range without resolving or probing.
Producer TypeScript-span and real-Hermes invocation tests pin the behavior.
