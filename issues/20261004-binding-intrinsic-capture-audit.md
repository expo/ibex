# Audit binding intrinsic capture under the required hardened-runtime posture

**Status:** Open
**Systems:** Bindings, Runtime, Security
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-10-04
**Related:** LLP 0068 §3 Decision C

Decision C requires every embedder using the bindings door to evaluate
`ibex2::bindings::HARDEN_SOURCE` (or perform an equivalent freeze) before
application code. The `isTrusted`, brand-registry, and private-state guarantees
are specified only for that hardened runtime.

This issue collects intrinsic-capture findings that appear only when app code
can mutate an unhardened runtime. They should be evaluated against the required
bootstrap order and fixed when they cross the hardened boundary; they should
not be repaired one by one to create a second, unsupported unhardened security
posture.

**Done when:** the bindings' captured and live intrinsic uses have been audited
after the required hardening step, with every hardened-runtime escape fixed or
recorded as a separately scoped issue.
