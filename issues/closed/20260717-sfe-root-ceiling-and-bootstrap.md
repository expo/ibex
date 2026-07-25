# Root-specific ceiling stratum + sealed bootstrap stage

**Status:** Resolved
**Severity:** P2
**Systems:** Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §4, LLP 0021, LLP 0014
**Depends-on:** llp0014-canonical-policy-v2

`AmbientRoot` authorizes otherwise-unauthorized root effects;
`processAuthorityCeiling` constrains it but is a whole-process bound
applied to every constrained principal — a root-only declaration there
would deny package floors. Introduce a **distinct root-specific
ceiling** (new earlier root-only stratum in capsec-semantics), keeping
`processAuthorityCeiling` as the true whole-process envelope; populate
it from the entry-manifest declaration flowing through the generator
(omission default: root ceiling = bootstrap floor only, fail-closed).
Bootstrap authority is a **sealed stage** with a named mechanism: an
unforgeable evaluator phase token orthogonal to frame principal (a
shared root HBC carrier cannot distinguish bootstrap from application
root by Hermes frame); the sealing transition destroys the token
before application evaluation.

**Done when:** root/package containment fixtures pass both ways;
over-ceiling denial; successful bootstrap + denial of the same effect
to application root after sealing + denial through retained
bootstrap-created callbacks.

## Progress — 2026-07-17

The distinct immutable `root-authority-ceiling` decision stratum is implemented
before principal denials and applies only to an authenticated root principal.
Canonical policy v2 rows flow into `rootAuthorityCeiling`; tests prove empty
bounded denial, matching root authority, and that package floors are not
narrowed. Publication identity and armed-snapshot validation include the new
ceiling.

The evaluator-owned bootstrap mechanism is now implemented end to end. Armed
snapshots carry a strict immutable `bootstrapAuthorityFloor`; its positive
stratum requires a shared one-way phase token and applies only to authenticated
root. Bootstrap-floor effects are excluded from later `AmbientRoot` fallback,
so sealing changes the same retained decision-context clone from an evidenced
`bootstrap-floor` allow to a production `missing-authority` denial. Hermes now
requires the active Host to consume that token exactly once after lockdown and
armed-posture verification and before application attribution/evaluation; a
missing, poisoned, or already-sealed transition refuses startup. The arming ABI
is `ibex-capsec-arming-2-root-ceiling-embedded-ranges-bootstrap-seal`, and the
host seal is inventoried as a non-capability authority-control-plane edge.

## Resolution — 2026-07-25

The concrete production bootstrap floor is intentionally empty. Current
bootstrap activity has no root-attributed capability effect: authenticated
runtime projections are consumed under the transparent runtime principal, and
application attribution begins only after the one-shot seal. A nonempty
selector without a corresponding observed root effect would create authority
rather than constrain it.

The generic positive-floor mechanism remains proven: an exact root selector
requires the live one-way phase token, retained decision-context clones lose
that authority after sealing, a second seal fails, and startup refuses if the
seal is missing or poisoned. That is the complete contract for the current
zero-effect bootstrap. If bootstrap later gains a root-attributed operation,
that change must populate its exact selector and land the retained
bootstrap-created callback denial fixture at the same time.
