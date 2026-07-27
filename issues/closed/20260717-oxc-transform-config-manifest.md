# Canonical transform-configuration manifest (one identity authority)

**Status:** Closed
**Resolution:** Closed from the completion evidence recorded in f5688afb: one strict transform authority now generates every fingerprint and cache/admission identity site.
**Severity:** P2
**Systems:** Module Loader, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §1, LLP 0027

Transform identity is duplicated string literals today (`transpile.rs`,
`producer_spike.rs` spike + production fingerprints), the ES target
(`es2022`) is hard-coded outside the option digest, and `hermes_target`
is populated from the loaded engine's bytecode-cache identity (mixing
evaluator/toolchain facts into producer identity). Introduce one
authored canonical transform-configuration manifest that generates the
Rust constants, cache tags, receipts, and CI pin assertions (drift
check), constructs the Oxc transformer, and populates the fingerprint:
Oxc locked-set digest (complete output-affecting resolved closure,
source/version/checksum), ECMAScript target, handwritten-pass version,
module-runner ABI component, detector + version, hermes-compat version,
full options. Redefine `hermes_target` as a producer-declared
syntax/ABI target; move evaluator/HBC-toolchain identity wholly to
carrier admission with same-target-reuse and incompatible-evaluator
fixtures. Rotation goldens for every output-changing phase.

**Done when:** single source of truth generates all identity sites;
goldens prove pre-rotation cache miss and carrier
revalidate-or-rebuild; fingerprint carries ES target and the redefined
hermes_target.

## Completion evidence (2026-07-17)

- `config/module-transform.json` is the strict authored authority. Its
  generator validates exact Cargo roots, computes a 135-package
  source/version/checksum Oxc closure, and emits the canonical receipt and
  Rust constants under the generated-artifact drift gate.
- The production and spike fingerprints, goal-specific option digests,
  transform cache tag, ES target, Hermes syntax/ABI target, CommonJS detector,
  handwritten-pass version, and module-runner ABI all consume that generated
  projection. The Oxc transformer fails closed on configuration values its
  implementation does not support.
- Producer APIs no longer accept loaded-evaluator identity. Source artifact
  cache keys omit it; Hermes binary/version checks remain on bytecode-carrier
  admission, where same-target reuse and incompatible-engine refusal are
  covered.
- Prepared-graph loading revalidates every artifact against the active
  transform configuration. Rust and JS rotation goldens cover the locked set
  and every output-changing phase, and the checked-in spike corpora were
  rotated to the generated fingerprint.
