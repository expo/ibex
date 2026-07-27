# Phase-0 format spike: envelope on a dynamic dev stub

**Status:** Closed
**Resolution:** Closed from the completion evidence recorded in f5688afb: malformed-envelope coverage and the signed, source-deleted relocation smoke test are green.
**Severity:** P2
**Systems:** Build, Module Loader
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §7 phase 0

De-risk the format before the static-Hermes long pole: a factory-table
payload embedded with a dynamically-linked dev stub, exercising
envelope parsing, bulk preflight (section types/offsets/lengths/
ordering/non-overlap/bijection), embedded admission, and disk-free
arming — no signing, no static linking, no HBC.

**Done when:** relocation smoke test passes (source tree deleted, spike
binary still runs); parser rejects a corpus of malformed envelopes.

## Progress — 2026-07-17

- `ibex-sfe-format` implements deterministic append/build, bounded footer
  admission, whole-envelope and per-section digests, canonical directory
  ordering/padding, limits, required singletons, entry designation, and
  carrier-pair bijection. Golden and mutation/property tests are green.
- `ibex-sfe-dev-pack` and `ibex-sfe-dev-stub` authenticate the embedded policy,
  graph, source carrier, and entry before an explicitly diagnostic Hermes
  runtime evaluates the dependency-free phase-0 module.
- `scripts/test-sfe-phase0.sh` builds from two distinct checkout paths,
  byte-compares the complete images (including carrier bytes), deletes both
  source files, and observes `{"answer":42}`. Linux executes the appended ELF
  directly. macOS injects the logical envelope into `__IBEX,__payload`, signs
  the resulting image ad hoc, validates the signature and signed layout, and
  executes that signed image directly; there is no development image-path
  override.

Completion reverified on 2026-07-17: the format mutation/property corpus is
green and the signed relocation smoke remains the owning end-to-end gate.
Release contracts, HBC carriers, catalogs, and publisher signing are
deliberately downstream concerns rather than hidden phase-0 requirements.
