# ibex/single-file-executable/1 envelope format

**Status:** Closed
**Resolution:** Closed from the completion evidence recorded in f5688afb: strict envelope schemas, canonical admission, malformed-input coverage, and ELF/Mach-O placement contracts landed.
**Severity:** P2
**Systems:** Build, Module Loader
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2b/§7 phase 2
**Depends-on:** sfe-format-spike

Canonical, versioned container: Merkle-style section directory; every
section typed, length-bound, digest-bound; provenance manifest pinning
StubContractV1 digest + CompilePlanV1 + catalog evidence; per-module
HBC carrier sections in v1 (grouped carriers deferred until a composed
carrier/HBC source map exists), manifest + payload as separate typed
sections with a required bijection, page-aligned with alignment
recorded; entry designation as a table with one required row (keeps
multi-entry format-possible). Boot bulk-preflights everything before
evaluating anything.

**Done when:** schema + canonical encoding + golden vectors land;
parser fuzz corpus green; bijection/overlap/duplication/limit
violations all refuse with stable errors.

## Progress — 2026-07-17

The product-neutral `ibex-sfe-format` crate and JSON schemas now cover the v1
directory, entry table, and development `StubContractV1`. A checked-in golden
pins file/envelope/section digests and offsets; property mutation plus explicit
footer, range, overlap, ordering, duplication, alignment, padding, empty-limit,
and incomplete-pair cases refuse under stable `SFE001`–`SFE008` classes. The
issue remains in progress for release HBC provenance/contract/catalog binding
and the full release signing vector. Mach-O embedding itself is now
implemented: the same logical envelope lives in the unique
`__IBEX,__payload` section, footer discovery follows the load-command range
rather than EOF, and admission accepts only a structurally sealed post-signing
layout. ELF retains the EOF envelope. Strict `ibex/compile-plan/1` and
`ibex/package-provenance/1` contracts now make final assembly input
path-independent and cross-bind the plan digest, release catalog/target, and
stub core. Release HBC envelope production and the full release signing vector
remain tracked by their owning downstream issues.

The envelope-format scope is complete as of 2026-07-17. Its strict schemas,
canonical encoder/admitter, checked golden, stable `SFE001`–`SFE008`
rejections, bounded arbitrary-byte mutation test, carrier-pair bijection, and
ELF/Mach-O placement contracts are green. HBC production and publisher-signing
vectors do not require another envelope wire-format change.
