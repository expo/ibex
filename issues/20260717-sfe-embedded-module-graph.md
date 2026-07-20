# ibex/embedded-module-graph/1 (path-independent inner contract)

**Status:** Complete
**Severity:** P2
**Systems:** Module Loader
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2b, LLP 0027
**Depends-on:** sfe-envelope-format

The on-disk `prepared-module-graph/1` index is path-bearing (absolute
`record.path`; file-only `SourceId`s in its schema while publication
emits builtin records — file that latent LLP 0027 schema defect as its
own fix with a conformance test, since the serde loader never enforces
the JSON schema) and reload re-authenticates sources from disk. Define
the embedded contract: compact content-addressed table (sorted
`SourceId → semantic digest, carrier binding, typed edges, virtual
label`), every `SourceId` variant, `/app`-anchored virtual labels and
`import.meta.url`/`__filename`/`__dirname`/source-map spellings,
candidate-table references when present, and embedded admission rules
(admission from envelope bytes only; no original-file reads).

**Done when:** schema + golden vectors; real graphs incl. builtins
validate; relocation tests (delete source tree; two checkout paths →
identical unsigned bytes incl. carrier bytes; runs) pass on the spike.

## Progress — 2026-07-17

`ibex/embedded-module-graph/1` now has strict Rust types, a JSON schema, and a
checked-in all-`SourceId` golden (root file, package file, builtin, synthetic).
Admission requires canonical ordering, typed conditioned edges, derived `/app`
observable labels, exact carrier/candidate bijections, and recomputation of the
authenticated snapshot identity. The initial single-module phase-0 relocation
harness was path-independent and disk-free after packing; the multi-module and
signed-macOS completion of that evidence is recorded below.

## Completion evidence — 2026-07-18

The phase-0 packer now walks the complete literal ESM/CommonJS dependency
closure with typed resolution kinds, conditions, and import attributes. It
assigns path-independent root/package/builtin `SourceId`s, integrity-binds
package principals, emits a distinct authenticated carrier pair for every
module, and admits the resulting embedded graph against the carrier facts
before publication. Following the 2026-07-18 Snapback decision, computed
dynamic-import candidates are ordinary admitted nodes: the embedded graph
authenticates the exact candidate-set projection, the executable envelope
carries each canonical sidecar under its digest, and admission requires an
exact graph/carrier/candidate bijection before any factory loads.

The relocation fixture is now a real three-record graph: an ESM entry, a
relative ESM dependency, and the `node:path` runtime builtin. It packages the
same graph from two different checkout paths, byte-compares the complete
unsigned executables including carrier payloads, deletes both complete source
trees, ad-hoc signs and strictly verifies the Mach-O image, then executes it
from embedded bytes and observes `{"answer":42}`. This satisfies the issue's
schema/golden, builtin-graph, byte-identity, deletion, relocation, and execution
criteria on the spike.
