# LLP 0027: ModuleArtifact Wire and ESM/CommonJS Interop Contract

**Type:** Spec
**Status:** Accepted
**Systems:** Module Loader, Runtime, Engine, Build, Security
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-15
**Revised:** 2026-07-15 (accepted by the author after the bounded CommonJS/JSON/builtin interop migration passed authenticated source/prepared real-Hermes coverage); 2026-07-15 (ENG-25063 retained graph generations through the complete embedder event-loop drive so delayed and fire-and-forget dynamic imports cannot observe released records); 2026-07-15 (ENG-25061 added host-owned builtin records and strict shared-identity JSON records across source/prepared ESM and CommonJS paths); 2026-07-15 (ENG-25061 linked production mixed ESM/CommonJS graphs in both directions, including pre-evaluation adapters and async ESM importers); 2026-07-15 (ENG-25064 canonical prepared-graph index, cache publication, strict reload, and full native linking); 2026-07-15 (ENG-25064 canonical prepared-carrier schema, admission, and source/HBC native loading); 2026-07-15 (ENG-25063 authenticated dynamic-edge metadata and
promise-returning CommonJS-to-ESM import ABI); 2026-07-15 (ENG-25061 native CommonJS cache records and ESM
snapshot adapters); 2026-07-15 (ENG-25059 v1 schema, codecs, admission gate,
producer adapter, and tamper fixtures)
**Related:** LLP 0012 (pinned Node compatibility target); LLP 0014 (reserved policy attributes); LLP 0023 (source identity); LLP 0026 (accepted module-runner architecture); ENG-25059; ENG-25061

## Summary

This document is the normative home for the versioned `ModuleArtifact` wire
format and the ESM/CommonJS interop boundary adopted by LLP 0026. LLP 0026
continues to own architecture and migration sequencing; this Spec owns bytes,
validation, digest domains, adapters, and observable interop behavior.

The first implementation targets `ibex/module-artifact/1`. The canonical
schema is `schemas/module-artifact-v1.schema.json`; the Rust codec and verifier
are `src/module_loader/artifact.rs`; the checked-in tamper matrix is under
`tests/fixtures/module-artifact-v1/`. Prepared graph publication is implemented
by `src/module_loader/runner_pipeline.rs` and described by
`schemas/prepared-module-graph-v1.schema.json`. The bounded
CommonJS/JSON/builtin interop migration is complete and covered through
authenticated source and prepared execution on real Hermes. No producer
output becomes trusted merely because it resembles this shape.

## Artifact envelope

A logical artifact contains:

```text
ModuleArtifactV1 {
  schema                    // exactly "ibex/module-artifact/1"
  semantics {
    source_id               // canonical authenticated LLP 0023 encoding
    source_goal             // module | common-js | json | builtin
    dialect                 // js | jsx | ts | tsx | null
    source_integrity
    transform_fingerprint
    static_edges[]
    dynamic_edges[]         // literal spellings or stable computed-site ids
    export_descriptors[]
    commonjs_exports?
    has_top_level_await
    factory_digest
    source_map              // SourceId indices, never host labels
  }
  semantic_digest
  payload                   // inline factory bytes | carrier entry binding
  producer                  // in-process | prepared
}
```

`static_edges`, `dynamic_edges`, and `export_descriptors` are closed tagged
variants, never free-form strings. Import edges distinguish named, default, namespace, and
side-effect forms. Re-export edges distinguish named and star forms. Export
descriptors distinguish local, indirect, and star forms. Every edge with an
authored specifier retains it and its validated runtime import attributes.
Literal dynamic imports retain their authored spelling and attributes. A
computed dynamic import retains only a stable producer-order site id; the exact
specifier and target come from the authenticated finite candidate set and are
checked at invocation, so an unselected spelling is denied without probing.
For compatibility with already-issued v1 artifacts, an empty `dynamic_edges`
array is omitted canonically and decodes as empty; a non-empty array is covered
by the semantic digest.
Reserved LLP 0014 policy keys are rejected: authority annotations are consumed
into the armed policy before artifact emission and never enter this wire form.

Entry/dependency role and execution generation are request/record state, not
artifact fields. `SourceLabel` is machine-local diagnostic data and is also
excluded. A local envelope maps stable `SourceId` indices in the source map to
authenticated display labels.

## Canonical encoding and validation

The deterministic encoding is RFC 8785-style JCS JSON over strict I-JSON input.
The checked-in JSON Schema is a review artifact; the Rust decoder independently
enforces the closed structure and semantic cross-field invariants. Decoders
reject at least unknown fields, duplicate keys, unknown enum/tag values, non-canonical
ordering or encoding, malformed `SourceId`s, unsupported schema or ABI
versions, inconsistent source-kind fields, reserved policy attributes,
non-canonical digests, and payload bindings that do not verify.

Prepared artifacts are admitted only when their semantic digest is bound into
the authenticated deployment graph and both the graph digest and prepared
producer binary digest match. Inline artifacts require the expected in-process
producer binary. Both paths also match the authenticated `SourceId`, source
integrity, expected producer identity, and transform-fingerprint digest.
Successful verification yields a `VerifiedModuleArtifactV1` token; cache
publication and factory compilation consume that token rather than raw
deserialization.

## Digest domains

The semantic digest is carrier-independent and covers every semantic field:
canonical `SourceId`, source kind, dialect, source integrity, transform
fingerprint, typed static and dynamic edges, typed export descriptors, CommonJS detected
names and detector version where applicable, the exact logical factory bytes,
top-level-await bit, and source map. Every semantic field is either covered or
deterministically derived and recomputed from covered data.

The payload binding authenticates the physical representation separately:

- an inline payload proves that its factory bytes produce the semantic digest;
- a carrier payload proves the carrier digest, entry identity, and the entry's
  mapping back to the semantic digest.

Inline and carrier forms of the same logical artifact therefore share one
semantic digest. A carrier has its own digest and manifest and never becomes
the `SourceId` or semantic identity of any contained module. Cross-project
portable reuse remains prohibited until LLP 0023 defines a stable authenticated
project identity collision domain.

The canonical prepared manifest is `ibex/module-carrier/1`, specified by
`schemas/module-carrier-v1.schema.json` and enforced by
`src/module_loader/carrier.rs` (`commit:c6d2aefe`). It binds exactly one
defining principal, prepared-producer binary, deployment-graph digest, carrier
digest, and either `javascript-factory-table` or `hermes-bytecode` encoding.
HBC encoding additionally binds the loaded engine binary digest and bytecode
version. Its strictly ordered entries contain an entry id, the complete
original semantic core, and its recomputed semantic digest. Admission rejects
cross-principal entries, bytes/metadata tamper, entry substitution, graph or
producer drift, and stale engine/HBC identity before native evaluation.

The graph-level cache index is `ibex/prepared-module-graph/1`, specified by
`schemas/prepared-module-graph-v1.schema.json`. It binds the authenticated
entry, producer and deployment digests, every original module's absolute
source label, resolved-specifier map, prepared artifact, carrier/entry
location, and the complete carrier inventory. It is strict canonical JCS.
Reload independently admits every carrier and artifact, re-authenticates each
source identity and integrity, re-resolves each authored edge against the
current armed snapshot, and rejects mixed inline/prepared graphs before
linking.

`transform_fingerprint` includes parser/transform versions, Hermes target,
TypeScript/JSX options, module-runner ABI, Hermes-compat pass version, CommonJS
detector version, and every output-affecting option.

The cache-key digest additionally covers the artifact schema, canonical
`SourceId`, source integrity, transform-fingerprint digest, loaded engine binary
digest, producer binary digest, and runtime-configuration digest. No host path,
source label, carrier path, or cache directory participates.

## ESM/CommonJS interop matrix

The oracle is LLP 0012's hermetically pinned Node release, currently Node
24.13.1. The checked-in corpus is authoritative when prose and a future oracle
pin disagree; changing the pin requires regenerating and reviewing the
fixtures. Any deliberate difference is a named expected divergence.

| Requester | Target | Contract |
|---|---|---|
| ESM `import` | ESM | Link to stable namespace and live checked binding cells; evaluation may suspend. |
| ESM `import` | CommonJS | Evaluate synchronously; expose a namespace whose `default` and `'module.exports'` entries are the final `module.exports`, with statically detected named snapshots. |
| CommonJS `require()` | CommonJS | Publish the cache record before execution, expose partial exports during cycles, and evict on throw. |
| CommonJS `require()` | ESM | Synchronously load/link/evaluate only when the complete statically reachable closure is proven free of top-level await and incompatible in-flight records. |
| CommonJS `import()` | ESM | Return a promise for the stable ESM namespace; asynchronous graphs are supported. |

CommonJS named exports use the pinned `cjs-module-lexer` behavior. Detected
names are snapshots and do not update after later `module.exports` mutation.
The detector's reexport specifiers are retained separately and must name typed
CommonJS require edges so adapter-name traversal never performs an ambient
resolution.
The CommonJS cache entry is evicted on throw, while any ESM adapter already
linked to that incarnation retains the same sticky failure. A later CommonJS
require may create and evaluate a fresh CommonJS record without mutating the
failed ESM incarnation.

The native implementation stamps factory handles with their admitted source
goal, publishes the initial CommonJS record before execution, and resolves
`require` only through authenticated links. A cycle observes the target's
current `module.exports`, including replacement before the recursive require.
A throw evicts and invalidates the CommonJS handle. Its single stable ESM
adapter is created before graph linking with uninitialized cells; successful
completion fills the two identity entries and detector-approved named
snapshots, while a throw marks the adapter errored.

The artifact represents each statically detected literal `require` as a
`common-js-require` static edge. It is resolved with CommonJS conditions and
authorized as `LiteralRequire`; it is never collapsed with an ESM static or
dynamic-import edge having the same authored specifier. Computed `require`
sites require a finite authenticated candidate table or remain outside the
native path.

The CommonJS factory ABI is `(require, module, exports, __filename, __dirname,
dynamicImport)`. `dynamicImport(specifier)` (also exposed as `require.import`
for lowering adapters) returns a fresh promise for an authenticated linked ESM
namespace and supports asynchronous target graphs. A missing, denied, stale,
or malformed target returns a rejected promise rather than throwing from the
factory call.

The embedder pins the authenticated graph generation before native linking and
releases it only after the file-owned event-loop drive completes. Dropping the
Rust linker handles therefore defers native record cleanup, allowing a dynamic
import initiated by a later timer or a fire-and-forget promise chain to retain
the same generation, context, target table, and sticky record state. Unpinning
releases all deferred ESM/CommonJS records and their context references as one
owner-thread operation.

For `require(ESM)`, an explicit ESM export named `'module.exports'` is returned
directly. Otherwise the namespace object is returned, with `__esModule`
conditionally present when the namespace has a default export, following the
pinned oracle including property descriptors and falsy defaults. An
async-tainted graph fails before evaluating any newly selected target record
with the stable `ERR_REQUIRE_ASYNC_MODULE`-class family. Same-drive cycles and
overlap with in-flight async records fail with the stable
`ERR_REQUIRE_CYCLE_MODULE`/async family defined by the corpus; no refused drive
may leave partial new records.

JSON retains one ordinary file-backed identity. ESM JSON imports require the
pinned import attribute; CommonJS JSON requires by extension. Both adapt the
same record. Ibex's `require` extension inside ESM follows the CommonJS request
rules rather than defining another interop mode. The trusted producer parses
strict JSON (including duplicate-key rejection), binds integrity to the
original bytes, and embeds canonical JCS only in a factory whose single export
is `default`. ESM observes that default through the normal namespace; CommonJS
`require()` returns the JSON value directly.

Builtins retain `SourceGoal: Builtin` and their manifest-derived builtin
`SourceId`; they cannot be represented by a package-owned file identity.
Their embedded registry source uses the CommonJS lifecycle and typed builtin
edges. A builtin is charged to the authenticated root initialization owner,
and a root-principal carrier may contain builtin entries without changing
their host-owned SourceIds. Package policy is checked by the no-probe armed
resolver before the exact builtin target enters the graph.

## Canonical artifacts and acceptance fixtures

The reviewed producer-spike artifacts live under
`tests/fixtures/module-runner-spike/`; its `manifest.json` is the canonical
12-case list and the frozen test262 subset records upstream paths and SHA-256
digests. LLP 0026 froze the real-Hermes spike threshold at 90% (18/20) with an
initially empty divergence list. Adoption evidence recorded 12/12 canonical
and 20/20 test262 passes.

The production v1 schema gate adds round-trip fixtures for every source kind
and edge/descriptor variant plus rejection fixtures for field substitution,
TLA-bit tampering, malformed variants, cross-machine label injection,
source/principal mismatch, carrier-entry substitution, detector-version
drift, unknown schema/ABI versions, and non-canonical encoding. Interop
fixtures cover namespace keys and descriptors, `'module.exports'`,
`__esModule`, falsy defaults, replacement/mutation, cycles, throws/eviction,
TLA refusal, in-flight overlap, and source/prepared equivalence on real Hermes.

## Resolved and open questions

- **Resolved:** v1 uses strict canonical JCS JSON, with a checked-in closed JSON
  Schema and an independent Rust verifier.
- **Resolved:** the semantic core stores a domain-separated factory digest.
  Inline payloads supply and verify the bytes; carrier payloads bind a carrier
  digest, entry identity, and the same factory digest. Thus cross-carrier forms
  retain one semantic digest without reconstructing bytes merely to identify
  the module.
- Which exact stable error codes and descriptor details need Ibex-owned names
  rather than direct pinned-oracle parity?
