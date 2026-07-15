# LLP 0027: ModuleArtifact Wire and ESM/CommonJS Interop Contract

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Runtime, Engine, Build, Security
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-15
**Revised:** 2026-07-15 (ENG-25059 v1 schema, codecs, admission gate,
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
`tests/fixtures/module-artifact-v1/`. The document remains Draft while the
ENG-25061 interop half is implemented. No producer output becomes trusted
merely because it resembles this shape.

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

`static_edges` and `export_descriptors` are closed tagged variants, never
free-form strings. Import edges distinguish named, default, namespace, and
side-effect forms. Re-export edges distinguish named and star forms. Export
descriptors distinguish local, indirect, and star forms. Every edge with an
authored specifier retains it and its validated runtime import attributes.
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
fingerprint, typed static edges, typed export descriptors, CommonJS detected
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
The ESM adapter for an evicted throwing CommonJS record follows CommonJS cache
algebra and may observe re-evaluation rather than ESM sticky failure.

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
rules rather than defining another interop mode.

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
