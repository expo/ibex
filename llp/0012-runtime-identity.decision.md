# LLP 0012: Runtime Identity

**Type:** Decision
**Status:** Draft
**Systems:** Runtime, CLI Runtime, Documentation
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-27
**Related:** LLP 0000; LLP 0006; LLP 0010

## Context

Ibex presents a JavaScript runtime identity through `process.title`,
`process.versions`, `navigator.userAgent`, the runtime banner, and generated
Rust/TypeScript bindings. Those values are read by application code and by
compatibility libraries, so they must be coherent across the Rust CLI, the
embedded runtime bundle, and native bootstrap snippets.

The repository was extracted from Exact, and some inherited comments referred
to a non-local Exact LLP. In Ibex, the local source of truth is
`runtime-identity.json`; generated bindings are produced from it by
`packages/ibex-devtools/src/scripts/generate-runtime-identity.ts`.

## Decision

`runtime-identity.json` is the authority for the runtime identity values that
ship with Ibex.

The policy is Node-primary and truth-preserving:

- `versions.node` names the Node release that the vendored compatibility corpus
  tracks.
- Ibex ships only truthful ambient version keys by default: the runtime, the
  engine, and the Node compatibility target.
- Ibex must not claim ambient `v8`, `uv`, `openssl`, or Node module ABI values
  that it does not actually provide.
- Fixture-only compatibility keys may be injected by test harnesses, but they
  must not become default runtime identity.
- The Bun-shaped surface is opt-in. When `--compat=bun` or
  `EXACT_COMPAT_BUN=1` enables the Bun facade, `process.versions.bun` is set
  too so feature detection remains coherent.

## Consequences

Renaming comments, banners, or generated identity outputs should update
`runtime-identity.json` or the generator, then regenerate the Rust and
TypeScript bindings.

Compatibility globals and specifiers that intentionally retain Exact names
(`Exact`, `__exact*`, `exact:*`) are not part of the user-facing runtime name.
They remain available unless a separate compatibility decision removes them.

## Open Questions

- Should the public runtime banner stay enabled by default for all entry modes,
  or only for interactive/debug modes?
