# LLP 0004: Module Loading and Builtins

**Type:** Explainer
**Status:** Draft
**Systems:** Runtime, Module Loader, Build
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Related:** LLP 0000; LLP 0002 (Host ABI); LLP 0005 (Build pipeline)

## Summary

Module loading has two layers: a **builtin registry** that maps bare/`node:`/
`bun:`/`exact:` specifiers to embedded JS sources, and an **on-disk resolver**
(oxc_resolver) for everything else. Both live in `src/module_loader/mod.rs`. The
builtin surface is data-driven: a manifest authored in TypeScript (`modules.ts`)
is compiled to a generated Rust table (`builtin_manifest.generated.rs`) and a
set of transformed builtin JS files, which the loader includes at compile time.
This document maps that resolution path and the builtin surface; how the
manifest/builtins are *generated and vendored* is [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).

## Resolution order

`ModuleLoader::resolve_meta` (`src/module_loader/mod.rs:113-144`) resolves a
specifier in this order `[observed]`:

1. **Private package imports** (`#`-prefixed): resolved against the nearest
   `package.json` `imports` map (`src/module_loader/mod.rs:118-125, 146-161`).
2. **Builtin registry hit**: if the specifier is a key in the builtins map, it
   returns a `ModuleKind::Builtin` with the embedded source inline — no disk
   access (`src/module_loader/mod.rs:126-133`).
3. **Unknown `exact:`/`node:` guard**: a specifier that *starts with* `exact:`
   or `node:` but missed the registry is a hard error
   (`Unknown exact builtin` / `Unsupported node builtin`,
   `src/module_loader/mod.rs:135-141`).
   `[observed]` Note this only fires for specifiers the manifest did not
   register; registered ones like `node:fs` hit step 2.
4. **On-disk resolution** via oxc_resolver (`resolve_with_oxc`,
   `src/module_loader/mod.rs:143`).

`resolve_module` on `Host` additionally enforces an `fs:read:<path>` capability
before loading a resolved file path (`src/host/mod.rs:161-174`) `[observed]`.

### The oxc_resolver configuration

The resolver is configured (`src/module_loader/mod.rs:67-105`) with
`[observed]`:

- Extensions `.js .cjs .mjs .ts .tsx .jsx .mts .cts .json`.
- Condition names `node, require, import, default`.
- TS `extension_alias` so `./x.js` in TS sources resolves to `./x.ts` on disk
  (`src/module_loader/mod.rs:88-98`), matching the TS NodeNext / Vite convention.

### Loading and on-the-fly transpilation

`load_source` reads the resolved file (`src/module_loader/mod.rs:163-186`) and
transpiles when needed: `.ts/.tsx/.jsx/.mts/.cts` always (`needs_transpile`,
`src/module_loader/mod.rs:188-193`),
and `.js/.mjs/.cjs` when the source uses syntax Hermes can't run directly —
async generators, `for await`, `using`, certain block-scoped loop closures —
which are down-leveled (`needs_js_downlevel` + the `source_needs_*` scanners,
`src/module_loader/mod.rs:195-228`). Transpilation runs through
`src/module_loader/transpile.rs`, which imports swc parser/codegen/transform
crates and lowers to CommonJS for the loader's synchronous `require()` chain
`[observed]` (`src/module_loader/transpile.rs:1-16, 20-34, 36-45`;
`Cargo.toml:56-64`).

## The builtin module surface

The builtin registry is built at runtime from a generated table:

- `src/module_loader/mod.rs:58` does
  `include!(concat!(env!("OUT_DIR"), "/builtin_manifest.generated.rs"))`,
  pulling in `BUILTIN_MANIFEST_REGISTRATIONS` (specifier -> source_key) and
  `BUILTIN_MANIFEST_DEBUG_ENTRIES` `[observed]`. The vendored snapshot shows
  the generated registration table and debug entries `[observed]`
  (`vendored-generated/builtin_manifest.generated.rs:1-5, 136-142`).
- `build_builtin_registry` (`src/module_loader/mod.rs:1047-1070`) resolves each registration's
  `source_key` to an embedded JS string via `generated_builtin_source` and
  builds the `HashMap<String, String>` of specifier -> source `[observed]`.

### One source, many specifiers

The manifest maps multiple public specifiers to one source. From the generated
table and its authoring file `[observed]`
(`vendored-generated/builtin_manifest.generated.rs:5-132`; `modules.ts:671-730`):

- `exact:*` are the native/runtime builtins (`exact:process`, `exact:crypto`,
  `exact:clipboard`, `exact:http`, `exact:sqlite`).
- Node compatibility: `node:fs`, `fs`, and `bun:fs` all map to `node_fs`;
  `node:crypto`/`crypto` map to `exact_crypto`; etc.
- Bun compatibility: `bun:sqlite` maps to the same source as `exact:sqlite`;
  `bun:fs` to `node_fs`.

So `node:`, `bun:`, and bare specifiers are deliberate aliases onto a shared set
of embedded sources `[observed]` (`modules.ts:693-699, 728-729`).
`[inferred: the single-source-many-aliases design lets Ibex present a Node- and
Bun-compatible import surface without maintaining separate implementations.]`

`exact:http` and `exact:sqlite` are not generated builtin files: their source
keys point at repo files under `packages/ibex-runtime-js`, and the generated
manifest includes those files directly from `CARGO_MANIFEST_DIR` `[observed]`
(`modules.ts:549-555`;
`vendored-generated/builtin_manifest.generated.rs:140-142, 271-272`).

The transformed builtin JS files are committed under
`vendored-generated/builtins/*.js` and authored under `src/builtins/*.js`
`[observed]` (`vendored-generated/README.md:11-27`). Two specifiers (`sqlite`,
`sea`) are reserved Node-only `[observed]` (`modules.ts:19-21`).

## How the runtime consumes this

- At **resolution** time, the Rust loader returns the inline builtin source (no
  bytecode here) `[observed]` (`src/module_loader/mod.rs:126-133`).
- The C++ engine reaches the loader through `__exactModuleResolve` /
  `__exactNativeModuleResolve` JSI functions, which call the Rust
  `ex_host_module_resolve` ABI (`src/engine/hermes_runtime.cc:1191-1193`;
  `src/host/abi.rs:730-779`) `[observed]`. The Rust side returns a JSON object
  carrying `id`, `kind` (`builtin`/`cjs`/`json`/`esm`), `path`, and `source`
  `[observed]` (`src/host/abi.rs:758-769`).
- The JS module-loader bootstrap (`src/engine/bootstrap/module-loader.js`)
  drives `require`/`import` against this resolve function `[observed]`
  (`src/engine/hermes_bootstrap.cc:193-204`).
  The C++ installer comments that the native alias survives a dev-server
  hot-reload override of the canonical resolver `[observed]`
  (`src/engine/hermes_runtime.cc:1186-1190`). `[inferred: registering both names
  keeps a stable native escape hatch while allowing development overrides.]`

## Boundaries / open questions

- The manifest and transformed builtins are **generated artifacts**, vendored
  for hermetic builds; editing the runtime surface means editing `modules.ts` /
  `src/builtins` and regenerating, not editing `vendored-generated/` —
  see [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).
- ESM/CJS interop and full Node package resolution are described in-code as
  "implemented incrementally (see TODOs)" `[observed]`
  (`src/module_loader/mod.rs:3-5`); the
  resolver is called "minimal." Exact gaps are not enumerated here.
