# LLP 0010: Ibex Binary Ownership

**Type:** Decision
**Status:** Accepted
**Systems:** CLI Runtime, Runtime, Build, Distribution, Documentation
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-14
**Revised:** 2026-07-06
**Related:** LLP 0000; LLP 0002; LLP 0005; LLP 0006

## Summary

The `ibex` executable is part of this repository. Exact may keep its project
CLI in the `exact` repo, but the JavaScript/TypeScript runtime binary that
users invoke as `ibex` is owned, built, and documented here.

This follows the product split already implied by the repo extraction:
Ibex is the runtime product; Exact is an application framework and project
tooling consumer of that runtime.

## Runtime Command Surface

The `ibex` command is runtime-only:

- shipped runtime commands: file execution, `run`, `eval`, `repl`, `build`,
  `completions`, `version`, runtime diagnostics (`debug`), and the LLP 0014
  `policy` toolchain.
- hidden harness commands: `self-test` runs a compact in-binary smoke suite for
  CI consumers; `compat` runs the WPT/Node/Bun/Exact compatibility harness
  (ported from exact's stranded `packages/exact-cli` compat module, ENG-23081)
  against the `test/compat/` fixture tree, which lives in the exact repo — the
  registered `websocket-wpt-compat` / `websocket-server-compat` checks invoke
  it through the vendored pin. Neither is advertised in help, and neither makes
  `ibex test` user-facing.
- reserved runtime names such as `test`, `install`, `bench`, and `exec` are not
  advertised until implemented.
- Exact project commands such as `new`, `create`, `init`, `verify`, `facet`,
  `agent`, `mcp`, `doctor`, and `lint` remain Exact CLI commands.

An existing local path wins over the command tables, so `ibex test` can still
execute a file named `test`.

### Surface manifest

The machine-readable authority for this surface is `runtime-surface.json` at
the repo root, next to `runtime-identity.json` (LLP 0012). It lives in this
repo — ibex-side, with the clap tree it describes — not in exact: after the
LLP 0180 split stranded exact's original manifest and its clap-tree pin
(exact-side LLP 0175 §8.1a), the manifest moved here with the binary
(ENG-22429). Two tests pin it in-process:

- `src/bin/ibex/cli.rs::surface_manifest_matches_clap_tree` — the clap tree's
  visible and hidden subcommands match the manifest exactly, and reserved and
  legacy names are absent from clap entirely.
- `src/bin/ibex/main.rs::dispatcher_tables_match_surface_manifest` — the
  pre-clap dispatcher tables own exactly the manifest's reserved and legacy
  names.

Adding or hiding a runtime command means updating the clap tree, the manifest,
and this document together. Exact's behavior guards may read this manifest from
the vendored pin; the copy here is authoritative.

## Binary Implementation

The binary target lives in this package as `[[bin]] name = "ibex"` and links
against the local `ibex_runtime` library crate. The `ex_` C ABI symbols and
`__exact*` JavaScript internals are compatibility surfaces and are not renamed
by this decision.

The binary reuses the same host ABI, Hermes bridge, module loader, generated
runtime bundle, and optional HTTP server implementation as embedders. This
keeps the runtime users exercise from the command line aligned with the
runtime library that Exact and Snapback embed.

## Build Profile

A default `cargo build --bin ibex` must compile without changing the library's
default feature set. In that profile the binary uses no-op HTTP/CDP bridge
shims where the `host-http-server` feature is absent.

The richer runtime CLI profile enables:

```sh
cargo build --bin ibex --features host-http-server,cli-notify
```

`host-http-server` links the real shared HTTP server. `cli-notify` replaces the
library's default callback notifier with the binary's Tokio-aware wakeup path.

## Consequences

- README and LLPs should describe this repo as the home of both the runtime
  library and the `ibex` runtime binary.
- Exact documentation should no longer be the source of truth for building or
  testing the `ibex` executable.
- Future runtime command additions should update this repo's CLI and LLPs.
- Future Exact project commands should not be added to the `ibex` clap tree
  without a new accepted Ibex LLP that changes the runtime/project boundary.
