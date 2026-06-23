# LLP 0010: Ibex Binary Ownership

**Type:** Decision
**Status:** Accepted
**Systems:** CLI Runtime, Runtime, Build, Distribution, Documentation
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-14
**Related:** LLP 0000; LLP 0002; LLP 0005; LLP 0006; exact LLP 0165; exact LLP 0175

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
  `completions`, `version`, and runtime diagnostics.
- reserved runtime names such as `test`, `install`, `bench`, and `exec` are not
  advertised until implemented.
- Exact project commands such as `new`, `create`, `init`, `verify`, `facet`,
  `agent`, `mcp`, `doctor`, and `lint` remain Exact CLI commands.

An existing local path wins over the command tables, so `ibex test` can still
execute a file named `test`.

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
