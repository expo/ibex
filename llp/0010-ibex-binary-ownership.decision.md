# LLP 0010: Ibex Binary Ownership

**Type:** Decision
**Status:** Accepted
**Systems:** CLI Runtime, Runtime, Build, Distribution, Documentation
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-14
**Revised:** 2026-07-13
**Related:** LLP 0000; LLP 0002; LLP 0005; LLP 0006; LLP 0022; LLP 0024; LLP 0025

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
(ENG-22429).

Manifest version 5 includes the deterministic `clapSurface.commands` inventory
introduced in version 4 and adds `replSurface` and `keybindingSurface` as the
machine-readable authorities for the interactive runtime surface. The version
bump is deliberate: a consumer that understands only the Clap inventory must
not silently treat the larger manifest as if it had classified every runtime
control.

`replSurface` records the complete dot-command namespace and command-recognition
grammar, including aliases, usage and arity, admissible session modes and input
states, success and error destinations, affordance-parity classification,
CapSec relations, source-submission/ordinal behavior, and help text. It also
owns `.load`'s longest-suffix-first dialect and named-refusal table. The
deterministic generator validates the section against
`session/schema/repl-surface.schema.json` and emits the Rust dispatcher and
lookup tables, the exact `.help` fixture, and a generated reference table under
`vendored-generated/`. Dispatcher recognition, command completion, help,
argument validation, `.load` classification, and source-ordinal routing consume
that generated projection rather than parallel handwritten lists (LLP 0022 §8,
LLP 0024 §2).

`keybindingSurface` is the exhaustive published set of Ibex-owned session
controls beside that command table. It records the byte sequence, semantic
action, interrupt-credit classification, and help text for Tab, `Ctrl+C`,
`Ctrl+D`, `Ctrl+R`, and `Ctrl+Z`. Ordinary Emacs-profile editing remains the
editor's behavior; these are the controls Ibex dispatches and documents. The
same generator emits their typed Rust table, so the editor byte dispatcher and
`.help` cannot disagree (LLP 0025 §5).

Each retained Clap row identifies one canonical recursive command path and,
when present, its hidden state, command flag forms, visible and hidden aliases,
options, and positionals. Each option records its stable clap ID, canonical long/short
spellings, hidden state, visible or hidden aliases, and its recorded
`valueShape`; a root-authored global option additionally records `global: true`
once on its authority row, while Clap's inherited child copies are not duplicated.
Positionals record their stable clap ID, index, passthrough
status, and the same value shape. A value shape fixes the Clap action,
requiredness, value names, minimum and maximum cardinality (`maxValues: null`
means unbounded), whether the domain is none/arbitrary/enumerated, every
possible value plus its aliases and hidden state, whether possible values are
hidden, ordinary defaults, default-missing values, and hyphen handling.
`clapSurface.semanticRelations` separately records every reflected argument
conflict and one stable reviewed parser kind for each non-enumerated value.
Type-erased numeric parsers additionally have exact boundary probes. Optional
command and option fields whose values would be false, null, or empty are
omitted. An unbounded positional that allows hyphen-prefixed values is
classified as passthrough. This is an exact contract for the recorded parser
semantics, not a claim that help text or every Clap-internal setting is
serialized. The source-side test accepts only reviewed `#[arg]` and
`#[command]` attribute keys, so a new unrepresented parser relation fails
before it can hide behind an unchanged manifest. The accepted inventory
currently contains 14 command paths including the root, 58 options, and 7
positionals, of which the root and `run` `ARGS` positionals are passthrough.

Clap's generated help arguments, generated version arguments, and generated
`help` subcommand are parser controls and are excluded from the inventory.
Authored command and argument identities are captured before `Command::build`
adds those controls, rather than inferred from the name or action afterward.
Explicitly authored Help/Version actions and an authored `help` subcommand
therefore remain included when generated controls are disabled. In particular,
root `--version`, `-v`, and hidden alias `-V` are an Ibex option, and
`ibex version` is an Ibex command. Focused tests pin the authority in-process:

- `src/bin/ibex/cli.rs::surface_manifest_matches_clap_tree` — builds and walks
  the clap tree recursively, requires an exact one-to-one join for every
  authored command, option, alias, positional, reviewed parser kind, and
  conflict relation; checks the top-level visible and hidden sets; and requires
  reserved and legacy names to remain absent from clap entirely.
- `src/bin/ibex/cli.rs::authored_controls_are_not_confused_with_generated_controls`
  proves the pre-build identity distinction with synthetic and authored
  Help/Version controls, while the source-attribute and numeric-boundary tests
  fail closed on unrepresented relations or parser drift.
- `src/bin/ibex/main.rs::dispatcher_tables_match_surface_manifest` — the
  pre-clap dispatcher tables own exactly the manifest's reserved and legacy
  names.

Adding or hiding a runtime command, or changing an option, alias, or positional,
means updating the clap tree, the manifest, and this document together. Exact's
behavior guards may read this manifest from the vendored pin; the copy here is
authoritative.

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
