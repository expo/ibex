# Minimal Oxc script frontend (-e/-p, REPL, .load, stdin)

**Status:** Closed
**Resolution:** Closed from the progress evidence recorded in f5688afb: all five script surfaces use the typed Oxc frontend and pass real-Hermes coverage.
**Severity:** P2
**Systems:** Runtime, Module Loader
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §3, LLP 0024
**Depends-on:** oxc-llp0024-revision-and-differential

The bounded implementation this program owns (explicitly NOT the full
LLP 0024 session stack): an Oxc-backed frontend for the script surfaces
that execute through SWC-adjacent paths today — goal detection
(including TLA, replacing the `contains_top_level_await` text-scanner
readers in `-e` handling and bundle-format selection), lowering to what
the runner/session evaluator consumes, and the script-surface
computed-import exclusion (no `SourceId` ⇒ candidate-less invocation
error; literal dynamic import unaffected).

**Done when:** `-e`/`-p`, REPL, `.load`, and stdin execute through the
frontend with real-Hermes fixtures (TLA and non-TLA per surface); the
text scanner has no remaining readers; gates step 4.

## Progress

- `script_frontend::prepare_hybrid_script` now owns the pin-bound hybrid
  adapter, Script early errors, TypeScript/JSX lowering, AST-span static-import
  hoisting, literal dynamic-import handoff, expression completion metadata, and
  candidate-less computed-import rejection. A dead computed site loads; a
  reached site evaluates source/options first and returns a rejected Promise
  carrying `IBEX_ERR_SCRIPT_COMPUTED_IMPORT_NO_CANDIDATES` and the original
  source location.
- `-e`, `-p`, prompt input, `.time`, and `.load` all consume that typed result.
  The old REPL keyword/import scanners, handwritten import parser, and
  `replace("import(", ...)` rewrite are deleted. `.load` implements LLP 0024's
  extension table, including JSON parse/display and named refusals for module,
  declaration, extensionless, and unknown inputs.
- Piped stdin is distinct from a terminal REPL and uses
  `prepare_module_entry`: extensionless TypeScript/non-JSX parsing, strict
  Module top-level `this`, `ibex:stdin` metadata, local import bindings, and TLA.
- Real-Hermes tests execute TLA and non-TLA fixtures for all five requested
  surface groups: `-e`, `-p`, REPL, `.load`, and stdin. Frontend unit fixtures
  additionally pin sloppy-only Script behavior, static imports, nested dynamic
  imports, TypeScript completion, and Module metadata.
- The explicitly deferred LLP 0024 work remains deferred: structured session
  evaluation and composed session maps were not smuggled into this bounded
  ticket.
