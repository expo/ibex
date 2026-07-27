# LLP 0024 revision (full seam) + archived parser differential

**Status:** Closed
**Resolution:** Closed by f5688afb after the LLP 0024 seam revision, archived parser differential, and native Hermes acceptance gate landed.
**Severity:** P2
**Systems:** Module Loader, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §3, LLP 0024, LLP 0026 §3

Revise LLP 0024 under LLP 0026 §3's "or 0024's contracts are revised"
clause — not just an engine rename: pin `oxc_parser` (locked version,
build-time assertion), name Oxc as the engine of the *future* session
implementation, and describe the complete post-retirement seam (parser
entry point; hybrid Script+import+TLA goal feasibility in Oxc terms
with its own oracle; the module-runner handoff once `transpile.rs` is
gone; source-map composition after Tier 2 deletion; non-module
requester identity per the script-surface exclusion). Reconcile every
LLP 0024 reference to deleted machinery. Cutover evidence: one-shot
archived `swc_ecma_parser` vs `oxc_parser` differential over the goals
**both parsers implement**, via a precommitted normalized
parse-equivalence projection (fields, spans, error-recovery classes
defined before the run), plus a representative `node_modules` sweep.
Add the separate Oxc-vs-Hermes acceptance check for JS goals on the
producer path (additional gate, proves engine acceptance only).

**Done when:** LLP 0024 `Revised:` entry lands; differential report
archived (content-addressed) with the precommitted projection;
Hermes-acceptance gate wired per advertised tuple.

## Progress

- LLP 0024 now pins Oxc 0.140.0 through the canonical transform configuration
  and describes the post-retirement parser, runner, requester-identity,
  computed-import, and source-map seam.
- The hybrid-goal feasibility path is executable: Oxc Module syntax parsing
  retains the required sloppy AST, then Script semantic validation admits only
  the exact diagnostics corresponding to real static import declarations. Tests
  cover sloppy/strict forms, imports, TLA, top-level reservation, and nested
  `await` identifiers.
- The predeclared projection and 24-case corpus now drive a reproducible report
  generator. The content-addressed archive covers 536 parses: the corpus plus
  Script and Module goals for 256 deterministic `node_modules` JavaScript files.
  Acceptance agrees in all cases. Five recorded differences are recovery-AST
  availability on inputs both parsers diagnose; the frontend rejects all parser
  diagnostics, so those ASTs are not observable.
- The separate named Oxc-producer-to-loaded-Hermes JavaScript gate is wired into
  the non-Windows native baseline matrix, which covers the advertised macOS
  arm64 and Linux x64 tuples. It admits the exact producer artifact, compiles it
  in the loaded evaluator, executes it, and checks the namespace. As required,
  it proves evaluator acceptance only—not TypeScript or SWC equivalence.
