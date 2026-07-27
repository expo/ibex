# LLP 0034: Enable Hermes ES6 Block Scoping in Ibex

**Type:** Decision
**Status:** Draft
**Systems:** Engine, Runtime, Build, Module Loader, Devtools, Verification
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-19
**Revised:** 2026-07-19; 2026-07-26 (tracked non-linkable Windows cross-compile exception)
**Related:** LLP 0003 (engine bridge); LLP 0005 (build pipeline); LLP 0007 (Vite/Rolldown/Oxc convergence); LLP 0019 (Hermes-compat transform authority); Exact LLP 0312 (Ibex transform authority); Exact LLP 0368 (TUI target); ENG-22558; ENG-22559; ENG-22569; ENG-25278; ENG-25279; ENG-25280; ENG-25281

## Context

Ibex's pinned Hermes contains an implementation of ES6 block scoping, including
per-iteration lexical environments for capturing `for`, `for...in`, and
`for...of` bindings. Hermes leaves that implementation disabled by default
behind the hidden compiler flag `-Xes6-block-scoping` and the embedder setting
`RuntimeConfig::Builder().withES6BlockScoping(bool)`.

Ibex currently accepts both defaults. As a result, a closure escaping a
`for (const binding of bindings)` loop can observe the final or an undefined
binding instead of the value from its own iteration. LLP 0019 compensates with
two source transforms, but both have intentional bailout sets. A real Exact TUI
bundle exposed one of those holes after Oxc preserved the modern loop while the
previous Babel/SWC path happened to downlevel it.

The failure is reproducible independently of Exact:

```js
const callbacks = [];
for (const binding of ["focus", "keydown", "blur"]) {
  const handler = binding === "keydown" ? () => "dismiss" : undefined;
  if (handler) callbacks.push(() => [binding, handler()]);
}
print(JSON.stringify(callbacks.map(callback => callback())));
```

The shipping default throws when the callback calls the captured `handler`.
Compiling the same source with `-Xes6-block-scoping` produces
`[["keydown","dismiss"]]`. The unmodified Oxc TUI bundle likewise passes the
product runtime/layout test when compiled in that mode.

Upstream introduced the gate because its debugger could not initially
represent the new block scopes. Debugger support has since improved, but the
upstream default remains disabled. Ibex therefore must own the product decision
rather than infer conformance from the upstream default.

## Options

### A. Keep source rewriting as the only compatibility mechanism

This preserves the current engine configuration, but retains LLP 0019's known
semantic holes and makes modern-transform adoption depend on whether a prior
tool happened to lower each loop.

### B. Patch the Hermes fork's global defaults

Changing Hermes's compiler and `RuntimeConfig` defaults would cover consumers
that never identify themselves as Ibex. It would also create an Ibex-only
upstream semantic patch, make rollback depend on rebuilt Hermes artifacts, and
hide the mode choice from bytecode cache identities.

### C. Enable the existing Hermes mode explicitly at every Ibex boundary

Ibex passes the compiler flag for HBC generation and sets the matching runtime
configuration for source compilation through `eval` and `Function`. Exact
compiler paths supplied by the Ibex integration do the same. The mode is named
in cache identities, observable in tests, and temporarily reversible.

## Decision

Choose Option C.

Ibex's default JavaScript semantic profile enables Hermes ES6 block scoping.
The mode is explicit at both sides of the compiler/runtime boundary:

- every Ibex-owned `hermesc` invocation that emits executable HBC passes
  `-Xes6-block-scoping`;
- every Ibex-owned main or worklet runtime sets
  `.withES6BlockScoping(true)`;
- Exact release/TUI compilation paths that consume Ibex's Hermes profile pass
  the same compiler flag;
- bytecode and bundle cache identities include the resolved mode;
- engine-executed fixtures assert per-iteration capture for precompiled HBC,
  JSI source evaluation, and worklet evaluation. Ibex's structural lockdown
  disables both direct `eval` and the dynamic `Function` constructor, so they
  are not separate product gates.

The temporary rollback control is
`IBEX_LEGACY_HERMES_BLOCK_SCOPING=1`. When present, Ibex and participating Exact
build paths omit the compiler flag, set the runtime configuration to false, and
select distinct cache identities. Because build-time bootstrap HBC embeds the
mode, a rollback build must rebuild those artifacts; the variable is not a
promise that already-emitted HBC can be reinterpreted under legacy semantics.

The rollback is a migration control, not a permanent public language mode. It
may be removed after the adoption and cleanup Linear issues close and at least
one checkpoint cycle has exercised the default on supported platforms.

### Tracked legacy Windows cross-compile exception

Exact's non-Windows `x86_64-pc-windows-msvc` compile gate has one explicit
exception while it cannot consume the authenticated source-patched Windows
Hermes bundle. Its strict authority is
`scripts/windows-hermes-cross-compile-profile.json` in the Exact repository,
and its retirement is tracked by
`issues/20260726-retire-legacy-windows-cross-compile-hermes.md`. The profile
digest-pins the deprecated `ReactNative.Hermes.Windows` 0.71.1 headers and
import library and must set both
`IBEX_WINDOWS_COMPILE_ONLY_PROFILE=1` and
`IBEX_LEGACY_HERMES_BLOCK_SCOPING=1`.

This is a cross-target metadata/type/lint fixture, not another supported
semantic or runtime profile. Its binary directory is empty, runtime provenance
is forbidden, runtime DLLs and compiler tools are absent, and Ibex poisons any
code-generation/final-link attempt. Consequently it is ineligible for native
link, runtime-extension, CapSec, WebGPU, lifecycle, or platform-qualification
evidence. Native Windows execution and conformance still require the
authenticated Ibex `windows-source-patched` profile with block scoping enabled.
The exception ends by deleting the Exact profile and its Ibex admission path,
not by generalizing `IBEX_LEGACY_HERMES_BLOCK_SCOPING`.

## Compatibility-transform transition

LLP 0019 remains the authority for the two existing `for...of` transforms
during adoption, but its engine premise changes:

1. Keep both transforms enabled initially. Correct engine scoping makes their
   successful rewrites redundant, while retaining them limits the first
   rollout's output-shape change.
2. Make the raw-engine canary mode-aware: default Ibex must match the
   JavaScript oracle; the explicit legacy mode must reproduce capture-last.
3. Add fixtures for every documented bailout. Under the new default, a bailout
   must no longer create an observable capture bug.
4. Retire the transforms only in a separate cleanup change after generated,
   loader, and direct-source paths are proven equivalent. Removing the AST
   authority and embedded scanner in one cleanup keeps LLP 0019's two-tier
   invariant true until the invariant is deliberately superseded.

## Cache and artifact identity

The resolved mode is an executable-code input, even when two HBC files happen
to share a bytecode format version. Therefore:

- the runtime entry-bytecode toolchain identity includes a stable mode token;
- the bundler cache key includes the same token because the compatibility
  transform retirement will make bundled source mode-dependent;
- TUI manifests record the mode alongside the `hermesc` version;
- changing the rollback variable cannot reuse an artifact emitted in the
  opposite mode.

This augments, and does not replace, the existing compiler/runtime binary
attestation and HBC-version gates in LLP 0005.

## Verification gates

The default may ship only when all of the following are green:

1. Minimal source and HBC closure-capture fixtures.
2. JSI source-evaluation closure capture in the embedded main runtime
   (structural lockdown intentionally disables direct `eval` and `Function`).
3. Worklet source evaluation with the same semantics.
4. Both LLP 0019 conformance runners, with mode-aware raw-engine expectations.
5. Ibex package/unit/integration tests and generated-artifact drift checks.
6. Exact's TUI runtime and PTY product profile using Oxc output without a
   source-level loop workaround.
7. TUI build latency and HBC size recorded against the existing SWC baseline;
   no regression beyond the governing product budgets.
8. At least one Apple-platform build and the available Linux/Windows compile
   gates, because runtime configuration is compiled separately per platform.

If a platform's Hermes artifact lacks `withES6BlockScoping`, that target must
fail configuration clearly or remain on the legacy profile with an explicit
tracked exception. It must not silently compile HBC in one mode and evaluate
source in another. The only current tracked exception is the non-linkable
Windows cross-compile fixture above; it does not qualify a native platform.

## Consequences

- Oxc can preserve modern lexical loops without relying on accidental
  downleveling for correctness.
- Direct source, cached HBC, bootstrap HBC, `eval`, and worklets share an
  explicit language-semantic profile.
- The compatibility transforms remain temporarily redundant, then become
  removable with engine-honest evidence.
- Ibex carries no new Hermes semantic patch; it configures an existing upstream
  feature and can take upstream improvements normally.
- A small amount of migration plumbing is required for the rollback control,
  cache keys, manifests, and generated capability-surface inventory.

## Open questions

- Whether the rollback control should be removed after one checkpoint cycle or
  retained until all platform artifacts share the same Hermes source pin.
- Whether the compatibility-transform cleanup should preserve a diagnostic
  legacy test path after removing the production transforms.
- Whether Ibex should separately take the post-pin upstream fix that propagates
  `-Xes6-block-scoping` into the standalone `hermes` CLI's REPL/eval runtime.
