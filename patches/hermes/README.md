# Carried Hermes patch stack (LLP 0013)

The Ibex Hermes pin (`scripts/hermes-version.sh`, currently
`260318099.0.0-stable`) **plus this ordered patch series is the fork** — the
Electron model at small scale. There is no separate long-lived fork repository.
`scripts/apply-hermes-patches.sh` applies the series after clone/checkout in
every `build-hermes*.sh`; it is idempotent and fails loudly if a patch stops
applying (the drift signal).

Each patch is classified in its header:

- **Class A — additive files** (new `.cpp`/`.h`, new JSI surface): rebase cost ~zero.
- **Class B — insertion points** (an `#include`, a call, a field at a marked site): rebase cost minutes; conflicts mechanical.
- **Class C — surgical semantic changes** (the interpreter `GetGlobalObject`/`this` cases, `eval`/`Function` binding): the only patches that can conflict meaningfully. Budgeted at single digits total.

A cross-cutting rewrite (realm-shaped) is prohibited by this discipline — that
is the line between "carrying patches" and "maintaining a divergent engine."

## Applied patches (Phase 2 — additive)

| # | File | Class | What |
|---|---|---|---|
| 0001 | `0001-domain-package-principal.patch` | B | Adds `Domain::packageId_` (a POD `uint32_t`; no metadata-builder change) + `get/setPackageId()`. The capability principal that owns a Domain's code. |
| 0002 | `0002-frame-attribution-helper.patch` | A (+1 B CMake line) | Adds `VM::getCurrentPackageId(Runtime&)`, which walks the stack to the nearest JS frame (skipping native frames, whose callee CodeBlock is null) and returns its Domain's `packageId`. The unforgeable replacement for the `g_active_module_id` thread-local. |

Both verified with `git apply --check` against the pinned checkout
(`ac8c6e6c80ec…`, HEAD of `origin/260318099.0.0-stable`).

### Remaining Phase 2 integration (not a Hermes patch)

The patches expose the primitive; wiring it to enforcement is Ibex-side:

1. **Set the principal.** When the module loader loads a package's bytecode,
   call a new JSI/C-API bridge to `domain->setPackageId(id)` for that package's
   Domain (per-package module units — Rolldown chunking — make Domain⇔package
   1:1). Until then `packageId_` stays 0 (trusted root).
2. **Read the principal.** `src/engine/hermes_runtime_internal.h:checkCapability`
   calls `getCurrentPackageId(runtime)` instead of reading `g_active_module_id`,
   and passes it to `ex_host_check_capability`. Then the thread-local,
   `__exactSetActiveModuleId`, and `__exactGrantCapability` can be deleted
   outright rather than sealed.

## Specified but not yet authored (Phase 3 — Class C, native compartments)

Exact anchors against the pinned checkout, so re-derivation is cheap (the spec,
not the diff, is the carried asset):

- **`GetGlobalObject` per-frame resolution.** `lib/VM/Interpreter.cpp:1842-1844`
  (`CASE(GetGlobalObject)` → `runtime.getGlobal()`), plus the sloppy-`this`
  UMD escapes `CASE(CoerceThisNS)` at `:1128` and `CASE(LoadThisNS)` at `:1143`.
  Replace `runtime.getGlobal()` with the executing frame's
  `CodeBlock→RuntimeModule→Domain→compartmentGlobal`. Companion **Class B**:
  add a `GCPointer<JSObject> compartmentGlobal_` field to `Domain` + its
  `DomainBuildMeta`. Budget: 3 interpreter sites.
- **`eval`/`Function` compartment binding.** `lib/VM/JSLib/Eval.cpp:157`
  (`getGlobal()` scope arg) and the two `codeBlock=nullptr` sites at
  `Eval.cpp:171-172` and `Interpreter-slowpaths.cpp:203-208`; the constructor
  entry points `Function.cpp:125-127`, `AsyncFunction.cpp:18-21`,
  `GeneratorFunction.cpp:76-78` (shared `createDynamicFunction` at
  `JSLibInternal.cpp:300`). Bind produced code to the caller's compartment.
- **Native lockdown primitive.** A new HermesInternal/JSI freeze function
  (**Class A**), optionally invoked after `initGlobalObject`/`initNativeBuiltins`
  at `lib/VM/Runtime.cpp:469-473` (**Class B**). Retires the userland freeze
  walk once native.

## Pin-bump runbook

1. Update `IBEX_HERMES_SOURCE_REF` in `scripts/hermes-version.sh`.
2. Build (the build scripts re-apply this series automatically). Class A/B
   resolve mechanically; for a Class C conflict, re-read the surrounding
   upstream change before resolving.
3. Run the conformance suite (`cargo test --test llp0013_compartments`), the
   runtime tests, and perf gates.
4. Land the pin bump + any patch updates in one commit; note in LLP 0013's
   revision log if semantics moved.

Target: routine bump ≤ half a day. Two consecutive bumps exceeding ~2 days each
is the signal to drop the costliest Class C patches back to their Phase 1
userland equivalents and keep A/B (see LLP 0013 §Contingencies).
