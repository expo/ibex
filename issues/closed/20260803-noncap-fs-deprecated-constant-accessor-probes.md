# noncap batch executes warning-producing node:fs constant accessors

**Status:** Closed
**Severity:** P3
**Systems:** CapSec, Testing
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-03
**Related:** LLP 0021 §WP10; PR #25

After the `node:crypto` `Sign.end` validator defect was fixed, the physical
Apple replay and Windows CapSec matrix both reached the next public builtin
fixture and failed on `node:fs` `F_OK`:

```
surface.builtin.export.node.fs.f.ok.0m31icr.main.non-capability:
public builtin probe failed: {"kind":"throw","moduleSpecifier":"node:fs",
"exportName":"F_OK","errorName":"Error",
"errorMessage":"process.emitWarning is disabled for this event in an armed runtime"}
```

The root `F_OK`, `R_OK`, `W_OK`, and `X_OK` properties are deprecated
accessors. Each getter intentionally emits DEP0176 before returning its value,
so none is a zero-effect read. The same numeric values remain available from
the inert `fs.constants` object.

## Resolution

Probe authoring now leaves exactly those four accessors residual with the
reason `builtin-export-requires-deprecation-warning`. The independent loaded-
engine validator rejects stale recipes before requiring `node:fs` or
evaluating a getter. Regression coverage fixes the exact four-name vocabulary,
and target accounting moves four fixtures from fully executable to unresolved
on both Apple and Windows without weakening armed warning-channel closure.
