# Unchecked JS-number casts in the WebSocket close hook and sqliteOwn

**Status:** Closed
**Systems:** Bindings, Runtime
**Author:** Codex
**Date:** 2026-10-05
**Resolution:** Routed WebSocket handles and close codes plus SQLite owner kinds through checked integer conversion, guarded Intl part counts before conversion, and covered the native closures after hardening.

L1e made every numeric argument to the opt-in fetch primitives validated before
conversion (type, finiteness, integrality, range), because converting a NaN,
infinite, or out-of-range double to an integer type is undefined behavior in
C++. Two other host functions in the same file still do the unchecked form,
`static_cast<int>(args[1].asNumber())`:

- the WebSocket `close` hook (the close code argument);
- `sqliteOwn`.

Both are reached only through binding scripts that capture them at install, not
directly from application code, so this is lower risk than the primitives were.
It's still undefined behavior if a binding script ever passes a bad value.

The completed audit also found that `websocket_handle` converted before its
range check and that Intl NumberFormat converted the host-returned part count
without validating finiteness, integrality, or range. Both now validate before
conversion. The regression fixture captures the same native WebSocket and
SQLite closures their binding factories receive, hardens the runtime, and
checks non-numbers, NaN, both infinities, fractions, oversized values,
negatives, and zero where invalid.
