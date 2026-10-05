# Unchecked JS-number casts in the WebSocket close hook and sqliteOwn

**Opened:** 2026-10-05 (found while fixing L1e's fetch primitives)
**Area:** `crates/ibex2/src/bindings/install.cc`

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

**Fix:** route both through the same checked-conversion helper L1e added
(`65e9354`), and add a regression test for each (NaN, Infinity, fraction,
out of range).
