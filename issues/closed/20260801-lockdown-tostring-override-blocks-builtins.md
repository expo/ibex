# Lockdown's override-mistake repair misses `toString`/`valueOf`, breaking `buffer`, `os`, `string_decoder`

**Status:** Closed
**Resolution:** 2026-08-05
**Severity:** P1 — `require('buffer')` is unusable in an armed runtime
**Systems:** Engine (lockdown), Builtins
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0013 Mechanism 1 (lockdown / SES-style intrinsics freeze);
issues/closed/20260801-builtin-commonjs-require-activation-refused.md (found
while unblocking that)

## Symptom

With the CommonJS builtin activation blocker fixed, these still fail at
*evaluation*:

```
$ ibex run -- 'require("buffer")'
error: Cannot assign to read-only property 'toString'
    at (builtin:node_buffer:937:22)   [vendored-generated/builtins/buffer.js]

$ ibex run -- 'require("os")'
error: Cannot assign to read-only property 'toString'
    at legacyStringValue (builtin:node_os:12:14)

$ ibex run -- 'require("string_decoder")'
error: Cannot assign to read-only property 'toString'
    at (builtin:node_string_decoder:248:34)
```

Measured with `cargo build --bin ibex --features standard,unadvertised-dev-arming`.
`net`, `dgram`, `http`, `util`, `assert`, `events`, `stream`, `dns`, `fs` and
`path` all load fine, so this is specific to modules that assign `toString`.

## Root cause

The classic "override mistake". Lockdown's freeze walk
(`src/engine/hermes_runtime.cc`, `roots = [Object, ..., Function.prototype,
Object.prototype, ...]`) makes `Function.prototype.toString` and
`Object.prototype.toString` non-writable data properties. A non-writable
property on the prototype chain rejects plain assignment on any inheriting
receiver, and builtin factories are compiled under `"use strict"` (the module
trampoline prepends it), so the assignment throws rather than silently
no-op'ing.

`os.js` does exactly this:

```js
fn.toString = function() { ... };
fn.valueOf = fn.toString;
```

Lockdown already contains the correct repair — `enableOverride(obj, label,
prop)` converts a data property into an accessor whose setter shadows on the
receiver — but it is applied **only to the error intrinsic family**
(`constructor`, `message`, `name`, and `Error.prototype.toString`). SES
moderate additionally enables `Object.prototype.toString`/`valueOf` and
`Function.prototype` members for precisely this reason.

## Suggested fix

Extend the `enableOverride` set to cover at least
`Object.prototype.{toString, valueOf}` and `Function.prototype.{toString,
valueOf}` before the freeze walk, matching SES moderate. Alternatively (or in
addition) change the three builtins to `Object.defineProperty(fn, 'toString',
{...})`, which is unaffected by the override mistake — but that only fixes the
builtins we happen to know about, and package code hits the same wall.

Whichever is chosen, the intrinsics must still end up frozen: the repair
converts the property to a frozen accessor pair, it does not leave it mutable.

**Done when:** `require('buffer')`, `require('os')` and
`require('string_decoder')` succeed in an armed runtime, with a regression test
that asserts `Object.prototype.toString` is still non-configurable-on-the-
prototype (assignment to the frozen prototype itself still throws) while
`someFn.toString = f` shadows on the receiver.

## Resolution

The implementation took the ticket's explicit-own-property alternative rather
than widening the intrinsic override set. Commits `74c1e5a1`, `e733ced2`, and
`673bfd10` converted the affected lazy builtins to define their own
`toString`/`valueOf` properties after primordial lockdown and added focused
regressions. On 2026-08-05,
`lazy-builtin-lockdown.test.ts` and
`string-decoder-lockdown-eng24233.test.ts` passed 3/3 locally; the release and
CapSec suites retain the armed-runtime coverage.
