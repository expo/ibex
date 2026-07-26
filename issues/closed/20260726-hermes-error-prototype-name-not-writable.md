# Error subclass `prototype.name` assignment fails under lockdown (override mistake)

**Status:** Closed (2026-07-26)

## Symptom

Under structural lockdown (the default — it is a runtime constructor
invariant), the ubiquitous npm error-subclass idiom fails:

```js
"use strict";
class MyError extends Error {}
MyError.prototype.name = "MyError";
// TypeError: Cannot assign to read-only property 'name'
```

The same failure hits instance-level renaming, equally common in real
packages:

```js
const e = new Error("x");
e.name = "MyError"; // TypeError in strict mode
```

In sloppy mode both silently no-op instead of throwing, which is arguably
worse (errors report the wrong `name` with no signal why).

## Cause

The Mechanism 1 lockdown pass (`src/engine/hermes_runtime.cc`, the
`<lockdown>` JS blob) freezes the shared intrinsics graph, making
`Error.prototype.name`/`message`/`toString`/`constructor` non-writable data
properties. Per JS assignment semantics, a non-writable data property anywhere
on the prototype chain rejects plain assignment on any receiver that inherits
it — the classic "override mistake". `MyError.prototype` and error instances
inherit from the frozen `Error.prototype`, so the assignments above fail even
though the receivers themselves are extensible.

LLP 0013 names the SES shim's `lockdown()` as the reference semantics; SES
repairs exactly this via `enablePropertyOverrides` (accessor conversion on the
enabled properties before freezing). Ibex's lockdown lacked that repair.

## Resolution

In the lockdown blob, before the freeze walk, convert the SES-moderate error
family enablements into accessors whose setter shadows on the receiver:
`constructor`/`message`/`name` on every error prototype (`Error`, `EvalError`,
`RangeError`, `ReferenceError`, `SyntaxError`, `TypeError`, `URIError`,
`AggregateError` when present), plus `toString` on `Error.prototype`.

- Assignment on the frozen prototypes themselves still throws — now in sloppy
  mode too (setter throws unconditionally when the receiver is the prototype),
  matching SES; previously sloppy-mode assignment silently no-opped.
- The accessor functions are literal-object accessors (no `.prototype` own
  property) and are frozen eagerly, so hardening does not depend on either
  freeze walk (JS or the patch-0006 native `__exactDeepFreeze`) traversing
  accessor pairs.
- Displaced non-primitive values (the original `Error.prototype.toString`)
  are pushed into the freeze roots explicitly, since they leave the
  own-property graph the walks traverse.

Deliberately scoped to the error family; SES moderate's other enablements
(`%ObjectPrototype%.toString`, `%FunctionPrototype%.bind`, …) exhibit the same
override mistake but are left unrepaired until real package breakage motivates
each one (documented in LLP 0013 Mechanism 1).

Regression test: `lockdown_enables_error_prototype_overrides`
(`src/bin/ibex/engine/hermes.rs`) — covers class subclass, instance rename,
util.inherits-style legacy subclassing, prototype intactness/immutability, and
hardening of the installed accessors and the displaced `toString`. Verified
end to end against the dev-arming build alongside the pre-existing
`locked_baseline_rejects_prototype_and_contains_late_global_mutation`.
LLP 0013 Mechanism 1 updated in the same change; `ref-check` green.
