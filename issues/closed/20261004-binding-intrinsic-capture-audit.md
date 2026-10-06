# Audit binding intrinsic capture under the required hardened-runtime posture

**Status:** Closed
**Systems:** Bindings, Runtime, Security
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-10-04
**Related:** LLP 0068 §3 Decision C
**Resolution:** Hid Headers handles and iterator state, made timer delivery private to the owning pump while borrowed adapters continue to refuse timer tasks, captured the optional abort timer at install, and recorded every remaining post-harden observation point below.

Decision C requires every embedder using the bindings door to evaluate
`ibex2::bindings::HARDEN_SOURCE` (or perform an equivalent freeze) before
application code. The `isTrusted`, brand-registry, and private-state guarantees
are specified only for that hardened runtime.

This issue collects intrinsic-capture findings that appear only when app code
can mutate an unhardened runtime. They should be evaluated against the required
bootstrap order and fixed when they cross the hardened boundary; they should
not be repaired one by one to create a second, unsupported unhardened security
posture.

## Audit result

The audit used the required order: install bindings, optionally install the
trusted prelude and capture intrinsics, harden, then run application code.
"Reachable" below means that application code can cause the site to run after
harden; it does not by itself mean that private host authority is reachable.

| Site | Reachable post-harden? | Fix or reason no hardened-boundary escape remains |
| --- | --- | --- |
| `harden.js` | No | It runs before application code and captures the descriptor and freeze operations it uses. |
| `domexception.js` | Yes, for Web-IDL string conversion | The conversions are the public API's specified observation point and expose no private handle. |
| `timers.js` | Yes | Removed the global timer-dispatch helper, retained it only on the adapter for the owning pump, kept borrowed `deliver_one` limited to settlements/events, and invoke callbacks with captured `Reflect.apply`. |
| `intl_case.js` | Yes, for public coercion and locale iteration | These are specified input observations; native hooks and primordials are captured before hardening. |
| `sqlite.js` | Yes, for row/result inspection | The raw host object and owner handle stay closure-private; `.then` is read only from the host-created internal promise. |
| `abort.js` | Yes | Captured the optional timer function at install so an application cannot add one later; signals, algorithms, and event hooks remain in private weak maps/closures. |
| `headers.js` | Yes | Moved header handles and iterator state into private weak maps; forged receivers and iterators can no longer select native rows. Required initializer iteration and callback calls remain observable. |
| `url.js` | Yes, for public string conversion | Conversion is required by the API; URL state and native parsing hooks remain private. |
| `events.js` | Yes, for listeners, accessors, and abort callbacks | Those are application dispatch boundaries. Trusted-event and listener state uses captured primordials plus private weak maps/null-prototype records. An app-added `AbortSignal` has no private subscribe hook. |
| `websocket.js` | Yes, for protocols, payloads, and callbacks | These are public inputs/callbacks; socket handles and native hooks remain private. Close codes now also cross checked integer conversion. |
| `fetch.js` | Yes, for request/init/body inputs | Required input hooks may run, but raw response promises, native handles, and hooks stay private; promise chaining is on a host-created promise before exposure. |
| `blob.js` | Yes, for public parts and coercion | Required input iteration/coercion affects only app-supplied values; bytes and brand state remain private. |
| `structured_clone.js` | Yes, for own properties and transfer iteration | Those observations are the clone API contract; cloning state, brands, and native hooks remain private. |
| `crypto.js` | Yes, for algorithm/data inputs | Required dictionary/coercion hooks may run; key material uses private native owners and internal-slot getters. |
| `intl_number_format.js` | Yes, for options and values | Intl-required observations remain; formatter owners and native hooks are private. Native part counts are validated before integer conversion. |
| `intl_datetime.js` | Yes, for options and values | Intl-required observations remain; formatter owners and native hooks are private. |
| `install.cc` host functions | Yes | Error/Promise/Object constructors are locked by hardening; promise methods are read only from host-created internal promises. Numeric arguments now validate type, finiteness, integrality, and range before conversion. Error-report coercion is caught, has a fallback, and conveys no private authority. |
| Intl/ICU C++ hosts | Yes | JavaScript errors use locked constructors, owners arrive only through private binding state, and the remaining values are native outputs. Part counts are checked before conversion. |

## Verification

Regression coverage now compares the exact captured timer-dispatch identity
against post-harden properties, proves the owning pump still fires timers and
the borrowed adapter refuses them, attempts forged Headers receiver/iterator
access, and attempts late installation of `setTimeout` for
`AbortSignal.timeout`. Existing WPT suites continue to cover required
iterators, coercions, callbacks, promise behavior, and event dispatch. The D5
freeze-budget test remains below its 2 ms limit.
