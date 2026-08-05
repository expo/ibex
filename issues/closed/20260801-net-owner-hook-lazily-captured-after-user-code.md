# `__exactNetOwner` is captured lazily, after user code — the net/dgram/http owner preflight is app-controllable

**Status:** Closed — resolved 2026-08-05
**Severity:** P2 — integrity/defense-in-depth defect and a false source comment;
**not** a privilege escalation (see blast radius). Former LLP 0045 step-0
blocker.
**Systems:** Builtins (net/dgram/http), Engine (JSI global install), Conformance
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Revised:** 2026-08-05 (option 1 landed atomically with hook-alias
normalization and a pre-require replacement regression)
**Related:** LLP 0045 step 0 (SSA-alias analyzer must credit the guarded ternary
as the authenticated hook); LLP 0013 Mechanism 2 (compartment membrane);
issues/20260801-network-terminal-provenance-program.md

## Resolution (2026-08-05)

Option 1 landed together with the analyzer-visible source normalization:

- `net.js`, `dgram.js`, and both `http.js` owner aliases now capture the exact
  `globalThis.__exact*Owner` property in a `const` binding.
- The POSIX net install (`hermes_runtime_net.cc:967-970`), HTTP install
  (`hermes_runtime_http.cc:347-350`), and Windows platform shim
  (`hermes_runtime_platform_windows.cc:2870-2873`) immediately seal their host
  function data property with `writable:false` and `configurable:false`.
- A loaded-Hermes regression attempts assignment, deletion, and
  `Object.defineProperty` replacement before the first `require('net')`, then
  constructs and destroys a socket and invokes both real owner hosts. The
  sentinel remains uncalled.
- Fresh Apple and Windows recipe catalogs each reduce network Lane B from 338
  to 292: **46 cells cleared**, exactly the ticket estimate. Across the whole
  network route-evidence diff, 104 unique cells change.

The captured value can no longer be attacker-chosen through the root-global
property, the comments now describe the actual immutable binding, and the
regression exercises the original reproducer timing. The done-when bar is met.

## Original claim under test (historical)

`src/builtins/net.js:219-222`:

```js
// Capture the native owner boundary before application code can replace the
// writable global binding. The host returns an opaque runtime/principal stamp;
// `assert` optionally checks an adopted native handle under the same owner.
var _netOwnerHost = typeof __exactNetOwner === 'function' ? __exactNetOwner : null;
```

The comment asserts the capture happens before application code runs.
`src/builtins/http.js:59-67` and `src/builtins/dgram.js:11` carry the same
pattern and the same claim.

## Verdict: the comment is false. Disproved empirically.

`__exactNetOwner` is installed with a plain JSI `setProperty`
(`src/engine/hermes_runtime_net.cc:967`), so it is writable, enumerable and
configurable. Lockdown's freeze walk covers the *intrinsics* graph
(`hermes_runtime.cc`, `roots = [Object, Array, ... ]`); `globalThis` itself is
never frozen and `__exactNetOwner` is never converted to a non-configurable
descriptor. Builtins are evaluated lazily on **first require**, which is after
the file program starts. The real order is: install hook → lockdown → user code
runs → first `require('net')` → capture.

All measurements below with
`cargo build --bin ibex --features standard,unadvertised-dev-arming`,
`ibex run` on a file program.

**1. Plain replacement — sentinel fires.**

```js
globalThis.__exactNetOwner = function sentinel(action){ fired.push(action); return 1; };
var net = require('net');
var s = new net.Socket(); s.destroy();
```

```
installed; readback typeof = function name = sentinel
SENTINEL FIRED new
SENTINEL FIRED assert     (x105)
socket constructed
```

Same for `dgram` (9 calls through `createSocket`/`close`) and for `http`
(`createServer` drives 10 `__exactNetOwner` calls; `__exactHttpOwner` is not
reached until `listen`).

**2. Accessor variant — the two reads of the ternary can be made to disagree.**

```js
Object.defineProperty(globalThis, '__exactNetOwner', {
  configurable: true,
  get: function () { reads++; return reads === 1 ? real : function attacker(a){ return 1; }; }
});
var net = require('net');
```

```
ACCESSOR READ #1
ACCESSOR READ #2
accessor reads during net evaluation = 2
```

Read #1 answers `typeof __exactNetOwner === 'function'` and read #2 supplies
the captured value. The guard therefore proves nothing about what was
captured.

**3. Deletion is fail-closed (the one good news).**

```js
delete globalThis.__exactNetOwner;   // returns true
var net = require('net'); new net.Socket();
// threw: net.Socket owner stamp is unavailable
```

**4. The unmodified hook does enforce.**

```
real stamp = 3347562452842515
forged stamp refused: __exactNetOwner: stamp belongs to another runtime or principal
```

## Blast radius — honest characterization

The JS preflight is **not** the authority boundary, and neutralizing it grants
no native authority. Verified both statically and by measurement:

- Every payload-bearing native net entry point goes through
  `requireSocketHandle` (`src/engine/hermes_runtime_net.cc:783`), which
  independently checks `entry.runtimeNonce != exactCurrentRuntimeNonce()` and
  `entry.owner != currentPrincipalId()` (→ `Permission denied`), plus typed
  connect/listen lease re-authorization. This matches the claim in
  `src/builtins/http.js:59-62` that payload-bearing hosts retain their own
  native owner checks.
- Measured with the preflight fully neutralized: `new net.Socket({fd: 3})`
  constructs (the JS-side adoption check is gone) but the fabricated handle is
  inert — `__exactTcpWrite(3, "x")` → `__exactTcpWrite: invalid handle`, and
  `__exactTcpConnect("127.0.0.1", 9)` → `Permission denied`.
- The **root file program is not compartmentalized**: `typeof
  globalThis.__exactTcpConnect === 'function'` from a plain `ibex run` script.
  So for the root principal the preflight was never a boundary — it can call
  the natives directly (and is refused by policy, as above).
- **Package code cannot mount this attack.** The compartment membrane
  (`hermes_runtime.cc:4124-4160`) withholds every `__exact*`/`__ibex*` name
  from a compartment's `get`/`has` traps, and its `set`/`defineProperty` traps
  write to the package-local target, never the real global. *(Static reading
  only — a policy-admitted package fixture was not run; the pinned example
  under `examples/llp0013-supply-chain/` does not currently start.)*

What is actually lost is a cross-package integrity invariant: because `net.js`
is a single shared module instance, a root program that replaces the global
strips the per-socket owner binding for **every** principal in the process —
the check that stops package A from operating package B's socket object. The
app composing those packages could already reach the natives directly, so the
marginal authority is nil; the loss is defense-in-depth plus a source comment
that overstates the guarantee.

## Consequence for LLP 0045

Step 0 wants the SSA-alias analyzer to credit
`typeof __exactNetOwner === 'function' ? __exactNetOwner : null` as resolving
to the authenticated native hook. Measurement 2 shows the two reads can be
made to disagree, and measurements 1/3 show the binding is replaceable and
deletable at the moment of capture. **Step 0's premise does not survive as
written.** Either the capture must be made genuinely unforgeable first, or the
analyzer rule must be justified on something other than the guarded ternary.

## Options considered (historical)

1. **Make the install non-configurable/non-writable.** Replace the plain
   `setProperty` at `hermes_runtime_net.cc:967` (and the Windows shim at
   `hermes_runtime_platform_windows.cc:2840`) with a
   `defineProperty`-equivalent that pins `writable:false, configurable:false`.
   Cheapest fix that makes the existing comments true and makes the analyzer
   rule sound. Needs a root-global-disposition restamp; check whether any
   trusted bootstrap path deletes or replaces the binding first.
2. **Capture eagerly in trusted bootstrap** and hand the builtins a closed-over
   reference instead of a global read. Removes the read from the analyzer's
   problem entirely, but changes the builtin module shape.
3. **Delete the globals after the builtins have captured them** — impossible
   while capture is lazy; would require (2).
4. **Do nothing and correct the comments.** Honest, but leaves LLP 0045 step 0
   without its premise.

Option 1 plus the analyzer rule is the recommended shape; it is the only one
that makes the *existing* source comments true.

**Done-when result:** met on 2026-08-05. The captured value provably cannot be
attacker-chosen through the sealed global property, and the regression replaces
the global before the first `require('net')` and asserts the real host still
runs.
