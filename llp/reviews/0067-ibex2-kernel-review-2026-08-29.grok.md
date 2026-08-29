# Review of the Ibex 2 kernel work, `fdc20c2a6..fa706afa8` — xAI Grok family

**Reviewer family:** xAI Grok
**Provider / runtime:** grok 1.0.5 (5115b46bc909) / `grok-4.6`
**Model / effort:** requested `grok-4.6` / `xhigh`
**Date:** 2026-08-29
**Target:** commits `fdc20c2a6..fa706afa8` — `crates/ibex2`, `scripts/metrics.mjs`, judged against LLP 0067
**Method:** Headless CLI session (`--permission-mode bypassPermissions`, web search off) in a detached worktree at `fa706afa8` with the engine artifacts linked in; the reviewer built the binary and ran its own probes
**Scope:** Adversarial code review. Priorities given: grant correctness, FFI soundness, spec conformance, tests that cannot fail their claims.

## Disposition

Every finding was reproduced by the author before being acted on — the
reviewer's own probes, re-run — and each fix carries the reproduction as a
test. Nothing the reviewer confirmed turned out to be wrong.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | HIGH | `__ibex2_response_field` on the global read any module's response by integer handle | **Fixed** (`d0e0adddb`) — Response objects over WeakMap handles; the factory is the script's value and never a global; every binding's helpers removed from the global; R5 exact against the engine baseline |
| 2 | HIGH | A directory named `react` nested in another package held `[react]` | **Fixed** (`117bce153`) — package identity is the install `bind` resolves; a nested copy is granted by directory or not at all |
| 3 | HIGH | ES modules ran sloppy | **Fixed** — `"use strict"` prepended to a lowered module's factory; CommonJS left as written |
| 4 | MEDIUM | `import /*(*/(` not lowered | **Fixed** — argument range from the parser's spans |
| 5 | MEDIUM | Symbol-keyed values not frozen | **Fixed** — the walk takes names and symbols; a whole-graph test reports anything reachable and open |
| 6 | MEDIUM | Four tests that could not fail their claims | **Fixed** — R1/R5 tests compare the global's added names to `ALLOWED_GLOBALS` exactly; the return-this test runs the shipping bindings and checks the accessor is gone; the key test builds two compilers and compares keys |

Sound findings the reviewer listed are recorded below as it wrote them; the
one it called out of scope — `fs` following a symlink out of a granted prefix
— was in scope after all (LLP 0067 §3 said a symlink could not move a grant
between check and use, and one could) and was fixed from Codex's
reproduction in the same commit as finding 2.

---

# Adversarial review: Ibex 2 (`fdc20c2a6..HEAD`)

Judged against LLP 0067. Reproduced on `target/release/ibex2` (`cargo build -p ibex2 --features hermes --release`).

## Findings

| # | Severity | Finding | Evidence |
|---|---|---|---|
| 1 | HIGH | Ungranted code can read any in-flight `fetch` response. `__ibex2_response_field` is an ambient accessor over a process-wide integer handle table. | `ibex2 run` of a two-module program: granted module `fetch`es; ungranted module reads `SECRET_BODY` via `__ibex2_response_field(1, 4)`. `Function("return this")` still sees the accessor. |
| 2 | HIGH | `[react]` is inherited by any file whose path contains `node_modules/react/`, including a dependency’s nested fake. Identity from the path, never `package.json`, makes folder-name impersonation the grant key. | Dummy top-level `react` plus `evil/node_modules/react`: `evil` itself is denied; the nested impostor’s `fetch` is allowed. |
| 3 | HIGH | ES modules run sloppy. Lowering wraps in a non-strict function and never inserts `"use strict"`, so ESM’s automatic strict mode is lost. | `undeclared = 2` creates `globalThis.undeclared`; `010` evaluates to `8`; `arguments.callee` is a function. Real ESM throws on all three. Not listed in LLP 0064 §3. |
| 4 | MEDIUM | `import()` is not lowered when a comment before the arguments contains `(`. Valid ESM then hits Hermes as `import(...)` and fails to compile. | `export const p = import /*(*/('./x.js')` → `Compiling JS failed: … invalid expression`. |
| 5 | MEDIUM | R4 does not walk symbol-keyed values. `Date.prototype[Symbol.toPrimitive]` (and the RegExp `Symbol.match` / `split` / … functions, `Function.prototype[Symbol.hasInstance]`) stay extensible. | After the freeze: `Object.isFrozen(Date.prototype[Symbol.toPrimitive]) === false`; `f.pwn = 1` and `defineProperty(f, 'length', {value: 9})` both take. |
| 6 | MEDIUM | Several tests cannot fail the claims in their names/comments. | `the_return_this_fast_path_is_open_and_yields_no_authority` only looks for `fetch` on the global it just deleted; `no_capability_is_reachable_from_the_global_object` does not list `__ibex2_response_field`; `the_linked_engine_is_part_of_every_key` never compares keys. |

---

## 1. Ambient response handles — capability bypass of R1

**Expected (LLP 0067 R1 / §3):** nothing capability-bearing is on `globalThis`. A module that was not handed `fetch` has no expression that evaluates to network authority. The handle *is* the authority, so it must not be a guessable integer behind a global function.

**Observed:**

```
net: handle=1
thief: 1:http://127.0.0.1:<port>/secret:SECRET_BODY
```

The ungranted module never called `fetch`. It scanned `1..32` and consumed the body (field 4). After boot, `({}).constructor.constructor('return this')()` still has `typeof g.__ibex2_response_field === "function"`.

**Reproduction:**

```bash
# local HTTP server that replies SECRET_BODY, then:
mkdir -p /tmp/ibex2-steal && cd /tmp/ibex2-steal
printf '%s\n' "require('./net.js'); require('./thief.js');" > index.js
printf '%s\n' "fetch('http://127.0.0.1:PORT/secret').then(h => console.log('net: handle=' + h));" > net.js
printf '%s\n' 'setTimeout(function () {
  for (var i = 1; i < 32; i++) {
    try {
      var url = __ibex2_response_field(i, 2);
      var body = __ibex2_text_decode(__ibex2_response_field(i, 4));
      console.log("thief: " + i + ":" + url + ":" + body);
    } catch (e) {}
  }
}, 50);' > thief.js
printf '%s\n' '[*]' '[./net.js]' 'net.fetch http://127.0.0.1:PORT' > grants.txt
target/release/ibex2 run ./index.js --root . --grants grants.txt --budget-ms 5000 --no-compile
```

**Cause:**

- `hermes_shim.cc:665-666` — per-module `fetch` is the raw async binding; it resolves to `HostValue::Number(handle)` (`boundary_abi.rs:720-721`, `task.rs:178-186`, handles from 1).
- `hermes_shim.cc:897-930` — `__ibex2_response_field` is installed on the **global** object in the ungated stdlib, with an explicit comment that handles were previously unreachable from the per-module loader. The fix for “cannot read my own response” was to put the accessor on `globalThis`, not to wrap `fetch` in a `Response` object.
- `ibex2_response_field` (`boundary_abi.rs:523-578`) does not consult a `GrantSet`. Any live handle in the runtime-wide map is readable and field 4 **consumes** the body.
- R5 cannot catch this. `ALLOWED_GLOBALS` lists `__ibex2_response_field` (`loader.rs:720-737`), and `bin/ibex2.rs:423-427` also allows **every** `__ibex2_*` name plus every uppercase intrinsic. The boot assertion is not the check LLP 0067 R5 states.

LLP 0062’s accepted `Function("return this")` hole is no longer harmless: reaching the global now yields this accessor.

**Fix:** keep the handle in a JS `WeakMap` on a `Response` instance created in the fetch binding (same shape as `headers.js` / `url.js`). Do not put `__ibex2_response_field` on `globalThis` (or delete it after the wrapper closes over it, before harden). Reject integer handles from JS; the token must be unforgeable. Pin with a test that is the reproduction above: ungranted `./thief.js` must not observe the granted module’s URL or body. Also extend `the_return_this_fast_path_is_open_and_yields_no_authority` to assert `typeof g.__ibex2_response_field === "undefined"` (or that calling it cannot see another module’s response).

---

## 2. Nested `node_modules/<name>/` impersonates a package grant

**Expected (LLP 0067 §2, LLP 0065 §4.2):** `[react]` covers every *installed copy of that package*. A package must not obtain another’s authority by declaring `"name": "react"`. A folder that is not that install must not obtain it either.

**Observed:**

```
evil-self: denied: net.fetch
nested-fake-react: ALLOWED
```

`evil/index.js` is denied. `evil/node_modules/react/index.js` — `package.json` name `"not-react"` — is allowed, because `package_of` returns `"react"` from the path. `require('react')` from `evil` resolves to the nested impostor first (Node’s own walk).

**Reproduction:**

```text
node_modules/react/{package.json,index.js}          # real, installed so bind succeeds
node_modules/evil/index.js                          # fetch → denied; require('react').probe()
node_modules/evil/node_modules/react/index.js       # fetch → allowed
grants: [*] / [react] net.fetch http://127.0.0.1:PORT
```

**Cause:** `package_of` (`loader.rs:105-122`) takes the innermost `node_modules/<name>/` segment and never looks at what `bind` resolved. `for_module` (`loader.rs:162-177`) then applies `per_package[name]` to **every** such path. `bind` (`loader.rs:195-228`) only checks that `root/node_modules/<name>` exists; for an in-place install it `continue`s without recording the real directory. Nested copies of a *fake* `react` therefore share `[react]`.

That is the inverse of the package.json-spoofing case the spec closed. Identity-from-path makes the **directory name** the grant key.

**Fix:** after `bind`, a package grant should apply only to paths under the canonical install(s) actually resolved (`root/node_modules/<name>` and, for pnpm, the store directory that symlink points at). A nested `evil/node_modules/react` that does not canonicalize to that install must not match. Real nested copies of the same package, if they still matter, have to be found by bind (or granted by directory), not by string-matching `node_modules/react`. Pin with the reproduction: nested impostor denied; `./node_modules/react/index.js` still allowed.

---

## 3. ESM lowering drops automatic strict mode

**Expected:** ES modules are always strict. LLP 0064 lists the remaining silent divergences (named-import snapshot, CJS cycles, TLA). Strict mode is not among them. “A module’s own code reaches the engine exactly as written” does not license changing the mode the engine runs it in.

**Observed:**

```
SLOPPY undeclared=2
callee function
octal 8
```

**Reproduction:**

```js
// index.js  (ESM: has `export`)
export const x = 1;
try { undeclared = 2; console.log('SLOPPY', globalThis.undeclared); }
catch (e) { console.log('STRICT', e.constructor.name); }
```

```bash
ibex2 run ./index.js --root . --no-compile
# prints: SLOPPY 2
# a browser / Node ESM prints: STRICT ReferenceError
```

**Cause:** `wrap` (`loader.rs:627-632`) is `(function (module, exports, require, fetch, fs, process, __ibex2_meta) {\n<source>\n})` with no `"use strict"`. `esm::lower` does not insert one either. CJS is sloppy by spec; ESM is not. The factory is also how every lowered Exact module will run.

**Fix:** for a module that `is_module` / that `lower` rewrote, prepend `"use strict";\n` to the factory body (not to CJS pass-through). Do **not** strict-wrap CJS. Pin with the three cases above plus `with (obj) {}` as a SyntaxError in ESM.

---

## 4. `import /*(*/(` is not lowered

**Expected (LLP 0064 §7):** Oxc parses `import()`; the transform rewrites every occurrence so Hermes never sees it.

**Observed:** `export const p = import /*(*/('./x.js');` → `Compiling JS failed: 2:43:invalid expression`.

**Cause:** `render` (`esm.rs:303-310`) takes the argument as “first `(` in the span … last character.” A comment containing `(` between `import` and the real argument list makes the first `(` the comment, so the replacement is garbage and Hermes still sees `import`. Nested `import(new URL(..., import.meta.url))` is handled; this form is not.

**Fix:** use the parser’s argument span (`ImportExpression::source.span()`, and the optional options argument), not `find('(')`. Pin with `import /*(*/('./x.js')` and `import /* ) */ ('./x.js')`.

---

## 5. Freeze does not walk symbol-keyed values (R4)

**Expected (LLP 0067 R4):** every object reachable from the locked global bindings is frozen.

**Observed:** after `harden.js`, `Date.prototype[Symbol.toPrimitive]` is extensible and not frozen; assigning `f.pwn = 1` and redefining `length` both succeed. Same for `RegExp.prototype[Symbol.match]` / `split` / `search` / `replace` / `matchAll` and `Function.prototype[Symbol.hasInstance]`. String-named aliases (`Array.prototype.values` === `@@iterator`) *are* frozen, which is why the existing tests pass.

**Cause:** `harden.js:52-61` uses `Object.getOwnPropertyNames` only, then `Object.freeze(obj)`. Freeze makes the **symbol property** on the prototype non-writable (so you cannot replace `Date.prototype[Symbol.toPrimitive]`), but the **function object** behind it is never queued.

**Fix:** also walk `Object.getOwnPropertySymbols`. Pin `Object.isFrozen(Date.prototype[Symbol.toPrimitive])` and a failed `f.pwn = 1` under strict.

This is integrity, not ambient authority. It is still a false R4 claim, and `intrinsics_are_frozen_and_global_bindings_are_locked` cannot fail it.

---

## 6. Tests that cannot fail their claims

**`the_return_this_fast_path_is_open_and_yields_no_authority`** (`hermes_tests.rs:987-1016`) deletes `__ibex2_fetch`, then asserts no global name contains `fetch`. On the shipping boot path `__ibex2_response_field` remains, and the same `Function("return this")` sees it. The test would still pass with finding 1 in place.

**`no_capability_is_reachable_from_the_global_object`** (`tests/loader.rs:132-149`) only forbids `fetch`, `WebSocket`, `localStorage`, `process`. It does not harden, does not go through `bin/ibex2.rs` R5, and does not mention `__ibex2_response_field`.

**`the_linked_engine_is_part_of_every_key`** (`bytecode.rs:647-650`) only checks that `Compiler::linked_engine()` looks like `sha256-…` or `no-linked-engine`. It never builds two compilers with different linked digests and compares `key()`. (The receipt-binding test next to it *does* compare keys.)

**R5 in the binary** (`bin/ibex2.rs:423-427`) is not “name ∉ `ALLOWED_GLOBALS`”. It also permits every `__ibex2_*` and every uppercase name (`HermesInternal`, `DebuggerInternal`, `WebSocket` if someone installed it). That is why finding 1 survives the boot assertion LLP 0067 R5 describes.

---

## What was checked and found sound

**Grants / resolution**

- Most-specific section, nothing combined; empty section does not inherit `[*]`; `react` vs `react-dom` vs `@w/ui` vs `@w/ui-extra`.
- `bind` refuses uninstalled names; workspace symlink `node_modules/@w/ui` → `packages/ui` is bound to `./packages/ui/` and is one file / one grant set from both spellings (`two_spellings_of_one_file_are_one_module_with_one_grant_set`).
- Containment on both resolver arms via `contain` (canonical path); symlink-out and relative-symlink-out tests hold; query strings are stripped before identity.
- `--root` is required for bare specifiers; not inferred.
- `process.env` is a snapshot of granted names only; ungranted names are absent; per-module. The object is **not** frozen (shim comment at `hermes_shim.cc:697` is false: you can add `INJECTED`). That is not OS-env authority — each module still has its own object, and extra keys are not `std::env::var`.
- `fs`: lexical `..` is normalized before `admit`; two-path ops need read on source and write on dest; prefixes are whole components. Grants are cloned into the async worker (`clone_grants` in `ibex2_async_begin`). Symlink-follow on `open` is the kernel’s, which LLP 0067 §6 (“whatever the platform hands back”) does not claim to close.

**FFI / loop**

- Completion queue: `complete` then `task_finished`; `wait` holds the mutex; a completion that arrives between `is_idle` and `wait` is visible because `in_flight` cannot hit 0 before the item is queued. Timer deadlines are the wait timeout, not a second condvar. Spurious wakeups just loop into `pump`.
- `jsi::Value` registry: registered before eval (cycles); re-read `module.exports` after (primitives work). Member destruction order is `modules` then `runtime`.
- Bytecode buffers are `OwnedBytes`; the lifetime bug has a pin test.
- `to_abi` `owned.reserve(count)` keeps string pointers valid for the call; async ops copy to `HostValue` before the thread starts.
- Teardown: workers hold an `Arc<RuntimeState>` and do not touch JSI.

**Correctness (other than 3–4)**

- Nested `import()` / `import.meta` inside `export function` / default export / `import(new URL(..., import.meta.url))` lower as specified; JSON modules are `JSON.parse` of a string literal (`__proto__` is an own property); `module.exports = 'text'` round-trips.
- URL parse/setters: IPv6 host/hostname, default-port nulling, `hostname = 'example.com:8080'` no-op, `host = 'h2:99'`, special→non-special protocol refusal all matched Node in this run. WPT `urltestdata.json` is `#[ignore]` (report-only).
- `Compiler::for_run` hashes nothing; `IBEX2_LINKED_ENGINE_DIGEST` is baked from the linked archive in `build.rs`; stale `#engine` manifests are refused under `--precompiled` and ignored otherwise. Bindings are compiled with that engine’s `hermesc` at link time.
- `queueMicrotask` is `Promise.resolve().then`; order with timers matches the pin test.

---

VERDICT: Ship-blocking R1 hole (`__ibex2_response_field` plus integer handles) and a path-identity grant spoof (`node_modules/<granted-name>/` inside another package); ESM also silently runs sloppy.
