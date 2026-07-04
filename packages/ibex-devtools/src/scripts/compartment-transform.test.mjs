// @ref LLP 0013#mechanism-2 — unit tests for the per-package compartment
// free-global rewrite. These are the transform-half of the named red-team
// cases: "recover the real global" (free-identifier + globalThis rewrite),
// "dynamic-code escape" (direct-eval rewrite), and "sloppy-this escape" (strict
// emission, tested at the loader level). Run with: bun test.

import { expect, test } from 'bun:test';
import {
  rewriteFreeGlobals,
  packageOfModuleId,
  defaultCompartmentGlobals,
} from './transforms.mjs';

const REF = '__compartment';
const names = defaultCompartmentGlobals;

function rw(src) {
  return rewriteFreeGlobals(src, { compartmentRef: REF, globalNames: names });
}

test('free global reference is routed through the compartment', () => {
  expect(rw('process.env.SECRET')).toBe('__compartment.process.env.SECRET');
  expect(rw('fetch("/x")')).toBe('__compartment.fetch("/x")');
});

test('globalThis rewrites to the bare compartment ref', () => {
  expect(rw('globalThis.process')).toBe('__compartment.process');
  expect(rw('const g = globalThis;')).toBe('const g = __compartment;');
});

test('a shadowing parameter is left untouched', () => {
  const src = 'function f(process) { return process.env; }';
  expect(rw(src)).toBe(src);
});

test('a shadowing var/let/const is left untouched', () => {
  expect(rw('{ let process = 1; process; }')).toBe('{ let process = 1; process; }');
  expect(rw('var fetch = 2; fetch;')).toBe('var fetch = 2; fetch;');
});

test('free in outer scope, bound in inner scope — only the free one rewrites', () => {
  const src = 'process; function f(process) { return process; }';
  const out = rw(src);
  expect(out).toBe('__compartment.process; function f(process) { return process; }');
});

// ENG-22638 — scope analysis must model ESM import specifiers, top-level export
// declarations, and `with`-object bindings, or a package's own reference to such
// a name that collides with a compartment global is wrongly rewritten.
test('ESM import binding shadowing a global is left untouched', () => {
  const src = "import fetch from 'cross-fetch';\nexport function go(u) { return fetch(u); }";
  expect(rw(src)).toBe(src);
  const named = "import { Buffer } from 'safe-buffer';\nBuffer.from('x');";
  expect(rw(named)).toBe(named);
  const ns = "import * as process from 'node:process';\nprocess.cwd();";
  expect(rw(ns)).toBe(ns);
});

test('top-level export declaration binding shadowing a global is left untouched', () => {
  const c = 'export const Buffer = mk();\nBuffer.from(1);';
  expect(rw(c)).toBe(c);
  const cls = 'export class fetch {}\nnew fetch();';
  expect(rw(cls)).toBe(cls);
});

test('a name bound by a with-object is not rewritten inside the with body', () => {
  // Inside `with (o)`, `process` may be a property of `o`, so it must be left
  // alone; a free `process` outside the with body still rewrites.
  const src = 'process;\nwith (o) { process.x; }';
  const out = rw(src);
  expect(out).toBe('__compartment.process;\nwith (o) { process.x; }');
});

test('member property with the same name is not rewritten', () => {
  expect(rw('obj.process')).toBe('obj.process');
  expect(rw('a.b.fetch()')).toBe('a.b.fetch()');
});

test('object literal property KEY is not rewritten; VALUE reference is', () => {
  expect(rw('({ process: 1 })')).toBe('({ process: 1 })');
  expect(rw('({ x: process })')).toBe('({ x: __compartment.process })');
});

test('shorthand property expands to a compartment reference', () => {
  expect(rw('({ process })')).toBe('({ process: __compartment.process })');
});

test('direct eval becomes a compartment-bound evaluator (indirect semantics)', () => {
  expect(rw('eval("1+1")')).toBe('__compartment.eval("1+1")');
});

test('indirect eval reference (not a call) still routes through the compartment', () => {
  // `eval` is in the endowment set, so a bare reference routes through too.
  expect(rw('var e = eval;')).toBe('var e = __compartment.eval;');
});

test('shadowed eval is not rewritten', () => {
  const src = 'function f(eval) { return eval("x"); }';
  expect(rw(src)).toBe(src);
});

test('catch param shadows', () => {
  const src = 'try { x(); } catch (process) { process; }';
  expect(rw(src)).toBe(src);
});

test('named function expression name is visible inside its body', () => {
  // `fetch` here is the function's own name, not the global.
  const src = '(function fetch() { return fetch; })';
  expect(rw(src)).toBe(src);
});

test('require/module/exports are NOT routed (they are CJS wrapper params)', () => {
  const src = 'const x = require("y"); module.exports = x;';
  expect(rw(src)).toBe(src);
});

test('non-target identifiers are never touched', () => {
  const src = 'const x = foo + bar.baz(qux);';
  expect(rw(src)).toBe(src);
});

test('destructuring binding shadows', () => {
  const src = 'const { process } = deps; process.run();';
  expect(rw(src)).toBe(src);
});

test('for-of loop binding shadows', () => {
  const src = 'for (const fetch of list) { fetch(); }';
  expect(rw(src)).toBe(src);
});

test('multiple free references all rewrite', () => {
  const src = 'process.exit(); fetch(url); Buffer.from(x);';
  const out = rw(src);
  expect(out).toContain('__compartment.process.exit()');
  expect(out).toContain('__compartment.fetch(url)');
  expect(out).toContain('__compartment.Buffer.from(x)');
});

// --- packageOfModuleId ---

test('packageOfModuleId extracts the package from a node_modules path', () => {
  expect(packageOfModuleId('/app/node_modules/lodash/index.js')).toBe('lodash');
  expect(packageOfModuleId('/app/node_modules/@scope/pkg/lib/x.js')).toBe('@scope/pkg');
});

test('packageOfModuleId returns the deepest (nested) package', () => {
  expect(
    packageOfModuleId('/app/node_modules/a/node_modules/b/index.js'),
  ).toBe('b');
});

test('packageOfModuleId returns null for first-party code', () => {
  expect(packageOfModuleId('/app/src/index.js')).toBeNull();
  expect(packageOfModuleId(null)).toBeNull();
});
