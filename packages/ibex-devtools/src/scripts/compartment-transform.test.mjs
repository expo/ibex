// @ref LLP 0013#mechanism-2 — unit tests for the per-package compartment
// free-global rewrite. These are the transform-half of the named red-team
// cases: "recover the real global" (free-identifier + globalThis rewrite),
// "dynamic-code escape" (direct-eval rewrite), and "sloppy-this escape" (strict
// emission, tested at the loader level). Run with: bun test.

import { expect, test } from 'bun:test';
import { rolldown } from 'rolldown';
import {
  rewriteFreeGlobals,
  packageOfModuleId,
  defaultCompartmentGlobals,
  createCompartmentGlobalsPlugin,
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
  expect(rw('window.process')).toBe('__compartment.window.process');
});

test('the authored registry name routes through the package-scoped registry', () => {
  expect(rw('__compartments["victim@1.0.0"]')).toBe(
    '__compartment.__compartments["victim@1.0.0"]',
  );
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

// --- hoistRef (ENG-22644) ---
// The plugin hoists the registry lookup once per module (`var __ibexC_* =
// __compartments["pkg"];`) so each access pays one Proxy trap hop, not two.

const HOIST_REF = '__compartments["pkg@1.0.0"]';

function rwHoist(src) {
  return rewriteFreeGlobals(src, {
    compartmentRef: HOIST_REF,
    globalNames: names,
    hoistRef: true,
  });
}

test('hoistRef declares the compartment binding once and routes accesses through it', () => {
  const out = rwHoist('process.exit();\nfetch(url);');
  const m = out.match(/^var (__ibexC_\w+) = __compartments\["pkg@1\.0\.0"\];\n/);
  expect(m).not.toBeNull();
  const ref = m[1];
  expect(out).toContain(`${ref}.process.exit()`);
  expect(out).toContain(`${ref}.fetch(url)`);
  // The registry expression appears exactly once — in the hoisted declaration.
  expect(out.split('__compartments').length).toBe(2);
});

test('hoistRef inserts after the directive prologue so "use strict" survives', () => {
  const out = rwHoist('"use strict";\nprocess.exit();');
  expect(out.startsWith('"use strict";')).toBe(true);
  const m = out.match(/^"use strict";\nvar (__ibexC_\w+) = __compartments\["pkg@1\.0\.0"\];/);
  expect(m).not.toBeNull();
  expect(out).toContain(`${m[1]}.process.exit()`);
});

test('hoistRef with no rewrites leaves the module byte-identical (no stray declaration)', () => {
  const src = 'const x = foo + bar.baz(qux);';
  expect(rwHoist(src)).toBe(src);
});

test('hoistRef binding name avoids collisions with module source text', () => {
  const clean = rwHoist('process.x;');
  const ref = clean.match(/^var (__ibexC_\w+) =/)[1];
  // A module that already mentions the derived name forces a suffixed one.
  const out = rwHoist(`var ${ref} = 1;\nprocess.x;`);
  const m = out.match(/var (__ibexC_\w+) = __compartments\["pkg@1\.0\.0"\];/);
  expect(m).not.toBeNull();
  expect(m[1]).not.toBe(ref);
});

test('hoistRef routes globalThis to the hoisted binding', () => {
  const out = rwHoist('const g = globalThis;');
  const m = out.match(/^var (__ibexC_\w+) =/);
  expect(out).toContain(`const g = ${m[1]};`);
});

// --- trusted Rolldown scope binding (ENG-24463) ---

function generatedScopeSpecifier(transformed) {
  const match = transformed.match(/import\s+[A-Za-z_$][\w$]*\s+from\s+("[^"]+");/);
  expect(match).not.toBeNull();
  return JSON.parse(match[1]);
}

test('the generated scope import is exact-importer-bound and preserves directives', () => {
  const victimId = '/app/node_modules/victim/index.js';
  const attackerId = '/app/node_modules/attacker/index.js';
  const plugin = createCompartmentGlobalsPlugin({
    resolvePackage(id) {
      if (id === victimId) return 'victim@1.0.0';
      if (id === attackerId) return 'attacker@1.0.0';
      return null;
    },
  });
  const transformed = plugin.transform('"use strict";\nprocess.env.SECRET;', victimId).code;
  expect(transformed.startsWith('"use strict";\nimport ')).toBe(true);
  const scopeSpecifier = generatedScopeSpecifier(transformed);
  const internalId = plugin.resolveId(scopeSpecifier, victimId);
  expect(internalId.startsWith('\0ibex:compartment-scope/')).toBe(true);
  expect(plugin.load(internalId)).toContain('["victim@1.0.0"]');
  const rendered = plugin.renderChunk('#!/usr/bin/env ibex\nrun();', {
    modules: { [internalId]: {} },
  }).code;
  expect(rendered.startsWith('#!/usr/bin/env ibex\n"use strict";\nrun();')).toBe(true);
  expect(() => plugin.resolveId(scopeSpecifier, attackerId)).toThrow(
    /Refusing Ibex compartment scope import/,
  );
  expect(() =>
    plugin.resolveId('ibex:compartment-scope/source-authored-forgery', attackerId),
  ).toThrow(/Refusing unrecognized Ibex compartment scope import/);
});

test('hashbang stays first when the trusted scope import is injected', () => {
  const id = '/app/node_modules/tool/bin.js';
  const plugin = createCompartmentGlobalsPlugin({
    resolvePackage(moduleId) {
      return moduleId === id ? 'tool@1.0.0' : null;
    },
  });
  const transformed = plugin.transform(
    '#!/usr/bin/env ibex\n"use strict";\nprocess.exit();',
    id,
  ).code;
  expect(transformed.startsWith('#!/usr/bin/env ibex\n"use strict";\nimport ')).toBe(true);
});

test('arbitrary free names remain delegated to the native Domain boundary', () => {
  const id = '/app/node_modules/evil/index.js';
  const plugin = createCompartmentGlobalsPlugin({
    resolvePackage(moduleId) {
      return moduleId === id ? 'evil@1.0.0' : null;
    },
  });
  // The build-time pass intentionally routes a finite high-risk set. It is
  // defense in depth, not an independent boundary for a post-arming/session
  // name such as `apiKey`; production isolation comes from the package Domain.
  // Routing every lexically free name in the flat transform is ENG-24527.
  expect(plugin.transform('module.exports = () => apiKey;', id)).toBeNull();
});

test('real Rolldown output cannot use raw or shadowed registry names to select another package', async () => {
  const entryId = '/virtual/app.js';
  const rawId = '/virtual/node_modules/evil/raw.js';
  const shadowId = '/virtual/node_modules/evil/shadow.js';
  const plainId = '/virtual/node_modules/evil/plain.js';
  const modules = new Map([
    [
      entryId,
      `const raw = require("raw");
const shadow = require("shadow");
const plain = require("plain");
globalThis.__ibexCompartmentTestResult = { raw: raw(), shadow: shadow(), plain: plain() };`,
    ],
    [
      rawId,
      `module.exports = function () {
  return {
    identifier: __compartments["victim@9.0.0"],
    alias: globalThis.__compartments["victim@9.0.0"],
    own: __compartments["evil@1.0.0"] === globalThis,
    marker: process.marker
  };
};`,
    ],
    [
      shadowId,
      `var __compartments = {
  "evil@1.0.0": { process: { marker: "FORGED" } }
};
module.exports = function () { return process.marker; };`,
    ],
    [
      plainId,
      `module.exports = function () {
  return { sloppyThis: (function () { return this; })(), apiKey: apiKey };
};`,
    ],
  ]);
  const fixturePlugin = {
    name: 'compartment-test-fixtures',
    resolveId(source) {
      if (modules.has(source)) return source;
      if (source === 'raw') return rawId;
      if (source === 'shadow') return shadowId;
      if (source === 'plain') return plainId;
      return null;
    },
    load(id) {
      return modules.get(id) ?? null;
    },
  };
  const compartmentPlugin = createCompartmentGlobalsPlugin({
    resolvePackage(id) {
      return id === rawId || id === shadowId || id === plainId ? 'evil@1.0.0' : null;
    },
  });
  const bundle = await rolldown({
    input: entryId,
    treeshake: false,
    plugins: [fixturePlugin, compartmentPlugin],
  });
  const generated = await bundle.generate({ format: 'cjs' });
  await bundle.close();
  const code = generated.output.find((item) => item.type === 'chunk').code;
  expect(code.startsWith('"use strict";')).toBe(true);

  const victim = { secret: 'must-not-leak' };
  const evil = Object.create(null);
  const scopedRegistry = new Proxy(Object.create(null), {
    get(_target, requested) {
      return requested === 'evil@1.0.0' ? evil : undefined;
    },
  });
  evil.process = { marker: 'SCOPED' };
  evil.__compartments = scopedRegistry;
  const rootRegistry = new Proxy(Object.create(null), {
    get(_target, requested) {
      if (requested === 'evil@1.0.0') return evil;
      if (requested === 'victim@9.0.0') return victim;
      return undefined;
    },
  });
  const fakeGlobal = Object.create(null);
  const cjsModule = { exports: {} };
  new Function('globalThis', '__compartments', 'module', 'exports', 'apiKey', code)(
    fakeGlobal,
    rootRegistry,
    cjsModule,
    cjsModule.exports,
    'ROOT-SESSION-SECRET',
  );

  expect(fakeGlobal.__ibexCompartmentTestResult).toEqual({
    raw: {
      identifier: undefined,
      alias: undefined,
      own: true,
      marker: 'SCOPED',
    },
    shadow: 'SCOPED',
    plain: {
      sloppyThis: undefined,
      // Explicit residual: the finite build-time rewrite does not isolate an
      // arbitrary session name. The native package Domain is the boundary;
      // exhaustive flat rewriting is tracked by ENG-24527.
      apiKey: 'ROOT-SESSION-SECRET',
    },
  });
});

test('a source-authored import of another module scope fails the real Rolldown build', async () => {
  const victimId = '/virtual/node_modules/victim/index.js';
  const attackerId = '/virtual/node_modules/attacker/index.js';
  const compartmentPlugin = createCompartmentGlobalsPlugin({
    resolvePackage(id) {
      if (id === victimId) return 'victim@1.0.0';
      if (id === attackerId) return 'attacker@1.0.0';
      return null;
    },
  });
  const victimTransform = compartmentPlugin.transform('process.env.SECRET;', victimId);
  const victimScope = generatedScopeSpecifier(victimTransform.code);
  const fixturePlugin = {
    name: 'cross-scope-import-fixture',
    resolveId(source) {
      if (source === attackerId) return attackerId;
      return null;
    },
    load(id) {
      if (id !== attackerId) return null;
      return `import stolen from ${JSON.stringify(victimScope)};\nmodule.exports = stolen;`;
    },
  };

  const build = async () => {
    const bundle = await rolldown({
      input: attackerId,
      treeshake: false,
      plugins: [fixturePlugin, compartmentPlugin],
    });
    try {
      await bundle.generate({ format: 'cjs' });
    } finally {
      await bundle.close();
    }
  };
  await expect(build()).rejects.toThrow(
    /Refusing Ibex compartment scope import for victim@1\.0\.0/,
  );
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
