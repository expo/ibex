// @ref LLP 0014#conformance — unit tests for the grant-authoring surface:
// parse (fail-closed), strip (grants have no runtime representation), the
// capability set algebra, and the delegation cascade. Run with: bun test.

import { expect, test } from 'bun:test';
import {
  parseImportGrants,
  stripGrantAttributes,
  packageNameOfSpecifier,
  builtinSpecifierOf,
  extractImportSpecifiers,
  diffBuiltinAxis,
  capabilitySubsumes,
  capabilityIntersect,
  capabilityUnion,
  resolveCascade,
  deriveSurfaces,
  createImportGrantsPlugin,
  bareNameOf,
} from './import-grants.mjs';
import { runtimeGatedNodeBuiltins } from './builtin-manifest.mjs';

// ---------------------------------------------------------------------------
// builtin aliases + package classification (ENG-22697 / ENG-22699)
// ---------------------------------------------------------------------------

test('builtinSpecifierOf recognizes exact:/bun: aliases and keeps them verbatim', () => {
  expect(builtinSpecifierOf('exact:sqlite')).toBe('exact:sqlite');
  expect(builtinSpecifierOf('bun:sqlite')).toBe('bun:sqlite');
  expect(builtinSpecifierOf('bun:fs')).toBe('bun:fs');
  // A real package is still not a builtin.
  expect(builtinSpecifierOf('lodash')).toBeNull();
});

test('packageNameOfSpecifier excludes bare/aliased builtins (ENG-22699)', () => {
  // Builtins in every spelling are NOT package selectors.
  for (const b of ['fs', 'fs/promises', 'node:fs', 'bun:fs', 'exact:sqlite', 'bun:sqlite']) {
    expect(packageNameOfSpecifier(b)).toBeNull();
  }
  // Real packages still resolve to a selector.
  expect(packageNameOfSpecifier('lodash')).toBe('lodash');
  expect(packageNameOfSpecifier('lodash/fp')).toBe('lodash');
  expect(packageNameOfSpecifier('@scope/pkg/x')).toBe('@scope/pkg');
});

// ---------------------------------------------------------------------------
// diffBuiltinAxis: --check tightening vs expansion (ENG-22701)
// ---------------------------------------------------------------------------

test('diffBuiltinAxis: unrestricted (omitted) → explicit list is tightening, not expansion', () => {
  const d = diffBuiltinAxis({ p: {} }, { p: { builtins: ['node:os'] } });
  expect(d.expansions).toEqual([]);
  expect(d.shrinkage).toEqual(['p: import *']);
});

test('diffBuiltinAxis: explicit → unrestricted (omitted) is an expansion', () => {
  const d = diffBuiltinAxis({ p: { builtins: ['node:os'] } }, { p: {} });
  expect(d.expansions).toEqual(['p: import *']);
  expect(d.shrinkage).toEqual(['p: import node:os']);
});

test('diffBuiltinAxis: explicit expansion and shrinkage', () => {
  const exp = diffBuiltinAxis({ p: { builtins: ['node:os'] } }, { p: { builtins: ['node:os', 'node:fs'] } });
  expect(exp.expansions).toEqual(['p: import node:fs']);
  expect(exp.shrinkage).toEqual([]);
  const shr = diffBuiltinAxis({ p: { builtins: ['node:os', 'node:fs'] } }, { p: { builtins: ['node:os'] } });
  expect(shr.expansions).toEqual([]);
  expect(shr.shrinkage).toEqual(['p: import node:fs']);
});

test('diffBuiltinAxis: literal "*" is an explicit builtin, not unrestricted', () => {
  const d = diffBuiltinAxis({ p: { builtins: ['*'] } }, { p: { builtins: ['node:os'] } });
  expect(d.expansions).toEqual(['p: import node:os']);
  expect(d.shrinkage).toEqual(['p: import *']);
});

test('diffBuiltinAxis: string-typed builtins is invalid policy shape', () => {
  expect(() => diffBuiltinAxis({ p: { builtins: 'node:os' } }, {})).toThrow(
    /packages\.p\.builtins must be an array/,
  );
});

// ---------------------------------------------------------------------------
// builtinSpecifierOf / extractImportSpecifiers (ENG-22683 — builtins axis)
// ---------------------------------------------------------------------------

test('builtinSpecifierOf classifies builtins and normalizes the node: prefix', () => {
  expect(builtinSpecifierOf('os')).toBe('node:os');
  expect(builtinSpecifierOf('node:os')).toBe('node:os');
  expect(builtinSpecifierOf('node:test')).toBe('node:test');
  expect(builtinSpecifierOf('fs/promises')).toBe('node:fs/promises'); // subpath preserved
  expect(builtinSpecifierOf('node:crypto')).toBe('node:crypto');
  expect(builtinSpecifierOf('lodash')).toBeNull(); // real package
  expect(builtinSpecifierOf('@scope/pkg')).toBeNull(); // scoped package
  expect(builtinSpecifierOf('./local.js')).toBeNull(); // relative path
  expect(builtinSpecifierOf('/abs/path')).toBeNull();
});

// @ref LLP 0014#the-generated-artifact (ENG-22683/ENG-22772) — the generator's
// builtin classifier and the runtime gate share the generated manifest roots. If
// this lags, a package's real `require("<root>")` (e.g. `sqlite`) is emitted as a
// package edge, omitted from the builtins allowlist, and DENIED under enforce.
test('builtinSpecifierOf covers every generated runtime-gated root', () => {
  expect(runtimeGatedNodeBuiltins.length).toBeGreaterThan(30);
  expect(runtimeGatedNodeBuiltins).toContain('repl');
  expect(runtimeGatedNodeBuiltins).toContain('sqlite');
  const missing = runtimeGatedNodeBuiltins.filter((r) => builtinSpecifierOf(r) !== `node:${r}`);
  expect(missing).toEqual([]);
});

test('extractImportSpecifiers finds import/export-from/dynamic-import/require', () => {
  const src = [
    'import a from "os";',
    'export { x } from "node:path";',
    'const p = import("fs/promises");',
    'const cp = require("child_process");',
    'const n = "o" + "s"; const dyn = require(n);', // computed → not extractable
  ].join('\n');
  const specs = extractImportSpecifiers(src);
  expect(specs).toContain('os');
  expect(specs).toContain('node:path');
  expect(specs).toContain('fs/promises');
  expect(specs).toContain('child_process');
  // The computed require contributes nothing (fail closed).
  expect(specs).not.toContain('n');
});

test('extractImportSpecifiers observes requires in sloppy-mode CommonJS (ENG-22683/ENG-22700)', () => {
  // Octal literals and `with` are invalid as ES modules; the script-parse
  // fallback must still observe the builtin require, else the package gets
  // builtins:[] and its require is denied under enforce.
  expect(extractImportSpecifiers('var mode = 0777;\nvar os = require("os");')).toContain('os');
  expect(extractImportSpecifiers('with (Math) { }\nvar fs = require("fs");')).toContain('fs');
  // The exact ENG-22700 probe: require() INSIDE a sloppy-only `with` block.
  expect(extractImportSpecifiers('with (x) { require("os") }')).toContain('os');
});

// ---------------------------------------------------------------------------
// parseImportGrants
// ---------------------------------------------------------------------------

test('parses grants, endow, builtins, and also from import attributes', () => {
  const src = `import lib from "image-lib" with {
    grants: "fs:read:/app/images/**, fs:write:/app/images/**",
    endow: "fetch",
    builtins: "node:fs",
    also: "tmp-helper => fs:read:/app/images/**; other => network:fetch",
  };`;
  const { sites, errors } = parseImportGrants(src, 'app.mjs');
  expect(errors).toEqual([]);
  expect(sites).toHaveLength(1);
  const site = sites[0];
  expect(site.package).toBe('image-lib');
  expect(site.line).toBe(1);
  expect(site.capabilities).toEqual([
    'fs:read:/app/images/**',
    'fs:write:/app/images/**',
  ]);
  expect(site.endow).toEqual(['fetch']);
  expect(site.builtins).toEqual(['node:fs']);
  expect(site.also['tmp-helper']).toEqual(['fs:read:/app/images/**']);
  expect(site.also.other).toEqual(['network:fetch']);
});

test('imports without grant keys produce no sites', () => {
  const { sites, errors } = parseImportGrants(
    `import a from "a";\nimport data from "./x.json" with { type: "json" };`,
  );
  expect(sites).toEqual([]);
  expect(errors).toEqual([]);
});

test('subpath and scoped specifiers fold onto the package selector', () => {
  expect(packageNameOfSpecifier('lodash/fp')).toBe('lodash');
  expect(packageNameOfSpecifier('@scope/pkg/sub')).toBe('@scope/pkg');
  expect(packageNameOfSpecifier('./local.js')).toBeNull();
  expect(packageNameOfSpecifier('node:fs')).toBeNull();
});

test('fail closed: grants on a non-package specifier are errors', () => {
  const { sites, errors } = parseImportGrants(
    `import x from "./local.js" with { grants: "fs:read" };`,
    'app.mjs',
  );
  expect(sites).toEqual([]);
  expect(errors).toHaveLength(1);
  expect(errors[0].message).toContain('non-package specifier');
});

test('fail closed: malformed capability and also entries are errors', () => {
  const { errors } = parseImportGrants(
    `import a from "a" with { grants: "fs read" };
     import b from "b" with { also: "no-arrow-here" };`,
    'app.mjs',
  );
  expect(errors).toHaveLength(2);
  expect(errors.map((error) => error.line)).toEqual([1, 2]);
});

// ---------------------------------------------------------------------------
// stripGrantAttributes
// ---------------------------------------------------------------------------

test('strips the whole with-clause when only grant keys are present', () => {
  const src = `import lib from "image-lib" with { grants: "fs:read" };\nlib();`;
  expect(stripGrantAttributes(src)).toBe(`import lib from "image-lib";\nlib();`);
});

test('preserves unrecognized attributes such as type: json', () => {
  const src = `import d from "./d.json" with { type: "json", grants: "fs:read" };`;
  expect(stripGrantAttributes(src)).toBe(`import d from "./d.json" with { type: "json" };`);
});

test('leaves attribute-free source byte-identical', () => {
  const src = `import a from "a";\nconst with_ = 1;\n`;
  expect(stripGrantAttributes(src)).toBe(src);
});

test('plugin strips grants and reports the parse to collect', () => {
  const plugin = createImportGrantsPlugin({
    collect(id, parsed) {
      expect(id).toBe('/x/app.mjs');
      expect(parsed.sites[0].package).toBe('image-lib');
    },
  });
  const out = plugin.transform(`import lib from "image-lib" with { grants: "fs:read" };`, '/x/app.mjs');
  expect(out.code).toBe(`import lib from "image-lib";`);
});

// ---------------------------------------------------------------------------
// Capability set algebra
// ---------------------------------------------------------------------------

test('a segment prefix subsumes its extensions', () => {
  expect(capabilitySubsumes('fs:read', 'fs:read:/app/images')).toBe(true);
  expect(capabilitySubsumes('fs:read:/app/images', 'fs:read')).toBe(false);
  expect(capabilitySubsumes('fs:read', 'fs:write')).toBe(false);
  expect(capabilitySubsumes('network:*', 'network:fetch')).toBe(true);
});

test('a trailing /** on a path parameter subsumes deeper paths', () => {
  expect(capabilitySubsumes('fs:read:/a/**', 'fs:read:/a/b')).toBe(true);
  expect(capabilitySubsumes('fs:read:/a/**', 'fs:read:/a')).toBe(true);
  expect(capabilitySubsumes('fs:read:/a/**', 'fs:read:/ab')).toBe(false);
});

test('intersection picks the narrower grant; disjoint drops (fail closed)', () => {
  // The LLP 0013 worked example: delegates fs:read against an effective
  // path-scoped grant narrows to the path-scoped grant.
  expect(capabilityIntersect('fs:read', 'fs:read:/app/images/**')).toBe(
    'fs:read:/app/images/**',
  );
  expect(capabilityIntersect('fs:read:/a/**', 'fs:read:/a/b')).toBe('fs:read:/a/b');
  expect(capabilityIntersect('fs:read:/a', 'fs:read:/b')).toBeNull();
  expect(capabilityIntersect('fs:read', 'network:fetch')).toBeNull();
});

test('union dedupes and drops subsumed grants', () => {
  expect(capabilityUnion(['fs:read:/a', 'fs:read', 'fs:read:/a'])).toEqual(['fs:read']);
  expect(capabilityUnion(['network:fetch', 'fs:read'])).toEqual([
    'fs:read',
    'network:fetch',
  ]);
});

// ---------------------------------------------------------------------------
// Delegation cascade
// ---------------------------------------------------------------------------

test('cascade: delegates intersect the delegator effective grant', () => {
  const effective = resolveCascade({
    rootGrants: new Map([
      ['image-lib', [{ capability: 'fs:read:/app/images/**', site: 'app.mjs:1' }]],
    ]),
    edges: [['image-lib', 'fast-codec']],
    requests: new Map([
      ['image-lib', { delegates: { 'fast-codec': ['fs:read'] } }],
    ]),
  });
  expect([...effective.get('fast-codec').keys()]).toEqual(['fs:read:/app/images/**']);
  expect(effective.get('fast-codec').get('fs:read:/app/images/**')).toEqual({
    via: 'image-lib',
    delegate: 'fs:read',
  });
});

test('cascade: a package can never delegate more than it holds', () => {
  const effective = resolveCascade({
    rootGrants: new Map([
      ['image-lib', [{ capability: 'fs:read:/app/images/**', site: 'app.mjs:1' }]],
    ]),
    edges: [['image-lib', 'fast-codec']],
    requests: new Map([
      // Compromised manifest requests the world for its dependency.
      ['image-lib', { delegates: { 'fast-codec': ['fs:write', 'network:fetch', 'process:spawn'] } }],
    ]),
  });
  expect(effective.has('fast-codec')).toBe(false);
});

test('cascade: multi-hop chains attenuate and terminate (cycles included)', () => {
  const effective = resolveCascade({
    rootGrants: new Map([['a', [{ capability: 'fs:read:/data/**', site: 's:1' }]]]),
    edges: [
      ['a', 'b'],
      ['b', 'c'],
      ['c', 'a'], // cycle
    ],
    requests: new Map([
      ['a', { delegates: { b: ['fs:read:/data/sub/**'] } }],
      ['b', { delegates: { c: ['fs:read'] } }],
      ['c', { delegates: { a: ['fs:read'] } }],
    ]),
  });
  expect([...effective.get('b').keys()]).toEqual(['fs:read:/data/sub/**']);
  expect([...effective.get('c').keys()]).toEqual(['fs:read:/data/sub/**']);
  // The cycle back into `a` adds nothing beyond its root grant.
  expect([...effective.get('a').keys()]).toEqual(['fs:read:/data/**']);
});

test('cascade: union across importers delegating different scopes', () => {
  const effective = resolveCascade({
    rootGrants: new Map([
      ['p', [{ capability: 'fs:read:/p/**', site: 's:1' }]],
      ['q', [{ capability: 'fs:read:/q/**', site: 's:2' }]],
    ]),
    edges: [
      ['p', 'shared'],
      ['q', 'shared'],
    ],
    requests: new Map([
      ['p', { delegates: { shared: ['fs:read'] } }],
      ['q', { delegates: { shared: ['fs:read'] } }],
    ]),
  });
  expect([...effective.get('shared').keys()].sort()).toEqual([
    'fs:read:/p/**',
    'fs:read:/q/**',
  ]);
});

test('bareNameOf strips the version, preserving scoped names and bare names', () => {
  expect(bareNameOf('shared-pkg@2.0.0')).toBe('shared-pkg');
  expect(bareNameOf('@scope/name@1.0.0')).toBe('@scope/name');
  expect(bareNameOf('shared-pkg')).toBe('shared-pkg');
  expect(bareNameOf('@scope/name')).toBe('@scope/name');
});

// @ref LLP 0013 (ENG-22818) — with an identity-keyed cascade a delegate declared
// by one installed version must not flow along a DIFFERENT version's import edge.
// Mirrors tests/fixtures/llp0013/versioned-delegation.
test('cascade: a delegate is not honored along a coexisting version edge', () => {
  const effective = resolveCascade({
    // The bare import-site grant is app-wide → seeded into both identities.
    rootGrants: new Map([
      ['shared-pkg@1.0.0', [{ capability: 'fs:read:/allowed/**', site: 'app:1' }]],
      ['shared-pkg@2.0.0', [{ capability: 'fs:read:/allowed/**', site: 'app:1' }]],
    ]),
    // Only v2 imports helper-pkg (edge); only v1 delegates to it (request).
    edges: [['shared-pkg@2.0.0', 'helper-pkg@1.0.0']],
    requests: new Map([
      ['shared-pkg@1.0.0', { delegates: { 'helper-pkg': ['fs:read'] } }],
    ]),
    bareOf: bareNameOf,
  });
  // No single version both imports helper-pkg AND delegates to it.
  expect(effective.has('helper-pkg@1.0.0')).toBe(false);
});

test('cascade: a delegate IS honored when the same version has the edge', () => {
  const effective = resolveCascade({
    rootGrants: new Map([
      ['shared-pkg@2.0.0', [{ capability: 'fs:read:/allowed/**', site: 'app:1' }]],
    ]),
    edges: [['shared-pkg@2.0.0', 'helper-pkg@1.0.0']],
    requests: new Map([
      // v2 both imports helper-pkg and delegates to it.
      ['shared-pkg@2.0.0', { delegates: { 'helper-pkg': ['fs:read'] } }],
    ]),
    bareOf: bareNameOf,
  });
  expect([...effective.get('helper-pkg@1.0.0').keys()]).toEqual(['fs:read:/allowed/**']);
  expect(effective.get('helper-pkg@1.0.0').get('fs:read:/allowed/**')).toEqual({
    via: 'shared-pkg@2.0.0',
    delegate: 'fs:read',
  });
});

// ---------------------------------------------------------------------------
// Surface derivation
// ---------------------------------------------------------------------------

test('derives endowments from capability classes but never a builtins allowlist', () => {
  expect(deriveSurfaces(['network:fetch'])).toEqual({
    endow: ['WebSocket', 'XMLHttpRequest', 'fetch'],
    builtins: [],
  });
  expect(deriveSurfaces(['process:env'])).toEqual({ endow: ['process'], builtins: [] });
  // ENG-22633: an fs grant must NOT synthesize a partial builtins allowlist — a
  // present list is enforced strictly and would deny every other builtin the
  // package imports. The builtins axis is opt-in via explicit `builtins:` only.
  expect(deriveSurfaces(['fs:read:/x'])).toEqual({ endow: [], builtins: [] });
});
