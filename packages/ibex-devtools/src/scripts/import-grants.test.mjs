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
  capabilitySubsumes,
  capabilityIntersect,
  capabilityUnion,
  resolveCascade,
  deriveSurfaces,
  createImportGrantsPlugin,
} from './import-grants.mjs';

// ---------------------------------------------------------------------------
// builtinSpecifierOf / extractImportSpecifiers (ENG-22683 — builtins axis)
// ---------------------------------------------------------------------------

test('builtinSpecifierOf classifies builtins and normalizes the node: prefix', () => {
  expect(builtinSpecifierOf('os')).toBe('node:os');
  expect(builtinSpecifierOf('node:os')).toBe('node:os');
  expect(builtinSpecifierOf('fs/promises')).toBe('node:fs/promises'); // subpath preserved
  expect(builtinSpecifierOf('node:crypto')).toBe('node:crypto');
  expect(builtinSpecifierOf('lodash')).toBeNull(); // real package
  expect(builtinSpecifierOf('@scope/pkg')).toBeNull(); // scoped package
  expect(builtinSpecifierOf('./local.js')).toBeNull(); // relative path
  expect(builtinSpecifierOf('/abs/path')).toBeNull();
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
