// Regression tests for ENG-22981 finding 3: module.builtinModules must not
// advertise names that cannot be required.
//
// `moduleBuiltinList` feeds `module.builtinModules`; `Module.isBuiltin` is
// backed by `moduleBuiltinRuntimeSpecifiers` (the actual registry). Folding the
// `reservedNodeOnly` names (`sqlite`, `sea`) into `moduleBuiltinList` made
// `builtinModules.includes('sqlite')` true while `isBuiltin('sqlite')` was
// false and `require('node:sqlite')` threw — so bundlers left those specifiers
// external and crashed at runtime. The advertised list must agree with what is
// requirable; reserved names stay reachable via `nodeOnlyBuiltinModules`.

import { expect, test } from 'bun:test';
import {
  moduleBuiltinList,
  moduleBuiltinRuntimeSpecifiers,
  nodeBuiltins,
  nodeOnlyBuiltinModules,
  reservedNodeOnlyBuiltins,
} from './builtin-manifest.mjs';

test('builtinModules does not advertise reserved-but-unrequirable names', () => {
  for (const name of reservedNodeOnlyBuiltins) {
    expect(moduleBuiltinList).not.toContain(name);
  }
  expect(moduleBuiltinList).not.toContain('sqlite');
  expect(moduleBuiltinList).not.toContain('sea');
});

test('every advertised builtin is actually requirable (agrees with isBuiltin)', () => {
  const requirable = new Set(moduleBuiltinRuntimeSpecifiers);
  for (const name of moduleBuiltinList) {
    // isBuiltin(name) === requirable.has(name); they must not disagree.
    expect(requirable.has(name)).toBe(true);
  }
});

test('reserved names remain discoverable as node-only builtins', () => {
  // sqlite/sea are still Node-only builtins for tooling that wants the full
  // Node name space, just not advertised as requirable via builtinModules.
  for (const name of reservedNodeOnlyBuiltins) {
    expect(nodeOnlyBuiltinModules).toContain(name);
  }
});

test('builtinModules still lists the ordinary public builtins', () => {
  expect(moduleBuiltinList).toEqual(nodeBuiltins.slice());
  for (const name of ['fs', 'path', 'events', 'util', 'stream', 'http']) {
    expect(moduleBuiltinList).toContain(name);
  }
});
