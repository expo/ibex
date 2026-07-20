import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertCompatSelectorInventory,
  assertSwcDependencyPrefixGate,
  swcSurfaceInventory,
} from './oxc-retirement-manifest.mjs';

test('compat selector inventory binds semantics, lifecycle, and exact readers', () => {
  const sources = new Map([
    ['fixture-producer', 'set EXACT'],
    ['fixture-reader', 'read EXACT'],
    ['loader-producer', 'set IBEX'],
    ['loader-reader', 'read IBEX'],
  ]);
  const entries = [
    {
      selector: 'EXACT_COMPAT_TEST',
      semantic: 'fixture-fidelity',
      role: 'producer',
      identity: 'fixture-producer',
      file: 'fixture-producer',
      needle: 'set EXACT',
      expectedOccurrences: 1,
      disposition: 'retain',
    },
    {
      selector: 'EXACT_COMPAT_TEST',
      semantic: 'fixture-fidelity',
      role: 'reader',
      identity: 'fixture-reader',
      file: 'fixture-reader',
      needle: 'read EXACT',
      expectedOccurrences: 1,
      disposition: 'retain',
    },
    {
      selector: 'IBEX_COMPAT_LOADER_TEST',
      semantic: 'loader-selection',
      role: 'producer',
      identity: 'loader-producer',
      file: 'loader-producer',
      needle: 'set IBEX',
      expectedOccurrences: 1,
      disposition: 'retire',
    },
    {
      selector: 'IBEX_COMPAT_LOADER_TEST',
      semantic: 'loader-selection',
      role: 'reader',
      identity: 'loader-reader',
      file: 'loader-reader',
      needle: 'read IBEX',
      expectedOccurrences: 1,
      disposition: 'retire',
    },
  ];
  assert.doesNotThrow(() =>
    assertCompatSelectorInventory(entries, (file) => sources.get(file)),
  );
  assert.throws(() =>
    assertCompatSelectorInventory(
      entries.map((entry) =>
        entry.identity === 'loader-reader'
          ? { ...entry, disposition: 'retain' }
          : entry,
      ),
      (file) => sources.get(file),
    ),
  );
});

test('SWC dependency gate inventories exact names for every retained profile', () => {
  assert.doesNotThrow(() =>
    assertSwcDependencyPrefixGate({
      mode: 'inventory',
      expectedNames: ['swc_common', 'swc_ecma_parser'],
      profileNames: {
        default: ['swc_ecma_parser', 'swc_common'],
        'no-default-features': ['swc_common', 'swc_ecma_parser'],
      },
      lockfileNames: ['swc_ecma_parser', 'swc_common'],
    }),
  );
  assert.throws(() =>
    assertSwcDependencyPrefixGate({
      mode: 'inventory',
      expectedNames: ['swc_common'],
      profileNames: { default: ['swc_common', 'swc_new_crate'] },
      lockfileNames: ['swc_common', 'swc_new_crate'],
    }),
  );
});

test('post-retirement prefix gate rejects any newly named swc_* package', () => {
  assert.doesNotThrow(() =>
    assertSwcDependencyPrefixGate({
      mode: 'forbid-prefix',
      expectedNames: [],
      profileNames: { default: [] },
      lockfileNames: [],
    }),
  );
  assert.throws(() =>
    assertSwcDependencyPrefixGate({
      mode: 'forbid-prefix',
      expectedNames: [],
      profileNames: { default: ['swc_future'] },
      lockfileNames: ['swc_future'],
    }),
  );
});

test('CapSec inventory freezes five exact base IDs and five main variants', () => {
  const surfaces = Array.from({ length: 5 }, (_, index) => ({
    edgeId: `surface.loader.route.${index}.swc.digest${index}`,
    branchId: `surface.loader.route.${index}.swc.digest${index}.main`,
    sourceRefs: [`src/module_loader/transpile.rs#symbol_${index}`],
  }));
  const inventory = swcSurfaceInventory({ surfaces });
  assert.equal(inventory.surfaceIds.length, 10);
  assert.equal(inventory.symbolRefs.length, 5);
});
