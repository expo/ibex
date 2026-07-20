// LLP 0021 regression: armed startup closes private heap inspection while the
// public process.memoryUsage() facade must still authorize its RSS system read.
// Run with:
//   bun test packages/ibex-runtime-js/src/node/process-memory-usage.test.ts

import { afterEach, expect, test } from 'bun:test';

const g = globalThis as Record<string, any>;
const previousGetHeapInfo = g.__exactGetHeapInfo;
const previousGetProcessRSS = g.__exactGetProcessRSS;
let freshImportOrdinal = 0;

async function freshProcessModule(): Promise<typeof import('./process.ts')> {
  freshImportOrdinal += 1;
  return import(`./process.ts?memory-usage=${freshImportOrdinal}`);
}

function restoreGlobal(name: string, value: unknown): void {
  if (value === undefined) {
    delete g[name];
  } else {
    g[name] = value;
  }
}

afterEach(() => {
  restoreGlobal('__exactGetHeapInfo', previousGetHeapInfo);
  restoreGlobal('__exactGetProcessRSS', previousGetProcessRSS);
});

test('memoryUsage retains its typed RSS read after heap inspection is closed', async () => {
  delete g.__exactGetHeapInfo;
  let reads = 0;
  g.__exactGetProcessRSS = () => {
    reads += 1;
    return 4_242_424;
  };

  const { process: isolatedProcess } = await freshProcessModule();

  expect(isolatedProcess.memoryUsage().rss).toBe(4_242_424);
  expect(reads).toBe(1);
});

test('memoryUsage propagates RSS authorization denial after heap inspection is closed', async () => {
  delete g.__exactGetHeapInfo;
  g.__exactGetProcessRSS = () => {
    throw new Error('Permission denied: sys:read memory');
  };

  const { process: isolatedProcess } = await freshProcessModule();

  expect(() => isolatedProcess.memoryUsage()).toThrow(/Permission denied/);
});
