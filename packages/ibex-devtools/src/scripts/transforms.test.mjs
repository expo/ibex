import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'path';
import { fileURLToPath } from 'node:url';
import { parse } from 'acorn';
import ts from 'typescript';
import { describe, expect, it } from 'bun:test';

import {
  createBundlerExternalPredicate,
  fixForOfScoping,
  protectExponentiation,
  replaceModuleDirnameBindings,
  restoreExponentiation,
  runtimeImportMetaDefine,
  transformAsyncGenerators,
  transformBigIntLiterals,
} from './transforms.mjs';

function expectParses(source) {
  try {
    parse(source, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      ranges: true,
    });
    return;
  } catch {}

  parse(source, {
    ecmaVersion: 'latest',
    sourceType: 'script',
    allowReturnOutsideFunction: true,
    ranges: true,
  });
}

describe('fixForOfScoping', () => {
  it('rewrites safe for-of loops and preserves per-iteration bindings', () => {
    const source = `
function collect(items) {
  const fns = [];
  for (const item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).not.toBe(source);
    expect(transformed).toContain('const __exactForOfIterator0 = (items)[Symbol.iterator]();');
    expect(transformed).toContain('const __exactForOfStep0 = __exactForOfIterator0.next();');
    // ENG-22569: the body runs inside a per-iteration-invoked arrow function
    // so the loop variable is a genuinely fresh binding per iteration even on
    // non-block-scoping Hermes (function parameters always are).
    expect(transformed).toContain('const __exactForOfBody0 = (__exactForOfValue0) => {');
    expect(transformed).toContain('const item = __exactForOfValue0;');
    expect(transformed).toContain('__exactForOfBody0(__exactForOfStep0.value);');
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect([1, 2, 3])).toEqual([1, 2, 3]);
  });

  it('preserves method this-binding inside rewritten loop bodies', () => {
    const source = `
class Counter {
  constructor() {
    this.total = 0;
  }

  addAll(items) {
    for (const item of items) {
      this.total += item;
    }
    return this.total;
  }
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).toContain('const __exactForOfIterator0 = (items)[Symbol.iterator]();');
    expect(transformed).toContain('const item = __exactForOfValue0;');
    expectParses(transformed);

    const Counter = new Function(`${transformed}; return Counter;`)();
    expect(new Counter().addAll([1, 2, 3])).toBe(6);
  });

  it('avoids destructured callback parameters in rewritten loops', () => {
    const source = `
function collectValues(items) {
  const fns = [];
  for (const { value } of items) {
    fns.push(() => value);
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).not.toContain('function({ value })');
    expect(transformed).toContain('const __exactForOfIterator0 = (items)[Symbol.iterator]();');
    expect(transformed).toContain('const { value } = __exactForOfValue0;');
    expectParses(transformed);

    const collectValues = new Function(`${transformed}; return collectValues;`)();
    expect(collectValues([{ value: 1 }, { value: 2 }])).toEqual([1, 2]);
  });

  it('leaves loops with break/continue/return control flow untouched', () => {
    const source = `
function firstPositive(items) {
  for (const item of items) {
    if (item < 0) {
      continue;
    }
    if (item > 0) {
      return item;
    }
    break;
  }
  return 0;
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('does not rewrite for-await-of loops', () => {
    const source = `
async function consume(items) {
  for await (const item of items) {
    console.log(item);
  }
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('does not rewrite loops whose bodies contain nested for-await-of', () => {
    const source = `
async function consume(groups) {
  for (const group of groups) {
    for await (const item of group) {
      console.log(item);
    }
  }
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('preserves live iterator semantics when the iterable mutates during iteration', () => {
    const source = `
function collect(iterable) {
  const seen = [];
  for (const item of iterable) {
    seen.push(item);
    if (item === "a") {
      iterable.items.push("b");
    }
  }
  return seen;
}
`;

    const transformed = fixForOfScoping(source);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    const iterable = {
      items: ["a"],
      [Symbol.iterator]() {
        let index = 0;
        const self = this;
        return {
          next() {
            if (index >= self.items.length) {
              return { done: true, value: undefined };
            }
            return { done: false, value: self.items[index++] };
          },
        };
      },
    };

    expect(collect(iterable)).toEqual(["a", "b"]);
  });

  it('rewrites nested for-of loops inside rewritten bodies (ENG-22559)', () => {
    const source = `
function collect(xs, ys) {
  const fns = [];
  for (const x of xs) {
    for (const y of ys) {
      fns.push(() => x + ':' + y);
    }
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    // The outer rewrite keeps its pre-ENG-22559 shape and numbering; the
    // inner loop is no longer emitted raw and gets non-colliding temporaries.
    expect(transformed).toContain('const __exactForOfIterator0 = (xs)[Symbol.iterator]();');
    expect(transformed).toContain('const __exactForOfIterator1 = (ys)[Symbol.iterator]();');
    expect(transformed).toContain('const x = __exactForOfValue0;');
    expect(transformed).toContain('const y = __exactForOfValue1;');
    expect(transformed).not.toMatch(/for\s*\(\s*const\s+y\s+of/);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect(['a', 'b'], [1, 2])).toEqual(['a:1', 'a:2', 'b:1', 'b:2']);
  });

  it('rewrites triply nested for-of loops with distinct temporaries', () => {
    const source = `
function collect(xs, ys, zs) {
  const fns = [];
  for (const x of xs) {
    for (const y of ys) {
      for (const z of zs) {
        fns.push(() => x + y + z);
      }
    }
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).toContain('__exactForOfIterator0');
    expect(transformed).toContain('__exactForOfIterator1');
    expect(transformed).toContain('__exactForOfIterator2');
    expect(transformed).not.toMatch(/for\s*\(\s*const\s+[xyz]\s+of/);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect(['a'], ['b'], ['c', 'd'])).toEqual(['abc', 'abd']);
  });

  it('rewrites a nested for-of that is the outer loop body without braces', () => {
    const source = `
function collect(xs, ys) {
  const fns = [];
  for (const x of xs) for (const y of ys) fns.push(() => x + ':' + y);
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).not.toMatch(/for\s*\(\s*const\s+[xy]\s+of/);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect(['a'], [1, 2])).toEqual(['a:1', 'a:2']);
  });

  it('rewrites for-of loops inside functions nested in a rewritten body while inner bails stay bailed', () => {
    // The callback body creates a function boundary, so its `return` does not
    // bail the outer loop — but it does bail the inner loop it belongs to.
    const source = `
function collect(xs, ys) {
  const results = [];
  for (const x of xs) {
    results.push(() => {
      for (const y of ys) {
        return x + ':' + y;
      }
    });
  }
  return results.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    // Outer rewritten; inner keeps its raw form (return bail), exactly as it
    // would outside a rewritten body.
    expect(transformed).toContain('const __exactForOfIterator0 = (xs)[Symbol.iterator]();');
    expect(transformed).toMatch(/for\s*\(\s*const\s+y\s+of\s+ys\)/);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect(['a', 'b'], [1, 2])).toEqual(['a:1', 'b:1']);
  });

  it('still rewrites inner loops when the outer loop bails (unchanged outer decision)', () => {
    const source = `
function firstJoined(xs, ys) {
  const fns = [];
  for (const x of xs) {
    for (const y of ys) {
      fns.push(() => x + ':' + y);
    }
    break;
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    // Outer bails on the break; the inner loop is rewritten via the bail-path
    // recursion (pre-existing behavior, preserved).
    expect(transformed).toMatch(/for\s*\(\s*const\s+x\s+of\s+xs\)/);
    expect(transformed).toContain('const __exactForOfIterator0 = (ys)[Symbol.iterator]();');
    expect(transformed).not.toMatch(/for\s*\(\s*const\s+y\s+of/);
    expectParses(transformed);

    const firstJoined = new Function(`${transformed}; return firstJoined;`)();
    expect(firstJoined(['a', 'b'], [1, 2])).toEqual(['a:1', 'a:2']);
  });

  it('rewrites for-of loops inside functions in the iterated expression of a rewritten loop', () => {
    const source = `
function collect(groups) {
  const fns = [];
  for (const item of groups.flatMap((group) => {
    const out = [];
    for (const value of group) {
      out.push(value);
    }
    return out;
  })) {
    fns.push(() => item);
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).not.toMatch(/for\s*\(\s*const\s+value\s+of/);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect([[1, 2], [3]])).toEqual([1, 2, 3]);
  });

  it('does not rewrite nested synthetic output on a second pass (idempotence)', () => {
    const source = `
function collect(xs, ys) {
  const fns = [];
  for (const x of xs) {
    for (const y of ys) {
      fns.push(() => x + ':' + y);
    }
  }
  return fns;
}
`;

    const once = fixForOfScoping(source);
    const twice = fixForOfScoping(once);

    expect(twice).toBe(once);
  });

  it('does not rewrite its own synthetic for-of loops on a second pass', () => {
    const source = `
function collect(items) {
  for (const item of items) {
    console.log(item);
  }
}
`;

    const once = fixForOfScoping(source);
    const twice = fixForOfScoping(once);

    expect(twice).toBe(once);
  });

  it('bails on bodies with var declarations (would lose function-scope hoisting in the wrapper)', () => {
    const source = `
function collect(items) {
  for (const item of items) {
    var last = item;
  }
  return last;
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('bails on bodies with function declarations (Annex B hoisting would change in the wrapper)', () => {
    const source = `
function collect(items) {
  for (const item of items) {
    function helper() { return item; }
    helper();
  }
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('bails when the body redeclares the loop binding at its top level', () => {
    const source = `
function collect(items) {
  for (const item of items) {
    let item = 1;
    console.log(item);
  }
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('does not bail on var declarations inside nested functions in the body', () => {
    const source = `
function collect(items) {
  const fns = [];
  for (const item of items) {
    fns.push(() => {
      var doubled = item + item;
      return doubled;
    });
  }
  return fns.map((fn) => fn());
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).not.toBe(source);
    expect(transformed).toContain('const __exactForOfBody0 = (__exactForOfValue0) => {');
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect(['a', 'b'])).toEqual(['aa', 'bb']);
  });

  it('still rewrites bodies with class declarations (block-scoped in both shapes)', () => {
    const source = `
function collect(items) {
  const out = [];
  for (const item of items) {
    class Wrapper { constructor() { this.item = item; } }
    out.push(new Wrapper().item);
  }
  return out;
}
`;

    const transformed = fixForOfScoping(source);

    expect(transformed).not.toBe(source);
    expectParses(transformed);

    const collect = new Function(`${transformed}; return collect;`)();
    expect(collect([1, 2])).toEqual([1, 2]);
  });

  it('bails on await in the body', () => {
    const source = `
async function collect(items) {
  for (const item of items) {
    await Promise.resolve(item);
  }
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('bails on yield in the body', () => {
    const source = `
function* collect(items) {
  for (const item of items) {
    yield item;
  }
}
`;

    expect(fixForOfScoping(source)).toBe(source);
  });

  it('keeps the inline shape for var-declared and plain-assignment loop variables', () => {
    const varSource = `
function collect(items) {
  const fns = [];
  for (var item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => fn());
}
`;
    const assignSource = `
function collect(items) {
  const fns = [];
  let item;
  for (item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => fn());
}
`;

    for (const source of [varSource, assignSource]) {
      const transformed = fixForOfScoping(source);

      // No per-iteration wrapper: these bind one function-scoped/outer
      // variable per the spec, so closures legitimately share it.
      expect(transformed).not.toBe(source);
      expect(transformed).not.toContain('__exactForOfBody0');
      expect(transformed).toContain('__exactForOfStep0.value;');
      expectParses(transformed);

      const collect = new Function(`${transformed}; return collect;`)();
      expect(collect(['a', 'b'])).toEqual(['b', 'b']);
    }
  });
});

// ENG-22569: engine-honest verification. The transform exists to fix closure
// capture on the Hermes configuration this repo ships (ES6BlockScoping=false,
// where block-level let/const are function-scoped), so these tests execute
// the transformed output on the real repo Hermes binary and compare against
// the untransformed source running on V8 (the spec oracle). Textual shape
// alone proved nothing: the old iterator-protocol shape passed every shape
// test while closures captured undefined on the actual engine.
// Hermes binary resolution for the ibex repo layout: IBEX_HERMES_BIN wins,
// then an ibex-local tools/hermes checkout, then the exact monorepo's
// tools/hermes when ibex is vendored at <exact>/vendor/ibex.
const testDir = fileURLToPath(new URL('.', import.meta.url));
const hermesBin =
  [
    process.env.IBEX_HERMES_BIN,
    path.resolve(testDir, '../../../../tools/hermes/hermes'),
    path.resolve(testDir, '../../../../../../tools/hermes/hermes'),
  ].find((candidate) => candidate && existsSync(candidate)) ?? '';

describe.skipIf(!existsSync(hermesBin))('fixForOfScoping on Hermes', () => {
  const runV8 = (code) => {
    const lines = [];
    new Function('print', code)((value) => lines.push(String(value)));
    return lines.join('\n');
  };

  const runHermes = (code) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'ibex-forof-hermes-'));
    const file = path.join(dir, 'fixture.js');
    writeFileSync(file, code);
    const result = spawnSync(hermesBin, [file], { encoding: 'utf8', timeout: 30000 });
    expect(result.status, `hermes failed: ${result.stderr}`).toBe(0);
    return result.stdout.trim();
  };

  const expectSpecSemanticsOnHermes = (source) => {
    const transformed = fixForOfScoping(source);
    const oracle = runV8(source);
    // The transform must not change semantics on a spec engine...
    expect(runV8(transformed)).toBe(oracle);
    // ...and must produce spec semantics on default-config Hermes.
    expect(runHermes(transformed)).toBe(oracle);
    return transformed;
  };

  it('restores per-iteration closure capture for a single-level loop', () => {
    const source = `
function collect(items) {
  const fns = [];
  for (const item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`;

    const transformed = expectSpecSemanticsOnHermes(source);
    expect(transformed).not.toBe(source);
    // Belt and braces: the raw source really does exhibit the Hermes
    // capture-last pitfall this transform exists to fix.
    expect(runHermes(source)).toBe('["b","b"]');
    expect(runV8(source)).toBe('["a","b"]');
  });

  it('restores per-iteration closure capture for nested loops (ENG-22559)', () => {
    const source = `
function collect(xs, ys) {
  const fns = [];
  for (const x of xs) {
    for (const y of ys) {
      fns.push(() => x + ":" + y);
    }
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"], [1, 2])));
`;

    expectSpecSemanticsOnHermes(source);
  });

  it('restores per-iteration capture for destructured bindings', () => {
    const source = `
function collect(items) {
  const fns = [];
  for (const { value } of items) {
    fns.push(() => value);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect([{ value: 1 }, { value: 2 }])));
`;

    expectSpecSemanticsOnHermes(source);
  });

  it('keeps let mutation per-iteration', () => {
    const source = `
function collect(items) {
  const fns = [];
  for (let item of items) {
    item = item + "!";
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`;

    expectSpecSemanticsOnHermes(source);
  });

  it('preserves method this-binding through the wrapper', () => {
    const source = `
class Counter {
  constructor() { this.total = 0; }
  addAll(items) {
    const fns = [];
    for (const item of items) {
      fns.push(() => { this.total += item; });
    }
    fns.forEach((fn) => fn());
    return this.total;
  }
}
print(JSON.stringify(new Counter().addAll([1, 2, 3])));
`;

    expectSpecSemanticsOnHermes(source);
  });

  it('preserves live iterator semantics on Hermes', () => {
    const source = `
function collect(iterable) {
  const seen = [];
  for (const item of iterable) {
    seen.push(item);
    if (item === "a") {
      iterable.items.push("b");
    }
  }
  return seen;
}
const iterable = {
  items: ["a"],
  [Symbol.iterator]() {
    let index = 0;
    const self = this;
    return {
      next() {
        if (index >= self.items.length) return { done: true, value: undefined };
        return { done: false, value: self.items[index++] };
      },
    };
  },
};
print(JSON.stringify(collect(iterable)));
`;

    expectSpecSemanticsOnHermes(source);
  });

  it('matches spec semantics for bailed break/continue bodies (left raw)', () => {
    const source = `
function firstPositive(items) {
  const out = [];
  for (const item of items) {
    if (item < 0) continue;
    if (item > 3) break;
    out.push(item);
  }
  return out;
}
print(JSON.stringify(firstPositive([-1, 1, 2, 9, 3])));
`;

    expect(fixForOfScoping(source)).toBe(source);
    expectSpecSemanticsOnHermes(source);
  });

  it('matches spec semantics for bailed yield bodies (left raw)', () => {
    const source = `
function* generate(items) {
  for (const item of items) {
    yield item * 2;
  }
}
print(JSON.stringify(Array.from(generate([1, 2, 3]))));
`;

    expect(fixForOfScoping(source)).toBe(source);
    expectSpecSemanticsOnHermes(source);
  });

  it('matches spec capture-last semantics for var-declared loop variables', () => {
    const source = `
function collect(items) {
  const fns = [];
  for (var item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`;

    expectSpecSemanticsOnHermes(source);
  });

  it('documents the tradeoff: hazard-bailed loops keep raw Hermes capture-last behavior', () => {
    // A body with a `var` declaration cannot be wrapped, so the loop stays
    // raw: on non-block-scoping Hermes escaping closures still capture the
    // last item (the pre-transform pitfall), while spec engines are correct.
    const source = `
function collect(items) {
  const fns = [];
  for (const item of items) {
    var current = item;
    fns.push(() => item + ":" + current);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`;

    expect(fixForOfScoping(source)).toBe(source);
    expect(runV8(source)).toBe('["a:b","b:b"]');
    expect(runHermes(source)).toBe('["b:b","b:b"]');
  });
});

describe('replaceModuleDirnameBindings', () => {
  it('rewrites module-scoped dirname and filename references', () => {
    const id = '/tmp/project/src/feature/example.js';
    const source = `
function locate() {
  return [__dirname, __filename];
}
const target = { __dirname, __filename };
const __dirname = 'local';
const literal = { __dirname: 1 };
`;

    const transformed = replaceModuleDirnameBindings(source, id);

    expect(transformed).not.toBe(source);
    expect(transformed).toContain(`[${JSON.stringify(path.dirname(id))}, ${JSON.stringify(id)}]`);
    expect(transformed).toContain(`{ __dirname: ${JSON.stringify(path.dirname(id))}, __filename: ${JSON.stringify(id)} }`);
    expect(transformed).toContain("const __dirname = 'local';");
    expect(transformed).toContain('const literal = { __dirname: 1 };');
    expectParses(transformed);
  });

  it('ignores relative and virtual module identifiers', () => {
    const source = 'console.log(__dirname, __filename);';

    expect(replaceModuleDirnameBindings(source, './relative.js')).toBe(source);
    expect(replaceModuleDirnameBindings(source, '\u0000virtual')).toBe(source);
  });
});

describe('runtimeImportMetaDefine', () => {
  it('defines longer import.meta aliases before shorter prefixes', () => {
    const keys = Object.keys(runtimeImportMetaDefine);

    expect(keys.indexOf('import.meta.dirname')).toBeLessThan(keys.indexOf('import.meta.dir'));
    expect(keys.indexOf('import.meta.filename')).toBeLessThan(keys.indexOf('import.meta.file'));
  });
});

describe('createBundlerExternalPredicate', () => {
  it('externalizes shared runtime modules and optional relative cjs files', () => {
    const external = createBundlerExternalPredicate({
      extraExternalModules: ['bun:test'],
      keepRelativeCjsExternal: true,
    });

    expect(external('node:fs')).toBe(true);
    expect(external('bun:fs')).toBe(true);
    expect(external('exact:http')).toBe(true);
    // node:test stopped being bundler-external when the runtime manifest moved
    // to the ibex submodule (51cffed2): ibex provides node:test itself (the
    // internal/test/binding bootstrap shims), so the registry marks it
    // bundleExternal: false. builtin-manifest.test.mjs pins the same truth.
    expect(external('node:test')).toBe(false);
    expect(external('test')).toBe(false);
    expect(external('ws')).toBe(true);
    expect(external('bun:test')).toBe(true);
    expect(external('./worker.cjs')).toBe(true);
    expect(external('../worker.cjs')).toBe(true);
    expect(external('./worker.js')).toBe(false);
    expect(external('bun:path')).toBe(false);
    expect(external('left-pad')).toBe(false);
  });
});

describe('transformAsyncGenerators', () => {
  it('rewrites async generators into valid async iterables', async () => {
    const source = `
async function* numbers() {
  yield 1;
  await Promise.resolve();
  yield 2;
}
`;

    const transformed = transformAsyncGenerators(source);

    expect(transformed).not.toContain('async function*');
    expect(transformed).toContain('[Symbol.asyncIterator]');
    expectParses(transformed);

    const numbers = new Function(`${transformed}; return numbers;`)();
    const iterator = numbers();

    await expect(iterator.next()).resolves.toEqual({ value: 1, done: false });
    await expect(iterator.next()).resolves.toEqual({ value: 2, done: false });
    await expect(iterator.next()).resolves.toEqual({
      value: undefined,
      done: true,
    });
  });

  it('suspends between consecutive yields until the consumer advances', async () => {
    const source = `
async function* numbers() {
  yield 1;
  yield 2;
  yield 3;
}
`;

    const transformed = transformAsyncGenerators(source);
    const numbers = new Function(`${transformed}; return numbers;`)();
    const iterator = numbers();

    await expect(iterator.next()).resolves.toEqual({ value: 1, done: false });
    await expect(iterator.next()).resolves.toEqual({ value: 2, done: false });
    await expect(iterator.next()).resolves.toEqual({ value: 3, done: false });
    await expect(iterator.next()).resolves.toEqual({
      value: undefined,
      done: true,
    });
  });

  it('rewrites async generator object methods into property functions', async () => {
    const source = `
const asyncIterable = {
  async* [Symbol.asyncIterator]() {
    yield 'a';
    yield 'b';
  }
};
`;

    const transformed = transformAsyncGenerators(source);

    expect(transformed).toContain('[Symbol.asyncIterator]: function()');
    expectParses(transformed);

    const asyncIterable = new Function(`${transformed}; return asyncIterable;`)();
    const iterator = asyncIterable[Symbol.asyncIterator]();

    await expect(iterator.next()).resolves.toEqual({ value: 'a', done: false });
    await expect(iterator.next()).resolves.toEqual({ value: 'b', done: false });
    await expect(iterator.next()).resolves.toEqual({
      value: undefined,
      done: true,
    });
  });

  it('leaves non-generator async functions unchanged', () => {
    const source = `
async function fetchValue() {
  return await Promise.resolve(42);
}
`;

    expect(transformAsyncGenerators(source)).toBe(source);
  });
});

describe('exponentiation compat transforms', () => {
  it('preserves exponentiation through transpile-style rewrites', () => {
    const source = `
const base = 10n;
const result = base ** 6n;
const chained = 2 ** 3 ** 2;
`;

    const protectedSource = protectExponentiation(source);

    expect(protectedSource).toContain('__exactCompatPow__(base, 6n)');
    expect(protectedSource).toContain('__exactCompatPow__(2, __exactCompatPow__(3, 2))');
    expectParses(protectedSource);

    const restored = restoreExponentiation(protectedSource);

    expect(restored).toContain('((base) ** (6n))');
    expect(restored).toContain('((2) ** (((3) ** (2))))');
    expectParses(restored);

    const evaluate = new Function(`${restored}; return { result, chained };`)();
    expect(evaluate.result).toBe(1000000n);
    expect(evaluate.chained).toBe(512);
  });

  it('keeps exponent operands parenthesized through the ES5 transpile path', () => {
    const source = `
const values = [];
for (let i = 1; i <= 3; i++) {
  const min = -(2 ** (i * 8 - 1));
  const max = 2 ** (i * 8 - 1) - 1;
  values.push([min, max]);
}
`;

    const protectedSource = protectExponentiation(source);
    const transpiled = ts.transpileModule(protectedSource, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES5,
      },
    }).outputText;
    const restored = restoreExponentiation(transpiled);

    expect(restored).toContain('-(((2) ** (i * 8 - 1)))');
    expect(restored).toContain('((2) ** (i * 8 - 1)) - 1');
    expectParses(restored);

    const values = new Function(`${restored}; return values;`)();
    expect(values).toEqual([
      [-128, 127],
      [-32768, 32767],
      [-8388608, 8388607],
    ]);
  });
});

// Ibex-only divergence from the exact-devtools transforms.mjs: Hermes accepts
// BigInt(...) calls but rejects BigInt literal source (LLP 0005).
describe('transformBigIntLiterals', () => {
  it('rewrites BigInt literals into BigInt(...) constructor calls', () => {
    const source = 'const big = 123n; const sep = 1_000n; const hex = 0xffn;';
    const transformed = transformBigIntLiterals(source);

    expect(transformed).toContain('BigInt("123")');
    expect(transformed).toContain('BigInt("1000")');
    expect(transformed).toContain('BigInt("0xff")');
    expectParses(transformed);
    expect(new Function(`${transformed}; return [big, sep, hex];`)()).toEqual([
      123n,
      1000n,
      255n,
    ]);
  });

  it('leaves identifiers and strings ending in n untouched', () => {
    const source = 'const n = fn("123n"); const chicken = hen;';
    expect(transformBigIntLiterals(source)).toBe(source);
  });
});
