import { describe, expect, it } from 'bun:test';

import {
  applyHermesTransforms,
  fixForOfScoping,
  protectExponentiation,
  restoreExponentiation,
  transformAsyncGenerators,
  transformBigIntLiterals,
} from './hermes-compat.mjs';
import { asyncGeneratorCorpus, forOfScopingCorpus } from './hermes-compat-corpus.mjs';
import { runCorpus } from './run-hermes-compat-corpus.mjs';

// Build a runnable driver from a corpus source that defines `runFixture()`, and
// return its result. The raw source runs as a native async generator (the
// oracle); the transformed source runs the desugared async iterator.
async function runAsyncFixture(source) {
  // eslint-disable-next-line no-new-func
  const build = new Function(`${source}\n;return runFixture();`);
  return await build();
}

// The canonical Hermes-compat module exposes the transform surface directly,
// independent of the broader ibex-devtools bundler module (LLP 0019).
describe('hermes-compat module surface', () => {
  it('exports the canonical transform functions', () => {
    for (const fn of [
      fixForOfScoping,
      protectExponentiation,
      restoreExponentiation,
      transformBigIntLiterals,
      transformAsyncGenerators,
      applyHermesTransforms,
    ]) {
      expect(typeof fn).toBe('function');
    }
  });

  it('applyHermesTransforms composes for-of + async-generator + BigInt lowering', () => {
    const source = 'const xs = [1n, 2n]; for (const x of xs) { fns.push(() => x); }';
    // BigInt literals are lowered and the for-of loop is rewritten.
    const out = applyHermesTransforms(source);
    expect(out).not.toContain('1n');
    expect(out).toContain('BigInt("1")');
    expect(out).toContain('[Symbol.iterator]()');
  });
});

// The shared conformance corpus asserts observable behavior — closure capture,
// live iteration, this-binding, bailout semantics — against the V8 oracle and,
// when a Hermes binary is available, against the shipping Hermes configuration.
describe('hermes-compat conformance corpus', () => {
  it('has the ENG-22569 engine-honest for-of fixtures', () => {
    expect(forOfScopingCorpus.length).toBeGreaterThanOrEqual(10);
    for (const fixture of forOfScopingCorpus) {
      expect(typeof fixture.id).toBe('string');
      expect(typeof fixture.source).toBe('string');
      expect(typeof fixture.rewrites).toBe('boolean');
    }
  });

  it('passes the corpus (V8 oracle always; Hermes when available)', () => {
    const report = runCorpus();
    const failed = report.results.filter((result) => !result.ok);
    const detail = failed
      .map((result) => `${result.id}: ${result.failures.join('; ')}`)
      .join('\n');
    expect(detail).toBe('');
    expect(report.ok).toBe(true);
  });
});

// The async-generator corpus (ENG-23036) asserts that the desugared async
// iterator reproduces native async-generator semantics — next(v) value
// threading, FIFO concurrency, lazy body start, and return()/throw()
// completion — by running each fixture raw (native async generator = oracle)
// and transformed, then comparing.
describe('hermes-compat async-generator conformance corpus', () => {
  it('has the ENG-23036 async-generator fixtures', () => {
    expect(asyncGeneratorCorpus.length).toBeGreaterThanOrEqual(5);
    for (const fixture of asyncGeneratorCorpus) {
      expect(typeof fixture.id).toBe('string');
      expect(typeof fixture.source).toBe('string');
    }
  });

  for (const fixture of asyncGeneratorCorpus) {
    it(`reproduces native async-generator semantics: ${fixture.id}`, async () => {
      const transformed = transformAsyncGenerators(fixture.source);
      // The transform must actually rewrite every async generator away —
      // including class/object `async *m()` methods and nested async
      // generators (ENG-23124).
      expect(transformed).not.toContain('async function*');
      expect(transformed).not.toMatch(/\basync\s*\*/);
      expect(transformed).not.toBe(fixture.source);

      const oracle = await runAsyncFixture(fixture.source);
      const actual = await runAsyncFixture(transformed);
      if (fixture.divergence) {
        // Documented divergence (LLP 0019 style): pin BOTH sides to their
        // exact output, so the pin fails loudly when either the engine or the
        // transform drifts — including when a fix makes them converge (the
        // fixture must then drop its divergence entry).
        expect(JSON.stringify(oracle)).toBe(fixture.divergence.oracle);
        expect(JSON.stringify(actual)).toBe(fixture.divergence.transformed);
      } else {
        expect(JSON.stringify(actual)).toBe(JSON.stringify(oracle));
      }
    });
  }
});
