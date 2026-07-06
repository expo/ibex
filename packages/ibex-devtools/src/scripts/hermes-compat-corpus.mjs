/**
 * Shared, implementation-neutral Hermes-compat conformance corpus (LLP 0312,
 * ENG-22569 / ENG-22987).
 *
 * These are the engine-honest `for...of` scoping fixtures promoted out of the
 * inline `fixForOfScoping on Hermes` suites that were duplicated across the
 * Ibex and Exact AST transform twins. The corpus is data only — it imports no
 * transform and no engine — so both Ibex and Exact can run it against their own
 * transform implementation and their own Hermes binary.
 *
 * Each fixture records observable behavior facts, not transform-output shape
 * (textual shape alone proved nothing: the pre-ENG-22569 iterator-protocol
 * shape passed every shape assertion while closures captured `undefined` on the
 * shipping Hermes configuration, ES6BlockScoping=false):
 *
 *   - `id`      stable fixture identifier.
 *   - `source`  the fixture source. Every fixture `print(...)`s a JSON string so
 *               the V8 spec oracle and the Hermes system-under-test produce a
 *               comparable stdout line.
 *   - `rewrites`  whether `fixForOfScoping` transforms the loop (true) or leaves
 *               it raw because a documented bailout applies (false).
 *   - `hermesMatchesOracle`  whether the transform output (or the raw source, for
 *               bailouts that are already spec-correct on Hermes) yields the V8
 *               spec oracle on the shipping Hermes configuration. Defaults to
 *               true. It is `false` only for the documented hole: a hazard-bailed
 *               loop whose escaping closures still capture-last on non-block-
 *               scoping Hermes.
 *   - `note`    what behavior the fixture pins.
 *   - `rawHermesCaptureLast` (optional) the stdout the *untransformed* source
 *               produces on non-block-scoping Hermes, documenting the
 *               capture-last pitfall the transform exists to fix (or that a
 *               hazard-bailed loop still exhibits). Only present where the
 *               original suite asserted it.
 *
 * The oracle for every fixture is the untransformed source run on V8/Node; the
 * runner derives it at run time rather than hard-coding it. See
 * run-hermes-compat-corpus.mjs.
 */

export const forOfScopingCorpus = Object.freeze([
  {
    id: 'single-level-closure-capture',
    rewrites: true,
    note: 'ENG-22569: single-level for-of restores per-iteration closure capture',
    rawHermesCaptureLast: '["b","b"]',
    source: `
function collect(items) {
  const fns = [];
  for (const item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`,
  },
  {
    id: 'nested-closure-capture',
    rewrites: true,
    note: 'ENG-22559: nested for-of inside a rewritten body also gets per-iteration capture',
    source: `
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
`,
  },
  {
    id: 'destructured-binding-capture',
    rewrites: true,
    note: 'Destructured loop bindings capture per iteration',
    source: `
function collect(items) {
  const fns = [];
  for (const { value } of items) {
    fns.push(() => value);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect([{ value: 1 }, { value: 2 }])));
`,
  },
  {
    id: 'let-mutation-per-iteration',
    rewrites: true,
    note: 'A `let` loop variable mutated in the body stays per-iteration',
    source: `
function collect(items) {
  const fns = [];
  for (let item of items) {
    item = item + "!";
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`,
  },
  {
    id: 'method-this-binding',
    rewrites: true,
    note: 'The per-iteration wrapper preserves lexical `this`',
    source: `
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
`,
  },
  {
    id: 'live-iterator-semantics',
    rewrites: true,
    note: 'Explicit iterator protocol keeps live/lazy iteration (not Array.from snapshot)',
    source: `
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
`,
  },
  {
    id: 'bailed-break-continue',
    rewrites: false,
    note: 'Non-local break/continue leaves the loop raw; raw for-of is spec-correct apart from closure capture',
    source: `
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
`,
  },
  {
    id: 'bailed-yield-body',
    rewrites: false,
    note: 'A `yield` in the body leaves the loop raw',
    source: `
function* generate(items) {
  for (const item of items) {
    yield item * 2;
  }
}
print(JSON.stringify(Array.from(generate([1, 2, 3]))));
`,
  },
  {
    id: 'var-declared-loop-variable',
    rewrites: true,
    note: 'A `var` loop variable is function-scoped; the plain iterator shape already models capture-last correctly',
    source: `
function collect(items) {
  const fns = [];
  for (var item of items) {
    fns.push(() => item);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`,
  },
  {
    id: 'hazard-bailed-var-in-body',
    rewrites: false,
    hermesMatchesOracle: false,
    note: 'A `var` declaration in the body is a hoisting hazard: loop stays raw, so escaping closures keep raw Hermes capture-last behavior (documented hole)',
    rawHermesCaptureLast: '["b:b","b:b"]',
    source: `
function collect(items) {
  const fns = [];
  for (const item of items) {
    var current = item;
    fns.push(() => item + ":" + current);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"])));
`,
  },
]);

export default forOfScopingCorpus;
