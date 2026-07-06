/**
 * Shared, implementation-neutral Hermes-compat conformance corpus (LLP 0019,
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
  {
    id: 'arguments-preserved',
    rewrites: true,
    note: 'ENG-22990: the per-iteration wrapper preserves the enclosing function’s `arguments` (an arrow, not a callback that binds its own)',
    rawHermesCaptureLast: '["b:2","b:2"]',
    source: `
function collect() {
  const fns = [];
  for (const item of arguments[0]) {
    fns.push(() => item + ":" + arguments.length);
  }
  return fns.map((fn) => String(fn()));
}
print(JSON.stringify(collect(["a", "b"], "extra")));
`,
  },
  {
    id: 'iterator-close-on-throw',
    rewrites: true,
    note: 'ENG-23036: a rewritten for-of runs IteratorClose (iterator.return) when the body throws, so a generator finally runs — native does, the pre-fix iterator-protocol shape did not',
    source: `
function run() {
  const log = [];
  function* g() {
    try {
      yield "a";
      yield "b";
    } finally {
      log.push("cleanup");
    }
  }
  try {
    for (const x of g()) {
      log.push("body:" + x);
      throw new Error("boom");
    }
  } catch (e) {
    log.push("caught:" + e.message);
  }
  return log;
}
print(JSON.stringify(run()));
`,
  },
]);

/**
 * Async-generator conformance corpus (ENG-23036).
 *
 * `transformAsyncGenerators` desugars `async function*` into a demand-driven
 * async iterator (Hermes has no native async generators). These fixtures pin
 * the observable async-generator semantics the desugaring must reproduce; the
 * oracle is the untransformed source run as a native async generator on
 * V8/Node (see hermes-compat.test.mjs, which runs each `runFixture()` raw and
 * transformed and compares the results).
 *
 * Each fixture is a self-contained source that defines one or more
 * `async function*` generators plus an `async function runFixture()` driver
 * (a plain async function, so the transform leaves it untouched) returning a
 * JSON-serializable result.
 */
export const asyncGeneratorCorpus = Object.freeze([
  {
    id: 'next-arg-threads-into-yield',
    note: 'ENG-23036 #1: `x = yield e` resolves to the value passed to the resuming next(v); the return value threads to the final {value, done:true}',
    source: `
async function* g() {
  const a = yield 1;
  const b = yield a + 10;
  return b + 100;
}
async function runFixture() {
  const it = g();
  const out = [];
  out.push(await it.next());
  out.push(await it.next(5));
  out.push(await it.next(7));
  out.push(await it.next(9));
  return out;
}
`,
  },
  {
    id: 'concurrent-next-fifo',
    note: 'ENG-23036 #2: overlapping next() calls queue FIFO — neither promise is orphaned and results are not reordered',
    source: `
async function* g() {
  await Promise.resolve();
  yield 1;
  yield 2;
}
async function runFixture() {
  const it = g();
  const p1 = it.next();
  const p2 = it.next();
  const r1 = await p1;
  const r2 = await p2;
  const r3 = await it.next();
  return [r1, r2, r3];
}
`,
  },
  {
    id: 'lazy-body-start',
    note: 'ENG-23036 #3: the body runs lazily on the first next(), not eagerly at generator-call time',
    source: `
const sideEffects = [];
async function* g() {
  sideEffects.push("body-start");
  yield 1;
}
async function runFixture() {
  const it = g();
  const before = sideEffects.slice();
  await it.next();
  const after = sideEffects.slice();
  return { before, after };
}
`,
  },
  {
    id: 'return-completes-iterator',
    note: 'ENG-23036: return(v) resolves {value:v, done:true} and completes the iterator (subsequent next() is done)',
    source: `
async function* g() {
  yield 1;
  yield 2;
}
async function runFixture() {
  const it = g();
  const a = await it.next();
  const b = await it.return(42);
  const c = await it.next();
  return [a, b, c];
}
`,
  },
  {
    id: 'throw-propagates-and-completes',
    note: 'ENG-23036: throw(err) rejects when the generator does not catch and completes the iterator',
    source: `
async function* g() {
  yield 1;
  yield 2;
}
async function runFixture() {
  const it = g();
  const a = await it.next();
  let message = null;
  try {
    await it.throw(new Error("boom"));
  } catch (e) {
    message = e.message;
  }
  const c = await it.next();
  return [a, message, c];
}
`,
  },
]);

export default forOfScopingCorpus;
