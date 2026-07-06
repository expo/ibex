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
    id: 'bailed-asi-bare-break-continue',
    rewrites: false,
    note: 'ENG-23137: bare ASI break/continue (semicolon-free style, keyword at end of line) must bail in BOTH tiers — the loader line scanner’s old regex required ;/}/\\n after the keyword but ran on split lines, so it rewrote the body into an arrow function where break/continue are illegal (SyntaxError from a green build)',
    source: `
function firstFew(items) {
  const out = []
  for (const item of items) {
    if (item < 0) continue
    if (item > 3) break
    out.push(item)
  }
  return out
}
print(JSON.stringify(firstFew([-1, 1, 2, 9, 3])));
`,
  },
  {
    id: 'bailed-labeled-continue',
    rewrites: false,
    note: 'ENG-23137: labeled break/continue (`continue outer`) must bail like bare ones — the old loader regex never matched a label after the keyword, so the rewrite emitted an illegal labeled continue inside the per-iteration arrow',
    source: `
function collect(matrix) {
  const out = []
  outer: for (const row of matrix) {
    for (const cell of row) {
      if (cell === 0) continue outer
      out.push(cell)
    }
  }
  return out
}
print(JSON.stringify(collect([[1, 2], [3, 0, 4], [5]])));
`,
  },
  {
    id: 'minified-destructured-header',
    rewrites: true,
    note: 'ENG-23137: a minified bracket-adjacent header (`for(const[k,v]of ...)`) has no literal " of ", so the AST authority’s old fast-path gate skipped the whole module and closures captured the last iteration on shipping Hermes; the gate is perf-only and must not decide correctness',
    rawHermesCaptureLast: '["b:2","b:2"]',
    source: `
const o = { a: 1, b: 2 };
const r = [];
for(const[k,v]of Object.entries(o))r.push(()=>k+":"+v);
print(JSON.stringify(r.map((f)=>f())));
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
 * JSON-serializable result. Drivers pump iterators manually (`await it.next()`
 * in a loop) rather than with `for await`, so the same fixture source runs on
 * engines without for-await support.
 *
 * A fixture may carry a `divergence` entry pinning a documented, deliberate
 * difference between the desugared iterator and native semantics (LLP 0019
 * style: exact expected outputs, so the pin fails loudly when either side
 * drifts — including when a fix makes the transform match natively):
 *   - `divergence.oracle`       JSON.stringify of the native result;
 *   - `divergence.transformed`  JSON.stringify of the desugared result;
 *   - `divergence.note`         why the divergence is accepted.
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
  {
    id: 'class-method-positions',
    note: 'ENG-23124 #1: class `async *m()` (instance, static, computed key) must replace the whole MethodDefinition — the old default branch emitted `class C { async *m function () {…} }`, a SyntaxError for the chunk',
    source: `
class C {
  constructor() { this.base = 10; }
  async *m(a) {
    yield this.base + a;
    yield "instance";
  }
  static async *sm() {
    yield "static";
  }
  async *["comp" + "uted"]() {
    yield "computed";
  }
}
async function drain(it) {
  const out = [];
  for (;;) {
    const step = await it.next();
    if (step.done) return out;
    out.push(step.value);
  }
}
async function runFixture() {
  const a = await drain(new C().m(5));
  const b = await drain(C.sm());
  const c = await drain(new C().computed());
  return { a, b, c };
}
`,
  },
  {
    id: 'yield-star-delegation',
    note: 'ENG-23124 #2: `yield*` pumps the inner (async or sync) iterable — values, next(v) threading into the inner generator, and the completion value — instead of yielding the iterator object as a single value',
    source: `
async function* inner() {
  const got = yield "i1";
  yield "got:" + got;
  return "inner-done";
}
async function* outer() {
  yield "before";
  const r = yield* inner();
  yield "result:" + r;
  yield* ["s1", "s2"];
}
async function runFixture() {
  const it = outer();
  const out = [];
  out.push(await it.next());
  out.push(await it.next());
  out.push(await it.next("X"));
  out.push(await it.next());
  out.push(await it.next());
  out.push(await it.next());
  out.push(await it.next());
  return out;
}
`,
  },
  {
    id: 'wrapper-preserves-this-and-arguments',
    note: 'ENG-23124 #3: the body runs with the original call’s `this` (object receiver) and `arguments`, not the driver plumbing’s',
    source: `
const q = {
  items: [1, 2],
  async *iter() {
    for (const d of this.items) {
      yield d;
    }
  }
};
async function* withArgs(a) {
  yield arguments.length;
  yield arguments[0] + a;
}
async function runFixture() {
  const out = [];
  let step;
  const it1 = q.iter();
  while (!(step = await it1.next()).done) out.push(step.value);
  const it2 = withArgs(7, 8);
  while (!(step = await it2.next()).done) out.push(step.value);
  return out;
}
`,
  },
  {
    id: 'nested-sync-generator-untouched',
    note: 'ENG-23124 #4a: a sync `function*` nested in an async generator keeps its own `yield`s (the old dead function-boundary guard rewrote them into `await _yield(...)` inside a sync generator — a parse error)',
    source: `
async function* outer() {
  function* inner() {
    yield 1;
    yield 2;
  }
  for (const v of inner()) {
    yield v * 10;
  }
}
async function runFixture() {
  const out = [];
  const it = outer();
  let step;
  while (!(step = await it.next()).done) out.push(step.value);
  return out;
}
`,
  },
  {
    id: 'nested-async-generator-transformed',
    note: 'ENG-23124 #4b: an `async function*` nested inside another is transformed too (fixpoint) — the old single pass left it verbatim and Hermes rejected the chunk',
    source: `
async function* outer() {
  async function* inner() {
    yield "a";
    yield "b";
  }
  yield* inner();
  yield "c";
}
async function runFixture() {
  const out = [];
  const it = outer();
  let step;
  while (!(step = await it.next()).done) out.push(step.value);
  return out;
}
`,
  },
  {
    id: 'yield-operand-awaited',
    note: 'ENG-23124 #5: AsyncGeneratorYield awaits the operand — consumers receive settled values (not {value: Promise}), operand rejection throws at the yield site, and return(promise) resolves to the settled value',
    source: `
async function* g() {
  yield Promise.resolve(41);
  try {
    yield Promise.reject(new Error("nope"));
  } catch (e) {
    yield "caught:" + e.message;
  }
}
async function* g2() {
  yield 1;
  yield 2;
}
async function runFixture() {
  const out = [];
  const it = g();
  out.push(await it.next());
  out.push(await it.next());
  out.push(await it.next());
  const it2 = g2();
  out.push(await it2.next());
  out.push(await it2.return(Promise.resolve(99)));
  return out;
}
`,
  },
  {
    id: 'throw-recoverable',
    note: 'ENG-23124 #6a: throw(err) resumes the body with a catchable throw completion — `try { yield } catch { yield "recovered" }` resolves {value:"recovered", done:false} instead of killing the generator',
    source: `
async function* g() {
  try {
    yield 1;
  } catch (e) {
    yield "recovered:" + e.message;
  }
  yield "after";
}
async function runFixture() {
  const it = g();
  const out = [];
  out.push(await it.next());
  out.push(await it.throw(new Error("x")));
  out.push(await it.next());
  out.push(await it.next());
  return out;
}
`,
  },
  {
    id: 'return-runs-finally-before-settling',
    note: 'ENG-23124 #6b: return(v) while suspended runs the body’s `finally` (including awaits inside it) to completion BEFORE the return() promise settles, then resolves {value:v, done:true}',
    source: `
const log = [];
async function* g() {
  try {
    yield 1;
    yield 2;
  } finally {
    await Promise.resolve();
    log.push("cleanup");
  }
}
async function runFixture() {
  const it = g();
  const first = await it.next();
  const second = await it.return(99);
  const finallyRanBeforeReturnSettled = log.length === 1;
  const third = await it.next();
  return { first, second, third, finallyRanBeforeReturnSettled };
}
`,
  },
  {
    id: 'return-catch-divergence',
    note: 'ENG-23124 #6c (pinned divergence): native return(v) resumes with a RETURN completion that skips `catch` blocks; the desugared body can only be resumed by resolve/reject, so a bare catch around a yield observes the abort sentinel and swallows the return value. Reproducing native semantics would need a state-machine rewrite of the body.',
    divergence: {
      oracle: '{"first":{"value":1,"done":false},"second":{"value":99,"done":true},"third":{"done":true},"log":["cleanup"]}',
      transformed: '{"first":{"value":1,"done":false},"second":{"done":true},"third":{"done":true},"log":["caught","cleanup"]}',
      note: 'catch runs on cancellation and the body then completes normally (undefined), so return() resolves {done:true} without the 99',
    },
    source: `
const log = [];
async function* g() {
  try {
    yield 1;
    yield 2;
  } catch (e) {
    log.push("caught");
  } finally {
    log.push("cleanup");
  }
}
async function runFixture() {
  const it = g();
  const first = await it.next();
  const second = await it.return(99);
  const third = await it.next();
  return { first, second, third, log };
}
`,
  },
]);

export default forOfScopingCorpus;
