// ENG-22970 — regression coverage for four correctness/perf bugs in core
// builtins (events / timers / readline / async-hooks). Each test requires the
// pure-JS builtin source directly and checks its behavior against Node's
// documented semantics. Run with: bun test.

import { expect, test, describe } from 'bun:test';
import { createRequire } from 'module';
import { EventEmitter as NodeEventEmitter } from 'node:events';

const require = createRequire(import.meta.url);

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Finding #1 — events.once() must scope its error-listener remover per call.
// A shared implicit global let the first once() to resolve rip out a *different*
// in-flight once()'s 'error' guard, turning that call's 'error' into an
// uncaught throw instead of a rejection.
// ---------------------------------------------------------------------------
describe('events.once() error-listener scoping (ENG-22970 #1)', () => {
  const Events = require('../../../src/builtins/events.js');

  test('resolving one once() does not strip another once()\'s error guard', async () => {
    const em1 = new Events.EventEmitter();
    const em2 = new Events.EventEmitter();

    const p1 = Events.once(em1, 'a');
    const p2 = Events.once(em2, 'b');
    // Keep p2 from becoming an unhandled rejection if the bug is present.
    p2.catch(() => {});

    em1.emit('a', 1);
    expect(await p1).toEqual([1]);

    // With the bug, p1's cleanup removed em2's 'error' listener, so this emit
    // would throw synchronously as an unhandled 'error' event. Fixed: em2 still
    // holds its own guard, so p2 rejects and emit() does not throw.
    const err = new Error('boom');
    let threw = false;
    try {
      em2.emit('error', err);
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);
    await expect(p2).rejects.toBe(err);
  });

  test('no implicit global leaked by once()', () => {
    const em = new Events.EventEmitter();
    const p = Events.once(em, 'x');
    em.emit('x');
    return p.then(() => {
      expect((globalThis as Record<string, unknown>).removeErrorListener).toBeUndefined();
    });
  });

  test('oracle: Node events.once rejects on error too', async () => {
    // Sanity anchor: Node's own once() rejects the promise on 'error'.
    const { once } = await import('node:events');
    const em = new NodeEventEmitter();
    const p = once(em, 'never');
    const err = new Error('x');
    em.emit('error', err);
    await expect(p).rejects.toBe(err);
  });
});

// ---------------------------------------------------------------------------
// ENG-24284 — with captureRejections disabled, EventEmitter must ignore a
// listener's return value completely. In particular it must not attach a
// second rejection observer to a Promise the application already handles, or
// even read a user-controlled thenable getter.
// ---------------------------------------------------------------------------
describe('events listener returns without captureRejections (ENG-24284)', () => {
  const Events = require('../../../src/builtins/events.js');

  test('a handled listener rejection is left to normal Promise tracking', async () => {
    const previousCaptureRejections = Events.EventEmitter.captureRejections;
    const previousExitCode = process.exitCode;
    Events.EventEmitter.captureRejections = false;
    const emitter = new Events.EventEmitter();
    const expected = new Error('handled-by-application');
    const shared = Promise.reject(expected);
    const handled = shared.catch((error: Error) => error);
    try {
      emitter.on('work', () => shared);
      expect(emitter.emit('work')).toBe(true);
      expect(await handled).toBe(expected);

      // Give the builtin's historical rejection observer enough turns to run.
      await Promise.resolve();
      await delay(0);
      expect(process.exitCode).toBe(previousExitCode);
    } finally {
      Events.EventEmitter.captureRejections = previousCaptureRejections;
      process.exitCode = previousExitCode;
    }
  });

  test('does not inspect a returned thenable when captureRejections is off', () => {
    const previousCaptureRejections = Events.EventEmitter.captureRejections;
    Events.EventEmitter.captureRejections = false;
    const emitter = new Events.EventEmitter();
    let thenReads = 0;
    const returned = Object.create(null, {
      then: {
        get() {
          thenReads++;
          throw new Error('listener return must be ignored');
        },
      },
    });

    try {
      emitter.on('work', () => returned);
      expect(() => emitter.emit('work')).not.toThrow();
      expect(thenReads).toBe(0);
    } finally {
      Events.EventEmitter.captureRejections = previousCaptureRejections;
    }
  });
});

// ---------------------------------------------------------------------------
// Finding #2 — timeout.refresh() must reactivate a timer whose callback has
// already fired (Node semantics), while a cleared/closed timer stays dead.
// ---------------------------------------------------------------------------
describe('timeout.refresh() after fire (ENG-22970 #2)', () => {
  const timers = require('../../../src/builtins/timers.js');

  test('refresh() reschedules a timer whose callback already fired', async () => {
    let count = 0;
    const t = timers.setTimeout(() => { count++; }, 20);

    await delay(60);
    expect(count).toBe(1);
    expect(t._destroyed).toBe(true); // fired

    // Node: "Using this on a timer that has already called its callback will
    // reactivate the timer." Before the fix this was a no-op.
    t.refresh();
    await delay(60);
    expect(count).toBe(2);

    // Still refreshable a second time.
    t.refresh();
    await delay(60);
    expect(count).toBe(3);

    timers.clearTimeout(t);
  });

  test('refresh() is a no-op after clearTimeout (stays dead)', async () => {
    let count = 0;
    const t = timers.setTimeout(() => { count++; }, 20);
    timers.clearTimeout(t);
    t.refresh(); // must NOT reactivate a cleared timer
    await delay(60);
    expect(count).toBe(0);
  });

  test('oracle: Node setTimeout refresh() re-fires', async () => {
    let count = 0;
    const t = setTimeout(() => { count++; }, 20);
    await delay(50);
    expect(count).toBe(1);
    t.refresh();
    await delay(50);
    expect(count).toBe(2);
    clearTimeout(t);
  });
});

// ---------------------------------------------------------------------------
// Finding #3 — readline async iterator needs return() (to close the interface
// and detach listeners on break) and must not clobber concurrent next() calls.
// ---------------------------------------------------------------------------
describe('readline async iterator (ENG-22970 #3)', () => {
  const readline = require('../../../src/builtins/readline.js');

  function makeInput() {
    const input = new NodeEventEmitter() as NodeEventEmitter & {
      resume: () => void; pause: () => void;
    };
    input.resume = () => {};
    input.pause = () => {};
    return input;
  }

  test('return() closes the interface and detaches its listeners', async () => {
    const input = makeInput();
    const rl = readline.createInterface({ input, terminal: false });
    const it = rl[Symbol.asyncIterator]();

    input.emit('data', 'one\ntwo\n');

    const r1 = await it.next();
    expect(r1).toEqual({ value: 'one', done: false });

    // Simulate `break` out of `for await`.
    const ret = await it.return();
    expect(ret).toEqual({ value: undefined, done: true });

    expect(rl.closed).toBe(true);
    expect(rl.listenerCount('line')).toBe(0);
    expect(rl.listenerCount('close')).toBe(0);

    // Further next() calls report done, not a hung promise or fresh line.
    expect(await it.next()).toEqual({ value: undefined, done: true });
  });

  test('for await ... break closes the interface', async () => {
    const input = makeInput();
    const rl = readline.createInterface({ input, terminal: false });

    const collected: string[] = [];
    const loop = (async () => {
      for await (const line of rl) {
        collected.push(line);
        if (collected.length === 1) break;
      }
    })();

    // Let the loop attach its listeners, then feed lines.
    await delay(0);
    input.emit('data', 'alpha\nbeta\n');
    await loop;

    expect(collected).toEqual(['alpha']);
    expect(rl.closed).toBe(true);
  });

  test('concurrent next() calls are not clobbered', async () => {
    const input = makeInput();
    const rl = readline.createInterface({ input, terminal: false });
    const it = rl[Symbol.asyncIterator]();

    // Two next() calls before any data: with the old single-slot resolver the
    // first promise would never settle (Promise.all would hang -> test timeout).
    const pA = it.next();
    const pB = it.next();
    input.emit('data', 'x\ny\n');

    const [ra, rb] = await Promise.all([pA, pB]);
    expect(ra).toEqual({ value: 'x', done: false });
    expect(rb).toEqual({ value: 'y', done: false });

    await it.return();
    expect(rl.closed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Finding #4 — async-hooks fast path: with zero AsyncLocalStorage instances the
// promise/timer wrappers must be a no-op (perf), yet context propagation must
// still work once an instance exists. Requiring this module patches global
// Promise/setTimeout, so keep it last and lazily required.
// ---------------------------------------------------------------------------
describe('async-hooks fast path (ENG-22970 #4)', () => {
  test('promise chains resolve with zero ALS instances (fast path)', async () => {
    const ah = require('../../../src/builtins/async-hooks.js');
    expect(typeof ah.AsyncLocalStorage).toBe('function');

    // No instance created yet -> wrappers must return callbacks unwrapped and
    // ordinary resolution must be unaffected.
    let observed: unknown;
    await Promise.resolve('Z').then((v) => { observed = v; });
    expect(observed).toBe('Z');

    let timerRan = false;
    await new Promise<void>((r) => setTimeout(() => { timerRan = true; r(); }, 5));
    expect(timerRan).toBe(true);
  });

  test('context still propagates through explicit .then when an instance exists', async () => {
    const ah = require('../../../src/builtins/async-hooks.js');
    const als = new ah.AsyncLocalStorage();
    try {
      let seen: unknown;
      als.run('S', () => {
        Promise.resolve().then(() => { seen = als.getStore(); });
      });
      await delay(10);
      expect(seen).toBe('S');
    } finally {
      als.disable();
    }
  });
});
