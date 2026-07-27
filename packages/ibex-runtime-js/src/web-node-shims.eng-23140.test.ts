// ENG-23140 — regression coverage for the web-polyfill / node-shim round-3
// fixes:
//   1.  process.kill signal names map through a platform-branched table
//       (Darwin numbers on Darwin; the old Linux-only table sent SIGBUS for
//       'SIGUSR1'), shared with binding('constants').os.signals.
//   2.  The fallback nextTick drain survives a throwing tick: the error is
//       routed to uncaughtException handling and the rest of the queue runs.
//       nextTick(nonFunction) throws at the call site.
//   3.  process.title has a setter (strict-mode `process.title = ...` no
//       longer throws) and validates strings.
//   4.  A throwing process.once() handler does not re-fire on the next emit.
//   5.  process.stdout/stderr.write passes Uint8Array/Buffer chunks through
//       as raw bytes instead of UTF-8-mangling them.
//   6.  path.basename keeps a dotfile name equal to the suffix.
//   7.  Buffer#toString('utf8') restores the decoder-stripped BOM even when
//       the content itself starts with U+FEFF.
//   8.  structuredClone throws DataCloneError for Promise/WeakMap/WeakSet and
//       detached ArrayBuffers, clones boxed primitives, preserves array holes
//       and non-index properties, and neuters unreachable transferables.
//   9.  Intl.Collator#compare works detached; Intl.PluralRules ru/pl/ar
//       return 'other' for fractional values.
//   10. performance.measure honors { end, duration }.
//   11. The fallback rejection tracker sees `new Promise(() => { throw e })`.
//   12. fetch's timeout-option signal context keeps the source-signal
//       forwarder alive while a streaming body is live.
//   13. readline question({signal}) drops its abort listener when the
//       interface closes first.
//   14. events.js emits MaxListenersExceededWarning via process.emitWarning.
//
// Run with: bun test.

import { expect, test, describe, beforeAll, afterAll } from 'bun:test';
import { createRequire } from 'module';
import os from 'os';
import { EventEmitter as NodeEventEmitter } from 'node:events';

import {
  process as shimProcess,
  signalNameToNumberMap,
  _drainNextTickQueue,
  _enqueueNextTickForTesting,
} from './node/process';
import { basename } from './node/path';
import { Buffer as ShimBuffer } from './node/Buffer';
import { structuredClone as shimStructuredClone } from './clone/structuredClone';
import { structuredCloneTransferSymbol } from './clone/transferableSymbols';
import { installIntlPolyfills } from './polyfills/intl';
import { Performance } from './performance/Performance';
import {
  installPromiseRejectionTracking,
  getUnhandledRejections,
} from './promise-rejection-tracking';
import { createEffectiveSignal, createSocketResponseBodyStream } from './fetch/fetch';

const g = globalThis as Record<string, any>;
const require = createRequire(import.meta.url);

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// Finding 1 — platform-branched signal numbering
// ---------------------------------------------------------------------------
describe('process.kill signal table (ENG-23140 #1)', () => {
  test('the Darwin table matches os.constants.signals on this host', () => {
    // Node's own table is the oracle for Darwin numbers (CI/dev boxes are
    // macOS; on Linux this compares the Linux table instead, same invariant).
    const oracle = os.constants.signals as Record<string, number>;
    const table = signalNameToNumberMap(process.platform);
    for (const name of Object.keys(table)) {
      if (name in oracle) {
        expect(`${name}=${table[name]}`).toBe(`${name}=${oracle[name]}`);
      }
    }
  });

  test('the previously-mismapped signals differ per platform', () => {
    const darwin = signalNameToNumberMap('darwin');
    const linux = signalNameToNumberMap('linux');
    expect(darwin.SIGUSR1).toBe(30); // Linux table said 10 (= Darwin SIGBUS)
    expect(darwin.SIGUSR2).toBe(31);
    expect(darwin.SIGBUS).toBe(10);
    expect(linux.SIGUSR1).toBe(10);
    expect(linux.SIGBUS).toBe(7);
    // Android runs a Linux kernel.
    expect(signalNameToNumberMap('android')).toEqual(linux);
  });

  test("binding('constants').os.signals agrees with the kill() table", () => {
    const constants = (shimProcess as any).binding('constants') as {
      os: { signals: Record<string, number> };
    };
    expect(constants.os.signals).toEqual(signalNameToNumberMap(shimProcess.platform));
  });

  test('a leaked host-native map never rewrites a foreign platform table', () => {
    // Loading builtins/child-process.js publishes the HOST's table as
    // globalThis.__exactSignalNumbersMap (shared bun test process), which on
    // Linux CI turned signalNameToNumberMap('darwin') into Linux numbers.
    // The native override may only refine the host platform's own table.
    const saved = g.__exactSignalNumbersMap;
    try {
      g.__exactSignalNumbersMap = { SIGUSR1: 999, SIGBUS: 998 };
      expect(signalNameToNumberMap('darwin').SIGUSR1).toBe(
        process.platform === 'darwin' ? 999 : 30
      );
      expect(signalNameToNumberMap('linux').SIGUSR1).toBe(
        process.platform === 'linux' ? 999 : 10
      );
    } finally {
      if (saved === undefined) delete g.__exactSignalNumbersMap;
      else g.__exactSignalNumbersMap = saved;
    }
  });
});

// ---------------------------------------------------------------------------
// Finding 2 — nextTick fallback drain
// ---------------------------------------------------------------------------
describe('nextTick fallback drain (ENG-23140 #2)', () => {
  test('a throwing tick routes to uncaughtException and later ticks still run', () => {
    const boom = new Error('tick-boom');
    const caught: unknown[] = [];
    const order: string[] = [];
    const handler = (error: unknown) => {
      caught.push(error);
    };
    shimProcess.on('uncaughtException', handler);
    try {
      _enqueueNextTickForTesting(() => {
        order.push('first');
        throw boom;
      });
      _enqueueNextTickForTesting(() => {
        order.push('second');
      });
      // The drain itself must not throw (a throw here is what used to reject
      // an unrelated promise chain and drop the queue).
      expect(() => _drainNextTickQueue()).not.toThrow();
    } finally {
      shimProcess.removeListener('uncaughtException', handler);
    }
    expect(order).toEqual(['first', 'second']);
    expect(caught).toEqual([boom]);
  });

  test('nextTick(nonFunction) throws ERR_INVALID_ARG_TYPE at the call site', () => {
    let err: any;
    try {
      (shimProcess as any).nextTick(42);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TypeError);
    expect(err.code).toBe('ERR_INVALID_ARG_TYPE');
  });
});

// ---------------------------------------------------------------------------
// Finding 3 — process.title setter
// ---------------------------------------------------------------------------
describe('process.title (ENG-23140 #3)', () => {
  test('assignment works (strict-mode code no longer throws) and validates', () => {
    const original = shimProcess.title;
    try {
      shimProcess.title = 'my-app';
      expect(shimProcess.title).toBe('my-app');
      expect(() => {
        (shimProcess as any).title = 42;
      }).toThrow(TypeError);
      expect(shimProcess.title).toBe('my-app');
    } finally {
      shimProcess.title = original;
    }
  });
});

// ---------------------------------------------------------------------------
// Finding 4 — throwing once() handler must not double-fire
// ---------------------------------------------------------------------------
describe('process once() with throwing handler (ENG-23140 #4)', () => {
  test('the handler is pruned before invocation, so it fires exactly once', () => {
    let calls = 0;
    shimProcess.once('eng23140-test-event', () => {
      calls += 1;
      throw new Error('handler-boom');
    });
    expect(() => shimProcess.emit('eng23140-test-event')).toThrow('handler-boom');
    // Old behavior: the throw skipped the listener-list rewrite, so the same
    // once-handler fired again here.
    expect(shimProcess.emit('eng23140-test-event')).toBe(false);
    expect(calls).toBe(1);
  });

  test('listeners added during emit do not run in the same emit (Node semantics)', () => {
    const order: string[] = [];
    const late = () => order.push('late');
    shimProcess.once('eng23140-add-during-emit', () => {
      order.push('first');
      shimProcess.once('eng23140-add-during-emit', late);
    });
    shimProcess.emit('eng23140-add-during-emit');
    expect(order).toEqual(['first']);
    shimProcess.emit('eng23140-add-during-emit');
    expect(order).toEqual(['first', 'late']);
  });
});

// ---------------------------------------------------------------------------
// Finding 5 — binary stdout/stderr writes
// ---------------------------------------------------------------------------
describe('process.stdout binary write (ENG-23140 #5)', () => {
  test('Uint8Array chunks reach the native write as raw bytes', () => {
    const written: Array<{ fd: number; data: unknown }> = [];
    const prior = g.__exactFsWrite;
    g.__exactFsWrite = (fd: number, data: unknown, _pos: number) => {
      written.push({ fd, data });
      return typeof data === 'string' ? data.length : (data as Uint8Array).byteLength;
    };
    try {
      const jpegMagic = new Uint8Array([0xff, 0xd8, 0xff, 0xe0]);
      shimProcess.stdout.write(jpegMagic);
      shimProcess.stdout.write('plain text');
      expect(written).toHaveLength(2);
      // The old path UTF-8-decoded the bytes (0xff -> U+FFFD) before native
      // re-encoded them; the chunk must now arrive as the same raw bytes.
      expect(written[0].data).toBeInstanceOf(Uint8Array);
      expect(Array.from(written[0].data as Uint8Array)).toEqual([0xff, 0xd8, 0xff, 0xe0]);
      expect(written[1].data).toBe('plain text');
    } finally {
      if (prior === undefined) {
        delete g.__exactFsWrite;
      } else {
        g.__exactFsWrite = prior;
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Finding 6 — path.basename dotfiles
// ---------------------------------------------------------------------------
describe('path.basename suffix handling (ENG-23140 #6)', () => {
  test('a basename equal to the suffix is returned unchanged (Node behavior)', () => {
    expect(basename('/dir/.txt', '.txt')).toBe('.txt');
    expect(basename('.txt', '.txt')).toBe('.txt');
  });

  test('a proper suffix is still stripped', () => {
    expect(basename('/foo/bar/baz.txt', '.txt')).toBe('baz');
    expect(basename('abcabc', 'abc')).toBe('abc');
  });
});

// ---------------------------------------------------------------------------
// Finding 7 — Buffer UTF-8 BOM restore
// ---------------------------------------------------------------------------
describe("Buffer#toString('utf8') BOM handling (ENG-23140 #7)", () => {
  test('a single encoded BOM is preserved', () => {
    const buf = ShimBuffer.from([0xef, 0xbb, 0xbf, 0x61]);
    expect(buf.toString('utf8')).toBe('\uFEFFa');
  });

  test('double encoded BOMs both survive (the old guard dropped one)', () => {
    const buf = ShimBuffer.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, 0x61]);
    expect(buf.toString('utf8')).toBe('\uFEFF\uFEFFa');
  });

  test('content without a BOM is untouched', () => {
    expect(ShimBuffer.from([0x61, 0x62]).toString('utf8')).toBe('ab');
  });
});

// ---------------------------------------------------------------------------
// Finding 8 — structuredClone spec semantics
// ---------------------------------------------------------------------------
describe('structuredClone DataCloneError + array/boxed semantics (ENG-23140 #8)', () => {
  const expectDataCloneError = (fn: () => unknown) => {
    let err: any;
    try {
      fn();
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.name).toBe('DataCloneError');
  };

  test('Promise / WeakMap / WeakSet throw DataCloneError instead of cloning to {}', () => {
    expectDataCloneError(() => shimStructuredClone(Promise.resolve(1)));
    expectDataCloneError(() => shimStructuredClone(new WeakMap()));
    expectDataCloneError(() => shimStructuredClone(new WeakSet()));
    expectDataCloneError(() => shimStructuredClone({ nested: new WeakMap() }));
  });

  test('boxed primitives clone as boxed primitives (per spec), not {}', () => {
    const num = shimStructuredClone(new Number(5)) as Number;
    expect(num).toBeInstanceOf(Number);
    expect(num.valueOf()).toBe(5);
    const str = shimStructuredClone(new String('hi')) as String;
    expect(str).toBeInstanceOf(String);
    expect(str.valueOf()).toBe('hi');
    const bool = shimStructuredClone(new Boolean(true)) as Boolean;
    expect(bool).toBeInstanceOf(Boolean);
    expect(bool.valueOf()).toBe(true);
  });

  test('arrays keep holes and own non-index properties', () => {
    const source: any[] = [1, , 3]; // eslint-disable-line no-sparse-arrays
    source.meta = 'kept';
    const clone = shimStructuredClone(source) as any[];
    expect(clone.length).toBe(3);
    expect(1 in clone).toBe(false); // hole stays a hole
    expect(clone[0]).toBe(1);
    expect(clone[2]).toBe(3);
    expect((clone as any).meta).toBe('kept');
  });

  test('a detached (already-transferred) ArrayBuffer throws DataCloneError', () => {
    const buffer = new ArrayBuffer(8);
    const clone = shimStructuredClone(buffer, { transfer: [buffer] });
    expect(clone.byteLength).toBe(8);
    expect(buffer.byteLength).toBe(0); // original was detached
    // Double transfer: DataCloneError, not a silent empty-buffer clone.
    expectDataCloneError(() => shimStructuredClone(buffer, { transfer: [buffer] }));
    // Cloning the detached buffer at all is also an error.
    expectDataCloneError(() => shimStructuredClone(buffer));
    expectDataCloneError(() => shimStructuredClone({ buf: buffer }));
  });

  test('transferables unreachable from the value are still neutered', () => {
    let transferCalls = 0;
    const transferable = {
      [structuredCloneTransferSymbol]() {
        transferCalls += 1;
        return {};
      },
    };
    const result = shimStructuredClone({ hello: 'world' }, { transfer: [transferable as any] });
    expect(result).toEqual({ hello: 'world' });
    expect(transferCalls).toBe(1);
  });

  test('reachable transferables are transferred exactly once', () => {
    let transferCalls = 0;
    const transferable = {
      [structuredCloneTransferSymbol]() {
        transferCalls += 1;
        return { transferred: true };
      },
    };
    const result = shimStructuredClone({ port: transferable }, { transfer: [transferable as any] }) as any;
    expect(result.port).toEqual({ transferred: true });
    expect(transferCalls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Finding 9 — Intl.Collator detached compare / PluralRules fractions
// ---------------------------------------------------------------------------
describe('Intl polyfills (ENG-23140 #9)', () => {
  let dCollator: PropertyDescriptor | undefined;
  let dPluralRules: PropertyDescriptor | undefined;
  // Oracles captured from the native implementations we are about to remove.
  let nativeNumericSort: string[];
  const nativeFractional: Record<string, string> = {};

  beforeAll(() => {
    nativeNumericSort = ['a10', 'a2'].sort(new Intl.Collator('en', { numeric: true }).compare);
    for (const locale of ['ru', 'pl', 'ar']) {
      nativeFractional[locale] = new Intl.PluralRules(locale).select(1.5);
    }

    dCollator = Object.getOwnPropertyDescriptor(Intl, 'Collator');
    dPluralRules = Object.getOwnPropertyDescriptor(Intl, 'PluralRules');
    delete (Intl as any).Collator;
    delete (Intl as any).PluralRules;
    installIntlPolyfills();
  });

  afterAll(() => {
    if (dCollator) Object.defineProperty(Intl, 'Collator', dCollator);
    if (dPluralRules) Object.defineProperty(Intl, 'PluralRules', dPluralRules);
  });

  test('detached collator.compare keeps locale and options (the canonical sort idiom)', () => {
    const collator = new Intl.Collator('en', { numeric: true });
    const detached = collator.compare;
    expect(['a10', 'a2'].sort(detached)).toEqual(nativeNumericSort);
    expect(nativeNumericSort).toEqual(['a2', 'a10']);
  });

  test('PluralRules ru/pl/ar match native for fractional values', () => {
    for (const locale of ['ru', 'pl', 'ar']) {
      expect(`${locale}:${new Intl.PluralRules(locale).select(1.5)}`).toBe(
        `${locale}:${nativeFractional[locale]}`,
      );
    }
    // The concrete expectation, so the test cannot pass vacuously:
    expect(nativeFractional).toEqual({ ru: 'other', pl: 'other', ar: 'other' });
  });

  test('PluralRules ru/pl/ar integer categories are unchanged', () => {
    const ru = new Intl.PluralRules('ru');
    expect(ru.select(1)).toBe('one');
    expect(ru.select(2)).toBe('few');
    expect(ru.select(5)).toBe('many');
    const pl = new Intl.PluralRules('pl');
    expect(pl.select(1)).toBe('one');
    expect(pl.select(2)).toBe('few');
    const ar = new Intl.PluralRules('ar');
    expect(ar.select(0)).toBe('zero');
    expect(ar.select(2)).toBe('two');
    expect(ar.select(11)).toBe('many');
  });
});

// ---------------------------------------------------------------------------
// Finding 10 — performance.measure duration option
// ---------------------------------------------------------------------------
describe('performance.measure options (ENG-23140 #10)', () => {
  test('{ end, duration } measures backwards from end (was silently 0-based)', () => {
    const perf = new Performance();
    const measure = perf.measure('m', { end: 100, duration: 40 });
    expect(measure.startTime).toBe(60);
    expect(measure.duration).toBe(40);
  });

  test('{ start, duration } still measures forwards', () => {
    const perf = new Performance();
    const measure = perf.measure('m', { start: 10, duration: 5 });
    expect(measure.startTime).toBe(10);
    expect(measure.duration).toBe(5);
  });

  test('start + end + duration together throw TypeError (User Timing spec)', () => {
    const perf = new Performance();
    expect(() => perf.measure('m', { start: 0, end: 10, duration: 5 })).toThrow(TypeError);
  });
});

// ---------------------------------------------------------------------------
// Finding 11 — rejection tracker sees throwing executors
// ---------------------------------------------------------------------------
describe('promise rejection tracking executor wrap (ENG-23140 #11)', () => {
  let OriginalPromise: PromiseConstructor;

  beforeAll(() => {
    OriginalPromise = g.Promise;
    // Bun has no __exactOnUnhandledRejection hook, so this installs the
    // userland polyfill path (wrapped constructor + then/catch tracking).
    installPromiseRejectionTracking();
  });

  afterAll(() => {
    // Restore the constructor. The prototype then/catch wrappers remain but
    // are semantically transparent (they delegate to the originals).
    g.Promise = OriginalPromise;
  });

  test('keeps the unwrapped Promise constructor off globalThis', () => {
    expect('__OriginalPromise' in g).toBe(false);
  });

  test('the wrapped Promise constructor cannot be called without new', () => {
    const shell = Object.create(g.Promise.prototype);
    expect(() => g.Promise.call(shell, () => {})).toThrow(
      'Promises must be constructed via new',
    );
  });

  // Observe the tracker's pending-unhandled map directly (the ENG-22985 test
  // pattern) rather than letting the rejection stay unhandled long enough for
  // the event dispatch: Bun's test runner fails any test with a genuinely
  // unhandled rejection, so we sample the map one microtask after creation
  // (after the tracker's own check microtask) and then attach a handler.
  function sampleTracker(factory: (P: PromiseConstructor) => Promise<unknown>): Promise<{
    tracked: boolean;
    reason: unknown;
    promise: Promise<unknown>;
  }> {
    const WrappedPromise = g.Promise as PromiseConstructor;
    const p = factory(WrappedPromise);
    return new Promise((resolveSample) => {
      queueMicrotask(() => {
        const pending = getUnhandledRejections();
        const tracked = pending.has(p);
        const reason = pending.get(p);
        // Handle it now: silences the pending 'unhandledrejection' dispatch
        // and satisfies Bun's unhandled-rejection detector.
        p.catch(() => {});
        resolveSample({ tracked, reason, promise: p });
      });
    });
  }

  test('new Promise(() => { throw e }) is tracked as an unhandled rejection', async () => {
    const boom = new Error('executor-throw');
    const sample = await sampleTracker(
      (P) =>
        new P(() => {
          throw boom;
        }),
    );
    // Old behavior: the native constructor converted the throw via its
    // INTERNAL reject, invisible to the tracker — `tracked` was false and the
    // rejection vanished from unhandledrejection reporting entirely.
    expect(sample.tracked).toBe(true);
    expect(sample.reason).toBe(boom);
  });

  test('an executor that resolves then throws is NOT tracked (native semantics)', async () => {
    const sample = await sampleTracker(
      (P) =>
        new P<number>((resolve) => {
          resolve(1);
          throw new Error('ignored-after-resolve');
        }) as Promise<unknown>,
    );
    expect(sample.tracked).toBe(false);
    expect(await sample.promise).toBe(1);
  });

  test('a synchronous rejection with a null reason is still tracked', async () => {
    const sample = await sampleTracker(
      (P) =>
        new P((_resolve, reject) => {
          reject(null);
        }),
    );
    // The old `pendingReject !== null` sentinel dropped null/undefined reasons.
    expect(sample.tracked).toBe(true);
    expect(sample.reason).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Finding 12 — fetch timeout-option signal context
// ---------------------------------------------------------------------------
describe('fetch createEffectiveSignal forwarding (ENG-23140 #12)', () => {
  test('cleanup({ keepAbortForwarding: true }) keeps user aborts flowing (streaming body case)', () => {
    const source = new AbortController();
    const ctx = createEffectiveSignal(source.signal, 60_000);
    // fetch() returned a streaming response; its finally runs cleanup with
    // keepAbortForwarding.
    ctx.cleanup({ keepAbortForwarding: true });
    expect(ctx.signal!.aborted).toBe(false);
    source.abort(new Error('user-abort'));
    // Old behavior: cleanup had removed the forwarder, so this stayed false
    // and the body-read abort wiring never fired.
    expect(ctx.signal!.aborted).toBe(true);
  });

  test('default cleanup() detaches the forwarder (buffered response case)', () => {
    const source = new AbortController();
    const ctx = createEffectiveSignal(source.signal, 60_000);
    ctx.cleanup();
    source.abort();
    expect(ctx.signal!.aborted).toBe(false);
  });

  test('release() detaches and is idempotent', () => {
    const source = new AbortController();
    const ctx = createEffectiveSignal(source.signal, 60_000);
    ctx.release();
    ctx.release();
    source.abort();
    expect(ctx.signal!.aborted).toBe(false);
    ctx.cleanup();
  });

  test('the timeout still aborts with TimeoutError', async () => {
    const ctx = createEffectiveSignal(undefined, 5);
    await delay(30);
    expect(ctx.signal!.aborted).toBe(true);
    expect((ctx.signal!.reason as DOMException).name).toBe('TimeoutError');
  });

  test('socket body stream reports settlement so the forwarder can be released', () => {
    let settled = 0;
    const sourceStream = new NodeEventEmitter() as NodeEventEmitter & {
      destroy: () => void;
      resume: () => void;
      pause: () => void;
    };
    sourceStream.destroy = () => {};
    sourceStream.resume = () => {};
    sourceStream.pause = () => {};
    const stream = createSocketResponseBodyStream(
      sourceStream,
      [],
      undefined,
      (specifier: string) => require(specifier),
      null,
      () => {
        settled += 1;
      },
    );
    stream.cancel(new Error('consumer done'));
    expect(settled).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Finding 13 — readline question({signal}) listener leak on close()
// ---------------------------------------------------------------------------
describe('readline question abort-listener cleanup (ENG-23140 #13)', () => {
  const readline = require('../../../src/builtins/readline.js');

  function makeInput() {
    const input = new NodeEventEmitter() as NodeEventEmitter & {
      resume: () => void;
      pause: () => void;
    };
    input.resume = () => {};
    input.pause = () => {};
    return input;
  }

  function makeTrackingSignal() {
    const listeners: Array<(...args: unknown[]) => void> = [];
    return {
      aborted: false,
      listeners,
      addEventListener(_type: string, fn: (...args: unknown[]) => void) {
        listeners.push(fn);
      },
      removeEventListener(_type: string, fn: (...args: unknown[]) => void) {
        const index = listeners.indexOf(fn);
        if (index !== -1) listeners.splice(index, 1);
      },
    };
  }

  test('closing the interface before the question resolves removes the abort listener', () => {
    const signal = makeTrackingSignal();
    // output: null — the builtin defaults absent output to process.stdout
    // (readline.js:548), which spams the prompt into the test runner's log.
    const rl = readline.createInterface({ input: makeInput(), output: null, terminal: false });
    rl.question('q? ', { signal }, () => {});
    expect(signal.listeners).toHaveLength(1);
    rl.close();
    // Old behavior: the listener stayed on the (possibly shared, long-lived)
    // signal forever — unbounded growth across interface lifecycles.
    expect(signal.listeners).toHaveLength(0);
  });

  test('an answered question also removes the abort listener', () => {
    const signal = makeTrackingSignal();
    const input = makeInput();
    const rl = readline.createInterface({ input, output: null, terminal: false });
    const answers: string[] = [];
    rl.question('q? ', { signal }, (answer: string) => answers.push(answer));
    expect(signal.listeners).toHaveLength(1);
    input.emit('data', 'hello\n');
    expect(answers).toEqual(['hello']);
    expect(signal.listeners).toHaveLength(0);
    rl.close();
  });
});

// ---------------------------------------------------------------------------
// Finding 14 — MaxListenersExceededWarning is actually emitted
// ---------------------------------------------------------------------------
describe('events MaxListenersExceededWarning (ENG-23140 #14)', () => {
  const { EventEmitter } = require('../../../src/builtins/events.js');

  test('exceeding maxListeners emits the warning through process.emitWarning', () => {
    const warnings: any[] = [];
    const originalEmitWarning = process.emitWarning;
    (process as any).emitWarning = (warning: any) => {
      warnings.push(warning);
    };
    try {
      const emitter = new EventEmitter();
      for (let i = 0; i < 11; i += 1) {
        emitter.on('data', () => {});
      }
      expect(warnings).toHaveLength(1);
      expect(warnings[0].name).toBe('MaxListenersExceededWarning');
      expect(warnings[0].type).toBe('data');
      expect(warnings[0].count).toBe(11);
      expect(warnings[0].emitter).toBe(emitter);
      // The warned flag still prevents repeats.
      emitter.on('data', () => {});
      expect(warnings).toHaveLength(1);
    } finally {
      (process as any).emitWarning = originalEmitWarning;
    }
  });
});
