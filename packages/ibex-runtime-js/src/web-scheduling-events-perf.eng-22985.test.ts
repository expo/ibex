// ENG-22985 — web events / scheduling / performance audit fixes.
//
// Covers the nine findings:
//   1. dispatchEvent must NOT reset the canceled (defaultPrevented) flag, and
//      re-dispatching an in-flight Event throws InvalidStateError.
//   2. AbortSignal "abort" listener is unregistered when the target listener is
//      removed / a once-listener fires (no per-render leak).
//   3. A reported unhandled rejection is evicted from the strong Map.
//   4. cancelAnimationFrame from a same-frame callback prevents the later frame.
//   5. Idle callbacks scheduled from an idle callback wait for the NEXT period.
//   6. Per-callback idle timeout timers are cancelled (not leaked).
//   7. Fallback clearTimeout/clearInterval are interchangeable (shared list).
//   8. `new Performance()` (not just the singleton) can addEventListener.
//   9. The performance timeline is bounded and getEntries stays sorted.
//
// Run with: bun test src/web-scheduling-events-perf.eng-22985.test.ts

import { expect, test } from 'bun:test';

import { Event } from './events/Event';
import { EventTarget } from './events/EventTarget';
import {
  trackPromiseRejection,
  trackPromiseRejectionHandled,
  getUnhandledRejections,
  resetPromiseRejectionTracking,
} from './promise-rejection-tracking';
import { requestAnimationFrame, cancelAnimationFrame } from './scheduling/AnimationFrame';
import { requestIdleCallback, cancelIdleCallback } from './scheduling/IdleCallback';
import {
  setTimeout as ibexSetTimeout,
  clearTimeout as ibexClearTimeout,
  setInterval as ibexSetInterval,
  clearInterval as ibexClearInterval,
} from './timers/Timers';
import { Performance } from './performance/Performance';

const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function abortListenerCount(signal: EventTarget): number {
  const map = (signal as unknown as { _listeners?: Map<string, { removed: boolean }[]> })._listeners;
  const list = map?.get('abort');
  return list ? list.filter((l) => !l.removed).length : 0;
}

// ---------------------------------------------------------------------------
// Finding 1 — Event canceled flag / re-dispatch
// ---------------------------------------------------------------------------

test('defaultPrevented persists after dispatchEvent returns', () => {
  const et = new EventTarget();
  et.addEventListener('x', (e) => e.preventDefault());

  const e = new Event('x', { cancelable: true });
  const notCanceled = et.dispatchEvent(e);

  expect(notCanceled).toBe(false);
  // Bug pre-fix: _resetFlags() cleared this to false at end of dispatch, so the
  // common `if (e.defaultPrevented)` follow-up wrongly ran the default action.
  expect(e.defaultPrevented).toBe(true);
});

test('the canceled flag persists across sequential re-dispatch', () => {
  const et = new EventTarget();
  et.addEventListener('x', (e) => e.preventDefault());

  const e = new Event('x', { cancelable: true });
  expect(et.dispatchEvent(e)).toBe(false);
  // A second, sequential dispatch is allowed (dispatch flag cleared) and the
  // canceled flag from the first dispatch still holds.
  expect(et.dispatchEvent(e)).toBe(false);
  expect(e.defaultPrevented).toBe(true);
});

test('re-dispatching an in-flight Event throws InvalidStateError without clobbering outer flags', () => {
  const et = new EventTarget();
  let threw = false;
  let secondRan = false;

  et.addEventListener('x', (e) => {
    e.preventDefault();
    e.stopImmediatePropagation();
    try {
      et.dispatchEvent(e); // event is already being dispatched
    } catch (err) {
      threw = true;
      expect((err as { name?: string }).name).toBe('InvalidStateError');
    }
  });
  et.addEventListener('x', () => {
    secondRan = true;
  });

  const e = new Event('x', { cancelable: true });
  const ret = et.dispatchEvent(e);

  expect(threw).toBe(true);
  // stopImmediatePropagation set before the (failed) re-dispatch is preserved.
  expect(secondRan).toBe(false);
  // defaultPrevented set before the (failed) re-dispatch is preserved.
  expect(ret).toBe(false);
  expect(e.defaultPrevented).toBe(true);
});

// ---------------------------------------------------------------------------
// Finding 2 — AbortSignal listener leak
// ---------------------------------------------------------------------------

test('removeEventListener unregisters the abort listener on the signal', () => {
  const target = new EventTarget();
  // A plain EventTarget is a valid stand-in signal: it exposes
  // add/removeEventListener and has a falsy `aborted`.
  const signal = new EventTarget();
  const cb = () => {};

  target.addEventListener('click', cb, { signal });
  expect(abortListenerCount(signal)).toBe(1);

  target.removeEventListener('click', cb);
  // Bug pre-fix: the removeOnAbort closure stayed on the signal, retaining
  // `target` until the signal aborted (possibly never).
  expect(abortListenerCount(signal)).toBe(0);
});

test('a once listener firing unregisters its abort listener on the signal', () => {
  const target = new EventTarget();
  const signal = new EventTarget();

  target.addEventListener('click', () => {}, { signal, once: true });
  expect(abortListenerCount(signal)).toBe(1);

  target.dispatchEvent(new Event('click'));
  expect(abortListenerCount(signal)).toBe(0);
});

// ---------------------------------------------------------------------------
// Finding 3 — unhandled rejection eviction
// ---------------------------------------------------------------------------

test('a reported unhandled rejection is evicted from the strong map', async () => {
  resetPromiseRejectionTracking();
  const origError = console.error;
  console.error = () => {};
  try {
    const key = Promise.resolve(); // harmless object used only as a Map key
    trackPromiseRejection(key as unknown as Promise<unknown>, new Error('boom'));

    // Pending until the deferred microtask reports it.
    expect(getUnhandledRejections().has(key as unknown as Promise<unknown>)).toBe(true);

    await Promise.resolve();
    await Promise.resolve();

    // Bug pre-fix: the entry was never deleted, retaining the promise + reason
    // (often an Error with a big context graph) for the life of the runtime.
    expect(getUnhandledRejections().has(key as unknown as Promise<unknown>)).toBe(false);

    // A later handler must not throw and leaves the strong map empty.
    trackPromiseRejectionHandled(key as unknown as Promise<unknown>);
    await Promise.resolve();
    expect(getUnhandledRejections().size).toBe(0);
  } finally {
    console.error = origError;
    resetPromiseRejectionTracking();
  }
});

// ---------------------------------------------------------------------------
// Finding 4 — cancelAnimationFrame from a same-frame callback
// ---------------------------------------------------------------------------

test('cancelAnimationFrame from a same-frame callback prevents the later callback', async () => {
  (globalThis as { __exactDisplayLinkedEventLoop?: boolean }).__exactDisplayLinkedEventLoop = true;
  try {
    const ran: string[] = [];
    let id2 = 0;
    requestAnimationFrame(() => {
      ran.push('1');
      cancelAnimationFrame(id2);
    });
    id2 = requestAnimationFrame(() => {
      ran.push('2');
    });

    await wait(20);
    // Bug pre-fix: runCallbacks snapshotted+cleared the map, so the cancel
    // couldn't reach id2 and '2' still ran.
    expect(ran).toEqual(['1']);
  } finally {
    delete (globalThis as { __exactDisplayLinkedEventLoop?: boolean }).__exactDisplayLinkedEventLoop;
  }
});

test('a frame requested from within a frame callback runs in the next frame', async () => {
  // Real ~16ms frames (no display-linked 0ms delay) so successive frames are
  // separated in time; the callback for 'b' is requested during 'a's frame.
  const order: string[] = [];
  requestAnimationFrame(() => {
    order.push('a');
    requestAnimationFrame(() => order.push('b'));
  });

  // Poll until the first frame runs, then assert 'b' has NOT run yet: it was
  // requested mid-frame so it is deferred to the next (~16ms later) frame.
  for (let i = 0; i < 50 && order.length === 0; i++) {
    await wait(2);
  }
  expect(order).toEqual(['a']);

  await wait(60); // let the next frame run
  expect(order).toEqual(['a', 'b']);
});

// ---------------------------------------------------------------------------
// Finding 5 & 6 — idle callbacks
// ---------------------------------------------------------------------------

test('an idle callback scheduled from an idle callback waits for the next period', async () => {
  const order: string[] = [];
  requestIdleCallback(() => {
    order.push('a');
    requestIdleCallback(() => order.push('b'));
  });

  await wait(160); // first idle period
  // Bug pre-fix: live-Map iteration also visited the newly-inserted callback, so
  // 'b' ran back-to-back in the same period.
  expect(order).toEqual(['a']);

  await wait(160); // next idle period
  expect(order).toEqual(['a', 'b']);
});

test('cancelIdleCallback clears the per-callback timeout timer (no leaked timer)', () => {
  const origClear = globalThis.clearTimeout;
  const cleared: unknown[] = [];
  (globalThis as { clearTimeout: typeof clearTimeout }).clearTimeout = ((h: unknown) => {
    cleared.push(h);
    return (origClear as (h: unknown) => void)(h);
  }) as typeof clearTimeout;

  try {
    const id = requestIdleCallback(() => {}, { timeout: 100000 });
    cancelIdleCallback(id);
    // Bug pre-fix: cancelIdleCallback only deleted from the callbacks map; the
    // full-duration timeout timer + closure stayed pending.
    expect(cleared.length).toBeGreaterThan(0);
  } finally {
    (globalThis as { clearTimeout: typeof clearTimeout }).clearTimeout = origClear;
  }
});

// ---------------------------------------------------------------------------
// Finding 7 — fallback timers share one list
// ---------------------------------------------------------------------------

test('clearTimeout cancels an interval id (shared timer list)', async () => {
  let ticks = 0;
  const id = ibexSetInterval(() => {
    ticks++;
  }, 10);
  ibexClearTimeout(id); // per spec must cancel the interval

  await wait(60);
  expect(ticks).toBe(0);
});

test('clearInterval cancels a timeout id (shared timer list)', async () => {
  let ran = false;
  const id = ibexSetTimeout(() => {
    ran = true;
  }, 10);
  ibexClearInterval(id);

  await wait(60);
  expect(ran).toBe(false);
});

// ---------------------------------------------------------------------------
// Finding 8 — non-singleton Performance is an EventTarget
// ---------------------------------------------------------------------------

test('a freshly constructed Performance can addEventListener and dispatchEvent', () => {
  const p = new Performance();
  expect(p instanceof EventTarget).toBe(true);

  let got = 0;
  // Bug pre-fix: _listeners was never initialized for `new Performance()` so
  // addEventListener threw a TypeError.
  expect(() => p.addEventListener('x', () => got++)).not.toThrow();
  p.dispatchEvent(new Event('x'));
  expect(got).toBe(1);
});

// ---------------------------------------------------------------------------
// Finding 9 — bounded timeline / stable ordering
// ---------------------------------------------------------------------------

test('the performance timeline is bounded (oldest entries evicted past the cap)', () => {
  const p = new Performance();
  const N = 10050;
  for (let i = 0; i < N; i++) {
    p.mark('m' + i);
  }

  const entries = p.getEntries();
  expect(entries.length).toBeLessThanOrEqual(10000);

  const names = new Set(entries.map((e) => e.name));
  expect(names.has('m' + (N - 1))).toBe(true); // newest retained
  expect(names.has('m0')).toBe(false); // oldest evicted
  // The by-name bucket was evicted too, so the old mark is no longer usable.
  expect(p.getEntriesByName('m0').length).toBe(0);
});

test('getEntries returns entries sorted by startTime (including out-of-order inserts)', () => {
  const p = new Performance();
  p.mark('a', { startTime: 5 });
  p.mark('b', { startTime: 1 });
  p.mark('c', { startTime: 3 });

  expect(p.getEntries().map((e) => e.startTime)).toEqual([1, 3, 5]);
});

test('getEntries preserves insertion order when startTimes are monotonic', () => {
  const p = new Performance();
  p.mark('a', { startTime: 1 });
  p.mark('b', { startTime: 2 });
  p.mark('c', { startTime: 3 });

  expect(p.getEntries().map((e) => e.name)).toEqual(['a', 'b', 'c']);
});
