// @ts-nocheck
/**
 * Promise Rejection Tracking
 *
 * Provides `unhandledrejection` and `rejectionhandled` event dispatch on globalThis.
 *
 * Strategy:
 * 1. If the native bridge exposes `__exactOnUnhandledRejection`, use it directly.
 * 2. Otherwise, install a userland polyfill that:
 *    a. Wraps `Promise.prototype.then` to track which promises have rejection handlers.
 *    b. Uses a Map to track unhandled rejections.
 *    c. Uses `queueMicrotask` to defer detection until after synchronous handler attachment.
 *    d. Dispatches `unhandledrejection` on globalThis when a rejection is unhandled.
 *    e. Dispatches `rejectionhandled` when a previously-unhandled rejection gets a handler.
 *
 * @see https://html.spec.whatwg.org/multipage/webappapis.html#unhandled-promise-rejections
 */

import { EventTarget } from "./events/EventTarget";
import { PromiseRejectionEvent } from "./events/PromiseRejectionEvent";

/**
 * Map of currently-pending unhandled rejections: Promise -> reason.
 * Entries live here only between the rejection and the microtask that reports
 * (or suppresses) it -- once 'unhandledrejection' has been dispatched the entry
 * is evicted so a genuinely-unhandled rejection never retains its Promise +
 * reason for the life of the runtime. Exposed for testing purposes.
 */
const _unhandledRejections: Map<Promise<any>, any> = new Map();

/**
 * Promises that have already been reported via 'unhandledrejection'. Held
 * WEAKLY (keyed by the promise) so a rejection that is never handled is not
 * retained forever, while a handler attached AFTER the report can still fire
 * 'rejectionhandled' with the original reason. (ENG-22985)
 */
const _reportedRejections: WeakMap<Promise<any>, any> = new WeakMap();

/**
 * Internal EventTarget used to dispatch promise rejection events.
 * We always use our own EventTarget instance to ensure compatibility with
 * our custom Event classes (avoids issues with native EventTarget implementations
 * in environments like Bun/Node that reject non-native Event subclasses).
 */
let _eventTarget: EventTarget | null = null;

/**
 * Whether globalThis.addEventListener has been wrapped to intercept
 * unhandledrejection/rejectionhandled listeners.
 */
let _globalListenersInstalled = false;

/**
 * Promise rejection event types that we intercept.
 */
const REJECTION_EVENT_TYPES = new Set(['unhandledrejection', 'rejectionhandled']);
const trailingDataErrorSymbol = Symbol.for("__exact.decompression.trailing-data-error");
const _synchronouslyHandledPromises = new WeakSet<Promise<any>>();
let _nativeHandledTrackingInstalled = false;

/**
 * Get or create the internal EventTarget for promise rejection events.
 */
function getEventTarget(): EventTarget {
  if (_eventTarget) return _eventTarget;
  _eventTarget = new EventTarget();
  return _eventTarget;
}

/**
 * Install interception of addEventListener/removeEventListener on globalThis
 * so that listeners for 'unhandledrejection' and 'rejectionhandled' are
 * forwarded to our internal EventTarget.
 */
function installGlobalListenerForwarding(): void {
  if (_globalListenersInstalled) return;
  _globalListenersInstalled = true;

  const g = globalThis as any;
  const et = getEventTarget();

  const origAddEventListener = g.addEventListener;
  const origRemoveEventListener = g.removeEventListener;

  if (typeof origAddEventListener === 'function') {
    // Wrap existing addEventListener to intercept rejection events
    g.addEventListener = function wrappedAddEventListener(
      type: string,
      callback: any,
      options?: any
    ): void {
      if (REJECTION_EVENT_TYPES.has(type)) {
        et.addEventListener(type, callback, options);
      } else {
        origAddEventListener.call(this, type, callback, options);
      }
    };
  } else {
    // No existing addEventListener, install ours directly
    g.addEventListener = et.addEventListener.bind(et);
  }

  if (typeof origRemoveEventListener === 'function') {
    g.removeEventListener = function wrappedRemoveEventListener(
      type: string,
      callback: any,
      options?: any
    ): void {
      if (REJECTION_EVENT_TYPES.has(type)) {
        et.removeEventListener(type, callback, options);
      } else {
        origRemoveEventListener.call(this, type, callback, options);
      }
    };
  } else {
    g.removeEventListener = et.removeEventListener.bind(et);
  }

  if (typeof g.dispatchEvent !== 'function') {
    g.dispatchEvent = et.dispatchEvent.bind(et);
  }
}

/**
 * Track a promise rejection. Called when a promise is rejected without a handler.
 * After a microtask, if no handler has been attached, dispatches `unhandledrejection`.
 */
export function trackPromiseRejection(promise: Promise<any>, reason: any): void {
  if (_synchronouslyHandledPromises.has(promise)) {
    return;
  }

  const suppressUnhandledRejection = (globalThis as any).__exactShouldSuppressUnhandledRejection;
  if (typeof suppressUnhandledRejection === "function") {
    try {
      if (suppressUnhandledRejection(reason, promise)) {
        return;
      }
    } catch (_) {}
  }

  if (reason && reason[trailingDataErrorSymbol]) {
    return;
  }

  _unhandledRejections.set(promise, reason);

  // Defer the check to after the current microtask queue drains,
  // giving synchronous .catch() calls a chance to attach.
  queueMicrotask(() => {
    if (!_unhandledRejections.has(promise)) {
      // Handler was attached synchronously -- nothing to report
      return;
    }

    // Evict from the strong pending map BEFORE dispatch and record it weakly.
    // The rejection has now been reported, so we must not keep retaining the
    // promise + reason; a later-attached handler still fires 'rejectionhandled'
    // via _reportedRejections. (ENG-22985)
    _unhandledRejections.delete(promise);
    _reportedRejections.set(promise, reason);

    const target = getEventTarget();
    const event = new PromiseRejectionEvent('unhandledrejection', {
      promise,
      reason,
      cancelable: true,
    });

    const notPrevented = target.dispatchEvent(event);

    if (notPrevented) {
      // Default behavior: log the unhandled rejection to console
      // (browsers typically report to console unless preventDefault is called)
      console.error('Unhandled promise rejection:', reason);
      // Fail loud: an unhandled rejection that no handler consumed must not
      // let the process report success — Node exits nonzero here. Keep running
      // (we report-and-continue rather than crash mid-run), but make the exit
      // code the CLI reads reflect the failure. A user-set nonzero exitCode is
      // preserved.
      // @ref LLP 0003#the-event-loop — async failures are fatal (ENG-23130)
      const proc = (globalThis as any).process;
      if (
        proc &&
        typeof proc === 'object' &&
        (typeof proc.exitCode !== 'number' || proc.exitCode === 0)
      ) {
        try {
          proc.exitCode = 1;
        } catch (_) {}
      }
    }
  });
}

function installNativeHandledPromiseTracking(OriginalPromise: PromiseConstructor): void {
  if (_nativeHandledTrackingInstalled) return;
  _nativeHandledTrackingInstalled = true;

  const originalThen = OriginalPromise.prototype.then;
  const originalCatch = OriginalPromise.prototype.catch;
  const originalFinally = OriginalPromise.prototype.finally;

  function markHandled(promise: Promise<any>): void {
    _synchronouslyHandledPromises.add(promise);
    // Consult BOTH the pending map and the already-reported weak map: after a
    // rejection is reported it is evicted from _unhandledRejections, but a
    // handler attached now must still fire 'rejectionhandled'. (ENG-22985)
    if (_unhandledRejections.has(promise) || _reportedRejections.has(promise)) {
      trackPromiseRejectionHandled(promise);
    }
  }

  OriginalPromise.prototype.then = function wrappedThen(
    onFulfilled?: any,
    onRejected?: any
  ): Promise<any> {
    if (this && (typeof this === 'object' || typeof this === 'function')) {
      markHandled(this as Promise<any>);
    }
    return originalThen.call(this, onFulfilled, onRejected);
  };

  OriginalPromise.prototype.catch = function wrappedCatch(
    onRejected?: any
  ): Promise<any> {
    if (typeof onRejected === 'function' && this && (typeof this === 'object' || typeof this === 'function')) {
      markHandled(this as Promise<any>);
    }
    return originalCatch.call(this, onRejected);
  };

  if (typeof originalFinally === 'function') {
    OriginalPromise.prototype.finally = function wrappedFinally(
      onFinally?: any
    ): Promise<any> {
      if (this && (typeof this === 'object' || typeof this === 'function')) {
        markHandled(this as Promise<any>);
      }
      return originalFinally.call(this, onFinally);
    };
  }
}

/**
 * Track that a previously-unhandled promise rejection has been handled.
 * Dispatches `rejectionhandled` on globalThis.
 */
export function trackPromiseRejectionHandled(promise: Promise<any>): void {
  _synchronouslyHandledPromises.add(promise);

  // Case 1: handled before 'unhandledrejection' was ever dispatched -- just drop
  // the pending entry; per spec no 'rejectionhandled' fires without a preceding
  // 'unhandledrejection'.
  if (_unhandledRejections.has(promise)) {
    _unhandledRejections.delete(promise);
    return;
  }

  // Case 2: handled after it was reported unhandled -- fire 'rejectionhandled'
  // with the original reason and stop tracking the promise weakly. (ENG-22985)
  if (!_reportedRejections.has(promise)) {
    return;
  }

  const reason = _reportedRejections.get(promise);
  _reportedRejections.delete(promise);

  // Dispatch rejectionhandled asynchronously (per spec, fires in a later task)
  queueMicrotask(() => {
    const target = getEventTarget();
    const event = new PromiseRejectionEvent('rejectionhandled', {
      promise,
      reason,
      cancelable: false,
    });

    target.dispatchEvent(event);
  });
}

/**
 * Install promise rejection tracking on the global Promise.
 *
 * This wraps Promise.prototype.then to intercept rejection handler attachment
 * and hooks into the Promise constructor to detect unhandled rejections.
 */
export function installPromiseRejectionTracking(): void {
  const g = globalThis as any;

  // Set up event listener forwarding on globalThis
  installGlobalListenerForwarding();

  // Keep the unwrapped constructor closure-local. Publishing it would give
  // project code a direct route around rejection tracking.
  // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces — internal runtime objects are not project globals
  const OriginalPromise = g.Promise;

  // If native bridge provides promise rejection hooks, use those
  if (typeof g.__exactOnUnhandledRejection === 'function') {
    installNativeHandledPromiseTracking(OriginalPromise);
    g.__exactOnUnhandledRejection((promise: Promise<any>, reason: any) => {
      trackPromiseRejection(promise, reason);
    });
    if (typeof g.__exactOnRejectionHandled === 'function') {
      g.__exactOnRejectionHandled((promise: Promise<any>) => {
        trackPromiseRejectionHandled(promise);
      });
    }
    return;
  }

  // Polyfill approach: wrap Promise.prototype.then to detect handler attachment
  // and wrap the Promise constructor to detect rejections without handlers.
  const originalThen = OriginalPromise.prototype.then;
  const originalCatch = OriginalPromise.prototype.catch;

  // WeakSet to track promises that have had rejection handlers attached
  const _handledPromises = new WeakSet<Promise<any>>();
  // WeakSet to track promises that have been reported as rejected
  const _rejectedPromises = new WeakSet<Promise<any>>();
  // WeakMap to map child promises back to parent for handler tracking
  const _promiseParents = new WeakMap<Promise<any>, Promise<any>>();

  /**
   * Mark a promise (and its ancestor chain) as handled.
   */
  function markHandled(promise: Promise<any>): void {
    let current: unknown = promise;
    while (current && (typeof current === 'object' || typeof current === 'function')) {
      if (_handledPromises.has(current)) break;
      _handledPromises.add(current);

      // If this promise was in the unhandled set, dispatch rejectionhandled
      if (_rejectedPromises.has(current)) {
        _rejectedPromises.delete(current);
        trackPromiseRejectionHandled(current);
      }

      current = _promiseParents.get(current);
    }
  }

  /**
   * Wrapped .then() that tracks rejection handler attachment.
   */
  OriginalPromise.prototype.then = function wrappedThen(
    onFulfilled?: any,
    onRejected?: any
  ): Promise<any> {
    const child = originalThen.call(this, onFulfilled, onRejected);

    // Track the parent-child relationship
    if (child && (typeof child === 'object' || typeof child === 'function')) {
      _promiseParents.set(child, this);
    }

    // If a rejection handler is provided, mark the promise as handled
    if (typeof onRejected === 'function' && this && (typeof this === 'object' || typeof this === 'function')) {
      markHandled(this);
    }

    return child;
  };

  /**
   * Wrapped .catch() that tracks rejection handler attachment.
   */
  OriginalPromise.prototype.catch = function wrappedCatch(
    onRejected?: any
  ): Promise<any> {
    const child = originalCatch.call(this, onRejected);

    // Track the parent-child relationship
    if (child && (typeof child === 'object' || typeof child === 'function')) {
      _promiseParents.set(child, this);
    }

    // A .catch() always provides a rejection handler
    if (typeof onRejected === 'function' && this && (typeof this === 'object' || typeof this === 'function')) {
      markHandled(this);
    }

    return child;
  };

  // Preserve .finally if it exists
  const originalFinally = OriginalPromise.prototype.finally;
  if (originalFinally) {
    OriginalPromise.prototype.finally = function wrappedFinally(
      onFinally?: any
    ): Promise<any> {
      const child = originalFinally.call(this, onFinally);
      if (child && (typeof child === 'object' || typeof child === 'function')) {
        _promiseParents.set(child, this);
      }
      return child;
    };
  }

  /**
   * Create a wrapper around Promise.reject to detect immediate rejections.
   */
  const originalReject = OriginalPromise.reject;
  OriginalPromise.reject = function wrappedReject(reason?: any): Promise<any> {
    const promise = originalReject.call(this, reason);
    if (promise && (typeof promise === 'object' || typeof promise === 'function')) {
      _rejectedPromises.add(promise);
    }

    // Schedule a microtask to check if a handler was attached
    queueMicrotask(() => {
      if (promise && (typeof promise === 'object' || typeof promise === 'function') && !_handledPromises.has(promise)) {
        trackPromiseRejection(promise, reason);
      }
    });

    return promise;
  };

  /**
   * Wrap the Promise constructor to detect rejections in executor functions.
   */
  const ExactPromise = function ExactPromise(
    this: any,
    executor: (
      resolve: (value?: any) => void,
      reject: (reason?: any) => void
    ) => void
  ): Promise<any> {
    let promiseRef: Promise<any> | null = null;
    let hasPendingReject = false;
    let pendingReject: any = null;

    const wrappedExecutor = (
      resolve: (value?: any) => void,
      reject: (reason?: any) => void
    ) => {
      let settled = false;

      const wrappedResolve = (value?: any) => {
        settled = true;
        return resolve(value);
      };

      const wrappedReject = (reason?: any) => {
        settled = true;
        if (promiseRef && (typeof promiseRef === 'object' || typeof promiseRef === 'function')) {
          _rejectedPromises.add(promiseRef);
          queueMicrotask(() => {
            if (!_handledPromises.has(promiseRef as any)) {
              trackPromiseRejection(promiseRef as any, reason);
            }
          });
        } else {
          // Use an explicit flag rather than a null sentinel so rejecting
          // with reason null/undefined is still tracked. (ENG-23140)
          hasPendingReject = true;
          pendingReject = reason;
        }

        return reject(reason);
      };

      // A synchronously-throwing executor is turned into a rejection by the
      // native Promise constructor via its INTERNAL reject, which this tracker
      // never sees — so `new Promise(() => { throw e })` rejections vanished
      // from unhandledrejection reporting. Route the throw through
      // wrappedReject ourselves. If the executor already settled the promise
      // before throwing, native semantics ignore the throw, so we do too. (ENG-23140)
      try {
        return executor(wrappedResolve, wrappedReject);
      } catch (error) {
        if (!settled) {
          wrappedReject(error);
        }
      }
    };

    const promise = new OriginalPromise(wrappedExecutor);
    promiseRef = promise;
    if (hasPendingReject) {
      const reason = pendingReject;
      hasPendingReject = false;
      pendingReject = null;
      _rejectedPromises.add(promiseRef);
      queueMicrotask(() => {
        if (!_handledPromises.has(promiseRef as any)) {
          trackPromiseRejection(promiseRef as any, reason);
        }
      });
    }

    return promise;
  } as any;

  // Copy static methods and properties
  const bindStatic = (name: string): void => {
    const value = (OriginalPromise as any)[name];
    if (typeof value === 'function') {
      ExactPromise[name] = value.bind(OriginalPromise);
    }
  };

  bindStatic('resolve');
  ExactPromise.reject = OriginalPromise.reject; // Already wrapped above
  bindStatic('all');
  bindStatic('allSettled');
  bindStatic('race');
  bindStatic('any');
  bindStatic('withResolvers');
  ExactPromise.prototype = OriginalPromise.prototype;
  ExactPromise[Symbol.species] = OriginalPromise;

  // Make instanceof checks work
  Object.defineProperty(ExactPromise, Symbol.hasInstance, {
    value: (instance: any) => instance instanceof OriginalPromise,
  });

  // Install as the global Promise
  g.Promise = ExactPromise;
}

/**
 * Get the current set of unhandled rejections (for testing).
 */
export function getUnhandledRejections(): Map<Promise<any>, any> {
  return _unhandledRejections;
}

/**
 * Reset tracking state (for testing).
 */
export function resetPromiseRejectionTracking(): void {
  _unhandledRejections.clear();
  _eventTarget = null;
  _globalListenersInstalled = false;
}
