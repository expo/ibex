// @ts-nocheck
/**
 * Timers - Web Standard Timer Implementation
 *
 * @see https://html.spec.whatwg.org/multipage/timers-and-user-prompts.html
 */

export interface TimerModule {
  setTimeout(callback: () => void, delay: number): number;
  clearTimeout(id: number): void;
  setInterval(callback: () => void, delay: number): number;
  clearInterval(id: number): void;
}

const symbolDispose =
  typeof Symbol === "function"
    ? (Symbol.dispose ?? (typeof Symbol.for === "function" ? Symbol.for("nodejs.dispose") : undefined))
    : undefined;

function validateTimerCallback<TArgs extends any[]>(callback: ((...args: TArgs) => void) | unknown): (...args: TArgs) => void {
  if (typeof callback === "function") {
    return callback;
  }
  const err = new TypeError(
    `The "callback" argument must be of type function. Received type ${
      callback === null ? "null" : typeof callback
    }`,
  ) as TypeError & { code?: string };
  err.code = "ERR_INVALID_ARG_TYPE";
  throw err;
}

class ImmediateHandle {
  private _handle: unknown;
  _destroyed = false;
  private _refed = true;

  constructor(handle: unknown) {
    this._handle = handle;
  }

  ref(): this {
    this._refed = true;
    const handle = this._handle as { ref?: () => void } | number | null | undefined;
    if (handle && typeof handle === "object" && typeof handle.ref === "function") {
      handle.ref();
    } else if (typeof (globalThis as any).__exactTimerRef === "function" && handle != null) {
      (globalThis as any).__exactTimerRef(handle);
    }
    return this;
  }

  unref(): this {
    this._refed = false;
    const handle = this._handle as { unref?: () => void } | number | null | undefined;
    if (handle && typeof handle === "object" && typeof handle.unref === "function") {
      handle.unref();
    } else if (typeof (globalThis as any).__exactTimerUnref === "function" && handle != null) {
      (globalThis as any).__exactTimerUnref(handle);
    }
    return this;
  }

  hasRef(): boolean {
    return this._refed;
  }

  close(): this {
    if (!this._destroyed) {
      this._destroyed = true;
      globalThis.clearTimeout(this._handle as any);
    }
    return this;
  }

  [Symbol.toPrimitive](): number {
    if (typeof this._handle === "number") {
      return this._handle;
    }
    return 0;
  }
}

if (symbolDispose) {
  (ImmediateHandle.prototype as any)[symbolDispose] = function dispose(this: ImmediateHandle) {
    this.close();
  };
}

// Native module for timer operations (set from native side)
let nativeTimerModule: TimerModule | null = null;

export function setNativeTimerModule(module: TimerModule): void {
  nativeTimerModule = module;
}

// Fallback implementation using JS-based timers
// This is used when native module is not available (e.g., in tests)
let nextId = 1;
const timeoutMap = new Map<number, ReturnType<typeof globalThis.setTimeout>>();
const intervalMap = new Map<number, ReturnType<typeof globalThis.setInterval>>();

const fallbackModule: TimerModule = {
  setTimeout(callback: () => void, delay: number): number {
    const id = nextId++;
    const handle = globalThis.setTimeout(() => {
      timeoutMap.delete(id);
      callback();
    }, delay);
    timeoutMap.set(id, handle);
    return id;
  },
  clearTimeout(id: number): void {
    const handle = timeoutMap.get(id);
    if (handle !== undefined) {
      globalThis.clearTimeout(handle);
      timeoutMap.delete(id);
    }
  },
  setInterval(callback: () => void, delay: number): number {
    const id = nextId++;
    const handle = globalThis.setInterval(callback, delay);
    intervalMap.set(id, handle);
    return id;
  },
  clearInterval(id: number): void {
    const handle = intervalMap.get(id);
    if (handle !== undefined) {
      globalThis.clearInterval(handle);
      intervalMap.delete(id);
    }
  },
};

function getModule(): TimerModule {
  return nativeTimerModule ?? fallbackModule;
}

function reportTimerError(error: unknown): void {
  const processObj = (globalThis as any).process;
  if (processObj && typeof processObj.emit === "function" && processObj.emit("uncaughtException", error)) {
    return;
  }

  queueMicrotask(() => {
    throw error;
  });
}

/**
 * setTimeout - Schedule a callback after a delay
 *
 * @param callback Function to call
 * @param delay Delay in milliseconds (default: 0)
 * @param args Additional arguments to pass to callback
 * @returns Timer ID (number, per web standard)
 */
export function setTimeout<TArgs extends any[]>(
  callback: (...args: TArgs) => void,
  delay?: number,
  ...args: TArgs
): number {
  callback = validateTimerCallback(callback);
  const ms = Math.max(0, Number(delay) || 0);

  // Wrap callback to pass arguments
  const wrappedCallback = () => {
    try {
      callback(...args);
    } catch (error) {
      reportTimerError(error);
    }
  };

  return getModule().setTimeout(wrappedCallback, ms);
}

/**
 * clearTimeout - Cancel a scheduled timeout
 *
 * @param id Timer ID returned by setTimeout
 */
export function clearTimeout(id?: number): void {
  if (id !== undefined && id !== null) {
    getModule().clearTimeout(id);
  }
}

/**
 * setInterval - Schedule a recurring callback
 *
 * @param callback Function to call
 * @param delay Delay between calls in milliseconds (default: 0)
 * @param args Additional arguments to pass to callback
 * @returns Timer ID (number, per web standard)
 */
export function setInterval<TArgs extends any[]>(
  callback: (...args: TArgs) => void,
  delay?: number,
  ...args: TArgs
): number {
  callback = validateTimerCallback(callback);
  const ms = Math.max(0, Number(delay) || 0);

  // Wrap callback to pass arguments
  const wrappedCallback = () => {
    try {
      callback(...args);
    } catch (error) {
      reportTimerError(error);
    }
  };

  return getModule().setInterval(wrappedCallback, ms);
}

/**
 * clearInterval - Cancel a recurring interval
 *
 * @param id Timer ID returned by setInterval
 */
export function clearInterval(id?: number): void {
  if (id !== undefined && id !== null) {
    getModule().clearInterval(id);
  }
}

/**
 * queueMicrotask - Schedule a microtask
 *
 * Microtasks run before the next macrotask (timer, I/O, etc.)
 *
 * @param callback Function to call
 */
export function queueMicrotask(callback: () => void): void {
  // Use native queueMicrotask if available
  if (typeof globalThis.queueMicrotask === "function") {
    globalThis.queueMicrotask(() => {
      try {
        callback();
      } catch (error) {
        console.error("Error in queueMicrotask callback:", error);
      }
    });
  } else {
    // Fallback using Promise
    Promise.resolve().then(() => {
      try {
        callback();
      } catch (error) {
        console.error("Error in queueMicrotask callback:", error);
      }
    });
  }
}

/**
 * setImmediate - Schedule a macrotask (Node.js compatibility)
 *
 * In Exact, this is equivalent to setTimeout(fn, 0)
 *
 * @param callback Function to call
 * @param args Additional arguments to pass to callback
 * @returns Timer ID
 */
export function setImmediate<TArgs extends any[]>(
  callback: (...args: TArgs) => void,
  ...args: TArgs
): ImmediateHandle {
  callback = validateTimerCallback(callback);
  let immediate: ImmediateHandle;
  const wrappedCallback = () => {
    immediate._destroyed = true;
    try {
      callback(...args);
    } catch (error) {
      reportTimerError(error);
    }
  };
  const handle = globalThis.setTimeout(wrappedCallback, 0);
  immediate = new ImmediateHandle(handle);
  return immediate;
}

/**
 * clearImmediate - Cancel a scheduled immediate (Node.js compatibility)
 *
 * @param id Timer ID returned by setImmediate
 */
export function clearImmediate(id?: number | ImmediateHandle): void {
  if (id && typeof id === "object" && typeof (id as ImmediateHandle).close === "function") {
    (id as ImmediateHandle).close();
    return;
  }
  clearTimeout(id as number | undefined);
}
