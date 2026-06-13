/**
 * LockManager - Web Locks API Implementation (single-context, pure JS)
 *
 * Provides a mechanism for coordinating access to shared resources within
 * a single JavaScript execution context. Supports exclusive and shared
 * lock modes, queuing, steal, ifAvailable, and AbortSignal cancellation.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API
 * @see https://w3c.github.io/web-locks/
 */

/**
 * Represents a held or pending lock.
 */
export interface Lock {
  readonly name: string;
  readonly mode: LockMode;
}

export type LockMode = "exclusive" | "shared";

export interface LockOptions {
  /** Lock mode: 'exclusive' (default) or 'shared'. */
  mode?: LockMode;
  /** If true, the callback receives null instead of waiting when the lock is unavailable. */
  ifAvailable?: boolean;
  /** If true, preempts any existing locks on the same resource. */
  steal?: boolean;
  /** An AbortSignal to cancel a pending lock request. */
  signal?: AbortSignal;
}

export type LockGrantedCallback = (lock: Lock | null) => Promise<any> | any;

export interface LockManagerSnapshot {
  held: Lock[];
  pending: Lock[];
}

/**
 * Internal representation of a queued lock request.
 */
interface LockRequest {
  name: string;
  mode: LockMode;
  callback: LockGrantedCallback;
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  signal?: AbortSignal;
  abortHandler?: () => void;
}

/**
 * Internal representation of a held lock with a release handle.
 */
interface HeldLockEntry {
  name: string;
  mode: LockMode;
}

/**
 * LockManager coordinates exclusive and shared access to named resources.
 *
 * Exclusive locks block all other lock requests for the same resource.
 * Shared locks allow other shared locks but block exclusive requests.
 * Pending requests are processed in FIFO order.
 */
export class LockManager {
  /** Map from lock name to array of currently held lock entries. */
  #held: Map<string, HeldLockEntry[]> = new Map();

  /** Map from lock name to ordered queue of pending requests. */
  #pending: Map<string, LockRequest[]> = new Map();

  /**
   * Request a lock.
   *
   * @overload
   * @param name - The resource name to lock.
   * @param callback - Called with the Lock when granted.
   */
  request(name: string, callback: LockGrantedCallback): Promise<any>;
  /**
   * Request a lock with options.
   *
   * @overload
   * @param name - The resource name to lock.
   * @param options - Lock request options.
   * @param callback - Called with the Lock (or null if ifAvailable and unavailable).
   */
  request(name: string, options: LockOptions, callback: LockGrantedCallback): Promise<any>;
  request(
    name: string,
    optionsOrCallback: LockOptions | LockGrantedCallback,
    maybeCallback?: LockGrantedCallback,
  ): Promise<any> {
    let options: LockOptions;
    let callback: LockGrantedCallback;

    if (typeof optionsOrCallback === "function") {
      options = {};
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback;
      callback = maybeCallback!;
    }

    if (typeof callback !== "function") {
      throw new TypeError("LockManager.request: callback must be a function");
    }

    if (typeof name !== "string") {
      throw new TypeError("LockManager.request: name must be a string");
    }

    // Validate name: must not start with '-'
    if (name.startsWith("-")) {
      throw new DOMException(
        `LockManager.request: names starting with '-' are reserved`,
        "NotSupportedError",
      );
    }

    const mode: LockMode = options.mode ?? "exclusive";
    if (mode !== "exclusive" && mode !== "shared") {
      throw new TypeError(`LockManager.request: invalid mode '${mode}'`);
    }

    if (options.steal && options.ifAvailable) {
      throw new DOMException(
        "LockManager.request: 'steal' and 'ifAvailable' cannot be used together",
        "NotSupportedError",
      );
    }

    if (options.steal && mode !== "exclusive") {
      throw new DOMException(
        "LockManager.request: 'steal' is only supported for exclusive locks",
        "NotSupportedError",
      );
    }

    if (options.signal && options.steal) {
      throw new DOMException(
        "LockManager.request: 'signal' and 'steal' cannot be used together",
        "NotSupportedError",
      );
    }

    // Check if signal is already aborted
    if (options.signal?.aborted) {
      return Promise.reject(options.signal.reason);
    }

    // Handle steal
    if (options.steal) {
      return this.#stealLock(name, callback);
    }

    // Handle ifAvailable
    if (options.ifAvailable) {
      return this.#requestIfAvailable(name, mode, callback);
    }

    // Normal lock acquisition: either grant immediately or queue
    return this.#requestLock(name, mode, callback, options.signal);
  }

  /**
   * Returns a snapshot of the currently held and pending locks.
   */
  async query(): Promise<LockManagerSnapshot> {
    const held: Lock[] = [];
    const pending: Lock[] = [];

    for (const [, locks] of this.#held) {
      for (const entry of locks) {
        held.push({ name: entry.name, mode: entry.mode });
      }
    }

    for (const [, requests] of this.#pending) {
      for (const req of requests) {
        pending.push({ name: req.name, mode: req.mode });
      }
    }

    return { held, pending };
  }

  /**
   * Steal a lock: abort all existing holders and pending requests, then grant.
   */
  #stealLock(name: string, callback: LockGrantedCallback): Promise<any> {
    // Clear all held locks for this name
    this.#held.delete(name);

    // Reject all pending requests for this name
    const existingPending = this.#pending.get(name);
    if (existingPending) {
      for (const req of existingPending) {
        this.#cleanupAbortHandler(req);
        req.reject(new DOMException("Lock broken by steal request", "AbortError"));
      }
      this.#pending.delete(name);
    }

    // Grant the lock immediately
    return this.#grantAndRun(name, "exclusive", callback);
  }

  /**
   * Try to acquire a lock without waiting. Returns null to callback if unavailable.
   */
  #requestIfAvailable(
    name: string,
    mode: LockMode,
    callback: LockGrantedCallback,
  ): Promise<any> {
    if (this.#canAcquire(name, mode)) {
      return this.#grantAndRun(name, mode, callback);
    }
    // Not available - call callback with null (no lock held)
    return this.#invokeCallback(callback, null);
  }

  /**
   * Normal lock request: grant immediately if possible, otherwise queue.
   */
  #requestLock(
    name: string,
    mode: LockMode,
    callback: LockGrantedCallback,
    signal?: AbortSignal,
  ): Promise<any> {
    if (this.#canAcquire(name, mode)) {
      return this.#grantAndRun(name, mode, callback);
    }

    // Queue the request
    return new Promise<any>((resolve, reject) => {
      const request: LockRequest = {
        name,
        mode,
        callback,
        resolve,
        reject,
        signal,
      };

      // Set up abort handler
      if (signal) {
        const abortHandler = () => {
          this.#removePendingRequest(name, request);
          request.reject(signal.reason);
        };
        request.abortHandler = abortHandler;
        signal.addEventListener("abort", abortHandler, { once: true });
      }

      let queue = this.#pending.get(name);
      if (!queue) {
        queue = [];
        this.#pending.set(name, queue);
      }
      queue.push(request);
    });
  }

  /**
   * Check if a lock can be granted immediately for the given name and mode.
   * Considers the pending queue to prevent writer starvation.
   */
  #canAcquire(name: string, mode: LockMode): boolean {
    const held = this.#held.get(name);
    if (!held || held.length === 0) {
      // Also check: if there's a pending queue for this name, new requests
      // should go behind them (FIFO fairness), unless the queue is empty.
      const pendingQueue = this.#pending.get(name);
      if (pendingQueue && pendingQueue.length > 0) {
        return false;
      }
      return true;
    }

    if (mode === "shared") {
      // All held must be shared
      if (!held.every((h) => h.mode === "shared")) return false;

      // And no pending exclusive requests (prevent writer starvation)
      const pendingQueue = this.#pending.get(name);
      if (pendingQueue && pendingQueue.some((p) => p.mode === "exclusive")) {
        return false;
      }

      return true;
    }

    // Exclusive needs no held locks
    return false;
  }

  /**
   * Check if a lock can be granted, used when draining the queue.
   * Does not consider pending queue for starvation (we process FIFO).
   */
  #canAcquireDirect(name: string, mode: LockMode): boolean {
    const held = this.#held.get(name);
    if (!held || held.length === 0) {
      return true;
    }

    if (mode === "shared") {
      return held.every((h) => h.mode === "shared");
    }

    return false;
  }

  /**
   * Grant a lock, run the callback, and release the lock when the callback finishes.
   * Returns the promise that resolves to the callback's return value.
   */
  #grantAndRun(
    name: string,
    mode: LockMode,
    callback: LockGrantedCallback,
  ): Promise<any> {
    const lock: Lock = Object.freeze({ name, mode });
    const entry: HeldLockEntry = { name, mode };

    // Register as held
    let heldList = this.#held.get(name);
    if (!heldList) {
      heldList = [];
      this.#held.set(name, heldList);
    }
    heldList.push(entry);

    // Run callback
    const result = this.#invokeCallback(callback, lock);

    // On completion (success or failure), release the lock and process queue
    return result.then(
      (value) => {
        this.#releaseLock(name, entry);
        return value;
      },
      (err) => {
        this.#releaseLock(name, entry);
        throw err;
      },
    );
  }

  /**
   * Invoke the user callback safely, wrapping the result in a promise.
   */
  #invokeCallback(callback: LockGrantedCallback, lock: Lock | null): Promise<any> {
    try {
      const result = callback(lock);
      return Promise.resolve(result);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  /**
   * Release a held lock and process the pending queue.
   */
  #releaseLock(name: string, entry: HeldLockEntry): void {
    const heldList = this.#held.get(name);
    if (heldList) {
      const idx = heldList.indexOf(entry);
      if (idx !== -1) {
        heldList.splice(idx, 1);
      }
      if (heldList.length === 0) {
        this.#held.delete(name);
      }
    }
    this.#processQueue(name);
  }

  /**
   * Remove a pending request from the queue (e.g., on abort).
   */
  #removePendingRequest(name: string, request: LockRequest): void {
    const queue = this.#pending.get(name);
    if (!queue) return;
    const idx = queue.indexOf(request);
    if (idx !== -1) {
      queue.splice(idx, 1);
    }
    if (queue.length === 0) {
      this.#pending.delete(name);
    }
  }

  /**
   * Clean up abort event listener for a request.
   */
  #cleanupAbortHandler(request: LockRequest): void {
    if (request.abortHandler && request.signal) {
      request.signal.removeEventListener("abort", request.abortHandler);
    }
  }

  /**
   * Process the pending queue for a given lock name, granting as many as possible.
   */
  #processQueue(name: string): void {
    const queue = this.#pending.get(name);
    if (!queue || queue.length === 0) return;

    while (queue.length > 0) {
      const next = queue[0];

      if (!this.#canAcquireDirect(name, next.mode)) {
        break;
      }

      // Remove from queue
      queue.shift();
      this.#cleanupAbortHandler(next);

      if (queue.length === 0) {
        this.#pending.delete(name);
      }

      // Grant the lock and run the callback. The result flows back through
      // the original promise that was returned from request().
      this.#grantAndRun(name, next.mode, next.callback).then(
        next.resolve,
        next.reject,
      );

      // If we just granted an exclusive lock, stop processing
      if (next.mode === "exclusive") {
        break;
      }

      // If we granted a shared lock, continue granting other shared locks
      // at the front of the queue
    }
  }

  get [Symbol.toStringTag](): string {
    return "LockManager";
  }
}

// DOMException polyfill for this module
class DOMException extends Error {
  readonly code: number = 0;
  constructor(message: string, name: string) {
    super(message);
    this.name = name;
  }
}
