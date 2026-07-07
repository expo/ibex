// @ts-nocheck
/**
 * WritableStream - WHATWG Streams API Implementation
 *
 * @see https://streams.spec.whatwg.org/#ws-class
 *
 * This implementation supports:
 * - Underlying sink with start/write/close/abort
 * - Queuing strategy with backpressure
 * - WritableStreamDefaultWriter with ready/closed promises
 * - WritableStreamDefaultController with error()
 * - Proper state machine: writable -> closing -> closed, or errored
 * - Symbol.toStringTag
 */

import { trackPromiseRejectionHandled } from '../promise-rejection-tracking';

// Capture Promise methods at module load time to be immune to monkey-patching
const originalPromiseThen = Promise.prototype.then;
const originalPromiseResolve = Promise.resolve.bind(Promise);
const originalPromiseReject = Promise.reject.bind(Promise);

function promiseThen<T, TResult1 = T, TResult2 = never>(
  promise: PromiseLike<T>,
  onFulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
  onRejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null
): Promise<TResult1 | TResult2> {
  if (
    typeof onRejected === "function" &&
    ((typeof promise === "object" && promise !== null) || typeof promise === "function")
  ) {
    trackPromiseRejectionHandled(promise as Promise<any>);
  }
  return originalPromiseThen.call(promise, onFulfilled, onRejected);
}

function markPromiseHandled(promise: PromiseLike<any>): void {
  originalPromiseThen.call(promise, undefined, () => {});
  if ((typeof promise === "object" && promise !== null) || typeof promise === "function") {
    trackPromiseRejectionHandled(promise as Promise<any>);
  }
}

function resolveHandledPromise<T>(value: T | PromiseLike<T>): Promise<T> {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    try {
      markPromiseHandled(value as PromiseLike<any>);
    } catch (_) {}
  }
  return originalPromiseResolve(value);
}

// ============================================================================
// Types
// ============================================================================

export interface UnderlyingSink<W = any> {
  start?: (controller: WritableStreamDefaultController) => void | Promise<void>;
  write?: (chunk: W, controller: WritableStreamDefaultController) => void | Promise<void>;
  close?: () => void | Promise<void>;
  abort?: (reason?: any) => void | Promise<void>;
  type?: undefined;
}

export interface QueuingStrategy<W = any> {
  highWaterMark?: number;
  size?: (chunk: W) => number;
}

export interface StreamPipeOptions {
  preventClose?: boolean;
  preventAbort?: boolean;
  preventCancel?: boolean;
  signal?: AbortSignal;
}

type WritableStreamState = 'writable' | 'erroring' | 'closing' | 'closed' | 'errored';
type PromiseState = 'pending' | 'fulfilled' | 'rejected';
type PromiseRecord<T> = {
  promise: Promise<T>;
  state: PromiseState;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: any) => void;
};

// ============================================================================
// Internal helpers
// ============================================================================

/** Create a deferred promise with exposed resolve/reject */
function createDeferred<T = undefined>(): {
  promise: Promise<T>;
  state: PromiseState;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: any) => void;
} {
  const record: PromiseRecord<T> = {
    promise: originalPromiseResolve(undefined as T),
    state: 'pending',
    resolve: function (_value: T | PromiseLike<T>) {},
    reject: function (_reason?: any) {},
  };

  record.promise = new Promise<T>(function (res, rej) {
    record.resolve = function (value: T | PromiseLike<T>) {
      if (record.state !== 'pending') {
        return;
      }
      record.state = 'fulfilled';
      res(value);
    };
    record.reject = function (reason?: any) {
      if (record.state !== 'pending') {
        return;
      }
      record.state = 'rejected';
      rej(reason);
    };
  });

  return record;
}

function createHandledRejectedPromise<T = never>(reason: any): Promise<T> {
  const p = new Promise<T>(function (_resolve, reject) {
    queueMicrotask(function () {
      reject(reason);
    });
  });
  markPromiseHandled(p);
  return p;
}

function createResolvedPromiseRecord<T>(value: T): PromiseRecord<T> {
  return {
    promise: originalPromiseResolve(value),
    state: 'fulfilled',
    resolve: function (_value: T | PromiseLike<T>) {},
    reject: function (_reason?: any) {},
  };
}

function createRejectedPromiseRecord<T = never>(reason: any): PromiseRecord<T> {
  return {
    promise: createHandledRejectedPromise<T>(reason),
    state: 'rejected',
    resolve: function (_value: T | PromiseLike<T>) {},
    reject: function (_reason?: any) {},
  };
}

function createReleasedWriterError(): TypeError {
  return new TypeError('Writer has been released');
}

function isCallable(value: unknown): value is (...args: any[]) => any {
  return typeof value === "function";
}

function toNumber(value: unknown): number {
  return Number(value);
}

function validateHighWaterMark(highWaterMark: unknown, defaultValue: number): number {
  if (highWaterMark === undefined) {
    return defaultValue;
  }

  const normalized = toNumber(highWaterMark);
  if (
    Number.isNaN(normalized) ||
    normalized < 0
  ) {
    throw new RangeError("The highWaterMark option must be a non-negative number");
  }

  return normalized;
}

function validateQueuingStrategySize(value: unknown): (chunk: any) => number {
  if (value === undefined) {
    return function () {
      return 1;
    };
  }

  if (!isCallable(value)) {
    throw new TypeError("size must be a function");
  }

  return value;
}

function validateSinkMethod(sink: any, member: "start" | "write" | "close" | "abort"): void {
  const method = sink[member];
  if (method !== undefined && !isCallable(method)) {
    throw new TypeError(`WritableStream underlying sink ${member} must be a function`);
  }
}

// ============================================================================
// WritableStreamDefaultController
// ============================================================================

export class WritableStreamDefaultController {
  /** @internal */
  _stream: WritableStream<any> | undefined;
  /** @internal */
  _abortReason: any;
  /** @internal */
  _abortController: AbortController;

  /** @internal */
  constructor() {
    this._abortController = new AbortController();
  }

  get signal(): AbortSignal {
    return this._abortController.signal;
  }

  error(e?: any): void {
    const stream = this._stream;
    if (stream === undefined) {
      throw new TypeError('Controller has no associated stream');
    }
    // Route through the erroring machinery (like abort) instead of erroring
    // immediately: FinishErroring must wait for an in-flight sink.write to
    // settle, and a fulfilling sink.write still resolves the user's write().
    // Ibex 'closing' maps to the spec's writable-with-close-queued, so it
    // errors too.
    stream._errorIfNeeded(e);
  }

  get [Symbol.toStringTag](): string {
    return 'WritableStreamDefaultController';
  }
}

// ============================================================================
// WritableStreamDefaultWriter
// ============================================================================

export class WritableStreamDefaultWriter<W = any> {
  /** @internal */
  _stream: WritableStream<W> | undefined;
  /** @internal */
  _releasedError: TypeError | undefined;
  /** @internal */
  _closedPromise: Promise<undefined>;
  /** @internal */
  _closedResolve!: (value?: any) => void;
  /** @internal */
  _closedReject!: (reason: any) => void;
  /** @internal */
  _closedPromiseRecord!: PromiseRecord<undefined>;
  /** @internal */
  _readyPromise: Promise<undefined>;
  /** @internal */
  _readyResolve!: (value?: any) => void;
  /** @internal */
  _readyReject!: (reason: any) => void;
  /** @internal */
  _readyPromiseRecord!: PromiseRecord<undefined>;

  /** @internal */
  _setClosedPromiseRecord(record: PromiseRecord<undefined>): void {
    this._closedPromiseRecord = record;
    this._closedPromise = record.promise;
    this._closedResolve = record.resolve;
    this._closedReject = record.reject as (reason: any) => void;
  }

  /** @internal */
  _setReadyPromiseRecord(record: PromiseRecord<undefined>): void {
    this._readyPromiseRecord = record;
    this._readyPromise = record.promise;
    this._readyResolve = record.resolve;
    this._readyReject = record.reject as (reason: any) => void;
  }

  /** @internal */
  _ensureClosedPromiseRejected(reason: any): void {
    const record = this._closedPromiseRecord;
    if (record.state === 'pending') {
      markPromiseHandled(record.promise);
      record.reject(reason);
      return;
    }

    this._setClosedPromiseRecord(createRejectedPromiseRecord(reason));
  }

  /** @internal */
  _ensureReadyPromiseRejected(reason: any): void {
    const record = this._readyPromiseRecord;
    if (record.state === 'pending') {
      markPromiseHandled(record.promise);
      record.reject(reason);
      return;
    }

    this._setReadyPromiseRecord(createRejectedPromiseRecord(reason));
  }

  constructor(stream: WritableStream<W>) {
    if (!(stream instanceof WritableStream)) {
      throw new TypeError('WritableStreamDefaultWriter can only be constructed with a WritableStream instance');
    }
    if (stream._writer !== undefined) {
      throw new TypeError('This stream already has a writer');
    }

    stream._writer = this;
    this._stream = stream;

    const state = stream._state;

    if (state === 'writable') {
      // Closed promise waits for close
      this._setClosedPromiseRecord(createDeferred<undefined>());

      // Ready depends on backpressure
      if (stream._backpressure) {
        this._setReadyPromiseRecord(createDeferred<undefined>());
      } else {
        this._setReadyPromiseRecord(createResolvedPromiseRecord(undefined));
      }
    } else if (state === 'closing') {
      // Closing: ready is resolved (no more writes), closed waits
      this._setReadyPromiseRecord(createResolvedPromiseRecord(undefined));
      this._setClosedPromiseRecord(createDeferred<undefined>());
    } else if (state === 'closed') {
      this._setClosedPromiseRecord(createResolvedPromiseRecord(undefined));
      this._setReadyPromiseRecord(createResolvedPromiseRecord(undefined));
    } else {
      // errored
      const storedError = stream._storedError;
      this._setClosedPromiseRecord(createRejectedPromiseRecord(storedError));
      this._setReadyPromiseRecord(createRejectedPromiseRecord(storedError));
    }
  }

  get closed(): Promise<undefined> {
    markPromiseHandled(this._closedPromise);
    return this._closedPromise;
  }

  get ready(): Promise<undefined> {
    markPromiseHandled(this._readyPromise);
    return this._readyPromise;
  }

  get desiredSize(): number | null {
    if (this._stream === undefined) {
      throw this._releasedError ?? createReleasedWriterError();
    }
    const state = this._stream._state;
    if (state === 'errored' || state === 'erroring') return null;
    if (state === 'closed' || state === 'closing') return 0;
    return this._stream._strategyHWM - (this._stream._queueTotalSize + this._stream._inFlightWriteSize);
  }

  write(chunk?: W): Promise<void> {
    if (this._stream === undefined) {
      return createHandledRejectedPromise(this._releasedError ?? createReleasedWriterError());
    }
    if (this._stream._state !== 'writable') {
      if (this._stream._state === 'errored' || this._stream._state === 'erroring') {
        return createHandledRejectedPromise(this._stream._storedError);
      }
      return createHandledRejectedPromise(new TypeError('The stream is not in the writable state and cannot be written to'));
    }

    return this._stream._writeChunk(chunk as W);
  }

  close(): Promise<void> {
    if (this._stream === undefined) {
      return createHandledRejectedPromise(this._releasedError ?? createReleasedWriterError());
    }

    const stream = this._stream;

    if (stream._state !== 'writable') {
      if (stream._state === 'closed') {
        return createHandledRejectedPromise(new TypeError('The stream is already closed'));
      }
      if (stream._state === 'closing') {
        return createHandledRejectedPromise(new TypeError('The stream is already closing'));
      }
      return createHandledRejectedPromise(new TypeError('The stream is not writable'));
    }

    const p = stream._closeStream();
    markPromiseHandled(p);
    return p;
  }

  abort(reason?: any): Promise<void> {
    if (this._stream === undefined) {
      return createHandledRejectedPromise(this._releasedError ?? createReleasedWriterError());
    }

    const p = this._stream._abortStream(reason);
    markPromiseHandled(p);
    return p;
  }

  releaseLock(): void {
    if (this._stream === undefined) return;

    const stream = this._stream;
    const releasedError = createReleasedWriterError();
    this._releasedError = releasedError;

    // Promise reactions must observe ready rejecting before closed.
    this._ensureReadyPromiseRejected(releasedError);
    this._ensureClosedPromiseRejected(releasedError);

    stream._writer = undefined;
    this._stream = undefined;
  }

  get [Symbol.toStringTag](): string {
    return 'WritableStreamDefaultWriter';
  }
}

// ============================================================================
// WritableStream
// ============================================================================

export class WritableStream<W = any> {
  /** @internal */
  _state: WritableStreamState = 'writable';
  /** @internal */
  _storedError: any;
  /** @internal */
  _writer: WritableStreamDefaultWriter<W> | undefined;
  /** @internal */
  _controller: WritableStreamDefaultController;
  /** @internal */
  _writeAlgorithm: ((chunk: W, controller: WritableStreamDefaultController) => Promise<void>) | undefined;
  /** @internal */
  _closeAlgorithm: (() => Promise<void>) | undefined;
  /** @internal */
  _abortAlgorithm: ((reason?: any) => Promise<void>) | undefined;
  /** @internal */
  _started: boolean = false;
  /** @internal */
  _writing: boolean = false;
  /** @internal */
  _closeAlgorithmRunning: boolean = false;
  /** @internal */
  _inFlightWriteRequest: {
    resolve: () => void;
    reject: (reason: any) => void;
  } | undefined;
  /** @internal */
  _inFlightWriteSize: number = 0;
  /** @internal */
  _inFlightCloseRequest: {
    resolve: () => void;
    reject: (reason: any) => void;
  } | undefined;
  /** @internal */
  _writeRequests: Array<{
    chunk: W;
    resolve: () => void;
    reject: (reason: any) => void;
  }> = [];
  /** @internal */
  _pendingAbortRequest: {
    reason: any;
    wasAlreadyErroring: boolean;
    promise: Promise<void>;
    resolve: () => void;
    reject: (reason: any) => void;
  } | undefined;
  /** @internal */
  _backpressure: boolean = false;
  /** @internal */
  _strategyHWM: number;
  /** @internal */
  _strategySizeAlgorithm: (chunk: W) => number;
  /** @internal */
  _queue: Array<{ chunk: W; size: number }> = [];
  /** @internal */
  _queueTotalSize: number = 0;

  constructor(
    underlyingSink?: UnderlyingSink<W>,
    strategy?: QueuingStrategy<W>
  ) {
    const sink = underlyingSink === undefined ? {} : Object(underlyingSink);
    const sinkAsAny = sink as any;
    if (sink.type !== undefined) {
      throw new TypeError("Unsupported underlying sink type");
    }
    const strat = strategy === undefined ? {} : Object(strategy);

    if (sink.start !== undefined) {
      validateSinkMethod(sink, "start");
    }
    if (sink.write !== undefined) {
      validateSinkMethod(sink, "write");
    }
    if (sink.close !== undefined) {
      validateSinkMethod(sink, "close");
    }
    if (sink.abort !== undefined) {
      validateSinkMethod(sink, "abort");
    }

    this._controller = new WritableStreamDefaultController();
    this._controller._stream = this;

    this._strategyHWM = validateHighWaterMark((strat as any).highWaterMark, 1);
    this._strategySizeAlgorithm = validateQueuingStrategySize((strat as any).size);

    this._writeAlgorithm = sink.write
      ? function (chunk: W, controller: WritableStreamDefaultController) {
          try {
            return resolveHandledPromise(sinkAsAny.write(chunk, controller));
          } catch (e) {
            return createHandledRejectedPromise(e);
          }
        }
      : undefined;
    this._closeAlgorithm = sink.close
      ? function () {
          try {
            return resolveHandledPromise(sinkAsAny.close());
          } catch (e) {
            return createHandledRejectedPromise(e);
          }
        }
      : undefined;
    this._abortAlgorithm = sink.abort
      ? function (reason?: any) {
          try {
            return resolveHandledPromise(sinkAsAny.abort(reason));
          } catch (e) {
            return createHandledRejectedPromise(e);
          }
        }
      : undefined;

    // Update backpressure
    this._updateBackpressure();

    // Run start algorithm
    const self = this;
    if (sink.start) {
      let startResult: any;
      try {
        startResult = sinkAsAny.start(this._controller);
      } catch (startError) {
        // Per spec: if start throws synchronously, the stream transitions to
        // errored state asynchronously — the constructor must NOT throw.
        // Route through the erroring machine so an abort() that raced start
        // still settles once start is marked done.
        promiseThen(originalPromiseResolve(), function () {
          self._started = true;
          self._dealWithRejection(startError);
        });
        return;
      }
      promiseThen(resolveHandledPromise(startResult),
        function () {
          self._started = true;
          self._advanceQueueIfNeeded();
        },
        function (e) {
          self._started = true;
          self._dealWithRejection(e);
        }
      );
    } else {
      // If there is no start, mark as started on next microtask
      promiseThen(originalPromiseResolve(), function () {
        self._started = true;
        self._advanceQueueIfNeeded();
      });
    }
  }

  get locked(): boolean {
    return this._writer !== undefined;
  }

  async abort(reason?: any): Promise<void> {
    if (this.locked) {
      throw new TypeError('Cannot abort a locked stream');
    }
    return await this._abortStream(reason);
  }

  async close(): Promise<void> {
    if (this.locked) {
      throw new TypeError('Cannot close a locked stream');
    }
    if (this._state !== 'writable') {
      if (this._state === 'closed') {
        throw new TypeError('The stream is already closed');
      }
      throw new TypeError('The stream is not writable');
    }
    return await this._closeStream();
  }

  getWriter(): WritableStreamDefaultWriter<W> {
    return new WritableStreamDefaultWriter(this);
  }

  get [Symbol.toStringTag](): string {
    return 'WritableStream';
  }

  // ============================================================================
  // Internal methods
  // ============================================================================

  /** @internal */
  _writeChunk(chunk: W): Promise<void> {
    // An abrupt or invalid size() completion runs
    // WritableStreamDefaultControllerErrorIfNeeded: the whole stream becomes
    // errored (ready rejects, later writes reject), not just this write.
    let size: number;
    try {
      const sizeAlgorithm = this._strategySizeAlgorithm;
      size = toNumber(sizeAlgorithm(chunk));
    } catch (error) {
      this._errorIfNeeded(error);
      return originalPromiseReject(error);
    }

    if (
      Number.isNaN(size) ||
      !Number.isFinite(size) ||
      size < 0
    ) {
      const rangeError = new RangeError("The size returned by the size() algorithm must be a non-negative finite number");
      this._errorIfNeeded(rangeError);
      return originalPromiseReject(rangeError);
    }

    const self = this;
    const p = new Promise<void>(function (resolve, reject) {
      self._writeRequests.push({ chunk: chunk, resolve: resolve, reject: reject });
      self._queue.push({ chunk: chunk, size: size });
      self._queueTotalSize += size;
      self._updateBackpressure();
      self._advanceQueueIfNeeded();
    });
    markPromiseHandled(p);
    return p;
  }

  /** @internal */
  _closeStream(): Promise<void> {
    // WritableStreamClose step 6: once close is requested no further writes
    // can be queued, so a ready promise pending on backpressure resolves now
    // (otherwise `await writer.ready` after close() hangs forever with e.g.
    // highWaterMark 0).
    const writer = this._writer;
    if (writer !== undefined && this._backpressure && this._state === 'writable') {
      writer._readyResolve?.(undefined);
    }

    this._state = 'closing';

    const self = this;
    return new Promise(function (resolve, reject) {
      self._inFlightCloseRequest = { resolve: resolve, reject: reject };
      self._advanceQueueIfNeeded();
    });
  }

  /**
   * @internal
   * Implements WritableStreamAbort. The abort algorithm (sink.abort) must NOT
   * run until any in-flight write/close (or a pending start) settles — running
   * it concurrently would let sink.abort race a still-executing sink.write and
   * spuriously reject a write whose bytes were actually flushed. A second abort
   * while one is pending returns the first abort's promise rather than
   * resolving to undefined.
   */
  _abortStream(reason?: any): Promise<void> {
    if (this._state === 'closed' || this._state === 'errored') {
      return originalPromiseResolve();
    }

    // A concurrent abort returns the in-flight abort's promise.
    if (this._pendingAbortRequest !== undefined) {
      return this._pendingAbortRequest.promise;
    }

    // Signal abort on the controller so sink code observing the signal can bail.
    this._controller._abortReason = reason;
    this._controller._abortController.abort(reason);

    const wasAlreadyErroring = this._state === 'erroring';
    if (wasAlreadyErroring) {
      // A stream already erroring ignores the new reason (spec).
      reason = undefined;
    }

    const record = createDeferred<void>();
    markPromiseHandled(record.promise);
    this._pendingAbortRequest = {
      reason: reason,
      wasAlreadyErroring: wasAlreadyErroring,
      promise: record.promise,
      resolve: record.resolve as () => void,
      reject: record.reject,
    };

    if (!wasAlreadyErroring) {
      this._startErroring(reason);
    }

    return record.promise;
  }

  /** @internal Whether a write or close operation is still in flight. */
  _hasOperationInFlight(): boolean {
    return this._inFlightWriteRequest !== undefined || this._closeAlgorithmRunning;
  }

  /**
   * @internal
   * WritableStreamStartErroring: transition to the transient 'erroring' state.
   * FinishErroring (which runs sink.abort and settles the abort promise) is
   * deferred until any in-flight operation settles and start() has resolved.
   */
  _startErroring(reason: any): void {
    this._state = 'erroring';
    this._storedError = reason;

    const writer = this._writer;
    if (writer) {
      writer._ensureReadyPromiseRejected(reason);
    }

    if (!this._hasOperationInFlight() && this._started) {
      this._finishErroring();
    }
  }

  /**
   * @internal
   * WritableStreamFinishErroring: move to 'errored', reject queued writes, then
   * run the abort algorithm (if this erroring was triggered by abort) and
   * settle the pending abort promise on its completion.
   */
  _finishErroring(): void {
    this._state = 'errored';

    // ErrorSteps: discard the queue.
    this._queue = [];
    this._queueTotalSize = 0;

    const storedError = this._storedError;
    const writeRequests = this._writeRequests;
    this._writeRequests = [];
    for (var i = 0; i < writeRequests.length; i++) {
      writeRequests[i].reject(storedError);
    }

    const abortRequest = this._pendingAbortRequest;
    if (abortRequest === undefined) {
      this._rejectClosedPromiseIfNeeded();
      return;
    }
    this._pendingAbortRequest = undefined;

    if (abortRequest.wasAlreadyErroring) {
      abortRequest.reject(storedError);
      this._rejectClosedPromiseIfNeeded();
      return;
    }

    const self = this;
    const abortAlgorithm = this._abortAlgorithm;
    const promise = abortAlgorithm
      ? abortAlgorithm(abortRequest.reason)
      : originalPromiseResolve();
    promiseThen(promise,
      function () {
        abortRequest.resolve();
        self._rejectClosedPromiseIfNeeded();
      },
      function (r) {
        abortRequest.reject(r);
        self._rejectClosedPromiseIfNeeded();
      }
    );
  }

  /**
   * @internal
   * WritableStreamDealWithRejection: routes a rejected write into the erroring
   * machine — start erroring from a live state, or finish an in-progress one.
   */
  _dealWithRejection(reason: any): void {
    const state = this._state;
    if (state === 'writable' || state === 'closing') {
      this._startErroring(reason);
      return;
    }
    if (state === 'erroring') {
      // The in-flight operation that was blocking FinishErroring has settled.
      this._finishErroring();
    }
    // 'errored'/'closed': already terminal, nothing to do.
  }

  /** @internal WritableStreamRejectCloseAndClosedPromiseIfNeeded. */
  _rejectClosedPromiseIfNeeded(): void {
    const storedError = this._storedError;
    const inFlightCloseRequest = this._inFlightCloseRequest;
    if (inFlightCloseRequest) {
      inFlightCloseRequest.reject(storedError);
      this._inFlightCloseRequest = undefined;
    }
    const writer = this._writer;
    if (writer) {
      writer._ensureClosedPromiseRejected(storedError);
    }
  }

  /**
   * @internal
   * WritableStreamDefaultControllerErrorIfNeeded: error the stream through the
   * StartErroring/FinishErroring machinery, so any in-flight sink.write/close
   * settles before the stream finishes erroring. Both 'writable' and 'closing'
   * map to the spec's "writable" state (closing = close queued/in flight).
   * Contrast _errorStream below, which errors immediately and rejects the
   * in-flight write.
   */
  _errorIfNeeded(e: any): void {
    if (this._state === 'writable' || this._state === 'closing') {
      this._startErroring(e);
    }
  }

  /** @internal */
  _errorStream(e: any): void {
    if (this._state !== 'writable' && this._state !== 'closing') return;

    this._state = 'errored';
    this._storedError = e;

    // Reject all pending write requests
    const inFlightWriteRequest = this._inFlightWriteRequest;
    if (inFlightWriteRequest) {
      inFlightWriteRequest.reject(e);
      this._inFlightWriteRequest = undefined;
    }
    this._inFlightWriteSize = 0;
    this._writing = false;
    for (var i = 0; i < this._writeRequests.length; i++) {
      this._writeRequests[i].reject(e);
    }
    this._writeRequests = [];
    this._queue = [];
    this._queueTotalSize = 0;

    // If there was an in-flight close request, reject it too
    const inFlightClose = this._inFlightCloseRequest;
    if (inFlightClose) {
      inFlightClose.reject(e);
      this._inFlightCloseRequest = undefined;
    }

    this._notifyWriterError(e);
  }

  /** @internal */
  _notifyWriterError(e: any): void {
    const writer = this._writer;
    if (writer) {
      writer._ensureReadyPromiseRejected(e);
      writer._ensureClosedPromiseRejected(e);
    }
  }

  /** @internal */
  _advanceQueueIfNeeded(): void {
    if (!this._started) return;
    if (this._writing) return;

    // A deferred abort/error can now finish because no write is in flight.
    if (this._state === 'erroring') {
      this._finishErroring();
      return;
    }

    if (this._state === 'errored') {
      return;
    }

    // Process close if closing and queue is empty
    if (this._state === 'closing' && this._queue.length === 0) {
      this._finishClose();
      return;
    }

    // Process next write from queue
    if (this._queue.length === 0) return;
    if (this._state !== 'writable' && this._state !== 'closing') return;

    const entry = this._queue.shift()!;
    this._queueTotalSize -= entry.size;

    const writeRequest = this._writeRequests.shift();
    this._inFlightWriteRequest = writeRequest;
    this._inFlightWriteSize = entry.size;
    this._writing = true;

    const self = this;
    const writeAlgorithm = this._writeAlgorithm;
    const writePromise = writeAlgorithm
      ? writeAlgorithm(entry.chunk, this._controller)
      : originalPromiseResolve();

    promiseThen(writePromise,
      function () {
        // The bytes were written: resolve the write request even if an abort
        // arrived mid-flight. _advanceQueueIfNeeded then runs the deferred
        // FinishErroring when the stream is erroring.
        self._writing = false;
        self._inFlightWriteSize = 0;
        const inFlightWriteRequest = self._inFlightWriteRequest;
        self._inFlightWriteRequest = undefined;
        if (inFlightWriteRequest) {
          inFlightWriteRequest.resolve();
        }
        self._updateBackpressure();
        self._advanceQueueIfNeeded();
      },
      function (reason) {
        self._writing = false;
        self._inFlightWriteSize = 0;
        const inFlightWriteRequest = self._inFlightWriteRequest;
        self._inFlightWriteRequest = undefined;
        if (inFlightWriteRequest) {
          inFlightWriteRequest.reject(reason);
        }
        // Route through the erroring machine so a pending abort still settles.
        self._dealWithRejection(reason);
      }
    );
  }

  /** @internal */
  _finishClose(): void {
    const closeAlgorithm = this._closeAlgorithm;
    // Mark the close algorithm as in flight so a concurrent abort defers its
    // FinishErroring until the close settles.
    this._closeAlgorithmRunning = true;
    let closePromise: Promise<void>;
    try {
      closePromise = closeAlgorithm ? closeAlgorithm() : originalPromiseResolve();
    } catch (e) {
      // The close algorithm threw synchronously; treat as a rejected promise.
      closePromise = originalPromiseReject(e);
    }

    const self = this;
    promiseThen(closePromise,
      function () {
        self._closeAlgorithmRunning = false;
        if (self._state !== 'closing' && self._state !== 'erroring') {
          return;
        }

        const closeRequest = self._inFlightCloseRequest;
        self._inFlightCloseRequest = undefined;
        if (closeRequest) {
          closeRequest.resolve();
        }

        if (self._state === 'erroring') {
          // The close already flushed successfully, so a concurrent abort
          // resolves and the stream closes cleanly without running sink.abort.
          self._storedError = undefined;
          const abortRequest = self._pendingAbortRequest;
          if (abortRequest) {
            self._pendingAbortRequest = undefined;
            abortRequest.resolve();
          }
        }

        self._state = 'closed';
        const writer = self._writer;
        if (writer) {
          writer._closedResolve?.(undefined);
        }
      },
      function (e) {
        self._closeAlgorithmRunning = false;
        if (self._state !== 'closing' && self._state !== 'erroring') {
          return;
        }

        const closeRequest = self._inFlightCloseRequest;
        self._inFlightCloseRequest = undefined;
        const abortRequest = self._pendingAbortRequest;
        self._pendingAbortRequest = undefined;

        self._state = 'errored';
        self._storedError = e;

        if (closeRequest) {
          closeRequest.reject(e);
        }
        if (abortRequest) {
          abortRequest.reject(e);
        }

        self._notifyWriterError(e);
      }
    );
  }

  /** @internal */
  _updateBackpressure(): void {
    const desiredSize = this._strategyHWM - (this._queueTotalSize + this._inFlightWriteSize);
    const backpressure = desiredSize <= 0;

    if (backpressure !== this._backpressure) {
      this._backpressure = backpressure;

      const writer = this._writer;
      if (writer) {
        if (backpressure) {
          // Create a new pending ready promise
          if (writer._readyPromiseRecord.state !== 'pending') {
            writer._setReadyPromiseRecord(createDeferred<undefined>());
          }
        } else if (writer._readyPromiseRecord.state === 'pending') {
          // Resolve the ready promise
          writer._readyResolve?.(undefined);
        }
      }
    }
  }
}
