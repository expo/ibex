// @ts-nocheck
/**
 * TransformStream - WHATWG Streams API Implementation
 *
 * @see https://streams.spec.whatwg.org/#ts-class
 *
 * This implementation supports:
 * - Transformer with start/transform/flush
 * - TransformStreamDefaultController with enqueue/error/terminate
 * - Readable and writable sides
 * - Backpressure propagation
 * - Symbol.toStringTag
 */

import {
  ReadableStream,
  ReadableStreamDefaultController,
} from './ReadableStream';
import {
  WritableStream,
  WritableStreamDefaultController,
} from './WritableStream';
import type { QueuingStrategy } from './WritableStream';

// Capture Promise methods at module load time to be immune to monkey-patching
const originalPromiseThen = Promise.prototype.then;
const originalPromiseResolve = Promise.resolve.bind(Promise);
const originalPromiseReject = Promise.reject.bind(Promise);

function promiseThen<T, TResult1 = T, TResult2 = never>(
  promise: PromiseLike<T>,
  onFulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
  onRejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null
): Promise<TResult1 | TResult2> {
  return originalPromiseThen.call(promise, onFulfilled, onRejected);
}

// ============================================================================
// Types
// ============================================================================

export interface Transformer<I = any, O = any> {
  start?: (controller: TransformStreamDefaultController<O>) => void | Promise<void>;
  transform?: (chunk: I, controller: TransformStreamDefaultController<O>) => void | Promise<void>;
  cancel?: (reason: any) => void | Promise<void>;
  flush?: (controller: TransformStreamDefaultController<O>) => void | Promise<void>;
  readableType?: undefined;
  writableType?: undefined;
}

// ============================================================================
// TransformStreamDefaultController
// ============================================================================

export class TransformStreamDefaultController<O = any> {
  /** @internal */
  _stream: TransformStream<any, O>;
  /** @internal */
  _transformAlgorithm: ((chunk: any) => Promise<void>) | undefined;
  /** @internal */
  _flushAlgorithm: (() => Promise<void>) | undefined;

  /** @internal */
  constructor(stream: TransformStream<any, O>) {
    this._stream = stream;
  }

  get desiredSize(): number | null {
    const readableController = this._stream._readable._controller;
    if (readableController === undefined) return null;
    return readableController.desiredSize;
  }

  enqueue(chunk: O): void {
    const readableController = this._stream._readable._controller;
    if (readableController === undefined) {
      throw new TypeError('Readable side has no controller');
    }

    try {
      readableController.enqueue(chunk);
    } catch (e) {
      // If enqueue throws (e.g., stream is not readable), propagate error
      // (TransformStreamErrorWritableAndUnblockWrite: error the writable via
      // the erroring machinery and release any backpressure-blocked write).
      const writable = this._stream._writable;
      if (writable === undefined) {
        this._stream._pendingWritableError = e;
      } else {
        writable._errorIfNeeded(e);
      }
      if (this._stream._backpressure) {
        this._stream._updateBackpressure(false);
      }
      throw this._stream._readable._storedError ?? e;
    }

    // Update backpressure based on readable side
    const backpressure = readableController.desiredSize !== null &&
      readableController.desiredSize <= 0;
    if (backpressure !== this._stream._backpressure) {
      this._stream._updateBackpressure(backpressure);
    }
  }

  error(reason?: any): void {
    const readable = this._stream._readable;
    const writable = this._stream._writable;

    // Error the readable side
    if (readable._controller) {
      readable._controller._error(reason);
    }

    // Error the writable side through the erroring machinery: an in-flight
    // sink.write (e.g. the transform() that called controller.error) must
    // settle first, and a fulfilling transform still resolves that write().
    if (writable === undefined) {
      this._stream._pendingWritableError = reason;
    } else {
      writable._errorIfNeeded(reason);
    }

    // Update backpressure flag
    if (this._stream._backpressure) {
      this._stream._updateBackpressure(false);
    }
  }

  terminate(): void {
    if (this._stream._isTerminated) {
      return;
    }
    this._stream._isTerminated = true;

    const readable = this._stream._readable;
    const writable = this._stream._writable;

    // Close the readable side
    if (readable._state === 'readable' && readable._controller) {
      readable._controller.close();
    }

    // Error the writable side with a TypeError (via the erroring machinery,
    // so an in-flight write settles before the stream finishes erroring)
    const error = new TypeError('TransformStream terminated');
    if (writable === undefined) {
      this._stream._pendingWritableError = error;
    } else {
      writable._errorIfNeeded(error);
    }

    // Update backpressure flag
    if (this._stream._backpressure) {
      this._stream._updateBackpressure(false);
    }
  }

  get [Symbol.toStringTag](): string {
    return 'TransformStreamDefaultController';
  }
}

// ============================================================================
// TransformStream
// ============================================================================

export class TransformStream<I = any, O = any> {
  /** @internal */
  _readable: ReadableStream<O>;
  /** @internal */
  _writable: WritableStream<I>;
  /** @internal */
  _controller: TransformStreamDefaultController<O>;
  /** @internal */
  _backpressure: boolean = false;
  /** @internal */
  _backpressureResolve: ((value?: any) => void) | undefined;
  /** @internal */
  _pendingWritableError: any = undefined;
  /** @internal */
  _isTerminated: boolean = false;

  get readable(): ReadableStream<O> {
    return this._readable;
  }

  get writable(): WritableStream<I> {
    return this._writable;
  }

  constructor(
    transformer?: Transformer<I, O>,
    writableStrategy?: QueuingStrategy<I>,
    readableStrategy?: QueuingStrategy<O>
  ) {
    const trans = transformer ?? {};
    const transformAsAny = trans as any;
    let pendingCancel: Promise<void> | undefined;
    const cancelAlgorithm = (reason: any) => {
      if (pendingCancel !== undefined) {
        return pendingCancel;
      }

      if (transformAsAny.cancel === undefined) {
        pendingCancel = originalPromiseResolve();
        return pendingCancel;
      }

      try {
        pendingCancel = originalPromiseResolve(transformAsAny.cancel(reason));
      } catch (e) {
        pendingCancel = originalPromiseReject(e);
      }
      return pendingCancel;
    };

    // Validate types
    if (trans.readableType !== undefined) {
      throw new RangeError('readableType not supported');
    }
    if (trans.writableType !== undefined) {
      throw new RangeError('writableType not supported');
    }

    this._controller = new TransformStreamDefaultController(this);

    // Build transform algorithm
    const controller = this._controller;
    const transformAlgorithm = trans.transform
      ? function (chunk: I): Promise<void> {
          try {
            return originalPromiseResolve(transformAsAny.transform(chunk, controller));
          } catch (e) {
            return originalPromiseReject(e);
          }
        }
      : function (chunk: I): Promise<void> {
          // Default: pass-through
          try {
            controller.enqueue(chunk as unknown as O);
          } catch (e) {
            return originalPromiseReject(e);
          }
          return originalPromiseResolve();
        };

    // Build flush algorithm
    const flushAlgorithm = trans.flush
      ? function (): Promise<void> {
          try {
            return originalPromiseResolve(transformAsAny.flush(controller));
          } catch (e) {
            return originalPromiseReject(e);
          }
        }
      : function (): Promise<void> {
          return originalPromiseResolve();
        };

    controller._transformAlgorithm = transformAlgorithm;
    controller._flushAlgorithm = flushAlgorithm;

    // Create readable side
    // The readable's pull should resolve backpressure
    // Per spec, TransformStream readable side defaults to HWM 0 (not 1 like
    // a standalone ReadableStream). This ensures pull is only triggered by
    // actual read requests, not by available queue space, which is critical
    // for correct backpressure propagation.
    const self = this;
    // ExtractHighWaterMark(readableStrategy, 0): the readable side defaults to
    // HWM 0 even when a strategy object is supplied without highWaterMark
    // (otherwise the transformer runs one chunk ahead of demand and
    // backpressure timing drifts from the spec).
    const effectiveReadableStrategy = {
      highWaterMark: (readableStrategy as any)?.highWaterMark ?? 0,
      size: (readableStrategy as any)?.size,
    };
    this._readable = new ReadableStream<O>(
      {
        pull: function () {
          // When the readable side pulls, that means the consumer wants data.
          // Resolve backpressure so the writable side can proceed.
          if (self._backpressure) {
            self._updateBackpressure(false);
          }
          return originalPromiseResolve();
        },
        cancel: function (reason: any) {
          // When readable is cancelled, error the writable (via the erroring
          // machinery) and unblock any backpressure-blocked write
          return promiseThen(cancelAlgorithm(reason), function () {
            self._writable._errorIfNeeded(reason);
            if (self._backpressure) {
              self._updateBackpressure(false);
            }
          }, function (e) {
            self._writable._errorIfNeeded(e);
            if (self._backpressure) {
              self._updateBackpressure(false);
            }
            throw e;
          });
        },
      },
      effectiveReadableStrategy
    );

    // Create writable side
    this._writable = new WritableStream<I>(
      {
        start: function (ctrl: WritableStreamDefaultController) {
          // Run the transformer's start algorithm
          if (transformAsAny.start) {
            return transformAsAny.start(controller);
          }
          return undefined;
        },
        write: function (chunk: I) {
          // If there's backpressure, wait for it to be resolved
          if (self._backpressure) {
            return promiseThen(new Promise(function (resolve) {
              const prevResolve = self._backpressureResolve;
              self._backpressureResolve = function (value) {
                if (prevResolve) prevResolve(value);
                resolve(undefined);
              };
            }), function () {
              // The unblock may come from an error/terminate/cancel path
              // (TransformStreamErrorWritableAndUnblockWrite): surface the
              // stored error instead of transforming a chunk on a stream
              // that started erroring while this write was blocked.
              const writableState = self._writable._state;
              if (writableState === 'erroring' || writableState === 'errored') {
                throw self._writable._storedError;
              }
              return transformAlgorithm(chunk);
            });
          }
          return transformAlgorithm(chunk);
        },
        close: function () {
          // Run the flush algorithm then close the readable side
          return promiseThen(flushAlgorithm(), function () {
            const readableController = self._readable._controller;
            if (readableController) {
              // Only close if still readable
              if (self._readable._state === 'readable') {
                readableController.close();
              }
            }
          }, function (e) {
            // Error both sides
            if (self._readable._controller) {
              self._readable._controller._error(e);
            }
            throw e;
          });
        },
        abort: function (reason: any) {
          return promiseThen(cancelAlgorithm(reason), function () {
            if (self._readable._controller) {
              self._readable._controller._error(reason);
            }
          }, function (e) {
            if (self._readable._controller) {
              self._readable._controller._error(e);
            }
            throw e;
          });
        },
      },
      writableStrategy
    );
    if (this._pendingWritableError !== undefined) {
      const pendingError = this._pendingWritableError;
      this._pendingWritableError = undefined;
      this._writable._errorIfNeeded(pendingError);
    }

    // Per spec, TransformStream starts with backpressure true. This ensures
    // writes to the writable side wait until the readable side is being consumed.
    this._updateBackpressure(true);
  }

  /** @internal */
  _updateBackpressure(backpressure: boolean): void {
    if (this._backpressure !== backpressure) {
      const wasBackpressured = this._backpressure;
      this._backpressure = backpressure;

      // If backpressure was just relieved, notify anyone waiting
      if (wasBackpressured && !backpressure) {
        if (this._backpressureResolve) {
          this._backpressureResolve(undefined);
          this._backpressureResolve = undefined;
        }
      }
    }
  }

  get [Symbol.toStringTag](): string {
    return 'TransformStream';
  }
}
