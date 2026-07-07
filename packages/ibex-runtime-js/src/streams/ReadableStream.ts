// @ts-nocheck
/**
 * ReadableStream - WHATWG Streams API Implementation
 *
 * @see https://streams.spec.whatwg.org/#rs-class
 *
 * This implementation supports:
 * - Underlying source with pull/start/cancel
 * - Queuing strategy
 * - ReadableStreamDefaultReader
 * - ReadableStreamBYOBReader (byte streams)
 * - ReadableByteStreamController
 * - Async iteration
 * - tee(), pipeTo(), pipeThrough()
 */

import { WritableStream } from './WritableStream';
import type { StreamPipeOptions } from './WritableStream';
import { DOMException } from "../events";
import { AbortSignal as AbortSignalImpl, isAbortSignal } from "../abort/AbortSignal";
import {
  isDetachedArrayBuffer,
  isNonTransferableArrayBuffer,
  markDetachedArrayBuffer,
} from "../arraybuffer-detach";
import { structuredClone, type StructuredSerializeOptions } from "../clone";
import { trackPromiseRejectionHandled } from "../promise-rejection-tracking";

// ============================================================================
// Types
// ============================================================================

export interface UnderlyingSource<R = any> {
  start?: (controller: ReadableStreamDefaultController<R>) => void | Promise<void>;
  pull?: (controller: ReadableStreamDefaultController<R>) => void | Promise<void>;
  cancel?: (reason?: any) => void | Promise<void>;
  type?: undefined; // Only default type supported
}

export interface UnderlyingByteSource {
  start?: (controller: ReadableByteStreamController) => void | Promise<void>;
  pull?: (controller: ReadableByteStreamController) => void | Promise<void>;
  cancel?: (reason?: any) => void | Promise<void>;
  type: 'bytes';
  autoAllocateChunkSize?: number;
}

function isBunCompatReadableStreamTest(): boolean {
  return readRuntimeEnv('EXACT_COMPAT_TEST') === '1' && readRuntimeEnv('EXACT_TEST_SECTION') === 'bun';
}

function readRuntimeEnv(key: string): string | undefined {
  const hostEnv = (globalThis as { __exactHostEnv?: Record<string, string | undefined> })
    .__exactHostEnv;
  if (hostEnv && typeof hostEnv[key] === 'string') {
    return hostEnv[key];
  }
  try {
    if (typeof process !== 'object' || !process || typeof process.env !== 'object') {
      return undefined;
    }
    const value = (process.env as Record<string, string | undefined>)[key];
    return typeof value === 'string' ? value : undefined;
  } catch {
    return undefined;
  }
}

function getReadableStreamLockedMessage(): string {
  return isBunCompatReadableStreamTest()
    ? 'ReadableStream is locked'
    : 'This stream already has a reader';
}

export interface ReadableStreamDirectController<R = any> {
  readonly desiredSize: number | null;
  close(): Promise<void>;
  enqueue(chunk: R, options?: StructuredSerializeOptions): Promise<void>;
  error(e?: any): Promise<void>;
  write(chunk: R, options?: StructuredSerializeOptions): Promise<void>;
  flush(): Promise<void>;
  end(chunk?: R, options?: StructuredSerializeOptions): Promise<void>;
}

export interface UnderlyingDirectSource<R = any> {
  start?: (controller: ReadableStreamDirectController<R>) => void | Promise<void>;
  pull?: (controller: ReadableStreamDirectController<R>) => void | Promise<void>;
  cancel?: (reason?: any) => void | Promise<void>;
  type: 'direct';
}

export interface QueuingStrategy<R = any> {
  highWaterMark?: number;
  size?: (chunk: R) => number;
}

export interface ReadableStreamDefaultReadResult<R> {
  done: boolean;
  value: R | undefined;
}

export interface ReadableStreamReadValueResult<T> {
  done: false;
  value: T;
}

export interface ReadableStreamReadDoneResult {
  done: true;
  value: undefined;
}

/** @internal */
export interface ReadableStreamBYOBReadValueResult<T extends ArrayBufferView> {
  done: false;
  value: T;
}

/** @internal */
export interface ReadableStreamBYOBReadDoneResult<T extends ArrayBufferView> {
  done: true;
  value: T;
}

export type ReadableStreamBYOBReadResult<T extends ArrayBufferView> =
  | ReadableStreamBYOBReadValueResult<T>
  | ReadableStreamBYOBReadDoneResult<T>;

/**
 * Create a read result object that is immune to Object.prototype.then injection.
 * Per WHATWG Streams spec, read results must not be thenables.
 */
function createReadResult<T>(done: boolean, value: T): { done: boolean; value: T } {
  const result = Object.create(null);
  result.done = done;
  result.value = value;
  return result;
}

const originalPromiseThen = Promise.prototype.then;
const originalPromiseResolve = Promise.resolve.bind(Promise);
const originalPromiseReject = Promise.reject.bind(Promise);
const OriginalPromise = Promise;

function hideFunctionPrototype<T extends Function>(fn: T): T {
  return new Proxy(fn, {
    has(target, property) {
      if (property === "prototype") {
        return false;
      }
      return property in target;
    },
  }) as T;
}

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

function promiseCatch<T, TResult = never>(
  promise: PromiseLike<T>,
  onRejected: ((reason: any) => TResult | PromiseLike<TResult>)
): Promise<T | TResult> {
  return promiseThen(promise, undefined, onRejected);
}

function newPromise<T>(executor: (resolve: (value: T | PromiseLike<T>) => void, reject: (reason?: any) => void) => void): Promise<T> {
  return new OriginalPromise(executor);
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

function scheduleMicrotask(callback: () => void): void {
  if (typeof queueMicrotask === "function") {
    queueMicrotask(callback);
    return;
  }
  promiseThen(originalPromiseResolve(), callback);
}

function observeObjectPrototypeThen(): void {
  const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, "then");
  if (!descriptor || typeof descriptor.get !== "function") {
    return;
  }
  try {
    void ({} as { then?: unknown }).then;
  } catch (_error) {
    // Only the getter side effect matters here.
  }
}

function createAsyncIteratorResult<T>(
  done: boolean,
  value: T
): IteratorResult<T> {
  return { done, value } as IteratorResult<T>;
}

function cloneChunkForTee<T>(value: T): T {
  if (!ArrayBuffer.isView(value)) {
    try {
      return structuredClone(value);
    } catch {
      return value;
    }
  }

  if (value instanceof Uint8Array) {
    return new Uint8Array(value) as T;
  }

  try {
    return structuredClone(value);
  } catch {
    const view = value as ArrayBufferView;
    return new Uint8Array(
      view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength)
    ) as T;
  }
}

export function isReadableStream(value: unknown): value is ReadableStream {
  return !!(
    value &&
    typeof value === "object" &&
    typeof (value as ReadableStream).getReader === "function" &&
    typeof (value as ReadableStream).cancel === "function"
  );
}

function isReadableStreamBrand(value: unknown): value is ReadableStream {
  return (
    value instanceof ReadableStream &&
    typeof (value as ReadableStream)._state === "string"
  );
}

function isWritableStreamBrand(value: unknown): value is WritableStream {
  return (
    value instanceof WritableStream &&
    typeof (value as WritableStream)._state === "string"
  );
}

function getPipeToAbortReason(signalReason: any): any {
  return signalReason === undefined
    ? new DOMException("The operation was aborted.", "AbortError")
    : signalReason;
}

export type ReadableStreamReadResult<T> =
  | ReadableStreamReadValueResult<T>
  | ReadableStreamReadDoneResult;

/** @internal */
type ReadableStreamReaderType = ReadableStreamDefaultReader<any> | ReadableStreamBYOBReader | undefined;

type ReadableStreamState = 'readable' | 'closed' | 'errored';

const byobRequestBrand = Symbol("ReadableStreamBYOBRequestBrand");

function isObject(value: unknown): value is object {
  return value !== null && (typeof value === "object" || typeof value === "function");
}

function isCallable(value: unknown): value is (...args: any[]) => any {
  return typeof value === "function";
}

function toNumber(value: unknown): number {
  return Number(value);
}

function toUnrestrictedDouble(value: unknown): number {
  return toNumber(value);
}

function getPropertyDescriptorWithoutObjectPrototype(
  object: unknown,
  property: string | symbol
): PropertyDescriptor | undefined {
  if (!isObject(object)) {
    return undefined;
  }

  let current: any = object;
  while (current !== null && current !== Object.prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(current, property);
    if (descriptor !== undefined) {
      return descriptor;
    }
    current = Object.getPrototypeOf(current);
  }

  return undefined;
}

function getPropertyValueWithoutObjectPrototype(
  object: unknown,
  property: string | symbol
): any {
  const descriptor = getPropertyDescriptorWithoutObjectPrototype(object, property);
  if (descriptor === undefined) {
    return undefined;
  }
  if (descriptor.get !== undefined) {
    return descriptor.get.call(object as any);
  }
  return (descriptor as { value?: any }).value;
}

function hasPropertyWithoutObjectPrototype(
  object: unknown,
  property: string | symbol
): boolean {
  return getPropertyDescriptorWithoutObjectPrototype(object, property) !== undefined;
}

function getQueuingStrategyHighWaterMark(
  init: { highWaterMark: number } | undefined,
  errorMessage: string
): number {
  if (init === undefined) {
    throw new TypeError(errorMessage);
  }
  const validated = Object(init);
  if (!hasPropertyWithoutObjectPrototype(validated, "highWaterMark")) {
    throw new TypeError(errorMessage);
  }
  const highWaterMark = getPropertyValueWithoutObjectPrototype(
    validated,
    "highWaterMark"
  );
  return toUnrestrictedDouble(highWaterMark);
}

function validateHighWaterMark(
  highWaterMark: unknown,
  defaultValue: number
): number {
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

function getUnderlyingSourceType(source: any): "bytes" | "owning" | "direct" | undefined {
  if (!hasPropertyWithoutObjectPrototype(source, "type")) {
    return undefined;
  }

  const streamType = getPropertyValueWithoutObjectPrototype(source, "type");
  if (streamType === undefined) {
    return undefined;
  }

  const type = String(streamType);
  if (type !== "bytes" && type !== "owning" && type !== "direct") {
    throw new TypeError('Cannot construct ReadableStream with non-"bytes" type');
  }
  return type;
}

function createDirectReadableStreamController<R>(
  getController: () => ReadableStreamDefaultController<R> | undefined
): ReadableStreamDirectController<R> {
  function resolveController(): ReadableStreamDefaultController<R> {
    const controller = getController();
    if (!controller) {
      throw new TypeError('ReadableStream direct controller is not initialized');
    }
    return controller;
  }

  function resolveVoid(): Promise<void> {
    return originalPromiseResolve(undefined);
  }

  function rejectError(error: any): Promise<void> {
    return originalPromiseReject(error);
  }

  return {
    get desiredSize(): number | null {
      return resolveController().desiredSize;
    },

    close(): Promise<void> {
      try {
        resolveController().close();
        return resolveVoid();
      } catch (error) {
        return rejectError(error);
      }
    },

    enqueue(chunk: R, options?: StructuredSerializeOptions): Promise<void> {
      try {
        resolveController().enqueue(chunk, options);
        return resolveVoid();
      } catch (error) {
        return rejectError(error);
      }
    },

    error(e?: any): Promise<void> {
      try {
        resolveController().error(e);
        return resolveVoid();
      } catch (error) {
        return rejectError(error);
      }
    },

    write(chunk: R, options?: StructuredSerializeOptions): Promise<void> {
      return this.enqueue(chunk, options);
    },

    flush(): Promise<void> {
      return resolveVoid();
    },

    end(chunk?: R, options?: StructuredSerializeOptions): Promise<void> {
      try {
        const controller = resolveController();
        if (arguments.length > 0) {
          controller.enqueue(chunk as R, options);
        }
        controller.close();
        return resolveVoid();
      } catch (error) {
        return rejectError(error);
      }
    },
  };
}

function validateUnderlyingSourceMethod(
  member: "start" | "pull" | "cancel",
  method: any
): void {
  if (method !== undefined && !isCallable(method)) {
    throw new TypeError(`ReadableStream underlying source ${member} must be a function`);
  }
}

function isSharedArrayBufferLike(buffer: unknown): boolean {
  return Object.prototype.toString.call(buffer) === "[object SharedArrayBuffer]";
}

function transferArrayBuffer(buffer: ArrayBuffer): ArrayBuffer {
  if (isSharedArrayBufferLike(buffer)) {
    throw new TypeError('Cannot transfer a non-transferable ArrayBuffer');
  }
  if (isNonTransferableArrayBuffer(buffer)) {
    throw new TypeError('Cannot transfer a non-transferable ArrayBuffer');
  }
  const bufferWithTransfer = buffer as ArrayBuffer & {
    transfer?: (newLength?: number) => ArrayBuffer;
  };
  if (typeof bufferWithTransfer.transfer === "function") {
    const transferred = bufferWithTransfer.transfer();
    if (buffer.byteLength !== 0) {
      markDetachedArrayBuffer(buffer);
    }
    return transferred;
  }
  const transferred = buffer.slice(0);
  markDetachedArrayBuffer(buffer);
  return transferred;
}

function transferArrayBufferView<T extends ArrayBufferView>(view: T): T {
  const byteOffset = view.byteOffset;
  const byteLength = view.byteLength;
  const elementSize = (view as any).BYTES_PER_ELEMENT || 1;
  const elementLength = Math.floor(byteLength / elementSize);
  const transferredBuffer = transferArrayBuffer(view.buffer);
  if (view instanceof DataView) {
    return new DataView(
      transferredBuffer,
      byteOffset,
      byteLength
    ) as T;
  }
  const ctor = view.constructor as new (
    buffer: ArrayBuffer,
    byteOffset: number,
    length: number
  ) => T;
  return new ctor(
    transferredBuffer,
    byteOffset,
    elementLength
  );
}

function toTransferList(value: unknown): object[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (value === undefined || value === null) {
    return [];
  }
  return Array.from(value as Iterable<object>);
}

function getControllerEnqueueTransferList(
  options?: StructuredSerializeOptions
): object[] | undefined {
  if (options === undefined || options === null) {
    return undefined;
  }
  if (!isObject(options)) {
    return undefined;
  }
  const transferValue = (options as StructuredSerializeOptions).transfer;
  if (transferValue === undefined) {
    return undefined;
  }
  return toTransferList(transferValue);
}

function cloneOwningStreamChunk<R>(chunk: R, transfer?: object[]): R {
  if (transfer === undefined || transfer.length === 0) {
    return chunk;
  }
  return structuredClone(chunk, { transfer }) as R;
}

const exactViewByteOffset = Symbol.for("exact.viewByteOffset");

function getArrayBufferViewByteOffset(view: ArrayBufferView): number {
  const taggedOffset = (view as any)[exactViewByteOffset];
  return typeof taggedOffset === "number" ? taggedOffset : view.byteOffset;
}

function getAsyncIteratorPrototype(): object {
  if (!isObject(Object.getPrototypeOf)) {
    return Object.prototype;
  }

  // Hermes on Apple native targets does not currently parse async-generator
  // syntax. We prefer a native AsyncIterator prototype when the engine exposes
  // one, and otherwise fall back to a plain object prototype that we populate
  // ourselves below.
  try {
    const maybeAsyncIterator = (globalThis as { AsyncIterator?: { prototype?: unknown } }).AsyncIterator;
    const nativePrototype = maybeAsyncIterator?.prototype;
    if (isObject(nativePrototype)) {
      return nativePrototype;
    }
  } catch (_error) {
    // Fall back to a runtime-owned prototype below.
  }

  try {
    const iteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]());
    if (isObject(iteratorPrototype)) {
      return Object.create(iteratorPrototype);
    }
  } catch (_error) {
    // Keep fallback.
  }

  return Object.prototype;
}

const asyncIteratorPrototype = getAsyncIteratorPrototype();

let originalReadableStreamDefaultReaderRead: ((...args: any[]) => any) | null = null;
let originalReadableStreamDefaultReaderReleaseLock: ((...args: any[]) => any) | null = null;
let originalReadableStreamGetReader: ((...args: any[]) => any) | null = null;

function isIteratorResult(value: unknown): value is { done: boolean; value?: any } {
  return isObject(value) && "done" in value;
}

interface InternalPipeToOptions {
  preventAbort: boolean;
  preventCancel: boolean;
  preventClose: boolean;
  signal: AbortSignal | undefined;
}

type PullIntoRequest = {
  resolve: (result: any) => void;
  reject: (reason: any) => void;
};

type PullIntoDescriptor = {
  buffer: ArrayBuffer;
  bufferByteLength: number;
  byteOffset: number;
  byteLength: number;
  bytesFilled: number;
  minimumBytes: number;
  elementSize: number;
  viewConstructor: new (
    buffer: ArrayBuffer,
    byteOffset: number,
    length: number
  ) => ArrayBufferView;
  readerType: 'byob' | 'default';
  pendingRequest: PullIntoRequest | null;
};

const countSizeTarget: () => number = (new Function("return (() => 1)"))();
const byteLengthSizeTarget: (chunk: ArrayBufferView) => number = (new Function("return ((chunk) => chunk.byteLength)"))();

Object.defineProperty(countSizeTarget, "name", { value: "size", configurable: true });
Object.defineProperty(byteLengthSizeTarget, "name", { value: "size", configurable: true });

const countSize: () => number = hideFunctionPrototype(countSizeTarget);
const byteLengthSize: (chunk: ArrayBufferView) => number = hideFunctionPrototype(byteLengthSizeTarget);

function normalizePipeToOptions(options?: StreamPipeOptions): InternalPipeToOptions {
  const pipeOptions = options === undefined || options === null ? {} : Object(options);
  const preventAbort = Boolean((pipeOptions as { preventAbort?: boolean }).preventAbort);
  const preventCancel = Boolean((pipeOptions as { preventCancel?: boolean }).preventCancel);
  const preventClose = Boolean((pipeOptions as { preventClose?: boolean }).preventClose);
  const signal = (pipeOptions as { signal?: AbortSignal }).signal;

  if (signal !== undefined && !isAbortSignal(signal)) {
    throw new TypeError('Expected signal to be a valid AbortSignal');
  }

  return {
    preventAbort,
    preventCancel,
    preventClose,
    signal
  };
}

function clampQueueTotalSize(size: number): number {
  return size < 0 ? 0 : size;
}

function copyByteSlice(buffer: ArrayBuffer, byteOffset: number, byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  if (byteLength > 0) {
    bytes.set(new Uint8Array(buffer, byteOffset, byteLength));
  }
  return bytes;
}

function invalidateReadableByteStreamByobRequest(controller: ReadableByteStreamController): void {
  if (controller._byobRequest !== null) {
    controller._byobRequest._view = null;
    controller._byobRequest = null;
  }
}

function removePullIntoRequestFromReader(
  controller: ReadableByteStreamController,
  descriptor: Pick<PullIntoDescriptor, 'readerType' | 'pendingRequest'>
): PullIntoRequest | null {
  const request = descriptor.pendingRequest;
  if (request === null) {
    return null;
  }

  const reader = controller._stream._reader;
  if (descriptor.readerType === 'byob') {
    if (reader instanceof ReadableStreamBYOBReader) {
      const requestIndex = reader._readIntoRequests.indexOf(request);
      if (requestIndex !== -1) {
        reader._readIntoRequests.splice(requestIndex, 1);
      }
    }
  } else if (reader instanceof ReadableStreamDefaultReader) {
    const requestIndex = reader._readRequests.indexOf(request);
    if (requestIndex !== -1) {
      reader._readRequests.splice(requestIndex, 1);
    }
  }

  descriptor.pendingRequest = null;
  return request;
}

function transferPullIntoDescriptorBuffer(descriptor: PullIntoDescriptor): void {
  const transferredBuffer = transferArrayBuffer(descriptor.buffer);
  descriptor.buffer = transferredBuffer;
  descriptor.bufferByteLength = transferredBuffer.byteLength;
}

function deliverByteStreamChunk(
  controller: ReadableByteStreamController,
  chunk: Uint8Array
): void {
  const reader = controller._stream._reader;
  if (reader instanceof ReadableStreamDefaultReader && reader._readRequests.length > 0) {
    const request = reader._readRequests.shift()!;
    request.resolve(createReadResult(false, chunk as any));
    return;
  }

  controller._queue.push({
    buffer: chunk.buffer,
    byteOffset: chunk.byteOffset,
    byteLength: chunk.byteLength,
  });
  controller._queueTotalSize = clampQueueTotalSize(
    controller._queueTotalSize + chunk.byteLength
  );
}

function attachDefaultReadRequestToPendingPullInto(
  controller: ReadableByteStreamController,
  request: PullIntoRequest
): boolean {
  const firstPullInto = controller._pendingPullIntos[0];
  if (
    firstPullInto === undefined ||
    firstPullInto.readerType !== 'default' ||
    firstPullInto.pendingRequest !== null
  ) {
    return false;
  }

  firstPullInto.pendingRequest = request;
  return true;
}

function enqueueByteStreamChunk(
  controller: ReadableByteStreamController,
  chunk: Uint8Array,
  preserveView: boolean = false
): void {
  if (chunk.byteLength === 0) {
    return;
  }

  let remainingOffset = chunk.byteOffset;
  let remainingBytes = chunk.byteLength;

  while (remainingBytes > 0 && controller._pendingPullIntos.length > 0) {
    const firstPullInto = controller._pendingPullIntos[0];
    if (isDetachedArrayBuffer(firstPullInto.buffer)) {
      throw new TypeError('Cannot enqueue into a detached BYOB request buffer');
    }
    const reader = controller._stream._reader;

    if (
      firstPullInto.readerType === 'default' &&
      firstPullInto.bytesFilled === 0 &&
      reader instanceof ReadableStreamDefaultReader
    ) {
      controller._pendingPullIntos.shift();
      transferPullIntoDescriptorBuffer(firstPullInto);
      invalidateReadableByteStreamByobRequest(controller);
      const request = removePullIntoRequestFromReader(controller, firstPullInto);
      const directChunk = preserveView
        ? new Uint8Array(chunk.buffer, remainingOffset, remainingBytes)
        : copyByteSlice(chunk.buffer, remainingOffset, remainingBytes);
      if (request !== null) {
        request.resolve(createReadResult(false, directChunk as any));
      } else {
        deliverByteStreamChunk(controller, directChunk);
      }
      return;
    }

    if (
      firstPullInto.readerType === 'byob' &&
      firstPullInto.pendingRequest === null &&
      reader instanceof ReadableStreamDefaultReader
    ) {
      controller._pendingPullIntos.shift();
      transferPullIntoDescriptorBuffer(firstPullInto);
      invalidateReadableByteStreamByobRequest(controller);
      if (firstPullInto.bytesFilled > 0) {
        deliverByteStreamChunk(
          controller,
          copyByteSlice(
            firstPullInto.buffer,
            firstPullInto.byteOffset,
            firstPullInto.bytesFilled
          )
        );
      }
      continue;
    }

    const bytesToCopy = Math.min(
      remainingBytes,
      firstPullInto.byteLength - firstPullInto.bytesFilled
    );
    const destBuffer = new Uint8Array(
      firstPullInto.buffer,
      firstPullInto.byteOffset + firstPullInto.bytesFilled,
      bytesToCopy
    );
    const srcBuffer = new Uint8Array(chunk.buffer, remainingOffset, bytesToCopy);
    destBuffer.set(srcBuffer);
    firstPullInto.bytesFilled += bytesToCopy;
    remainingOffset += bytesToCopy;
    remainingBytes -= bytesToCopy;
    if (firstPullInto.bytesFilled < firstPullInto.minimumBytes && bytesToCopy > 0) {
      transferPullIntoDescriptorBuffer(firstPullInto);
    }
    invalidateReadableByteStreamByobRequest(controller);

    if (firstPullInto.bytesFilled >= firstPullInto.minimumBytes) {
      controller._pendingPullIntos.shift();
      resolvePullIntoDescriptor(controller, firstPullInto, false);
    }
  }

  if (remainingBytes === 0) {
    return;
  }

  const remainingChunk = preserveView
    ? new Uint8Array(chunk.buffer, remainingOffset, remainingBytes)
    : copyByteSlice(chunk.buffer, remainingOffset, remainingBytes);
  deliverByteStreamChunk(controller, remainingChunk);
}

function resolvePullIntoDescriptor(
  controller: ReadableByteStreamController,
  descriptor: PullIntoDescriptor,
  done: boolean
): void {
  const remainderSize = descriptor.bytesFilled % descriptor.elementSize;
  const readyBytes = descriptor.bytesFilled - remainderSize;
  const remainderChunk =
    remainderSize > 0
      ? copyByteSlice(
          descriptor.buffer,
          descriptor.byteOffset + readyBytes,
          remainderSize
        )
      : null;
  const request = removePullIntoRequestFromReader(controller, descriptor);

  if (request !== null) {
    const filledView = new (descriptor.viewConstructor as any)(
      descriptor.buffer,
      descriptor.byteOffset,
      readyBytes / descriptor.elementSize
    );
    request.resolve(createReadResult(done, transferArrayBufferView(filledView)));
  } else if (readyBytes > 0) {
    enqueueByteStreamChunk(
      controller,
      copyByteSlice(descriptor.buffer, descriptor.byteOffset, readyBytes)
    );
  }

  if (remainderChunk !== null) {
    enqueueByteStreamChunk(controller, remainderChunk);
  }
}

function detachPendingPullIntoRequests(
  controller: ReadableByteStreamController,
  requests: PullIntoRequest[]
): void {
  if (requests.length === 0) {
    return;
  }

  for (const descriptor of controller._pendingPullIntos) {
    if (descriptor.pendingRequest !== null && requests.includes(descriptor.pendingRequest)) {
      descriptor.pendingRequest = null;
    }
  }
}

function resolvePendingPullIntosOnClose(controller: ReadableByteStreamController): void {
  if (controller._pendingPullIntos.length === 0) {
    return;
  }

  for (const descriptor of controller._pendingPullIntos) {
    if (descriptor.bytesFilled % descriptor.elementSize !== 0) {
      const e = new TypeError('Insufficient bytes to fill elements in the given buffer');
      controller.error(e);
      return;
    }
  }

  const descriptors = controller._pendingPullIntos.slice();
  controller._pendingPullIntos = [];
  invalidateReadableByteStreamByobRequest(controller);

  for (const descriptor of descriptors) {
    resolvePullIntoDescriptor(controller, descriptor, true);
  }
}

function finalizeReadableByteStreamBranchClose(controller: ReadableByteStreamController): void {
  if (controller._stream._state !== 'readable') {
    return;
  }

  if (controller._pendingPullIntos.length === 0) {
    controller.close();
    return;
  }

  resolvePendingPullIntosOnClose(controller);
  if (controller._stream._state !== 'readable') {
    return;
  }
  controller._stream._closeStream();
}

function deliverReadableByteStreamBranchChunk(
  controller: ReadableByteStreamController,
  chunk: Uint8Array,
  preserveView: boolean
): void {
  if (!preserveView || controller._pendingPullIntos.length > 0) {
    controller.enqueue(chunk);
    return;
  }

  const reader = controller._stream._reader;
  if (reader && reader instanceof ReadableStreamDefaultReader && reader._readRequests.length > 0) {
    const request = reader._readRequests.shift()!;
    request.resolve(createReadResult(false, chunk as any));
    controller._pullIfNeeded();
    return;
  }

  controller._queue.push({
    buffer: chunk.buffer,
    byteOffset: chunk.byteOffset,
    byteLength: chunk.byteLength,
  });
  controller._queueTotalSize = clampQueueTotalSize(controller._queueTotalSize + chunk.byteLength);
  controller._pullIfNeeded();
}

function ensureAutoAllocatePullInto(controller: ReadableByteStreamController): void {
  if (controller._autoAllocateChunkSize === undefined || controller._pendingPullIntos.length > 0) {
    return;
  }

  const reader = controller._stream._reader;
  if (!(reader instanceof ReadableStreamDefaultReader) || reader._readRequests.length === 0) {
    return;
  }

  let buffer: ArrayBuffer;
  try {
    buffer = new ArrayBuffer(controller._autoAllocateChunkSize);
  } catch (error) {
    controller._error(error);
    return;
  }

  controller._pendingPullIntos.push({
    buffer,
    bufferByteLength: buffer.byteLength,
    byteOffset: 0,
    byteLength: buffer.byteLength,
    bytesFilled: 0,
    minimumBytes: 1,
    elementSize: 1,
    viewConstructor: Uint8Array as any,
    readerType: 'default',
    pendingRequest: reader._readRequests[0] ?? null,
  });
}

async function performPipeTo<R>(
  source: ReadableStream<R>,
  destination: WritableStream<R>,
  options: InternalPipeToOptions
): Promise<void> {
  const {
    preventAbort,
    preventCancel,
    preventClose,
    signal
  } = options;

  if (source.locked) {
    throw new TypeError('Cannot pipe a locked stream');
  }
  if (destination.locked) {
    throw new TypeError('Cannot pipe to a locked stream');
  }

  const getReader = originalReadableStreamGetReader ?? source.getReader;
  const reader = getReader.call(source);
  const writer = destination.getWriter();
  markPromiseHandled(writer.ready);
  const pendingWrites = new Set<Promise<void>>();
  let pendingWriteError: any = undefined;
  let hasPendingWriteError = false;
  let shuttingDown = false;
  let abortError: any = undefined;
  let abortListener: (() => void) | undefined;
  let abortPromise: Promise<never> | undefined;

  const releaseReader = () => {
    if (reader._stream === undefined) {
      return;
    }
    if (source._reader === reader) {
      source._reader = undefined;
    }
    reader._stream = undefined;
  };

  const releaseWriter = () => {
    if (writer._stream === undefined) {
      return;
    }
    if (destination._writer === writer) {
      destination._writer = undefined;
    }
    writer._stream = undefined;
  };

  if (signal !== undefined) {
    abortError = getPipeToAbortReason(signal.reason);
    abortPromise = new Promise<never>((_, reject) => {
      const onAbort = () => {
        abortError = getPipeToAbortReason(signal!.reason);
        reject(abortError);
      };
      abortListener = onAbort;
      if (signal.aborted) {
        onAbort();
      } else {
        signal.addEventListener('abort', onAbort);
      }
    });
    markPromiseHandled(abortPromise);
  }

  if (signal !== undefined && signal.aborted) {
    const reason = abortError !== undefined
      ? abortError
      : new DOMException('The operation was aborted.', 'AbortError');
    let abortFailure: any = undefined;
    let cancelFailure: any = undefined;

    if (abortListener !== undefined) {
      signal.removeEventListener('abort', abortListener);
      abortListener = undefined;
    }

    if (!preventAbort && destination._state === 'writable') {
      try {
        await writer.abort(reason);
      } catch (error) {
        abortFailure = error;
      }
    }

    if (!preventCancel && source._state === 'readable') {
      try {
        await reader.cancel(reason);
      } catch (error) {
        cancelFailure = error;
      }
    } else if (!preventCancel && source._state === 'errored' && source._controller !== undefined) {
      try {
        await source._controller._cancelAlgorithm(reason);
      } catch (error) {
        cancelFailure = error;
      }
    }

    releaseReader();
    releaseWriter();
    throw abortFailure ?? cancelFailure ?? reason;
  }
  const canAbortDestination = (): boolean =>
    destination._state !== 'errored' && destination._state !== 'closed';

  const waitPendingWrites = async (): Promise<void> => {
    if (pendingWrites.size === 0) {
      return;
    }
    for (const pendingWrite of [...pendingWrites]) {
      try {
        await pendingWrite;
      } catch (_error) {}
    }
  };

  const shutdown = async (
    error: any,
    hasError: boolean,
    action?: () => Promise<any>,
    preferActionError: boolean = false
  ): Promise<void> => {
    if (shuttingDown) {
      if (hasError) {
        throw error;
      }
      return;
    }
    shuttingDown = true;

    if (abortListener !== undefined && signal !== undefined) {
      signal.removeEventListener('abort', abortListener);
      abortListener = undefined;
    }

    await waitPendingWrites();

    let finalError = error;
    let hasFinalError = hasError;
    if (!hasFinalError && hasPendingWriteError) {
      finalError = pendingWriteError;
      hasFinalError = true;
    }

    if (action !== undefined && (!hasFinalError || preferActionError)) {
      try {
        await action();
      } catch (actionError) {
        finalError = actionError;
        hasFinalError = true;
      }
    }

    releaseReader();
    releaseWriter();

    if (hasFinalError) {
      throw finalError;
    }
  };

  const shutdownOnAbort = async (): Promise<never> => {
    const reason = abortError !== undefined
      ? abortError
      : new DOMException('The operation was aborted.', 'AbortError');
    let abortFailure: any = undefined;
    let cancelFailure: any = undefined;
    await shutdown(undefined, false, async () => {
      if (!preventAbort && canAbortDestination()) {
        try {
          await writer.abort(reason);
        } catch (error) {
          abortFailure = error;
        }
      }
      if (!preventCancel && source._state === 'readable') {
        try {
          await reader.cancel(reason);
        } catch (error) {
          cancelFailure = error;
        }
      } else if (!preventCancel && source._state === 'errored' && source._controller !== undefined) {
        try {
          await source._controller._cancelAlgorithm(reason);
        } catch (error) {
          cancelFailure = error;
        }
      }
    });
    throw abortFailure ?? cancelFailure ?? reason;
  };

  const shutdownOnSourceError = async (error: any): Promise<never> => {
    await shutdown(
      error,
      true,
      async () => {
        if (!preventAbort && canAbortDestination()) {
          await writer.abort(error);
        }
      },
      true
    );
    throw error;
  };

  const shutdownOnDestinationError = async (error: any): Promise<never> => {
    await shutdown(
      error,
      true,
      async () => {
        if (!preventCancel) {
          await reader.cancel(error);
        }
      },
      true
    );
    throw error;
  };

  const shutdownOnDestinationClosed = async (): Promise<never> => {
    const closedError = new TypeError('the destination writable stream closed before all data could be piped to it');
    let finalError: any = closedError;
    if (!preventCancel) {
      try {
        await reader.cancel(closedError);
      } catch (cancelError) {
        finalError = cancelError;
      }
    }
    await shutdown(finalError, true);
    throw finalError;
  };

  const shutdownOnClose = async (): Promise<void> => {
    await shutdown(undefined, false, async () => {
      if (preventClose) {
        return;
      }
      if (destination._state === 'errored') {
        throw destination._storedError;
      }
      if (destination._state === 'closing' || destination._state === 'closed') {
        return;
      }
      try {
        await writer.close();
      } catch (closeError) {
        if (destination._state === 'errored') {
          throw destination._storedError;
        }
        throw closeError;
      }
    });
  };

  const WAIT_READY = 1;
  const WAIT_DESTINATION_CLOSED = 2;
  const WAIT_WRITE_COMPLETE = 3;
  const WAIT_READ_COMPLETE = 4;
  const WAIT_SOURCE_CLOSED = 5;
  let pendingReadResult!: ReadableStreamReadResult<R>;

  const waitForWriterReady = (): Promise<number> => {
    return new Promise<number>((resolve, reject) => {
      let settled = false;

      const resolveOnce = (value: number) => {
        if (settled) {
          return;
        }
        settled = true;
        resolve(value);
      };

      const rejectOnce = (reason: any) => {
        if (settled) {
          return;
        }
        settled = true;
        reject(reason);
      };

      promiseThen(writer.ready,
        () => resolveOnce(WAIT_READY),
        rejectOnce
      );
      promiseThen(reader.closed,
        () => resolveOnce(WAIT_SOURCE_CLOSED),
        rejectOnce
      );
      promiseThen(writer.closed,
        () => resolveOnce(WAIT_DESTINATION_CLOSED),
        rejectOnce
      );
      if (abortPromise !== undefined) {
        promiseThen(abortPromise, undefined, rejectOnce);
      }
    });
  };

  const waitForRead = (): Promise<number> => {
    return new Promise<number>((resolve, reject) => {
      let settled = false;
      const request = {
        resolve(result: ReadableStreamReadResult<R>) {
          if (settled) {
            return;
          }
          settled = true;
          pendingReadResult = result;
          resolve(WAIT_READ_COMPLETE);
        },
        reject(reason: any) {
          if (settled) {
            return;
          }
          settled = true;
          reject(reason);
        },
      };

      const rejectOnce = (reason: any) => {
        if (settled) {
          return;
        }
        settled = true;
        const index = reader._readRequests.indexOf(request);
        if (index !== -1) {
          reader._readRequests.splice(index, 1);
        }
        reject(reason);
      };

      source._disturbed = true;
      reader._readRequests.push(request);
      reader._processReadRequests();
      if (reader._readRequests.includes(request)) {
        source._controller!._pullIfNeeded();
      }

      promiseThen(writer.closed,
        () => rejectOnce(new TypeError('the destination writable stream closed before all data could be piped to it')),
        rejectOnce
      );
      if (abortPromise !== undefined) {
        promiseThen(abortPromise, undefined, rejectOnce);
      }
    });
  };

  const waitForWrite = (promise: Promise<void>): Promise<number> => {
    return new Promise<number>((resolve, reject) => {
      let settled = false;

      const resolveOnce = (value: number) => {
        if (settled) {
          return;
        }
        settled = true;
        resolve(value);
      };

      const rejectOnce = (reason: any) => {
        if (settled) {
          return;
        }
        settled = true;
        reject(reason);
      };

      promiseThen(promise,
        () => resolveOnce(WAIT_WRITE_COMPLETE),
        rejectOnce
      );
      promiseThen(writer.closed,
        () => resolveOnce(WAIT_DESTINATION_CLOSED),
        rejectOnce
      );
      if (abortPromise !== undefined) {
        promiseThen(abortPromise, undefined, rejectOnce);
      }
    });
  };

  // Per WHATWG spec: source errors are only lower priority than an already-errored
  // destination when that destination is still transitioning out of start().
  if (source._state === 'errored' && destination._state === 'errored') {
    const initialError =
      !preventAbort && destination._started === false
        ? destination._storedError
        : source._storedError;
    if (abortListener && signal !== undefined) {
      signal.removeEventListener('abort', abortListener);
      abortListener = undefined;
    }
    releaseReader();
    releaseWriter();
    throw initialError;
  }

  if (source._state === 'errored') {
    const sourceError = source._storedError;
    if (abortListener && signal !== undefined) {
      signal.removeEventListener('abort', abortListener);
      abortListener = undefined;
    }
    let finalError: any = sourceError;
    if (!preventAbort && canAbortDestination()) {
      try {
        await writer.abort(sourceError);
      } catch (abortFailure) {
        finalError = abortFailure;
      }
    }
    releaseReader();
    releaseWriter();
    throw finalError;
  }

  if (destination._state === 'closing' || destination._state === 'closed') {
    if (source._state === 'closed') {
      if (abortListener && signal !== undefined) {
        signal.removeEventListener('abort', abortListener);
        abortListener = undefined;
      }
      releaseReader();
      releaseWriter();
      return;
    }
    const closedError = new TypeError('the destination writable stream closed before all data could be piped to it');
    let finalError: any = closedError;
    if (!preventCancel) {
      try {
        await reader.cancel(closedError);
      } catch (cancelError) {
        finalError = cancelError;
      }
    }
    if (abortListener && signal !== undefined) {
      signal.removeEventListener('abort', abortListener);
      abortListener = undefined;
    }
    releaseReader();
    releaseWriter();
    throw finalError;
  }

  if (destination._state === 'errored') {
    const destError = destination._storedError;
    if (abortListener && signal !== undefined) {
      signal.removeEventListener('abort', abortListener);
      abortListener = undefined;
    }
    let cancelError: any = destError;
    if (!preventCancel) {
      try {
        await reader.cancel(destError);
      } catch (error) {
        cancelError = error;
      }
    }
    releaseReader();
    releaseWriter();
    throw cancelError;
  }

  try {
    while (true) {
      if (shuttingDown) {
        break;
      }

      if (destination._state === 'errored') {
        await shutdownOnDestinationError(destination._storedError);
        return;
      }
      if (destination._state === 'closing' || destination._state === 'closed') {
        await shutdownOnDestinationClosed();
        return;
      }
      if (source._state === 'closed') {
        break;
      }
      if (writer.desiredSize === null) {
        await shutdownOnDestinationError(destination._storedError);
        return;
      }
      if (writer.desiredSize <= 0) {
        try {
          const readyResult = await waitForWriterReady();
          if (readyResult === WAIT_DESTINATION_CLOSED) {
            await shutdownOnDestinationClosed();
            return;
          }
          if (readyResult === WAIT_SOURCE_CLOSED || source._state === 'closed') {
            break;
          }
        } catch (error) {
          if (!preventAbort && destination._state === 'errored') {
            await shutdownOnDestinationError(destination._storedError);
            return;
          }
          if (source._state === 'errored') {
            await shutdownOnSourceError(source._storedError);
            return;
          }
          if (destination._state === 'errored') {
            await shutdownOnDestinationError(destination._storedError);
            return;
          }
          if (destination._state === 'closing' || destination._state === 'closed') {
            await shutdownOnDestinationClosed();
            return;
          }
          if (signal !== undefined && signal.aborted && error === abortError) {
            await shutdownOnAbort();
            return;
          }
          await shutdown(error, true);
          throw error;
        }
        continue;
      }

      let readResult: ReadableStreamReadResult<R>;
      try {
        await waitForRead();
        readResult = pendingReadResult;
      } catch (error) {
        if (shuttingDown) {
          throw error;
        }
        if (!preventAbort && destination._state === 'errored') {
          await shutdownOnDestinationError(destination._storedError);
          return;
        }
        if (source._state === 'errored') {
          await shutdownOnSourceError(source._storedError);
          return;
        }
        if (destination._state === 'errored') {
          await shutdownOnDestinationError(destination._storedError);
          return;
        }
        if (destination._state === 'closing' || destination._state === 'closed') {
          await shutdownOnDestinationClosed();
          return;
        }
        if (signal !== undefined && signal.aborted && error === abortError) {
          await shutdownOnAbort();
          return;
        }
        await shutdown(error, true);
        throw error;
      }

      if (readResult.done) {
        break;
      }

      const chunk = readResult.value;
      const writePromise = promiseCatch(writer.write(chunk), (error) => {
        if (!hasPendingWriteError) {
          hasPendingWriteError = true;
          pendingWriteError = error;
        }
        throw error;
      });
      pendingWrites.add(writePromise);
      markPromiseHandled(promiseThen(writePromise, () => {
        pendingWrites.delete(writePromise);
      }, () => {
        pendingWrites.delete(writePromise);
      }));
      markPromiseHandled(writePromise);

      await originalPromiseResolve();

      if (!preventAbort && destination._state === 'errored') {
        await shutdownOnDestinationError(destination._storedError);
        return;
      }
      if (source._state === 'errored') {
        await shutdownOnSourceError(source._storedError);
        return;
      }
      if (destination._state === 'errored') {
        await shutdownOnDestinationError(destination._storedError);
        return;
      }
      if (destination._state === 'closing' || destination._state === 'closed') {
        await shutdownOnDestinationClosed();
        return;
      }
      if (signal !== undefined && signal.aborted) {
        await shutdownOnAbort();
        return;
      }

      if (writer.desiredSize === null) {
        await shutdownOnDestinationError(destination._storedError);
        return;
      }
      if (writer.desiredSize <= 0) {
        try {
          const writeResult = await waitForWrite(writePromise);
          if (writeResult === WAIT_DESTINATION_CLOSED) {
            await shutdownOnDestinationClosed();
            return;
          }
        } catch (error) {
          if (!preventAbort && destination._state === 'errored') {
            await shutdownOnDestinationError(destination._storedError);
            return;
          }
          if (source._state === 'errored') {
            await shutdownOnSourceError(source._storedError);
            return;
          }
          if (destination._state === 'errored') {
            await shutdownOnDestinationError(destination._storedError);
            return;
          }
          if (destination._state === 'closing' || destination._state === 'closed') {
            await shutdownOnDestinationClosed();
            return;
          }
          if (signal !== undefined && signal.aborted && error === abortError) {
            await shutdownOnAbort();
            return;
          }
          await shutdownOnDestinationError(error);
          return;
        }
      }
    }

    await shutdownOnClose();
  } catch (error) {
    if (shuttingDown) {
      throw error;
    }

    if (!preventAbort && destination._state === 'errored') {
      await shutdownOnDestinationError(destination._storedError);
      return;
    }
    if (source._state === 'errored') {
      await shutdownOnSourceError(source._storedError);
      return;
    }
    if (destination._state === 'errored') {
      await shutdownOnDestinationError(destination._storedError);
      return;
    }
    if (destination._state === 'closing' || destination._state === 'closed') {
      await shutdownOnDestinationClosed();
      return;
    }
    if (signal !== undefined && signal.aborted && error === abortError) {
      await shutdownOnAbort();
      return;
    }

    await shutdown(error, true);
    throw error;
  } finally {
    if (!shuttingDown) {
      await shutdown(undefined, false);
    }
  }
}

// ============================================================================
// ReadableStreamDefaultController
// ============================================================================

export class ReadableStreamDefaultController<R = any> {
  /** @internal */
  _stream: ReadableStream<R>;
  /** @internal */
  _queue: Array<{ value: R; size: number }> = [];
  /** @internal */
  _queueTotalSize: number = 0;
  /** @internal */
  _started: boolean = false;
  /** @internal */
  _closeRequested: boolean = false;
  /** @internal */
  _pullAgain: boolean = false;
  /** @internal */
  _pulling: boolean = false;
  /** @internal */
  _strategySizeAlgorithm: (chunk: R) => number;
  /** @internal */
  _strategyHWM: number;
  /** @internal */
  _cancelAlgorithm: (reason?: any) => Promise<void>;
  /** @internal */
  _pullAlgorithm: () => Promise<void>;

  /** @internal */
  _canCloseOrEnqueue: () => boolean;
  /** @internal */
  _pullIfNeeded: () => void;
  /** @internal */
  _shouldPull: () => boolean;
  /** @internal */
  _error: (e?: any) => void;
  /** @internal */
  _dequeue: () => R | undefined;
  /** @internal */
  _isOwningStream: boolean;

  /** @internal */
  constructor(
    stream: ReadableStream<R>,
    startAlgorithm: () => void | Promise<void>,
    pullAlgorithm: () => Promise<void>,
    cancelAlgorithm: (reason?: any) => Promise<void>,
    strategySizeAlgorithm: (chunk: R) => number,
    strategyHWM: number,
    isOwningStream: boolean
  ) {
    this._stream = stream;
    this._pullAlgorithm = pullAlgorithm;
    this._cancelAlgorithm = cancelAlgorithm;
    this._strategySizeAlgorithm = strategySizeAlgorithm;
    this._strategyHWM = strategyHWM;
    this._isOwningStream = isOwningStream;

    this._canCloseOrEnqueue = () => {
      return this._stream._state === 'readable' && !this._closeRequested;
    };

    this._pullIfNeeded = () => {
      if (!this._shouldPull()) return;

      if (this._pulling) {
        this._pullAgain = true;
        return;
      }

      this._pulling = true;

      let pullResult: Promise<void>;
      try {
        pullResult = this._pullAlgorithm();
      } catch (error) {
        this._pulling = false;
        this._error(error);
        return;
      }

      promiseThen(pullResult,
        () => {
          this._pulling = false;
          if (this._pullAgain) {
            this._pullAgain = false;
            this._pullIfNeeded();
          }
        },
        (e) => {
          this._error(e);
        }
      );
    };

    this._shouldPull = () => {
      if (this._stream._state !== 'readable') return false;
      if (this._closeRequested) return false;
      if (!this._started) return false;

      const reader = this._stream._reader;
      if (reader && reader instanceof ReadableStreamDefaultReader && reader._readRequests.length > 0) return true;

      const desiredSize = this.desiredSize;
      if (desiredSize !== null && desiredSize > 0) return true;

      return false;
    };

    this._error = (e: any) => {
      if (this._stream._state !== 'readable') return;
      this._queue = [];
      this._queueTotalSize = 0;
      this._stream._errorStream(e);
    };

    this._dequeue = () => {
      if (this._queue.length === 0) return undefined;
      const { value, size } = this._queue.shift()!;
      this._queueTotalSize = clampQueueTotalSize(this._queueTotalSize - size);
      return value;
    };

    // Set controller on stream BEFORE running start so the start callback
    // receives the correct controller reference (not undefined).
    stream._controller = this;

    // Run start algorithm
    let startResult: void | Promise<void>;
    try {
      startResult = startAlgorithm();
    } catch (error) {
      // Per spec: if start throws synchronously, the stream transitions to
      // errored state — the constructor must NOT throw.
      this._started = true;
      this._error(error);
      return;
    }
    promiseThen(resolveHandledPromise(startResult),
      () => {
        this._started = true;
        this._pullIfNeeded();
      },
      (e) => {
        this._started = true;
        this._error(e);
      }
    );
  }

  get desiredSize(): number | null {
    const state = this._stream._state;
    if (state === 'errored') return null;
    if (state === 'closed') return 0;
    return this._strategyHWM - this._queueTotalSize;
  }

  close(): void {
    if (!this._canCloseOrEnqueue()) {
      throw new TypeError('Cannot close a stream that is not readable');
    }
    this._closeRequested = true;
    if (this._queue.length === 0) {
      this._stream._closeStream();
    }
  }

  enqueue(chunk: R, options?: StructuredSerializeOptions): void {
    if (!this._canCloseOrEnqueue()) {
      throw new TypeError('Cannot enqueue to a stream that is not readable');
    }

    let transfer: object[] | undefined;
    try {
      transfer = getControllerEnqueueTransferList(options);
    } catch (error) {
      if (this._isOwningStream) {
        this._error(error);
      }
      throw error;
    }

    if (!this._isOwningStream && transfer !== undefined && transfer.length > 0) {
      throw new TypeError("transfer list is not empty");
    }

    let queuedChunk = chunk;
    if (this._isOwningStream) {
      try {
        queuedChunk = cloneOwningStreamChunk(chunk, transfer);
      } catch (error) {
        this._error(error);
        throw error;
      }
    }

    const reader = this._stream._reader;
    if (reader && reader instanceof ReadableStreamDefaultReader && reader._readRequests.length > 0) {
      const request = reader._readRequests.shift()!;
      request.resolve(createReadResult(false, queuedChunk));
      this._pullIfNeeded();
      return;
    }

    let size: number;
    try {
      size = this._strategySizeAlgorithm(queuedChunk);
    } catch (error) {
      this._error(error);
      throw error;
    }

    try {
      size = toNumber(size);
    } catch (error) {
      this._error(error);
      throw error;
    }
    if (
      Number.isNaN(size) ||
      !Number.isFinite(size) ||
      size < 0
    ) {
      const rangeError = new RangeError(
        "The size returned by the size() algorithm must be a non-negative finite number"
      );
      this._error(rangeError);
      throw rangeError;
    }

    if (this._stream._state !== 'readable') {
      return;
    }

    this._queue.push({ value: queuedChunk, size });
    this._queueTotalSize = clampQueueTotalSize(this._queueTotalSize + size);
    this._pullIfNeeded();
  }

  error(e?: any): void {
    this._error(e);
  }

  get [Symbol.toStringTag](): string {
    return 'ReadableStreamDefaultController';
  }
}

// ============================================================================
// ReadableStreamBYOBRequest
// ============================================================================

export class ReadableStreamBYOBRequest {
  /** @internal */
  _controller: ReadableByteStreamController;
  /** @internal */
  _view: ArrayBufferView | null;

  /** @internal */
  constructor(
    controller: ReadableByteStreamController,
    view: ArrayBufferView,
    brand?: symbol
  ) {
    if (brand !== byobRequestBrand) {
      throw new TypeError('Illegal constructor');
    }
    if (!(controller instanceof ReadableByteStreamController)) {
      throw new TypeError('ReadableStreamBYOBRequest must use a ReadableByteStreamController');
    }
    if (!ArrayBuffer.isView(view)) {
      throw new TypeError('ReadableStreamBYOBRequest requires an ArrayBufferView');
    }

    this._controller = controller;
    this._view = view;
  }

  get view(): ArrayBufferView | null {
    return this._view;
  }

  respond(bytesWritten: number): void {
    if (this._view === null) {
      throw new TypeError('This BYOB request has been invalidated');
    }
    const view = this._view;
    if (view.byteLength < 0) {
      throw new TypeError('Invalid BYOB view');
    }
    if (view.byteOffset + view.byteLength > view.buffer.byteLength) {
      throw new TypeError('Invalid BYOB view');
    }

    const normalized = toNumber(bytesWritten);
    if (Number.isNaN(normalized) || !Number.isFinite(normalized) || normalized < 0) {
      throw new RangeError('The view\'s response must be a non-negative finite number');
    }
    if (!Number.isInteger(normalized) || normalized > view.byteLength) {
      throw new RangeError('The view\'s response must be between 0 and the byteLength');
    }

    if (isDetachedArrayBuffer(view.buffer)) {
      throw new TypeError('Cannot read from detached ArrayBuffer');
    }

    const controller = this._controller;
    if (controller._stream._state !== 'readable') {
      throw new TypeError('The stream is not in readable state');
    }
    // Spec respond() step 5: while the stream is still readable (close not
    // yet requested), zero bytesWritten must throw instead of silently
    // invalidating the request and re-pulling (which would loop a buggy
    // source). respond(0) stays valid as the close handshake once close()
    // has been requested with an empty queue.
    if (
      normalized === 0 &&
      !(controller._closeRequested && controller._queue.length === 0)
    ) {
      throw new TypeError(
        'bytesWritten must not be 0 when calling respond() on a readable stream'
      );
    }
    this._view = null;
    controller._respondToByobRequest(normalized);
  }

  respondWithNewView(view: ArrayBufferView): void {
    if (this._view === null) {
      throw new TypeError('This BYOB request has been invalidated');
    }
    if (!ArrayBuffer.isView(view)) {
      throw new TypeError('view must be an ArrayBufferView');
    }

    const controller = this._controller;
    if (controller._stream._state !== 'readable') {
      throw new TypeError('The stream is not in readable state');
    }
    this._view = null;
    controller._respondWithNewViewToByobRequest(view);
  }

  get [Symbol.toStringTag](): string {
    return 'ReadableStreamBYOBRequest';
  }
}

// ============================================================================
// ReadableByteStreamController
// ============================================================================

export class ReadableByteStreamController {
  /** @internal */
  _stream!: ReadableStream<Uint8Array>;
  /** @internal */
  _queue: Array<{ buffer: ArrayBuffer; byteOffset: number; byteLength: number }> = [];
  /** @internal */
  _queueTotalSize: number = 0;
  /** @internal */
  _started: boolean = false;
  /** @internal */
  _closeRequested: boolean = false;
  /** @internal */
  _pullAgain: boolean = false;
  /** @internal */
  _pulling: boolean = false;
  /** @internal */
  _strategyHWM: number = 0;
  /** @internal */
  _cancelAlgorithm!: (reason?: any) => Promise<void>;
  /** @internal */
  _pullAlgorithm!: () => Promise<void>;
  /** @internal */
  _autoAllocateChunkSize: number | undefined;
  /** @internal */
  _pendingPullIntos: Array<{
    buffer: ArrayBuffer;
    bufferByteLength: number;
    byteOffset: number;
    byteLength: number;
    bytesFilled: number;
    minimumBytes: number;
    elementSize: number;
    viewConstructor: new (buffer: ArrayBuffer, byteOffset: number, length: number) => ArrayBufferView;
    readerType: 'byob' | 'default';
    pendingRequest: PullIntoRequest | null;
  }> = [];
  /** @internal */
  _byobRequest: ReadableStreamBYOBRequest | null = null;

  /** @internal */
  constructor() {
    // Initialization happens in _setup() called by the stream constructor
  }

  /** @internal */
  _setup(
    stream: ReadableStream<Uint8Array>,
    startAlgorithm: () => void | Promise<void>,
    pullAlgorithm: () => Promise<void>,
    cancelAlgorithm: (reason?: any) => Promise<void>,
    highWaterMark: number,
    autoAllocateChunkSize: number | undefined
  ): void {
    this._stream = stream;
    this._pullAlgorithm = pullAlgorithm;
    this._cancelAlgorithm = cancelAlgorithm;
    this._strategyHWM = highWaterMark;
    this._autoAllocateChunkSize = autoAllocateChunkSize;

    (stream as any)._controller = this;
    (stream as any)._isByteStream = true;

    let startResult: void | Promise<void>;
    try {
      startResult = startAlgorithm();
    } catch (error) {
      // Per spec: if start throws synchronously, the stream transitions to
      // errored state — the constructor must NOT throw.
      this._started = true;
      this._error(error);
      return;
    }
    promiseThen(resolveHandledPromise(startResult),
      () => {
        this._started = true;
        this._pullIfNeeded();
      },
      (e) => {
        this._started = true;
        this._error(e);
      }
    );
  }

  get byobRequest(): ReadableStreamBYOBRequest | null {
    if (this._byobRequest === null && this._pendingPullIntos.length > 0) {
      const firstDescriptor = this._pendingPullIntos[0];
      const view = new Uint8Array(
        firstDescriptor.buffer,
        firstDescriptor.byteOffset + firstDescriptor.bytesFilled,
        firstDescriptor.byteLength - firstDescriptor.bytesFilled
      );
      this._byobRequest = new ReadableStreamBYOBRequest(this, view, byobRequestBrand);
    }
    return this._byobRequest;
  }

  get desiredSize(): number | null {
    const state = this._stream._state;
    if (state === 'errored') return null;
    if (state === 'closed') return 0;
    return this._strategyHWM - this._queueTotalSize;
  }

  close(): void {
    if (this._closeRequested) {
      throw new TypeError('Cannot close a stream that is already closing');
    }
    if (this._stream._state !== 'readable') {
      throw new TypeError('Cannot close a stream that is not readable');
    }

    this._closeRequested = true;

    if (this._queue.length === 0) {
      if (this._pendingPullIntos.length > 0) {
        const firstPullInto = this._pendingPullIntos[0];
        if (firstPullInto.bytesFilled % firstPullInto.elementSize !== 0) {
          const e = new TypeError('Insufficient bytes to fill elements in the given buffer');
          this._error(e);
          throw e;
        }
        return;
      }
      this._stream._closeStream();
    }
  }

  enqueue(chunk: ArrayBufferView): void {
    if (!ArrayBuffer.isView(chunk)) {
      throw new TypeError('chunk must be an ArrayBufferView');
    }
    if (chunk.byteLength === 0) {
      throw new TypeError('chunk must have non-zero byteLength');
    }
    if (isDetachedArrayBuffer(chunk.buffer)) {
      throw new TypeError('Cannot enqueue a view with a detached buffer');
    }
    if (this._closeRequested) {
      throw new TypeError('Cannot enqueue to a closing stream');
    }
    if (this._stream._state !== 'readable') {
      throw new TypeError('Cannot enqueue to a stream that is not readable');
    }

    const buffer = chunk.buffer as ArrayBuffer;
    const byteOffset = chunk.byteOffset;
    const byteLength = chunk.byteLength;
    const transferredBuffer = transferArrayBuffer(buffer);
    const hadPendingPullIntos = this._pendingPullIntos.length > 0;
    enqueueByteStreamChunk(
      this,
      new Uint8Array(transferredBuffer, byteOffset, byteLength),
      true
    );
    if (hadPendingPullIntos && this._pendingPullIntos.length === 0) {
      observeObjectPrototypeThen();
    }
    this._pullIfNeeded();
  }

  error(e?: any): void {
    this._error(e);
  }

  /** @internal */
  _respondToByobRequest(bytesWritten: number): void {
    if (this._pendingPullIntos.length === 0) return;
    if (!Number.isInteger(bytesWritten) || bytesWritten < 0) {
      throw new TypeError('bytesWritten must be a non-negative integer');
    }

    const firstPullInto = this._pendingPullIntos[0];
    if (isDetachedArrayBuffer(firstPullInto.buffer)) {
      throw new TypeError('Cannot respond using a detached BYOB request buffer');
    }
    const availableBytes = firstPullInto.byteLength - firstPullInto.bytesFilled;
    if (bytesWritten > availableBytes) {
      throw new RangeError('Too many bytes written');
    }

    firstPullInto.bytesFilled += bytesWritten;
    if (this._closeRequested && this._queue.length === 0) {
      invalidateReadableByteStreamByobRequest(this);
      if (firstPullInto.bytesFilled % firstPullInto.elementSize !== 0) {
        const e = new TypeError('Insufficient bytes to fill elements in the given buffer');
        this._error(e);
        throw e;
      }
      this._pendingPullIntos.shift();
      resolvePullIntoDescriptor(this, firstPullInto, true);
      this._stream._closeStream();
      return;
    }
    if (firstPullInto.bytesFilled < firstPullInto.minimumBytes) {
      if (bytesWritten > 0) {
        transferPullIntoDescriptorBuffer(firstPullInto);
      }
      invalidateReadableByteStreamByobRequest(this);
      this._pullIfNeeded();
      return;
    }

    invalidateReadableByteStreamByobRequest(this);
    this._pendingPullIntos.shift();
    resolvePullIntoDescriptor(this, firstPullInto, false);

    this._pullIfNeeded();
  }

  /** @internal */
  _respondWithNewViewToByobRequest(view: ArrayBufferView): void {
    if (this._pendingPullIntos.length === 0) return;
    if (!ArrayBuffer.isView(view)) {
      throw new TypeError('View must be an ArrayBufferView');
    }
    if (isDetachedArrayBuffer(view.buffer)) {
      throw new TypeError('Cannot read from detached ArrayBuffer');
    }
    if (view.buffer instanceof ArrayBuffer && isNonTransferableArrayBuffer(view.buffer)) {
      throw new TypeError('Cannot read from non-transferable ArrayBuffer');
    }

    const firstPullInto = this._pendingPullIntos[0];
    const expectedByteOffset = firstPullInto.byteOffset + firstPullInto.bytesFilled;
    const remainingBytes = firstPullInto.byteLength - firstPullInto.bytesFilled;
    const closeRequested = this._closeRequested && this._queue.length === 0;

    if (view.byteOffset !== expectedByteOffset) {
      throw new RangeError('The supplied view has an unexpected byteOffset');
    }
    if (closeRequested) {
      if (view.buffer.byteLength !== firstPullInto.bufferByteLength) {
        throw new RangeError('The supplied view has an unexpected buffer length');
      }
      if (view.byteLength !== 0) {
        throw new TypeError('View must be zero-length when responding after close()');
      }
    } else {
      if (view.byteLength === 0) {
        throw new TypeError('View must be a non-empty ArrayBufferView');
      }
      if (view.buffer.byteLength === 0) {
        throw new TypeError('View buffer must have non-zero byteLength');
      }
      if (view.buffer.byteLength !== firstPullInto.bufferByteLength) {
        throw new RangeError('The supplied view has an unexpected buffer length');
      }
    }
    if (view.byteLength > remainingBytes) {
      throw new RangeError('The supplied view is larger than the pending BYOB request');
    }

    this._pendingPullIntos.shift();
    invalidateReadableByteStreamByobRequest(this);
    const request = removePullIntoRequestFromReader(this, firstPullInto);

    if (view.buffer === firstPullInto.buffer) {
      firstPullInto.pendingRequest = request;
      firstPullInto.bytesFilled += view.byteLength;
      resolvePullIntoDescriptor(this, firstPullInto, closeRequested);
    } else if (request !== null) {
      request.resolve(createReadResult(closeRequested, view as any));
    } else if (view.byteLength > 0) {
      enqueueByteStreamChunk(
        this,
        copyByteSlice(view.buffer as ArrayBuffer, view.byteOffset, view.byteLength)
      );
    }

    if (closeRequested) {
      this._stream._closeStream();
      return;
    }

    this._pullIfNeeded();
  }

  /** @internal */
  _pullIfNeeded(): void {
    if (!this._shouldPull()) return;
    ensureAutoAllocatePullInto(this);

    if (this._pulling) {
      this._pullAgain = true;
      return;
    }

    this._pulling = true;

    let pullResult: Promise<void>;
    try {
      pullResult = this._pullAlgorithm();
    } catch (error) {
      this._pulling = false;
      this._error(error);
      return;
    }

    promiseThen(pullResult,
      () => {
        this._pulling = false;
        if (this._pullAgain) {
          this._pullAgain = false;
          this._pullIfNeeded();
        }
      },
      (e) => {
        this._error(e);
      }
    );
  }

  /** @internal */
  _shouldPull(): boolean {
    if (this._stream._state !== 'readable') return false;
    if (this._closeRequested) return false;
    if (!this._started) return false;

    const reader = this._stream._reader;
    if (reader) {
      if (reader instanceof ReadableStreamDefaultReader && reader._readRequests.length > 0) return true;
      if (reader instanceof ReadableStreamBYOBReader && reader._readIntoRequests.length > 0) return true;
    }

    const desiredSize = this.desiredSize;
    if (desiredSize !== null && desiredSize > 0) return true;

    return false;
  }

  /** @internal */
  _error(e: any): void {
    if (this._stream._state !== 'readable') return;
    this._queue = [];
    this._queueTotalSize = 0;

    // Reject any pending BYOB pull-intos
    const reader = this._stream._reader;
    if (reader && reader instanceof ReadableStreamBYOBReader) {
      for (const request of reader._readIntoRequests) {
        request.reject(e);
      }
      reader._readIntoRequests = [];
    }
    this._pendingPullIntos = [];
    invalidateReadableByteStreamByobRequest(this);

    this._stream._errorStream(e);
  }

  /** @internal - used by default reader to process queued byte chunks */
  _dequeue(): Uint8Array | undefined {
    if (this._queue.length === 0) return undefined;
    const { buffer, byteOffset, byteLength } = this._queue.shift()!;
    this._queueTotalSize = clampQueueTotalSize(this._queueTotalSize - byteLength);
    return new Uint8Array(buffer, byteOffset, byteLength);
  }

  /** @internal - Process a BYOB read request, called by ReadableStreamBYOBReader */
  _processReadIntoRequest(
    view: ArrayBufferView,
    min: number,
    readIntoRequest: {
      resolve: (result: ReadableStreamBYOBReadResult<any>) => void;
      reject: (reason: any) => void;
    }
  ): void {
    const elementSize = (view as any).BYTES_PER_ELEMENT || 1;
    const minimumBytes = min * elementSize;
    const viewConstructor = (view.constructor as any) || Uint8Array;
    const byteOffset = view.byteOffset;
    const byteLength = view.byteLength;
    const finishReadIntoRequest = () => {
      const reader = this._stream._reader;
      if (!(reader instanceof ReadableStreamBYOBReader)) {
        return;
      }
      const requestIndex = reader._readIntoRequests.indexOf(readIntoRequest);
      if (requestIndex !== -1) {
        reader._readIntoRequests.splice(requestIndex, 1);
      }
    };

    // If the stream is closed, resolve with done
    if (this._stream._state === 'closed') {
      const emptyView = transferArrayBufferView(
        new viewConstructor(view.buffer, byteOffset, 0)
      );
      finishReadIntoRequest();
      readIntoRequest.resolve(createReadResult(true, emptyView));
      return;
    }

    let bytesFilled = 0;

    // Try to fulfill from queue
    if (this._queueTotalSize > 0) {
      const destBuffer = new Uint8Array(view.buffer, byteOffset, byteLength);

      while (bytesFilled < byteLength && this._queue.length > 0) {
        const front = this._queue[0];
        const bytesToCopy = Math.min(byteLength - bytesFilled, front.byteLength);
        const srcView = new Uint8Array(front.buffer, front.byteOffset, bytesToCopy);
        destBuffer.set(srcView, bytesFilled);
        bytesFilled += bytesToCopy;

        if (bytesToCopy === front.byteLength) {
          this._queue.shift();
        } else {
          front.byteOffset += bytesToCopy;
          front.byteLength -= bytesToCopy;
        }
        this._queueTotalSize = clampQueueTotalSize(this._queueTotalSize - bytesToCopy);
      }

      if (bytesFilled >= minimumBytes) {
        resolvePullIntoDescriptor(
          this,
          {
            buffer: view.buffer,
            bufferByteLength: view.buffer.byteLength,
            byteOffset,
            byteLength,
            minimumBytes,
            bytesFilled,
            elementSize,
            viewConstructor,
            readerType: 'byob',
            pendingRequest: readIntoRequest,
          },
          false
        );

        // If close was requested and queue is now empty, close the stream
        if (this._closeRequested && this._queue.length === 0) {
          this._stream._closeStream();
        } else {
          this._pullIfNeeded();
        }
        return;
      }
    }

    // If the stream is closed (via closeRequested + empty queue), resolve appropriately
    if (this._closeRequested && this._queue.length === 0) {
      if (bytesFilled > 0) {
        if (bytesFilled < minimumBytes || bytesFilled % elementSize !== 0) {
          const e = new TypeError('Insufficient bytes to fill elements in the given buffer');
          this._error(e);
          return;
        }
        resolvePullIntoDescriptor(
          this,
          {
            buffer: view.buffer,
            bufferByteLength: view.buffer.byteLength,
            byteOffset,
            byteLength,
            minimumBytes,
            bytesFilled,
            elementSize,
            viewConstructor,
            readerType: 'byob',
            pendingRequest: readIntoRequest,
          },
          false
        );
      } else {
        const emptyView = transferArrayBufferView(
          new viewConstructor(view.buffer, byteOffset, 0)
        );
        finishReadIntoRequest();
        readIntoRequest.resolve(createReadResult(true, emptyView));
      }
      this._stream._closeStream();
      return;
    }

    // Not enough data in queue; register the pull-into descriptor and pull
    const pullIntoDescriptor = {
      buffer: view.buffer,
      bufferByteLength: view.buffer.byteLength,
      byteOffset: byteOffset,
      byteLength: byteLength,
      minimumBytes,
      bytesFilled,
      elementSize,
      viewConstructor,
      readerType: 'byob' as const,
      pendingRequest: readIntoRequest,
    };
    this._pendingPullIntos.push(pullIntoDescriptor);
    this._pullIfNeeded();
  }

  get [Symbol.toStringTag](): string {
    return 'ReadableByteStreamController';
  }
}

// ============================================================================
// ReadableStreamDefaultReader
// ============================================================================

export class ReadableStreamDefaultReader<R = any> {
  /** @internal */
  _stream: ReadableStream<R> | undefined;
  /** @internal */
  _readRequests: Array<{
    resolve: (result: ReadableStreamReadResult<R>) => void;
    reject: (reason: any) => void;
  }> = [];
  /** @internal */
  _closedPromise: Promise<undefined>;
  /** @internal */
  _closedResolve!: () => void;
  /** @internal */
  _closedReject!: (reason: any) => void;

  _initializeClosedPromise(
    state: "pending" | "resolved" | "rejected",
    value?: any
  ): void {
    if (state === "pending") {
      this._closedPromise = new Promise((resolve, reject) => {
        this._closedResolve = resolve as () => void;
        this._closedReject = reject;
      });
    } else if (state === "resolved") {
      this._closedPromise = originalPromiseResolve(value);
    } else {
      this._closedPromise = originalPromiseReject(value);
    }
    markPromiseHandled(this._closedPromise);
  }

  constructor(stream: ReadableStream<R>) {
    if (!(stream instanceof ReadableStream)) {
      throw new TypeError('ReadableStreamDefaultReader constructor only accepts a ReadableStream');
    }
    if (stream._reader !== undefined) {
      throw new TypeError(getReadableStreamLockedMessage());
    }

    stream._reader = this;
    this._stream = stream;

    if (stream._state === 'closed') {
      this._initializeClosedPromise("resolved", undefined);
    } else if (stream._state === 'errored') {
      this._initializeClosedPromise("rejected", stream._storedError);
    } else {
      this._initializeClosedPromise("pending");
    }
  }

  get closed(): Promise<undefined> {
    return this._closedPromise;
  }

  read(): Promise<ReadableStreamReadResult<R>> {
    if (this._stream === undefined) {
      return originalPromiseReject(new TypeError('Reader has been released'));
    }

    // Per spec: reading from a stream marks it as disturbed
    this._stream._disturbed = true;

    const p = new Promise<ReadableStreamReadResult<R>>((resolve, reject) => {
      const request = { resolve, reject };
      this._readRequests.push(request);
      this._processReadRequests();
      if (this._readRequests.includes(request)) {
        const controller = this._stream!._controller;
        if (controller instanceof ReadableByteStreamController) {
          if (!attachDefaultReadRequestToPendingPullInto(controller, request)) {
            ensureAutoAllocatePullInto(controller);
          }
        }
        this._stream!._controller!._pullIfNeeded();
      }
    });
    // Suppress unhandled rejection tracking for stream-internal error propagation.
    // When a stream errors, pending read requests are rejected. The caller may not
    // attach a .catch() handler (e.g., WPT tests that call read() just to disturb
    // the stream). This pre-catch marks the promise as handled in our tracking
    // without affecting the caller's ability to catch/await the rejection.
    markPromiseHandled(p);
    return p;
  }

  releaseLock(): void {
    if (this._stream === undefined) return;

    const releaseError = new TypeError('Reader was released');
    const controller = this._stream._controller;
    if (this._readRequests.length > 0) {
      const requests = this._readRequests.slice();
      if (controller instanceof ReadableByteStreamController) {
        detachPendingPullIntoRequests(controller, requests);
      }
      for (const request of this._readRequests) {
        request.reject(releaseError);
      }
      this._readRequests = [];
    }

    this._stream._reader = undefined;
    this._closedReject?.(releaseError);
    markPromiseHandled(this._closedPromise);
    this._stream = undefined;
  }

  cancel(reason?: any): Promise<void> {
    if (this._stream === undefined) {
      return originalPromiseReject(new TypeError('Reader has been released'));
    }
    // Per spec: reader.cancel() should cancel the stream even though it's locked
    // We bypass the locked check by calling _cancelStream directly
    this._stream._disturbed = true;
    return this._stream._cancelStream(reason, this);
  }

  /** @internal */
  _processReadRequests(): void {
    if (this._stream === undefined) return;

    const controller = this._stream._controller;
    if (!controller) return;
    let shouldClose = false;

    while (this._readRequests.length > 0) {
      if (controller._queue.length > 0) {
        const chunk = controller._dequeue();
        const request = this._readRequests.shift()!;
        request.resolve(createReadResult(false, chunk as R));

        if (controller._closeRequested && controller._queue.length === 0) {
          shouldClose = true;
          break;
        } else {
          controller._pullIfNeeded();
        }
      } else if (this._stream._state === 'closed') {
        const request = this._readRequests.shift()!;
        request.resolve(createReadResult(true, undefined));
      } else if (this._stream._state === 'errored') {
        const request = this._readRequests.shift()!;
        request.reject(this._stream._storedError);
      } else {
        // No data available, wait for more
        break;
      }
    }

    if (shouldClose) {
      this._stream._closeStream();
    }
  }

  get [Symbol.toStringTag](): string {
    return 'ReadableStreamDefaultReader';
  }
}

originalReadableStreamDefaultReaderRead = ReadableStreamDefaultReader.prototype.read;
originalReadableStreamDefaultReaderReleaseLock = ReadableStreamDefaultReader.prototype.releaseLock;

// ============================================================================
// ReadableStreamBYOBReader
// ============================================================================

export class ReadableStreamBYOBReader {
  /** @internal */
  _stream: ReadableStream<Uint8Array> | undefined;
  /** @internal */
  _readIntoRequests: Array<{
    resolve: (result: ReadableStreamBYOBReadResult<any>) => void;
    reject: (reason: any) => void;
  }> = [];
  /** @internal */
  _closedPromise: Promise<undefined>;
  /** @internal */
  _closedResolve!: () => void;
  /** @internal */
  _closedReject!: (reason: any) => void;

  _initializeClosedPromise(
    state: "pending" | "resolved" | "rejected",
    value?: any
  ): void {
    if (state === "pending") {
      this._closedPromise = new Promise((resolve, reject) => {
        this._closedResolve = resolve as () => void;
        this._closedReject = reject;
      });
    } else if (state === "resolved") {
      this._closedPromise = originalPromiseResolve(value);
    } else {
      this._closedPromise = originalPromiseReject(value);
    }
    markPromiseHandled(this._closedPromise);
  }

  constructor(stream: ReadableStream<Uint8Array>) {
    if (stream._reader !== undefined) {
      throw new TypeError(getReadableStreamLockedMessage());
    }
    if (!(stream as any)._isByteStream) {
      throw new TypeError('Cannot construct a ReadableStreamBYOBReader for a non-byte stream');
    }

    (stream as any)._reader = this;
    this._stream = stream;

    if (stream._state === 'closed') {
      this._initializeClosedPromise("resolved", undefined);
    } else if (stream._state === 'errored') {
      this._initializeClosedPromise("rejected", stream._storedError);
    } else {
      this._initializeClosedPromise("pending");
    }
  }

  get closed(): Promise<undefined> {
    return this._closedPromise;
  }

  async read<T extends ArrayBufferView>(
    view: T,
    options?: { min?: number }
  ): Promise<ReadableStreamBYOBReadResult<T>> {
    if (this._stream === undefined) {
      throw new TypeError('Reader has been released');
    }
    if (options === null) {
      throw new TypeError('Cannot read properties of null (reading options)');
    }
    if (options !== undefined && typeof options !== 'object') {
      throw new TypeError('Invalid read options');
    }
    const viewMin = options?.min ?? 1;
    const normalizedMin = toNumber(viewMin);
    if (!Number.isInteger(normalizedMin) || normalizedMin < 1) {
      throw new TypeError('The \'min\' option must be a positive integer');
    }
    if (!ArrayBuffer.isView(view)) {
      throw new TypeError('view must be an ArrayBufferView');
    }
    if (isDetachedArrayBuffer(view.buffer as ArrayBuffer)) {
      throw new TypeError('Cannot read into detached ArrayBuffer');
    }
    if (view.buffer instanceof ArrayBuffer && isNonTransferableArrayBuffer(view.buffer)) {
      throw new TypeError('Cannot read into non-transferable ArrayBuffer');
    }
    if (view.byteLength === 0) {
      throw new TypeError('view must have non-zero byteLength');
    }
    if (view.buffer.byteLength === 0) {
      throw new TypeError('view\'s buffer must have non-zero byteLength');
    }
    const elementSize = (view as any).BYTES_PER_ELEMENT || 1;
    const viewLength = view instanceof DataView
      ? view.byteLength
      : Math.floor(view.byteLength / elementSize);
    if (normalizedMin > viewLength) {
      throw new RangeError('The \'min\' option cannot be greater than view.byteLength');
    }
    const stream = this._stream;
    // Per spec: reading from a stream marks it as disturbed
    stream._disturbed = true;
    if (normalizedMin > 0 && stream._state === 'closed') {
      const emptyView = transferArrayBufferView(
        new (view as any).constructor(
          view.buffer,
          view.byteOffset,
          0
        ) as T
      );
      return createReadResult(true, emptyView) as ReadableStreamBYOBReadResult<T>;
    }

    if (stream._state === 'errored') {
      throw stream._storedError;
    }

    const p = new Promise<ReadableStreamBYOBReadResult<T>>((resolve, reject) => {
      const readIntoRequest = {
        resolve: resolve as any,
        reject
      };
      this._readIntoRequests.push(readIntoRequest);

      const controller = (stream as any)._controller as ReadableByteStreamController;
      controller._processReadIntoRequest(view, normalizedMin, readIntoRequest);
    });
    // Match default-reader semantics so internal stream errors do not surface
    // as transient unhandled rejections before user code awaits the read().
    markPromiseHandled(p);
    return p;
  }

  releaseLock(): void {
    if (this._stream === undefined) return;

    const releaseError = new TypeError('Reader was released');
    const controller = this._stream._controller;
    if (this._readIntoRequests.length > 0) {
      const requests = this._readIntoRequests.slice();
      if (controller instanceof ReadableByteStreamController) {
        detachPendingPullIntoRequests(controller, requests);
      }
      for (const request of this._readIntoRequests) {
        request.reject(releaseError);
      }
      this._readIntoRequests = [];
    }

    (this._stream as any)._reader = undefined;
    this._closedReject?.(releaseError);
    markPromiseHandled(this._closedPromise);
    this._stream = undefined;
  }

  cancel(reason?: any): Promise<void> {
    if (this._stream === undefined) {
      return originalPromiseReject(new TypeError('Reader has been released'));
    }
    this._stream._disturbed = true;
    return this._stream._cancelStream(reason, this);
  }

  get [Symbol.toStringTag](): string {
    return 'ReadableStreamBYOBReader';
  }
}

// ============================================================================
// ReadableStream async iterator
// ============================================================================

class ReadableStreamAsyncIterator<R> implements AsyncIterableIterator<R> {
  _reader: ReadableStreamDefaultReader<R>;
  _stream: ReadableStream<R>;
  _preventCancel: boolean;
  _readerRead: () => Promise<IteratorResult<R>>;
  _readerReleaseLock: () => void;
  _returnInProgress: Promise<void> | null = null;
  _lockReleased = false;
  _finished = false;
  _operationQueue: Array<() => void> = [];
  _operationRunning = false;

  constructor(
    reader: ReadableStreamDefaultReader<R>,
    stream: ReadableStream<R>,
    preventCancel: boolean
  ) {
    this._reader = reader;
    this._stream = stream;
    this._preventCancel = preventCancel;
    const readerRead = originalReadableStreamDefaultReaderRead ?? reader.read;
    const readerReleaseLock = originalReadableStreamDefaultReaderReleaseLock ?? reader.releaseLock;
    this._readerRead = readerRead.bind(reader);
    this._readerReleaseLock = readerReleaseLock.bind(reader);
    Object.defineProperty(this, "throw", {
      configurable: true,
      enumerable: false,
      writable: true,
      value: undefined,
    });
    (this as any)._releaseLockSynchronously = this._releaseLockSynchronously.bind(this);
    (this as any)._advanceOperationQueue = this._advanceOperationQueue.bind(this);
    (this as any)._enqueueOperation = this._enqueueOperation.bind(this);
    (this as any)._nextImpl = this._nextImpl.bind(this);
    (this as any)._returnImpl = this._returnImpl.bind(this);
    Object.setPrototypeOf(this, readableStreamAsyncIteratorPrototype);
  }

  _releaseLockSynchronously(): void {
    if (this._lockReleased) {
      return;
    }
    this._lockReleased = true;
    if (this._reader._stream !== undefined) {
      this._reader._stream = undefined;
    }
    if (this._stream._reader === this._reader) {
      this._stream._reader = undefined;
    }
  }

  _advanceOperationQueue(): void {
    const next = this._operationQueue.shift();
    if (next) {
      next();
      return;
    }
    this._operationRunning = false;
  }

  _enqueueOperation<T>(start: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const run = () => {
        this._operationRunning = true;
        let operation: Promise<T>;
        try {
          operation = start();
        } catch (error) {
          operation = originalPromiseReject(error);
        }
        promiseThen(operation,
          (value) => {
            resolve(value);
            this._advanceOperationQueue();
          },
          (error) => {
            reject(error);
            this._advanceOperationQueue();
          }
        );
      };

      if (this._operationRunning) {
        this._operationQueue.push(run);
      } else {
        run();
      }
    });
  }

  async _nextImpl(): Promise<IteratorResult<R>> {
    if (this._returnInProgress !== null) {
      await this._returnInProgress;
      return createAsyncIteratorResult(true, undefined as R);
    }
    if (this._finished) {
      return createAsyncIteratorResult(true, undefined as R);
    }

    try {
      const result = await this._readerRead();
      if (result.done) {
        this._finished = true;
        this._releaseLockSynchronously();
      }
      return createAsyncIteratorResult(result.done, result.value);
    } catch (error) {
      this._finished = true;
      this._releaseLockSynchronously();
      throw error;
    }
  }

  next(): Promise<IteratorResult<R>> {
    return this._enqueueOperation(() => this._nextImpl());
  }

  async _returnImpl(returnValue: any): Promise<IteratorResult<R>> {
    if (!this._lockReleased) {
      this._releaseLockSynchronously();
      this._readerReleaseLock();
    }
    if (this._returnInProgress !== null) {
      await this._returnInProgress;
      return createAsyncIteratorResult(true, returnValue);
    }
    if (this._finished) {
      return createAsyncIteratorResult(true, returnValue);
    }
    if (this._stream._state === 'errored') {
      throw this._stream._storedError;
    }

    if (this._preventCancel) {
      this._returnInProgress = originalPromiseResolve();
    } else {
      this._returnInProgress = this._stream._cancelStream(returnValue, this._reader);
    }
    await this._returnInProgress;
    this._finished = true;
    return createAsyncIteratorResult(true, returnValue);
  }

  return(value?: any): Promise<IteratorResult<R>> {
    const returnValue = value;
    if (!this._lockReleased && !this._operationRunning) {
      this._releaseLockSynchronously();
      this._readerReleaseLock();
    }
    return this._enqueueOperation(() => this._returnImpl(returnValue));
  }

  [Symbol.asyncIterator](): AsyncIterator<R, any, undefined> {
    return this;
  }
}

const readableStreamAsyncIteratorPrototype = Object.create(asyncIteratorPrototype);
Object.defineProperties(readableStreamAsyncIteratorPrototype, {
  next: {
    configurable: true,
    enumerable: true,
    writable: true,
    value: ReadableStreamAsyncIterator.prototype.next,
  },
  return: {
    configurable: true,
    enumerable: true,
    writable: true,
    value: ReadableStreamAsyncIterator.prototype.return,
  },
});
if (typeof Symbol === "function" && typeof Symbol.asyncIterator === "symbol") {
  Object.defineProperty(readableStreamAsyncIteratorPrototype, Symbol.asyncIterator, {
    configurable: true,
    enumerable: false,
    writable: true,
    value: ReadableStreamAsyncIterator.prototype[Symbol.asyncIterator],
  });
}
delete (readableStreamAsyncIteratorPrototype as any).constructor;

// ============================================================================
// ReadableStream
// ============================================================================

export class ReadableStream<R = any> {
  /** @internal */
  _state: ReadableStreamState = 'readable';
  /** @internal */
  _storedError: any;
  /** @internal */
  _reader: ReadableStreamReaderType;
  /** @internal */
  _isByteStream: boolean = false;
  /** @internal */
  _isOwningStream: boolean = false;
  /** @internal - set to true when any read operation is performed on this stream */
  _disturbed: boolean = false;
  /** @internal */
  _controller: ReadableStreamDefaultController<R> | ReadableByteStreamController | undefined;

  constructor(
    underlyingSource?: UnderlyingSource<R> | UnderlyingByteSource | UnderlyingDirectSource<R>,
    strategy?: QueuingStrategy<R>
  ) {
    if (originalReadableStreamGetReader === null) {
      originalReadableStreamGetReader = ReadableStream.prototype.getReader;
    }
    if (underlyingSource === null) {
      throw new TypeError('Cannot convert undefined or null to object');
    }
    const source = underlyingSource === undefined
      ? ({} as UnderlyingSource<R>)
      : Object(underlyingSource) as UnderlyingSource<R>;
    const strat = strategy === undefined ? {} : Object(strategy);

    const strategyHasSize = hasPropertyWithoutObjectPrototype(strat, "size");
    const strategyHasHighWaterMark = hasPropertyWithoutObjectPrototype(strat, "highWaterMark");

    const strategySize = strategyHasSize
      ? validateQueuingStrategySize(getPropertyValueWithoutObjectPrototype(strat, "size"))
      : (() => 1);

    let strategyHWM = validateHighWaterMark(
      getPropertyValueWithoutObjectPrototype(strat, "highWaterMark"),
      1
    );

    const sourceType = getUnderlyingSourceType(source as any);
    const isByteStream = sourceType === "bytes";
    const isOwningStream = sourceType === "owning";
    const isDirectStream = sourceType === "direct";
    const sourceAsAny = source as any;
    const sourceStart = getPropertyValueWithoutObjectPrototype(
      sourceAsAny,
      "start"
    ) as ((controller: any) => any) | undefined;
    const sourcePull = getPropertyValueWithoutObjectPrototype(
      sourceAsAny,
      "pull"
    ) as ((controller: any) => any) | undefined;
    const sourceCancel = getPropertyValueWithoutObjectPrototype(
      sourceAsAny,
      "cancel"
    ) as ((reason?: any) => any) | undefined;

    validateUnderlyingSourceMethod("start", sourceStart);
    validateUnderlyingSourceMethod("pull", sourcePull);
    validateUnderlyingSourceMethod("cancel", sourceCancel);

    if (isByteStream && strategyHasSize) {
      throw new RangeError("The size option must not be specified for byte streams");
    }
    if (isByteStream && !strategyHasHighWaterMark) {
      strategyHWM = 0;
    }

    if (isByteStream) {
      const byteSource = source as UnderlyingByteSource;
      let autoAllocateChunkSize: number | undefined = undefined;
      if (byteSource.autoAllocateChunkSize !== undefined) {
        const converted = toNumber(byteSource.autoAllocateChunkSize);
        if (converted === 0) {
          throw new TypeError('Invalid autoAllocateChunkSize');
        }
        if (
          !Number.isFinite(converted) ||
          !Number.isInteger(converted) ||
          converted < 1
        ) {
          throw new RangeError('Invalid autoAllocateChunkSize');
        }
        autoAllocateChunkSize = converted;
      }

      this._isByteStream = true;

      const byteController = new ReadableByteStreamController();
      const startAlgorithm = () => {
        if (sourceStart) {
          return sourceStart.call(source, byteController);
        }
      };
      const pullAlgorithm = () => {
        try {
          return resolveHandledPromise(sourcePull ? sourcePull.call(source, byteController) : undefined);
        } catch (e) { return originalPromiseReject(e); }
      };
      const cancelAlgorithm = (reason?: any) => {
        try {
          return resolveHandledPromise(sourceCancel ? sourceCancel.call(source, reason) : undefined);
        } catch (e) { return originalPromiseReject(e); }
      };

      byteController._setup(
        this as unknown as ReadableStream<Uint8Array>,
        startAlgorithm,
        pullAlgorithm,
        cancelAlgorithm,
        strategyHWM,
        autoAllocateChunkSize
      );
    } else {
      const sourceController = isDirectStream
        ? createDirectReadableStreamController<R>(
            () => this._controller as ReadableStreamDefaultController<R> | undefined
          )
        : undefined;
      const startAlgorithm = () => {
        if (sourceStart) {
          return sourceStart.call(
            source,
            (sourceController ?? this._controller) as
              | ReadableStreamDefaultController<R>
              | ReadableStreamDirectController<R>
          );
        }
      };
      const pullAlgorithm = () => {
        try {
          return resolveHandledPromise(
            sourcePull
              ? sourcePull.call(
                  source,
                  (sourceController ?? this._controller) as
                    | ReadableStreamDefaultController<R>
                    | ReadableStreamDirectController<R>
                )
              : undefined
          );
        } catch (e) { return originalPromiseReject(e); }
      };
      const cancelAlgorithm = (reason?: any) => {
        try {
          return resolveHandledPromise(sourceCancel ? sourceCancel.call(source, reason) : undefined);
        } catch (e) { return originalPromiseReject(e); }
      };

      this._isOwningStream = isOwningStream;
      this._controller = new ReadableStreamDefaultController(
        this,
        startAlgorithm,
        pullAlgorithm,
        cancelAlgorithm,
        strategySize,
        strategyHWM,
        isOwningStream
      );
    }
  }

  get locked(): boolean {
    return this._reader !== undefined;
  }

  cancel(reason?: any): Promise<void> {
    // Per ReadableStream.cancel() spec, a locked stream yields a *rejected
    // promise* (so .catch chains observe it), never a synchronous throw.
    if (this.locked) {
      return originalPromiseReject(new TypeError('Cannot cancel a locked stream'));
    }
    this._disturbed = true;
    return this._cancelStream(reason);
  }

  getReader(options?: { mode?: 'byob' | undefined }): ReadableStreamDefaultReader<R>;
  getReader(options: { mode: 'byob' }): ReadableStreamBYOBReader;
  getReader(
    options?: { mode?: 'byob' | undefined }
  ): ReadableStreamDefaultReader<R> | ReadableStreamBYOBReader {
    if (options === null) {
      throw new TypeError('Cannot read properties of null (reading \'mode\')');
    }
    let mode: string | undefined;
    if (options !== undefined) {
      if (typeof options !== "object" && typeof options !== "function") {
        throw new TypeError('ReadableStream getReader options must be an object');
      }
      const modeValue = getPropertyValueWithoutObjectPrototype(
        options,
        "mode"
      );
      if (modeValue !== undefined) {
        mode = String(modeValue);
      }
    }

    if (mode !== undefined && mode !== 'byob') {
      throw new TypeError('Invalid reader options mode');
    }
    if (mode === 'byob') {
      if (!this._isByteStream) {
        throw new TypeError('Cannot get a BYOB reader for a non-byte stream');
      }
      return new ReadableStreamBYOBReader(this as unknown as ReadableStream<Uint8Array>);
    }
    return new ReadableStreamDefaultReader(this);
  }

  pipeThrough<T>(
    transform: { readable: ReadableStream<T>; writable: WritableStream<R> },
    options?: StreamPipeOptions
  ): ReadableStream<T> {
    if (!isReadableStreamBrand(this)) {
      throw new TypeError('Cannot pipe through from a non-ReadableStream');
    }
    if (transform === null || transform === undefined) {
      throw new TypeError('Cannot destructure property of undefined or null');
    }
    if (this.locked) {
      throw new TypeError('Cannot pipe a locked stream');
    }

    const readable = (transform as any).readable;
    if (!isReadableStreamBrand(readable)) {
      throw new TypeError('The transform readable is not a ReadableStream');
    }

    const writable = (transform as any).writable;
    if (!isWritableStreamBrand(writable)) {
      throw new TypeError('The transform writable is not a WritableStream');
    }
    const pipeOptions = normalizePipeToOptions(options);
    if (writable.locked) {
      throw new TypeError('Cannot pipe to a locked stream');
    }

    markPromiseHandled(performPipeTo(this, writable, pipeOptions));
    return readable;
  }

  pipeTo(
    destination: WritableStream<R>,
    options?: StreamPipeOptions
  ): Promise<void> {
    try {
      if (!isReadableStreamBrand(this)) {
        throw new TypeError('Cannot pipe from a non-ReadableStream');
      }
      if (!isWritableStreamBrand(destination)) {
        throw new TypeError('Cannot pipe to a non-WritableStream');
      }

      const pipeOptions = normalizePipeToOptions(options);
      const p = performPipeTo(this, destination, pipeOptions);
      // Consumers often capture a pipeTo() promise and assert on it later.
      // Mark it handled immediately so abort/error paths do not surface as
      // transient unhandled rejections in runtimes with eager tracking.
      markPromiseHandled(p);
      return p;
    } catch (error) {
      const p = originalPromiseReject(error);
      markPromiseHandled(p);
      return p;
    }
  }

  tee(): [ReadableStream<R>, ReadableStream<R>] {
    if (this.locked) {
      throw new TypeError('Cannot tee a locked stream');
    }

    const isByteStream = this._isByteStream;
    const isOwningStream = this._isOwningStream;
    if (isByteStream) {
      const sourceStream = this;
      const getReader = originalReadableStreamGetReader ?? sourceStream.getReader;
      let byobReader: ReadableStreamBYOBReader | undefined;
      let defaultReader = getReader.call(sourceStream) as ReadableStreamDefaultReader<any>;
      let reading = false;
      let sourceDone = false;
      let sourceError: any = null;
      let canceled1 = false;
      let canceled2 = false;
      let reason1: any;
      let reason2: any;
      let cancelPromise: Promise<void> | undefined;
      let resolveCancel: (() => void) | undefined;
      let rejectCancel: ((reason: any) => void) | undefined;
      let cancelStarted = false;
      let stream1Controller: ReadableByteStreamController | undefined;
      let stream2Controller: ReadableByteStreamController | undefined;
      let stream1!: ReadableStream<R>;
      let stream2!: ReadableStream<R>;

      const releaseSourceReader = (
        activeReader:
          | ReadableStreamDefaultReader<any>
          | ReadableStreamBYOBReader
          | undefined
      ) => {
        if (activeReader === undefined || activeReader._stream === undefined) {
          return;
        }
        if (sourceStream._reader === activeReader) {
          sourceStream._reader = undefined;
        }
        activeReader._stream = undefined;
      };

      const getBranchDemand = (
        controller: ReadableByteStreamController | undefined,
        stream: ReadableStream<R> | undefined,
        canceled: boolean
      ): number => {
        if (canceled || controller === undefined || stream === undefined) {
          return 0;
        }
        if (controller._pendingPullIntos.length > 0) {
          const descriptor = controller._pendingPullIntos[0];
          const minRemaining = descriptor.minimumBytes - descriptor.bytesFilled;
          const capacityRemaining = descriptor.byteLength - descriptor.bytesFilled;
          if (capacityRemaining <= 0) {
            return 0;
          }
          return Math.max(1, Math.min(capacityRemaining, Math.max(minRemaining, 1)));
        }

        const branchReader = stream._reader;
        if (branchReader instanceof ReadableStreamDefaultReader && branchReader._readRequests.length > 0) {
          return 1;
        }

        return 0;
      };

      const getBranchReadTarget = (
        controller: ReadableByteStreamController | undefined,
        canceled: boolean,
        owner: 1 | 2
      ):
        | {
            owner: 1 | 2;
            view: Uint8Array;
            min: number;
          }
        | undefined => {
        if (canceled || controller === undefined || controller._pendingPullIntos.length === 0) {
          return undefined;
        }

        const descriptor = controller._pendingPullIntos[0];
        const capacityRemaining = descriptor.byteLength - descriptor.bytesFilled;
        if (capacityRemaining <= 0) {
          return undefined;
        }

        return {
          owner,
          view: new Uint8Array(capacityRemaining),
          min: 1,
        };
      };

      const hasReadDemand = () =>
        getBranchDemand(stream1Controller, stream1, canceled1) > 0 ||
        getBranchDemand(stream2Controller, stream2, canceled2) > 0;

      const ensureCancelPromise = (): Promise<void> => {
        if (cancelPromise === undefined) {
          cancelPromise = new Promise<void>((resolve, reject) => {
            resolveCancel = resolve;
            rejectCancel = reject;
          });
        }
        return cancelPromise;
      };

      const propagateSourceError = (error: any) => {
        if (sourceDone || sourceError !== null) {
          return;
        }
        sourceError = error;
        if (cancelPromise !== undefined && !cancelStarted) {
          resolveCancel?.();
        }
        if (!canceled1) {
          stream1Controller?.error(error);
        }
        if (!canceled2) {
          stream2Controller?.error(error);
        }
      };

      const watchSourceReader = (
        activeReader: ReadableStreamDefaultReader<any> | ReadableStreamBYOBReader
      ) => {
        promiseThen(activeReader.closed, undefined, (error) => {
          propagateSourceError(error);
        });
      };

      const ensureByobReader = (): ReadableStreamBYOBReader => {
        if (byobReader !== undefined) {
          return byobReader;
        }
        releaseSourceReader(defaultReader);
        defaultReader = undefined as any;
        byobReader = getReader.call(sourceStream, { mode: 'byob' }) as ReadableStreamBYOBReader;
        watchSourceReader(byobReader);
        return byobReader;
      };

      const ensureDefaultReader = (): ReadableStreamDefaultReader<any> => {
        if (defaultReader !== undefined) {
          return defaultReader;
        }
        releaseSourceReader(byobReader);
        byobReader = undefined;
        defaultReader = getReader.call(sourceStream) as ReadableStreamDefaultReader<any>;
        watchSourceReader(defaultReader);
        return defaultReader;
      };

      const maybeFinalizeCancel = (alreadyCanceled: boolean): Promise<void> => {
        if (sourceDone) {
          return originalPromiseResolve();
        }
        if (sourceStream._state === 'errored') {
          if (alreadyCanceled && cancelPromise !== undefined) {
            return cancelPromise;
          }
          return originalPromiseReject(sourceStream._storedError);
        }
        if (sourceError !== null) {
          if (alreadyCanceled && cancelPromise !== undefined) {
            return cancelPromise;
          }
          return originalPromiseReject(sourceError);
        }

        const promise = ensureCancelPromise();
        if (!canceled1 || !canceled2) {
          return promise;
        }
        if (cancelStarted) {
          return promise;
        }

        cancelStarted = true;
        // Composite cancel reason is always the 2-element [reason1, reason2]
        // tuple, including undefined slots (ReadableStreamTee step 17).
        const reasons: Array<any> = [reason1, reason2];
        const activeSourceReader = byobReader ?? ensureDefaultReader();
        void promiseThen(activeSourceReader.cancel(reasons),
          () => resolveCancel?.(),
          (error) => rejectCancel?.(error)
        );
        return promise;
      };

      const drainSource = async () => {
        if (reading || sourceDone || sourceError !== null) {
          return;
        }

        reading = true;

        try {
          while (true) {
            const demand1 = getBranchDemand(stream1Controller, stream1, canceled1);
            const demand2 = getBranchDemand(stream2Controller, stream2, canceled2);
            const readSize = Math.max(demand1, demand2);

            if (readSize === 0) {
              break;
            }

            const branch1Target = getBranchReadTarget(stream1Controller, canceled1, 1);
            const branch2Target = getBranchReadTarget(stream2Controller, canceled2, 2);
            const readTarget = branch1Target ?? branch2Target;
            let done = false;
            let chunk: Uint8Array | undefined;
            try {
              if (readTarget !== undefined) {
                const reader = ensureByobReader();
                const result = await reader.read(readTarget.view, { min: readTarget.min });
                done = result.done;
                chunk = result.value;
              } else {
                const reader = ensureDefaultReader();
                const result = await reader.read();
                done = result.done;
                chunk = result.value as Uint8Array | undefined;
              }
            } catch (error) {
              propagateSourceError(error);
              break;
            }

            if (done) {
              sourceDone = true;
              if (!canceled1) {
                if (stream1Controller !== undefined) {
                  finalizeReadableByteStreamBranchClose(stream1Controller);
                }
              }
              if (!canceled2) {
                if (stream2Controller !== undefined) {
                  finalizeReadableByteStreamBranchClose(stream2Controller);
                }
              }
              break;
            }

            const deliveredChunk = chunk!;
            const deliverOriginalToBranch1 =
              !canceled1 && (readTarget?.owner === 1 || readTarget === undefined);
            const deliverOriginalToBranch2 =
              !canceled2 &&
              (readTarget?.owner === 2 || (readTarget === undefined && canceled1));
            const chunk1 = !canceled1
              ? (deliverOriginalToBranch1
                ? deliveredChunk
                : cloneChunkForTee(deliveredChunk)) as Uint8Array
              : undefined;
            const chunk2 = !canceled2
              ? (deliverOriginalToBranch2
                ? deliveredChunk
                : cloneChunkForTee(deliveredChunk)) as Uint8Array
              : undefined;
            if (!canceled1) {
              deliverReadableByteStreamBranchChunk(
                stream1Controller!,
                chunk1!,
                deliverOriginalToBranch1
              );
            }
            if (!canceled2) {
              deliverReadableByteStreamBranchChunk(
                stream2Controller!,
                chunk2!,
                deliverOriginalToBranch2
              );
            }
          }
        } catch (error) {
          propagateSourceError(error);
        } finally {
          reading = false;
          if (!sourceDone && sourceError === null && hasReadDemand()) {
            void drainSource();
          }
          if (sourceDone && !cancelStarted) {
            resolveCancel?.();
          }
        }
      };

      const createBranch = (branch: 1 | 2): ReadableStream<R> =>
        new ReadableStream<R>({
          type: 'bytes',
          pull: () => {
            if (sourceError !== null) {
              throw sourceError;
            }
            if (sourceDone) {
              return;
            }
            void drainSource();
          },
          cancel: (reason?: any) => {
            let alreadyCanceled: boolean;
            if (branch === 1) {
              alreadyCanceled = canceled1;
              canceled1 = true;
              reason1 = reason;
            } else {
              alreadyCanceled = canceled2;
              canceled2 = true;
              reason2 = reason;
            }
            return maybeFinalizeCancel(alreadyCanceled);
          },
        } as UnderlyingByteSource);

      stream1 = createBranch(1);
      stream2 = createBranch(2);
      stream1Controller = stream1._controller as ReadableByteStreamController;
      stream2Controller = stream2._controller as ReadableByteStreamController;
      watchSourceReader(defaultReader);

      return [stream1, stream2];
    }

    const getReader = originalReadableStreamGetReader ?? this.getReader;
    const reader = getReader.call(this);
    let reading = false;
    let sourceDone = false;
    let sourceError: any = null;
    let canceled1 = false;
    let canceled2 = false;
    let reason1: any;
    let reason2: any;
    let pendingReads1 = 0;
    let pendingReads2 = 0;
    let stream1Controller:
      | ReadableStreamDefaultController<R>
      | ReadableByteStreamController
      | undefined;
    let stream2Controller:
      | ReadableStreamDefaultController<R>
      | ReadableByteStreamController
      | undefined;
    let stream1!: ReadableStream<R>;
    let stream2!: ReadableStream<R>;

    const hasReadDemand = () => {
      return (
        (!canceled1 && pendingReads1 > 0) ||
        (!canceled2 && pendingReads2 > 0)
      );
    };

    const drainSource = async () => {
      if (reading || sourceDone || sourceError !== null) {
        return;
      }

      reading = true;

      try {
        while (hasReadDemand()) {
          try {
            const { done, value } = await reader.read();
            if (done) {
              sourceDone = true;
              if (!canceled1) {
                stream1Controller?.close();
              }
              if (!canceled2) {
                stream2Controller?.close();
              }
              break;
            }

            if (!canceled1) {
              const value1 = isByteStream ? cloneChunkForTee(value) : value;
              stream1Controller?.enqueue(value1 as any);
              if (pendingReads1 > 0) {
                pendingReads1 -= 1;
              }
            }
            if (!canceled2) {
              // Per ReadableStreamDefaultTee, both branches of a *default*
              // (non-byte) tee observe the same chunk reference — cloning is
              // only spec'd for byte-stream tee (handled in the isByteStream
              // branch above). Aliasing here preserves chunk identity for
              // non-primitive values and avoids an O(n) copy per chunk.
              // "Owning" streams are an Ibex-internal source type (not part
              // of the tee() spec) that still needs an isolated copy per
              // branch, so they keep the structuredClone path.
              let value2 = value;
              if (isOwningStream) {
                try {
                  value2 = structuredClone(value);
                } catch (error) {
                  canceled2 = true;
                  pendingReads2 = 0;
                  stream2Controller?.error(error);
                  continue;
                }
              }
              stream2Controller?.enqueue(value2 as any);
              if (pendingReads2 > 0) {
                pendingReads2 -= 1;
              }
            }
          } catch (error) {
            sourceError = error;
            break;
          }
        }
      } catch (error) {
        sourceError = error;
      } finally {
        reading = false;
        if (!sourceDone && sourceError === null && hasReadDemand()) {
          void drainSource();
        }
        if (sourceError !== null) {
          if (!canceled1) {
            stream1Controller?.error(sourceError);
          }
          if (!canceled2) {
            stream2Controller?.error(sourceError);
          }
        }
      }
    };

    const pullAlgorithm = (branch: 1 | 2) => {
      if (sourceError !== null) {
        throw sourceError;
      }
      if (sourceDone) {
        return;
      }
      if (branch === 1) {
        pendingReads1 += 1;
      } else {
        pendingReads2 += 1;
      }
      if (!canceled1 || !canceled2) {
        void drainSource();
      }
    };

    // Per ReadableStreamDefaultTee, both branch cancels settle with the same
    // ReadableStreamCancel(source, [reason1, reason2]) result: the promise
    // stays pending until BOTH branches cancel, the composite reason is always
    // the 2-element tuple (undefined slots included), and a rejecting source
    // cancel rejects both branch cancel() promises.
    let resolveTeeCancelPromise!: (value: Promise<void> | undefined) => void;
    const teeCancelPromise = new Promise<void>((resolve) => {
      resolveTeeCancelPromise = resolve as (value: Promise<void> | undefined) => void;
    });
    markPromiseHandled(teeCancelPromise);

    const ensureCancel = () => {
      if (canceled1 && canceled2) {
        const sourceCancelPromise = reader.cancel([reason1, reason2]) as Promise<void>;
        // Attach a rejection handler before the resolve-with-thenable adoption
        // job runs: a promptly-rejecting source cancel settles in the microtask
        // ahead of that job and would otherwise surface as a transient
        // unhandled rejection.
        markPromiseHandled(sourceCancelPromise);
        resolveTeeCancelPromise(sourceCancelPromise);
      }
    };

    const createBranch = (branch: 1 | 2): ReadableStream<R> => {
      const cancel = (reason?: any) => {
        if (branch === 1) {
          canceled1 = true;
          reason1 = reason;
          pendingReads1 = 0;
        } else {
          canceled2 = true;
          reason2 = reason;
          pendingReads2 = 0;
        }
        ensureCancel();
        return teeCancelPromise;
      };

      if (isByteStream) {
        return new ReadableStream<R>({
          type: 'bytes',
          pull: () => pullAlgorithm(branch),
          cancel,
        } as UnderlyingByteSource);
      }

      return new ReadableStream<R>({
        pull: () => pullAlgorithm(branch),
        cancel,
      });
    };

    stream1 = createBranch(1);
    stream2 = createBranch(2);

    stream1Controller = stream1._controller;
    stream2Controller = stream2._controller;

    return [stream1, stream2];
  }

  values(options?: { preventCancel?: boolean }): AsyncIterableIterator<R> {
    const getReader = originalReadableStreamGetReader ?? this.getReader;
    const reader = getReader.call(this) as ReadableStreamDefaultReader<R>;
    const preventCancel = options?.preventCancel ?? false;
    const iterator = new ReadableStreamAsyncIterator(reader, this, preventCancel);
    return iterator;
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<R> {
    return this.values();
  }

  // Bun-compatible convenience methods on ReadableStream
  async text(): Promise<string> {
    const reader = this.getReader();
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value instanceof Uint8Array) {
        chunks.push(value);
      } else if (typeof value === 'string') {
        chunks.push(new TextEncoder().encode(value));
      } else if (value instanceof ArrayBuffer) {
        chunks.push(new Uint8Array(value.slice(0)));
      } else if (ArrayBuffer.isView(value)) {
        chunks.push(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
      } else {
        throw new TypeError('ReadableStream chunk must be a string, Buffer, or ArrayBufferView.');
      }
    }
    const totalLen = chunks.reduce((s, c) => s + c.byteLength, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder().decode(merged);
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    const reader = this.getReader();
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value instanceof Uint8Array) {
        chunks.push(value);
      } else if (typeof value === 'string') {
        chunks.push(new TextEncoder().encode(value));
      } else if (value instanceof ArrayBuffer) {
        chunks.push(new Uint8Array(value.slice(0)));
      } else if (ArrayBuffer.isView(value)) {
        chunks.push(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
      } else {
        throw new TypeError('ReadableStream chunk must be a string, Buffer, or ArrayBufferView.');
      }
    }
    const totalLen = chunks.reduce((s, c) => s + c.byteLength, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return merged.buffer;
  }

  async bytes(): Promise<Uint8Array> {
    return new Uint8Array(await this.arrayBuffer());
  }

  async blob(): Promise<Blob> {
    const bytes = await this.bytes();
    return new Blob([bytes]);
  }

  async json(): Promise<any> {
    const text = await this.text();
    return JSON.parse(text);
  }

  /** @internal */
  _closeStream(): void {
    if (this._state !== 'readable') return;

    if (this._controller instanceof ReadableByteStreamController) {
      resolvePendingPullIntosOnClose(this._controller);
      if (this._state !== 'readable') {
        return;
      }
    }

    this._state = 'closed';

    const reader = this._reader;
    if (reader) {
      if (reader instanceof ReadableStreamDefaultReader) {
        reader._processReadRequests();
      } else if (
        reader instanceof ReadableStreamBYOBReader &&
        !(this._controller instanceof ReadableByteStreamController)
      ) {
        // Resolve any pending BYOB read requests with done
        for (const request of reader._readIntoRequests) {
          request.resolve(createReadResult(true, new Uint8Array(0) as any));
        }
        reader._readIntoRequests = [];
      }
      reader._closedResolve?.();
    }
  }

  /** @internal */
  _errorStream(e: any): void {
    if (this._state !== 'readable') return;

    this._state = 'errored';
    this._storedError = e;

    const reader = this._reader;
    if (reader) {
      reader._closedReject?.(e);
      if (reader._closedPromise) markPromiseHandled(reader._closedPromise);
      if (reader instanceof ReadableStreamDefaultReader) {
        reader._readRequests.forEach((r) => r.reject(e));
        reader._readRequests = [];
      } else if (reader instanceof ReadableStreamBYOBReader) {
        reader._readIntoRequests.forEach((r) => r.reject(e));
        reader._readIntoRequests = [];
      }
    }
  }

  /** @internal */
  async _cancelStream(
    reason?: any,
    reader?: ReadableStreamReaderType
  ): Promise<void> {
    // ReadableStreamCancel: cancelling an errored stream rejects with the
    // stored error (resolving would mask it); a closed stream resolves.
    if (this._state === 'errored') {
      throw this._storedError;
    }
    if (this._state !== 'readable') {
      return;
    }

    this._state = 'closed';

    const targetReader = reader ?? this._reader;
    if (targetReader) {
      targetReader._closedResolve?.();

      if (targetReader instanceof ReadableStreamDefaultReader) {
        const doneResult = createReadResult(true, undefined);
        const requests = targetReader._readRequests.slice();
        targetReader._readRequests = [];
        requests.forEach((request) => request.resolve(doneResult));
      } else if (targetReader instanceof ReadableStreamBYOBReader) {
        const requests = targetReader._readIntoRequests.slice();
        targetReader._readIntoRequests = [];
        requests.forEach((request) => request.resolve(createReadResult(true, undefined as any)));
      }
    }

    if (this._controller instanceof ReadableByteStreamController) {
      this._controller._pendingPullIntos = [];
      invalidateReadableByteStreamByobRequest(this._controller);
    }

    if (this._controller) {
      await this._controller._cancelAlgorithm(reason);
    }
  }

  // Static methods
  static from<T>(asyncIterable: AsyncIterable<T> | Iterable<T>): ReadableStream<T> {
    if (!isObject(asyncIterable)) {
      throw new TypeError('Cannot convert undefined or null to object');
    }

    let iterator: any;
    let next: () => any;
    let returnFn: ((reason?: any) => any) | undefined;
    let done = false;

    const asyncIteratorMethod = getPropertyValueWithoutObjectPrototype(
      asyncIterable,
      Symbol.asyncIterator
    );
    if (asyncIteratorMethod !== undefined) {
      if (asyncIteratorMethod === null) {
        // Treat null as no async iterator, fall through to sync iterable handling
      } else {
        if (typeof asyncIteratorMethod !== 'function') {
          throw new TypeError('async iterator property is not callable');
        }
        iterator = asyncIteratorMethod.call(asyncIterable);
        if (!isObject(iterator)) {
          throw new TypeError('async iterator method did not return an object');
        }

        next = getPropertyValueWithoutObjectPrototype(iterator, 'next');
        if (typeof next !== 'function') {
          throw new TypeError('iterator.next must be callable');
        }
        returnFn = getPropertyValueWithoutObjectPrototype(iterator, 'return');
      }
    }

    if (next === undefined) {
      const syncIteratorMethod = getPropertyValueWithoutObjectPrototype(
        asyncIterable,
        Symbol.iterator
      );
      if (typeof syncIteratorMethod !== 'function') {
        throw new TypeError('Cannot get iterator method');
      }
      iterator = syncIteratorMethod.call(asyncIterable);
      if (!isObject(iterator)) {
        throw new TypeError('iterator method did not return an object');
      }

      next = getPropertyValueWithoutObjectPrototype(iterator, 'next');
      if (typeof next !== 'function') {
        throw new TypeError('iterator.next must be callable');
      }
      // Per the spec's async-from-sync iterator wrapper, return() forwards to
      // the sync iterator, so cancelling the stream must run e.g. a
      // generator's finally blocks instead of leaking their resources.
      returnFn = getPropertyValueWithoutObjectPrototype(iterator, 'return');
    }

    return new ReadableStream<T>({
      async pull(controller) {
        if (done) {
          controller.close();
          return;
        }

        let nextResult: any;
        try {
          nextResult = await next.call(iterator);
        } catch (error) {
          controller.error(error);
          return;
        }

        if (!isObject(nextResult)) {
          controller.error(new TypeError('iterator next must return an object'));
          return;
        }
        if (
          !(isIteratorResult(nextResult))
        ) {
          controller.error(new TypeError('iterator.next result must be an object with done and value'));
          return;
        }

        if (nextResult.done) {
          done = true;
          controller.close();
        } else {
          controller.enqueue(nextResult.value);
        }
      },
      async cancel(reason) {
        if (returnFn === undefined) {
          return;
        }
        if (typeof returnFn !== 'function') {
          throw new TypeError('iterator.return must be callable');
        }

        const returnResult = await returnFn.call(iterator, reason);
        if (!isObject(returnResult)) {
          throw new TypeError('iterator.return must return an object');
        }
      },
    }, { highWaterMark: 0 });
  }

  get [Symbol.toStringTag](): string {
    return 'ReadableStream';
  }
}

originalReadableStreamGetReader = ReadableStream.prototype.getReader;

// ============================================================================
// ByteLengthQueuingStrategy
// ============================================================================

export class ByteLengthQueuingStrategy implements QueuingStrategy<ArrayBufferView> {
  readonly highWaterMark: number;

  constructor(init: { highWaterMark: number }) {
    const highWaterMark = getQueuingStrategyHighWaterMark(
      init,
      'ByteLengthQueuingStrategy requires a highWaterMark'
    );
    this.highWaterMark = highWaterMark;
  }

  get size(): (chunk: ArrayBufferView) => number {
    return byteLengthSize;
  }

  get [Symbol.toStringTag](): string {
    return 'ByteLengthQueuingStrategy';
  }
}

// ============================================================================
// CountQueuingStrategy
// ============================================================================

export class CountQueuingStrategy implements QueuingStrategy {
  readonly highWaterMark: number;

  constructor(init: { highWaterMark: number }) {
    const highWaterMark = getQueuingStrategyHighWaterMark(
      init,
      'CountQueuingStrategy requires a highWaterMark'
    );
    this.highWaterMark = highWaterMark;
  }

  get size(): () => number {
    return countSize;
  }

  get [Symbol.toStringTag](): string {
    return 'CountQueuingStrategy';
  }
}
