// @ts-nocheck
import { DOMException } from '../events/DOMException';
import { ReadableStream, ReadableStreamDefaultController, WritableStream } from '../streams';
import { WebSocket } from './WebSocket';
import { WebSocketError } from './WebSocketError';

export interface WebSocketStreamOptions {
  protocols?: string[];
  signal?: AbortSignal;
}

export interface WebSocketCloseInfo {
  closeCode?: number;
  reason?: string;
}

interface OpenedInfo {
  readable: ReadableStream<string | Uint8Array>;
  writable: WritableStream<string | ArrayBuffer | ArrayBufferView | Blob>;
  protocol: string;
  extensions: string;
}

interface ClosedInfo {
  closeCode: number;
  reason: string;
}

// NSURLSessionWebSocketTask does not expose a reliable send-drain signal for
// large messages, so WebSocketStream applies a conservative completion budget
// for oversized writes to preserve backpressure semantics.
const STREAM_WRITE_IMMEDIATE_WINDOW_BYTES = 256 * 1024;
const STREAM_WRITE_DRAIN_BYTES_PER_MS = 4096;

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function createRealmDomException(message: string, name: string): DOMException {
  const DOMExceptionCtor = ((globalThis as any).DOMException || DOMException) as typeof DOMException;
  return new DOMExceptionCtor(message, name);
}

function createAbortError(): DOMException {
  return createRealmDomException('The operation was aborted.', 'AbortError');
}

function createInvalidStateError(): DOMException {
  return createRealmDomException('The stream is no longer writable.', 'InvalidStateError');
}

function isObjectLike(value: unknown): value is Record<string, unknown> {
  return (typeof value === 'object' && value !== null) || typeof value === 'function';
}

function isSharedArrayBufferInstance(buffer: unknown): boolean {
  return typeof SharedArrayBuffer === 'function' && buffer instanceof SharedArrayBuffer;
}

function isResizableArrayBuffer(buffer: unknown): boolean {
  return !!buffer &&
    typeof buffer === 'object' &&
    typeof (buffer as any).byteLength === 'number' &&
    (buffer as any).resizable === true;
}

function normalizeCloseArguments(value: unknown): { code?: number; reason?: string } {
  if (value === undefined) {
    return {};
  }
  if (!isObjectLike(value)) {
    throw new TypeError('close() requires an options object');
  }
  const raw = value as WebSocketCloseInfo;
  const reason = raw.reason === undefined ? undefined : String(raw.reason);
  let code = raw.closeCode;
  if (reason !== undefined && reason !== '' && code === undefined) {
    code = 1000;
  }
  if (code !== undefined) {
    if (typeof code !== 'number' || !Number.isInteger(code) || (code !== 1000 && (code < 3000 || code > 4999))) {
      throw createRealmDomException('Invalid close code', 'InvalidAccessError');
    }
  }
  if (reason !== undefined) {
    const encoded = new TextEncoder().encode(reason);
    if (encoded.byteLength > 123) {
      throw createRealmDomException('Close reason is too long', 'SyntaxError');
    }
  }
  if (code === undefined && reason === '') {
    return {};
  }
  return { code, reason };
}

function getAbortCloseArguments(reason: unknown): { code?: number; reason?: string } {
  if (reason instanceof WebSocketError) {
    const closeCode = reason.closeCode === null ? undefined : reason.closeCode;
    return {
      code: closeCode === undefined ? undefined : closeCode,
      reason: reason.reason || undefined,
    };
  }
  return {};
}

function closeSocket(socket: WebSocket, code?: number, reason?: string): void {
  if (code === undefined) {
    socket.close();
    return;
  }
  if (reason === undefined) {
    socket.close(code);
    return;
  }
  socket.close(code, reason);
}

function normalizeClosedInfo(code: number, reason: string): ClosedInfo {
  return {
    closeCode: code || 1005,
    reason: reason || '',
  };
}

function createWebSocketCloseError(message: string, code: number, reason: string): WebSocketError {
  const closeCode = code === 1005 ? null : code;
  return new WebSocketError(message, {
    closeCode: closeCode === undefined ? null : closeCode,
    reason,
  });
}

function getMonotonicNow(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}

function estimateWriteResolveDelay(byteLength: number): number {
  if (byteLength <= STREAM_WRITE_IMMEDIATE_WINDOW_BYTES) {
    return 0;
  }
  return Math.ceil(
    (byteLength - STREAM_WRITE_IMMEDIATE_WINDOW_BYTES) / STREAM_WRITE_DRAIN_BYTES_PER_MS
  );
}

function normalizeWritableChunk(
  chunk: unknown
): { sendValue: string | ArrayBuffer | ArrayBufferView | Blob; byteLength: number } {
  if (typeof chunk === 'string') {
    return {
      sendValue: chunk,
      byteLength: new TextEncoder().encode(chunk).byteLength,
    };
  }

  if (chunk instanceof ArrayBuffer) {
    if (isResizableArrayBuffer(chunk)) {
      throw new TypeError('Resizable ArrayBuffer is not supported');
    }
    return { sendValue: chunk, byteLength: chunk.byteLength };
  }

  if (ArrayBuffer.isView(chunk)) {
    if (isSharedArrayBufferInstance(chunk.buffer)) {
      throw new TypeError('SharedArrayBuffer-backed views are not supported');
    }
    if (isResizableArrayBuffer(chunk.buffer)) {
      throw new TypeError('Resizable ArrayBuffer is not supported');
    }
    return { sendValue: chunk, byteLength: chunk.byteLength };
  }

  if (chunk && typeof chunk === 'object' && typeof (chunk as Blob).arrayBuffer === 'function' && typeof (chunk as Blob).size === 'number') {
    return { sendValue: chunk as Blob, byteLength: (chunk as Blob).size };
  }

  const stringified = String(chunk);
  return {
    sendValue: stringified,
    byteLength: new TextEncoder().encode(stringified).byteLength,
  };
}

export class WebSocketStream {
  readonly url: string;
  readonly opened: Promise<OpenedInfo>;
  readonly closed: Promise<ClosedInfo>;

  _socket: WebSocket | null = null;
  _readableController: ReadableStreamDefaultController<string | Uint8Array> | null = null;
  _readable: ReadableStream<string | Uint8Array> | null = null;
  _writable: WritableStream<string | ArrayBuffer | ArrayBufferView | Blob> | null = null;
  _openedDeferred = createDeferred<OpenedInfo>();
  _closedDeferred = createDeferred<ClosedInfo>();
  _openedSettled = false;
  _closedSettled = false;
  _connected = false;
  _localCloseInitiated = false;
  _closedDuringHandshake = false;
  _ignoredTerminal = false;
  _pendingWriteRequests: Array<{
    remaining: number;
    readyAt: number;
    resolve: () => void;
    reject: (reason: unknown) => void;
  }> = [];
  _writableInvalidStateError: DOMException | null = null;
  _pendingWriteResolveTimer: number | null = null;

  constructor(url: string | URL, options?: WebSocketStreamOptions) {
    const urlString = url instanceof URL ? url.href : String(url);
    this.url = urlString;
    this.opened = this._openedDeferred.promise;
    this.closed = this._closedDeferred.promise;

    if (arguments.length === 0) {
      throw new TypeError('WebSocketStream constructor requires a URL');
    }
    if (options !== undefined && !isObjectLike(options)) {
      throw new TypeError('WebSocketStream options must be an object');
    }
    if (options?.protocols !== undefined && !Array.isArray(options.protocols)) {
      throw new TypeError('WebSocketStream protocols option must be an array');
    }

    const signal = options?.signal;
    if (signal?.aborted) {
      const abortError = createAbortError();
      this._rejectOpened(abortError);
      this._rejectClosed(abortError);
      return;
    }

    this._readable = new ReadableStream<string | Uint8Array>({
      start: (controller) => {
        this._readableController = controller;
      },
      pull: () => {
        this._syncReadableBackpressure();
      },
      cancel: async (reason?: unknown) => {
        const closeArgs = getAbortCloseArguments(reason);
        await this._initiateClose(closeArgs.code, closeArgs.reason);
      },
    });

    this._writable = new WritableStream<string | ArrayBuffer | ArrayBufferView | Blob>({
      write: async (chunk) => {
        if (!this._socket || !this._connected) {
          throw createInvalidStateError();
        }
        const normalized = normalizeWritableChunk(chunk);
        return new Promise<void>((resolve, reject) => {
          const resolveDelay = estimateWriteResolveDelay(normalized.byteLength);
          this._pendingWriteRequests.push({
            remaining: normalized.byteLength,
            readyAt: getMonotonicNow() + resolveDelay,
            resolve,
            reject,
          });
          try {
            this._socket!.send(normalized.sendValue as any);
            if (normalized.byteLength === 0) {
              const waiter = this._pendingWriteRequests.shift();
              waiter?.resolve();
            }
          } catch (error) {
            const waiter = this._pendingWriteRequests.pop();
            waiter?.reject(error);
          }
        });
      },
      close: async () => {
        await this._initiateClose(undefined, undefined);
      },
      abort: async (reason?: unknown) => {
        const closeArgs = getAbortCloseArguments(reason);
        await this._initiateClose(closeArgs.code, closeArgs.reason);
      },
    });

    const socket = new WebSocket(urlString, options?.protocols);
    socket.binaryType = 'arraybuffer';
    socket._setIncomingFlowControl(true);
    this._socket = socket;

    const originalHandleBytesSent = socket._handleBytesSent.bind(socket);
    socket._handleBytesSent = (bytesSent: number) => {
      originalHandleBytesSent(bytesSent);
      this._handleBytesSent(bytesSent);
    };

    socket.addEventListener('open', () => {
      this._connected = true;
      if (signal) {
        signal.removeEventListener('abort', abortListener);
      }
      this._resolveOpened({
        readable: this._readable!,
        writable: this._writable!,
        protocol: socket.protocol,
        extensions: socket.extensions,
      });
    });

    socket.addEventListener('message', (event: any) => {
      if (!this._readableController) {
        return;
      }
      if (typeof event.data === 'string') {
        this._readableController.enqueue(event.data);
      } else if (event.data instanceof ArrayBuffer) {
        this._readableController.enqueue(new Uint8Array(event.data));
      } else if (ArrayBuffer.isView(event.data)) {
        this._readableController.enqueue(new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength));
      }
      this._syncReadableBackpressure();
    });

    socket.addEventListener('error', () => {
      // Close carries the structured outcome we care about.
    });

    socket.addEventListener('close', (event: any) => {
      if (signal) {
        signal.removeEventListener('abort', abortListener);
      }
      this._handleSocketClose(event.code, event.reason || '', !!event.wasClean);
    });

    const abortListener = () => {
      if (this._connected) {
        return;
      }
      const abortError = createAbortError();
      this._ignoredTerminal = true;
      this._rejectOpened(abortError);
      this._rejectClosed(abortError);
      try {
        socket.close();
      } catch (_abortCloseErr) {}
    };

    if (signal) {
      signal.addEventListener('abort', abortListener, { once: true });
    }
  }

  close(info?: WebSocketCloseInfo): void {
    const normalized = normalizeCloseArguments(info);
    void this._initiateClose(normalized.code, normalized.reason);
  }

  _handleBytesSent(bytesSent: number): void {
    let remainingBytes = bytesSent;
    for (const request of this._pendingWriteRequests) {
      if (remainingBytes <= 0) {
        break;
      }
      if (request.remaining <= 0) {
        continue;
      }
      if (remainingBytes >= request.remaining) {
        remainingBytes -= request.remaining;
        request.remaining = 0;
      } else {
        request.remaining -= remainingBytes;
        remainingBytes = 0;
      }
    }
    this._drainResolvedWrites();
  }

  _syncReadableBackpressure(): void {
    if (!this._socket || !this._connected || !this._readableController) {
      return;
    }

    const desiredSize = this._readableController.desiredSize;
    if (desiredSize !== null && desiredSize <= 0) {
      this._socket._pauseIncoming();
      return;
    }

    this._socket._resumeIncoming();
  }

  async _initiateClose(code?: number, reason?: string): Promise<void> {
    if (this._closedSettled) {
      return;
    }

    if (!this._socket) {
      if (!this._closedSettled) {
        const abortError = createAbortError();
        this._rejectOpened(abortError);
        this._rejectClosed(abortError);
      }
      return;
    }

    if (!this._connected && !this._openedSettled) {
      this._closedDuringHandshake = true;
      this._localCloseInitiated = true;
      const error = createWebSocketCloseError('WebSocketStream closed during handshake', 1005, '');
      this._ignoredTerminal = true;
      this._rejectOpened(error);
      this._rejectClosed(error);
      try {
        closeSocket(this._socket, code, reason);
      } catch (_closeDuringHandshakeErr) {}
      return;
    }

    if (this._localCloseInitiated) {
      return this.closed.then(() => undefined);
    }

    this._localCloseInitiated = true;
    closeSocket(this._socket, code, reason);
    return this.closed.then(() => undefined);
  }

  _handleSocketClose(code: number, reason: string, wasClean: boolean): void {
    if (this._ignoredTerminal) {
      return;
    }

    this._connected = false;

    const closeInfo = normalizeClosedInfo(code, reason);
    const closeError = createWebSocketCloseError(reason || 'WebSocket closed', closeInfo.closeCode, closeInfo.reason);
    const hadPendingWrites = this._pendingWriteRequests.length > 0;

    if (!this._openedSettled) {
      this._rejectOpened(closeError);
      this._rejectClosed(closeError);
      this._rejectPendingWrites(createInvalidStateError());
      this._errorReadable(closeError);
      this._errorWritable(closeError);
      return;
    }

    if (!wasClean || closeInfo.closeCode === 1006) {
      this._rejectClosed(closeError);
      this._errorReadable(closeError);
      if (hadPendingWrites) {
        const invalidStateError = this._getWritableInvalidStateError();
        this._rejectPendingWrites(invalidStateError);
        this._errorWritable(invalidStateError);
      } else {
        this._errorWritable(closeError);
      }
      return;
    }

    if (hadPendingWrites) {
      const invalidStateError = this._getWritableInvalidStateError();
      this._rejectClosed(closeError);
      this._closeReadable();
      this._rejectPendingWrites(invalidStateError);
      this._errorWritable(invalidStateError);
      return;
    }

    this._resolveClosed(closeInfo);
    this._closeReadable();
    if (this._localCloseInitiated) {
      this._finishWritableClose();
    } else {
      const invalidStateError = this._getWritableInvalidStateError();
      this._rejectPendingWrites(invalidStateError);
      this._errorWritable(invalidStateError);
    }
  }

  _getWritableInvalidStateError(): DOMException {
    if (!this._writableInvalidStateError) {
      this._writableInvalidStateError = createInvalidStateError();
    }
    return this._writableInvalidStateError;
  }

  _rejectPendingWrites(reason: unknown): void {
    this._clearPendingWriteResolveTimer();
    while (this._pendingWriteRequests.length > 0) {
      const request = this._pendingWriteRequests.shift();
      request?.reject(reason);
    }
  }

  _drainResolvedWrites(): void {
    this._clearPendingWriteResolveTimer();

    while (this._pendingWriteRequests.length > 0) {
      const current = this._pendingWriteRequests[0];
      if (current.remaining > 0) {
        return;
      }

      const delay = current.readyAt - getMonotonicNow();
      if (delay > 0) {
        this._pendingWriteResolveTimer = setTimeout(() => {
          this._pendingWriteResolveTimer = null;
          this._drainResolvedWrites();
        }, delay) as unknown as number;
        return;
      }

      this._pendingWriteRequests.shift();
      current.resolve();
    }
  }

  _clearPendingWriteResolveTimer(): void {
    if (this._pendingWriteResolveTimer === null) {
      return;
    }
    clearTimeout(this._pendingWriteResolveTimer);
    this._pendingWriteResolveTimer = null;
  }

  _resolveOpened(value: OpenedInfo): void {
    if (this._openedSettled) {
      return;
    }
    this._openedSettled = true;
    this._openedDeferred.resolve(value);
  }

  _rejectOpened(reason: unknown): void {
    if (this._openedSettled) {
      return;
    }
    this._openedSettled = true;
    this._openedDeferred.reject(reason);
  }

  _resolveClosed(value: ClosedInfo): void {
    if (this._closedSettled) {
      return;
    }
    this._closedSettled = true;
    this._closedDeferred.resolve(value);
  }

  _rejectClosed(reason: unknown): void {
    if (this._closedSettled) {
      return;
    }
    this._closedSettled = true;
    this._closedDeferred.reject(reason);
  }

  _closeReadable(): void {
    if (this._readableController) {
      try {
        this._readableController.close();
        return;
      } catch (_closeReadableErr) {}
    }
    if (!this._readable) {
      return;
    }
    (this._readable as any)._closeStream();
  }

  _errorReadable(reason: unknown): void {
    if (!this._readable) {
      return;
    }
    (this._readable as any)._errorStream(reason);
  }

  _finishWritableClose(): void {
    if (!this._writable) {
      return;
    }
    const writable = this._writable as any;
    if (writable._state === 'closed' || writable._state === 'errored') {
      return;
    }

    writable._state = 'closed';
    writable._queue = [];
    writable._queueTotalSize = 0;

    const closeRequest = writable._inFlightCloseRequest;
    if (closeRequest) {
      closeRequest.resolve();
      writable._inFlightCloseRequest = undefined;
    }

    const writer = writable._writer;
    if (writer) {
      writer._readyResolve?.(undefined);
      writer._closedResolve?.(undefined);
    }
  }

  _errorWritable(reason: unknown): void {
    if (!this._writable) {
      return;
    }
    (this._writable as any)._errorStream(reason);
  }

  get [Symbol.toStringTag](): string {
    return 'WebSocketStream';
  }
}

export default WebSocketStream;
