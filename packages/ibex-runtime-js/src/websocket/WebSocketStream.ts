// @ts-nocheck
import { DOMException } from '../events/DOMException';
import { ReadableStream, ReadableStreamDefaultController, WritableStream } from '../streams';
import {
  WebSocket,
  createWebSocketForStream,
  getSupportedWebSocketBlobSize,
} from './WebSocket';
import { WebSocketError, createWireWebSocketError } from './WebSocketError';

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

interface AuthorizedWebSocketStreamWrite {
  socket: WebSocket;
  chunk: unknown;
}

interface AuthorizedWebSocketStreamRead {
  socket: WebSocket;
  chunk: string | Uint8Array;
}

// The generic WritableStream exposes compatibility `_` fields, so never put
// caller data or a forgeable "authorized" bit directly in its deferred queue.
// The queue receives only a frozen identity object; its payload and one-shot
// admission record stay module-private.
const authorizedWebSocketStreamWrites = new WeakMap<
  object,
  AuthorizedWebSocketStreamWrite
>();
const consumedWebSocketStreamWrites = new WeakSet<object>();

// Inbound payloads must likewise never sit in ReadableStream's compatibility
// `_controller._queue`. Queue only an opaque identity and resolve it after an
// owner-admitted read; direct queue/request inspection can reveal at most the
// frozen token, never the peer's bytes.
// @ref LLP 0004#retained-native-wrapper-invariant — deferred stream queues
// carry opaque one-shot identities, with payloads held only in private maps.
const authorizedWebSocketStreamReads = new WeakMap<
  object,
  AuthorizedWebSocketStreamRead
>();
const consumedWebSocketStreamReads = new WeakSet<object>();

// Capture the socket surface before application code can replace prototype
// methods and intercept the closure-private socket during stream setup.
const webSocketStreamSocketSend = WebSocket.prototype.send;
const webSocketStreamSocketClose = WebSocket.prototype.close;
const webSocketStreamSocketPauseIncoming = WebSocket.prototype._pauseIncoming;
const webSocketStreamSocketResumeIncoming = WebSocket.prototype._resumeIncoming;
const webSocketStreamSocketSetIncomingFlowControl = WebSocket.prototype._setIncomingFlowControl;
const webSocketStreamSocketAddEventListener = WebSocket.prototype.addEventListener;
const webSocketStreamSocketBinaryTypeSetter = Object.getOwnPropertyDescriptor(
  WebSocket.prototype,
  'binaryType'
)?.set;
const webSocketStreamSocketProtocolGetter = Object.getOwnPropertyDescriptor(
  WebSocket.prototype,
  'protocol'
)?.get;
const webSocketStreamSocketExtensionsGetter = Object.getOwnPropertyDescriptor(
  WebSocket.prototype,
  'extensions'
)?.get;

interface PendingWebSocketStreamWrite {
  remaining: number;
  readyAt: number;
  resolve: () => void;
  reject: (reason: unknown) => void;
}

interface WebSocketStreamPrivateState {
  constructing: boolean;
  url: string;
  socket: WebSocket | null;
  readableController: ReadableStreamDefaultController<string | Uint8Array> | null;
  readable: ReadableStream<string | Uint8Array> | null;
  writable: WritableStream<string | ArrayBuffer | ArrayBufferView | Blob> | null;
  openedDeferred: ReturnType<typeof createDeferred<OpenedInfo>>;
  closedDeferred: ReturnType<typeof createDeferred<ClosedInfo>>;
  openedSettled: boolean;
  closedSettled: boolean;
  connected: boolean;
  localCloseInitiated: boolean;
  closedDuringHandshake: boolean;
  ignoredTerminal: boolean;
  pendingWriteRequests: PendingWebSocketStreamWrite[];
  writableInvalidStateError: DOMException | null;
  pendingWriteResolveTimer: number | null;
  assertStateOwner: (() => void) | null;
  assertSendOwner: (() => void) | null;
  assertReleaseOwner: (() => void) | null;
  writableCloseAdmitted: boolean;
  writableAbortAdmitted: boolean;
}

// WebSocketStream wrappers can cross principal boundaries. Keep every native
// handle reference, deferred settlement bit, and write-accounting record off
// the wrapper so forged properties cannot redirect or poison the owner's
// state machine.
const webSocketStreamPrivateStates = new WeakMap<object, WebSocketStreamPrivateState>();
const webSocketStreamInternalKey = {};

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

function newWebSocketStreamPrivateState(url: string): WebSocketStreamPrivateState {
  return {
    constructing: true,
    url,
    socket: null,
    readableController: null,
    readable: null,
    writable: null,
    openedDeferred: createDeferred<OpenedInfo>(),
    closedDeferred: createDeferred<ClosedInfo>(),
    openedSettled: false,
    closedSettled: false,
    connected: false,
    localCloseInitiated: false,
    closedDuringHandshake: false,
    ignoredTerminal: false,
    pendingWriteRequests: [],
    writableInvalidStateError: null,
    pendingWriteResolveTimer: null,
    assertStateOwner: null,
    assertSendOwner: null,
    assertReleaseOwner: null,
    writableCloseAdmitted: false,
    writableAbortAdmitted: false,
  };
}

function webSocketStreamPrivateState(value: unknown): WebSocketStreamPrivateState {
  const state = value !== null && (typeof value === 'object' || typeof value === 'function')
    ? webSocketStreamPrivateStates.get(value as object)
    : undefined;
  if (!state) {
    throw new TypeError('Illegal invocation');
  }
  return state;
}

function ownedWebSocketStreamPrivateState(value: unknown): WebSocketStreamPrivateState {
  const state = webSocketStreamPrivateState(value);
  // A pre-aborted constructor never creates a native wrapper. Its already-
  // rejected promises remain observable without inventing an owner identity.
  state.assertStateOwner?.();
  return state;
}

function assertWebSocketStreamInternal(key: unknown): void {
  if (key !== webSocketStreamInternalKey) {
    throw new TypeError('Illegal invocation');
  }
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
    webSocketStreamSocketClose.call(socket);
    return;
  }
  if (reason === undefined) {
    webSocketStreamSocketClose.call(socket, code);
    return;
  }
  webSocketStreamSocketClose.call(socket, code, reason);
}

function normalizeClosedInfo(code: number, reason: string): ClosedInfo {
  return {
    closeCode: code || 1005,
    reason: reason || '',
  };
}

function createWebSocketCloseError(message: string, code: number, reason: string): WebSocketError {
  // Wire close codes are peer-controlled (1001/1011/... are all conforming),
  // so this must go through the non-validating wire factory: a throwing
  // constructor here would kill the close listener and leave opened/closed
  // pending forever (ENG-23133).
  const closeCode = code === 1005 ? null : code;
  return createWireWebSocketError(message, closeCode === undefined ? null : closeCode, reason);
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

  const blobByteLength = getSupportedWebSocketBlobSize(chunk);
  if (blobByteLength !== null) {
    return { sendValue: chunk as Blob, byteLength: blobByteLength };
  }

  const stringified = String(chunk);
  return {
    sendValue: stringified,
    byteLength: new TextEncoder().encode(stringified).byteLength,
  };
}

export class WebSocketStream {
  constructor(url: string | URL, options?: WebSocketStreamOptions) {
    if (arguments.length === 0) {
      throw new TypeError('WebSocketStream constructor requires a URL');
    }
    const urlString = url instanceof URL ? url.href : String(url);
    const state = newWebSocketStreamPrivateState(urlString);
    webSocketStreamPrivateStates.set(this, state);

    if (options !== undefined && !isObjectLike(options)) {
      throw new TypeError('WebSocketStream options must be an object');
    }
    if (options?.protocols !== undefined && !Array.isArray(options.protocols)) {
      throw new TypeError('WebSocketStream protocols option must be an array');
    }

    const signal = options?.signal;
    if (signal?.aborted) {
      const abortError = createAbortError();
      webSocketStreamRejectOpened.call(this, abortError, webSocketStreamInternalKey);
      webSocketStreamRejectClosed.call(this, abortError, webSocketStreamInternalKey);
      return;
    }

    state.readable = new ReadableStream<string | Uint8Array>({
      start: (controller) => {
        state.readableController = controller;
      },
      pull: () => {
        webSocketStreamSyncReadableBackpressure.call(this, webSocketStreamInternalKey);
      },
      cancel: async (reason?: unknown) => {
        if (!state.socket || !state.assertReleaseOwner) {
          throw createInvalidStateError();
        }
        state.assertReleaseOwner();
        const closeArgs = getAbortCloseArguments(reason);
        await webSocketStreamInitiateClose.call(
          this,
          closeArgs.code,
          closeArgs.reason,
          webSocketStreamInternalKey
        );
      },
    }, undefined, {
      read: () => {
        if (!state.assertStateOwner) {
          // ReadableStream schedules some setup work as a microtask. If the
          // later WebSocket construction throws (for example invalid URL
          // credentials), that inaccessible partial stream must still be able
          // to finish its internal setup without creating an unhandled error.
          if (state.constructing) {
            return;
          }
          throw createInvalidStateError();
        }
        state.assertStateOwner();
      },
      transformChunk: (chunk) => {
        const socket = state.socket;
        const entry = isObjectLike(chunk) ? chunk as object : null;
        const authorized = entry
          ? authorizedWebSocketStreamReads.get(entry)
          : undefined;
        if (
          !socket ||
          !entry ||
          !authorized ||
          authorized.socket !== socket ||
          consumedWebSocketStreamReads.has(entry)
        ) {
          throw createInvalidStateError();
        }
        consumedWebSocketStreamReads.add(entry);
        return authorized.chunk;
      },
      cancel: () => {
        if (!state.socket || !state.assertReleaseOwner) {
          throw createInvalidStateError();
        }
        state.assertReleaseOwner();
      },
    } as any);

    state.writable = new WritableStream<string | ArrayBuffer | ArrayBufferView | Blob>({
      write: async (admittedWrite) => {
        const socket = state.socket;
        if (!socket || !state.connected || !state.assertSendOwner) {
          throw createInvalidStateError();
        }
        // `_writeAlgorithm` is a compatibility field on the generic stream.
        // Re-authenticate before resolving an opaque admission back to its
        // caller-owned payload, so a retained foreign caller cannot make us
        // invoke conversion hooks or inspect that payload through the sink.
        state.assertSendOwner();
        const entry = isObjectLike(admittedWrite) ? admittedWrite as object : null;
        const authorized = entry
          ? authorizedWebSocketStreamWrites.get(entry)
          : undefined;
        if (
          !entry ||
          !authorized ||
          authorized.socket !== socket ||
          consumedWebSocketStreamWrites.has(entry)
        ) {
          throw createInvalidStateError();
        }
        const normalized = normalizeWritableChunk(authorized.chunk);
        return new Promise<void>((resolve, reject) => {
          const resolveDelay = estimateWriteResolveDelay(normalized.byteLength);
          const request: PendingWebSocketStreamWrite = {
            remaining: normalized.byteLength,
            readyAt: getMonotonicNow() + resolveDelay,
            resolve,
            reject,
          };
          state.pendingWriteRequests.push(request);
          try {
            webSocketStreamSocketSend.call(socket, normalized.sendValue as any);
            // Consume only after the native owner preflight in send() has
            // succeeded. A direct foreign call to the captured sink cannot
            // burn the owner's admitted entry.
            consumedWebSocketStreamWrites.add(entry);
          } catch (error) {
            const requestIndex = state.pendingWriteRequests.indexOf(request);
            if (requestIndex !== -1) {
              state.pendingWriteRequests.splice(requestIndex, 1);
            }
            request.reject(error);
          }
        });
      },
      close: async () => {
        if (!state.writableCloseAdmitted || !state.socket || !state.assertReleaseOwner) {
          throw createInvalidStateError();
        }
        state.assertReleaseOwner();
        await webSocketStreamInitiateClose.call(
          this,
          undefined,
          undefined,
          webSocketStreamInternalKey
        );
        state.writableCloseAdmitted = false;
      },
      abort: async (reason?: unknown) => {
        if (!state.writableAbortAdmitted || !state.socket || !state.assertReleaseOwner) {
          throw createInvalidStateError();
        }
        state.assertReleaseOwner();
        const closeArgs = getAbortCloseArguments(reason);
        await webSocketStreamInitiateClose.call(
          this,
          closeArgs.code,
          closeArgs.reason,
          webSocketStreamInternalKey
        );
        state.writableAbortAdmitted = false;
      },
    }, undefined, {
      inspect: () => {
        if (!state.assertStateOwner) {
          if (state.constructing) {
            return;
          }
          throw createInvalidStateError();
        }
        state.assertStateOwner();
      },
      write: (chunk) => {
        const socket = state.socket;
        if (!socket || !state.connected || !state.assertSendOwner) {
          throw createInvalidStateError();
        }

        // @ref LLP 0021#decision-staging-and-principal-semantics — authenticate
        // at public writer.write() queue admission, not when a prior owner's
        // Promise continuation eventually drains this entry.
        state.assertSendOwner();
        const entry = Object.freeze(Object.create(null));
        authorizedWebSocketStreamWrites.set(entry, {
          socket,
          chunk,
        });
        return entry as any;
      },
      close: () => {
        if (!state.socket || !state.connected || !state.assertReleaseOwner) {
          throw createInvalidStateError();
        }
        state.assertReleaseOwner();
        state.writableCloseAdmitted = true;
      },
      abort: () => {
        if (!state.socket || !state.connected || !state.assertReleaseOwner) {
          throw createInvalidStateError();
        }
        state.assertReleaseOwner();
        state.writableAbortAdmitted = true;
      },
    });

    const streamSocket = createWebSocketForStream(
      urlString,
      options?.protocols,
      (bytesSent) => webSocketStreamHandleBytesSent.call(
        this,
        bytesSent,
        webSocketStreamInternalKey
      ),
      (byteSize, error) => webSocketStreamHandleSendFailure.call(
        this,
        byteSize,
        error,
        webSocketStreamInternalKey
      )
    );
    const socket = streamSocket.socket;
    state.socket = socket;
    state.assertStateOwner = streamSocket.assertStateOwner;
    state.assertSendOwner = streamSocket.assertSendOwner;
    state.assertReleaseOwner = streamSocket.assertReleaseOwner;
    state.constructing = false;
    if (!webSocketStreamSocketBinaryTypeSetter) {
      throw new TypeError('WebSocket binaryType setter is unavailable');
    }
    webSocketStreamSocketBinaryTypeSetter.call(socket, 'arraybuffer');
    webSocketStreamSocketSetIncomingFlowControl.call(socket, true);

    webSocketStreamSocketAddEventListener.call(socket, 'open', () => {
      // The open callback commits externally observable stream state. Bind it
      // to the native handle owner before changing settlement flags.
      state.assertReleaseOwner?.();
      state.connected = true;
      if (signal) {
        try {
          signal.removeEventListener('abort', abortListener);
        } catch (_removeAbortListenerError) {}
      }
      webSocketStreamResolveOpened.call(this, {
        readable: state.readable!,
        writable: state.writable!,
        protocol: webSocketStreamSocketProtocolGetter?.call(socket) || '',
        extensions: webSocketStreamSocketExtensionsGetter?.call(socket) || '',
      }, webSocketStreamInternalKey);
    });

    webSocketStreamSocketAddEventListener.call(socket, 'message', (event: any) => {
      if (!state.connected || !state.readableController || !state.assertStateOwner) {
        return;
      }
      state.assertStateOwner();
      let chunk: string | Uint8Array | undefined;
      if (typeof event.data === 'string') {
        chunk = event.data;
      } else if (event.data instanceof ArrayBuffer) {
        chunk = new Uint8Array(event.data);
      } else if (ArrayBuffer.isView(event.data)) {
        chunk = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
      }
      if (chunk !== undefined) {
        const entry = Object.freeze(Object.create(null));
        authorizedWebSocketStreamReads.set(entry, { socket, chunk });
        state.readableController.enqueue(entry as any);
      }
      webSocketStreamSyncReadableBackpressure.call(this, webSocketStreamInternalKey);
    });

    webSocketStreamSocketAddEventListener.call(socket, 'error', () => {
      // Close carries the structured outcome we care about.
    });

    webSocketStreamSocketAddEventListener.call(socket, 'close', (event: any) => {
      if (signal) {
        try {
          signal.removeEventListener('abort', abortListener);
        } catch (_removeAbortListenerError) {}
      }
      webSocketStreamHandleSocketClose.call(
        this,
        event.code,
        event.reason || '',
        !!event.wasClean,
        webSocketStreamInternalKey
      );
    });

    const abortListener = () => {
      if (state.connected) {
        return;
      }
      // The native close is also the strict owner check. A foreign principal
      // retaining the AbortSignal must not terminally settle this stream when
      // that check rejects.
      closeSocket(socket);
      const abortError = createAbortError();
      state.ignoredTerminal = true;
      webSocketStreamRejectOpened.call(this, abortError, webSocketStreamInternalKey);
      webSocketStreamRejectClosed.call(this, abortError, webSocketStreamInternalKey);
    };

    if (signal) {
      signal.addEventListener('abort', abortListener, { once: true });
    }
  }

  get url(): string {
    return ownedWebSocketStreamPrivateState(this).url;
  }

  get opened(): Promise<OpenedInfo> {
    return ownedWebSocketStreamPrivateState(this).openedDeferred.promise;
  }

  get closed(): Promise<ClosedInfo> {
    return ownedWebSocketStreamPrivateState(this).closedDeferred.promise;
  }

  close(info?: WebSocketCloseInfo): void {
    const state = webSocketStreamPrivateState(this);
    if (state.closedSettled || state.localCloseInitiated) {
      return;
    }
    if (!state.socket || !state.assertReleaseOwner) {
      throw createInvalidStateError();
    }
    // Validate authority before touching caller-controlled close option
    // getters. A denied retained-wrapper call must be observationally inert.
    state.assertReleaseOwner();
    const normalized = normalizeCloseArguments(info);
    void webSocketStreamInitiateClose.call(
      this,
      normalized.code,
      normalized.reason,
      webSocketStreamInternalKey
    );
  }

  _handleBytesSent(bytesSent: number, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    let remainingBytes = Number.isFinite(bytesSent) && bytesSent > 0 ? bytesSent : 0;
    for (const request of state.pendingWriteRequests) {
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
    webSocketStreamDrainResolvedWrites.call(this, webSocketStreamInternalKey);
  }

  _handleSendFailure(_byteSize: number, error: unknown, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    const request = state.pendingWriteRequests.shift();
    if (!request) {
      return;
    }
    webSocketStreamClearPendingWriteResolveTimer.call(this, webSocketStreamInternalKey);
    request.reject(error);
    webSocketStreamDrainResolvedWrites.call(this, webSocketStreamInternalKey);
  }

  _syncReadableBackpressure(internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (!state.socket || !state.connected || !state.readableController || !state.assertSendOwner) {
      return;
    }

    state.assertSendOwner();

    const desiredSize = state.readableController.desiredSize;
    if (desiredSize !== null && desiredSize <= 0) {
      webSocketStreamSocketPauseIncoming.call(state.socket);
      return;
    }

    webSocketStreamSocketResumeIncoming.call(state.socket);
  }

  _initiateClose(code?: number, reason?: string, internalKey?: unknown): Promise<void> | void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.closedSettled) {
      return;
    }

    if (!state.socket) {
      if (!state.closedSettled) {
        const abortError = createAbortError();
        webSocketStreamRejectOpened.call(this, abortError, webSocketStreamInternalKey);
        webSocketStreamRejectClosed.call(this, abortError, webSocketStreamInternalKey);
      }
      return;
    }

    if (!state.connected && !state.openedSettled) {
      // Authorize/release the native handle before changing any public stream
      // outcome. A rejected retained-wrapper close remains retryable.
      closeSocket(state.socket, code, reason);
      state.closedDuringHandshake = true;
      state.localCloseInitiated = true;
      const error = createWebSocketCloseError('WebSocketStream closed during handshake', 1005, '');
      state.ignoredTerminal = true;
      webSocketStreamRejectOpened.call(this, error, webSocketStreamInternalKey);
      webSocketStreamRejectClosed.call(this, error, webSocketStreamInternalKey);
      return Promise.resolve();
    }

    if (state.localCloseInitiated) {
      return state.closedDeferred.promise.then(() => undefined);
    }

    closeSocket(state.socket, code, reason);
    state.localCloseInitiated = true;
    return state.closedDeferred.promise.then(() => undefined);
  }

  _handleSocketClose(
    code: number,
    reason: string,
    wasClean: boolean,
    internalKey?: unknown
  ): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.ignoredTerminal) {
      return;
    }

    state.connected = false;

    const closeInfo = normalizeClosedInfo(code, reason);
    const closeError = createWebSocketCloseError(reason || 'WebSocket closed', closeInfo.closeCode, closeInfo.reason);
    const hadPendingWrites = state.pendingWriteRequests.length > 0;

    if (!state.openedSettled) {
      webSocketStreamRejectOpened.call(this, closeError, webSocketStreamInternalKey);
      webSocketStreamRejectClosed.call(this, closeError, webSocketStreamInternalKey);
      webSocketStreamRejectPendingWrites.call(this, createInvalidStateError(), webSocketStreamInternalKey);
      webSocketStreamErrorReadable.call(this, closeError, webSocketStreamInternalKey);
      webSocketStreamErrorWritable.call(this, closeError, webSocketStreamInternalKey);
      return;
    }

    if (!wasClean || closeInfo.closeCode === 1006) {
      webSocketStreamRejectClosed.call(this, closeError, webSocketStreamInternalKey);
      webSocketStreamErrorReadable.call(this, closeError, webSocketStreamInternalKey);
      if (hadPendingWrites) {
        const invalidStateError = webSocketStreamGetWritableInvalidStateError.call(
          this,
          webSocketStreamInternalKey
        );
        webSocketStreamRejectPendingWrites.call(this, invalidStateError, webSocketStreamInternalKey);
        webSocketStreamErrorWritable.call(this, invalidStateError, webSocketStreamInternalKey);
      } else {
        webSocketStreamErrorWritable.call(this, closeError, webSocketStreamInternalKey);
      }
      return;
    }

    if (hadPendingWrites) {
      const invalidStateError = webSocketStreamGetWritableInvalidStateError.call(
        this,
        webSocketStreamInternalKey
      );
      webSocketStreamRejectClosed.call(this, closeError, webSocketStreamInternalKey);
      webSocketStreamCloseReadable.call(this, webSocketStreamInternalKey);
      webSocketStreamRejectPendingWrites.call(this, invalidStateError, webSocketStreamInternalKey);
      webSocketStreamErrorWritable.call(this, invalidStateError, webSocketStreamInternalKey);
      return;
    }

    webSocketStreamResolveClosed.call(this, closeInfo, webSocketStreamInternalKey);
    webSocketStreamCloseReadable.call(this, webSocketStreamInternalKey);
    if (state.localCloseInitiated) {
      webSocketStreamFinishWritableClose.call(this, webSocketStreamInternalKey);
    } else {
      const invalidStateError = webSocketStreamGetWritableInvalidStateError.call(
        this,
        webSocketStreamInternalKey
      );
      webSocketStreamRejectPendingWrites.call(this, invalidStateError, webSocketStreamInternalKey);
      webSocketStreamErrorWritable.call(this, invalidStateError, webSocketStreamInternalKey);
    }
  }

  _getWritableInvalidStateError(internalKey?: unknown): DOMException {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (!state.writableInvalidStateError) {
      state.writableInvalidStateError = createInvalidStateError();
    }
    return state.writableInvalidStateError;
  }

  _rejectPendingWrites(reason: unknown, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    webSocketStreamClearPendingWriteResolveTimer.call(this, webSocketStreamInternalKey);
    while (state.pendingWriteRequests.length > 0) {
      const request = state.pendingWriteRequests.shift();
      request?.reject(reason);
    }
  }

  _drainResolvedWrites(internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    webSocketStreamClearPendingWriteResolveTimer.call(this, webSocketStreamInternalKey);

    while (state.pendingWriteRequests.length > 0) {
      const current = state.pendingWriteRequests[0];
      if (current.remaining > 0) {
        return;
      }

      const delay = current.readyAt - getMonotonicNow();
      if (delay > 0) {
        state.pendingWriteResolveTimer = setTimeout(() => {
          state.pendingWriteResolveTimer = null;
          webSocketStreamDrainResolvedWrites.call(this, webSocketStreamInternalKey);
        }, delay) as unknown as number;
        return;
      }

      state.pendingWriteRequests.shift();
      current.resolve();
    }
  }

  _clearPendingWriteResolveTimer(internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.pendingWriteResolveTimer === null) {
      return;
    }
    clearTimeout(state.pendingWriteResolveTimer);
    state.pendingWriteResolveTimer = null;
  }

  _resolveOpened(value: OpenedInfo, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.openedSettled) {
      return;
    }
    state.openedSettled = true;
    state.openedDeferred.resolve(value);
  }

  _rejectOpened(reason: unknown, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.openedSettled) {
      return;
    }
    state.openedSettled = true;
    state.openedDeferred.reject(reason);
  }

  _resolveClosed(value: ClosedInfo, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.closedSettled) {
      return;
    }
    state.closedSettled = true;
    state.closedDeferred.resolve(value);
  }

  _rejectClosed(reason: unknown, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.closedSettled) {
      return;
    }
    state.closedSettled = true;
    state.closedDeferred.reject(reason);
  }

  _closeReadable(internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (state.readableController) {
      try {
        state.readableController.close();
        return;
      } catch (_closeReadableErr) {}
    }
    if (!state.readable) {
      return;
    }
    (state.readable as any)._closeStream();
  }

  _errorReadable(reason: unknown, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (!state.readable) {
      return;
    }
    (state.readable as any)._errorStream(reason);
  }

  _finishWritableClose(internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (!state.writable) {
      return;
    }
    const writable = state.writable as any;
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

  _errorWritable(reason: unknown, internalKey?: unknown): void {
    assertWebSocketStreamInternal(internalKey);
    const state = webSocketStreamPrivateState(this);
    if (!state.writable) {
      return;
    }
    (state.writable as any)._errorStream(reason);
  }

  get [Symbol.toStringTag](): string {
    return 'WebSocketStream';
  }
}

// Capture all internal state-machine entry points once. The closure-private
// key rejects direct, saved, and base-prototype calls before they can mutate
// private settlement or write-accounting state.
const webSocketStreamHandleBytesSent = WebSocketStream.prototype._handleBytesSent;
const webSocketStreamHandleSendFailure = WebSocketStream.prototype._handleSendFailure;
const webSocketStreamSyncReadableBackpressure = WebSocketStream.prototype._syncReadableBackpressure;
const webSocketStreamInitiateClose = WebSocketStream.prototype._initiateClose;
const webSocketStreamHandleSocketClose = WebSocketStream.prototype._handleSocketClose;
const webSocketStreamGetWritableInvalidStateError = WebSocketStream.prototype._getWritableInvalidStateError;
const webSocketStreamRejectPendingWrites = WebSocketStream.prototype._rejectPendingWrites;
const webSocketStreamDrainResolvedWrites = WebSocketStream.prototype._drainResolvedWrites;
const webSocketStreamClearPendingWriteResolveTimer = WebSocketStream.prototype._clearPendingWriteResolveTimer;
const webSocketStreamResolveOpened = WebSocketStream.prototype._resolveOpened;
const webSocketStreamRejectOpened = WebSocketStream.prototype._rejectOpened;
const webSocketStreamResolveClosed = WebSocketStream.prototype._resolveClosed;
const webSocketStreamRejectClosed = WebSocketStream.prototype._rejectClosed;
const webSocketStreamCloseReadable = WebSocketStream.prototype._closeReadable;
const webSocketStreamErrorReadable = WebSocketStream.prototype._errorReadable;
const webSocketStreamFinishWritableClose = WebSocketStream.prototype._finishWritableClose;
const webSocketStreamErrorWritable = WebSocketStream.prototype._errorWritable;

export default WebSocketStream;
