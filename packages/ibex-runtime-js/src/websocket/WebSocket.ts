// @ts-nocheck
/**
 * WebSocket implementation for Ibex runtime
 *
 * Implements the WHATWG WebSocket API.
 * @see https://websockets.spec.whatwg.org/
 *
 * NOTE: Uses _prefix private state for compatibility with the embedded runtimes
 * we support, including Hermes-based builds.
 */

import { EventTarget } from '../events/EventTarget';
import { Event } from '../events/Event';
import { MessageEvent } from '../events/MessageEvent';
import { CloseEvent } from '../events/CloseEvent';
import { ErrorEvent } from '../events/ErrorEvent';
import { getNativeModule } from '../native/NativeModules';
import { Blob } from '../blob/Blob';
import { requireCapability, Capabilities } from '../security/Capabilities';
import { URL as ExactURL } from '../url/URL';

// WebSocket ready states
const CONNECTING = 0;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

// Standard WebSocket close codes
// @see https://www.rfc-editor.org/rfc/rfc6455#section-7.4.1
const CLOSE_NORMAL = 1000;
const CLOSE_GOING_AWAY = 1001;
const CLOSE_PROTOCOL_ERROR = 1002;
const CLOSE_UNSUPPORTED_DATA = 1003;
// 1004 is reserved
const CLOSE_NO_STATUS = 1005;     // Synthetic - must not be sent on wire
const CLOSE_ABNORMAL = 1006;      // Synthetic - must not be sent on wire
const CLOSE_INVALID_PAYLOAD = 1007;
const CLOSE_POLICY_VIOLATION = 1008;
const CLOSE_TOO_BIG = 1009;
const CLOSE_MANDATORY_EXT = 1010;
const CLOSE_INTERNAL_ERROR = 1011;
// 1012-1014 are reserved
const CLOSE_TLS_HANDSHAKE = 1015; // Synthetic - must not be sent on wire

interface WebSocketPrivateState {
  url: string;
  protocol: string;
  extensions: string;
  readyState: number;
  bufferedAmount: number;
  binaryType: BinaryType;
  socketId: number;
  closeEventPending: boolean;
  incomingPaused: boolean;
  incomingFlowControlled: boolean;
  sendQueue: Array<() => Promise<void>>;
  sendQueueOffset: number;
  isSendingQueue: boolean;
  pendingSendAcks: Array<{
    remaining: number;
    resolve: () => void;
  }>;
  pendingSendAckOffset: number;
  eventQueue: Array<() => void>;
  eventQueueOffset: number;
  eventQueueScheduled: boolean;
  onopen: ((this: WebSocket, ev: Event) => any) | null;
  onmessage: ((this: WebSocket, ev: MessageEvent) => any) | null;
  onerror: ((this: WebSocket, ev: Event) => any) | null;
  onclose: ((this: WebSocket, ev: CloseEvent) => any) | null;
  bytesSentHook: ((bytesSent: number) => void) | null;
  sendFailureHook: ((byteSize: number, error: unknown) => void) | null;
  native: WebSocketNativeBindings | null;
  ownerStamp: unknown;
}

interface WebSocketNativeBindings {
  createOwner(): unknown;
  checkStateOwner(owner: unknown): void;
  create(url: string, protocols?: string[], instance?: any): number;
  checkOwner(id: number): void;
  checkReleaseOwner(id: number): void;
  send(id: number, data: string | Uint8Array): void;
  close(id: number, code?: number, reason?: string): void;
  pause?: (id: number) => void;
  resume?: (id: number) => void;
  setFlowControlled?: (id: number, enabled: boolean) => void;
}

// A retained wrapper can cross package/principal boundaries. Keep the native
// selector and every queue/state-machine field out of the wrapper so property
// writes cannot redirect or poison the owner's connection. Hermes supports
// WeakMap even though it does not support the private-field syntax we avoid
// here.
const webSocketPrivateStates = new WeakMap<object, WebSocketPrivateState>();
const webSocketInternalKey = {};

function newWebSocketPrivateState(): WebSocketPrivateState {
  return {
    url: '',
    protocol: '',
    extensions: '',
    readyState: CONNECTING,
    bufferedAmount: 0,
    binaryType: 'blob',
    socketId: -1,
    closeEventPending: false,
    incomingPaused: false,
    incomingFlowControlled: false,
    sendQueue: [],
    sendQueueOffset: 0,
    isSendingQueue: false,
    pendingSendAcks: [],
    pendingSendAckOffset: 0,
    eventQueue: [],
    eventQueueOffset: 0,
    eventQueueScheduled: false,
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
    bytesSentHook: null,
    sendFailureHook: null,
    native: null,
    ownerStamp: null,
  };
}

function webSocketPrivateState(value: unknown): WebSocketPrivateState {
  const state = value !== null && (typeof value === 'object' || typeof value === 'function')
    ? webSocketPrivateStates.get(value as object)
    : undefined;
  if (!state) {
    throw new TypeError('Illegal invocation');
  }
  return state;
}

function assertWebSocketInternal(key: unknown): void {
  if (key !== webSocketInternalKey) {
    throw new TypeError('Illegal invocation');
  }
}

function ownedWebSocketPrivateState(value: unknown): WebSocketPrivateState {
  const state = webSocketPrivateState(value);
  if (state.native) {
    state.native.checkStateOwner(state.ownerStamp);
  }
  return state;
}

function assertWebSocketEventTargetOwner(target: object): void {
  void ownedWebSocketPrivateState(target);
}

function assertNativeWebSocketSendOwner(nativeWebSocket: any, socketId: number): void {
  if (typeof nativeWebSocket?.checkOwner !== 'function') {
    const error = new Error('WebSocket native owner preflight is unavailable');
    (error as any).code = 'ERR_WEBSOCKET_OWNER_PREFLIGHT_UNAVAILABLE';
    throw error;
  }
  nativeWebSocket.checkOwner(socketId);
}

function captureNativeWebSocketBindings(nativeWebSocket: any): WebSocketNativeBindings {
  const capturedMethods: Record<string, any> = Object.create(null);
  for (const method of ['createOwner', 'checkStateOwner', 'create', 'checkOwner', 'checkReleaseOwner', 'send', 'close', 'pause', 'resume', 'setFlowControlled'] as const) {
    capturedMethods[method] = nativeWebSocket?.[method];
  }
  for (const method of ['createOwner', 'checkStateOwner', 'create', 'checkOwner', 'checkReleaseOwner', 'send', 'close'] as const) {
    if (typeof capturedMethods[method] !== 'function') {
      const error = new Error(`WebSocket native ${method} binding is unavailable`);
      (error as any).code = method === 'checkOwner'
        ? 'ERR_WEBSOCKET_OWNER_PREFLIGHT_UNAVAILABLE'
        : 'ERR_WEBSOCKET_NATIVE_BINDING_UNAVAILABLE';
      throw error;
    }
  }

  // Bind once while constructing the owner wrapper. The registry setters and
  // module objects are compatibility exports, so looking methods up again at
  // send time would let a retained foreign caller swap in a no-op preflight
  // and receive this socket's closure-private selector.
  const bindings: WebSocketNativeBindings = {
    createOwner: capturedMethods.createOwner.bind(nativeWebSocket),
    checkStateOwner: capturedMethods.checkStateOwner.bind(nativeWebSocket),
    create: capturedMethods.create.bind(nativeWebSocket),
    checkOwner: capturedMethods.checkOwner.bind(nativeWebSocket),
    checkReleaseOwner: capturedMethods.checkReleaseOwner.bind(nativeWebSocket),
    send: capturedMethods.send.bind(nativeWebSocket),
    close: capturedMethods.close.bind(nativeWebSocket),
  };
  for (const method of ['pause', 'resume', 'setFlowControlled'] as const) {
    if (typeof capturedMethods[method] === 'function') {
      (bindings as any)[method] = capturedMethods[method].bind(nativeWebSocket);
    }
  }
  return Object.freeze(bindings);
}

function getBaseUrl(): string | undefined {
  const currentLocation = (globalThis as any).location;
  if (currentLocation && typeof currentLocation.href === 'string') {
    return currentLocation.href;
  }
  return undefined;
}

function networkConnectCapabilityForWebSocketUrl(parsedUrl: ExactURL): string {
  const host = parsedUrl.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  const port = parsedUrl.port || (parsedUrl.protocol === 'wss:' ? '443' : '80');
  return `${Capabilities.NETWORK_CONNECT}:${host}:${port}`;
}

function isSecureContextForWebSocket(): boolean {
  const currentLocation = (globalThis as any).location;
  return !!currentLocation && currentLocation.protocol === 'https:';
}

const exactBlobSizeGetter = Object.getOwnPropertyDescriptor(Blob.prototype, 'size')?.get;
const platformBlobPrototype = typeof (globalThis as any).Blob === 'function'
  ? (globalThis as any).Blob.prototype
  : null;
const platformBlobSizeGetter = platformBlobPrototype && platformBlobPrototype !== Blob.prototype
  ? Object.getOwnPropertyDescriptor(platformBlobPrototype, 'size')?.get
  : null;
const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength'
)?.get;

/**
 * Brand-check a supported Blob with its captured base getter. A duck-typed
 * `{ size, arrayBuffer }` object is ordinary WebSocket string data; trusting
 * its claimed size would let a tiny buffered reservation hide an arbitrarily
 * large asynchronous allocation/send.
 */
export function getSupportedWebSocketBlobSize(value: unknown): number | null {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) {
    return null;
  }
  for (const getter of [exactBlobSizeGetter, platformBlobSizeGetter]) {
    if (typeof getter !== 'function') {
      continue;
    }
    try {
      const size = getter.call(value);
      if (typeof size === 'number' && Number.isSafeInteger(size) && size >= 0) {
        return size;
      }
    } catch (_brandError) {
      // Try the other supported Blob implementation. Its base getter is the
      // brand check; Symbol.toStringTag and caller-supplied size getters are
      // deliberately ignored.
    }
  }
  return null;
}

function createBlobSizeMismatchError(expected: number, actual: number): TypeError {
  const error = new TypeError(
    `WebSocket Blob size mismatch: reserved ${expected} bytes but resolved ${actual}`
  );
  (error as any).code = 'ERR_WEBSOCKET_BLOB_SIZE_MISMATCH';
  return error;
}

function getBrandedArrayBufferByteLength(value: unknown): number | null {
  if (typeof arrayBufferByteLengthGetter !== 'function') {
    return null;
  }
  try {
    return arrayBufferByteLengthGetter.call(value);
  } catch (_brandError) {
    return null;
  }
}

function isValidWebSocketSubprotocol(value: string): boolean {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value);
}

/**
 * WebSocket provides full-duplex communication over a single TCP connection.
 */
export class WebSocket extends EventTarget {
  // Ready state constants
  static readonly CONNECTING = CONNECTING;
  static readonly OPEN = OPEN;
  static readonly CLOSING = CLOSING;
  static readonly CLOSED = CLOSED;

  constructor(url: string | URL, protocols?: string | string[]) {
    super(assertWebSocketEventTargetOwner);
    const state = newWebSocketPrivateState();
    webSocketPrivateStates.set(this, state);

    // Normalize URL
    const urlString = String(url);

    if (urlString.includes('#')) {
      throw new DOMException(
        "The URL contains a fragment identifier, which is not allowed in WebSocket URLs.",
        'SyntaxError'
      );
    }

    // Validate URL
    let parsedUrl: ExactURL;
    try {
      const baseUrl = getBaseUrl();
      // Absolute URLs are base-independent. Avoid routing them through the
      // bootstrap URL implementation's relative-resolution path: on Hermes
      // that path can truncate `ws://host:port/` to `host:port`, handing the
      // native security boundary an endpoint with no scheme.
      parsedUrl = /^[A-Za-z][A-Za-z0-9+.-]*:/.test(urlString) || baseUrl === undefined
        ? new ExactURL(urlString)
        : new ExactURL(urlString, baseUrl);
    } catch {
      throw new DOMException('Invalid URL', 'SyntaxError');
    }

    if (parsedUrl.protocol === 'http:') {
      parsedUrl.protocol = 'ws:';
    } else if (parsedUrl.protocol === 'https:') {
      parsedUrl.protocol = 'wss:';
    } else if (parsedUrl.protocol !== 'ws:' && parsedUrl.protocol !== 'wss:') {
      throw new DOMException(
        `The URL's scheme must be either 'ws' or 'wss'. '${parsedUrl.protocol}' is not allowed.`,
        'SyntaxError'
      );
    }

    // Per spec, a WebSocket URL must not include credentials; proceeding
    // would silently send userinfo on the wire.
    // https://websockets.spec.whatwg.org/#dom-websocket-websocket
    if (parsedUrl.username !== '' || parsedUrl.password !== '') {
      throw new DOMException(
        'The URL contains embedded credentials, which is not allowed in WebSocket URLs.',
        'SyntaxError'
      );
    }

    if (isSecureContextForWebSocket() && parsedUrl.protocol === 'ws:') {
      throw new DOMException(
        'Cannot construct an insecure WebSocket from a secure context.',
        'SecurityError'
      );
    }

    // @ref LLP 0013#policy — generated policy can grant individual network
    // endpoints, so the JS guard mirrors the native WebSocket boundary.
    requireCapability(networkConnectCapabilityForWebSocketUrl(parsedUrl));

    // Normalize protocols
    const protocolList = protocols !== undefined
      ? Array.isArray(protocols) ? protocols : [protocols]
      : [];

    // Validate protocols
    const seen = new Set<string>();
    for (const protocol of protocolList) {
      if (protocol === '') {
        throw new DOMException('Invalid protocol: empty string', 'SyntaxError');
      }
      const normalizedProtocol = String(protocol);
      const seenKey = normalizedProtocol.toLowerCase();
      if (seen.has(seenKey)) {
        throw new DOMException(`Invalid protocol: duplicate '${protocol}'`, 'SyntaxError');
      }
      if (!isValidWebSocketSubprotocol(normalizedProtocol)) {
        throw new DOMException(`Invalid protocol: '${protocol}'`, 'SyntaxError');
      }
      seen.add(seenKey);
    }

    state.url = parsedUrl.href;

    // Try to connect via native module
    const nativeWebSocketModule = getNativeModule('websocket');
    if (nativeWebSocketModule) {
      state.native = captureNativeWebSocketBindings(nativeWebSocketModule);
      state.ownerStamp = state.native.createOwner();
      webSocketConnectNative.call(this, state.native, protocolList, webSocketInternalKey);
    } else {
      // Fallback: simulate connection failure after a delay
      webSocketSimulateConnection.call(this, webSocketInternalKey);
    }
  }

  get readyState(): number {
    return ownedWebSocketPrivateState(this).readyState;
  }

  get url(): string {
    return ownedWebSocketPrivateState(this).url;
  }

  get protocol(): string {
    return ownedWebSocketPrivateState(this).protocol;
  }

  get extensions(): string {
    return ownedWebSocketPrivateState(this).extensions;
  }

  get bufferedAmount(): number {
    return ownedWebSocketPrivateState(this).bufferedAmount;
  }

  get binaryType(): BinaryType {
    return ownedWebSocketPrivateState(this).binaryType;
  }

  set binaryType(value: BinaryType) {
    const socket = this;
    if (value !== 'blob' && value !== 'arraybuffer') {
      return;
    }
    ownedWebSocketPrivateState(socket).binaryType = value;
  }

  get onopen(): ((this: WebSocket, ev: Event) => any) | null {
    return ownedWebSocketPrivateState(this).onopen;
  }

  set onopen(value: ((this: WebSocket, ev: Event) => any) | null) {
    ownedWebSocketPrivateState(this).onopen = typeof value === 'function' ? value : null;
  }

  get onmessage(): ((this: WebSocket, ev: MessageEvent) => any) | null {
    return ownedWebSocketPrivateState(this).onmessage;
  }

  set onmessage(value: ((this: WebSocket, ev: MessageEvent) => any) | null) {
    ownedWebSocketPrivateState(this).onmessage = typeof value === 'function' ? value : null;
  }

  get onerror(): ((this: WebSocket, ev: Event) => any) | null {
    return ownedWebSocketPrivateState(this).onerror;
  }

  set onerror(value: ((this: WebSocket, ev: Event) => any) | null) {
    ownedWebSocketPrivateState(this).onerror = typeof value === 'function' ? value : null;
  }

  get onclose(): ((this: WebSocket, ev: CloseEvent) => any) | null {
    return ownedWebSocketPrivateState(this).onclose;
  }

  set onclose(value: ((this: WebSocket, ev: CloseEvent) => any) | null) {
    ownedWebSocketPrivateState(this).onclose = typeof value === 'function' ? value : null;
  }

  _enqueueEventTask(task: () => void, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    state.eventQueue.push(task);

    if (state.eventQueueScheduled) {
      return;
    }

    state.eventQueueScheduled = true;
    setTimeout(() => {
      state.eventQueueScheduled = false;
      while (state.eventQueueOffset < state.eventQueue.length) {
        const next = state.eventQueue[state.eventQueueOffset++];
        if (next) {
          try {
            next();
          } catch (error) {
            // A throwing task must not abort the drain: later queued events
            // (e.g. the 'close' behind a 'message') would be dropped forever,
            // leaving readyState stuck at CLOSING (ENG-23133).
            console.error('Error in WebSocket event handler:', error);
          }
        }
      }
      state.eventQueue.length = 0;
      state.eventQueueOffset = 0;
    }, 0);
  }

  /**
   * Invoke an onX attribute handler with EventTarget's per-listener error
   * semantics: report the exception and continue, so a throwing handler
   * cannot break event delivery for the rest of the task (ENG-23133).
   */
  _callEventHandler(
    handler: ((this: WebSocket, ev: any) => any) | null,
    event: any,
    internalKey?: unknown
  ): void {
    assertWebSocketInternal(internalKey);
    if (!handler) {
      return;
    }
    try {
      handler.call(this, event);
    } catch (error) {
      console.error('Error in event listener:', error);
    }
  }

  /**
   * Send data through the WebSocket connection.
   */
  send(data: string | ArrayBuffer | ArrayBufferView | Blob): void {
    const socket = this;
    const state = ownedWebSocketPrivateState(socket);
    if (arguments.length === 0) {
      throw new TypeError(
        "Failed to execute 'send' on 'WebSocket': 1 argument required, but only 0 present."
      );
    }

    if (state.readyState === CONNECTING) {
      throw new DOMException(
        'WebSocket is still in CONNECTING state',
        'InvalidStateError'
      );
    }

    if (state.readyState !== OPEN) {
      // Silently fail if not open (per spec)
      return;
    }

    const nativeWebSocket = state.native;
    if (!nativeWebSocket || state.socketId === -1) {
      return;
    }

    // @ref LLP 0021#decision-staging-and-principal-semantics — queue
    // admission is the first visible stage. Authenticate the live caller
    // before reading caller-controlled Blob-like properties, reserving
    // bufferedAmount, or appending work that an owner-attributed async queue
    // continuation could otherwise send later.
    assertNativeWebSocketSendOwner(nativeWebSocket, state.socketId);

    // Handle genuine supported Blobs specially. Start the conversion under
    // the authenticated caller now, then queue only its result to preserve
    // wire ordering. Instance overrides are allowed for compatibility, but
    // their result must match the base-getter reservation exactly.
    const blobByteSize = getSupportedWebSocketBlobSize(data);
    if (blobByteSize !== null) {
      const arrayBufferMethod = (data as any).arrayBuffer;
      if (typeof arrayBufferMethod !== 'function') {
        throw new TypeError('WebSocket Blob arrayBuffer method is unavailable');
      }
      const byteSize = blobByteSize;
      const bufferPromise = Promise.resolve(arrayBufferMethod.call(data));
      state.bufferedAmount += byteSize;
      webSocketQueueSend.call(socket, async () => {
        let handedToNative = false;
        try {
          if (state.readyState !== OPEN) return;
          const buffer = await bufferPromise;
          const actualByteLength = getBrandedArrayBufferByteLength(buffer);
          if (actualByteLength === null) {
            throw new TypeError('WebSocket Blob arrayBuffer() must resolve to an ArrayBuffer');
          }
          if (actualByteLength !== byteSize) {
            throw createBlobSizeMismatchError(byteSize, actualByteLength);
          }
          if (state.readyState !== OPEN) return;
          await webSocketSendNative.call(
            socket,
            new Uint8Array(buffer as ArrayBuffer),
            byteSize,
            webSocketInternalKey
          );
          handedToNative = true;
        } catch (error) {
          if (!handedToNative) {
            state.bufferedAmount = Math.max(0, state.bufferedAmount - byteSize);
            state.sendFailureHook?.(byteSize, error);
          }
          throw error;
        }
      }, webSocketInternalKey);
      return;
    }

    // Convert data to sendable format
    let sendData: string | Uint8Array;
    let byteSize: number;

    if (typeof data === 'string') {
      sendData = data;
      byteSize = new TextEncoder().encode(data).byteLength;
      state.bufferedAmount += byteSize;
    } else if (data instanceof ArrayBuffer) {
      sendData = new Uint8Array(data);
      byteSize = data.byteLength;
      state.bufferedAmount += byteSize;
    } else if (ArrayBuffer.isView(data)) {
      sendData = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      byteSize = data.byteLength;
      state.bufferedAmount += byteSize;
    } else {
      sendData = String(data);
      byteSize = new TextEncoder().encode(sendData).byteLength;
      state.bufferedAmount += byteSize;
    }

    webSocketQueueSend.call(socket, async () => {
      if (state.readyState !== OPEN) return;
      await webSocketSendNative.call(socket, sendData, byteSize, webSocketInternalKey);
    }, webSocketInternalKey);
  }

  /**
   * Queue a send operation to maintain ordering.
   */
  async _queueSend(sendFn: () => Promise<void>, internalKey?: unknown): Promise<void> {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    state.sendQueue.push(sendFn);

    if (state.isSendingQueue) {
      return;
    }

    state.isSendingQueue = true;

    while (state.sendQueueOffset < state.sendQueue.length) {
      const fn = state.sendQueue[state.sendQueueOffset++]!;
      try {
        await fn();
      } catch (e) {
        // Silently ignore send errors per WebSocket spec
      }
    }

    state.sendQueue.length = 0;
    state.sendQueueOffset = 0;
    state.isSendingQueue = false;
  }

  _sendNative(data: string | Uint8Array, byteSize: number, internalKey?: unknown): Promise<void> {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    const nativeWebSocket = state.native;
    if (!nativeWebSocket || state.socketId === -1 || state.readyState !== OPEN) {
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      if (byteSize === 0) {
        try {
          nativeWebSocket.send(state.socketId, data);
          // The native layer has no positive byte acknowledgement for an
          // empty frame, so explicitly release a WebSocketStream zero-byte
          // write after the synchronous native admission succeeds.
          state.bytesSentHook?.(0);
        } catch (sendZeroError) {
          state.sendFailureHook?.(0, sendZeroError);
        }
        resolve();
        return;
      }

      state.pendingSendAcks.push({
        remaining: byteSize,
        resolve,
      });

      try {
        nativeWebSocket.send(state.socketId, data);
      } catch (sendError) {
        state.bufferedAmount = Math.max(0, state.bufferedAmount - byteSize);
        const ack = state.pendingSendAcks.pop();
        ack?.resolve();
        state.sendFailureHook?.(byteSize, sendError);
      }
    });
  }

  _resolvePendingSendAcks(internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    while (state.pendingSendAckOffset < state.pendingSendAcks.length) {
      const ack = state.pendingSendAcks[state.pendingSendAckOffset++];
      ack?.resolve();
    }
    state.pendingSendAcks.length = 0;
    state.pendingSendAckOffset = 0;
  }

  _pauseIncoming(): void {
    const state = webSocketPrivateState(this);
    if (state.incomingPaused || state.socketId === -1) {
      return;
    }
    const nativeWebSocket = state.native;
    if (!nativeWebSocket) {
      return;
    }
    assertNativeWebSocketSendOwner(nativeWebSocket, state.socketId);
    nativeWebSocket?.pause?.(state.socketId);
    state.incomingPaused = true;
  }

  _resumeIncoming(): void {
    const state = webSocketPrivateState(this);
    if (!state.incomingPaused || state.socketId === -1) {
      return;
    }
    const nativeWebSocket = state.native;
    if (!nativeWebSocket) {
      return;
    }
    assertNativeWebSocketSendOwner(nativeWebSocket, state.socketId);
    nativeWebSocket?.resume?.(state.socketId);
    state.incomingPaused = false;
  }

  _setIncomingFlowControl(enabled: boolean): void {
    const state = webSocketPrivateState(this);
    const nextEnabled = !!enabled;
    if (state.socketId === -1) {
      throw new DOMException('WebSocket is not open', 'InvalidStateError');
    }
    const nativeWebSocket = state.native;
    if (!nativeWebSocket) {
      throw new DOMException('WebSocket is not open', 'InvalidStateError');
    }
    assertNativeWebSocketSendOwner(nativeWebSocket, state.socketId);
    nativeWebSocket?.setFlowControlled?.(state.socketId, nextEnabled);
    state.incomingFlowControlled = nextEnabled;
  }

  /**
   * Close the WebSocket connection.
   */
  close(code?: number, reason?: string): void {
    const socket = this;
    const state = ownedWebSocketPrivateState(socket);
    if (reason !== undefined && code === undefined) {
      throw new DOMException(
        'Close reason must not be provided without a close code.',
        'InvalidAccessError'
      );
    }

    if (code !== undefined) {
      if (typeof code !== 'number' || !Number.isInteger(code)) {
        throw new DOMException(
          `Invalid close code: ${String(code)}. Must be an integer.`,
          'InvalidAccessError'
        );
      }
      if (code !== 1000 && (code < 3000 || code > 4999)) {
        throw new DOMException(
          `Invalid close code: ${code}. Must be 1000 or in range 3000-4999.`,
          'InvalidAccessError'
        );
      }
    }

    if (reason !== undefined) {
      // Reason must be valid UTF-8 and <= 123 bytes
      const encoded = new TextEncoder().encode(reason);
      if (encoded.byteLength > 123) {
        throw new DOMException(
          'Close reason is too long (max 123 bytes)',
          'SyntaxError'
        );
      }
    }

    if (state.readyState === CLOSING || state.readyState === CLOSED) {
      return;
    }

    const nativeWebSocket = state.native;
    if (nativeWebSocket && state.socketId !== -1) {
      // Native close is the strict owner check. Do not advance the JS state
      // before it succeeds: a foreign principal may retain this wrapper, and
      // its rejected close must leave the owner able to retry.
      nativeWebSocket.close(state.socketId, code ?? CLOSE_NO_STATUS, reason ?? '');
      if (state.readyState !== CLOSED) {
        state.readyState = CLOSING;
      }
    } else {
      state.readyState = CLOSING;
      // Simulate close asynchronously (native would also be async)
      queueMicrotask(() => {
        webSocketHandleCloseInternal.call(
          socket,
          code ?? CLOSE_NO_STATUS,
          reason ?? '',
          true,
          webSocketInternalKey
        );
      });
    }
  }

  /**
   * Connect using native WebSocket module.
   */
  _connectNative(nativeWebSocket: any, protocols: string[], internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    // The C++ bridge calls methods via JSI fn.call() which doesn't bind `this`,
    // so we pass a wrapper with arrow functions that capture `this` correctly.
    const self = this;
    const bridge = {
      _handleOpen: (protocol: string, extensions: string) =>
        webSocketHandleOpen.call(self, protocol, extensions, webSocketInternalKey),
      _handleMessage: (data: string | ArrayBuffer) =>
        webSocketHandleMessage.call(self, data, webSocketInternalKey),
      _handleClose: (code: number, reason: string, wasClean: boolean) =>
        webSocketHandleClose.call(self, code, reason, wasClean, webSocketInternalKey),
      _handleError: (message: string) =>
        webSocketHandleError.call(self, message, webSocketInternalKey),
      _handleBytesSent: (bytesSent: number) =>
        webSocketHandleBytesSent.call(self, bytesSent, webSocketInternalKey),
    };
    const state = webSocketPrivateState(this);
    state.socketId = nativeWebSocket.create(state.url, protocols, bridge);
  }

  /**
   * Simulate connection for testing without native module.
   */
  _simulateConnection(internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    // Simulate failed connection after a short delay
    queueMicrotask(() => {
      setTimeout(() => {
        webSocketHandleErrorInternal.call(
          this,
          'WebSocket connection failed: no native module',
          webSocketInternalKey
        );
        webSocketHandleCloseInternal.call(
          this,
          CLOSE_ABNORMAL,
          '',
          false,
          webSocketInternalKey
        );
      }, 100);
    });
  }

  /**
   * Handle incoming message (called by native bridge).
   */
  _handleMessage(data: string | ArrayBuffer, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    if (state.readyState !== OPEN) {
      return;
    }

    if (state.incomingFlowControlled) {
      state.incomingPaused = true;
    }

    webSocketEnqueueEventTask.call(this, () => {
      // A message accepted while OPEN stays ahead of a subsequently queued
      // close task. close handling moves readyState to CLOSING immediately, so
      // requiring OPEN here would silently discard that already-admitted
      // message before the event queue can preserve wire order.
      if (state.readyState === CLOSED) {
        return;
      }

      let messageData: string | ArrayBuffer | Blob;

      if (typeof data === 'string') {
        messageData = data;
      } else if (state.binaryType === 'arraybuffer') {
        messageData = data;
      } else {
        const BlobCtor = ((globalThis as any).Blob || Blob) as typeof Blob;
        messageData = new BlobCtor([data]);
      }

      const event = new MessageEvent('message', {
        data: messageData,
        origin: new URL(state.url).origin,
      });

      webSocketCallEventHandler.call(this, state.onmessage, event, webSocketInternalKey);
      webSocketDispatchEvent.call(this, event);
    }, webSocketInternalKey);
  }

  /**
   * Handle connection open (called by native bridge).
   */
  _handleOpen(protocol: string, extensions: string, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    if (state.readyState !== CONNECTING) {
      return;
    }

    state.readyState = OPEN;
    state.protocol = protocol || '';
    state.extensions = extensions || '';
    webSocketEnqueueEventTask.call(this, () => {
      const event = new Event('open');

      webSocketCallEventHandler.call(this, state.onopen, event, webSocketInternalKey);
      webSocketDispatchEvent.call(this, event);
    }, webSocketInternalKey);
  }

  /**
   * Handle error (internal).
   */
  _handleErrorInternal(message: string, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    webSocketEnqueueEventTask.call(this, () => {
      const event = new ErrorEvent('error', {
        message,
      });

      webSocketCallEventHandler.call(this, state.onerror, event, webSocketInternalKey);
      webSocketDispatchEvent.call(this, event);
    }, webSocketInternalKey);
  }

  /**
   * Handle connection close (internal).
   */
  _handleCloseInternal(
    code: number,
    reason: string,
    wasClean: boolean,
    internalKey?: unknown
  ): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    if (state.readyState === CLOSED || state.closeEventPending) {
      return;
    }

    state.readyState = CLOSING;
    state.closeEventPending = true;

    setTimeout(() => {
      webSocketEnqueueEventTask.call(this, () => {
        if (state.readyState === CLOSED) {
          return;
        }

        state.readyState = CLOSED;
        state.closeEventPending = false;
        state.bufferedAmount = 0;
        state.incomingPaused = false;
        state.incomingFlowControlled = false;
        webSocketResolvePendingSendAcks.call(this, webSocketInternalKey);

        const event = new CloseEvent('close', {
          code,
          reason,
          wasClean,
        });

        webSocketCallEventHandler.call(this, state.onclose, event, webSocketInternalKey);
        webSocketDispatchEvent.call(this, event);
      }, webSocketInternalKey);
    }, 0);
  }

  /**
   * Public method for native bridge to call on close.
   */
  _handleClose(code: number, reason: string, wasClean: boolean, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    webSocketHandleCloseInternal.call(this, code, reason, wasClean, webSocketInternalKey);
  }

  /**
   * Public method for native bridge to call on error.
   */
  _handleError(message: string, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    webSocketHandleErrorInternal.call(this, message, webSocketInternalKey);
  }

  /**
   * Public method for native bridge to call when data has been sent.
   * This allows bufferedAmount to decrease as data is transmitted.
   * @param bytesSent Number of bytes that have been sent to the network
   */
  _handleBytesSent(bytesSent: number, internalKey?: unknown): void {
    assertWebSocketInternal(internalKey);
    const state = webSocketPrivateState(this);
    state.bufferedAmount = Math.max(0, state.bufferedAmount - bytesSent);

    let remainingBytes = bytesSent;
    while (remainingBytes > 0 && state.pendingSendAckOffset < state.pendingSendAcks.length) {
      const current = state.pendingSendAcks[state.pendingSendAckOffset];
      if (remainingBytes >= current.remaining) {
        remainingBytes -= current.remaining;
        state.pendingSendAckOffset++;
        current.resolve();
      } else {
        current.remaining -= remainingBytes;
        remainingBytes = 0;
      }
    }
    if (state.pendingSendAckOffset === state.pendingSendAcks.length) {
      state.pendingSendAcks.length = 0;
      state.pendingSendAckOffset = 0;
    } else if (state.pendingSendAckOffset > 64 && state.pendingSendAckOffset * 2 >= state.pendingSendAcks.length) {
      state.pendingSendAcks.splice(0, state.pendingSendAckOffset);
      state.pendingSendAckOffset = 0;
    }

    state.bytesSentHook?.(bytesSent);
  }

  get [Symbol.toStringTag](): string {
    return 'WebSocket';
  }
}

// Capture every internal method once, before application code can replace a
// prototype property. Calls also carry the closure-private key, so invoking an
// underscore method on a retained wrapper cannot drive its state machine.
const webSocketEnqueueEventTask = WebSocket.prototype._enqueueEventTask;
const webSocketCallEventHandler = WebSocket.prototype._callEventHandler;
const webSocketQueueSend = WebSocket.prototype._queueSend;
const webSocketSendNative = WebSocket.prototype._sendNative;
const webSocketResolvePendingSendAcks = WebSocket.prototype._resolvePendingSendAcks;
const webSocketConnectNative = WebSocket.prototype._connectNative;
const webSocketSimulateConnection = WebSocket.prototype._simulateConnection;
const webSocketHandleMessage = WebSocket.prototype._handleMessage;
const webSocketHandleOpen = WebSocket.prototype._handleOpen;
const webSocketHandleErrorInternal = WebSocket.prototype._handleErrorInternal;
const webSocketHandleCloseInternal = WebSocket.prototype._handleCloseInternal;
const webSocketHandleClose = WebSocket.prototype._handleClose;
const webSocketHandleError = WebSocket.prototype._handleError;
const webSocketHandleBytesSent = WebSocket.prototype._handleBytesSent;
const webSocketDispatchEvent = EventTarget.prototype.dispatchEvent;

/**
 * Internal construction path for WebSocketStream. The hook is installed in
 * closure-private state and can only affect the new socket returned here; it
 * does not expose a mutator for an already-retained WebSocket.
 */
export function createWebSocketForStream(
  url: string | URL,
  protocols: string[] | undefined,
  bytesSentHook: (bytesSent: number) => void,
  sendFailureHook: (byteSize: number, error: unknown) => void
): {
  socket: WebSocket;
  assertStateOwner: () => void;
  assertSendOwner: () => void;
  assertReleaseOwner: () => void;
} {
  const socket = new WebSocket(url, protocols);
  const state = webSocketPrivateState(socket);
  state.bytesSentHook = bytesSentHook;
  state.sendFailureHook = sendFailureHook;
  return {
    socket,
    // Metadata and inbound bytes belong to the wrapper's creating principal,
    // but do not require a still-live positive send grant or an OPEN handle.
    // The owner stamp therefore remains usable for pending opened/closed
    // promises and post-close buffered reads.
    assertStateOwner: () => {
      void ownedWebSocketPrivateState(socket);
    },
    // WebSocketStream's generic WritableStream has its own deferred queue.
    // Give that adapter a closure-bound admission check without exposing the
    // selector or the internal state-machine key on the retained socket.
    assertSendOwner: () => {
      const state = ownedWebSocketPrivateState(socket);
      if (state.readyState !== OPEN || state.socketId === -1) {
        throw new DOMException('WebSocket is not open', 'InvalidStateError');
      }
      const nativeWebSocket = state.native;
      if (!nativeWebSocket) {
        throw new DOMException('WebSocket is not open', 'InvalidStateError');
      }
      assertNativeWebSocketSendOwner(nativeWebSocket, state.socketId);
    },
    assertReleaseOwner: () => {
      const state = ownedWebSocketPrivateState(socket);
      if (
        state.readyState === CLOSING ||
        state.readyState === CLOSED ||
        state.socketId === -1 ||
        !state.native
      ) {
        throw new DOMException('WebSocket is not open', 'InvalidStateError');
      }
      state.native.checkReleaseOwner(state.socketId);
    },
  };
}

Object.defineProperty(WebSocket, 'length', {
  value: 1,
  configurable: true,
});
Object.defineProperty(WebSocket.prototype.close, 'length', {
  value: 0,
  configurable: true,
});

function nameAccessor(
  descriptor: PropertyDescriptor | undefined,
  propertyName: string
): PropertyDescriptor | undefined {
  if (!descriptor) {
    return descriptor;
  }
  if (typeof descriptor.get === 'function') {
    Object.defineProperty(descriptor.get, 'name', {
      value: `get ${propertyName}`,
      configurable: true,
    });
  }
  if (typeof descriptor.set === 'function') {
    Object.defineProperty(descriptor.set, 'name', {
      value: `set ${propertyName}`,
      configurable: true,
    });
  }
  return descriptor;
}

const urlDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'url'), 'url')!;
const readyStateDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'readyState'), 'readyState')!;
const bufferedAmountDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'bufferedAmount'), 'bufferedAmount')!;
const onopenDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onopen'), 'onopen')!;
const onerrorDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onerror'), 'onerror')!;
const oncloseDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onclose'), 'onclose')!;
const extensionsDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'extensions'), 'extensions')!;
const protocolDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'protocol'), 'protocol')!;
const onmessageDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onmessage'), 'onmessage')!;
const binaryTypeDescriptor = nameAccessor(Object.getOwnPropertyDescriptor(WebSocket.prototype, 'binaryType'), 'binaryType')!;

Object.defineProperties(WebSocket, {
  CONNECTING: { value: CONNECTING, writable: false, enumerable: true, configurable: false },
  OPEN: { value: OPEN, writable: false, enumerable: true, configurable: false },
  CLOSING: { value: CLOSING, writable: false, enumerable: true, configurable: false },
  CLOSED: { value: CLOSED, writable: false, enumerable: true, configurable: false },
});

Object.defineProperties(WebSocket.prototype, {
  CONNECTING: { value: CONNECTING, writable: false, enumerable: true, configurable: false },
  OPEN: { value: OPEN, writable: false, enumerable: true, configurable: false },
  CLOSING: { value: CLOSING, writable: false, enumerable: true, configurable: false },
  CLOSED: { value: CLOSED, writable: false, enumerable: true, configurable: false },
  url: { get: urlDescriptor.get, enumerable: true, configurable: true },
  readyState: { get: readyStateDescriptor.get, enumerable: true, configurable: true },
  bufferedAmount: { get: bufferedAmountDescriptor.get, enumerable: true, configurable: true },
  onopen: {
    get: onopenDescriptor.get,
    set: onopenDescriptor.set,
    enumerable: true,
    configurable: true,
  },
  onerror: {
    get: onerrorDescriptor.get,
    set: onerrorDescriptor.set,
    enumerable: true,
    configurable: true,
  },
  onclose: {
    get: oncloseDescriptor.get,
    set: oncloseDescriptor.set,
    enumerable: true,
    configurable: true,
  },
  extensions: { get: extensionsDescriptor.get, enumerable: true, configurable: true },
  protocol: { get: protocolDescriptor.get, enumerable: true, configurable: true },
  close: { value: WebSocket.prototype.close, writable: true, enumerable: true, configurable: true },
  onmessage: {
    get: onmessageDescriptor.get,
    set: onmessageDescriptor.set,
    enumerable: true,
    configurable: true,
  },
  binaryType: {
    get: binaryTypeDescriptor.get,
    set: binaryTypeDescriptor.set,
    enumerable: true,
    configurable: true,
  },
  send: { value: WebSocket.prototype.send, writable: true, enumerable: true, configurable: true },
});

Object.setPrototypeOf(WebSocket.prototype, EventTarget.prototype);
Object.setPrototypeOf(WebSocket, EventTarget);

export type BinaryType = 'blob' | 'arraybuffer';

export default WebSocket;
