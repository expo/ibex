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

function getBaseUrl(): string | undefined {
  const currentLocation = (globalThis as any).location;
  if (currentLocation && typeof currentLocation.href === 'string') {
    return currentLocation.href;
  }
  return undefined;
}

function networkConnectCapabilityForWebSocketUrl(parsedUrl: URL): string {
  const host = parsedUrl.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  const port = parsedUrl.port || (parsedUrl.protocol === 'wss:' ? '443' : '80');
  return `${Capabilities.NETWORK_CONNECT}:${host}:${port}`;
}

function isSecureContextForWebSocket(): boolean {
  const currentLocation = (globalThis as any).location;
  return !!currentLocation && currentLocation.protocol === 'https:';
}

function isBlobLike(value: unknown): value is Blob {
  return !!value &&
    typeof value === 'object' &&
    typeof (value as any).arrayBuffer === 'function' &&
    typeof (value as any).size === 'number';
}

function isValidWebSocketSubprotocol(value: string): boolean {
  return /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(value);
}

function assertWebSocketBrand(value: unknown): WebSocket {
  if (!(value instanceof WebSocket)) {
    throw new TypeError('Illegal invocation');
  }
  return value;
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

  // Internal state (using _prefix for Hermes compatibility - no #private fields)
  _url: string = '';
  _protocol: string = '';
  _extensions: string = '';
  _readyState: number = CONNECTING;
  _bufferedAmount: number = 0;
  _binaryType: BinaryType = 'blob';
  _socketId: number = -1;
  _closeEventPending: boolean = false;
  _incomingPaused: boolean = false;
  _incomingFlowControlled: boolean = false;

  // Send queue to maintain ordering for native sends and async Blob conversion.
  _sendQueue: Array<() => Promise<void>> = [];
  _isSendingQueue = false;
  _pendingSendAcks: Array<{
    remaining: number;
    resolve: () => void;
  }> = [];
  _eventQueue: Array<() => void> = [];
  _eventQueueScheduled = false;

  // Event handlers
  _onopen: ((this: WebSocket, ev: Event) => any) | null = null;
  _onmessage: ((this: WebSocket, ev: MessageEvent) => any) | null = null;
  _onerror: ((this: WebSocket, ev: Event) => any) | null = null;
  _onclose: ((this: WebSocket, ev: CloseEvent) => any) | null = null;

  constructor(url: string | URL, protocols?: string | string[]) {
    super();

    // Normalize URL
    const urlString = url instanceof URL ? url.href : String(url);

    if (urlString.includes('#')) {
      throw new DOMException(
        "The URL contains a fragment identifier, which is not allowed in WebSocket URLs.",
        'SyntaxError'
      );
    }

    // Validate URL
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlString, getBaseUrl());
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

    this._url = parsedUrl.href;

    // Try to connect via native module
    const nativeWebSocket = getNativeModule('websocket');
    if (nativeWebSocket) {
      this._connectNative(nativeWebSocket, protocolList);
    } else {
      // Fallback: simulate connection failure after a delay
      this._simulateConnection();
    }
  }

  get readyState(): number {
    return assertWebSocketBrand(this)._readyState;
  }

  get url(): string {
    return assertWebSocketBrand(this)._url;
  }

  get protocol(): string {
    return assertWebSocketBrand(this)._protocol;
  }

  get extensions(): string {
    return assertWebSocketBrand(this)._extensions;
  }

  get bufferedAmount(): number {
    return assertWebSocketBrand(this)._bufferedAmount;
  }

  get binaryType(): BinaryType {
    return assertWebSocketBrand(this)._binaryType;
  }

  set binaryType(value: BinaryType) {
    const socket = assertWebSocketBrand(this);
    if (value !== 'blob' && value !== 'arraybuffer') {
      return;
    }
    socket._binaryType = value;
  }

  get onopen(): ((this: WebSocket, ev: Event) => any) | null {
    return assertWebSocketBrand(this)._onopen;
  }

  set onopen(value: ((this: WebSocket, ev: Event) => any) | null) {
    assertWebSocketBrand(this)._onopen = typeof value === 'function' ? value : null;
  }

  get onmessage(): ((this: WebSocket, ev: MessageEvent) => any) | null {
    return assertWebSocketBrand(this)._onmessage;
  }

  set onmessage(value: ((this: WebSocket, ev: MessageEvent) => any) | null) {
    assertWebSocketBrand(this)._onmessage = typeof value === 'function' ? value : null;
  }

  get onerror(): ((this: WebSocket, ev: Event) => any) | null {
    return assertWebSocketBrand(this)._onerror;
  }

  set onerror(value: ((this: WebSocket, ev: Event) => any) | null) {
    assertWebSocketBrand(this)._onerror = typeof value === 'function' ? value : null;
  }

  get onclose(): ((this: WebSocket, ev: CloseEvent) => any) | null {
    return assertWebSocketBrand(this)._onclose;
  }

  set onclose(value: ((this: WebSocket, ev: CloseEvent) => any) | null) {
    assertWebSocketBrand(this)._onclose = typeof value === 'function' ? value : null;
  }

  _enqueueEventTask(task: () => void): void {
    this._eventQueue.push(task);

    if (this._eventQueueScheduled) {
      return;
    }

    this._eventQueueScheduled = true;
    setTimeout(() => {
      this._eventQueueScheduled = false;
      while (this._eventQueue.length > 0) {
        const next = this._eventQueue.shift();
        if (next) {
          next();
        }
      }
    }, 0);
  }

  /**
   * Send data through the WebSocket connection.
   */
  send(data: string | ArrayBuffer | ArrayBufferView | Blob): void {
    const socket = assertWebSocketBrand(this);
    if (arguments.length === 0) {
      throw new TypeError(
        "Failed to execute 'send' on 'WebSocket': 1 argument required, but only 0 present."
      );
    }

    if (socket._readyState === CONNECTING) {
      throw new DOMException(
        'WebSocket is still in CONNECTING state',
        'InvalidStateError'
      );
    }

    if (socket._readyState !== OPEN) {
      // Silently fail if not open (per spec)
      return;
    }

    const nativeWebSocket = getNativeModule('websocket');
    if (!nativeWebSocket || socket._socketId === -1) {
      return;
    }

    // Handle Blob specially - queue it to maintain ordering
    if (isBlobLike(data)) {
      const byteSize = data.size;
      socket._bufferedAmount += byteSize;
      socket._queueSend(async () => {
        if (socket._readyState !== OPEN) return;
        const buffer = await data.arrayBuffer();
        if (socket._readyState !== OPEN) return;
        await socket._sendNative(new Uint8Array(buffer), byteSize);
      });
      return;
    }

    // Convert data to sendable format
    let sendData: string | Uint8Array;
    let byteSize: number;

    if (typeof data === 'string') {
      sendData = data;
      byteSize = new TextEncoder().encode(data).byteLength;
      socket._bufferedAmount += byteSize;
    } else if (data instanceof ArrayBuffer) {
      sendData = new Uint8Array(data);
      byteSize = data.byteLength;
      socket._bufferedAmount += byteSize;
    } else if (ArrayBuffer.isView(data)) {
      sendData = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      byteSize = data.byteLength;
      socket._bufferedAmount += byteSize;
    } else {
      sendData = String(data);
      byteSize = new TextEncoder().encode(sendData).byteLength;
      socket._bufferedAmount += byteSize;
    }

    socket._queueSend(async () => {
      if (socket._readyState !== OPEN) return;
      await socket._sendNative(sendData, byteSize);
    });
  }

  /**
   * Queue a send operation to maintain ordering.
   */
  async _queueSend(sendFn: () => Promise<void>): Promise<void> {
    this._sendQueue.push(sendFn);

    if (this._isSendingQueue) {
      return;
    }

    this._isSendingQueue = true;

    while (this._sendQueue.length > 0) {
      const fn = this._sendQueue.shift()!;
      try {
        await fn();
      } catch (e) {
        // Silently ignore send errors per WebSocket spec
      }
    }

    this._isSendingQueue = false;
  }

  _sendNative(data: string | Uint8Array, byteSize: number): Promise<void> {
    const nativeWebSocket = getNativeModule('websocket');
    if (!nativeWebSocket || this._socketId === -1 || this._readyState !== OPEN) {
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      if (byteSize === 0) {
        try {
          nativeWebSocket.send(this._socketId, data);
        } catch (_sendZeroErr) {}
        resolve();
        return;
      }

      this._pendingSendAcks.push({
        remaining: byteSize,
        resolve,
      });

      try {
        nativeWebSocket.send(this._socketId, data);
      } catch (_sendErr) {
        this._bufferedAmount = Math.max(0, this._bufferedAmount - byteSize);
        const ack = this._pendingSendAcks.pop();
        ack?.resolve();
      }
    });
  }

  _resolvePendingSendAcks(): void {
    while (this._pendingSendAcks.length > 0) {
      const ack = this._pendingSendAcks.shift();
      ack?.resolve();
    }
  }

  _pauseIncoming(): void {
    if (this._incomingPaused || this._socketId === -1) {
      return;
    }
    const nativeWebSocket = getNativeModule('websocket');
    nativeWebSocket?.pause?.(this._socketId);
    this._incomingPaused = true;
  }

  _resumeIncoming(): void {
    if (!this._incomingPaused || this._socketId === -1) {
      return;
    }
    const nativeWebSocket = getNativeModule('websocket');
    nativeWebSocket?.resume?.(this._socketId);
    this._incomingPaused = false;
  }

  _setIncomingFlowControl(enabled: boolean): void {
    const nextEnabled = !!enabled;
    this._incomingFlowControlled = nextEnabled;
    if (this._socketId === -1) {
      return;
    }
    const nativeWebSocket = getNativeModule('websocket');
    nativeWebSocket?.setFlowControlled?.(this._socketId, nextEnabled);
  }

  /**
   * Close the WebSocket connection.
   */
  close(code?: number, reason?: string): void {
    const socket = assertWebSocketBrand(this);
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

    if (socket._readyState === CLOSING || socket._readyState === CLOSED) {
      return;
    }

    socket._readyState = CLOSING;

    const nativeWebSocket = getNativeModule('websocket');
    if (nativeWebSocket && socket._socketId !== -1) {
      nativeWebSocket.close(socket._socketId, code ?? CLOSE_NO_STATUS, reason ?? '');
    } else {
      // Simulate close asynchronously (native would also be async)
      queueMicrotask(() => {
        socket._handleCloseInternal(code ?? CLOSE_NO_STATUS, reason ?? '', true);
      });
    }
  }

  /**
   * Connect using native WebSocket module.
   */
  _connectNative(nativeWebSocket: any, protocols: string[]): void {
    // The C++ bridge calls methods via JSI fn.call() which doesn't bind `this`,
    // so we pass a wrapper with arrow functions that capture `this` correctly.
    const self = this;
    const bridge = {
      _handleOpen: (protocol: string, extensions: string) => self._handleOpen(protocol, extensions),
      _handleMessage: (data: string | ArrayBuffer) => self._handleMessage(data),
      _handleClose: (code: number, reason: string, wasClean: boolean) => self._handleClose(code, reason, wasClean),
      _handleError: (message: string) => self._handleError(message),
      _handleBytesSent: (bytesSent: number) => self._handleBytesSent(bytesSent),
    };
    this._socketId = nativeWebSocket.create(this.url, protocols, bridge);
  }

  /**
   * Simulate connection for testing without native module.
   */
  _simulateConnection(): void {
    // Simulate failed connection after a short delay
    queueMicrotask(() => {
      setTimeout(() => {
        this._handleErrorInternal('WebSocket connection failed: no native module');
        this._handleCloseInternal(CLOSE_ABNORMAL, '', false);
      }, 100);
    });
  }

  /**
   * Handle incoming message (called by native bridge).
   */
  _handleMessage(data: string | ArrayBuffer): void {
    if (this._readyState === CLOSED) {
      return;
    }

    if (this._incomingFlowControlled) {
      this._incomingPaused = true;
    }

    this._enqueueEventTask(() => {
      if (this._readyState === CLOSED) {
        return;
      }

      let messageData: string | ArrayBuffer | Blob;

      if (typeof data === 'string') {
        messageData = data;
      } else if (this._binaryType === 'arraybuffer') {
        messageData = data;
      } else {
        const BlobCtor = ((globalThis as any).Blob || Blob) as typeof Blob;
        messageData = new BlobCtor([data]);
      }

      const event = new MessageEvent('message', {
        data: messageData,
        origin: new URL(this.url).origin,
      });

      if (this._onmessage) {
        this._onmessage.call(this, event);
      }
      this.dispatchEvent(event);
    });
  }

  /**
   * Handle connection open (called by native bridge).
   */
  _handleOpen(protocol: string, extensions: string): void {
    if (this._readyState !== CONNECTING) {
      return;
    }

    this._readyState = OPEN;
    this._protocol = protocol || '';
    this._extensions = extensions || '';
    this._enqueueEventTask(() => {
      const event = new Event('open');

      if (this._onopen) {
        this._onopen.call(this, event);
      }
      this.dispatchEvent(event);
    });
  }

  /**
   * Handle error (internal).
   */
  _handleErrorInternal(message: string): void {
    this._enqueueEventTask(() => {
      const event = new ErrorEvent('error', {
        message,
      });

      if (this._onerror) {
        this._onerror.call(this, event);
      }
      this.dispatchEvent(event);
    });
  }

  /**
   * Handle connection close (internal).
   */
  _handleCloseInternal(code: number, reason: string, wasClean: boolean): void {
    if (this._readyState === CLOSED || this._closeEventPending) {
      return;
    }

    this._readyState = CLOSING;
    this._closeEventPending = true;

    setTimeout(() => {
      this._enqueueEventTask(() => {
        if (this._readyState === CLOSED) {
          return;
        }

        this._readyState = CLOSED;
        this._closeEventPending = false;
        this._bufferedAmount = 0;
        this._incomingPaused = false;
        this._incomingFlowControlled = false;
        this._resolvePendingSendAcks();

        const event = new CloseEvent('close', {
          code,
          reason,
          wasClean,
        });

        if (this._onclose) {
          this._onclose.call(this, event);
        }
        this.dispatchEvent(event);
      });
    }, 0);
  }

  /**
   * Public method for native bridge to call on close.
   */
  _handleClose(code: number, reason: string, wasClean: boolean): void {
    this._handleCloseInternal(code, reason, wasClean);
  }

  /**
   * Public method for native bridge to call on error.
   */
  _handleError(message: string): void {
    this._handleErrorInternal(message);
  }

  /**
   * Public method for native bridge to call when data has been sent.
   * This allows bufferedAmount to decrease as data is transmitted.
   * @param bytesSent Number of bytes that have been sent to the network
   */
  _handleBytesSent(bytesSent: number): void {
    this._bufferedAmount = Math.max(0, this._bufferedAmount - bytesSent);

    let remainingBytes = bytesSent;
    while (remainingBytes > 0 && this._pendingSendAcks.length > 0) {
      const current = this._pendingSendAcks[0];
      if (remainingBytes >= current.remaining) {
        remainingBytes -= current.remaining;
        this._pendingSendAcks.shift();
        current.resolve();
      } else {
        current.remaining -= remainingBytes;
        remainingBytes = 0;
      }
    }
  }

  get [Symbol.toStringTag](): string {
    return 'WebSocket';
  }
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
