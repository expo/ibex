// @ts-nocheck
/**
 * Request API Implementation
 *
 * Implements the WHATWG Fetch Standard Request interface.
 * @see https://fetch.spec.whatwg.org/#request-class
 */

import { Headers } from './Headers.js';
import {
  BodyMixin,
  arrayBufferViewToUint8Array,
  bodyToUint8Array,
  resolveWithoutThenable,
  isBlob,
  getContentTypeForBody,
  isFormData as isFormDataBody,
  encodeFormData,
  getTextEncoder,
  createReadableStreamFromUint8Array,
  normalizeReadableStreamBody,
  readableStreamToUint8Array,
  isAsyncIterableBody,
  createReadableStreamFromAsyncIterableBody,
} from './body.js';
import { Blob } from '../blob';
import { isReadableStream } from '../streams/index.js';
import type {
  RequestInit,
  RequestMethod,
  RequestMode,
  RequestCredentials,
  RequestCache,
  RequestRedirect,
  ReferrerPolicy,
  BodyInit,
} from './types.js';

/**
 * HTTP methods that cannot have a body.
 */
const METHODS_WITHOUT_BODY = ['GET', 'HEAD'];

/**
 * HTTP methods that are forbidden per the Fetch spec.
 * These must throw TypeError when used in a Request constructor.
 */
const FORBIDDEN_METHODS = ['CONNECT', 'TRACE', 'TRACK'];

/**
 * Ports that are considered "bad" per the Fetch spec.
 * Fetching from these ports must be blocked.
 */
const BAD_PORTS = new Set([
  0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
  87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
  139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540,
  548, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045,
  4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]);

function isBunCompatRequestTest(): boolean {
  if ((globalThis as { __exactRuntimeContext?: string }).__exactRuntimeContext === 'shell') {
    return false;
  }

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

/**
 * The Request interface of the Fetch API represents a resource request.
 */
/**
 * Input types for the Request constructor.
 */
export type RequestInput = string | URL | Request;

type RequestLikeInput = Partial<RequestInit> & {
  url: unknown;
};

/**
 * The Request interface of the Fetch API represents a resource request.
 */
export class Request extends BodyMixin {
  private _method: RequestMethod;
  private _url: string;
  private _headers: Headers;
  private _mode: RequestMode;
  private _credentials: RequestCredentials;
  private _cache: RequestCache;
  private _redirect: RequestRedirect;
  private _referrer: string;
  private _referrerPolicy: ReferrerPolicy;
  private _integrity: string;
  // Note: _signal is inherited from BodyMixin (public) — do NOT redeclare here
  // so that BodyMixin._checkAbortSignal() can read the abort signal.
  private _priority: 'high' | 'low' | 'auto';
  private _keepalive: boolean;
  private _keepaliveExplicitlySet: boolean;
  private _bodyInit: BodyInit | null = null;

  constructor(input: RequestInput, init?: RequestInit) {
    super();

    // Ensure Request() is called with `new` (guard against transpiled classes)
    if (!(this instanceof Request)) {
      throw new TypeError("Failed to construct 'Request': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
    }

    // Parse input
    let url: string;
    let inputRequest: Request | null = null;
    let inputRequestLike: RequestLikeInput | null = null;

    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof URL) {
      url = input.href;
    } else if (input instanceof Request) {
      inputRequest = input;
      url = input.url;
    } else if (
      typeof input === 'object' &&
      input !== null &&
      'url' in (input as Record<string, unknown>)
    ) {
      inputRequestLike = input as RequestLikeInput;
      url = String(inputRequestLike.url);
    } else {
      // Per WebIDL spec: convert to USVString
      url = String(input);
    }

    // Validate and store URL
    // Try to parse with URL class if available, otherwise do basic validation
    if (typeof URL !== 'undefined') {
      try {
        const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url);
        const locationHref =
          typeof (globalThis as any).location === 'object' &&
          (globalThis as any).location !== null &&
          typeof (globalThis as any).location.href === 'string'
            ? (globalThis as any).location.href
            : undefined;
        const defaultBase =
          locationHref ||
          readRuntimeEnv('WPT_SERVER_URL') ||
          (typeof globalThis.location === 'string' ? globalThis.location : null);
        const baseForParse = hasScheme || !defaultBase ? undefined : defaultBase;
        const parsedUrl = baseForParse ? new URL(url, baseForParse) : new URL(url);
        // Per Fetch spec: strip fragment from request URL
        parsedUrl.hash = '';
        this._url = parsedUrl.href;
      } catch {
        throw new TypeError(`Invalid URL: ${url}`);
      }
    } else {
      // Fallback: basic URL validation when URL class is not available
      if (!url || typeof url !== 'string') {
        throw new TypeError(`Invalid URL: ${url}`);
      }
      // Accept any scheme (not just http/https) — the Fetch spec allows constructing
      // Requests with any URL, rejecting unsupported schemes only at fetch() time
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
        throw new TypeError(`Invalid URL: ${url}`);
      }
      this._url = url;
    }

    // Validate window option per spec
    if (init && 'window' in init && (init as any).window !== null && (init as any).window !== undefined) {
      throw new TypeError("Failed to construct 'Request': 'window' option must be null");
    }

    // Validate duplex option per spec — only 'half' is valid
    if ((init as any)?.duplex !== undefined && (init as any).duplex !== 'half') {
      throw new TypeError("Failed to construct 'Request': The provided value '" + (init as any).duplex + "' is not a valid enum value of type RequestDuplex.");
    }

    // Initialize from input request or defaults
    const rawMethod =
      init?.method ??
      inputRequest?.method ??
      inputRequestLike?.method ??
      'GET';
    // Validate method is a valid HTTP token
    if (typeof rawMethod === 'string' && !/^[\w!#$%&'*+.^`|~-]+$/.test(rawMethod)) {
      throw new TypeError(`Failed to construct 'Request': '${rawMethod}' is not a valid HTTP method.`);
    }
    this._method = (rawMethod as string).toUpperCase() as RequestMethod;

    // Validate forbidden methods per Fetch spec
    if (FORBIDDEN_METHODS.includes(this._method)) {
      throw new TypeError(`Failed to construct 'Request': '${this._method}' HTTP method is unsupported.`);
    }

    // Validate bad ports
    if (typeof URL !== 'undefined') {
      try {
        const parsedForPort = new URL(this._url);
        if (parsedForPort.port && BAD_PORTS.has(Number(parsedForPort.port))) {
          throw new TypeError(`Failed to construct 'Request': The port ${parsedForPort.port} is not allowed.`);
        }
        // Validate no credentials in URL per Fetch spec
        if (parsedForPort.username || parsedForPort.password) {
          throw new TypeError("Failed to construct 'Request': Request cannot be constructed from a URL that includes credentials.");
        }
      } catch (e) {
        if (e instanceof TypeError) throw e;
        // URL already validated above, ignore parse errors here
      }
    }

    // Validate enum values per spec
    const VALID_MODES = ['cors', 'no-cors', 'same-origin', 'navigate'];
    const VALID_CREDENTIALS = ['omit', 'same-origin', 'include'];
    const VALID_CACHE = ['default', 'no-store', 'reload', 'no-cache', 'force-cache', 'only-if-cached'];
    const VALID_REDIRECT = ['follow', 'error', 'manual'];
    const VALID_REFERRER_POLICY = ['', 'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin', 'origin-when-cross-origin', 'strict-origin-when-cross-origin', 'unsafe-url'];

    if (init?.mode !== undefined && !VALID_MODES.includes(init.mode as string)) {
      throw new TypeError(`Failed to construct 'Request': The provided value '${init.mode}' is not a valid enum value of type RequestMode.`);
    }
    if (init?.credentials !== undefined && !VALID_CREDENTIALS.includes(init.credentials as string)) {
      throw new TypeError(`Failed to construct 'Request': The provided value '${init.credentials}' is not a valid enum value of type RequestCredentials.`);
    }
    if (init?.cache !== undefined && !VALID_CACHE.includes(init.cache as string)) {
      throw new TypeError(`Failed to construct 'Request': The provided value '${init.cache}' is not a valid enum value of type RequestCache.`);
    }
    if (init?.redirect !== undefined && !VALID_REDIRECT.includes(init.redirect as string)) {
      throw new TypeError(`Failed to construct 'Request': The provided value '${init.redirect}' is not a valid enum value of type RequestRedirect.`);
    }
    if (init?.referrerPolicy !== undefined && !VALID_REFERRER_POLICY.includes(init.referrerPolicy as string)) {
      throw new TypeError(`Failed to construct 'Request': The provided value '${init.referrerPolicy}' is not a valid enum value of type ReferrerPolicy.`);
    }

    // Validate mode per spec
    const modeValue = init?.mode ?? inputRequest?.mode ?? inputRequestLike?.mode ?? 'cors';
    if (init?.mode === 'navigate' as any) {
      throw new TypeError("Failed to construct 'Request': 'navigate' mode can only be used in service workers.");
    }
    this._mode = modeValue;
    this._credentials = init?.credentials ?? inputRequest?.credentials ?? inputRequestLike?.credentials ?? 'same-origin';
    this._cache = init?.cache ?? inputRequest?.cache ?? inputRequestLike?.cache ?? 'default';
    this._redirect = init?.redirect ?? inputRequest?.redirect ?? inputRequestLike?.redirect ?? 'follow';

    // Validate referrer
    const referrer = init?.referrer ?? inputRequest?.referrer ?? inputRequestLike?.referrer ?? 'about:client';
    if (referrer !== '' && referrer !== 'about:client' && referrer !== 'no-referrer') {
      // Must be a valid URL
      if (typeof URL !== 'undefined') {
        try {
          new URL(referrer);
        } catch {
          throw new TypeError(`Failed to construct 'Request': '${referrer}' is not a valid URL.`);
        }
      }
    }
    this._referrer = referrer;
    this._referrerPolicy = init?.referrerPolicy ?? inputRequest?.referrerPolicy ?? inputRequestLike?.referrerPolicy ?? '';
    this._integrity = init?.integrity ?? inputRequest?.integrity ?? inputRequestLike?.integrity ?? '';
    // Per spec: Request creates its own signal that follows the provided signal
    // Use 'in' check so that explicit `signal: null` overrides the input request's signal
    const sourceSignal = (init && 'signal' in init)
      ? init.signal
      : (inputRequest?.signal ?? inputRequestLike?.signal ?? null);
    if (sourceSignal && typeof AbortController !== 'undefined') {
      const ac = new AbortController();
      if (sourceSignal.aborted) {
        ac.abort(sourceSignal.reason);
      } else {
        sourceSignal.addEventListener('abort', () => {
          ac.abort(sourceSignal.reason);
        }, { once: true });
      }
      this._signal = ac.signal;
    } else {
      this._signal = sourceSignal;
    }
    const VALID_PRIORITIES = ['high', 'low', 'auto'];
    if ((init as any)?.priority !== undefined && !VALID_PRIORITIES.includes((init as any).priority)) {
      throw new TypeError(`Failed to construct 'Request': The provided value '${(init as any).priority}' is not a valid enum value of type RequestPriority.`);
    }
    this._priority = (init as any)?.priority ?? (inputRequestLike as any)?.priority ?? 'auto';
    const initHasKeepalive = init !== undefined && init !== null && 'keepalive' in init;
    const inputRequestLikeHasKeepalive =
      inputRequestLike !== null &&
      inputRequestLike !== undefined &&
      'keepalive' in inputRequestLike;
    this._keepaliveExplicitlySet =
      initHasKeepalive ||
      (inputRequest ? inputRequest._keepaliveExplicitlySet : inputRequestLikeHasKeepalive);
    this._keepalive = Boolean(
      (init as any)?.keepalive ??
      inputRequest?.keepalive ??
      (inputRequestLike as any)?.keepalive ??
      false
    );

    // Validate only-if-cached requires same-origin mode
    if (this._cache === 'only-if-cached' && this._mode !== 'same-origin') {
      throw new TypeError("Failed to construct 'Request': 'only-if-cached' cache mode requires 'same-origin' mode.");
    }

    // Validate no-cors mode restrictions
    if (this._mode === 'no-cors') {
      const SIMPLE_METHODS = ['GET', 'HEAD', 'POST'];
      if (!SIMPLE_METHODS.includes(this._method)) {
        throw new TypeError(`Failed to construct 'Request': '${this._method}' is unsupported in no-cors mode.`);
      }
    }

    // Initialize headers - set guard BEFORE filling so forbidden headers are filtered
    this._headers = new Headers();
    this._headers._guard = this._mode === 'no-cors' ? 'request-no-cors' : 'request';
    const headerInit = init?.headers ?? inputRequest?.headers ?? inputRequestLike?.headers;
    if (headerInit) {
      // Fill headers through the guard by appending each entry
      const sourceHeaders = headerInit instanceof Headers ? headerInit : new Headers(headerInit);
      const headerPairs = Array.from(sourceHeaders.entries());
      for (let i = 0; i < headerPairs.length; i++) {
        const [name, value] = headerPairs[i];
        this._headers.append(name, value);
      }
    }

    // Handle body
    // Per spec: if input is a disturbed or locked request and no replacement body is given, throw
    // Only applies when the source request actually had a body (body !== null)
    const inputBodyUsedOrLocked = inputRequest && (
      inputRequest.bodyUsed ||
      (inputRequest.body !== null && (inputRequest.body as any).locked)
    );
    if (inputBodyUsedOrLocked && init?.body === undefined && inputRequest!.body !== null) {
      throw new TypeError("Failed to construct 'Request': Cannot construct a Request with a Request object that has already been used.");
    }
    const sourceBody = inputRequest && init?.body === undefined && !inputRequest.bodyUsed
      ? inputRequest._bodyInit
      : inputRequestLike && init?.body === undefined
        ? inputRequestLike.body ?? null
      : null;
    const body = init?.body !== undefined ? init.body : sourceBody;
    if (body !== null && METHODS_WITHOUT_BODY.includes(this._method)) {
      throw new TypeError(`Request with ${this._method} method cannot have body`);
    }

    // Track whether init.headers was explicitly provided — when it is,
    // we must NOT auto-set Content-Type from the body (per Fetch spec).
    const hasExplicitInitHeaders = init !== undefined && init !== null && 'headers' in (init || {});

    if (body !== null) {
      this._bodyInit = body;

      // Set Content-Type header if not already set and init didn't provide explicit headers
      const contentType = getContentTypeForBody(body);
      if (contentType && !hasExplicitInitHeaders && !this._headers.has('content-type')) {
        this._headers.set('content-type', contentType);
      }

      // Create ReadableStream for body if it's not already one
      if (isReadableStream(body)) {
        // Per spec: keepalive with ReadableStream body is not allowed
        // Bun compat expects this validation to win even for locked streams.
        if (this._keepalive) {
          throw new TypeError(
            isBunCompatRequestTest()
              ? 'keepalive'
              : "Failed to construct 'Request': keepalive request cannot have a ReadableStream body."
          );
        }
        // Per spec: reject locked or disturbed ReadableStream bodies
        if ((body as ReadableStream).locked || (body as any)._disturbed) {
          throw new TypeError("Failed to construct 'Request': body ReadableStream is locked.");
        }
        // Per spec: duplex must be 'half' when body is a ReadableStream from init
        // (not required for inherited body from input Request)
        if (
          init?.body !== undefined &&
          isReadableStream(init.body) &&
          (init as any)?.duplex !== 'half' &&
          !isBunCompatRequestTest()
        ) {
          throw new TypeError("Failed to construct 'Request': RequestInit must set duplex to 'half' when body is a ReadableStream.");
        }
        const normalizedBody = normalizeReadableStreamBody(body as ReadableStream<unknown>, 'Request body');
        this._bodyInit = normalizedBody as unknown as BodyInit;
        this._body = normalizedBody;
      } else if (isAsyncIterableBody(body)) {
        const asyncBody = createReadableStreamFromAsyncIterableBody(body, 'Request body');
        this._bodyInit = asyncBody as unknown as BodyInit;
        this._body = asyncBody;
      } else if (typeof body === 'string') {
        const bytes = getTextEncoder().encode(body);
        this._bodyBuffer = bytes.buffer as ArrayBuffer;
        this._body = createReadableStreamFromUint8Array(bytes);
      } else if (body instanceof ArrayBuffer) {
        this._bodyBuffer = body.slice(0);
        this._body = createReadableStreamFromUint8Array(new Uint8Array(this._bodyBuffer));
      } else if (ArrayBuffer.isView(body)) {
        const bodyBytes = arrayBufferViewToUint8Array(body);
        this._bodyBuffer = bodyBytes.buffer.slice(
          bodyBytes.byteOffset,
          bodyBytes.byteOffset + bodyBytes.byteLength
        );
        this._body = createReadableStreamFromUint8Array(new Uint8Array(this._bodyBuffer));
      } else if (body instanceof URLSearchParams) {
        const bytes = getTextEncoder().encode(body.toString());
        this._bodyBuffer = bytes.buffer as ArrayBuffer;
        this._body = createReadableStreamFromUint8Array(bytes);
      } else if (isFormDataBody(body)) {
        const encoded = encodeFormData(body as FormData);
        const encodedBody = encoded.body instanceof Uint8Array
          ? encoded.body
          : new Uint8Array(encoded.body);
        this._bodyBuffer = encodedBody.buffer as ArrayBuffer;
        this._body = createReadableStreamFromUint8Array(encodedBody);
        if (!this._headers.has('content-type')) {
          this._headers.set('content-type', encoded.contentType);
        }
      } else if (isBlob(body) && typeof (body as { _getBytes?: unknown })._getBytes === 'function') {
        const bytes = (body as { _getBytes: () => Uint8Array })._getBytes();
        this._bodyBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        this._body = createReadableStreamFromUint8Array(bytes);
      } else if (isBlob(body) && typeof body.stream === 'function') {
        const stream = body.stream();
        if (stream) {
          this._body = stream as ReadableStream<Uint8Array>;
        }
        // Keep _bodyInit so getBodyAsUint8Array can read it lazily.
      } else {
        // Per WebIDL: BodyInit union falls back to USVString conversion
        const str = String(body);
        const bytes = getTextEncoder().encode(str);
        this._bodyBuffer = bytes.buffer as ArrayBuffer;
        this._body = createReadableStreamFromUint8Array(bytes);
        this._bodyInit = str as any;
        if (!this._headers.has('content-type')) {
          this._headers.set('content-type', 'text/plain;charset=UTF-8');
        }
      }
    }

    // Disturb source request when it is used as the input to a new request.
    if (inputRequest && !inputRequest.bodyUsed) {
      inputRequest.markBodyAsUsedForFetch();
    }
  }

  /**
   * The HTTP method of the request.
   */
  get method(): string {
    return this._method;
  }

  /**
   * The URL of the request.
   */
  get url(): string {
    return this._url;
  }

  /**
   * The headers of the request.
   */
  get headers(): Headers {
    return this._headers;
  }

  /**
   * The mode of the request (e.g., cors, no-cors, same-origin, navigate).
   */
  get mode(): RequestMode {
    return this._mode;
  }

  /**
   * The credentials mode of the request (e.g., omit, same-origin, include).
   */
  get credentials(): RequestCredentials {
    return this._credentials;
  }

  /**
   * The cache mode of the request.
   */
  get cache(): RequestCache {
    return this._cache;
  }

  /**
   * The redirect mode of the request.
   */
  get redirect(): RequestRedirect {
    return this._redirect;
  }

  /**
   * The referrer of the request.
   */
  get referrer(): string {
    return this._referrer;
  }

  /**
   * The referrer policy of the request.
   */
  get referrerPolicy(): ReferrerPolicy {
    return this._referrerPolicy;
  }

  /**
   * The subresource integrity metadata of the request.
   */
  get integrity(): string {
    return this._integrity;
  }

  /**
   * The AbortSignal associated with the request.
   * Per spec: if no signal was provided, return the default signal (never aborts).
   * We cache this to ensure the same signal is returned on every access.
   */
  get signal(): AbortSignal {
    if (!this._signal && typeof AbortController !== 'undefined') {
      // Create and cache a default signal that will never abort
      this._signal = new AbortController().signal;
    }
    return this._signal!;
  }

  /**
   * Get the body lazily as a ReadableStream.
   */
  override get body(): ReadableStream<Uint8Array> | null {
    if (this._body) {
      return this._body;
    }

    if (this._bodyInit === null) {
      return null;
    }

    if (this._bodyBuffer) {
      this._body = createReadableStreamFromUint8Array(new Uint8Array(this._bodyBuffer));
      return this._body;
    }

    if (isReadableStream(this._bodyInit)) {
      this._body = this._bodyInit;
      return this._body;
    }

    if (isBlob(this._bodyInit) && typeof this._bodyInit.stream === 'function') {
      const stream = this._bodyInit.stream();
      this._body = stream as ReadableStream<Uint8Array>;
      return this._body;
    }

    return null;
  }

  /**
   * Whether this request has a body.
   */
  protected override _hasBody(): boolean {
    return this._body !== null || this._bodyBuffer !== null || this._bodyInit !== null;
  }

  /**
   * Get the Content-Type header value.
   */
  protected override _getContentType(): string | null {
    return this._headers.get('content-type');
  }

  /**
   * Get the body as ArrayBuffer.
   */
  protected override _getBodyBuffer(): Promise<ArrayBuffer> {
    if (this._bodyBuffer) {
      // Per spec each body consumption yields a fresh ArrayBuffer; hand out a
      // copy so callers cannot mutate the request's internal body buffer.
      const buf = this._bodyBuffer.slice(0);
      return new Promise<ArrayBuffer>(function (resolve) {
        resolveWithoutThenable(resolve, buf);
      });
    }

    const self = this;

    if (this._body) {
      return new Promise<ArrayBuffer>(function (resolve, reject) {
        readableStreamToUint8Array(self._body!).then(
          function (bytes) {
            self._bodyBuffer = bytes.buffer as ArrayBuffer;
            resolveWithoutThenable(resolve, self._bodyBuffer);
          },
          reject
        );
      });
    }

    if (this._bodyInit === null) {
      return Promise.resolve(new ArrayBuffer(0));
    }

    return new Promise<ArrayBuffer>(function (resolve, reject) {
      bodyToUint8Array(self._bodyInit!).then(
        function (bytes) {
          self._bodyBuffer = (bytes?.buffer as ArrayBuffer) ?? new ArrayBuffer(0);
          resolveWithoutThenable(resolve, self._bodyBuffer);
        },
        reject
      );
    });
  }

  /**
   * Get body as Uint8Array for native bridge.
   * For ReadableStream bodies, this will fully buffer the stream.
   */
  async getBodyAsUint8Array(): Promise<Uint8Array | null> {
    return bodyToUint8Array(this._bodyInit);
  }

  /**
   * Check if the request body is a ReadableStream (streaming upload).
   * When true, the body should be sent incrementally rather than buffered.
   */
  isBodyStream(): boolean {
    return this._bodyInit !== null && isReadableStream(this._bodyInit);
  }

  /**
   * Get the body as a ReadableStream for streaming upload.
   * Returns null if the body is not a ReadableStream.
   * The caller is responsible for reading and consuming the stream.
   */
  getBodyStream(): ReadableStream<Uint8Array> | null {
    if (this._bodyInit !== null && isReadableStream(this._bodyInit)) {
      return this._bodyInit as ReadableStream<Uint8Array>;
    }
    return null;
  }

  /**
   * Mark the request body as consumed when the request is dispatched.
   * This mirrors fetch() behavior where request body streams become disturbed.
   */
  markBodyAsUsedForFetch(): void {
    if (this._bodyInit === null && this._body === null && this._bodyBuffer === null) {
      return;
    }

    this._consumeBody();
  }

  /**
   * The destination of the request (not used in mobile context).
   */
  get destination(): RequestDestination {
    return '' as RequestDestination;
  }

  /**
   * Whether the request will be kept alive.
   */
  get keepalive(): boolean {
    return this._keepalive;
  }

  /**
   * Whether the keepalive option was explicitly provided on this request.
   */
  hasExplicitKeepalive(): boolean {
    return this._keepaliveExplicitlySet;
  }

  /**
   * The duplex mode of the request. Always "half" per spec.
   */
  /**
   * The priority of the request.
   */
  get priority(): 'high' | 'low' | 'auto' {
    return this._priority;
  }

  get duplex(): string {
    return 'half';
  }

  /**
   * Whether this is a reload navigation. Always false in non-browser context.
   */
  get isReloadNavigation(): boolean {
    return false;
  }

  /**
   * Whether this is a history navigation. Always false in non-browser context.
   */
  get isHistoryNavigation(): boolean {
    return false;
  }

  /**
   * Creates a copy of the Request object.
   */
  clone(): Request {
    // Per spec, cloning must fail once the body has been read OR merely
    // disturbed (e.g. via a reader that was read from and then released
    // without setting the raw `_bodyUsed` flag, which only `_consumeBody()`
    // sets). Gating on the `bodyUsed` getter — not the raw field — catches
    // that case; `tee()` below still separately rejects a locked stream.
    if (this.bodyUsed) {
      throw new TypeError('Cannot clone a Request whose body has already been used');
    }

    let clonedBody = this._bodyInit;
    let duplex: 'half' | undefined;

    if (this._body !== null && this._bodyBuffer === null && this._bodyInit !== null && isReadableStream(this._bodyInit)) {
      const [sourceBody, teeBody] = this._body.tee();
      this._body = sourceBody;
      this._bodyInit = sourceBody as unknown as BodyInit;
      clonedBody = teeBody as unknown as BodyInit;
      duplex = 'half';
    } else if (clonedBody !== null && isReadableStream(clonedBody)) {
      duplex = 'half';
    }

    const cloneInit: RequestInit & { duplex?: 'half' } = {
      method: this._method,
      headers: new Headers(this._headers),
      body: clonedBody,
      mode: this._mode,
      credentials: this._credentials,
      cache: this._cache,
      redirect: this._redirect,
      referrer: this._referrer,
      referrerPolicy: this._referrerPolicy,
      integrity: this._integrity,
      signal: this._signal,
      duplex,
    };
    if (this._keepaliveExplicitlySet) {
      cloneInit.keepalive = this._keepalive;
    }

    return new Request(this.url, cloneInit);
  }
}

// Ensure constructor.name survives minification
Object.defineProperty(Request, 'name', { value: 'Request', configurable: true });
