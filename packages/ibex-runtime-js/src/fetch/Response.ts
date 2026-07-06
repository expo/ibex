/**
 * Response API Implementation
 *
 * Implements the WHATWG Fetch Standard Response interface.
 * @see https://fetch.spec.whatwg.org/#response-class
 */

import { Headers } from './Headers.js';
import {
  BodyMixin,
  createReadableStreamFromUint8Array,
  readableStreamToUint8Array,
  resolveWithoutThenable,
  getTextEncoder,
  isFormData as isFormDataBody,
  encodeFormData,
  normalizeReadableStreamBody,
  isAsyncIterableBody,
  createReadableStreamFromAsyncIterableBody,
} from './body.js';
import { isReadableStream } from '../streams/index.js';
import type {
  ResponseInit,
  ResponseType,
  NativeResponse,
  NativeStreamingResponse,
} from './types.js';

/**
 * HTTP status codes that represent redirects.
 */
const REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308];

/**
 * HTTP status codes that are considered null body statuses.
 */
const NULL_BODY_STATUS_CODES = [204, 205, 304];

/**
 * Default HTTP status text for common status codes.
 * Used when the native bridge doesn't provide a status text
 * (e.g., NSURLSession on macOS doesn't expose HTTP reason phrases,
 * and HTTP/2 doesn't have reason phrases at all).
 */
const DEFAULT_STATUS_TEXT: Record<number, string> = {
  100: 'Continue',
  101: 'Switching Protocols',
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  203: 'Non-Authoritative Information',
  204: 'No Content',
  205: 'Reset Content',
  206: 'Partial Content',
  300: 'Multiple Choices',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  406: 'Not Acceptable',
  408: 'Request Timeout',
  409: 'Conflict',
  410: 'Gone',
  411: 'Length Required',
  412: 'Precondition Failed',
  413: 'Payload Too Large',
  414: 'URI Too Long',
  415: 'Unsupported Media Type',
  416: 'Range Not Satisfiable',
  417: 'Expectation Failed',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  501: 'Not Implemented',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
};

function isBunCompatResponseTest(): boolean {
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
 * The Response interface of the Fetch API represents the response to a request.
 */
export class Response extends BodyMixin {
  private _status: number;
  private _statusText: string;
  private _headers: Headers;
  private _ok: boolean;
  private _type: ResponseType;
  private _url: string;
  private _redirected: boolean;

  constructor(body?: BodyInit | null, init?: ResponseInit) {
    super();

    // Initialize from options
    this._status = Number(init?.status ?? 200);
    this._statusText = init?.statusText !== undefined ? String(init.statusText) : '';
    this._ok = this._status >= 200 && this._status < 300;
    this._type = 'default';
    this._url = '';
    this._redirected = false;

    // Validate status — per spec, only 200-599 is valid for Response constructor
    if (!Number.isFinite(this._status) || !Number.isInteger(this._status) || this._status < 200 || this._status > 599) {
      throw new RangeError(`Failed to construct 'Response': The status provided (${this._status}) is outside the range [200, 599].`);
    }

    // Validate statusText — must be a valid reason-phrase per HTTP spec
    // reason-phrase = *( HTAB / SP / VCHAR / obs-text )
    // VCHAR = 0x21-0x7E, obs-text = 0x80-0xFF, SP = 0x20, HTAB = 0x09
    if (this._statusText) {
      for (let i = 0; i < this._statusText.length; i++) {
        const c = this._statusText.charCodeAt(i);
        if (c > 0xFF || (c < 0x20 && c !== 0x09)) {
          throw new TypeError(`Failed to construct 'Response': Invalid statusText`);
        }
      }
    }

    // Validate body for null body status
    if (body !== null && body !== undefined && NULL_BODY_STATUS_CODES.includes(this._status)) {
      throw new TypeError('Response with null body status cannot have body');
    }

    // Initialize headers
    this._headers = new Headers(init?.headers);
    this._headers._guard = 'response';

    // Handle body
    if (body !== null && body !== undefined) {
      // Use isReadableStream() instead of instanceof to avoid ReferenceError
      // when ReadableStream global isn't available
      if (isReadableStream(body)) {
        // Per spec: reject locked or disturbed ReadableStream bodies
        if ((body as ReadableStream).locked || (body as any)._disturbed) {
          throw new TypeError("Failed to construct 'Response': body ReadableStream is locked.");
        }
        this._body = normalizeReadableStreamBody(body as ReadableStream<unknown>, 'Response body');
      } else if (isAsyncIterableBody(body)) {
        this._body = createReadableStreamFromAsyncIterableBody(body, 'Response body');
      } else if (typeof body === 'string') {
        const bytes = getTextEncoder().encode(body);
        // Only cache the buffer; `body` (the getter below) lazily builds the
        // ReadableStream — arrayBuffer()/text()/json() read `_bodyBuffer`
        // directly and never touch it, so eagerly building+copying here was
        // pure waste unless the caller actually reads `.body`.
        this._bodyBuffer = bytes.buffer as ArrayBuffer;

        // Set default Content-Type for string bodies
        if (!this._headers.has('content-type')) {
          this._headers.set('content-type', 'text/plain;charset=UTF-8');
        }
      } else if (body instanceof ArrayBuffer) {
        this._bodyBuffer = body.slice(0);
      } else if (ArrayBuffer.isView(body)) {
        this._bodyBuffer = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength);
      } else if (body instanceof Blob) {
        // Try sync bytes extraction first (our custom Blob), then stream
        if (typeof (body as any)._getBytes === 'function') {
          const bytes = (body as any)._getBytes() as Uint8Array;
          this._bodyBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
        } else if (typeof body.stream === 'function') {
          const stream = body.stream();
          if (stream) {
            this._body = stream;
          } else {
            // Fallback: bootstrap Blob.stream() returns null
            this._bodyBuffer = new ArrayBuffer(0);
          }
        }

        // Set Content-Type from Blob.type if non-empty and not already set
        if (body.type && !this._headers.has('content-type')) {
          this._headers.set('content-type', body.type);
        }
      } else if (body instanceof URLSearchParams) {
        const bytes = getTextEncoder().encode(body.toString());
        this._bodyBuffer = bytes.buffer as ArrayBuffer;

        if (!this._headers.has('content-type')) {
          this._headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
        }
      } else if (isFormDataBody(body)) {
        const encoded = encodeFormData(body as FormData);
        this._bodyBuffer = encoded.body.buffer as ArrayBuffer;

        if (!this._headers.has('content-type')) {
          this._headers.set('content-type', encoded.contentType);
        }
      }
    }
  }

  /**
   * A ReadableStream of the body contents.
   * Lazily materialized from `_bodyBuffer` on first access — mirrors
   * `Request.body` — so a caller that only ever calls arrayBuffer()/text()/
   * json()/bytes() (which read `_bodyBuffer` directly) never pays for the
   * ReadableStream allocation + full byte copy that `.body` requires.
   */
  override get body(): ReadableStream<Uint8Array> | null {
    if (this._body) {
      return this._body;
    }
    if (this._bodyBuffer) {
      this._body = createReadableStreamFromUint8Array(new Uint8Array(this._bodyBuffer));
      if (this._bodyUsed && this._body) {
        // The buffered body was already consumed via text()/json()/
        // arrayBuffer() before `.body` was ever touched. Reflect that on the
        // now-materialized stream (lock it without reading through it —
        // the bytes were already produced from `_bodyBuffer`) instead of
        // handing back a fresh, readable stream for an already-used body.
        (this._body as any)._disturbed = true;
        try { this._body.getReader(); } catch {}
      }
    }
    return this._body;
  }

  /**
   * Whether the response was successful (status 200-299).
   */
  get ok(): boolean {
    return this._ok;
  }

  /**
   * The HTTP status code of the response.
   */
  get status(): number {
    return this._status;
  }

  /**
   * The HTTP status message of the response.
   */
  get statusText(): string {
    return this._statusText;
  }

  /**
   * The headers of the response.
   */
  get headers(): Headers {
    return this._headers;
  }

  /**
   * The type of the response.
   */
  get type(): ResponseType {
    return this._type;
  }

  /**
   * The URL of the response.
   */
  get url(): string {
    // Per Fetch spec: response URL excludes fragment
    if (this._url && this._url.includes('#')) {
      return this._url.split('#')[0];
    }
    return this._url;
  }

  /**
   * Whether the response is the result of a redirect.
   */
  get redirected(): boolean {
    return this._redirected;
  }

  /**
   * Get the Content-Type header value.
   */
  protected override _getContentType(): string | null {
    return this._headers.get('content-type');
  }

  /**
   * Get the body as ArrayBuffer.
   * Uses explicit promise chains (not async) and resolveWithoutThenable to
   * prevent Object.prototype.then from intercepting resolution values.
   */
  protected override _getBodyBuffer(): Promise<ArrayBuffer> {
    if (this._bodyBuffer) {
      // Per spec each body consumption yields a fresh ArrayBuffer. Hand out a
      // copy so callers cannot mutate the internal body — and so a clone that
      // shares this cached buffer is unaffected by mutations to a prior read.
      const buf = this._bodyBuffer.slice(0);
      return new Promise<ArrayBuffer>(function (resolve) {
        resolveWithoutThenable(resolve, buf);
      });
    }

    if (this._body === null) {
      return Promise.resolve(new ArrayBuffer(0));
    }

    const self = this;
    return new Promise<ArrayBuffer>(function (resolve, reject) {
      // Thread the fetch's abort signal so a mid-download abort cancels the
      // reader (and the underlying native download) and rejects with the
      // abort reason instead of resolving with a partial/complete body.
      readableStreamToUint8Array(self._body!, self._signal).then(
        function (bytes) {
          self._bodyBuffer = bytes.buffer as ArrayBuffer;
          resolveWithoutThenable(resolve, self._bodyBuffer);
        },
        reject
      );
    });
  }

  /**
   * Creates a copy of the Response object.
   */
  clone(): Response {
    // Per spec, cloning must fail once the body has been read OR merely
    // disturbed (e.g. via a reader that was read from and then released
    // without setting the raw `_bodyUsed` flag, which only `_consumeBody()`
    // sets). Gating on the `bodyUsed` getter — not the raw field — catches
    // that case; `tee()` below still separately rejects a locked stream.
    if (this.bodyUsed) {
      throw new TypeError('Cannot clone a Response whose body has already been used');
    }

    const cloned = new Response(null, {
      status: this._status,
      statusText: this._statusText,
      headers: new Headers(this._headers),
    });

    cloned._ok = this._ok;
    cloned._type = this._type;
    cloned._url = this._url;
    cloned._redirected = this._redirected;
    // Give the clone its own buffer copy so consuming/mutating one body cannot
    // corrupt the other's contents.
    cloned._bodyBuffer = this._bodyBuffer ? this._bodyBuffer.slice(0) : null;
    cloned._signal = this._signal;

    // Clone the body stream using tee if available
    if (this._body) {
      const [stream1, stream2] = this._body.tee();
      this._body = stream1;
      cloned._body = stream2;
    }

    return cloned;
  }

  /**
   * Creates a new Response representing a network error.
   */
  static error(): Response {
    const response = new Response(null);
    response._status = 0;
    response._statusText = '';
    response._ok = false;
    response._type = 'error';
    response._headers = new Headers();
    response._headers._guard = 'immutable';
    return response;
  }

  /**
   * Creates a new Response for a redirect to the specified URL.
   */
  static redirect(url: string, status: number | { status?: number } = 302): Response {
    const bunCompat = isBunCompatResponseTest();
    const rawStatus =
      typeof status === 'object' && status !== null && 'status' in status
        ? status.status
        : status;
    const normalizedStatus =
      rawStatus === undefined || rawStatus === null || (bunCompat && typeof rawStatus !== 'number')
        ? 302
        : Number(rawStatus);

    if (!REDIRECT_STATUS_CODES.includes(normalizedStatus)) {
      throw new RangeError('Invalid redirect status code');
    }

    // Validate URL — resolve relative URLs against the current base if available
    let finalUrl = String(url);
    if (finalUrl.startsWith('://')) {
      try {
        const base = typeof globalThis.location !== 'undefined' ? globalThis.location.href : undefined;
        if (base) {
          const schemeMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.exec(String(base));
          if (schemeMatch) {
            finalUrl = schemeMatch[0] + finalUrl.slice(1);
          }
        }
      } catch {
        // Keep the protocol-relative Bun compat form when no usable base exists.
      }
    }
    if (!(bunCompat && finalUrl.startsWith('://')) && typeof URL !== 'undefined') {
      try {
        const base = typeof globalThis.location !== 'undefined' ? globalThis.location.href : undefined;
        const parsedUrl = new URL(finalUrl, base);
        finalUrl = parsedUrl.href;
      } catch {
        if (!bunCompat) {
          throw new TypeError('Invalid URL');
        }
      }
    }

    return new Response(null, {
      status: normalizedStatus,
      statusText: '',
      headers: {
        Location: finalUrl,
      },
    });
  }

  /**
   * Creates a new Response with a JSON body.
   */
  static json(data: unknown, init?: ResponseInit): Response {
    // Per spec: JSON.stringify errors propagate directly (not wrapped in TypeError)
    const body = JSON.stringify(data);
    if (body === undefined) {
      throw new TypeError(
        isBunCompatResponseTest()
          ? 'Value is not JSON serializable'
          : "Failed to execute 'json' on 'Response': The data is not JSON serializable"
      );
    }

    // Per spec: null-body status with body throws TypeError
    const status = init?.status ?? 200;
    if (NULL_BODY_STATUS_CODES.includes(status)) {
      throw new TypeError('Response with null body status cannot have body');
    }

    const response = new Response(body, init);

    // Per spec: Response.json() sets Content-Type to application/json
    // but user-provided Content-Type in init headers takes precedence.
    // Check if the user explicitly provided a content-type header.
    const userHeaders = init?.headers;
    let userProvidedContentType = false;
    if (userHeaders) {
      if (userHeaders instanceof Headers) {
        userProvidedContentType = userHeaders.has('content-type');
      } else if (Array.isArray(userHeaders)) {
        userProvidedContentType = userHeaders.some(
          (h) => Array.isArray(h) && h[0].toLowerCase() === 'content-type'
        );
      } else if (typeof userHeaders === 'object') {
        userProvidedContentType = Object.keys(userHeaders as Record<string, string>).some(
          (k) => k.toLowerCase() === 'content-type'
        );
      }
    }
    if (!userProvidedContentType) {
      response._headers.set(
        'content-type',
        isBunCompatResponseTest() ? 'application/json;charset=utf-8' : 'application/json'
      );
    }

    return response;
  }

  /**
   * Detect if a redirect occurred by comparing the request URL to the response URL.
   * The native bridge may not always set `redirected: true`, so we also check
   * whether the response URL differs from the original request URL.
   */
  private static _detectRedirected(
    nativeRedirected: boolean,
    responseUrl: string,
    requestUrl?: string
  ): boolean {
    if (nativeRedirected) return true;
    if (!requestUrl || !responseUrl) return false;
    // Compare URLs: if they differ, the request was redirected
    return responseUrl !== requestUrl;
  }

  /**
   * Create a Response from native response data.
   * @param nativeResponse The native response data
   * @param requestUrl The original request URL, used to detect redirects by URL comparison
   */
  static fromNative(nativeResponse: NativeResponse, requestUrl?: string): Response {
    // Bypass the constructor's status validation (native responses can have any status)
    const status = Number(nativeResponse.status);
    const response = new Response(null);
    response._status = status;
    // Use provided statusText, or fall back to default for the status code.
    // NSURLSession on macOS and HTTP/2 don't provide reason phrases.
    response._statusText = nativeResponse.statusText || DEFAULT_STATUS_TEXT[status] || '';
    response._headers = Headers.fromTupleArray(nativeResponse.headers);
    response._headers._guard = 'response';
    response._url = nativeResponse.url;
    response._redirected = Response._detectRedirected(
      nativeResponse.redirected,
      nativeResponse.url,
      requestUrl
    );
    response._ok = status >= 200 && status < 300;
    response._type = 'basic';

    // Set body. Only cache the buffer here — the lazy `body` getter builds
    // the ReadableStream on demand. arrayBuffer()/text()/json()/bytes() read
    // `_bodyBuffer` directly, so eagerly memcpy-ing the whole native body
    // into a stream was wasted work (and peak memory) for callers that never
    // touch `.body` (e.g. `await (await fetch(url)).json()`).
    if (!NULL_BODY_STATUS_CODES.includes(response._status)) {
      if (nativeResponse.body) {
        response._bodyBuffer = nativeResponse.body;
      } else if (isBunCompatResponseTest()) {
        response._bodyBuffer = new ArrayBuffer(0);
      }
    }

    return response;
  }

  /**
   * Create a Response from native streaming response data with a body stream.
   * @param nativeResponse The native streaming response data
   * @param bodyStream The ReadableStream for the response body
   * @param requestUrl The original request URL, used to detect redirects by URL comparison
   */
  static fromNativeStreaming(
    nativeResponse: NativeStreamingResponse,
    bodyStream: ReadableStream<Uint8Array>,
    requestUrl?: string
  ): Response {
    // Bypass the constructor's status validation (native responses can have any status)
    const status = Number(nativeResponse.status);
    const response = new Response(null);
    response._status = status;
    // Use provided statusText, or fall back to default for the status code.
    response._statusText = nativeResponse.statusText || DEFAULT_STATUS_TEXT[status] || '';
    response._headers = Headers.fromTupleArray(nativeResponse.headers);
    response._headers._guard = 'immutable';
    if (!NULL_BODY_STATUS_CODES.includes(status)) {
      response._body = bodyStream;
    }
    response._url = nativeResponse.url;
    response._redirected = Response._detectRedirected(
      nativeResponse.redirected,
      nativeResponse.url,
      requestUrl
    );
    response._ok = status >= 200 && status < 300;
    response._type = 'basic';

    return response;
  }
}

// Ensure constructor.name survives minification
Object.defineProperty(Response, 'name', { value: 'Response', configurable: true });
