/**
 * Fetch API Type Definitions
 *
 * Based on the WHATWG Fetch Standard with extensions for Ibex runtime.
 * @see https://fetch.spec.whatwg.org/
 */

// =============================================================================
// Request Types
// =============================================================================

export type RequestMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'DELETE'
  | 'PATCH'
  | 'HEAD'
  | 'OPTIONS'
  | 'CONNECT'
  | 'TRACE';

export type RequestMode = 'cors' | 'no-cors' | 'same-origin' | 'navigate';

export type RequestCredentials = 'omit' | 'same-origin' | 'include';

export type RequestCache =
  | 'default'
  | 'no-store'
  | 'reload'
  | 'no-cache'
  | 'force-cache'
  | 'only-if-cached';

export type RequestRedirect = 'follow' | 'error' | 'manual';

export type ReferrerPolicy =
  | ''
  | 'no-referrer'
  | 'no-referrer-when-downgrade'
  | 'same-origin'
  | 'origin'
  | 'strict-origin'
  | 'origin-when-cross-origin'
  | 'strict-origin-when-cross-origin'
  | 'unsafe-url';

export type RequestDuplex = 'half';
export type TlsCertificateSource = string | ArrayBufferView | Array<string | ArrayBufferView>;

export interface FetchTlsOptions {
  ca?: TlsCertificateSource;
  cert?: TlsCertificateSource;
  key?: TlsCertificateSource;
  pfx?: TlsCertificateSource;
  passphrase?: string;
  servername?: string;
  rejectUnauthorized?: boolean;
  checkServerIdentity?: (hostname: string, cert: unknown) => Error | null | undefined;
  [key: string]: unknown;
}

/**
 * Request initialization options.
 */
export interface RequestInit {
  /** HTTP method (GET, POST, etc.) */
  method?: string;
  /** Request headers */
  headers?: HeadersInit;
  /** Request body */
  body?: BodyInit | null;
  /** Request mode for CORS */
  mode?: RequestMode;
  /** Credentials mode */
  credentials?: RequestCredentials;
  /** Cache mode */
  cache?: RequestCache;
  /** Redirect handling mode */
  redirect?: RequestRedirect;
  /** Referrer URL */
  referrer?: string;
  /** Referrer policy */
  referrerPolicy?: ReferrerPolicy;
  /** Subresource integrity hash */
  integrity?: string;
  /** Abort signal for cancellation */
  signal?: AbortSignal | null;
  /** Abort the request after this many milliseconds. Set to 0 to disable the default timeout. */
  timeout?: number;
  /** Required for streaming uploads */
  duplex?: RequestDuplex;
  /** Keep connection alive after page unloads (not supported) */
  keepalive?: boolean;
  /** Disable automatic content decoding and suppress Accept-Encoding injection */
  decompress?: boolean;
  /** Connect over a Unix domain socket instead of TCP. Bun compatibility extension. */
  unix?: string;
  /** Configure TLS certificate validation for HTTPS requests. Bun compatibility extension. */
  tls?: FetchTlsOptions;
}

// =============================================================================
// Response Types
// =============================================================================

export type ResponseType =
  | 'basic'
  | 'cors'
  | 'default'
  | 'error'
  | 'opaque'
  | 'opaqueredirect';

/**
 * Response initialization options.
 */
export interface ResponseInit {
  /** HTTP status code */
  status?: number;
  /** HTTP status text */
  statusText?: string;
  /** Response headers */
  headers?: HeadersInit;
}

// =============================================================================
// Headers Types
// =============================================================================

export type HeadersInit =
  | Headers
  | Record<string, string>
  | Iterable<[string, string]>
  | [string, string][];

// =============================================================================
// Body Types
// =============================================================================

export type BodyInit =
  | Blob
  | BufferSource
  | FormData
  | URLSearchParams
  | ReadableStream<Uint8Array>
  | string;

export type BufferSource = ArrayBuffer | ArrayBufferView;

// =============================================================================
// Native Bridge Types
// =============================================================================

/**
 * Native request initialization passed to the native layer.
 */
export interface NativeRequestInit {
  method: string;
  headers: [string, string][];
  credentials: RequestCredentials;
  redirect: RequestRedirect;
  decompress?: boolean;
  signal?: AbortSignal | null;
}

/**
 * Native response data returned from the native layer.
 */
export interface NativeResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  url: string;
  redirected: boolean;
  body: ArrayBuffer | null;
}

/**
 * Native streaming response data.
 */
export interface NativeStreamingResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  url: string;
  redirected: boolean;
}

/**
 * Interface for the native fetch module.
 * This will be implemented by the native layer (Swift/Kotlin/Rust).
 */
export interface NativeFetchModule {
  /** Internal marker for the real native bridge implementation. */
  __exactNativeBridge?: boolean;
  /**
   * Perform a fetch request.
   * @param url The request URL
   * @param init Request options
   * @param body Request body as Uint8Array (if any)
   * @returns Promise resolving to native response
   */
  fetch(
    url: string,
    init: NativeRequestInit,
    body: Uint8Array | null
  ): Promise<NativeResponse>;

  /**
   * Perform a streaming fetch request.
   * @param url The request URL
   * @param init Request options
   * @param body Request body as Uint8Array (if any)
   * @param onHeaders Callback when headers are received
   * @param onData Callback when data chunk is received
   * @param onComplete Callback when response is complete
   * @param onError Callback when error occurs
   * @returns Function to cancel the request
   */
  fetchStreaming?(
    url: string,
    init: NativeRequestInit,
    body: Uint8Array | null,
    onHeaders: (response: NativeStreamingResponse) => void,
    onData: (chunk: Uint8Array) => void,
    onComplete: () => void,
    onError: (error: Error) => void
  ): () => void;

  /**
   * Perform a fetch request with a streaming upload body.
   * The native layer calls onBodyChunk repeatedly to pull body chunks,
   * receiving null when the body is fully sent.
   *
   * Per spec (half-duplex): the request body is fully sent before
   * the response starts streaming.
   *
   * @param url The request URL
   * @param init Request options
   * @param onBodyChunk Async callback that returns the next body chunk,
   *   or null when the body is complete
   * @param onHeaders Callback when response headers are received
   * @param onData Callback when response data chunk is received
   * @param onComplete Callback when response is complete
   * @param onError Callback when error occurs
   * @returns Function to cancel the request
   */
  fetchStreamingUpload?(
    url: string,
    init: NativeRequestInit,
    onBodyChunk: () => Promise<Uint8Array | null>,
    onHeaders: (response: NativeStreamingResponse) => void,
    onData: (chunk: Uint8Array) => void,
    onComplete: () => void,
    onError: (error: Error) => void
  ): () => void;
}
