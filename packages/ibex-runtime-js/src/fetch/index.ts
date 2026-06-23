/**
 * Fetch API
 *
 * Web-standard Fetch API implementation for the Ibex runtime.
 * Follows the WHATWG Fetch Standard with native platform integration.
 *
 * @see https://fetch.spec.whatwg.org/
 *
 * @example
 * ```typescript
 * import { fetch, Headers, Request, Response } from '@exact/runtime/fetch';
 *
 * // Simple GET request
 * const response = await fetch('https://api.example.com/data');
 * const data = await response.json();
 *
 * // POST with JSON body
 * const response = await fetch('https://api.example.com/users', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json' },
 *   body: JSON.stringify({ name: 'John' }),
 * });
 *
 * // With AbortController
 * const controller = new AbortController();
 * setTimeout(() => controller.abort(), 5000);
 * const response = await fetch('https://api.example.com/slow', {
 *   signal: controller.signal,
 * });
 * ```
 */

// Core fetch function
export { fetch, fetchPolyfill, setNativeFetchModule, isNativeFetchModuleInitialized, installFetchGlobals } from './fetch.js';

// Native bridge
export {
  isNativeFetchAvailable,
  createNativeFetchModule,
  initializeNativeFetch,
} from './native-bridge.js';

// Classes
export { Headers } from './Headers.js';
export { Request, type RequestInput } from './Request.js';
export { Response } from './Response.js';

// Cookie jar
export { cookieJar, CookieJar, setRuntimeOrigin, getRuntimeOrigin } from './cookie-jar.js';
export type { StoredCookie } from './cookie-jar.js';

// Errors
export { FetchError, AbortError, NetworkError, URLError, BodyConsumedError } from './errors.js';

// Types
export type {
  // Request types
  RequestInit,
  RequestMethod,
  RequestMode,
  RequestCredentials,
  RequestCache,
  RequestRedirect,
  ReferrerPolicy,
  RequestDuplex,

  // Response types
  ResponseInit,
  ResponseType,

  // Headers types
  HeadersInit,

  // Body types
  BodyInit,
  BufferSource,

  // Native bridge types
  NativeRequestInit,
  NativeResponse,
  NativeStreamingResponse,
  NativeFetchModule,
} from './types.js';

// Body utilities (for advanced usage)
export {
  bodyToUint8Array,
  readableStreamToUint8Array,
  concatUint8Arrays,
  parseJson,
  parseText,
  parseMultipartFormData,
  extractBoundary,
  isBlob,
  isFormData,
  isArrayBuffer,
  isArrayBufferView,
} from './body.js';

// Stream utilities
export { isReadableStream } from '../streams/index.js';
