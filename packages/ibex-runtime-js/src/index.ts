// @ts-nocheck
// @system @ref LLP 0003#the-bootstrap-sequence — Web-standard runtime globals on Ibex.
/**
 * Ibex Runtime
 *
 * Web-standard APIs for the Ibex runtime environment.
 * These APIs are implemented to match browser standards while
 * running on top of native platform code.
 */

// =============================================================================
// Bootstrap - Install all globals
// =============================================================================

export { installGlobals, areGlobalsInstalled, getRuntimeVersion, runtimeInfo } from "./bootstrap";

// =============================================================================
// Events & Errors (Phase 0)
// =============================================================================

export {
  Event,
  CustomEvent,
  EventTarget,
  DOMException,
  KeyboardEvent,
  FocusEvent,
} from "./events";
export type {
  EventInit,
  CustomEventInit,
  EventListener,
  EventListenerObject,
  EventListenerOrEventListenerObject,
  AddEventListenerOptions,
  EventListenerOptions,
  KeyboardEventInit,
  FocusEventInit,
} from "./events";

// =============================================================================
// Console (Phase 0)
// =============================================================================

export { Console, console, setConsoleOutput } from "./console";
export type { LogLevel, ConsoleOutput } from "./console";

// =============================================================================
// Accessibility / Preferences
// =============================================================================

export {
  announceForAccessibility,
  focusElementForAccessibility,
  getExactAccessibilitySnapshot,
  installExactAccessibilityGlobal,
  refreshExactAccessibility,
  subscribeExactAccessibilityChanges,
  type AccessibilityInfoEvent,
  type AccessibilityInfoKey,
  type ExactAccessibilitySnapshot,
} from "./accessibility";

// =============================================================================
// Timers (Phase 0)
// =============================================================================

export {
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  queueMicrotask,
  setImmediate,
  clearImmediate,
  setNativeTimerModule,
} from "./timers";
export type { TimerModule } from "./timers";

// =============================================================================
// Encoding (Phase 0)
// =============================================================================

export { TextEncoder, TextDecoder } from "./encoding";
export type { TextEncoderEncodeIntoResult, TextDecoderOptions, TextDecodeOptions } from "./encoding";

// =============================================================================
// Performance (Phase 0)
// =============================================================================

export {
  Performance,
  PerformanceEntry,
  PerformanceMark,
  PerformanceMeasure,
  performance,
  setNativePerformanceModule,
} from "./performance";
export type { PerformanceModule, PerformanceMarkOptions, PerformanceMeasureOptions } from "./performance";

// =============================================================================
// Base64 (Phase 0)
// =============================================================================

export { atob, btoa } from "./base64";

// =============================================================================
// Inspect (Object Pretty-Printing)
// =============================================================================

export { inspect, type InspectOptions } from "./inspect";

// =============================================================================
// URL (Phase 1)
// =============================================================================

export { URL, URLSearchParams, URLPattern } from "./url";
export type { URLPatternInit, URLPatternInput, URLPatternResult, URLPatternComponentResult } from "./url";

// =============================================================================
// Abort (Phase 1)
// =============================================================================

export { AbortController, AbortSignal } from "./abort";

// =============================================================================
// Crypto (Phase 3)
// =============================================================================

export { Crypto, SubtleCrypto, crypto } from "./crypto";

// =============================================================================
// Streams (Web Streams API)
// =============================================================================

export {
  ReadableStream,
  ReadableStreamDefaultReader,
  ReadableStreamDefaultController,
  ReadableByteStreamController,
  WritableStream,
  WritableStreamDefaultWriter,
  WritableStreamDefaultController,
  TransformStream,
  TransformStreamDefaultController,
  ByteLengthQueuingStrategy,
  CountQueuingStrategy,
} from "./streams";

export type {
  UnderlyingSource,
  UnderlyingByteSource,
  UnderlyingSink,
  Transformer,
  QueuingStrategy,
  StreamPipeOptions,
  ReadableStreamReadResult,
  ReadableStreamReadValueResult,
  ReadableStreamReadDoneResult,
} from "./streams";

// =============================================================================
// Web Locks API
// =============================================================================

export { LockManager } from "./locks";
export type { Lock, LockMode, LockOptions, LockGrantedCallback, LockManagerSnapshot } from "./locks";

// =============================================================================
// HTTP Server (exact:http)
// =============================================================================

export type {
  ServeHandle,
  ServeOptions,
} from "./http-server/index.js";

// =============================================================================
// EventSource (Server-Sent Events)
// =============================================================================

export { EventSource } from "./eventsource";
export type { EventSourceInit } from "./eventsource";

// =============================================================================
// Native Module Interfaces
// =============================================================================

export {
  setNativeCryptoModule,
  setNativeEncodingModule,
  setNativeConsoleModule,
  setNativeFetchModule as setNativeFetchBridge,
  setNativeWebSocketModule,
  setNativeStorageModule,
  setNativeFileSystemModule,
  getNativeCryptoModule,
  getNativeEncodingModule,
  getNativeConsoleModule,
  getNativeFetchModule,
  getNativeWebSocketModule,
  getNativeStorageModule,
  getNativeFileSystemModule,
  hasRequiredNativeModules,
  getMissingNativeModules,
} from "./native";

export type {
  NativeTimerModule,
  NativePerformanceModule,
  NativeCryptoModule,
  NativeEncodingModule,
  NativeConsoleModule,
  NativeWebSocketModule,
  NativeStorageModule,
  NativeFileSystemModule,
} from "./native";

// =============================================================================
// Fetch API (Phase 2 - existing implementation)
// =============================================================================

export {
  // Main fetch function
  fetch,
  fetchPolyfill,
  setNativeFetchModule,
  installFetchGlobals,

  // Classes
  Headers,
  Request,
  Response,

  // Errors
  FetchError,
  AbortError,
  NetworkError,
  URLError,
  BodyConsumedError,

  // Body utilities
  bodyToUint8Array,
  readableStreamToUint8Array,
  concatUint8Arrays,
  parseJson,
  parseText,
  isBlob,
  isFormData,
  isArrayBuffer,
  isArrayBufferView,
  isReadableStream,
} from './fetch/index.js';

export type {
  // Request types
  RequestInput,
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
} from './fetch/index.js';
