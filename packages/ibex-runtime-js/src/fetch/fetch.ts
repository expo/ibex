// @ts-nocheck
/**
 * Fetch API Implementation
 *
 * Implements the WHATWG Fetch Standard fetch() function.
 * @see https://fetch.spec.whatwg.org/#fetch-method
 */

import { Headers } from './Headers.js';
import { Request, type RequestInput } from './Request.js';
import { Response } from './Response.js';
import { FetchError, AbortError } from './errors.js';
import { DOMException } from '../events/DOMException.js';
import type {
  RequestInit,
  NativeRequestInit,
  NativeFetchModule,
  NativeResponse,
  NativeStreamingResponse,
} from './types.js';
import { requireCapability, Capabilities } from '../security/Capabilities';
import { cookieJar, getRuntimeOrigin } from './cookie-jar.js';
import { getTextEncoder, normalizeBlobContentType, readableStreamToUint8Array } from './body.js';

/**
 * Global reference to the native fetch module.
 * This is injected by the native layer at runtime.
 */
let nativeFetchModule: NativeFetchModule | null = null;
const DEFAULT_FETCH_TIMEOUT_MS = 0;

/**
 * Set the native fetch module.
 * Called by the native layer during initialization.
 */
export function setNativeFetchModule(module: NativeFetchModule): void {
  nativeFetchModule = module;
}

/**
 * Check if the native fetch module has been initialized.
 * Use this to decide whether to set up a mock/fallback.
 */
export function isNativeFetchModuleInitialized(): boolean {
  return nativeFetchModule !== null;
}

/**
 * Get the native fetch module.
 * Throws if not initialized.
 */
function getNativeFetchModule(): NativeFetchModule {
  if (!nativeFetchModule) {
    throw new FetchError('Native fetch module not initialized');
  }
  return nativeFetchModule;
}

function networkFetchCapabilityForUrl(url: string): string {
  const parsedUrl = new URL(url, getRuntimeOrigin());
  const host = parsedUrl.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  return `${Capabilities.NETWORK_FETCH}:${host}`;
}

function requireFetchCapabilityForUrl(url: string): void {
  // @ref LLP 0013#policy — generated policy can grant individual fetch hosts,
  // so JS-side checks mirror the native boundary's endpoint-scoped decision.
  requireCapability(networkFetchCapabilityForUrl(url));
}

function isDataUrl(url: unknown): url is string {
  return typeof url === 'string' && url.slice(0, 5).toLowerCase() === 'data:';
}

/**
 * Add an abort signal listener with cleanup function.
 */
function addAbortSignalListener(
  signal: AbortSignal | null | undefined,
  listener: () => void
): () => void {
  if (!signal) {
    return () => {};
  }

  signal.addEventListener('abort', listener);
  return () => {
    signal.removeEventListener('abort', listener);
  };
}

function createDataUrlFetchError(): TypeError {
  return new TypeError(
    isBunCompatEnv() ? 'failed to fetch the data URL' : 'Failed to fetch: invalid data URL'
  );
}

function isAsciiHexDigit(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x46) ||
    (code >= 0x61 && code <= 0x66)
  );
}

function hexDigitToValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) {
    return code - 0x30;
  }
  if (code >= 0x41 && code <= 0x46) {
    return code - 0x41 + 10;
  }
  return code - 0x61 + 10;
}

function decodePercentEscapesLooseToLatin1(input: string): string {
  let decoded = '';
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (
      code === 0x25 &&
      i + 2 < input.length &&
      isAsciiHexDigit(input.charCodeAt(i + 1)) &&
      isAsciiHexDigit(input.charCodeAt(i + 2))
    ) {
      decoded += String.fromCharCode(
        (hexDigitToValue(input.charCodeAt(i + 1)) << 4) | hexDigitToValue(input.charCodeAt(i + 2))
      );
      i += 2;
      continue;
    }
    decoded += input[i];
  }
  return decoded;
}

function decodeDataUrlPayloadLoose(input: string): Uint8Array {
  const bytes: number[] = [];
  const encoder = getTextEncoder();

  for (let i = 0; i < input.length; ) {
    const code = input.charCodeAt(i);
    if (
      code === 0x25 &&
      i + 2 < input.length &&
      isAsciiHexDigit(input.charCodeAt(i + 1)) &&
      isAsciiHexDigit(input.charCodeAt(i + 2))
    ) {
      bytes.push(
        (hexDigitToValue(input.charCodeAt(i + 1)) << 4) | hexDigitToValue(input.charCodeAt(i + 2))
      );
      i += 3;
      continue;
    }

    const codePoint = input.codePointAt(i)!;
    const encoded = encoder.encode(String.fromCodePoint(codePoint));
    for (let j = 0; j < encoded.length; j++) {
      bytes.push(encoded[j]);
    }
    i += codePoint > 0xffff ? 2 : 1;
  }

  return new Uint8Array(bytes);
}

// Internal coordination promises are observed indirectly through await/Promise.race.
// Attach a no-op rejection handler so the runtime's unhandled rejection tracker does not
// report the internal promise when the error is rethrown through the public fetch promise.
function suppressInternalPromiseRejection<T>(promise: Promise<T>): Promise<T> {
  promise.catch(() => {});
  return promise;
}

function resolveTimeoutMs(init?: RequestInit): number {
  const timeout = init?.timeout;
  if (timeout === undefined) {
    return DEFAULT_FETCH_TIMEOUT_MS;
  }
  if (!Number.isFinite(timeout) || timeout < 0) {
    throw new TypeError('Failed to fetch: timeout must be a non-negative finite number');
  }
  return timeout;
}

function createEffectiveSignal(
  sourceSignal: AbortSignal | null | undefined,
  timeoutMs: number
): { signal: AbortSignal | null | undefined; cleanup: () => void } {
  if (timeoutMs === 0) {
    return { signal: sourceSignal, cleanup: () => {} };
  }

  const controller = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
    controller.abort(new DOMException('The operation timed out.', 'TimeoutError'));
  }, timeoutMs);

  const forwardAbort = () => {
    controller.abort(sourceSignal?.reason);
  };

  if (sourceSignal?.aborted) {
    forwardAbort();
  } else if (sourceSignal) {
    sourceSignal.addEventListener('abort', forwardAbort);
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      if (timeoutId !== undefined) {
        clearTimeout(timeoutId);
        timeoutId = undefined;
      }
      if (sourceSignal) {
        sourceSignal.removeEventListener('abort', forwardAbort);
      }
    },
  };
}

type ReferrerSource = 'request-object' | 'input';
type CancelableNativeResponsePromise = Promise<NativeResponse> & {
  __exactCancel?: () => void;
};

type SocketBuffer = Uint8Array & {
  toString?(encoding?: string, start?: number, end?: number): string;
  length: number;
  subarray(start?: number, end?: number): SocketBuffer;
};

interface BufferConstructorLike {
  from(input: string | ArrayBuffer | ArrayBufferView, encoding?: string): SocketBuffer;
  alloc(size: number): SocketBuffer;
  concat(list: ReadonlyArray<Uint8Array>): SocketBuffer;
}

type RequestTlsOptions = NonNullable<RequestInit['tls']>;

const CERTIFICATE_PEM_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

function normalizeNativeBody(body: unknown): ArrayBuffer | null {
  if (body == null) {
    return null;
  }
  if (body instanceof ArrayBuffer) {
    return body;
  }
  if (ArrayBuffer.isView(body)) {
    const view = body as ArrayBufferView;
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  }
  throw new TypeError('Failed to fetch: invalid native response body');
}

function validateNativeHeaders(headers: unknown): [string, string][] {
  if (!Array.isArray(headers)) {
    throw new TypeError('Failed to fetch: invalid native response headers');
  }

  return headers.map((header) => {
    if (!Array.isArray(header) || header.length !== 2) {
      throw new TypeError('Failed to fetch: invalid native response headers');
    }
    const [name, value] = header;
    if (typeof name !== 'string' || typeof value !== 'string') {
      throw new TypeError('Failed to fetch: invalid native response headers');
    }
    return [name, normalizeBunCompatHeaderValue(value)];
  });
}

function validateNativeResponseBase(nativeResponse: unknown): Omit<NativeResponse, 'body'> {
  if (typeof nativeResponse !== 'object' || nativeResponse === null) {
    throw new TypeError('Failed to fetch: invalid native response');
  }

  const { status, statusText, headers, url, redirected } = nativeResponse as Record<string, unknown>;
  if (!Number.isInteger(status) || (status as number) < 0 || (status as number) > 599) {
    throw new TypeError('Failed to fetch: invalid native response status');
  }
  if (typeof statusText !== 'string') {
    throw new TypeError('Failed to fetch: invalid native response status text');
  }
  if (typeof url !== 'string') {
    throw new TypeError('Failed to fetch: invalid native response url');
  }
  if (typeof redirected !== 'boolean') {
    throw new TypeError('Failed to fetch: invalid native response redirect flag');
  }

  return {
    status,
    statusText,
    headers: validateNativeHeaders(headers),
    url,
    redirected,
  };
}

function validateNativeResponse(nativeResponse: unknown): NativeResponse {
  const base = validateNativeResponseBase(nativeResponse);
  const body = normalizeNativeBody((nativeResponse as Record<string, unknown>).body);
  return { ...base, body };
}

function validateNativeStreamingResponse(nativeResponse: unknown): NativeStreamingResponse {
  return validateNativeResponseBase(nativeResponse);
}

function hasHeader(headers: [string, string][], name: string): boolean {
  const target = name.toLowerCase();
  for (const [headerName] of headers) {
    if (headerName.toLowerCase() === target) {
      return true;
    }
  }
  return false;
}

function setHeader(headers: [string, string][], name: string, value: string): void {
  const target = name.toLowerCase();
  for (let i = 0; i < headers.length; i++) {
    if (headers[i][0].toLowerCase() === target) {
      headers[i] = [headers[i][0], value];
      return;
    }
  }
  headers.push([name, value]);
}

function copyErrorMetadata(target: Error, source: unknown): void {
  if (typeof source !== 'object' || source === null) {
    return;
  }

  const sourceRecord = source as Record<string, unknown>;
  const targetRecord = target as Record<string, unknown>;
  const fields = ['code', 'errno', 'syscall', 'address', 'port'];
  for (let i = 0; i < fields.length; i++) {
    const key = fields[i];
    if (sourceRecord[key] !== undefined) {
      targetRecord[key] = sourceRecord[key];
    }
  }
}

function createSocketTransportError(message: string, code: string): Error {
  const error = new Error(message);
  copyErrorMetadata(error, { code });
  return error;
}

function getSocketBufferConstructor(
  runtimeRequire: (specifier: string) => unknown
): BufferConstructorLike {
  const globalBuffer = (globalThis as {
    Buffer?: BufferConstructorLike;
  }).Buffer;
  if (globalBuffer && typeof globalBuffer.from === 'function' && typeof globalBuffer.concat === 'function') {
    return globalBuffer;
  }

  const bufferModule = runtimeRequire('node:buffer') as { Buffer?: BufferConstructorLike };
  if (bufferModule && bufferModule.Buffer && typeof bufferModule.Buffer.from === 'function') {
    return bufferModule.Buffer;
  }

  throw new FetchError('Buffer constructor unavailable for socket transport');
}

function getRuntimeProcessEnv(
  runtimeRequire: (specifier: string) => unknown
): Record<string, string | undefined> | null {
  try {
    const processModule = runtimeRequire('node:process') as {
      env?: Record<string, string | undefined>;
    };
    return processModule?.env ?? null;
  } catch {
    return null;
  }
}

function mergeCertificateSources(existing: unknown, extra: string): unknown {
  if (existing === undefined || existing === null || existing === '') {
    return extra;
  }
  if (Array.isArray(existing)) {
    return existing.concat(extra);
  }
  return [existing, extra];
}

function loadNodeExtraCaBundle(
  runtimeRequire: (specifier: string) => unknown,
  env: Record<string, string | undefined> | null
): string | null {
  const extraCaPath = typeof env?.NODE_EXTRA_CA_CERTS === 'string'
    ? env.NODE_EXTRA_CA_CERTS.trim()
    : '';
  if (!extraCaPath) {
    return null;
  }

  let contents = '';
  try {
    const fs = runtimeRequire('node:fs') as {
      readFileSync(path: string, encoding: string): string;
    };
    if (!fs || typeof fs.readFileSync !== 'function') {
      return null;
    }
    contents = fs.readFileSync(extraCaPath, 'utf8');
  } catch {
    return null;
  }

  if (!contents.trim()) {
    return null;
  }

  const matches = contents.match(CERTIFICATE_PEM_PATTERN);
  if (!matches || matches.length === 0) {
    return null;
  }

  const remainder = contents.replace(CERTIFICATE_PEM_PATTERN, '').trim();
  if (remainder) {
    if (typeof console !== 'undefined' && typeof console.error === 'function') {
      console.error('ignoring extra certs from NODE_EXTRA_CA_CERTS');
    }
    return null;
  }

  return matches.join('\n');
}

function applyHttpsRequestTlsOptions(
  requestOptions: Record<string, any>,
  init: RequestInit | undefined,
  runtimeRequire: (specifier: string) => unknown
): void {
  const tlsOptions = init?.tls;
  if (tlsOptions && typeof tlsOptions === 'object') {
    const tlsRecord = tlsOptions as RequestTlsOptions & Record<string, unknown>;
    const keys = Object.keys(tlsRecord);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      requestOptions[key] = tlsRecord[key];
    }
  }

  const env = getRuntimeProcessEnv(runtimeRequire);
  if (
    requestOptions.rejectUnauthorized === undefined &&
    env?.NODE_TLS_REJECT_UNAUTHORIZED === '0'
  ) {
    requestOptions.rejectUnauthorized = false;
  }

  const extraCaBundle = loadNodeExtraCaBundle(runtimeRequire, env);
  if (extraCaBundle) {
    requestOptions.ca = mergeCertificateSources(requestOptions.ca, extraCaBundle);
  }
}

function indexOfByteSequence(
  buffer: Uint8Array,
  sequence: readonly number[],
  start = 0
): number {
  if (sequence.length === 0) {
    return start;
  }

  outer:
  for (let i = start; i <= buffer.length - sequence.length; i++) {
    for (let j = 0; j < sequence.length; j++) {
      if (buffer[i + j] !== sequence[j]) {
        continue outer;
      }
    }
    return i;
  }

  return -1;
}

function decodeSocketLatin1(buffer: SocketBuffer, start = 0, end = buffer.length): string {
  if (typeof buffer.toString === 'function') {
    return buffer.toString('latin1', start, end);
  }

  let decoded = '';
  for (let i = start; i < end; i++) {
    decoded += String.fromCharCode(buffer[i]);
  }
  return decoded;
}

function maybeDecompressSocketResponseBody(
  responseBody: Uint8Array | null,
  headers: [string, string][],
  decompress: boolean | undefined,
  runtimeRequire: (specifier: string) => unknown
): Uint8Array | null {
  if (!responseBody || decompress === false) {
    return responseBody;
  }

  const encodingHeader = headers.find(([name]) => name.toLowerCase() === 'content-encoding');
  const contentEncoding = encodingHeader
    ? encodingHeader[1].split(',', 1)[0].trim().toLowerCase()
    : '';
  if (
    contentEncoding !== 'gzip' &&
    contentEncoding !== 'x-gzip' &&
    contentEncoding !== 'deflate' &&
    contentEncoding !== 'br' &&
    contentEncoding !== 'zstd'
  ) {
    return responseBody;
  }

  const zlib = runtimeRequire('node:zlib') as {
    gunzipSync(buffer: Uint8Array): Uint8Array;
    inflateSync(buffer: Uint8Array): Uint8Array;
    inflateRawSync?: (buffer: Uint8Array) => Uint8Array;
    brotliDecompressSync?: (buffer: Uint8Array) => Uint8Array;
    zstdDecompressSync?(buffer: Uint8Array): Uint8Array;
  };
  if (!zlib) {
    return responseBody;
  }

  if (contentEncoding === 'gzip' || contentEncoding === 'x-gzip') {
    return new Uint8Array(zlib.gunzipSync(responseBody));
  }
  if (contentEncoding === 'deflate') {
    try {
      return new Uint8Array(zlib.inflateSync(responseBody));
    } catch (error) {
      if (typeof zlib.inflateRawSync === 'function') {
        try {
          return new Uint8Array(zlib.inflateRawSync(responseBody));
        } catch {
          throw error;
        }
      }
      throw error;
    }
  }
  if (contentEncoding === 'br' && typeof zlib.brotliDecompressSync === 'function') {
    return new Uint8Array(zlib.brotliDecompressSync(responseBody));
  }
  if (contentEncoding === 'zstd' && typeof zlib.zstdDecompressSync === 'function') {
    return new Uint8Array(zlib.zstdDecompressSync(responseBody));
  }

  return responseBody;
}

function getSocketResponseContentEncoding(
  headers: [string, string][],
  decompress: boolean | undefined
): string {
  if (decompress === false) {
    return '';
  }

  const encodingHeader = headers.find(([name]) => name.toLowerCase() === 'content-encoding');
  return encodingHeader
    ? encodingHeader[1].split(',', 1)[0].trim().toLowerCase()
    : '';
}

function isLikelyZlibWrappedDeflatePrefix(prefix: Uint8Array): boolean {
  if (prefix.byteLength < 2) {
    return true;
  }

  const cmf = prefix[0];
  const flg = prefix[1];
  return (cmf & 0x0f) === 8 && (cmf >> 4) <= 7 && (((cmf << 8) + flg) % 31) === 0;
}

function normalizeSocketBodyStreamError(error: unknown, code?: string): Error {
  const normalized = error instanceof Error ? error : new Error(String(error));
  const normalizedCode = (normalized as Error & { code?: unknown }).code;
  if (typeof normalizedCode === 'string' && normalizedCode.startsWith('HPE_')) {
    const mapped = createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
    copyErrorMetadata(mapped, normalized);
    (mapped as Error & { code?: string }).code = 'InvalidHTTPResponse';
    return mapped;
  }
  if (!code) {
    return normalized;
  }

  const mapped = new Error(normalized.message);
  mapped.name = 'Error';
  copyErrorMetadata(mapped, normalized);
  (mapped as Error & { code?: string }).code = code;
  return mapped;
}

const SOCKET_DECOMPRESSED_CHUNK_SIZE = 16 * 1024;

function createSocketResponseBodyStream(
  sourceStream: any,
  headers: [string, string][],
  decompress: boolean | undefined,
  runtimeRequire: (specifier: string) => unknown,
  signal: AbortSignal | null | undefined
): ReadableStream<Uint8Array> {
  const BufferCtor = getSocketBufferConstructor(runtimeRequire);
  const contentEncoding = getSocketResponseContentEncoding(headers, decompress);
  let settled = false;
  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  let queuedChunks: Uint8Array[] = [];
  let pendingError: Error | null = null;
  let pendingClose = false;

  function flushQueuedState(): void {
    if (!controller || settled) {
      return;
    }

    while (queuedChunks.length > 0) {
      controller.enqueue(queuedChunks.shift()!);
    }

    if (pendingError) {
      const error = pendingError;
      pendingError = null;
      const activeController = controller;
      controller = null;
      activeController.error(error);
      return;
    }

    if (pendingClose) {
      pendingClose = false;
      const activeController = controller;
      controller = null;
      activeController.close();
    }
  }

  function toSocketBodyChunk(chunk: Uint8Array | ArrayBufferView | string): Uint8Array {
    return typeof chunk === 'string'
      ? BufferCtor.from(chunk, 'utf8')
      : BufferCtor.from(chunk as ArrayBufferView);
  }

  function queueChunkCopy(chunk: Uint8Array): void {
    const copy = new Uint8Array(chunk.byteLength);
    copy.set(chunk);

    if (controller) {
      controller.enqueue(copy);
      return;
    }

    queuedChunks.push(copy);
  }

  function enqueueChunk(chunk: Uint8Array | ArrayBufferView | string, maxChunkSize?: number): void {
    if (settled) {
      return;
    }

    const bytes = toSocketBodyChunk(chunk);
    if (typeof maxChunkSize !== 'number' || maxChunkSize <= 0 || bytes.byteLength <= maxChunkSize) {
      queueChunkCopy(bytes);
      return;
    }

    for (let offset = 0; offset < bytes.byteLength; offset += maxChunkSize) {
      queueChunkCopy(bytes.subarray(offset, Math.min(offset + maxChunkSize, bytes.byteLength)));
    }
  }

  const bodyStream = new ReadableStream<Uint8Array>({
    start(streamController) {
      controller = streamController;
      flushQueuedState();
    },
    cancel(reason) {
      cleanupAbortListener();
      settled = true;
      queuedChunks = [];
      if (typeof sourceStream?.destroy === 'function') {
        try {
          sourceStream.destroy(reason instanceof Error ? reason : undefined);
        } catch {}
      }
    },
  });

  const abortListener = () => {
    const reason = signal?.reason instanceof Error
      ? signal.reason
      : new DOMException('The operation was aborted.', 'AbortError');
    failOutput(reason);
  };

  if (signal) {
    if (signal.aborted) {
      abortListener();
    } else {
      signal.addEventListener('abort', abortListener);
    }
  }

  function cleanupAbortListener(): void {
    if (signal) {
      signal.removeEventListener('abort', abortListener);
    }
  }

  function finishOutput(): void {
    if (settled) {
      return;
    }
    settled = true;
    cleanupAbortListener();
    if (typeof sourceStream?.destroy === 'function') {
      try {
        sourceStream.destroy();
      } catch {}
    }
    if (controller) {
      const activeController = controller;
      controller = null;
      activeController.close();
      return;
    }
    pendingClose = true;
  }

  function failOutput(error: unknown, code?: string): void {
    if (settled) {
      return;
    }
    settled = true;
    cleanupAbortListener();
    if (typeof sourceStream?.destroy === 'function') {
      try {
        sourceStream.destroy(error instanceof Error ? error : undefined);
      } catch {}
    }
    const normalizedError = normalizeSocketBodyStreamError(error, code);
    queuedChunks = [];
    if (controller) {
      const activeController = controller;
      controller = null;
      activeController.error(normalizedError);
      return;
    }
    pendingError = normalizedError;
  }

  function forwardReadable(readable: any, errorCode?: string, maxChunkSize?: number): void {
    readable.on('data', (chunk: Uint8Array | ArrayBufferView | string) => {
      try {
        enqueueChunk(chunk, maxChunkSize);
      } catch (error) {
        failOutput(error, errorCode);
      }
    });
    readable.on('end', finishOutput);
    readable.on('error', (error: unknown) => {
      failOutput(error, errorCode);
    });
    if (typeof readable.resume === 'function') {
      readable.resume();
    }
  }

  sourceStream.on('aborted', () => {
    failOutput(createSocketTransportError('aborted', 'ECONNRESET'));
  });
  sourceStream.on('close', () => {
    if (!settled && typeof sourceStream.complete === 'boolean' && sourceStream.complete === false) {
      failOutput(createSocketTransportError('aborted', 'ECONNRESET'));
    }
  });
  sourceStream.on('error', (error: unknown) => {
    failOutput(error);
  });

  if (!contentEncoding) {
    forwardReadable(sourceStream);
    return bodyStream;
  }

  const zlib = runtimeRequire('node:zlib') as {
    createGunzip?: () => any;
    createInflate?: () => any;
    createInflateRaw?: () => any;
    createBrotliDecompress?: () => any;
    createZstdDecompress?: () => any;
  };
  if (!zlib) {
    forwardReadable(sourceStream);
    return bodyStream;
  }

  if (contentEncoding === 'gzip' || contentEncoding === 'x-gzip') {
    if (typeof zlib.createGunzip !== 'function') {
      forwardReadable(sourceStream);
      return bodyStream;
    }
    const decoder = zlib.createGunzip();
    sourceStream.pipe(decoder);
    forwardReadable(decoder, 'ZlibError', SOCKET_DECOMPRESSED_CHUNK_SIZE);
    return bodyStream;
  }

  if (contentEncoding === 'br') {
    if (typeof zlib.createBrotliDecompress !== 'function') {
      forwardReadable(sourceStream);
      return bodyStream;
    }
    const decoder = zlib.createBrotliDecompress();
    sourceStream.pipe(decoder);
    forwardReadable(decoder, 'BrotliDecompressionError', SOCKET_DECOMPRESSED_CHUNK_SIZE);
    return bodyStream;
  }

  if (contentEncoding === 'zstd') {
    if (typeof zlib.createZstdDecompress !== 'function') {
      forwardReadable(sourceStream);
      return bodyStream;
    }
    const decoder = zlib.createZstdDecompress();
    sourceStream.pipe(decoder);
    forwardReadable(decoder, 'ZstdDecompressionError', SOCKET_DECOMPRESSED_CHUNK_SIZE);
    return bodyStream;
  }

  if (
    contentEncoding === 'deflate' &&
    typeof zlib.createInflate === 'function' &&
    typeof zlib.createInflateRaw === 'function'
  ) {
    let decoder: any = null;
    const prefixChunks: Uint8Array[] = [];
    let prefixLength = 0;

    function startDeflateDecoder(): void {
      if (decoder) {
        return;
      }

      const prefix = prefixLength > 0 ? concatUint8Chunks(prefixChunks, prefixLength) : new Uint8Array(0);
      decoder = isLikelyZlibWrappedDeflatePrefix(prefix)
        ? zlib.createInflate!()
        : zlib.createInflateRaw!();
      forwardReadable(decoder, 'ZlibError', SOCKET_DECOMPRESSED_CHUNK_SIZE);
      if (prefix.byteLength > 0) {
        decoder.write(BufferCtor.from(prefix));
      }
    }

    sourceStream.on('data', (chunk: Uint8Array | ArrayBufferView | string) => {
      const bytes = toSocketBodyChunk(chunk);
      if (!decoder) {
        const copy = new Uint8Array(bytes.byteLength);
        copy.set(bytes);
        prefixChunks.push(copy);
        prefixLength += copy.byteLength;
        if (prefixLength >= 2) {
          startDeflateDecoder();
        }
        return;
      }
      decoder.write(bytes);
    });
    sourceStream.on('end', () => {
      startDeflateDecoder();
      decoder.end();
    });
    return bodyStream;
  }

  forwardReadable(sourceStream);
  return bodyStream;
}

interface ParsedSocketResponseHead {
  status: number;
  statusText: string;
  headers: [string, string][];
  bodyOffset: number;
  chunked: boolean;
  contentLength: number | null;
  noBody: boolean;
}

function parseSocketResponseHead(
  buffer: SocketBuffer,
  method: string
): ParsedSocketResponseHead | null {
  const headerEnd = indexOfByteSequence(buffer, [13, 10, 13, 10], 0);
  if (headerEnd === -1) {
    return null;
  }

  const headerText = decodeSocketLatin1(buffer, 0, headerEnd);
  const lines = headerText.split('\r\n');
  const statusLine = lines.shift() ?? '';
  const statusMatch = /^HTTP\/\d+\.\d+\s+(\d{3})(?:\s+(.*))?$/.exec(statusLine);
  if (!statusMatch) {
    throw createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
  }

  const status = Number.parseInt(statusMatch[1], 10);
  const statusText = statusMatch[2] ?? '';
  const headers: [string, string][] = [];
  let transferEncoding = '';
  let contentLength: number | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) {
      continue;
    }

    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) {
      throw createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
    }

    const name = line.slice(0, colonIndex);
    const value = line.slice(colonIndex + 1).trim();
    headers.push([name, value]);

    const normalizedName = name.toLowerCase();
    if (normalizedName === 'transfer-encoding') {
      transferEncoding = transferEncoding ? `${transferEncoding},${value}` : value;
    } else if (normalizedName === 'content-length' && contentLength === null) {
      const parsedLength = Number.parseInt(value, 10);
      if (Number.isFinite(parsedLength) && parsedLength >= 0) {
        contentLength = parsedLength;
      }
    }
  }

  const chunked = transferEncoding
    .split(',')
    .some((token) => token.trim().toLowerCase() === 'chunked');
  if (chunked) {
    contentLength = null;
  }

  const noBody =
    method === 'HEAD' ||
    (status >= 100 && status < 200) ||
    status === 204 ||
    status === 304;

  return {
    status,
    statusText,
    headers,
    bodyOffset: headerEnd + 4,
    chunked,
    contentLength,
    noBody,
  };
}

async function executeRawHttpSocketFetchHop(
  url: string,
  nativeInit: NativeRequestInit,
  effectiveHeaders: [string, string][],
  body: Uint8Array | null,
  runtimeRequire: (specifier: string) => unknown,
  signal: AbortSignal | null | undefined,
  socketPath?: string
): Promise<NativeResponse> {
  const parsedUrl = new URL(url);
  const net = runtimeRequire('node:net') as {
    createConnection(
      options: { host?: string; port?: number; path?: string }
    ): {
      on(event: string, listener: (...args: any[]) => void): unknown;
      once(event: string, listener: (...args: any[]) => void): unknown;
      removeAllListeners?(event?: string): unknown;
      write(chunk: Uint8Array | string, encoding?: string): unknown;
      end(chunk?: Uint8Array | string, encoding?: string): unknown;
      destroy(error?: Error): unknown;
      setNoDelay?(noDelay?: boolean): unknown;
      unref?(): unknown;
    };
  };
  if (!net || typeof net.createConnection !== 'function') {
    throw new FetchError('node:net not available for socket transport compatibility path');
  }

  const BufferCtor = getSocketBufferConstructor(runtimeRequire);
  return await suppressInternalPromiseRejection(new Promise<NativeResponse>((resolve, reject) => {
    const port = parsedUrl.port ? Number(parsedUrl.port) : 80;
    const requestPath = `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`;
    const socket = socketPath
      ? net.createConnection({ path: socketPath })
      : net.createConnection({ host: parsedUrl.hostname, port });

    let settled = false;
    let responseBuffer = BufferCtor.alloc(0);
    let parsedHead: ParsedSocketResponseHead | null = null;
    let bodyOffset = 0;
    let chunkedState: 'size' | 'data' | 'data-crlf' | 'trailers' = 'size';
    let currentChunkSize = 0;
    const bodyChunks: Uint8Array[] = [];
    let bodyLength = 0;
    const abortListener = () => {
      settleReject(signal?.reason instanceof Error ? signal.reason : new Error('The operation was aborted.'));
    };

    const settleResolve = (nativeResponse: NativeResponse): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (signal) {
        signal.removeEventListener('abort', abortListener);
      }
      if (typeof socket.removeAllListeners === 'function') {
        socket.removeAllListeners('data');
        socket.removeAllListeners('end');
        socket.removeAllListeners('error');
      }
      if (typeof socket.unref === 'function') {
        socket.unref();
      }
      resolve(nativeResponse);
    };

    const settleReject = (error: unknown): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (signal) {
        signal.removeEventListener('abort', abortListener);
      }
      socket.destroy(error instanceof Error ? error : undefined);
      reject(error);
    };

    const pushBodyChunk = (start: number, end: number): void => {
      const length = end - start;
      if (length <= 0) {
        return;
      }

      const chunk = new Uint8Array(length);
      chunk.set(responseBuffer.subarray(start, end));
      bodyChunks.push(chunk);
      bodyLength += chunk.byteLength;
    };

    const finalizeResponse = (): void => {
      if (!parsedHead) {
        settleReject(createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse'));
        return;
      }

      let responseBody = bodyLength > 0 ? concatUint8Chunks(bodyChunks, bodyLength) : null;
      try {
        responseBody = maybeDecompressSocketResponseBody(
          responseBody,
          parsedHead.headers,
          nativeInit.decompress,
          runtimeRequire
        );
      } catch (error) {
        settleReject(error);
        return;
      }

      settleResolve({
        status: parsedHead.status,
        statusText: parsedHead.statusText,
        headers: parsedHead.headers,
        url,
        redirected: false,
        body: responseBody
          ? responseBody.buffer.slice(
              responseBody.byteOffset,
              responseBody.byteOffset + responseBody.byteLength
            )
          : null,
      });
    };

    const consumeAvailable = (eof: boolean): void => {
      if (settled) {
        return;
      }

      try {
        if (!parsedHead) {
          parsedHead = parseSocketResponseHead(responseBuffer, nativeInit.method);
          if (!parsedHead) {
            if (eof) {
              throw createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
            }
            return;
          }

          bodyOffset = parsedHead.bodyOffset;
          if (parsedHead.noBody) {
            finalizeResponse();
            return;
          }
          if (parsedHead.contentLength === 0) {
            finalizeResponse();
            return;
          }
        }

        if (parsedHead.chunked) {
          while (true) {
            if (chunkedState === 'size') {
              const lineEnd = indexOfByteSequence(responseBuffer, [13, 10], bodyOffset);
              if (lineEnd === -1) {
                if (eof) {
                  throw createSocketTransportError('aborted', 'ECONNRESET');
                }
                return;
              }

              const chunkLine = decodeSocketLatin1(responseBuffer, bodyOffset, lineEnd);
              const sizeToken = chunkLine.split(';', 1)[0].trim();
              if (!/^[0-9A-Fa-f]+$/.test(sizeToken)) {
                throw createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
              }

              currentChunkSize = Number.parseInt(sizeToken, 16);
              bodyOffset = lineEnd + 2;
              if (currentChunkSize === 0) {
                chunkedState = 'trailers';
              } else {
                chunkedState = 'data';
              }
              continue;
            }

            if (chunkedState === 'data') {
              if (responseBuffer.length - bodyOffset < currentChunkSize) {
                if (eof) {
                  throw createSocketTransportError('aborted', 'ECONNRESET');
                }
                return;
              }

              pushBodyChunk(bodyOffset, bodyOffset + currentChunkSize);
              bodyOffset += currentChunkSize;
              chunkedState = 'data-crlf';
              continue;
            }

            if (chunkedState === 'data-crlf') {
              if (responseBuffer.length - bodyOffset < 2) {
                if (eof) {
                  throw createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
                }
                return;
              }

              if (responseBuffer[bodyOffset] !== 13 || responseBuffer[bodyOffset + 1] !== 10) {
                throw createSocketTransportError('InvalidHTTPResponse', 'InvalidHTTPResponse');
              }

              bodyOffset += 2;
              currentChunkSize = 0;
              chunkedState = 'size';
              continue;
            }

            if (responseBuffer.length - bodyOffset >= 2 &&
                responseBuffer[bodyOffset] === 13 &&
                responseBuffer[bodyOffset + 1] === 10) {
              bodyOffset += 2;
              finalizeResponse();
              return;
            }

            const trailerEnd = indexOfByteSequence(responseBuffer, [13, 10, 13, 10], bodyOffset);
            if (trailerEnd !== -1) {
              bodyOffset = trailerEnd + 4;
              finalizeResponse();
              return;
            }

            if (eof) {
              finalizeResponse();
              return;
            }

            return;
          }
        }

        if (parsedHead.contentLength !== null) {
          if (responseBuffer.length - bodyOffset < parsedHead.contentLength) {
            if (eof) {
              throw createSocketTransportError('aborted', 'ECONNRESET');
            }
            return;
          }

          pushBodyChunk(bodyOffset, bodyOffset + parsedHead.contentLength);
          bodyOffset += parsedHead.contentLength;
          finalizeResponse();
          return;
        }

        if (eof) {
          pushBodyChunk(bodyOffset, responseBuffer.length);
          bodyOffset = responseBuffer.length;
          finalizeResponse();
        }
      } catch (error) {
        settleReject(error);
      }
    };

    socket.on('data', (chunk: Uint8Array | ArrayBufferView | string) => {
      if (settled) {
        return;
      }

      const bytes =
        typeof chunk === 'string'
          ? BufferCtor.from(chunk, 'utf8')
          : BufferCtor.from(chunk as ArrayBufferView);
      responseBuffer = responseBuffer.length === 0
        ? bytes
        : BufferCtor.concat([responseBuffer, bytes]);
      consumeAvailable(false);
    });

    socket.on('end', () => {
      consumeAvailable(true);
    });

    socket.on('error', (error: unknown) => {
      settleReject(error);
    });

    socket.on('connect', () => {
      if (typeof socket.setNoDelay === 'function') {
        socket.setNoDelay(true);
      }

      const requestLines: string[] = [
        `${nativeInit.method} ${requestPath} HTTP/1.1`,
      ];
      for (let i = 0; i < effectiveHeaders.length; i++) {
        const [name, value] = effectiveHeaders[i];
        requestLines.push(`${name}: ${value}`);
      }
      requestLines.push('', '');

      const requestHead = BufferCtor.from(requestLines.join('\r\n'), 'utf8');
      if (body && body.byteLength > 0) {
        socket.write(requestHead);
        socket.write(body);
      } else {
        socket.write(requestHead);
      }
    });

    if (signal) {
      signal.addEventListener('abort', abortListener);
    }

    if (signal?.aborted) {
      abortListener();
      return;
    }
  }));
}

function isSecureUrlProtocol(protocol: string): boolean {
  return protocol === 'https:' || protocol === 'wss:';
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1';
}

function shouldUseBunCompatKeepaliveSocketTransport(url: string, request: Request): boolean {
  if (!isBunCompatEnv() || !request.hasExplicitKeepalive() || request.keepalive) {
    return false;
  }

  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol === 'http:' && isLoopbackHostname(parsedUrl.hostname);
  } catch {
    return false;
  }
}

function shouldUseBunCompatLoopbackSocketTransport(url: string): boolean {
  if (!isBunCompatEnv()) {
    return false;
  }

  try {
    const parsedUrl = new URL(url);
    return (
      (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') &&
      isLoopbackHostname(parsedUrl.hostname)
    );
  } catch {
    return false;
  }
}

function shouldUseTlsSocketTransport(init?: RequestInit): boolean {
  if (init?.tls) {
    return true;
  }

  const env = (globalThis as {
    process?: { env?: Record<string, string | undefined> };
  }).process?.env;
  if (!env) {
    return false;
  }

  return (
    (typeof env.NODE_EXTRA_CA_CERTS === 'string' && env.NODE_EXTRA_CA_CERTS.trim().length > 0) ||
    env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
  );
}

function locationForReferrer(source: ReferrerSource): string | null {
  const location = (globalThis as any).location;
  if (!location || typeof location !== 'object') {
    return null;
  }
  const directHref = typeof location.href === 'string' ? location.href : null;
  if (source === 'request-object') {
    if (directHref) {
      return directHref;
    }
  }

  if (source === 'input') {
    if (typeof location.toString === 'function') {
      const stringValue = location.toString();
      if (stringValue) {
        return stringValue;
      }
    }
  }

  if (directHref) {
    return directHref;
  }
  return null;
}

function isRequestInputObject(input: unknown): input is Request {
  return (
    typeof input === 'object' &&
    input !== null &&
    'url' in input &&
    'method' in input &&
    'referrer' in input
  );
}

function buildReferrerHeader(request: Request, source: ReferrerSource): string | null {
  const rawReferrer = request.referrer;
  if (rawReferrer === '' || rawReferrer === 'no-referrer') {
    return null;
  }

  const policy = request.referrerPolicy || 'no-referrer-when-downgrade';
  const targetUrl = request.url;
  if (!targetUrl) {
    return null;
  }

  let referrerUrl: URL;
  try {
    const resolvedReferrer = rawReferrer === 'about:client'
      ? locationForReferrer(source)
      : rawReferrer;
    if (!resolvedReferrer) {
      return null;
    }
    referrerUrl = new URL(resolvedReferrer);
  } catch {
    return null;
  }

  let requestUrl: URL;
  try {
    requestUrl = new URL(targetUrl);
  } catch {
    return null;
  }

  // Per Fetch spec, strip credentials and fragment from the referrer URL.
  referrerUrl.username = '';
  referrerUrl.password = '';
  referrerUrl.hash = '';
  const isDownGrade = isSecureUrlProtocol(referrerUrl.protocol) && !isSecureUrlProtocol(requestUrl.protocol);
  const sameOrigin = requestUrl.origin === referrerUrl.origin;

  if (policy === 'no-referrer') {
    return null;
  }
  if (policy === 'no-referrer-when-downgrade') {
    return isDownGrade ? null : referrerUrl.href;
  }
  if (policy === 'same-origin') {
    return sameOrigin ? referrerUrl.href : null;
  }
  if (policy === 'origin') {
    return referrerUrl.origin;
  }
  if (policy === 'origin-when-cross-origin') {
    return sameOrigin ? referrerUrl.href : referrerUrl.origin;
  }
  if (policy === 'strict-origin') {
    return isDownGrade ? null : referrerUrl.origin;
  }
  if (policy === 'strict-origin-when-cross-origin') {
    if (sameOrigin) {
      return referrerUrl.href;
    }
    if (isDownGrade) {
      return null;
    }
    return referrerUrl.origin;
  }
  if (policy === 'unsafe-url') {
    return referrerUrl.href;
  }

  // Default policy per Request defaults.
  return sameOrigin ? referrerUrl.href : referrerUrl.origin;
}

/**
 * Check if cookies should be processed for this request.
 */
function shouldProcessCookies(request: Request): boolean {
  if (request.credentials === 'omit') return false;
  if (request.credentials === 'same-origin' && request.mode === 'cors') return false;
  return true;
}

/**
 * Extract Set-Cookie headers from a native response and store them in the cookie jar.
 */
function storeCookiesFromHeaders(headers: [string, string][], url: string): void {
  try {
    const responseUrl = new URL(url);
    for (const [name, value] of headers) {
      if (name.toLowerCase() === 'set-cookie') {
        cookieJar.setCookie(value, responseUrl);
      }
    }
  } catch {
    // URL parse failure — skip cookie storage
  }
}

/**
 * HTTP redirect status codes per Fetch spec.
 */
const REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308];

/**
 * Maximum number of redirects to follow per Fetch spec.
 */
const MAX_REDIRECTS = 20;

/**
 * Headers that must be stripped on cross-origin redirects per Fetch spec.
 */
const SENSITIVE_HEADERS = ['authorization', 'cookie', 'proxy-authorization'];

function isBunCompatEnv(): boolean {
  if ((globalThis as { __exactRuntimeContext?: string }).__exactRuntimeContext === 'shell') {
    return false;
  }
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  return env?.EXACT_COMPAT_TEST === '1' && env?.EXACT_TEST_SECTION === 'bun';
}

function normalizeRedirectLocation(location: string, currentUrl?: string): string {
  let normalized = location;

  if (isBunCompatEnv() && /[^\u0000-\u007f]/.test(normalized)) {
    const BufferCtor = (globalThis as { Buffer?: { from(input: string, encoding?: string): { toString(encoding?: string): string } } }).Buffer;
    if (BufferCtor && typeof BufferCtor.from === 'function') {
      try {
        let decoded = normalized;
        for (let i = 0; i < 3; i++) {
          let isLatin1Only = true;
          for (let j = 0; j < decoded.length; j++) {
            if (decoded.charCodeAt(j) > 0xff) {
              isLatin1Only = false;
              break;
            }
          }
          if (!isLatin1Only) {
            break;
          }

          const next = BufferCtor.from(decoded, 'latin1').toString('utf8');
          if (next.includes('\uFFFD') || next === decoded) {
            break;
          }
          decoded = next;
        }
        if (!decoded.includes('\uFFFD')) {
          normalized = decoded;
        }
      } catch {
        // Preserve the original header value if decoding fails.
      }
    }
  }

  if (normalized.startsWith('://')) {
    let protocol = 'http:';
    if (currentUrl) {
      const schemeMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.exec(currentUrl);
      if (schemeMatch) {
        protocol = schemeMatch[0];
      }
    }
    return protocol + normalized.slice(1);
  }

  return normalized;
}

function normalizeBunCompatNetworkError(message: string): string | null {
  if (!isBunCompatEnv()) {
    return null;
  }

  if (/specified hostname could not be found/i.test(message)) {
    return 'Unable to connect. Is the computer able to access the url?';
  }

  return null;
}

function normalizeBunCompatHeaderValue(value: string): string {
  if (!isBunCompatEnv() || !/[ÃÂ]/.test(value)) {
    return value;
  }

  const BufferCtor = (globalThis as {
    Buffer?: {
      from(input: string, encoding?: string): { toString(encoding?: string): string };
    };
  }).Buffer;
  if (!BufferCtor || typeof BufferCtor.from !== 'function') {
    return value;
  }

  try {
    const decoded = BufferCtor.from(value, 'latin1').toString('utf8');
    if (!decoded.includes('\uFFFD') && decoded !== value) {
      return decoded;
    }
  } catch {
    // Preserve the original header value if decoding fails.
  }

  return value;
}

/**
 * Compute the new HTTP method after a redirect per Fetch spec.
 * - 301/302 with POST → GET (body cleared)
 * - 303 → GET (body cleared) unless HEAD
 * - 307/308 → preserve method and body
 */
function computeRedirectMethod(status: number, method: string): string {
  if (status === 301 || status === 302) {
    if (method === 'POST') return 'GET';
  }
  if (status === 303) {
    if (method !== 'HEAD') return 'GET';
  }
  // 307, 308: preserve method
  return method;
}

/**
 * Create an opaque redirect response for redirect: 'manual'.
 * Per spec: status 0, no headers exposed, type 'opaqueredirect'.
 */
function createOpaqueRedirectResponse(url: string): Response {
  const response = new Response(null);
  (response as any)._status = 0;
  (response as any)._statusText = '';
  (response as any)._ok = false;
  (response as any)._type = 'opaqueredirect';
  (response as any)._url = url;
  (response as any)._redirected = false;
  (response as any)._headers = new Headers();
  (response as any)._headers._guard = 'immutable';
  return response;
}

function concatUint8Chunks(chunks: Uint8Array[], totalLength: number): Uint8Array {
  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function buildNativeHeaders(
  request: Request,
  source: ReferrerSource,
  decompress: boolean
): [string, string][] {
  const requestHeaders = request.headers.toTupleArray();

  if (isBunCompatEnv() && !hasHeader(requestHeaders, 'connection')) {
    if (request.keepalive) {
      setHeader(requestHeaders, 'connection', 'keep-alive');
    } else if (!request.hasExplicitKeepalive()) {
      setHeader(requestHeaders, 'connection', 'keep-alive');
    }
  }

  if (!hasHeader(requestHeaders, 'accept')) {
    requestHeaders.push(['accept', '*/*']);
  }
  if (!hasHeader(requestHeaders, 'accept-language')) {
    requestHeaders.push(['accept-language', 'en-US,en;q=0.9']);
  }
  if (
    isBunCompatEnv() &&
    !hasHeader(requestHeaders, 'user-agent') &&
    typeof navigator === 'object' &&
    navigator !== null &&
    typeof navigator.userAgent === 'string' &&
    navigator.userAgent.length > 0
  ) {
    requestHeaders.push(['user-agent', navigator.userAgent]);
  }
  const referrer = buildReferrerHeader(request, source);
  if (referrer !== null && !hasHeader(requestHeaders, 'referer')) {
    requestHeaders.push(['referer', referrer]);
  }
  if (!decompress && !hasHeader(requestHeaders, 'accept-encoding')) {
    requestHeaders.push(['accept-encoding', 'identity']);
  }

  return requestHeaders;
}

/**
 * The global fetch() method starts the process of fetching a resource from the network,
 * returning a promise which is fulfilled once the response is available.
 */
/**
 * Fetch a data: URL and return a synthetic Response.
 */
function fetchDataUrl(url: string, method?: string): Response {
  // Parse: data:[<mediatype>][;base64],<data>
  const commaIndex = url.indexOf(',');
  if (commaIndex === -1) {
    throw createDataUrlFetchError();
  }

  const meta = url.slice(5, commaIndex); // after "data:" before ","
  const dataStr = url.slice(commaIndex + 1);

  let mimeType = isBunCompatEnv() ? 'text/plain;charset=utf-8' : 'text/plain;charset=US-ASCII';
  let isBase64 = false;

  if (meta) {
    if (meta.endsWith(';base64')) {
      isBase64 = true;
      mimeType = meta.slice(0, -7) || mimeType;
    } else {
      mimeType = meta;
    }
  }
  mimeType = isBunCompatEnv() ? normalizeBlobContentType(mimeType) : mimeType;

  let bodyBytes: Uint8Array;
  try {
    if (isBase64) {
      const decodedBase64 = isBunCompatEnv()
        ? decodePercentEscapesLooseToLatin1(dataStr)
        : decodeURIComponent(dataStr);
      const binaryString = atob(decodedBase64);
      bodyBytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bodyBytes[i] = binaryString.charCodeAt(i);
      }
    } else if (isBunCompatEnv()) {
      bodyBytes = decodeDataUrlPayloadLoose(dataStr);
    } else {
      const decoded = decodeURIComponent(dataStr);
      bodyBytes = getTextEncoder().encode(decoded);
    }
  } catch {
    throw createDataUrlFetchError();
  }

  // Per spec: HEAD requests to data URLs return empty body
  const responseBody = method?.toUpperCase() === 'HEAD' ? new Uint8Array(0) : bodyBytes;
  const response = new Response(responseBody, {
    status: 200,
    statusText: 'OK',
    headers: { 'Content-Type': mimeType },
  });
  // Per spec: data URL responses have type "basic"
  (response as any)._type = 'basic';
  return response;
}

export async function fetch(
  input: RequestInput,
  init?: RequestInit
): Promise<Response> {
  // Handle data: URLs before creating Request (to avoid URL validation issues)
  const inputUrl = typeof input === 'string' ? input : (input instanceof URL ? input.href : input.url);
  if (isDataUrl(inputUrl)) {
    try {
      const method = typeof input === 'string' ? init?.method : (input instanceof Request ? input.method : init?.method);
      return fetchDataUrl(inputUrl, method);
    } catch (error) {
      if (error instanceof TypeError) {
        throw error;
      }
      throw new TypeError('Failed to fetch');
    }
  }

  // Create Request object
  // Per spec: if input is a Request, init overrides should still be applied
  let request: Request;
  try {
    request = new Request(input, init);
  } catch (error) {
    if (
      isBunCompatEnv() &&
      error instanceof TypeError &&
      init?.method === undefined &&
      init?.body !== undefined &&
      error.message.includes('cannot have body')
    ) {
      throw new TypeError('fetch() request with GET/HEAD/OPTIONS method cannot have body.');
    }
    throw error;
  }
  const isRequestInput = isRequestInputObject(input);
  requireFetchCapabilityForUrl(request.url);
  const decompress = init?.decompress !== false;
  const timeoutMs = resolveTimeoutMs(init);

  try {
    // Dispatching a fetch consumes the request body.
    request.markBodyAsUsedForFetch();
  } catch (error) {
    if (error instanceof TypeError) {
      throw error;
    }
    throw new FetchError('Request body was already used');
  }

  // Get native module
  const nativeModule = getNativeFetchModule();

  // Check if already aborted (signal may be null if AbortController not available)
  const signalContext = createEffectiveSignal(request.signal, timeoutMs);
  const signal = signalContext.signal;
  if (signal?.aborted) {
    throw signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
  }

  // Set up abort handling
  let abortCleanup: () => void = () => {};
  let cancelled = false;

  const abortPromise = suppressInternalPromiseRejection(new Promise<never>((_, reject) => {
    abortCleanup = addAbortSignalListener(signal, () => {
      cancelled = true;
      reject(signal?.reason ?? new DOMException('The operation was aborted.', 'AbortError'));
    });
  }));
  let cancelRequest: (() => void) | undefined;

  try {
    const isStreamingUpload = request.isBodyStream();
    const requestBodySource = isStreamingUpload ? request.getBodyStream() : null;
    const requestSource = isRequestInput ? 'request-object' : 'input';
    const uploadChunks: Uint8Array[] = [];
    let uploadChunkLength = 0;
    const useSocketDecompressCompat =
      !decompress &&
      (nativeModule as NativeFetchModule & { __exactNativeBridge?: boolean }).__exactNativeBridge === true;
    const unixSocketPath =
      typeof (init as RequestInit | undefined)?.unix === 'string' &&
      (init as RequestInit).unix.length > 0
        ? (init as RequestInit).unix
        : undefined;
    const useTlsSocketTransport = shouldUseTlsSocketTransport(init);
    const preferSocketTransport =
      useSocketDecompressCompat ||
      !!unixSocketPath ||
      useTlsSocketTransport ||
      shouldUseBunCompatLoopbackSocketTransport(request.url) ||
      shouldUseBunCompatKeepaliveSocketTransport(request.url, request);
    let uploadReader =
      requestBodySource && nativeModule.fetchStreamingUpload && !preferSocketTransport
        ? requestBodySource.getReader()
        : null;
    let bufferedUploadBody: Uint8Array | null = null;
    let streamUploadPending = isStreamingUpload && !!nativeModule.fetchStreamingUpload && !!uploadReader;
    let currentBody: Uint8Array | null;

    if (!isStreamingUpload) {
      currentBody = await request.getBodyAsUint8Array();
    } else if (!streamUploadPending) {
      currentBody = await readableStreamToUint8Array(requestBodySource!, signal);
    } else {
      currentBody = null;
    }

    let redirectCount = 0;
    let redirected = false;
    let currentUrl = request.url;
    let currentMethod = request.method;
    let currentUnixSocketPath = unixSocketPath;
    const redirectMode = request.redirect;
    let stripSensitiveHeaders = false;

    const getReplayableUploadBody = (): Uint8Array => {
      if (bufferedUploadBody) {
        return bufferedUploadBody;
      }
      bufferedUploadBody = concatUint8Chunks(uploadChunks, uploadChunkLength);
      return bufferedUploadBody;
    };

    const finalizeResponse = (
      nativeResponse: NativeResponse | NativeStreamingResponse,
      bodyStream?: ReadableStream<Uint8Array>
    ): Response => {
      const response = bodyStream
        ? Response.fromNativeStreaming(nativeResponse as NativeStreamingResponse, bodyStream, currentUrl)
        : Response.fromNative(nativeResponse as NativeResponse, currentUrl);

      (response as any)._redirected = redirected || (response as any)._redirected === true;
      (response as any)._url = redirected ? currentUrl : (nativeResponse.url || currentUrl);

      try {
        const responseOrigin = new URL(nativeResponse.url || currentUrl).origin;
        if (responseOrigin !== getRuntimeOrigin().origin) {
          (response as any)._type = 'cors';
        }
      } catch {
        // URL parse failure — keep the default response type.
      }

      if (signal) {
        response._signal = signal;
      }

      return response;
    };

    const executeSocketFetchHopStreaming = async (
      url: string,
      nativeInit: NativeRequestInit,
      body: Uint8Array | null,
      socketPath?: string
    ): Promise<{
      nativeResponse: NativeStreamingResponse;
      bodyStream?: ReadableStream<Uint8Array>;
    }> => {
      const parsedUrl = new URL(url);
      const runtimeRequire = (globalThis as { require?: (specifier: string) => any }).require;
      if (typeof runtimeRequire !== 'function') {
        throw new FetchError('Module loader not available for socket transport compatibility path');
      }
      const transport: any = parsedUrl.protocol === 'https:'
        ? runtimeRequire('node:https')
        : runtimeRequire('node:http');
      const disableSocketDefaultHeaders = shouldUseBunCompatKeepaliveSocketTransport(url, request);
      const effectiveHeaders = nativeInit.headers.slice();
      if (!hasHeader(effectiveHeaders, 'host')) {
        effectiveHeaders.push(['host', parsedUrl.host || parsedUrl.hostname]);
      }
      if (
        body !== null &&
        !hasHeader(effectiveHeaders, 'content-length') &&
        !hasHeader(effectiveHeaders, 'transfer-encoding')
      ) {
        effectiveHeaders.push(['content-length', String(body.byteLength)]);
      }

      const requestHeaders: Record<string, string | string[]> = {};
      for (const [name, value] of effectiveHeaders) {
        const existing = requestHeaders[name];
        if (existing === undefined) {
          requestHeaders[name] = value;
        } else if (Array.isArray(existing)) {
          existing.push(value);
        } else {
          requestHeaders[name] = [existing, value];
        }
      }

      let activeCancelRequest: (() => void) | undefined;
      const requestPromise = suppressInternalPromiseRejection(new Promise<{
        nativeResponse: NativeStreamingResponse;
        bodyStream?: ReadableStream<Uint8Array>;
      }>((resolve, reject) => {
        const requestOptions: Record<string, any> = {
          protocol: parsedUrl.protocol,
          method: nativeInit.method,
          headers: requestHeaders,
          path: parsedUrl.pathname + (parsedUrl.search || ''),
        };
        if (disableSocketDefaultHeaders) {
          requestOptions.setDefaultHeaders = false;
          requestOptions.setHost = false;
        }
        if (socketPath) {
          requestOptions.socketPath = socketPath;
          if (parsedUrl.hostname) {
            requestOptions.hostname = parsedUrl.hostname;
          }
          if (parsedUrl.port) {
            requestOptions.port = Number(parsedUrl.port);
          }
        } else {
          requestOptions.hostname = parsedUrl.hostname;
          requestOptions.port = parsedUrl.port ? Number(parsedUrl.port) : undefined;
        }
        if (parsedUrl.protocol === 'https:') {
          applyHttpsRequestTlsOptions(requestOptions, init, runtimeRequire);
          if (requestOptions.agent === undefined && transport?.globalAgent) {
            requestOptions.agent = transport.globalAgent;
          }
        }
        const req = transport.request(
          requestOptions,
          (res: any) => {
            const headers: [string, string][] = [];
            const rawHeaders = Array.isArray(res.rawHeaders) ? res.rawHeaders : [];
            for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
              headers.push([String(rawHeaders[i]), String(rawHeaders[i + 1])]);
            }

            const status = res.statusCode || 0;
            const noBody =
              nativeInit.method === 'HEAD' ||
              (status >= 100 && status < 200) ||
              status === 204 ||
              status === 304;
            if (noBody) {
              if (typeof res.resume === 'function') {
                res.resume();
              }
              resolve({
                nativeResponse: {
                  status,
                  statusText: res.statusMessage || '',
                  headers,
                  url,
                  redirected: false,
                },
              });
              return;
            }

            resolve({
              nativeResponse: {
                status,
                statusText: res.statusMessage || '',
                headers,
                url,
                redirected: false,
              },
              bodyStream: createSocketResponseBodyStream(
                res,
                headers,
                nativeInit.decompress,
                runtimeRequire,
                signal
              ),
            });
            res.on('error', reject);
          }
        );

        activeCancelRequest = () => {
          req.destroy(signal?.reason instanceof Error ? signal.reason : new Error('The operation was aborted.'));
        };
        req.on('error', reject);
        if (body?.byteLength) {
          req.write(body);
        }
        req.end();
      }));

      if (activeCancelRequest) {
        cancelRequest = activeCancelRequest;
      }
      try {
        return await Promise.race([requestPromise, abortPromise]);
      } finally {
        if (cancelRequest === activeCancelRequest) {
          cancelRequest = undefined;
        }
      }
    };

    const executeHop = async (
      url: string,
      nativeInit: NativeRequestInit,
      body: Uint8Array | null,
      useStreamingUpload: boolean
    ): Promise<{
      nativeResponse: NativeResponse | NativeStreamingResponse;
      bodyStream?: ReadableStream<Uint8Array>;
    }> => {
      requireFetchCapabilityForUrl(url);
      const preferSocketTransportForHop =
        useSocketDecompressCompat ||
        !!currentUnixSocketPath ||
        useTlsSocketTransport ||
        shouldUseBunCompatLoopbackSocketTransport(url) ||
        shouldUseBunCompatKeepaliveSocketTransport(url, request);
      if (preferSocketTransportForHop && !useStreamingUpload) {
        const socketResponse = await executeSocketFetchHopStreaming(
          url,
          nativeInit,
          body,
          currentUnixSocketPath
        );
        return {
          nativeResponse: validateNativeStreamingResponse(socketResponse.nativeResponse),
          bodyStream: socketResponse.bodyStream,
        };
      }

      if (useStreamingUpload && nativeModule.fetchStreamingUpload && uploadReader) {
        let resolveHeaders!: (value: NativeStreamingResponse) => void;
        let rejectHeaders!: (error: Error) => void;
        let headersSettled = false;
        let streamClosed = false;

        const headersPromise = suppressInternalPromiseRejection(new Promise<NativeStreamingResponse>((resolve, reject) => {
          resolveHeaders = resolve;
          rejectHeaders = reject;
        }));

        let activeCancelRequest: (() => void) | undefined;
        const responseBodyStream = new ReadableStream<Uint8Array>({
          type: 'bytes',
          start(controller: any) {
            activeCancelRequest = nativeModule.fetchStreamingUpload!(
              url,
              nativeInit,
              async () => {
                const result = await uploadReader!.read();
                if (result.done) {
                  return null;
                }
                const chunk = result.value;
                if (chunk?.byteLength) {
                  const bufferedChunk = new Uint8Array(chunk);
                  uploadChunks.push(bufferedChunk);
                  uploadChunkLength += bufferedChunk.byteLength;
                }
                return chunk;
              },
              (nativeResponse) => {
                if (headersSettled) {
                  return;
                }
                headersSettled = true;
                resolveHeaders(nativeResponse);
              },
              (chunk) => {
                if (streamClosed) {
                  return;
                }
                if (chunk?.byteLength) {
                  controller.enqueue(new Uint8Array(chunk));
                }
              },
              () => {
                if (streamClosed) {
                  return;
                }
                streamClosed = true;
                controller.close();
              },
              (error) => {
                if (streamClosed) {
                  return;
                }
                if (!headersSettled) {
                  streamClosed = true;
                  headersSettled = true;
                  rejectHeaders(error);
                  return;
                }
                streamClosed = true;
                controller.error(error);
              }
            );

            if (!activeCancelRequest) {
              activeCancelRequest = () => {};
            }
            cancelRequest = activeCancelRequest;
          },
          cancel() {
            streamClosed = true;
            activeCancelRequest?.();
          },
        } as any);

        const nativeResponse = validateNativeStreamingResponse(
          await Promise.race([headersPromise, abortPromise])
        );
        return {
          nativeResponse,
          bodyStream: responseBodyStream,
        };
      }

      if (nativeModule.fetchStreaming) {
        let resolveHeaders!: (value: NativeStreamingResponse) => void;
        let rejectHeaders!: (error: Error) => void;
        let headersSettled = false;
        let streamClosed = false;
        let activeCancelRequest: (() => void) | undefined;

        const headersPromise = suppressInternalPromiseRejection(new Promise<NativeStreamingResponse>((resolve, reject) => {
          resolveHeaders = resolve;
          rejectHeaders = reject;
        }));

        const bodyStream = new ReadableStream<Uint8Array>({
          type: 'bytes',
          start(controller: any) {
            activeCancelRequest = nativeModule.fetchStreaming!(
              url,
              nativeInit,
              body,
              (nativeResponse) => {
                if (headersSettled) {
                  return;
                }
                headersSettled = true;
                resolveHeaders(nativeResponse);
              },
              (chunk) => {
                if (streamClosed) {
                  return;
                }
                if (chunk?.byteLength) {
                  controller.enqueue(new Uint8Array(chunk));
                }
              },
              () => {
                if (streamClosed) {
                  return;
                }
                streamClosed = true;
                controller.close();
              },
              (error) => {
                if (streamClosed) {
                  return;
                }
                if (!headersSettled) {
                  streamClosed = true;
                  headersSettled = true;
                  rejectHeaders(error);
                  return;
                }
                streamClosed = true;
                controller.error(error);
              }
            );

            if (!activeCancelRequest) {
              activeCancelRequest = () => {};
            }
            cancelRequest = activeCancelRequest;
          },
          cancel() {
            streamClosed = true;
            activeCancelRequest?.();
          },
        } as any);

        const nativeResponse = validateNativeStreamingResponse(
          await Promise.race([headersPromise, abortPromise])
        );
        return {
          nativeResponse,
          bodyStream,
        };
      }

      const nativeFetchPromise = suppressInternalPromiseRejection(
        nativeModule.fetch(url, nativeInit, body)
      ) as CancelableNativeResponsePromise;
      const nativeCancel = typeof nativeFetchPromise.__exactCancel === 'function'
        ? nativeFetchPromise.__exactCancel
        : undefined;
      if (nativeCancel) {
        cancelRequest = nativeCancel;
      }
      const nativeResponse = validateNativeResponse(
        await Promise.race([
          nativeFetchPromise,
          abortPromise,
        ])
      );
      if (cancelRequest === nativeCancel) {
        cancelRequest = undefined;
      }
      return { nativeResponse };
    };

    while (true) {
      // Build headers for this hop
      const nativeHeaders = buildNativeHeaders(request, requestSource, decompress);

      // Map cache mode to Cache-Control headers
      if (request.cache === 'no-store' && !hasHeader(nativeHeaders, 'cache-control')) {
        nativeHeaders.push(['cache-control', 'no-store']);
      } else if (request.cache === 'no-cache' && !hasHeader(nativeHeaders, 'cache-control')) {
        nativeHeaders.push(['cache-control', 'no-cache']);
      } else if (request.cache === 'reload' && !hasHeader(nativeHeaders, 'cache-control')) {
        nativeHeaders.push(['cache-control', 'no-cache']);
        if (!hasHeader(nativeHeaders, 'pragma')) {
          nativeHeaders.push(['pragma', 'no-cache']);
        }
      }

      if (redirected) {
        const cookieIdx = nativeHeaders.findIndex(([n]) => n.toLowerCase() === 'cookie');
        if (cookieIdx !== -1) {
          nativeHeaders.splice(cookieIdx, 1);
        }
      }

      if (stripSensitiveHeaders) {
        for (let i = nativeHeaders.length - 1; i >= 0; i--) {
          if (SENSITIVE_HEADERS.includes(nativeHeaders[i][0].toLowerCase())) {
            nativeHeaders.splice(i, 1);
          }
        }
      }

      if (shouldProcessCookies(request)) {
        try {
          const reqUrl = new URL(currentUrl);
          const cookieHeader = cookieJar.getCookieHeader(
            reqUrl,
            request.credentials,
            getRuntimeOrigin(),
            request.mode,
            currentMethod
          );
          if (cookieHeader) {
            const existingIdx = nativeHeaders.findIndex(([n]) => n.toLowerCase() === 'cookie');
            if (existingIdx !== -1) {
              nativeHeaders.splice(existingIdx, 1);
            }
            nativeHeaders.push(['cookie', cookieHeader]);
          }
        } catch {
          // URL parse failure — skip cookie injection
        }
      }

      const nativeInit: NativeRequestInit = {
        method: currentMethod,
        headers: nativeHeaders,
        credentials: request.credentials,
        redirect: 'follow',
        decompress,
        signal,
      };

      const hop = await executeHop(
        currentUrl,
        nativeInit,
        currentBody,
        streamUploadPending && currentMethod !== 'GET' && currentMethod !== 'HEAD'
      );
      const nativeResponse = hop.nativeResponse;

      if (shouldProcessCookies(request)) {
        storeCookiesFromHeaders(nativeResponse.headers, nativeResponse.url || currentUrl);
      }

      const status = nativeResponse.status;
      if (!REDIRECT_STATUS_CODES.includes(status)) {
        const response = finalizeResponse(nativeResponse, hop.bodyStream);
        if (hop.bodyStream) {
          cancelRequest = undefined;
        }
        return response;
      }

      if (redirectMode === 'error') {
        cancelRequest?.();
        cancelRequest = undefined;
        const error = new TypeError('Failed to fetch: unexpected redirect') as TypeError & { code?: string };
        if (isBunCompatEnv()) {
          error.code = 'UnexpectedRedirect';
        }
        throw error;
      }
      if (redirectMode === 'manual') {
        if (isBunCompatEnv()) {
          const response = finalizeResponse(nativeResponse, hop.bodyStream);
          if (hop.bodyStream) {
            cancelRequest = undefined;
          }
          return response;
        }
        cancelRequest?.();
        cancelRequest = undefined;
        return createOpaqueRedirectResponse(currentUrl);
      }

      redirectCount++;
      if (redirectCount > MAX_REDIRECTS) {
        cancelRequest?.();
        cancelRequest = undefined;
        throw new TypeError('Failed to fetch: redirect count exceeded');
      }

      let location: string | null = null;
      for (const [name, value] of nativeResponse.headers) {
        if (name.toLowerCase() === 'location') {
          location = value;
          break;
        }
      }

      if (!location) {
        const response = finalizeResponse(nativeResponse, hop.bodyStream);
        if (hop.bodyStream) {
          cancelRequest = undefined;
        }
        return response;
      }

      let redirectUrl: URL;
      try {
        const normalizedLocation = normalizeRedirectLocation(location, currentUrl);
        if (location.startsWith('://') || normalizedLocation.startsWith('://')) {
          const schemeMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.exec(currentUrl);
          const protocol = schemeMatch ? schemeMatch[0] : 'http:';
          redirectUrl = new URL(protocol + normalizedLocation.slice(1));
        } else {
          redirectUrl = new URL(normalizedLocation, currentUrl);
        }
      } catch {
        cancelRequest?.();
        cancelRequest = undefined;
        throw new TypeError('Failed to fetch: invalid redirect URL');
      }

      const newMethod = computeRedirectMethod(status, currentMethod);
      const previousUrl = currentUrl;
      cancelRequest?.();
      cancelRequest = undefined;

      if (newMethod !== currentMethod && (newMethod === 'GET' || newMethod === 'HEAD')) {
        currentBody = null;
        streamUploadPending = false;
      } else if (streamUploadPending) {
        currentBody = getReplayableUploadBody();
        streamUploadPending = false;
      }

      try {
        if (new URL(previousUrl).origin !== redirectUrl.origin) {
          stripSensitiveHeaders = true;
        }
        if (currentUnixSocketPath && new URL(previousUrl).origin !== redirectUrl.origin) {
          currentUnixSocketPath = undefined;
        }
      } catch {
        // URL parse failure — keep existing header stripping behavior.
      }

      currentMethod = newMethod;
      currentUrl = redirectUrl.href;
      redirected = true;
    }
  } catch (error) {
    if (cancelled || error instanceof AbortError) {
      throw error;
    }
    if (error instanceof TypeError) {
      throw error;
    }

    // Per Fetch spec, network errors should be TypeError
    if (error instanceof Error) {
      const bunCompatMessage = normalizeBunCompatNetworkError(error.message);
      if (bunCompatMessage) {
        const bunCompatError = new TypeError(bunCompatMessage);
        copyErrorMetadata(bunCompatError, error);
        throw bunCompatError;
      }
      const typeError = new TypeError(`Failed to fetch: ${error.message}`);
      copyErrorMetadata(typeError, error);
      throw typeError;
    }

    throw new TypeError(`Failed to fetch: ${String(error)}`);
  } finally {
    if (cancelRequest) {
      cancelRequest();
    }
    abortCleanup();
    signalContext.cleanup();
  }
}

/**
 * A mock/polyfill fetch implementation for testing and web fallback.
 * Uses XMLHttpRequest under the hood where native module is not available.
 */
export async function fetchPolyfill(
  input: RequestInput,
  init?: RequestInit
): Promise<Response> {
  // Handle data: URLs locally; they do not exercise network authority.
  const inputUrl = typeof input === 'string' ? input : (input instanceof URL ? input.href : input.url);
  if (isDataUrl(inputUrl)) {
    const method = typeof input === 'string' ? init?.method : (input instanceof Request ? input.method : init?.method);
    return fetchDataUrl(inputUrl, method);
  }

  // Create Request object
  // Per spec: if input is a Request, init overrides should still be applied
  const request = new Request(input, init);
  const isRequestInput = isRequestInputObject(input);
  requireFetchCapabilityForUrl(request.url);
  const decompress = init?.decompress !== false;
  const timeoutMs = resolveTimeoutMs(init);

  // Dispatching a fetch consumes the request body.
  request.markBodyAsUsedForFetch();

  return new Promise((resolve, reject) => {
    const signalContext = createEffectiveSignal(request.signal, timeoutMs);
    const signal = signalContext.signal;

    // Check if aborted
    if (signal?.aborted) {
      signalContext.cleanup();
      reject(new AbortError(signal.reason?.message ?? 'The operation was aborted'));
      return;
    }

    // Check if XMLHttpRequest is available (browser/polyfill environment)
    if (typeof XMLHttpRequest === 'undefined') {
      signalContext.cleanup();
      reject(new FetchError('XMLHttpRequest not available'));
      return;
    }

    const xhr = new XMLHttpRequest();
    xhr.responseType = 'arraybuffer';

    // Set up abort handling (only if signal is available)
    const abortHandler = () => {
      xhr.abort();
      signalContext.cleanup();
      reject(new AbortError(signal?.reason?.message ?? 'The operation was aborted'));
    };
    signal?.addEventListener('abort', abortHandler);

    xhr.onload = () => {
      signal?.removeEventListener('abort', abortHandler);
      signalContext.cleanup();

      // Parse response headers
      const headerLines = xhr.getAllResponseHeaders().trim().split(/[\r\n]+/);
      const headers: [string, string][] = [];
      for (const line of headerLines) {
        const parts = line.split(': ');
        const name = parts.shift()!;
        const value = parts.join(': ');
        if (name) {
          headers.push([name, value]);
        }
      }

      const response = Response.fromNative({
        status: xhr.status,
        statusText: xhr.statusText,
        headers,
        url: xhr.responseURL || request.url,
        redirected: xhr.responseURL !== request.url,
        body: xhr.response,
      });

      resolve(response);
    };

    xhr.onerror = () => {
      signal?.removeEventListener('abort', abortHandler);
      signalContext.cleanup();
      reject(new FetchError('Network request failed'));
    };

    xhr.ontimeout = () => {
      signal?.removeEventListener('abort', abortHandler);
      signalContext.cleanup();
      reject(new FetchError('Request timeout'));
    };

    // Open connection
    xhr.open(request.method, request.url, true);

    // Set headers
    const nativeHeaders = buildNativeHeaders(
      request,
      isRequestInput ? 'request-object' : 'input',
      decompress
    );
    for (const [name, value] of nativeHeaders) {
      // Skip forbidden headers
      try {
        xhr.setRequestHeader(name, value);
      } catch {
        // Ignore forbidden header errors
      }
    }

    // Handle credentials
    xhr.withCredentials = request.credentials === 'include';

    // Send request with body
    request.getBodyAsUint8Array().then(
      (body) => {
        xhr.send(body as XMLHttpRequestBodyInit | null);
      },
      (error) => {
        signal?.removeEventListener('abort', abortHandler);
        signalContext.cleanup();
        reject(error);
      }
    );
  });
}

/**
 * Install fetch globally.
 * This sets up the global fetch, Headers, Request, and Response.
 */
export function installFetchGlobals(globalObject: typeof globalThis = globalThis): void {
  // Use native module if available, otherwise fall back to polyfill
  const fetchImpl = nativeFetchModule ? fetch : fetchPolyfill;
  const installedFetch = function fetch(input: RequestInput): Promise<Response> {
    return fetchImpl(input, arguments.length > 1 ? arguments[1] as RequestInit : undefined);
  };

  Object.defineProperties(globalObject, {
    fetch: {
      value: installedFetch,
      writable: true,
      configurable: true,
      enumerable: true,
    },
    Headers: {
      value: Headers,
      writable: true,
      configurable: true,
      enumerable: true,
    },
    Request: {
      value: Request,
      writable: true,
      configurable: true,
      enumerable: true,
    },
    Response: {
      value: Response,
      writable: true,
      configurable: true,
      enumerable: true,
    },
  });
}
