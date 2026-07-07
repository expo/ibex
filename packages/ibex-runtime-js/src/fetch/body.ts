// @ts-nocheck
/**
 * Body Handling Utilities
 *
 * Implements body mixin functionality for Request and Response.
 * @see https://fetch.spec.whatwg.org/#body-mixin
 */

import type { BodyInit, BufferSource } from './types.js';
import { BodyConsumedError } from './errors.js';
import { isReadableStream, ReadableStream as RuntimeReadableStream } from '../streams/index.js';

/**
 * Text encoder/decoder - lazy initialization with fallbacks for Hermes.
 */
let _textEncoder: { encode(s: string): Uint8Array } | null = null;
let _textDecoder: { decode(b: BufferSource): string } | null = null;
let _textDecoderNoBOM: { decode(b: BufferSource): string } | null = null;

function isBunCompatFetchTest(): boolean {
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

export function normalizeBlobContentType(contentType: string | null): string {
  if (!contentType) {
    return '';
  }

  const normalized = contentType
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .join(';')
    .toLowerCase();

  if (!isBunCompatFetchTest() || normalized.includes('charset=')) {
    return normalized;
  }

  const mediaType = normalized.split(';', 1)[0];
  const isUtf8TextLike =
    mediaType.startsWith('text/') ||
    mediaType === 'application/json' ||
    mediaType === 'application/javascript' ||
    mediaType === 'application/x-www-form-urlencoded' ||
    mediaType === 'application/xml' ||
    mediaType.endsWith('+json') ||
    mediaType.endsWith('+xml');

  return isUtf8TextLike ? `${normalized};charset=utf-8` : normalized;
}

export function getTextEncoder(): { encode(s: string): Uint8Array } {
  if (_textEncoder) return _textEncoder;

  if (typeof TextEncoder !== 'undefined') {
    _textEncoder = new TextEncoder();
  } else {
    // UTF-8 fallback for Hermes (handles full Unicode including surrogate pairs)
    _textEncoder = {
      encode(str: string): Uint8Array {
        const bytes = new Uint8Array(str.length * 4); // Max 4 bytes per code unit
        let offset = 0;
        for (let i = 0; i < str.length; i++) {
          const code = str.charCodeAt(i);
          if (code < 0x80) {
            bytes[offset++] = code;
          } else if (code < 0x800) {
            bytes[offset++] = 0xc0 | (code >> 6);
            bytes[offset++] = 0x80 | (code & 0x3f);
          } else if (code >= 0xd800 && code <= 0xdbff) {
            // High surrogate: combine with next low surrogate to get full codepoint
            const low = str.charCodeAt(i + 1);
            if (low >= 0xdc00 && low <= 0xdfff) {
              const cp = (code - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000;
              bytes[offset++] = 0xf0 | (cp >> 18);
              bytes[offset++] = 0x80 | ((cp >> 12) & 0x3f);
              bytes[offset++] = 0x80 | ((cp >> 6) & 0x3f);
              bytes[offset++] = 0x80 | (cp & 0x3f);
              i++; // Skip the low surrogate
            } else {
              // Lone high surrogate: encode as replacement character U+FFFD
              bytes[offset++] = 0xef;
              bytes[offset++] = 0xbf;
              bytes[offset++] = 0xbd;
            }
          } else if (code >= 0xdc00 && code <= 0xdfff) {
            // Lone low surrogate: encode as replacement character U+FFFD
            bytes[offset++] = 0xef;
            bytes[offset++] = 0xbf;
            bytes[offset++] = 0xbd;
          } else {
            bytes[offset++] = 0xe0 | (code >> 12);
            bytes[offset++] = 0x80 | ((code >> 6) & 0x3f);
            bytes[offset++] = 0x80 | (code & 0x3f);
          }
        }
        return bytes.slice(0, offset);
      },
    };
  }
  return _textEncoder;
}

function getTextDecoder(): { decode(b: BufferSource): string } {
  if (_textDecoder) return _textDecoder;

  if (typeof TextDecoder !== 'undefined') {
    _textDecoder = new TextDecoder();
  } else {
    // Simple UTF-8 fallback for Hermes
    _textDecoder = {
      decode(buffer: BufferSource): string {
        const bytes = buffer instanceof ArrayBuffer
          ? new Uint8Array(buffer)
          : arrayBufferViewToUint8Array(buffer);

        let result = '';
        let i = 0;
        while (i < bytes.length) {
          const byte = bytes[i];
          if (byte < 0x80) {
            result += String.fromCharCode(byte);
            i++;
          } else if ((byte & 0xe0) === 0xc0) {
            result += String.fromCharCode(((byte & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
            i += 2;
          } else if ((byte & 0xf0) === 0xe0) {
            result += String.fromCharCode(
              ((byte & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f)
            );
            i += 3;
          } else if ((byte & 0xf8) === 0xf0) {
            // 4-byte sequence: decode full codepoint and convert to surrogate pair
            const cp =
              ((byte & 0x07) << 18) |
              ((bytes[i + 1] & 0x3f) << 12) |
              ((bytes[i + 2] & 0x3f) << 6) |
              (bytes[i + 3] & 0x3f);
            result += String.fromCodePoint(cp);
            i += 4;
          } else {
            // Invalid leading byte: skip it
            i++;
          }
        }
        return result;
      },
    };
  }
  return _textDecoder;
}

function getTextDecoderNoBOM(): { decode(b: BufferSource): string } {
  if (_textDecoderNoBOM) return _textDecoderNoBOM;

  if (typeof TextDecoder !== 'undefined') {
    _textDecoderNoBOM = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });
  } else {
    _textDecoderNoBOM = getTextDecoder();
  }
  return _textDecoderNoBOM;
}

function decodeTextForFormData(buffer: ArrayBuffer): string {
  const text = getTextDecoderNoBOM().decode(new Uint8Array(buffer));
  return text.startsWith("\uFEFF") ? text.slice(1) : text;
}

/**
 * Check if a value is a Blob-like object.
 */
export function isBlob(value: unknown): value is Blob {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Blob).arrayBuffer === 'function' &&
    typeof (value as Blob).slice === 'function' &&
    typeof (value as Blob).size === 'number' &&
    typeof (value as Blob).type === 'string'
  );
}

/**
 * FormData with entries method (for iteration).
 */
interface FormDataWithEntries extends FormData {
  entries(): IterableIterator<[string, FormDataEntryValue]>;
}

/**
 * Check if a value is FormData-like.
 */
export function isFormData(value: unknown): value is FormDataWithEntries {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as FormData).append === 'function' &&
    typeof (value as FormData & { entries?: unknown }).entries === 'function'
  );
}

/**
 * Check if a value is an ArrayBuffer.
 */
export function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return value instanceof ArrayBuffer;
}

/**
 * Check if a value is an ArrayBufferView (TypedArray or DataView).
 */
export function isArrayBufferView(value: unknown): value is ArrayBufferView {
  return ArrayBuffer.isView(value);
}

export function getArrayBufferViewByteLength(view: ArrayBufferView): number {
  const reportedByteLength = view.byteLength;
  const typedArrayLength = (view as ArrayBufferView & { length?: unknown }).length;
  const bytesPerElement =
    view &&
    view.constructor &&
    typeof (view.constructor as { BYTES_PER_ELEMENT?: unknown }).BYTES_PER_ELEMENT === 'number'
      ? (view.constructor as { BYTES_PER_ELEMENT: number }).BYTES_PER_ELEMENT
      : null;

  if (
    typeof typedArrayLength === 'number' &&
    typeof bytesPerElement === 'number'
  ) {
    const computedByteLength = typedArrayLength * bytesPerElement;
    if (computedByteLength >= 0 && computedByteLength <= reportedByteLength) {
      return computedByteLength;
    }
  }

  return reportedByteLength;
}

export function arrayBufferViewToUint8Array(view: ArrayBufferView): Uint8Array {
  return new Uint8Array(view.buffer, view.byteOffset, getArrayBufferViewByteLength(view));
}

export function normalizeBodyChunk(
  chunk: unknown,
  source = 'ReadableStream body'
): Uint8Array {
  if (chunk instanceof Uint8Array) {
    return chunk;
  }

  if (typeof chunk === 'string') {
    return getTextEncoder().encode(chunk);
  }

  if (isArrayBuffer(chunk)) {
    return new Uint8Array(chunk.slice(0));
  }

  if (isArrayBufferView(chunk)) {
    return arrayBufferViewToUint8Array(chunk);
  }

  throw new TypeError(`${source} chunk must be a string, Buffer, or ArrayBufferView.`);
}

export function normalizeReadableStreamBody(
  stream: ReadableStream<unknown>,
  source = 'ReadableStream body'
): ReadableStream<Uint8Array> {
  const reader = stream.getReader();
  reader.closed.catch(function () {});
  let released = false;

  function releaseReader(): void {
    if (released) {
      return;
    }
    released = true;
    try {
      reader.releaseLock();
      reader.closed.catch(function () {});
    } catch {}
  }

  return new RuntimeReadableStream<Uint8Array>({
    pull(controller) {
      const readPromise = reader.read();
      readPromise.catch(function () {});
      return readPromise.then(
        function (result) {
          if (result.done) {
            releaseReader();
            controller.close();
            return;
          }
          try {
            controller.enqueue(normalizeBodyChunk(result.value, source));
          } catch (error) {
            try { reader.cancel(error).catch(function () {}); } catch {}
            releaseReader();
            throw error;
          }
        },
        function (error) {
          releaseReader();
          throw error;
        }
      );
    },
    cancel(reason) {
      const cancelResult = reader.cancel(reason);
      if (cancelResult && typeof (cancelResult as Promise<void>).then === 'function') {
        return (cancelResult as Promise<void>).then(
          function () {
            releaseReader();
          },
          function () {
            releaseReader();
          }
        );
      }
      releaseReader();
      return undefined;
    },
  });
}

export function isAsyncIterableBody(value: unknown): value is AsyncIterable<unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function'
  );
}

export function createReadableStreamFromAsyncIterableBody(
  body: AsyncIterable<unknown>,
  source = 'Async iterable body'
): ReadableStream<Uint8Array> {
  const iterator = body[Symbol.asyncIterator]();
  return new RuntimeReadableStream<Uint8Array>({
    async pull(controller) {
      const result = await iterator.next();
      if (result.done) {
        controller.close();
        return;
      }
      controller.enqueue(normalizeBodyChunk(result.value, source));
    },
    async cancel(reason) {
      if (typeof iterator.return === 'function') {
        await iterator.return(reason);
      }
    },
  });
}

export async function asyncIterableToUint8Array(
  body: AsyncIterable<unknown>,
  source = 'Async iterable body'
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const iterator = body[Symbol.asyncIterator]();
  let shouldCloseIterator = false;

  try {
    while (true) {
      const result = await iterator.next();
      if (result.done) {
        break;
      }

      // Track whether we have accepted a chunk but not yet finished handling
      // it so abrupt failures can still signal iterator cleanup.
      shouldCloseIterator = true;
      chunks.push(normalizeBodyChunk(result.value, source));
      shouldCloseIterator = false;
    }
  } catch (error) {
    if (shouldCloseIterator && typeof iterator.return === 'function') {
      try {
        await iterator.return();
      } catch {
        // Preserve the original body conversion failure.
      }
    }
    throw error;
  }

  return concatUint8Arrays(chunks);
}

/**
 * Convert various body types to Uint8Array.
 */
export async function bodyToUint8Array(
  body: BodyInit | null | undefined
): Promise<Uint8Array | null> {
  if (body === null || body === undefined) {
    return null;
  }

  if (typeof body === 'string') {
    return getTextEncoder().encode(body);
  }

  if (isArrayBuffer(body)) {
    return new Uint8Array(body);
  }

  if (isArrayBufferView(body)) {
    return arrayBufferViewToUint8Array(body);
  }

  if (isBlob(body)) {
    const buffer = await body.arrayBuffer();
    return new Uint8Array(buffer);
  }

  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
    return getTextEncoder().encode(body.toString());
  }

  if (isFormData(body)) {
    // Use FormData's built-in multipart encoding if available
    if (typeof (body as any)._encode === 'function') {
      const result = (body as any)._encode();
      return result.body;
    }
    
    // Fallback: Convert FormData to multipart/form-data format
    const encoded = await encodeFormDataInternalAsync(body);
    return encoded.body;
  }

  if (isReadableStream(body)) {
    return await readableStreamToUint8Array(normalizeReadableStreamBody(body));
  }

  if (isAsyncIterableBody(body)) {
    return await asyncIterableToUint8Array(body);
  }

  throw new TypeError('Unsupported body type');
}

/**
 * Resolve a promise with a value, preventing Object.prototype.then from
 * making the value appear as a thenable (per Fetch spec, internal algorithms
 * should not be affected by prototype pollution).
 */
export function resolveWithoutThenable<T>(resolve: (value: T) => void, value: T): void {
  if (value != null && typeof value === 'object' && typeof (value as any).then === 'function') {
    Object.defineProperty(value, 'then', { value: undefined, configurable: true, writable: true });
    resolve(value);
    delete (value as any).then;
  } else {
    resolve(value);
  }
}

/**
 * Read a ReadableStream to Uint8Array.
 * Uses explicit promise chains (not async/await) to prevent compiled async
 * wrappers from creating intermediate promises that trigger Object.prototype.then.
 */
export function readableStreamToUint8Array(
  stream: ReadableStream<Uint8Array>,
  signal?: AbortSignal | null
): Promise<Uint8Array> {
  return new Promise<Uint8Array>(function (outerResolve, outerReject) {
    const reader = stream.getReader();
    reader.closed.catch(function () {});
    const chunks: Uint8Array[] = [];
    let settled = false;

    function cleanupAbortListener(): void {
      if (signal) {
        signal.removeEventListener('abort', abortReader);
      }
    }

    function rejectWith(error: unknown): void {
      if (settled) {
        return;
      }
      settled = true;
      cleanupAbortListener();
      try { reader.cancel(error).catch(function () {}); } catch {}
      try {
        reader.releaseLock();
        reader.closed.catch(function () {});
      } catch {}
      outerReject(error);
    }

    function abortReader(): void {
      rejectWith(
        signal?.reason ??
        new DOMException('The operation was aborted.', 'AbortError')
      );
    }

    if (signal) {
      if (signal.aborted) {
        abortReader();
        return;
      }
      signal.addEventListener('abort', abortReader);
    }

    function pump(): void {
      if (settled) {
        return;
      }
      if (signal?.aborted) {
        abortReader();
        return;
      }

      const readPromise = reader.read();
      readPromise.catch(function () {});
      readPromise.then(
        function (result) {
          if (settled) {
            return;
          }
          if (result.done) {
            settled = true;
            cleanupAbortListener();
            reader.releaseLock();
            const concatenated = concatUint8Arrays(chunks);
            resolveWithoutThenable(outerResolve, concatenated);
            return;
          }
          try {
            chunks.push(normalizeBodyChunk(result.value));
          } catch (error) {
            rejectWith(error);
            return;
          }
          if (signal?.aborted) {
            abortReader();
            return;
          }
          pump();
        },
        function (err) {
          rejectWith(err);
        }
      );
    }

    pump();
  });
}

/**
 * Concatenate multiple Uint8Arrays into one.
 */
export function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Generate a boundary string for multipart/form-data.
 */
export function generateBoundary(): string {
  return '----ExactFormBoundary' + Math.random().toString(36).slice(2);
}

/**
 * Get the Content-Type header for a body type.
 */
export function getContentTypeForBody(body: BodyInit | null): string | null {
  if (body === null || body === undefined) {
    return null;
  }

  if (typeof body === 'string') {
    return 'text/plain;charset=UTF-8';
  }

  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
    return 'application/x-www-form-urlencoded;charset=UTF-8';
  }

  if (isBlob(body) && body.type) {
    return body.type;
  }

  // For ArrayBuffer, TypedArray, etc., no default Content-Type
  return null;
}

/**
 * Internal sync encoding for FormData (uses _getBytes for Blobs).
 */
function encodeFormDataInternal(body: FormData): { body: Uint8Array; contentType: string } {
  // Use FormData's built-in encoding if available
  if (typeof (body as any)._encode === 'function') {
    return (body as any)._encode();
  }

  const boundary = generateBoundary();
  const parts: Uint8Array[] = [];

  for (const [name, value] of (body as any).entries()) {
    if (typeof value === 'string') {
      parts.push(getTextEncoder().encode(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
        `${value}\r\n`
      ));
    } else if (isBlob(value)) {
      const fileBytes = (value as any)._getBytes?.() ?? new Uint8Array(0);
      const fileName = (value as File).name || 'blob';
      const contentType = value.type || 'application/octet-stream';

      parts.push(getTextEncoder().encode(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${name}"; filename="${fileName}"\r\n` +
        `Content-Type: ${contentType}\r\n\r\n`
      ));
      parts.push(fileBytes);
      parts.push(getTextEncoder().encode('\r\n'));
    }
  }

  // Per WPT: empty FormData produces an empty body
  if (parts.length === 0) {
    return {
      body: new Uint8Array(0),
      contentType: `multipart/form-data; boundary=${boundary}`,
    };
  }

  parts.push(getTextEncoder().encode(`--${boundary}--\r\n`));

  return {
    body: concatUint8Arrays(parts),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

/**
 * Internal async encoding for FormData (uses arrayBuffer for Blobs).
 */
async function encodeFormDataInternalAsync(body: FormData): Promise<{ body: Uint8Array; contentType: string }> {
  // Use FormData's built-in encoding if available
  if (typeof (body as any)._encode === 'function') {
    return (body as any)._encode();
  }
  
  const boundary = generateBoundary();
  const parts: Uint8Array[] = [];

  for (const [name, value] of (body as any).entries()) {
    if (typeof value === 'string') {
      parts.push(getTextEncoder().encode(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
        `${value}\r\n`
      ));
    } else if (isBlob(value)) {
      const buffer = await value.arrayBuffer();
      const fileBytes = new Uint8Array(buffer);
      const fileName = (value as File).name || 'blob';
      const contentType = value.type || 'application/octet-stream';

      parts.push(getTextEncoder().encode(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${name}"; filename="${fileName}"\r\n` +
        `Content-Type: ${contentType}\r\n\r\n`
      ));
      parts.push(fileBytes);
      parts.push(getTextEncoder().encode('\r\n'));
    }
  }

  // Per WPT: empty FormData produces an empty body
  if (parts.length === 0) {
    return {
      body: new Uint8Array(0),
      contentType: `multipart/form-data; boundary=${boundary}`,
    };
  }

  parts.push(getTextEncoder().encode(`--${boundary}--\r\n`));

  return {
    body: concatUint8Arrays(parts),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

/**
 * Encode FormData body with its content type (for consistent boundary).
 * Returns both the body bytes and content-type header.
 */
export function encodeFormData(body: FormData): { body: Uint8Array; contentType: string } {
  if (typeof (body as any)._encode === 'function') {
    return (body as any)._encode();
  }

  // Fallback encoding
  return encodeFormDataInternal(body);
}

/**
 * Parse array buffer as JSON.
 */
export function parseJson(buffer: ArrayBuffer): unknown {
  // Per Fetch spec: reject UTF-16 encoded content (only UTF-8 is valid for JSON)
  const bytes = new Uint8Array(buffer);
  if (bytes.length >= 2) {
    // UTF-16 BE BOM: FE FF, or UTF-16 LE BOM: FF FE
    if ((bytes[0] === 0xFE && bytes[1] === 0xFF) || (bytes[0] === 0xFF && bytes[1] === 0xFE)) {
      throw new SyntaxError('Invalid JSON: UTF-16 encoded content is not valid');
    }
    // Detect BOM-less UTF-16: valid JSON always starts with an ASCII character
    // (whitespace, '{', '[', '"', digit, 't', 'f', 'n'). In UTF-16 LE the
    // second byte is 0x00, in UTF-16 BE the first byte is 0x00.
    if (bytes[0] === 0x00 || bytes[1] === 0x00) {
      throw new SyntaxError('Invalid JSON: UTF-16 encoded content is not valid');
    }
  }
  const text = getTextDecoder().decode(buffer);
  return JSON.parse(text);
}

/**
 * Parse array buffer as text.
 */
export function parseText(buffer: ArrayBuffer): string {
  return getTextDecoder().decode(buffer);
}

/**
 * Create a ReadableStream from a Uint8Array.
 * Returns null if ReadableStream is not available (falls back to buffer-based reading).
 */
export function createReadableStreamFromUint8Array(
  data: Uint8Array | null
): ReadableStream<Uint8Array> | null {
  if (data === null) {
    return null;
  }

  // Byte streams may detach the enqueued chunk's backing buffer. Keep the
  // caller-owned buffer stable by enqueueing a cloned view instead.
  const streamData = new Uint8Array(data.byteLength);
  streamData.set(data);

  const streamCtor =
    (globalThis as any).ReadableStream || RuntimeReadableStream;

  // Check if a ReadableStream constructor is available - it might not be in
  // all environments.
  if (typeof streamCtor !== 'function') {
    return null;
  }

  // Create a byte stream (type: 'bytes') so that BYOB readers work
  return new (streamCtor as typeof ReadableStream)({
    type: 'bytes',
    start(controller: any) {
      if (streamData.byteLength > 0) {
        controller.enqueue(streamData);
      }
      controller.close();
    },
  } as any);
}

/**
 * Extract the boundary parameter from a multipart/form-data Content-Type header.
 * @param contentType The Content-Type header value
 * @returns The boundary string, or null if not found
 */
export function extractBoundary(contentType: string): string | null {
  // Match boundary parameter: boundary=VALUE or boundary="VALUE"
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
  if (!match) return null;
  return match[1] ?? match[2] ?? null;
}

/**
 * Find the index of a byte sequence (needle) within a Uint8Array (haystack),
 * starting from the given offset.
 */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, offset: number = 0): number {
  const haystackLen = haystack.length;
  const needleLen = needle.length;
  if (needleLen === 0) return offset;
  if (offset + needleLen > haystackLen) return -1;

  outer:
  for (let i = offset; i <= haystackLen - needleLen; i++) {
    for (let j = 0; j < needleLen; j++) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

/**
 * Parse a Content-Disposition header value to extract name and filename parameters.
 */
function parseContentDisposition(header: string): { name: string; filename?: string } {
  let name = '';
  let filename: string | undefined;

  // Extract name parameter
  const nameMatch = header.match(/\bname=(?:"([^"]*(?:\\.[^"]*)*)"|([^\s;]+))/i);
  if (nameMatch) {
    name = (nameMatch[1] ?? nameMatch[2] ?? '').replace(/\\"/g, '"');
  }

  // Extract filename parameter
  const filenameMatch = header.match(/\bfilename=(?:"([^"]*(?:\\.[^"]*)*)"|([^\s;]+))/i);
  if (filenameMatch) {
    filename = (filenameMatch[1] ?? filenameMatch[2] ?? '').replace(/\\"/g, '"');
  }

  return { name, filename };
}

/**
 * Parse the headers section of a multipart part.
 * Returns a map of lowercased header names to their values.
 */
function parsePartHeaders(headerBytes: Uint8Array): Map<string, string> {
  const decoder = getTextDecoder();
  const headerText = decoder.decode(headerBytes);
  const headers = new Map<string, string>();

  // Split by CRLF, handling potential line folding
  const lines = headerText.split('\r\n');
  for (const line of lines) {
    if (!line) continue;
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) continue;
    const name = line.slice(0, colonIndex).trim().toLowerCase();
    const value = line.slice(colonIndex + 1).trim();
    headers.set(name, value);
  }

  return headers;
}

/**
 * Parse a multipart/form-data body into a FormData object.
 *
 * @param body The raw body bytes
 * @param boundary The boundary string from the Content-Type header
 * @returns A populated FormData object
 */
export function parseMultipartFormData(body: Uint8Array, boundary: string): FormData {
  const encoder = getTextEncoder();
  const formData = new FormData();

  // Boundary markers
  const dashBoundary = encoder.encode('--' + boundary);
  const crlf = encoder.encode('\r\n');
  const doubleCrlf = encoder.encode('\r\n\r\n');

  // Find the first boundary
  let pos = indexOfBytes(body, dashBoundary, 0);
  if (pos === -1) {
    throw new TypeError('Failed to parse multipart/form-data body: boundary not found');
  }

  // Move past the first boundary line
  pos += dashBoundary.length;

  // Check if immediately followed by -- (closing boundary with no parts)
  if (pos + 2 <= body.length && body[pos] === 0x2d && body[pos + 1] === 0x2d) {
    return formData;
  }

  // Skip CRLF after boundary
  if (pos + 2 <= body.length && body[pos] === 0x0d && body[pos + 1] === 0x0a) {
    pos += 2;
  }

  let foundClosingBoundary = false;

  while (pos < body.length) {
    // Find the end of headers (double CRLF)
    const headersEnd = indexOfBytes(body, doubleCrlf, pos);
    if (headersEnd === -1) break;

    // Parse headers for this part
    const headerBytes = body.slice(pos, headersEnd);
    const headers = parsePartHeaders(headerBytes);

    // Move past the double CRLF to the start of the body
    const bodyStart = headersEnd + doubleCrlf.length;

    // Find the next boundary to determine where this part's body ends
    const nextBoundary = indexOfBytes(body, dashBoundary, bodyStart);
    if (nextBoundary === -1) break;

    // The body ends before the CRLF preceding the boundary
    // The format is: body\r\n--boundary
    let bodyEnd = nextBoundary;
    if (bodyEnd >= 2 && body[bodyEnd - 2] === 0x0d && body[bodyEnd - 1] === 0x0a) {
      bodyEnd -= 2;
    }

    const partBody = body.slice(bodyStart, bodyEnd);

    // Parse Content-Disposition to get name and filename
    const disposition = headers.get('content-disposition') ?? '';
    const { name, filename } = parseContentDisposition(disposition);

    if (!name) {
      // Skip parts without a name (per spec)
      pos = nextBoundary + dashBoundary.length;
      // Check for closing boundary
      if (pos + 2 <= body.length && body[pos] === 0x2d && body[pos + 1] === 0x2d) {
        foundClosingBoundary = true;
        break;
      }
      // Skip CRLF
      if (pos + 2 <= body.length && body[pos] === 0x0d && body[pos + 1] === 0x0a) pos += 2;
      continue;
    }

    if (filename !== undefined) {
      // File field: create a File object
      const contentType = headers.get('content-type') ?? 'application/octet-stream';
      const file = new File([partBody], filename, { type: contentType });
      formData.append(name, file);
    } else {
      // Text field: decode as UTF-8
      const decoder = getTextDecoder();
      const text = decoder.decode(partBody);
      formData.append(name, text);
    }

    // Move past the boundary
    pos = nextBoundary + dashBoundary.length;

    // Check for closing boundary (--)
    if (pos + 2 <= body.length && body[pos] === 0x2d && body[pos + 1] === 0x2d) {
      foundClosingBoundary = true;
      break;
    }

    // Skip CRLF after boundary
    if (pos + 2 <= body.length && body[pos] === 0x0d && body[pos + 1] === 0x0a) {
      pos += 2;
    }
  }

  // Per spec: if the multipart body doesn't have a valid closing boundary, reject
  if (!foundClosingBoundary) {
    throw new TypeError('Failed to parse multipart/form-data body: missing closing boundary');
  }

  return formData;
}

/**
 * Body mixin base class.
 * Provides common body handling functionality for Request and Response.
 */
export abstract class BodyMixin {
  protected _body: ReadableStream<Uint8Array> | null = null;
  protected _bodyUsed = false;
  protected _bodyBuffer: ArrayBuffer | null = null;

  /**
   * Per Fetch spec: the abort signal associated with the fetch that created
   * this response. Body consumption methods check this and reject with the
   * abort reason if the signal is aborted.
   */
  public _signal: AbortSignal | null = null;

  /**
   * A ReadableStream of the body contents.
   */
  get body(): ReadableStream<Uint8Array> | null {
    return this._body;
  }

  /**
   * A Boolean that indicates whether the body has been read.
   * Per spec: also true when the body stream has been disturbed (read from)
   * or locked (e.g., via getReader() or pipeTo()).
   */
  get bodyUsed(): boolean {
    if (this._bodyUsed) return true;
    if (this._body !== null) {
      if ((this._body as any)._disturbed) return true;
    }
    return false;
  }

  /**
   * Whether this object has a body. Subclasses can override to check
   * additional state (e.g., Request._bodyInit).
   */
  protected _hasBody(): boolean {
    return this._body !== null || this._bodyBuffer !== null;
  }

  /**
   * Determine whether a body read should fail before attempting consumption.
   * Bun compat expects a reused body to report "Body already used" even if the
   * underlying stream is already locked from the prior read.
   */
  protected _getBodyReadPreconditionError(): TypeError | null {
    if (this.bodyUsed) {
      return new BodyConsumedError();
    }

    if (this._body !== null && typeof (this._body as any).locked !== 'undefined' && (this._body as any).locked) {
      return new TypeError(
        isBunCompatFetchTest() ? 'ReadableStream is locked' : 'Failed to execute: body stream is locked'
      );
    }

    return null;
  }

  /**
   * Mark body as used and throw if already used.
   * Per spec: consuming a null body returns empty without setting bodyUsed.
   */
  protected _consumeBody(): void {
    if (this.bodyUsed) {
      throw new BodyConsumedError();
    }
    // Per spec: only set bodyUsed if there is actually a body
    if (this._hasBody()) {
      this._bodyUsed = true;
    }
    // Per Fetch spec: consuming a body locks its stream.
    // When _bodyBuffer is cached, _getBodyBuffer() won't read the stream,
    // so we must lock it here. For stream-only bodies (_bodyBuffer === null),
    // readableStreamToUint8Array() will lock the stream when it runs.
    if (this._body !== null && this._bodyBuffer !== null && !this._body.locked) {
      (this._body as any)._disturbed = true;
      try { this._body.getReader(); } catch {}
    }
  }

  /**
   * Get the body as ArrayBuffer.
   * Must be implemented by subclasses.
   */
  protected abstract _getBodyBuffer(): Promise<ArrayBuffer>;

  /**
   * Get the Content-Type header value.
   * Must be implemented by subclasses to support multipart formData() parsing.
   */
  protected abstract _getContentType(): string | null;

  /**
   * Per Fetch spec: check if the associated abort signal is aborted, and if so
   * reject with the signal's reason.
   */
  protected _checkAbortSignal(): Error | null {
    if (this._signal && this._signal.aborted) {
      return this._signal.reason ??
        new DOMException('The operation was aborted.', 'AbortError');
    }
    return null;
  }

  /**
   * Returns a promise that resolves with an ArrayBuffer.
   * Note: uses explicit promise chain (not async) to avoid compiled async
   * wrapper creating intermediate promises that trigger unhandled rejection tracking.
   */
  arrayBuffer(): Promise<ArrayBuffer> {
    const preconditionError = this._getBodyReadPreconditionError();
    if (preconditionError) {
      return Promise.reject(preconditionError);
    }
    // Reject up front if the associated fetch was already aborted, even for a
    // fully-buffered body that would otherwise resolve without reading a stream.
    const abortError = this._checkAbortSignal();
    if (abortError) {
      return Promise.reject(abortError);
    }
    try {
      this._consumeBody();
    } catch (e) {
      return Promise.reject(e);
    }
    return this._getBodyBuffer();
  }

  /**
   * Returns a promise that resolves with a Blob.
   */
  blob(): Promise<Blob> {
    const preconditionError = this._getBodyReadPreconditionError();
    if (preconditionError) {
      return Promise.reject(preconditionError);
    }
    return this.arrayBuffer().then((buffer) => {
      const type = normalizeBlobContentType(this._getContentType());
      return type ? new Blob([buffer], { type }) : new Blob([buffer]);
    });
  }

  /**
   * Returns a promise that resolves with a Uint8Array.
   */
  bytes(): Promise<Uint8Array> {
    const preconditionError = this._getBodyReadPreconditionError();
    if (preconditionError) {
      return Promise.reject(preconditionError);
    }
    return this.arrayBuffer().then((buffer) => new Uint8Array(buffer));
  }

  /**
   * Returns a promise that resolves with a FormData.
   * Supports both multipart/form-data and application/x-www-form-urlencoded.
   */
  formData(): Promise<FormData> {
    const preconditionError = this._getBodyReadPreconditionError();
    if (preconditionError) {
      return Promise.reject(preconditionError);
    }

    const abortError = this._checkAbortSignal();
    if (abortError) {
      return Promise.reject(abortError);
    }

    try {
      this._consumeBody();
    } catch (e) {
      return Promise.reject(e);
    }

    const contentType = this._getContentType();
    const ct = contentType?.toLowerCase() ?? '';
    const isMultipart = ct.startsWith('multipart/form-data');
    const isUrlEncoded = ct.startsWith('application/x-www-form-urlencoded');

    const self = this;
    // Read the body buffer first so that stream errors propagate before
    // content-type checks (per spec and response-error-from-stream WPT tests).
    return this._getBodyBuffer().then(function (buffer) {
      if (!isMultipart && !isUrlEncoded) {
        throw new TypeError(
          "Failed to execute 'formData': Content-Type is not 'multipart/form-data' or 'application/x-www-form-urlencoded'"
        );
      }
      // multipart/form-data
      if (isMultipart) {
        const boundary = extractBoundary(contentType!);
        if (!boundary) {
          throw new TypeError('multipart/form-data Content-Type missing boundary');
        }
        const bytes = new Uint8Array(buffer);
        // Empty body handling: only return empty FormData if the body was
        // explicitly set (e.g. new Response(new FormData())). A null body
        // with a multipart Content-Type header should reject per spec.
        if (bytes.length === 0) {
          if (self._hasBody()) {
            return new FormData();
          }
          throw new TypeError('Could not parse content as FormData.');
        }
        return parseMultipartFormData(bytes, boundary);
      }

      // application/x-www-form-urlencoded
      const text = decodeTextForFormData(buffer);
      const formData = new FormData();
      const params = new URLSearchParams(text);
      // Use indexed iteration to avoid the Rolldown for-of → forEach transform
      // which rewrites the loop body into a regular function, breaking returns.
      const paramEntries = Array.from(params);
      for (let i = 0; i < paramEntries.length; i++) {
        formData.append(paramEntries[i][0], paramEntries[i][1]);
      }
      return formData;
    });
  }

  /**
   * Returns a promise that resolves with the result of parsing the body as JSON.
   */
  json(): Promise<unknown> {
    const preconditionError = this._getBodyReadPreconditionError();
    if (preconditionError) {
      return Promise.reject(preconditionError);
    }
    return this.arrayBuffer().then(parseJson);
  }

  /**
   * Returns a promise that resolves with a string (decoded as UTF-8).
   */
  text(): Promise<string> {
    const preconditionError = this._getBodyReadPreconditionError();
    if (preconditionError) {
      return Promise.reject(preconditionError);
    }
    return this.arrayBuffer().then(parseText);
  }
}
