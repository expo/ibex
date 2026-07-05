// @ts-nocheck
/**
 * Blob implementation for Ibex runtime
 * 
 * Implements the WHATWG Blob API for handling binary data.
 * https://w3c.github.io/FileAPI/#blob-section
 */

import { ReadableStream, type UnderlyingByteSource } from '../streams';

export interface BlobPropertyBag {
  type?: string;
  endings?: 'transparent' | 'native';
}

export type BlobPart = ArrayBuffer | ArrayBufferView | Blob | string;

/**
 * Blob represents immutable raw binary data.
 */
export class Blob {
  readonly #parts: Uint8Array[];
  readonly #type: string;
  readonly #size: number;

  constructor(blobParts?: BlobPart[], options?: BlobPropertyBag) {
    this.#parts = [];
    this.#type = normalizeType(options?.type ?? '');
    const endings = options?.endings ?? 'transparent';

    if (blobParts) {
      const parts = Array.from(blobParts);
      for (let i = 0; i < parts.length; i++) {
        this.#parts.push(convertToBytes(parts[i], endings));
      }
    }

    this.#size = this.#parts.reduce((acc, part) => acc + part.byteLength, 0);
  }

  /**
   * The size of the Blob in bytes.
   */
  get size(): number {
    return this.#size;
  }

  /**
   * The MIME type of the Blob.
   */
  get type(): string {
    return this.#type;
  }

  /**
   * Returns a new Blob containing a subset of this Blob's data.
   */
  slice(start?: number, end?: number, contentType?: string): Blob {
    const size = this.#size;
    
    // Normalize start
    let relativeStart: number;
    if (start === undefined) {
      relativeStart = 0;
    } else if (start < 0) {
      relativeStart = Math.max(size + start, 0);
    } else {
      relativeStart = Math.min(start, size);
    }

    // Normalize end
    let relativeEnd: number;
    if (end === undefined) {
      relativeEnd = size;
    } else if (end < 0) {
      relativeEnd = Math.max(size + end, 0);
    } else {
      relativeEnd = Math.min(end, size);
    }

    // Calculate span
    const span = Math.max(relativeEnd - relativeStart, 0);
    
    if (span === 0) {
      return new Blob([], { type: normalizeType(contentType ?? '') });
    }

    // Extract the slice
    const allBytes = this.#concatenateBytes();
    const slicedBytes = allBytes.slice(relativeStart, relativeStart + span);

    return new Blob([slicedBytes], { type: normalizeType(contentType ?? '') });
  }

  /**
   * Returns a Promise that resolves with the contents as an ArrayBuffer.
   */
  async arrayBuffer(): Promise<ArrayBuffer> {
    const bytes = this.#concatenateBytes();
    // Return a copy to ensure immutability
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  /**
   * Returns a Promise that resolves with the contents as a string.
   */
  async text(): Promise<string> {
    const bytes = this.#concatenateBytes();
    return new TextDecoder().decode(bytes);
  }

  /**
   * Returns a Promise that resolves with the parsed JSON contents.
   */
  async json(): Promise<unknown> {
    const text = await this.text();
    const normalized = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
    return JSON.parse(normalized);
  }

  /**
   * Returns a Promise that resolves with parsed application/x-www-form-urlencoded data.
   */
  async formData(): Promise<FormData> {
    const text = await this.text();
    const normalized = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
    const params = new URLSearchParams(normalized);
    const form = new FormData();
    params.forEach((value, key) => {
      form.append(key, value);
    });
    return form;
  }

  /**
   * Returns a Promise that resolves with the Blob contents as a Uint8Array.
   */
  async bytes(): Promise<Uint8Array> {
    return this.#concatenateBytes();
  }

  /**
   * Returns a ReadableStream that can be used to read the Blob's contents.
   *
   * Uses byte stream type (type: 'bytes') so that BYOB readers work.
   */
  stream(): ReadableStream<Uint8Array> {
    const bytes = this.#concatenateBytes();
    let position = 0;
    const chunkSize = 65536; // 64KB chunks

    const source: UnderlyingByteSource = {
      type: 'bytes',
      pull(controller) {
        if (position >= bytes.length) {
          controller.close();
          return;
        }
        const chunk = bytes.slice(position, position + chunkSize);
        position += chunkSize;
        controller.enqueue(chunk);
      },
    };

    // Prefer the global ReadableStream when available so that
    // `instanceof ReadableStream` checks work against the platform class.
    const RS = (globalThis as any).ReadableStream ?? ReadableStream;
    return new RS(source);
  }

  /**
   * Returns a new Blob with the given bytes appended.
   * Non-standard extension for internal use.
   */
  #concatenateBytes(): Uint8Array {
    if (this.#parts.length === 0) {
      return new Uint8Array(0);
    }
    if (this.#parts.length === 1) {
      // Return a copy, never the internal part array: bytes()/_getBytes()/text()
      // hand this out to callers, and a Blob is immutable — leaking the backing
      // store would let `(await b.bytes())[0] = 0` corrupt the Blob.
      return this.#parts[0].slice();
    }

    const result = new Uint8Array(this.#size);
    let offset = 0;
    for (const part of this.#parts) {
      result.set(part, offset);
      offset += part.byteLength;
    }
    return result;
  }

  /**
   * Returns the raw bytes for internal use.
   * Non-standard - used by File and other internal APIs.
   */
  _getBytes(): Uint8Array {
    return this.#concatenateBytes();
  }

  get [Symbol.toStringTag](): string {
    return 'Blob';
  }
}

/**
 * Normalize a MIME type string.
 * Per spec: lowercase, only ASCII printable chars (0x20-0x7E) excluding certain chars.
 */
function normalizeType(type: string): string {
  if (!type) return '';
  
  // Convert to lowercase
  const lowered = type.toLowerCase();
  
  // Check for invalid characters
  for (let i = 0; i < lowered.length; i++) {
    const code = lowered.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      return '';
    }
  }
  
  return lowered;
}

/**
 * Convert a BlobPart to bytes.
 */
function convertToBytes(part: BlobPart, endings: 'transparent' | 'native'): Uint8Array {
  if (typeof part === 'string') {
    let str = part;
    if (endings === 'native') {
      // Convert line endings to platform-native
      // On most platforms this is \n, but could be \r\n on Windows
      const nativeLineEnding = '\n'; // Mobile platforms use \n
      str = str.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      if (nativeLineEnding !== '\n') {
        str = str.replace(/\n/g, nativeLineEnding);
      }
    }
    return new TextEncoder().encode(str);
  }

  if (part instanceof Blob) {
    // _getBytes() already returns a fresh copy of the Blob's bytes.
    return part._getBytes();
  }

  // Per the File API, the Blob constructor takes a *snapshot* of each part's
  // bytes. Copy out of the caller's ArrayBuffer/view so that later mutation of
  // the source (`const b = new Blob([u]); u[0] = 9;`) does not change the Blob.
  if (part instanceof ArrayBuffer) {
    return new Uint8Array(part.slice(0));
  }

  if (ArrayBuffer.isView(part)) {
    return new Uint8Array(part.buffer, part.byteOffset, part.byteLength).slice();
  }

  throw new TypeError('Invalid blob part type');
}

export default Blob;
