/**
 * FormData implementation for Exact runtime
 * 
 * Implements the WHATWG FormData API with multipart/form-data encoding.
 * https://xhr.spec.whatwg.org/#interface-formdata
 */

import { Blob } from './Blob';
import { File } from './File';

export type FormDataEntryValue = string | File;

interface BlobLikeValue {
  type?: string;
  name?: string;
  lastModified?: number;
  _getBytes(): Uint8Array;
}

/**
 * Result of encoding FormData to multipart/form-data
 */
export interface MultipartEncodingResult {
  /** The encoded body as bytes */
  body: Uint8Array;
  /** The Content-Type header value including boundary */
  contentType: string;
  /** The boundary string used */
  boundary: string;
}

/**
 * FormData provides a way to construct a set of key/value pairs
 * representing form fields and their values.
 */
export class FormData {
  readonly #entries: Array<[string, FormDataEntryValue]> = [];

  constructor(form?: unknown) {
    // Note: In a browser, this would accept an HTMLFormElement.
    // In Exact runtime, we only support creating empty FormData.
    if (form !== undefined && form !== null) {
      throw new TypeError('FormData constructor with form element is not supported');
    }
  }

  /**
   * Appends a new value to an existing key, or adds the key if it doesn't exist.
   */
  append(name: string, value: string): void;
  append(name: string, value: Blob, filename?: string): void;
  append(name: string, value: string | Blob, filename?: string): void {
    const normalizedName = String(name);
    const entry = normalizeValue(value, filename);
    this.#entries.push([normalizedName, entry]);
  }

  /**
   * Deletes all entries with the given name.
   */
  delete(name: string): void {
    const normalizedName = String(name);
    for (let i = this.#entries.length - 1; i >= 0; i--) {
      if (this.#entries[i][0] === normalizedName) {
        this.#entries.splice(i, 1);
      }
    }
  }

  /**
   * Returns the first value associated with a given key.
   */
  get(name: string): FormDataEntryValue | null {
    const normalizedName = String(name);
    for (const [entryName, value] of this.#entries) {
      if (entryName === normalizedName) {
        return value;
      }
    }
    return null;
  }

  /**
   * Returns all values associated with a given key.
   */
  getAll(name: string): FormDataEntryValue[] {
    const normalizedName = String(name);
    const result: FormDataEntryValue[] = [];
    for (const [entryName, value] of this.#entries) {
      if (entryName === normalizedName) {
        result.push(value);
      }
    }
    return result;
  }

  /**
   * Returns whether a key exists in the FormData.
   */
  has(name: string): boolean {
    const normalizedName = String(name);
    for (const [entryName] of this.#entries) {
      if (entryName === normalizedName) {
        return true;
      }
    }
    return false;
  }

  /**
   * Sets a key to a value, replacing any existing entries with that key.
   */
  set(name: string, value: string): void;
  set(name: string, value: Blob, filename?: string): void;
  set(name: string, value: string | Blob, filename?: string): void {
    const normalizedName = String(name);
    const entry = normalizeValue(value, filename);
    
    // Find first occurrence and replace
    let found = false;
    for (let i = 0; i < this.#entries.length; i++) {
      if (this.#entries[i][0] === normalizedName) {
        if (!found) {
          this.#entries[i] = [normalizedName, entry];
          found = true;
        } else {
          // Remove subsequent entries
          this.#entries.splice(i, 1);
          i--;
        }
      }
    }
    
    // If not found, append
    if (!found) {
      this.#entries.push([normalizedName, entry]);
    }
  }

  /**
   * Returns an iterator of all keys.
   */
  *keys(): IterableIterator<string> {
    for (const [name] of this.#entries) {
      yield name;
    }
  }

  /**
   * Returns an iterator of all values.
   */
  *values(): IterableIterator<FormDataEntryValue> {
    for (const [, value] of this.#entries) {
      yield value;
    }
  }

  /**
   * Returns an iterator of all key/value pairs.
   */
  *entries(): IterableIterator<[string, FormDataEntryValue]> {
    for (const entry of this.#entries) {
      yield entry;
    }
  }

  /**
   * Calls a function for each key/value pair.
   */
  forEach(
    callback: (value: FormDataEntryValue, key: string, parent: FormData) => void,
    thisArg?: unknown
  ): void {
    // Use indexed loop to avoid the Rolldown for-of → forEach transform which
    // rewrites `this` inside the callback to the global object.
    const entries = this.#entries;
    for (let i = 0; i < entries.length; i++) {
      callback.call(thisArg, entries[i][1], entries[i][0], this);
    }
  }

  [Symbol.iterator](): IterableIterator<[string, FormDataEntryValue]> {
    return this.entries();
  }

  get [Symbol.toStringTag](): string {
    return 'FormData';
  }

  /**
   * Internal method to get all entries for serialization.
   * Used by fetch() to build multipart/form-data body.
   */
  _getEntries(): Array<[string, FormDataEntryValue]> {
    return [...this.#entries];
  }

  /**
   * Encode FormData as multipart/form-data.
   * 
   * This method is used by fetch() when sending FormData as request body.
   * 
   * @returns Object containing body bytes, content-type header, and boundary
   * 
   * @example
   * const formData = new FormData();
   * formData.append('name', 'John');
   * formData.append('file', new File(['content'], 'test.txt'));
   * const { body, contentType } = formData._encode();
   * // contentType = 'multipart/form-data; boundary=----ExactFormBoundary...'
   */
  _encode(): MultipartEncodingResult {
    // Generate a unique boundary
    const boundary = generateBoundary();
    const encoder = new TextEncoder();
    const parts: Uint8Array[] = [];
    const CRLF = '\r\n';

    for (const [name, value] of this.#entries) {
      // Add boundary
      parts.push(encoder.encode(`--${boundary}${CRLF}`));

      if (typeof value === 'string') {
        // Text field
        parts.push(encoder.encode(
          `Content-Disposition: form-data; name="${escapeQuotes(name)}"${CRLF}` +
          `${CRLF}` +
          `${value}${CRLF}`
        ));
      } else {
        // File field
        const filename = value.name || 'blob';
        const contentType = value.type || 'application/octet-stream';
        
        parts.push(encoder.encode(
          `Content-Disposition: form-data; name="${escapeQuotes(name)}"; filename="${escapeQuotes(filename)}"${CRLF}` +
          `Content-Type: ${contentType}${CRLF}` +
          `${CRLF}`
        ));
        
        // Add file content
        parts.push(value._getBytes());
        parts.push(encoder.encode(CRLF));
      }
    }

    // Add closing boundary
    parts.push(encoder.encode(`--${boundary}--${CRLF}`));

    // Concatenate all parts
    const totalLength = parts.reduce((acc, part) => acc + part.byteLength, 0);
    const body = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
      body.set(part, offset);
      offset += part.byteLength;
    }

    return {
      body,
      contentType: `multipart/form-data; boundary=${boundary}`,
      boundary,
    };
  }
}

/**
 * Generate a unique boundary string for multipart encoding.
 */
function generateBoundary(): string {
  // Use a combination of timestamp and random values
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).slice(2, 10);
  const random2 = Math.random().toString(36).slice(2, 10);
  return `----ExactFormBoundary${timestamp}${random}${random2}`;
}

/**
 * Escape quotes in a string for use in Content-Disposition header.
 */
function escapeQuotes(str: string): string {
  return str.replace(/"/g, '\\"').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function isBlobLikeValue(value: unknown): value is BlobLikeValue {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as BlobLikeValue)._getBytes === 'function'
  );
}

/**
 * Normalize a value for storage in FormData.
 * Strings are stored as-is, Blobs are converted to Files.
 */
function normalizeValue(value: string | Blob | BlobLikeValue, filename?: string): FormDataEntryValue {
  if (typeof value === 'string') {
    return value;
  }

  // If it's already a File and no filename override, use as-is
  if (value instanceof File && filename === undefined) {
    return value;
  }

  if (!isBlobLikeValue(value)) {
    throw new TypeError("FormData value must be a string, Blob, or File");
  }

  // Convert Blob to File
  const name = filename ?? (typeof value.name === 'string' ? value.name : 'blob');
  const options = {
    type: value.type,
    lastModified: typeof value.lastModified === 'number' ? value.lastModified : Date.now(),
  };

  // Need to extract the bytes from the Blob
  const bytes = value._getBytes();
  return new File([bytes], name, options);
}

export default FormData;
