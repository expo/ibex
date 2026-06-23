// @ts-nocheck
/**
 * Buffer implementation for Ibex runtime (Node.js compatibility)
 * 
 * Buffer is a Uint8Array subclass that provides additional methods
 * for working with binary data.
 * @see https://nodejs.org/api/buffer.html
 */

type BufferEncoding = 'utf8' | 'utf-8' | 'ascii' | 'latin1' | 'binary' | 'hex' | 'base64' | 'base64url' | 'ucs2' | 'ucs-2' | 'utf16le' | 'utf-16le';
type NormalizedEncoding = 'utf8' | 'ascii' | 'latin1' | 'hex' | 'base64' | 'base64url' | 'utf16le';

/**
 * Buffer class for Node.js compatibility.
 * Extends Uint8Array with additional methods.
 */
export class Buffer extends Uint8Array {
  /**
   * Allocates a new Buffer of size bytes.
   * The buffer is initialized with zeros.
   */
  static alloc(size: number, fill?: string | number | Uint8Array, encoding?: BufferEncoding): Buffer {
    size = validateBufferSize(size);

    const buffer = new Buffer(size);

    if (fill !== undefined) {
      buffer.fill(fill, 0, size, encoding);
    }

    return buffer;
  }

  /**
   * Allocates a new Buffer of size bytes.
   * The buffer is NOT initialized (contains garbage data).
   * 
   * WARNING: This returns uninitialized memory for performance.
   * Use Buffer.alloc() for security-sensitive code.
   */
  static allocUnsafe(size: number): Buffer {
    size = validateBufferSize(size);
    // Note: In JS we can't actually get uninitialized memory,
    // but we skip the fill step for "unsafe" behavior
    return new Buffer(size);
  }

  /**
   * Same as allocUnsafe but guaranteed to never use pooled memory.
   */
  static allocUnsafeSlow(size: number): Buffer {
    return Buffer.allocUnsafe(size);
  }

  /**
   * Creates a Buffer from various inputs.
   */
  static from(value: string, encoding?: BufferEncoding): Buffer;
  static from(value: ArrayBuffer | SharedArrayBuffer, byteOffset?: number, length?: number): Buffer;
  static from(value: ArrayLike<number> | Iterable<number>): Buffer;
  static from(value: Buffer): Buffer;
  static from(value: { type: 'Buffer'; data: ArrayLike<number> | Iterable<number> }): Buffer;
  static from(
    value: string | ArrayBuffer | SharedArrayBuffer | ArrayLike<number> | Iterable<number> | Buffer | { type: 'Buffer'; data: ArrayLike<number> | Iterable<number> },
    encodingOrOffset?: BufferEncoding | number | unknown,
    length?: number
  ): Buffer {
    if (value === null || value === undefined) {
      throw makeFirstArgumentError(value);
    }

    if (typeof value === 'string') {
      return Buffer.fromString(value, encodingOrOffset as BufferEncoding);
    }

    const arrayBufferByteLength = getArrayBufferByteLength(value);
    if (arrayBufferByteLength !== null) {
      const byteOffset = normalizeArrayBufferOffset(encodingOrOffset, arrayBufferByteLength);
      const viewLength = normalizeArrayBufferLength(length, arrayBufferByteLength, byteOffset);
      // Copy the data to avoid aliasing bugs with native memory that may be
      // freed or reused.  This matches Node.js Buffer.from(ArrayBuffer) semantics.
      const copy = new Uint8Array(viewLength);
      copy.set(new Uint8Array(value as ArrayBuffer, byteOffset, viewLength));
      return Object.setPrototypeOf(copy, Buffer.prototype) as Buffer;
    }

    if (value instanceof Buffer) {
      const buffer = new Buffer(value.length);
      buffer.set(value);
      return buffer;
    }

    if (
      typeof value === 'object' &&
      value !== null &&
      (value as { type?: unknown }).type === 'Buffer' &&
      'data' in value
    ) {
      return Buffer.from((value as { data: ArrayLike<number> | Iterable<number> }).data);
    }

    if (Array.isArray(value) || ArrayBuffer.isView(value)) {
      const buffer = new Buffer(toArrayLikeLength(value));
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = (value as ArrayLike<number>)[i] & 0xff;
      }
      return buffer;
    }

    if (typeof value === 'object' && 'length' in value) {
      const arrayLike = value as ArrayLike<number>;
      const buffer = new Buffer(toArrayLikeLength(value));
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = (arrayLike[i] ?? 0) & 0xff;
      }
      return buffer;
    }

    // Iterable
    if (typeof value === 'object' && Symbol.iterator in value) {
      const arr = [...(value as Iterable<number>)];
      return Buffer.from(arr);
    }

    throw makeFirstArgumentError(value);
  }

  /**
   * Creates a Buffer from a string with specified encoding.
   */
  private static fromString(str: string, encoding: BufferEncoding = 'utf8'): Buffer {
    const normalizedEncoding = normalizeEncoding(encoding);

    switch (normalizedEncoding) {
      case 'utf8': {
        const bytes = new TextEncoder().encode(str);
        const buffer = new Buffer(bytes.length);
        buffer.set(bytes);
        return buffer;
      }
      case 'ascii':
      case 'latin1': {
        const buffer = new Buffer(str.length);
        for (let i = 0; i < str.length; i++) {
          buffer[i] = str.charCodeAt(i) & 0xff;
        }
        return buffer;
      }
      case 'hex': {
        const bytes: number[] = [];
        for (let i = 0; i < str.length - 1; i += 2) {
          const byte = parseInt(str.slice(i, i + 2), 16);
          if (Number.isNaN(byte)) {
            break;
          }
          bytes.push(byte);
        }
        const buffer = new Buffer(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
          buffer[i] = bytes[i];
        }
        return buffer;
      }
      case 'base64':
      case 'base64url': {
        const bytes = decodeBase64Bytes(normalizedEncoding === 'base64url'
          ? str.replace(/-/g, '+').replace(/_/g, '/')
          : str);
        const buffer = new Buffer(bytes.length);
        buffer.set(bytes);
        return buffer;
      }
      case 'utf16le': {
        const buffer = new Buffer(str.length * 2);
        for (let i = 0; i < str.length; i++) {
          const code = str.charCodeAt(i);
          buffer[i * 2] = code & 0xff;
          buffer[i * 2 + 1] = (code >> 8) & 0xff;
        }
        return buffer;
      }
      default:
        throw new TypeError(`Unknown encoding: ${encoding}`);
    }
  }

  /**
   * Returns the byte length of a string when encoded.
   */
  static byteLength(
    string: string | ArrayBuffer | SharedArrayBuffer | ArrayBufferView,
    encoding?: BufferEncoding | string,
  ): number {
    if (typeof string !== 'string') {
      if (ArrayBuffer.isView(string)) {
        return string.byteLength;
      }
      if (isArrayBufferLike(string)) {
        return string.byteLength;
      }
      throw makeInvalidArgTypeError(
        'string',
        'of type string or an instance of Buffer or ArrayBuffer',
        string,
      );
    }

    const normalizedEncoding = normalizeEncodingOrUtf8(encoding);

    switch (normalizedEncoding) {
      case 'ascii':
      case 'latin1':
        return string.length;
      case 'hex':
        return Math.floor(string.length / 2);
      case 'base64':
      case 'base64url':
        return Buffer.from(string, normalizedEncoding).length;
      case 'utf16le':
        return string.length * 2;
      case 'utf8':
      default:
        return utf8ByteLength(string);
    }
  }

  /**
   * Concatenate multiple Buffers into one.
   */
  static concat(list: (Buffer | Uint8Array)[], totalLength?: number): Buffer {
    if (!Array.isArray(list)) {
      throw makeInvalidArgTypeError('list', 'an instance of Array', list);
    }
    if (list.length === 0) {
      return new Buffer(0);
    }

    let len: number;
    if (totalLength === undefined) {
      len = 0;
      for (let i = 0; i < list.length; i++) {
        const item = list[i];
        if (!isUint8ArrayLike(item)) {
          throw makeInvalidArgTypeError(`list[${i}]`, 'an instance of Buffer or Uint8Array', item);
        }
        len += item.length;
      }
    } else {
      if (typeof totalLength !== 'number') {
        throw makeInvalidArgTypeError('length', 'of type number', totalLength);
      }
      if (!Number.isInteger(totalLength)) {
        throw createOutOfRangeError('length', 'an integer', totalLength);
      }
      if (totalLength < 0 || totalLength > Number.MAX_SAFE_INTEGER) {
        throw createOutOfRangeError('length', '>= 0 && <= 9007199254740991', totalLength);
      }
      len = totalLength;
      for (let i = 0; i < list.length; i++) {
        const item = list[i];
        if (!isUint8ArrayLike(item)) {
          throw makeInvalidArgTypeError(`list[${i}]`, 'an instance of Buffer or Uint8Array', item);
        }
      }
    }
    const result = new Buffer(len);
    
    let offset = 0;
    for (const buf of list) {
      if (offset >= len) break;
      const copyLen = Math.min(buf.length, len - offset);
      result.set(buf.subarray(0, copyLen), offset);
      offset += copyLen;
    }

    return result;
  }

  /**
   * Compares two Buffers.
   */
  static compare(buf1: Buffer | Uint8Array, buf2: Buffer | Uint8Array): -1 | 0 | 1 {
    if (!isUint8ArrayLike(buf1)) {
      throw makeInvalidArgTypeError('buf1', 'an instance of Buffer or Uint8Array', buf1, true);
    }
    if (!isUint8ArrayLike(buf2)) {
      throw makeInvalidArgTypeError('buf2', 'an instance of Buffer or Uint8Array', buf2, true);
    }
    return compareByteRanges(buf1, buf2, 0, buf1.length, 0, buf2.length);
  }

  /**
   * Check if value is a Buffer.
   */
  static isBuffer(obj: unknown): obj is Buffer {
    return !!(
      obj &&
      typeof obj === 'object' &&
      ArrayBuffer.isView(obj) &&
      (((obj as any)[Symbol.toStringTag] === 'Buffer') || obj instanceof Buffer)
    );
  }

  /**
   * Check if encoding is valid.
   */
  static isEncoding(encoding: unknown): encoding is BufferEncoding {
    if (typeof encoding !== 'string' || encoding === '') {
      return false;
    }
    try {
      normalizeEncoding(encoding as BufferEncoding);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Pool size for allocUnsafe (not used in this implementation).
   */
  static poolSize = 8192;

  /**
   * Buffer constants.
   */
  static constants = Object.freeze({
    MAX_LENGTH: 2 ** 31 - 1,
    MAX_STRING_LENGTH: 2 ** 28 - 16,
  });

  // Instance methods

  /**
   * Compare this buffer with another.
   */
  compare(target: Buffer | Uint8Array, targetStart = 0, targetEnd?: number, sourceStart = 0, sourceEnd?: number): -1 | 0 | 1 {
    if (!isUint8ArrayLike(target)) {
      throw makeInvalidArgTypeError('target', 'an instance of Buffer or Uint8Array', target, true);
    }

    const actualTargetStart = normalizeCompareIndex(targetStart, 'targetStart', 0);
    const actualTargetEnd = normalizeCompareIndex(targetEnd, 'targetEnd', target.length);
    const actualSourceStart = normalizeCompareIndex(sourceStart, 'sourceStart', 0);
    const actualSourceEnd = normalizeCompareIndex(sourceEnd, 'sourceEnd', this.length);

    if (actualTargetStart < 0) {
      throw createOutOfRangeError('targetStart', '>= 0', actualTargetStart);
    }
    if (actualTargetEnd < 0) {
      throw createOutOfRangeError('targetEnd', '>= 0', actualTargetEnd);
    }
    if (actualSourceStart < 0) {
      throw createOutOfRangeError('sourceStart', '>= 0', actualSourceStart);
    }
    if (actualSourceEnd < 0) {
      throw createOutOfRangeError('sourceEnd', '>= 0', actualSourceEnd);
    }
    if (actualTargetEnd > target.length) {
      throw createOutOfRangeError('targetEnd', `>= 0 && <= ${target.length}`, actualTargetEnd);
    }
    if (actualSourceEnd > this.length) {
      throw createOutOfRangeError('sourceEnd', `>= 0 && <= ${this.length}`, actualSourceEnd);
    }

    if (actualSourceStart >= actualSourceEnd) {
      return actualTargetStart >= actualTargetEnd ? 0 : -1;
    }
    if (actualTargetStart >= actualTargetEnd) {
      return 1;
    }

    return compareByteRanges(
      this,
      target,
      actualSourceStart,
      actualSourceEnd,
      actualTargetStart,
      actualTargetEnd,
    );
  }

  /**
   * Copy data from this buffer to target.
   */
  copy(target: Buffer | Uint8Array, targetStart = 0, sourceStart = 0, sourceEnd?: number): number {
    const sourceBytes = getWritableByteView(this);
    if (!sourceBytes) {
      throw makeInvalidArgTypeError('this', 'an instance of Buffer or Uint8Array', this);
    }
    const targetBytes = getWritableByteView(target);
    if (!targetBytes) {
      throw makeInvalidArgTypeError('target', 'an instance of Buffer or Uint8Array', target);
    }

    const actualTargetStart = normalizeCopyIndex(targetStart, 'targetStart', 0);
    const actualSourceStart = normalizeCopyIndex(sourceStart, 'sourceStart', 0);
    let actualSourceEnd = sourceEnd == null
      ? sourceBytes.length
      : normalizeCopyIndex(sourceEnd, 'sourceEnd', sourceBytes.length);

    if (actualTargetStart < 0) {
      throw createOutOfRangeError('targetStart', '>= 0', actualTargetStart);
    }
    if (actualSourceStart < 0) {
      throw createOutOfRangeError('sourceStart', '>= 0', actualSourceStart);
    }
    if (actualSourceEnd < 0) {
      throw createOutOfRangeError('sourceEnd', '>= 0', actualSourceEnd);
    }
    if (actualSourceStart > sourceBytes.length) {
      throw createOutOfRangeError('sourceStart', `>= 0 && <= ${sourceBytes.length}`, actualSourceStart);
    }
    if (actualSourceEnd > sourceBytes.length) {
      actualSourceEnd = sourceBytes.length;
    }
    if (actualSourceEnd <= actualSourceStart || actualTargetStart >= targetBytes.length) {
      return 0;
    }

    const length = Math.min(actualSourceEnd - actualSourceStart, targetBytes.length - actualTargetStart);
    if (
      sourceBytes.buffer === targetBytes.buffer &&
      actualSourceStart < actualTargetStart &&
      actualTargetStart < actualSourceStart + length
    ) {
      for (let i = length - 1; i >= 0; i--) {
        targetBytes[actualTargetStart + i] = sourceBytes[actualSourceStart + i];
      }
      return length;
    }
    for (let i = 0; i < length; i++) {
      targetBytes[actualTargetStart + i] = sourceBytes[actualSourceStart + i];
    }
    return length;
  }

  /**
   * Check if this buffer equals another.
   */
  equals(other: Buffer | Uint8Array): boolean {
    if (!isUint8ArrayLike(other)) {
      throw makeInvalidArgTypeError('otherBuffer', 'an instance of Buffer or Uint8Array', other, true);
    }
    return compareByteRanges(this, other, 0, this.length, 0, other.length) === 0;
  }

  /**
   * Fill buffer with a value.
   */
  fill(value: string | number | Uint8Array, offset = 0, end?: number, encoding?: BufferEncoding): this {
    // Handle overload: fill(value, encoding)
    if (typeof offset === 'string') {
      encoding = offset as unknown as BufferEncoding;
      offset = 0;
    }
    // Handle overload: fill(value, offset, encoding)
    if (typeof end === 'string') {
      encoding = end as unknown as BufferEncoding;
      end = undefined;
    }

    const fillEnd = end ?? this.length;

    // Clamp offset and end to valid range
    const clampedOffset = Math.max(0, Math.min(offset, this.length));
    const clampedEnd = Math.max(0, Math.min(fillEnd, this.length));

    if (clampedOffset >= clampedEnd) {
      return this;
    }

    if (typeof value === 'number') {
      for (let i = clampedOffset; i < clampedEnd; i++) {
        this[i] = value & 0xff;
      }
    } else if (typeof value === 'string') {
      if (value.length === 0) {
        // Node.js fills with zeros for empty string
        for (let i = clampedOffset; i < clampedEnd; i++) {
          this[i] = 0;
        }
      } else {
        const fillBuffer = Buffer.from(value, encoding);
        if (fillBuffer.length === 0) {
          // Encoded to zero bytes - fill with zeros
          for (let i = clampedOffset; i < clampedEnd; i++) {
            this[i] = 0;
          }
        } else {
          let j = 0;
          for (let i = clampedOffset; i < clampedEnd; i++) {
            this[i] = fillBuffer[j % fillBuffer.length];
            j++;
          }
        }
      }
    } else {
      if (value.length === 0) {
        return this;
      }
      let j = 0;
      for (let i = clampedOffset; i < clampedEnd; i++) {
        this[i] = value[j % value.length];
        j++;
      }
    }

    return this;
  }

  /**
   * Check if buffer includes a value.
   */
  includes(value: string | number | Buffer | Uint8Array, byteOffset?: number | string, encoding?: BufferEncoding): boolean {
    if (typeof byteOffset === 'string') {
      return this.indexOf(value, 0, byteOffset as BufferEncoding) !== -1;
    }
    return this.indexOf(value, byteOffset, encoding) !== -1;
  }

  /**
   * Find index of value in buffer.
   */
  indexOf(value: string | number | Buffer | Uint8Array, byteOffset?: number, encoding?: BufferEncoding): number {
    // Handle overload: indexOf(value, encoding)
    if (typeof byteOffset === 'string') {
      encoding = byteOffset as unknown as BufferEncoding;
      byteOffset = 0;
    }

    // Normalize byteOffset: negative values count from end
    let offset = byteOffset ?? 0;
    if (offset < 0) {
      offset = Math.max(0, this.length + offset);
    }
    if (offset >= this.length) {
      if (typeof value === 'number') return -1;
      const searchBuffer = typeof value === 'string' ? Buffer.from(value, encoding) : value;
      return searchBuffer.length === 0 ? this.length : -1;
    }

    if (typeof value === 'number') {
      for (let i = offset; i < this.length; i++) {
        if (this[i] === (value & 0xff)) return i;
      }
      return -1;
    }

    const searchBuffer = typeof value === 'string'
      ? Buffer.from(value, encoding)
      : value;

    if (searchBuffer.length === 0) return Math.min(offset, this.length);
    if (searchBuffer.length > this.length - offset) return -1;

    outer: for (let i = offset; i <= this.length - searchBuffer.length; i++) {
      for (let j = 0; j < searchBuffer.length; j++) {
        if (this[i + j] !== searchBuffer[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  /**
   * Find last index of value in buffer.
   */
  lastIndexOf(value: string | number | Buffer | Uint8Array, byteOffset?: number, encoding?: BufferEncoding): number {
    // Handle overload: lastIndexOf(value, encoding)
    if (typeof byteOffset === 'string') {
      encoding = byteOffset as unknown as BufferEncoding;
      byteOffset = undefined;
    }

    let startOffset = byteOffset ?? this.length;

    // Negative byteOffset counts from end
    if (startOffset < 0) {
      startOffset = this.length + startOffset;
      if (startOffset < 0) {
        // If still negative after adjustment, nothing can be found
        if (typeof value === 'number') return -1;
        const searchBuffer = typeof value === 'string' ? Buffer.from(value, encoding) : value;
        return searchBuffer.length === 0 ? 0 : -1;
      }
    }

    if (typeof value === 'number') {
      for (let i = Math.min(startOffset, this.length - 1); i >= 0; i--) {
        if (this[i] === (value & 0xff)) return i;
      }
      return -1;
    }

    const searchBuffer = typeof value === 'string'
      ? Buffer.from(value, encoding)
      : value;

    if (searchBuffer.length === 0) return Math.min(startOffset, this.length);

    outer: for (let i = Math.min(startOffset, this.length - searchBuffer.length); i >= 0; i--) {
      for (let j = 0; j < searchBuffer.length; j++) {
        if (this[i + j] !== searchBuffer[j]) continue outer;
      }
      return i;
    }
    return -1;
  }

  /**
   * Create a new Buffer that shares memory with this one.
   */
  slice(start?: number, end?: number): Buffer {
    return this.subarray(start, end);
  }

  /**
   * Create a subarray (shares memory).
   */
  subarray(start?: number, end?: number): Buffer {
    const sub = super.subarray(start, end);
    return Object.setPrototypeOf(sub, Buffer.prototype);
  }

  /**
   * Swap byte order (16-bit).
   */
  swap16(): this {
    if (this.length % 2 !== 0) {
      throw new RangeError('Buffer size must be a multiple of 16-bits');
    }
    for (let i = 0; i < this.length; i += 2) {
      const tmp = this[i];
      this[i] = this[i + 1];
      this[i + 1] = tmp;
    }
    return this;
  }

  /**
   * Swap byte order (32-bit).
   */
  swap32(): this {
    if (this.length % 4 !== 0) {
      throw new RangeError('Buffer size must be a multiple of 32-bits');
    }
    for (let i = 0; i < this.length; i += 4) {
      const tmp0 = this[i];
      const tmp1 = this[i + 1];
      this[i] = this[i + 3];
      this[i + 1] = this[i + 2];
      this[i + 2] = tmp1;
      this[i + 3] = tmp0;
    }
    return this;
  }

  /**
   * Swap byte order (64-bit).
   */
  swap64(): this {
    if (this.length % 8 !== 0) {
      throw new RangeError('Buffer size must be a multiple of 64-bits');
    }
    for (let i = 0; i < this.length; i += 8) {
      const tmp0 = this[i];
      const tmp1 = this[i + 1];
      const tmp2 = this[i + 2];
      const tmp3 = this[i + 3];
      this[i] = this[i + 7];
      this[i + 1] = this[i + 6];
      this[i + 2] = this[i + 5];
      this[i + 3] = this[i + 4];
      this[i + 4] = tmp3;
      this[i + 5] = tmp2;
      this[i + 6] = tmp1;
      this[i + 7] = tmp0;
    }
    return this;
  }

  /**
   * Convert buffer to JSON.
   */
  toJSON(): { type: 'Buffer'; data: number[] } {
    return {
      type: 'Buffer',
      data: [...this],
    };
  }

  /**
   * Convert buffer to string.
   */
  toString(encoding: BufferEncoding = 'utf8', start = 0, end?: number): string {
    const normalizedEncoding = normalizeEncoding(encoding);
    const actualStart = normalizeToStringRangeIndex(start, this.length, 0);
    const actualEnd = end === undefined
      ? this.length
      : normalizeToStringRangeIndex(end, this.length, 0);

    if (actualEnd <= actualStart) {
      return '';
    }

    const slice = this.subarray(actualStart, actualEnd);

    switch (normalizedEncoding) {
      case 'utf8': {
        const decoded = new TextDecoder('utf-8').decode(slice);
        if (
          slice.length >= 3 &&
          slice[0] === 0xef &&
          slice[1] === 0xbb &&
          slice[2] === 0xbf &&
          decoded.charCodeAt(0) !== 0xfeff
        ) {
          return `\uFEFF${decoded}`;
        }
        return decoded;
      }
      case 'ascii': {
        let result = '';
        for (let i = 0; i < slice.length; i++) {
          result += String.fromCharCode(slice[i] & 0x7f);
        }
        return result;
      }
      case 'latin1': {
        let result = '';
        for (let i = 0; i < slice.length; i++) {
          result += String.fromCharCode(slice[i]);
        }
        return result;
      }
      case 'hex': {
        let result = '';
        for (let i = 0; i < slice.length; i++) {
          result += slice[i].toString(16).padStart(2, '0');
        }
        return result;
      }
      case 'base64': {
        let binary = '';
        for (let i = 0; i < slice.length; i++) {
          binary += String.fromCharCode(slice[i]);
        }
        return btoa(binary);
      }
      case 'base64url': {
        let binary = '';
        for (let i = 0; i < slice.length; i++) {
          binary += String.fromCharCode(slice[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      }
      case 'utf16le': {
        let result = '';
        for (let i = 0; i < slice.length - 1; i += 2) {
          result += String.fromCharCode(slice[i] | (slice[i + 1] << 8));
        }
        return result;
      }
    }
  }

  /**
   * Write string to buffer.
   */
  write(string: string, offset = 0, length?: number, encoding?: BufferEncoding): number {
    let writeEncoding = encoding;
    let writeLength = length;

    if (typeof length === 'string') {
      writeEncoding = length;
      writeLength = undefined;
    } else if (typeof offset === 'string') {
      writeEncoding = offset;
      offset = 0;
      writeLength = undefined;
    }

    const data = Buffer.from(string, writeEncoding);
    const bytesToWrite = Math.min(
      writeLength ?? data.length,
      this.length - offset,
      data.length
    );

    if (bytesToWrite <= 0) {
      return 0;
    }
    this.set(data.subarray(0, bytesToWrite), offset);
    return bytesToWrite;
  }

  // Read/write integer methods (big-endian and little-endian)
  
  readBigInt64BE(offset = 0): bigint {
    offset = validateOffset(offset, 8, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getBigInt64(0, false);
  }

  readBigInt64LE(offset = 0): bigint {
    offset = validateOffset(offset, 8, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getBigInt64(0, true);
  }

  readBigUInt64BE(offset = 0): bigint {
    offset = validateOffset(offset, 8, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getBigUint64(0, false);
  }

  readBigUInt64LE(offset = 0): bigint {
    offset = validateOffset(offset, 8, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getBigUint64(0, true);
  }

  readDoubleBE(offset = 0): number {
    offset = validateOffset(offset, 8, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getFloat64(0, false);
  }

  readDoubleLE(offset = 0): number {
    offset = validateOffset(offset, 8, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getFloat64(0, true);
  }

  readFloatBE(offset = 0): number {
    offset = validateOffset(offset, 4, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getFloat32(0, false);
  }

  readFloatLE(offset = 0): number {
    offset = validateOffset(offset, 4, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getFloat32(0, true);
  }

  readInt8(offset = 0): number {
    offset = validateOffset(offset, 1, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getInt8(0);
  }

  readInt16BE(offset = 0): number {
    offset = validateOffset(offset, 2, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getInt16(0, false);
  }

  readInt16LE(offset = 0): number {
    offset = validateOffset(offset, 2, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getInt16(0, true);
  }

  readInt32BE(offset = 0): number {
    offset = validateOffset(offset, 4, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getInt32(0, false);
  }

  readInt32LE(offset = 0): number {
    offset = validateOffset(offset, 4, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getInt32(0, true);
  }

  readUInt8(offset = 0): number {
    offset = validateOffset(offset, 1, this.length);
    return this[offset];
  }

  readUInt16BE(offset = 0): number {
    offset = validateOffset(offset, 2, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getUint16(0, false);
  }

  readUInt16LE(offset = 0): number {
    offset = validateOffset(offset, 2, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getUint16(0, true);
  }

  readUInt32BE(offset = 0): number {
    offset = validateOffset(offset, 4, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getUint32(0, false);
  }

  readUInt32LE(offset = 0): number {
    offset = validateOffset(offset, 4, this.length);
    return new DataView(this.buffer, this.byteOffset + offset).getUint32(0, true);
  }

  readUIntBE(offset?: number, byteLength?: number): number {
    return readVariableUint(this, offset, byteLength, false);
  }

  readUIntLE(offset?: number, byteLength?: number): number {
    return readVariableUint(this, offset, byteLength, true);
  }

  readIntBE(offset?: number, byteLength?: number): number {
    return readVariableInt(this, offset, byteLength, false);
  }

  readIntLE(offset?: number, byteLength?: number): number {
    return readVariableInt(this, offset, byteLength, true);
  }

  writeBigInt64BE(value: bigint, offset = 0): number {
    validateBigIntWrite(value, true);
    validateFixedWidthOffset(offset, 8, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setBigInt64(0, value, false);
    return offset + 8;
  }

  writeBigInt64LE(value: bigint, offset = 0): number {
    validateBigIntWrite(value, true);
    validateFixedWidthOffset(offset, 8, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setBigInt64(0, value, true);
    return offset + 8;
  }

  writeBigUInt64BE(value: bigint, offset = 0): number {
    validateBigIntWrite(value, false);
    validateFixedWidthOffset(offset, 8, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setBigUint64(0, value, false);
    return offset + 8;
  }

  writeBigUInt64LE(value: bigint, offset = 0): number {
    validateBigIntWrite(value, false);
    validateFixedWidthOffset(offset, 8, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setBigUint64(0, value, true);
    return offset + 8;
  }

  writeDoubleBE(value: number, offset = 0): number {
    new DataView(this.buffer, this.byteOffset + offset).setFloat64(0, value, false);
    return offset + 8;
  }

  writeDoubleLE(value: number, offset = 0): number {
    new DataView(this.buffer, this.byteOffset + offset).setFloat64(0, value, true);
    return offset + 8;
  }

  writeFloatBE(value: number, offset = 0): number {
    new DataView(this.buffer, this.byteOffset + offset).setFloat32(0, value, false);
    return offset + 4;
  }

  writeFloatLE(value: number, offset = 0): number {
    new DataView(this.buffer, this.byteOffset + offset).setFloat32(0, value, true);
    return offset + 4;
  }

  writeInt8(value: number, offset = 0): number {
    validateIntegerWriteValue(value, -0x80, 0x7f, '>= -128 and <= 127');
    offset = validateOffset(offset, 1, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setInt8(0, value);
    return offset + 1;
  }

  writeInt16BE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, -0x8000, 0x7fff, '>= -32768 and <= 32767');
    offset = validateOffset(offset, 2, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setInt16(0, value, false);
    return offset + 2;
  }

  writeInt16LE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, -0x8000, 0x7fff, '>= -32768 and <= 32767');
    offset = validateOffset(offset, 2, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setInt16(0, value, true);
    return offset + 2;
  }

  writeInt32BE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, -0x80000000, 0x7fffffff, '>= -2147483648 and <= 2147483647');
    offset = validateOffset(offset, 4, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setInt32(0, value, false);
    return offset + 4;
  }

  writeInt32LE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, -0x80000000, 0x7fffffff, '>= -2147483648 and <= 2147483647');
    offset = validateOffset(offset, 4, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setInt32(0, value, true);
    return offset + 4;
  }

  writeUInt8(value: number, offset = 0): number {
    validateIntegerWriteValue(value, 0, 0xff, '>= 0 and <= 255');
    offset = validateOffset(offset, 1, this.length);
    this[offset] = value & 0xff;
    return offset + 1;
  }

  writeUInt16BE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, 0, 0xffff, '>= 0 and <= 65535');
    offset = validateOffset(offset, 2, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setUint16(0, value, false);
    return offset + 2;
  }

  writeUInt16LE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, 0, 0xffff, '>= 0 and <= 65535');
    offset = validateOffset(offset, 2, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setUint16(0, value, true);
    return offset + 2;
  }

  writeUInt32BE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, 0, 0xffffffff, '>= 0 and <= 4294967295');
    offset = validateOffset(offset, 4, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setUint32(0, value, false);
    return offset + 4;
  }

  writeUInt32LE(value: number, offset = 0): number {
    validateIntegerWriteValue(value, 0, 0xffffffff, '>= 0 and <= 4294967295');
    offset = validateOffset(offset, 4, this.length);
    new DataView(this.buffer, this.byteOffset + offset).setUint32(0, value, true);
    return offset + 4;
  }

  writeUIntBE(value: number, offset: number, byteLength: number): number {
    return writeVariableUint(this, value, offset, byteLength, false);
  }

  writeUIntLE(value: number, offset: number, byteLength: number): number {
    return writeVariableUint(this, value, offset, byteLength, true);
  }

  writeIntBE(value: number, offset: number, byteLength: number): number {
    return writeVariableInt(this, value, offset, byteLength, false);
  }

  writeIntLE(value: number, offset: number, byteLength: number): number {
    return writeVariableInt(this, value, offset, byteLength, true);
  }

  readUint8(offset = 0): number {
    return this.readUInt8(offset);
  }

  readUint16BE(offset = 0): number {
    return this.readUInt16BE(offset);
  }

  readUint16LE(offset = 0): number {
    return this.readUInt16LE(offset);
  }

  readUint32BE(offset = 0): number {
    return this.readUInt32BE(offset);
  }

  readUint32LE(offset = 0): number {
    return this.readUInt32LE(offset);
  }

  readUintBE(offset?: number, byteLength?: number): number {
    return this.readUIntBE(offset, byteLength);
  }

  readUintLE(offset?: number, byteLength?: number): number {
    return this.readUIntLE(offset, byteLength);
  }

  readBigUint64BE(offset = 0): bigint {
    return this.readBigUInt64BE(offset);
  }

  readBigUint64LE(offset = 0): bigint {
    return this.readBigUInt64LE(offset);
  }

  writeUint8(value: number, offset = 0): number {
    return this.writeUInt8(value, offset);
  }

  writeUint16BE(value: number, offset = 0): number {
    return this.writeUInt16BE(value, offset);
  }

  writeUint16LE(value: number, offset = 0): number {
    return this.writeUInt16LE(value, offset);
  }

  writeUint32BE(value: number, offset = 0): number {
    return this.writeUInt32BE(value, offset);
  }

  writeUint32LE(value: number, offset = 0): number {
    return this.writeUInt32LE(value, offset);
  }

  writeUintBE(value: number, offset: number, byteLength: number): number {
    return this.writeUIntBE(value, offset, byteLength);
  }

  writeUintLE(value: number, offset: number, byteLength: number): number {
    return this.writeUIntLE(value, offset, byteLength);
  }

  writeBigUint64BE(value: bigint, offset = 0): number {
    return this.writeBigUInt64BE(value, offset);
  }

  writeBigUint64LE(value: bigint, offset = 0): number {
    return this.writeBigUInt64LE(value, offset);
  }

  [Symbol.iterator](): IterableIterator<number> {
    return super.values();
  }

  entries(): IterableIterator<[number, number]> {
    return super.entries();
  }

  keys(): IterableIterator<number> {
    return super.keys();
  }

  values(): IterableIterator<number> {
    return super.values();
  }

  [Symbol.for('nodejs.util.inspect.custom')](_depth?: number, _opts?: unknown): string {
    if (this.length === 0) {
      return '<Buffer >';
    }
    const hexBytes: string[] = [];
    const limit = Math.min(this.length, 50);
    for (let i = 0; i < limit; i++) {
      hexBytes.push(this[i].toString(16).padStart(2, '0'));
    }
    const suffix = this.length > 50 ? ` ... ${this.length - 50} more bytes` : '';
    return `<Buffer ${hexBytes.join(' ')}${suffix}>`;
  }

  get parent(): ArrayBufferLike {
    return this.buffer;
  }

  get offset(): number {
    return this.byteOffset;
  }

  get [Symbol.toStringTag](): string {
    return 'Buffer';
  }
}

/**
 * Normalize encoding name to standard form.
 */
function normalizeEncoding(encoding: BufferEncoding | string | unknown): NormalizedEncoding {
  const value = typeof encoding === 'string' ? encoding : String(encoding);
  switch (value.toLowerCase()) {
    case 'utf8':
    case 'utf-8':
      return 'utf8';
    case 'ascii':
      return 'ascii';
    case 'latin1':
    case 'binary':
      return 'latin1';
    case 'hex':
      return 'hex';
    case 'base64':
      return 'base64';
    case 'base64url':
      return 'base64url';
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return 'utf16le';
    default:
      throw makeUnknownEncodingError(value);
  }
}

function normalizeEncodingOrUtf8(encoding: unknown): NormalizedEncoding {
  if (typeof encoding !== 'string' || encoding === '') {
    return 'utf8';
  }
  try {
    return normalizeEncoding(encoding);
  } catch {
    return 'utf8';
  }
}

function utf8ByteLength(value: string): number {
  let total = 0;

  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) {
      total += 1;
      continue;
    }
    if (code <= 0x7ff) {
      total += 2;
      continue;
    }
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        total += 4;
        index += 1;
        continue;
      }
    }
    total += 3;
  }

  return total;
}

function decodeBase64Char(code: number): number {
  if (code >= 0x41 && code <= 0x5a) return code - 0x41;
  if (code >= 0x61 && code <= 0x7a) return code - 0x47;
  if (code >= 0x30 && code <= 0x39) return code + 0x04;
  if (code === 0x2b || code === 0x2d) return 62;
  if (code === 0x2f || code === 0x5f) return 63;
  return -1;
}

function decodeBase64Bytes(value: string): Uint8Array {
  const sextets: number[] = [];
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d || code === 0x20) {
      continue;
    }
    if (code === 0x3d) {
      break;
    }
    const sextet = decodeBase64Char(code);
    if (sextet >= 0) {
      sextets.push(sextet);
    }
  }

  const fullGroups = Math.floor(sextets.length / 4);
  const remainder = sextets.length % 4;
  let byteLength = fullGroups * 3;
  if (remainder === 2) {
    byteLength += 1;
  } else if (remainder === 3) {
    byteLength += 2;
  }

  const bytes = new Uint8Array(byteLength);
  let outIndex = 0;
  let sextetIndex = 0;

  for (let group = 0; group < fullGroups; group++) {
    const a = sextets[sextetIndex++];
    const b = sextets[sextetIndex++];
    const c = sextets[sextetIndex++];
    const d = sextets[sextetIndex++];
    bytes[outIndex++] = (a << 2) | (b >> 4);
    bytes[outIndex++] = ((b & 0x0f) << 4) | (c >> 2);
    bytes[outIndex++] = ((c & 0x03) << 6) | d;
  }

  if (remainder === 2) {
    const a = sextets[sextetIndex++];
    const b = sextets[sextetIndex++];
    bytes[outIndex++] = (a << 2) | (b >> 4);
  } else if (remainder === 3) {
    const a = sextets[sextetIndex++];
    const b = sextets[sextetIndex++];
    const c = sextets[sextetIndex++];
    bytes[outIndex++] = (a << 2) | (b >> 4);
    bytes[outIndex++] = ((b & 0x0f) << 4) | (c >> 2);
  }

  return bytes;
}

function validateBufferSize(size: number): number {
  if (typeof size !== 'number') {
    throw makeInvalidArgTypeError('size', 'of type number', size);
  }
  if (Number.isNaN(size)) {
    throw createOutOfRangeError('size', 'a non-negative integer', 'NaN');
  }
  if (!Number.isFinite(size) || size < 0 || size > Buffer.constants.MAX_LENGTH) {
    throw createOutOfRangeError('size', `>= 0 && <= ${Buffer.constants.MAX_LENGTH}`, size);
  }
  return normalizeInteger(size);
}

function isArrayBufferLike(value: unknown): value is ArrayBuffer | SharedArrayBuffer {
  return getArrayBufferByteLength(value) !== null;
}

function getArrayBufferByteLength(value: unknown): number | null {
  if (!value || typeof value !== 'object') {
    return null;
  }
  const tag = Object.prototype.toString.call(value);
  if (tag !== '[object ArrayBuffer]' && tag !== '[object SharedArrayBuffer]') {
    return null;
  }
  try {
    return typeof (value as ArrayBuffer | SharedArrayBuffer).byteLength === 'number'
      ? (value as ArrayBuffer | SharedArrayBuffer).byteLength
      : null;
  } catch {
    return null;
  }
}

function isUint8ArrayLike(value: unknown): value is Uint8Array {
  return !!(
    value &&
    typeof value === 'object' &&
    (value instanceof Buffer || Object.prototype.toString.call(value) === '[object Uint8Array]')
  );
}

function toArrayLikeLength(value: unknown): number {
  const raw = Number((value as { length?: unknown })?.length);
  if (!Number.isFinite(raw) || raw <= 0) {
    return 0;
  }
  return Math.min(Math.floor(raw), 0x7fffffff);
}

function formatReceivedValue(value: unknown, quoteStrings = false): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') {
    return quoteStrings ? `type string ('${value}')` : `type string (${value})`;
  }
  if (typeof value === 'function') {
    return `function ${(value as Function).name || '<anonymous>'}`;
  }
  if (typeof value !== 'object') {
    return `type ${typeof value} (${String(value)})`;
  }
  const ctorName = (value as { constructor?: { name?: string } }).constructor?.name;
  if (ctorName) {
    return `an instance of ${ctorName}`;
  }
  return String(value);
}

function makeInvalidArgTypeError(
  name: string,
  expected: string,
  value: unknown,
  quoteStrings = false,
): TypeError & { code: string } {
  const err = new TypeError(
    `The "${name}" argument must be ${expected}. Received ${formatReceivedValue(value, quoteStrings)}`,
  ) as TypeError & { code: string };
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function makeFirstArgumentError(value: unknown): TypeError & { code: string } {
  const err = new TypeError(
    'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. ' +
      `Received ${formatReceivedValue(value)}`,
  ) as TypeError & { code: string };
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function makeUnknownEncodingError(encoding: string): TypeError & { code: string } {
  const err = new TypeError(`Unknown encoding: ${encoding}`) as TypeError & { code: string };
  err.code = 'ERR_UNKNOWN_ENCODING';
  return err;
}

function createOutOfRangeError(
  name: string,
  expectation: string,
  received: unknown,
): RangeError & { code: string } {
  const err = new RangeError(
    `The value of "${name}" is out of range. It must be ${expectation}. Received ${String(received)}`,
  ) as RangeError & { code: string };
  err.code = 'ERR_OUT_OF_RANGE';
  return err;
}

function makeBufferBoundsError(which: 'offset' | 'length'): RangeError & { code: string } {
  const err = new RangeError(`"${which}" is outside of buffer bounds`) as RangeError & { code: string };
  err.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
  return err;
}

function normalizeInteger(value: number): number {
  return value < 0 ? Math.ceil(value) : Math.floor(value);
}

function normalizeToStringRangeIndex(value: unknown, bufferLength: number, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  let numeric = Number(value);
  if (Number.isNaN(numeric)) {
    numeric = 0;
  }
  if (!Number.isFinite(numeric)) {
    return numeric < 0 ? 0 : bufferLength;
  }
  numeric = normalizeInteger(numeric);
  if (numeric < 0) {
    return 0;
  }
  if (numeric > bufferLength) {
    return bufferLength;
  }
  return numeric;
}

function normalizeArrayBufferOffset(value: unknown, totalLength: number): number {
  if (value === undefined) {
    return 0;
  }
  const offset = Number(value);
  if (Number.isNaN(offset)) {
    return 0;
  }
  if (!Number.isFinite(offset)) {
    throw makeBufferBoundsError('offset');
  }
  const normalized = normalizeInteger(offset);
  if (normalized < 0 || normalized > totalLength) {
    throw makeBufferBoundsError('offset');
  }
  return normalized;
}

function normalizeArrayBufferLength(value: unknown, totalLength: number, offset: number): number {
  if (value === undefined) {
    return totalLength - offset;
  }
  const length = Number(value);
  if (Number.isNaN(length)) {
    return 0;
  }
  if (!Number.isFinite(length)) {
    throw makeBufferBoundsError('length');
  }
  const normalized = normalizeInteger(length);
  if (normalized < 0 || offset + normalized > totalLength) {
    throw makeBufferBoundsError('length');
  }
  return normalized;
}

function compareByteRanges(
  left: Uint8Array,
  right: Uint8Array,
  leftStart: number,
  leftEnd: number,
  rightStart: number,
  rightEnd: number,
): -1 | 0 | 1 {
  const leftLength = leftEnd - leftStart;
  const rightLength = rightEnd - rightStart;
  const length = Math.min(leftLength, rightLength);
  for (let i = 0; i < length; i++) {
    const leftValue = left[leftStart + i];
    const rightValue = right[rightStart + i];
    if (leftValue !== rightValue) {
      return leftValue < rightValue ? -1 : 1;
    }
  }
  if (leftLength === rightLength) {
    return 0;
  }
  return leftLength < rightLength ? -1 : 1;
}

function getWritableByteView(value: unknown): Uint8Array | null {
  if (isUint8ArrayLike(value)) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return null;
}

function normalizeCompareIndex(value: unknown, name: string, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'number') {
    throw makeInvalidArgTypeError(name, 'of type number', value);
  }
  if (Number.isNaN(value) || !Number.isInteger(value)) {
    throw createOutOfRangeError(name, 'an integer', value);
  }
  if (!Number.isFinite(value)) {
    throw createOutOfRangeError(name, '>= 0 && <= 2147483647', value);
  }
  return normalizeInteger(value);
}

function normalizeCopyIndex(value: unknown, name: string, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  const numeric = Number(value);
  if (Number.isNaN(numeric)) {
    return fallback;
  }
  if (!Number.isFinite(numeric)) {
    throw createOutOfRangeError(name, '>= 0', value);
  }
  return normalizeInteger(numeric);
}

function validateBigIntWrite(value: unknown, signed: boolean): void {
  if (typeof value !== 'bigint') {
    throw makeInvalidArgTypeError('value', 'of type bigint', value);
  }
  const min = signed ? -(1n << 63n) : 0n;
  const max = signed ? (1n << 63n) - 1n : (1n << 64n) - 1n;
  if (value < min || value > max) {
    const expectation = signed
      ? '>= -(2n ** 63n) and < 2n ** 63n'
      : '>= 0n and < 2n ** 64n';
    const err = new RangeError(
      `The value of "value" is out of range. It must be ${expectation}. Received ${formatBigInt(value)}`,
    ) as RangeError & { code: string };
    err.code = 'ERR_OUT_OF_RANGE';
    throw err;
  }
}

function formatBigInt(value: bigint): string {
  const negative = value < 0n;
  const digits = (negative ? -value : value).toString();
  let formatted = '';
  const prefixLength = digits.length % 3;
  if (prefixLength > 0) {
    formatted = digits.slice(0, prefixLength);
  }
  for (let index = prefixLength; index < digits.length; index += 3) {
    if (formatted) {
      formatted += '_';
    }
    formatted += digits.slice(index, index + 3);
  }
  return `${negative ? '-' : ''}${formatted || '0'}n`;
}

function formatIntegerForRangeError(value: number): string {
  if (!Number.isFinite(value) || Number.isNaN(value)) {
    return String(value);
  }
  const negative = value < 0;
  const digits = String(Math.trunc(Math.abs(value)));
  let formatted = '';
  const prefixLength = digits.length % 3;
  if (prefixLength > 0) {
    formatted = digits.slice(0, prefixLength);
  }
  for (let index = prefixLength; index < digits.length; index += 3) {
    if (formatted) {
      formatted += '_';
    }
    formatted += digits.slice(index, index + 3);
  }
  return `${negative ? '-' : ''}${formatted || '0'}`;
}

function validateIntegerWriteValue(
  value: unknown,
  min: number,
  max: number,
  expectation: string,
  formatReceived = false,
): number {
  if (typeof value !== 'number') {
    throw makeInvalidArgTypeError('value', 'of type number', value);
  }
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < min || value > max) {
    throw createOutOfRangeError(
      'value',
      expectation,
      formatReceived ? formatIntegerForRangeError(value) : value,
    );
  }
  return value;
}

function validateFixedWidthOffset(offset: number, byteLength: number, bufferLength: number): void {
  if (!Number.isInteger(offset) || offset < 0 || offset + byteLength > bufferLength) {
    throw createOutOfRangeError('offset', `>= 0 and <= ${Math.max(bufferLength - byteLength, 0)}`, offset);
  }
}

function makeOutOfBoundsReadError(): RangeError & { code: string } {
  const err = new RangeError('Attempt to access memory outside buffer bounds') as RangeError & { code: string };
  err.code = 'ERR_BUFFER_OUT_OF_BOUNDS';
  return err;
}

function validateOffset(offset: unknown, byteLength: number, bufferLength: number): number {
  if (offset === undefined) {
    return 0;
  }
  if (typeof offset !== 'number') {
    throw makeInvalidArgTypeError('offset', 'of type number', offset);
  }
  if (Number.isNaN(offset) || (Number.isFinite(offset) && !Number.isInteger(offset))) {
    throw createOutOfRangeError('offset', 'an integer', offset);
  }
  const maxOffset = Math.max(bufferLength - byteLength, 0);
  if (!Number.isFinite(offset) || offset < 0 || offset > maxOffset) {
    if (bufferLength < byteLength && offset >= 0 && Number.isFinite(offset)) {
      throw makeOutOfBoundsReadError();
    }
    throw createOutOfRangeError('offset', `>= 0 and <= ${maxOffset}`, offset);
  }
  if (offset + byteLength > bufferLength) {
    throw makeOutOfBoundsReadError();
  }
  return offset;
}

function validateRequiredOffset(offset: unknown, byteLength: number, bufferLength: number): number {
  if (offset === undefined) {
    throw makeInvalidArgTypeError('offset', 'of type number', offset);
  }
  return validateOffset(offset, byteLength, bufferLength);
}

function validateByteLength(byteLength: unknown): number {
  if (typeof byteLength !== 'number') {
    throw makeInvalidArgTypeError('byteLength', 'of type number', byteLength);
  }
  if (Number.isNaN(byteLength) || (Number.isFinite(byteLength) && !Number.isInteger(byteLength))) {
    throw createOutOfRangeError('byteLength', 'an integer', byteLength);
  }
  if (!Number.isFinite(byteLength) || byteLength < 1 || byteLength > 6) {
    throw createOutOfRangeError('byteLength', '>= 1 and <= 6', byteLength);
  }
  return byteLength;
}

function readVariableUint(
  buffer: Uint8Array,
  offset: unknown,
  byteLength: unknown,
  littleEndian: boolean,
): number {
  const actualByteLength = validateByteLength(byteLength);
  const actualOffset = validateRequiredOffset(offset, actualByteLength, buffer.length);

  let value = 0;
  if (littleEndian) {
    for (let index = actualByteLength - 1; index >= 0; index--) {
      value = (value * 256) + buffer[actualOffset + index];
    }
    return value;
  }

  for (let index = 0; index < actualByteLength; index++) {
    value = (value * 256) + buffer[actualOffset + index];
  }
  return value;
}

function readVariableInt(
  buffer: Uint8Array,
  offset: unknown,
  byteLength: unknown,
  littleEndian: boolean,
): number {
  const actualByteLength = validateByteLength(byteLength);
  const unsigned = readVariableUint(buffer, offset, actualByteLength, littleEndian);
  const bits = actualByteLength * 8;
  const signBit = 2 ** (bits - 1);
  const fullRange = 2 ** bits;
  return unsigned >= signBit ? unsigned - fullRange : unsigned;
}

function writeVariableUint(
  buffer: Uint8Array,
  value: number,
  offset: number,
  byteLength: number,
  littleEndian: boolean,
): number {
  const actualByteLength = validateByteLength(byteLength);
  const actualOffset = validateRequiredOffset(offset, actualByteLength, buffer.length);
  const max = (2 ** (actualByteLength * 8)) - 1;
  const expectation = actualByteLength > 4
    ? `>= 0 and < 2 ** ${actualByteLength * 8}`
    : `>= 0 and <= ${max}`;
  let remaining = validateIntegerWriteValue(value, 0, max, expectation, actualByteLength > 4);

  if (littleEndian) {
    for (let i = 0; i < actualByteLength; i++) {
      buffer[actualOffset + i] = remaining & 0xff;
      remaining = Math.floor(remaining / 256);
    }
  } else {
    for (let i = actualByteLength - 1; i >= 0; i--) {
      buffer[actualOffset + i] = remaining & 0xff;
      remaining = Math.floor(remaining / 256);
    }
  }

  return actualOffset + actualByteLength;
}

function writeVariableInt(
  buffer: Uint8Array,
  value: number,
  offset: number,
  byteLength: number,
  littleEndian: boolean,
): number {
  const actualByteLength = validateByteLength(byteLength);
  const min = -(2 ** (actualByteLength * 8 - 1));
  const max = (2 ** (actualByteLength * 8 - 1)) - 1;
  const expectation = actualByteLength > 4
    ? `>= -(2 ** ${actualByteLength * 8 - 1}) and < 2 ** ${actualByteLength * 8 - 1}`
    : `>= ${min} and <= ${max}`;
  const actualValue = validateIntegerWriteValue(
    value,
    min,
    max,
    expectation,
    actualByteLength > 4,
  );
  const fullRange = 2 ** (actualByteLength * 8);
  const unsigned = actualValue < 0 ? actualValue + fullRange : actualValue;
  return writeVariableUint(buffer, unsigned, offset, actualByteLength, littleEndian);
}

/**
 * Maximum buffer size (same as Buffer.constants.MAX_LENGTH).
 */
export const kMaxLength = 2 ** 31 - 1;

/**
 * SlowBuffer is deprecated but some packages still use it.
 * It's equivalent to Buffer.allocUnsafeSlow.
 */
export const SlowBuffer = Buffer.allocUnsafeSlow.bind(Buffer);

const bufferPrototype = Buffer.prototype as Record<string, unknown>;
for (const [alias, original] of [
  ['readUint8', 'readUInt8'],
  ['readUint16LE', 'readUInt16LE'],
  ['readUint16BE', 'readUInt16BE'],
  ['readUint32LE', 'readUInt32LE'],
  ['readUint32BE', 'readUInt32BE'],
  ['readUintLE', 'readUIntLE'],
  ['readUintBE', 'readUIntBE'],
  ['readBigUint64LE', 'readBigUInt64LE'],
  ['readBigUint64BE', 'readBigUInt64BE'],
  ['writeUint8', 'writeUInt8'],
  ['writeUint16LE', 'writeUInt16LE'],
  ['writeUint16BE', 'writeUInt16BE'],
  ['writeUint32LE', 'writeUInt32LE'],
  ['writeUint32BE', 'writeUInt32BE'],
  ['writeUintLE', 'writeUIntLE'],
  ['writeUintBE', 'writeUIntBE'],
  ['writeBigUint64LE', 'writeBigUInt64LE'],
  ['writeBigUint64BE', 'writeBigUInt64BE'],
] as const) {
  Object.defineProperty(bufferPrototype, alias, {
    value: bufferPrototype[original],
    writable: true,
    configurable: true,
  });
}

export default Buffer;
