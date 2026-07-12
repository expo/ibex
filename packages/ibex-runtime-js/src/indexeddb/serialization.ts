/**
 * Structured serialization for IndexedDB values and keys.
 *
 * Record values are persisted as a versioned SQLite BLOB envelope: a compact
 * JSON metadata header followed by raw binary attachments. Keys remain a
 * deterministic text encoding because SQLite equality/order predicates use
 * them directly. Plain `JSON.stringify` silently corrupts the
 * structured-clone-compatible types IndexedDB is required to preserve: Dates
 * become ISO strings, typed arrays become `{"0":...}` plain objects, and
 * Map/Set/undefined are dropped entirely. This module round-trips those types
 * with a tagged encoding so `get()` returns a faithful clone of what `put()`
 * stored, and so Date/binary *keys* deserialize back to their real type (which
 * `compareKeys` needs in order to sort and range-filter them correctly).
 *
 * The encoding wraps special types in an object carrying a reserved tag key.
 * User objects that happen to contain that key are escaped so they round-trip
 * unambiguously.
 *
 * Separately, `encodeOrderedKey` produces an *order-preserving* text encoding
 * of a key (see the block at the bottom of this file). The tagged-JSON key
 * above is deterministic and reversible but does NOT sort lexicographically, so
 * range/order queries had to scan the whole table and filter/sort in JS. The
 * ordered encoding lets SQLite do `WHERE keyenc BETWEEN ? AND ?` and
 * `ORDER BY keyenc` in the same order IndexedDB's compareKeys() defines, so the
 * filtering and ordering push down into SQL (ENG-22999).
 */

import { DOMException } from './utils';

const TAG = '__idb_tag__';
const VALUE_MAGIC = new Uint8Array([0x49, 0x44, 0x42, 0x32]); // "IDB2"
const VALUE_HEADER_BYTES = VALUE_MAGIC.length + 4;

interface BinaryEncodeContext {
  parts: Uint8Array[];
  length: number;
}

// Blobs decoded from our own persistent representation may be host Blobs that
// do not expose Ibex's synchronous `_getBytes()` hook. Remember the bytes on
// those instances so a value can be cloned again (for example while resolving
// an auto-increment key) without falling back to an asynchronous Blob read.
// WeakMap keeps this bookkeeping invisible to user code and non-retaining.
interface DecodedBlobState {
  bytes: Uint8Array;
  tag: 'Blob' | 'File';
}

const decodedBlobState = new WeakMap<object, DecodedBlobState>();

function bytesToBase64(bytes: Uint8Array): string {
  const BufferCtor = (globalThis as any).Buffer;
  if (BufferCtor?.from) return BufferCtor.from(bytes).toString('base64');
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(data: string): Uint8Array {
  const BufferCtor = (globalThis as any).Buffer;
  if (BufferCtor?.from) return new Uint8Array(BufferCtor.from(data, 'base64'));
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodedBytes(value: any, binary?: Uint8Array): Uint8Array {
  if (Array.isArray(value.bin) && binary) {
    const offset = Number(value.bin[0]);
    const length = Number(value.bin[1]);
    if (
      !Number.isSafeInteger(offset) ||
      !Number.isSafeInteger(length) ||
      offset < 0 ||
      length < 0 ||
      offset + length > binary.byteLength
    ) {
      throw new DOMException('IndexedDB binary value is corrupt.', 'DataError');
    }
    return binary.slice(offset, offset + length);
  }
  return typeof value.data === 'string'
    ? base64ToBytes(value.data)
    : Uint8Array.from(value.bytes ?? []);
}

function encodeBytes(bytes: Uint8Array, binary?: BinaryEncodeContext): Record<string, any> {
  if (!binary) return { data: bytesToBase64(bytes) };
  const snapshot = bytes.slice();
  const offset = binary.length;
  binary.parts.push(snapshot);
  binary.length += snapshot.byteLength;
  return { bin: [offset, snapshot.byteLength] };
}

/**
 * Whether a value duck-types as a Blob/File. Detection is structural (tag +
 * size/type) rather than `instanceof` against the runtime Blob classes:
 * importing blob/Blob from here would drag this module into the
 * blob → streams → structuredClone → blob import cycle (File extends Blob
 * hits the TDZ), and it also keeps host-provided Blobs recognizable.
 * (ENG-23134)
 */
function blobLikeTag(value: any): 'Blob' | 'File' | null {
  const decoded = decodedBlobState.get(value);
  if (decoded) return decoded.tag;
  const tag = value?.[Symbol.toStringTag];
  if (tag !== 'Blob' && tag !== 'File') return null;
  if (typeof value.size !== 'number' || typeof value.type !== 'string') return null;
  return tag;
}

/**
 * Sync byte access for a Blob-like value. The Ibex runtime Blob exposes the
 * internal `_getBytes()` accessor (the same hook structuredClone uses); a
 * foreign host Blob without it cannot be read synchronously and must be
 * refused loudly rather than silently stored as `{}`. (ENG-23134)
 */
function blobBytes(value: any): Uint8Array | null {
  if (typeof value._getBytes === 'function') {
    return new Uint8Array(value._getBytes() as Uint8Array);
  }
  const decoded = decodedBlobState.get(value);
  if (decoded) return decoded.bytes.slice();
  return null;
}

const ERROR_CTORS: Record<string, ErrorConstructor> = Object.create(null);
for (const Ctor of [Error, EvalError, RangeError, ReferenceError, SyntaxError, TypeError, URIError]) {
  ERROR_CTORS[Ctor.name] = Ctor as ErrorConstructor;
}

/** Convert a value into a JSON-safe representation, tagging non-JSON types. */
function encode(value: any, binary?: BinaryEncodeContext): any {
  if (value === undefined) return { [TAG]: 'undefined' };
  if (value === null) return null;

  const t = typeof value;
  if (t === 'boolean' || t === 'string') return value;
  if (t === 'number') {
    if (Number.isNaN(value)) return { [TAG]: 'number', v: 'NaN' };
    if (value === Infinity) return { [TAG]: 'number', v: 'Infinity' };
    if (value === -Infinity) return { [TAG]: 'number', v: '-Infinity' };
    return value;
  }
  if (t === 'bigint') return { [TAG]: 'bigint', v: value.toString() };

  if (value instanceof Date) return { [TAG]: 'Date', ms: value.getTime() };
  if (value instanceof RegExp) return { [TAG]: 'RegExp', source: value.source, flags: value.flags };

  if (value instanceof ArrayBuffer) {
    return { [TAG]: 'ArrayBuffer', ...encodeBytes(new Uint8Array(value), binary) };
  }
  if (ArrayBuffer.isView(value)) {
    // Uint8Array, Float64Array, DataView, ... — reconstruct from raw bytes so
    // every view type (including BigInt typed arrays) round-trips uniformly.
    const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return { [TAG]: 'View', ctor: value.constructor.name, ...encodeBytes(bytes, binary) };
  }

  if (value instanceof Map) {
    return {
      [TAG]: 'Map',
      entries: Array.from(value.entries()).map(([k, v]) => [encode(k, binary), encode(v, binary)]),
    };
  }
  if (value instanceof Set) {
    return { [TAG]: 'Set', values: Array.from(value.values()).map((v) => encode(v, binary)) };
  }

  if (Array.isArray(value)) {
    return value.map((v) => encode(v, binary));
  }

  if (t === 'object') {
    // Blob/File have getters and no own enumerable keys, so the generic
    // object walk below silently stored a camera Blob as `{}` — the payload
    // was lost while put() reported success. (ENG-23134)
    const blobTag = blobLikeTag(value);
    if (blobTag !== null) {
      const bytes = blobBytes(value);
      if (bytes === null) {
        throw new DOMException(
          `${blobTag} value could not be serialized: no synchronous byte access.`,
          'DataCloneError',
        );
      }
      if (blobTag === 'File') {
        return {
          [TAG]: 'File',
          ...encodeBytes(bytes, binary),
          name: String(value.name),
          mime: String(value.type),
          lastModified: Number(value.lastModified),
        };
      }
      return { [TAG]: 'Blob', ...encodeBytes(bytes, binary), mime: String(value.type) };
    }

    // Error objects (structured clone serializes name/message/stack/cause);
    // previously these also collapsed to `{}`. (ENG-23134)
    if (value instanceof Error) {
      const out: Record<string, any> = {
        [TAG]: 'Error',
        name: String(value.name),
        message: String(value.message),
      };
      if (typeof value.stack === 'string') out.stack = value.stack;
      if ('cause' in value) out.cause = encode((value as any).cause, binary);
      return out;
    }

    // Boxed primitives are structured-clone-able ([[BooleanData]] etc.).
    // (ENG-23134)
    if (value instanceof Number || value instanceof String || value instanceof Boolean) {
      return { [TAG]: 'Boxed', v: encode(value.valueOf(), binary) };
    }

    // Types structured clone explicitly refuses — fail loudly instead of
    // storing an empty object. (ENG-23134)
    if (
      (typeof Promise !== 'undefined' && value instanceof Promise) ||
      (typeof WeakMap !== 'undefined' && value instanceof WeakMap) ||
      (typeof WeakSet !== 'undefined' && value instanceof WeakSet)
    ) {
      throw new DOMException(
        `${value.constructor?.name ?? 'This object'} could not be cloned.`,
        'DataCloneError',
      );
    }

    const out: Record<string, any> = {};
    for (const k of Object.keys(value)) {
      out[k] = encode(value[k], binary);
    }
    // A plain object that itself carries the reserved tag key must be escaped
    // so decode() does not mistake it for one of our wrappers.
    if (Object.prototype.hasOwnProperty.call(value, TAG)) {
      return { [TAG]: 'object', props: out };
    }
    return out;
  }

  // functions / symbols are not structured-cloneable (spec: DataCloneError).
  throw new DOMException(`Value of type ${t} could not be cloned.`, 'DataCloneError');
}

function decodePlainObject(obj: Record<string, any>, binary?: Uint8Array): Record<string, any> {
  const out: Record<string, any> = {};
  for (const k of Object.keys(obj)) {
    out[k] = decode(obj[k], binary);
  }
  return out;
}

/** Inverse of encode(). */
function decode(value: any, binary?: Uint8Array): any {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => decode(v, binary));

  const tag = value[TAG];
  if (typeof tag === 'string') {
    switch (tag) {
      case 'undefined':
        return undefined;
      case 'number':
        return value.v === 'NaN' ? NaN : value.v === 'Infinity' ? Infinity : -Infinity;
      case 'bigint':
        return BigInt(value.v);
      case 'Date':
        return new Date(value.ms);
      case 'RegExp':
        return new RegExp(value.source, value.flags);
      case 'ArrayBuffer':
        return decodedBytes(value, binary).buffer;
      case 'View': {
        const buf = decodedBytes(value, binary).buffer;
        const Ctor = (globalThis as any)[value.ctor];
        if (!Ctor) return buf; // Unknown view type — surface the raw buffer.
        return value.ctor === 'DataView' ? new DataView(buf) : new Ctor(buf);
      }
      case 'Map':
        return new Map(
          value.entries.map(([k, v]: [any, any]) => [decode(k, binary), decode(v, binary)]),
        );
      case 'Set':
        return new Set(value.values.map((v: any) => decode(v, binary)));
      case 'Blob': {
        // Reconstruct with the environment's Blob (the runtime bootstrap
        // installs the Ibex Blob there — see blobLikeTag for why this module
        // does not import it directly).
        const BlobCtor = (globalThis as any).Blob;
        if (!BlobCtor) {
          throw new DOMException('Blob is not available in this environment.', 'DataError');
        }
        const bytes = decodedBytes(value, binary);
        const blob = new BlobCtor([bytes], { type: value.mime });
        decodedBlobState.set(blob, { bytes: bytes.slice(), tag: 'Blob' });
        return blob;
      }
      case 'File': {
        const FileCtor = (globalThis as any).File;
        if (!FileCtor) {
          throw new DOMException('File is not available in this environment.', 'DataError');
        }
        const bytes = decodedBytes(value, binary);
        const file = new FileCtor([bytes], value.name, {
          type: value.mime,
          lastModified: value.lastModified,
        });
        decodedBlobState.set(file, { bytes: bytes.slice(), tag: 'File' });
        return file;
      }
      case 'Error': {
        const Ctor = ERROR_CTORS[value.name] ?? Error;
        const err: any = new Ctor(value.message);
        err.name = value.name;
        if (typeof value.stack === 'string') err.stack = value.stack;
        if ('cause' in value) err.cause = decode(value.cause, binary);
        return err;
      }
      case 'Boxed':
        return Object(decode(value.v, binary));
      case 'object':
        // Escaped user object — decode its properties as a plain object.
        return decodePlainObject(value.props, binary);
      default:
        // Unrecognized tag: treat as an ordinary object.
        return decodePlainObject(value, binary);
    }
  }
  return decodePlainObject(value, binary);
}

/**
 * Serialize a structured-clone-compatible value into a compact BLOB envelope.
 * Raw ArrayBuffer/view/Blob/File bytes are appended directly rather than
 * expanded to base64 or JSON number arrays.
 */
export function serializeValue(value: any): Uint8Array {
  const binary: BinaryEncodeContext = { parts: [], length: 0 };
  const header = new TextEncoder().encode(JSON.stringify(encode(value, binary)));
  const result = new Uint8Array(VALUE_HEADER_BYTES + header.byteLength + binary.length);
  result.set(VALUE_MAGIC, 0);
  new DataView(result.buffer).setUint32(VALUE_MAGIC.length, header.byteLength, true);
  result.set(header, VALUE_HEADER_BYTES);
  let offset = VALUE_HEADER_BYTES + header.byteLength;
  for (const part of binary.parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

/**
 * Deserialize a value produced by serializeValue(). TEXT rows from the v1
 * base64/tagged-JSON representation remain readable, allowing existing
 * databases to migrate lazily as records are rewritten.
 */
export function deserializeValue(stored: any): any {
  if (typeof stored === 'string') return decode(JSON.parse(stored));
  let bytes: Uint8Array;
  if (stored instanceof ArrayBuffer) {
    bytes = new Uint8Array(stored);
  } else if (ArrayBuffer.isView(stored)) {
    bytes = new Uint8Array(stored.buffer, stored.byteOffset, stored.byteLength);
  } else {
    throw new DOMException('IndexedDB value has an unsupported storage type.', 'DataError');
  }
  if (
    bytes.byteLength < VALUE_HEADER_BYTES ||
    !VALUE_MAGIC.every((byte, index) => bytes[index] === byte)
  ) {
    throw new DOMException('IndexedDB binary value has an invalid header.', 'DataError');
  }
  const headerLength = new DataView(
    bytes.buffer,
    bytes.byteOffset + VALUE_MAGIC.length,
    4,
  ).getUint32(0, true);
  const payloadOffset = VALUE_HEADER_BYTES + headerLength;
  if (payloadOffset > bytes.byteLength) {
    throw new DOMException('IndexedDB binary value is truncated.', 'DataError');
  }
  const header = new TextDecoder().decode(bytes.subarray(VALUE_HEADER_BYTES, payloadOffset));
  return decode(JSON.parse(header), bytes.subarray(payloadOffset));
}

/**
 * Canonicalize an IndexedDB key: the spec compares binary keys by their byte
 * sequences, so an ArrayBuffer and a typed-array view over the same bytes are
 * the SAME key. Serializing them with different tags made `get(buffer)` miss
 * a record `put()` with a view of identical bytes — and `add()` created a
 * duplicate row with an identical `keyenc`. Views fold to a bytes-only
 * ArrayBuffer before encoding, which also matches what the spec's "convert a
 * key to a value" hands back to script for binary keys. Arrays recurse.
 * (ENG-23134)
 */
export function canonicalizeKey(key: any): any {
  if (ArrayBuffer.isView(key)) {
    const bytes = new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
    return bytes.slice().buffer;
  }
  if (Array.isArray(key)) return key.map(canonicalizeKey);
  return key;
}

/**
 * Serialize an IndexedDB key to a canonical text form usable as a SQLite
 * primary-key column. Deterministic: keys the spec defines as equal always
 * produce identical text (so `WHERE key = ?` equality works — see
 * canonicalizeKey for binary keys), and deserializeKey() restores the key so
 * compareKeys() can order it.
 */
export function serializeKey(key: any): string {
  return JSON.stringify(encode(canonicalizeKey(key)));
}

/**
 * Deserialize a key previously produced by serializeKey().
 */
export function deserializeKey(text: string): any {
  return decode(JSON.parse(text));
}

// ===========================================================================
// Order-preserving key encoding (ENG-22999)
//
// Produces a text string whose default SQLite (BINARY / memcmp) ordering equals
// the IndexedDB key ordering that compareKeys() implements:
//   Number < Date < String < Binary < Array
// and, within each type, the spec ordering (numeric, ms, UTF-16 code units,
// unsigned byte-wise, element-wise). This is stored in a separate `keyenc`
// column so range predicates and ORDER BY can run in SQL instead of a full JS
// scan+sort. It is intentionally NOT reversible: keys are always reconstructed
// from the tagged-JSON `key` column, so the encoding only needs to be a total,
// deterministic, order-preserving embedding — never decoded.
//
// The alphabet of a scalar (non-array) encoding is a leading type tag digit
// ('1'..'5') plus lowercase hex, i.e. only bytes >= 0x30. Arrays additionally
// use three control bytes that all sort BELOW 0x30:
//   ORD_END (0x01) terminates an array, ORD_SEP (0x02) precedes each element,
//   ORD_ESC (0x03) escapes any control byte that appears inside a nested
//   element's encoding (so a nested array's structure can't collide with its
//   parent's separators). With escaping, an element's bytes are all >= ORD_ESC,
//   so ORD_END < ORD_SEP < every element byte — which is exactly what makes the
//   element-wise + shorter-is-smaller array ordering fall out of memcmp.
// ===========================================================================

const ORD_TAG_NUMBER = '1';
const ORD_TAG_DATE = '2';
const ORD_TAG_STRING = '3';
const ORD_TAG_BINARY = '4';
const ORD_TAG_ARRAY = '5';

const ORD_END = '\x01';
const ORD_SEP = '\x02';
const ORD_ESC = '\x03';

// Reused scratch view so the double->ordered-bits transform allocates nothing.
const _ordDataView = new DataView(new ArrayBuffer(8));

function hex8(n: number): string {
  return (n >>> 0).toString(16).padStart(8, '0');
}

/**
 * Map an IEEE-754 double onto a 64-bit unsigned integer whose ordering matches
 * the numeric ordering of the doubles, rendered as 16 fixed-width hex chars.
 * Positive numbers get the sign bit set; negatives are fully inverted. -0 is
 * normalized to +0 so it collates equal to 0 (compareKeys treats them equal).
 *
 * Done with two 32-bit halves rather than BigInt/getBigUint64 so it does not
 * depend on BigInt DataView methods being present in the host engine.
 */
function encodeDoubleOrdered(value: number): string {
  let v = value;
  if (Object.is(v, -0)) v = 0;
  _ordDataView.setFloat64(0, v, false); // big-endian, platform-independent
  let hi = _ordDataView.getUint32(0, false);
  let lo = _ordDataView.getUint32(4, false);
  if (hi & 0x80000000) {
    // Negative: invert every bit so more-negative sorts smaller.
    hi = ~hi >>> 0;
    lo = ~lo >>> 0;
  } else {
    // Positive / +0: set the sign bit so it sorts above all negatives.
    hi = (hi | 0x80000000) >>> 0;
  }
  return hex8(hi) + hex8(lo);
}

function ordBinaryBytes(v: any): Uint8Array {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
}

/**
 * Escape the array control bytes (ORD_END/ORD_SEP/ORD_ESC) inside a nested
 * element's encoding so they can't be confused with the enclosing array's
 * structure. Each control byte c (0x01..0x03) becomes ORD_ESC + (c + 0x30),
 * a two-char sequence beginning with 0x03; this per-symbol code is prefix-free
 * and order-preserving, so it preserves both ordering and the prefix relation.
 */
function ordEscape(s: string): string {
  // Fast path: scalar element encodings never contain control bytes.
  if (!/[\x01\x02\x03]/.test(s)) return s;
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 1 && c <= 3) {
      out += ORD_ESC + String.fromCharCode(c + 0x30);
    } else {
      out += s[i];
    }
  }
  return out;
}

function ordThrowInvalid(): never {
  throw new DOMException('The parameter is not a valid key.', 'DataError');
}

function encodeOrderedRaw(key: any): string {
  if (typeof key === 'number') {
    if (Number.isNaN(key)) ordThrowInvalid();
    return ORD_TAG_NUMBER + encodeDoubleOrdered(key);
  }
  if (key instanceof Date) {
    const t = key.getTime();
    if (Number.isNaN(t)) ordThrowInvalid();
    return ORD_TAG_DATE + encodeDoubleOrdered(t);
  }
  if (typeof key === 'string') {
    // One fixed-width (4 hex) group per UTF-16 code unit, matching the
    // code-unit comparison compareKeys() uses for strings.
    let out = ORD_TAG_STRING;
    for (let i = 0; i < key.length; i++) {
      out += key.charCodeAt(i).toString(16).padStart(4, '0');
    }
    return out;
  }
  if (key instanceof ArrayBuffer || ArrayBuffer.isView(key)) {
    const bytes = ordBinaryBytes(key);
    let out = ORD_TAG_BINARY;
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
  }
  if (Array.isArray(key)) {
    let out = ORD_TAG_ARRAY;
    for (const el of key) {
      out += ORD_SEP + ordEscape(encodeOrderedRaw(el));
    }
    out += ORD_END;
    return out;
  }
  ordThrowInvalid();
}

/**
 * Encode an IndexedDB key to an order-preserving text form (see block comment
 * above). Throws a DataError DOMException for anything that is not a valid key,
 * mirroring compareKeys().
 */
export function encodeOrderedKey(key: any): string {
  return encodeOrderedRaw(key);
}
