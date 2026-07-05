/**
 * Structured serialization for IndexedDB values and keys.
 *
 * Records are persisted into a SQLite TEXT column, so we need a lossless,
 * deterministic text encoding. Plain `JSON.stringify` silently corrupts the
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
 */

const TAG = '__idb_tag__';

function toByteArray(view: ArrayBufferView): number[] {
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  return Array.from(bytes);
}

/** Convert a value into a JSON-safe representation, tagging non-JSON types. */
function encode(value: any): any {
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
    return { [TAG]: 'ArrayBuffer', bytes: Array.from(new Uint8Array(value)) };
  }
  if (ArrayBuffer.isView(value)) {
    // Uint8Array, Float64Array, DataView, ... — reconstruct from raw bytes so
    // every view type (including BigInt typed arrays) round-trips uniformly.
    return { [TAG]: 'View', ctor: value.constructor.name, bytes: toByteArray(value) };
  }

  if (value instanceof Map) {
    return { [TAG]: 'Map', entries: Array.from(value.entries()).map(([k, v]) => [encode(k), encode(v)]) };
  }
  if (value instanceof Set) {
    return { [TAG]: 'Set', values: Array.from(value.values()).map(encode) };
  }

  if (Array.isArray(value)) {
    return value.map(encode);
  }

  if (t === 'object') {
    const out: Record<string, any> = {};
    for (const k of Object.keys(value)) {
      out[k] = encode(value[k]);
    }
    // A plain object that itself carries the reserved tag key must be escaped
    // so decode() does not mistake it for one of our wrappers.
    if (Object.prototype.hasOwnProperty.call(value, TAG)) {
      return { [TAG]: 'object', props: out };
    }
    return out;
  }

  // functions / symbols are not structured-cloneable.
  throw new TypeError(`Value of type ${t} could not be cloned.`);
}

function decodePlainObject(obj: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const k of Object.keys(obj)) {
    out[k] = decode(obj[k]);
  }
  return out;
}

/** Inverse of encode(). */
function decode(value: any): any {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(decode);

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
        return Uint8Array.from(value.bytes).buffer;
      case 'View': {
        const buf = Uint8Array.from(value.bytes).buffer;
        const Ctor = (globalThis as any)[value.ctor];
        if (!Ctor) return buf; // Unknown view type — surface the raw buffer.
        return value.ctor === 'DataView' ? new DataView(buf) : new Ctor(buf);
      }
      case 'Map':
        return new Map(value.entries.map(([k, v]: [any, any]) => [decode(k), decode(v)]));
      case 'Set':
        return new Set(value.values.map(decode));
      case 'object':
        // Escaped user object — decode its properties as a plain object.
        return decodePlainObject(value.props);
      default:
        // Unrecognized tag: treat as an ordinary object.
        return decodePlainObject(value);
    }
  }
  return decodePlainObject(value);
}

/**
 * Serialize an arbitrary structured-clone-compatible value to text for storage.
 */
export function serializeValue(value: any): string {
  return JSON.stringify(encode(value));
}

/**
 * Deserialize a value previously produced by serializeValue().
 */
export function deserializeValue(text: string): any {
  return decode(JSON.parse(text));
}

/**
 * Serialize an IndexedDB key to a canonical text form usable as a SQLite
 * primary-key column. Deterministic: equal keys always produce identical text
 * (so `WHERE key = ?` equality works), and deserializeKey() restores the key's
 * real type so compareKeys() can order it.
 */
export function serializeKey(key: any): string {
  return JSON.stringify(encode(key));
}

/**
 * Deserialize a key previously produced by serializeKey().
 */
export function deserializeKey(text: string): any {
  return decode(JSON.parse(text));
}
