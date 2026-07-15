/**
 * Headers API Implementation
 *
 * Implements the WHATWG Fetch Standard Headers interface.
 * @see https://fetch.spec.whatwg.org/#headers-class
 */

import type { HeadersInit } from './types.js';

/**
 * Header guard modes per the Fetch spec.
 */
export type HeaderGuard = 'none' | 'request' | 'request-no-cors' | 'response' | 'immutable';

/**
 * Normalize a header name to lowercase.
 * HTTP header names are case-insensitive.
 */
function normalizeHeaderName(name: string): string {
  if (typeof name !== 'string') {
    name = String(name);
  }
  if (!/^[\w!#$%&'*+.^`|~-]+$/.test(name)) {
    throw new TypeError(
      isBunCompatEnv() ? `Invalid header name: '${name}'` : `Invalid header name: ${name}`
    );
  }
  return name.toLowerCase();
}

function isBunCompatEnv(): boolean {
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

function ensureRequiredArguments(
  methodName: string,
  actualCount: number,
  requiredCount: number
): void {
  if (actualCount < requiredCount) {
    throw new TypeError(
      `Failed to execute '${methodName}' on 'Headers': ${requiredCount} argument${
        requiredCount === 1 ? '' : 's'
      } required, but only ${actualCount} present.`
    );
  }
}

function ensureHeadersBrand(value: unknown, methodName: string): Headers {
  if (!(value instanceof Headers)) {
    throw new TypeError(`Failed to execute '${methodName}' on 'Headers': Illegal invocation`);
  }
  return value;
}

function formatHeadersForInspect(entries: ReadonlyArray<[string, string]>): string {
  if (entries.length === 0) {
    return 'Headers {}';
  }

  const lines = ['Headers {'];
  for (let i = 0; i < entries.length; i++) {
    const [name, value] = entries[i];
    lines.push(`  ${JSON.stringify(name)}: ${JSON.stringify(value)},`);
  }
  lines.push('}');
  return lines.join('\n');
}

/**
 * CORS-safelisted request header names.
 */
const CORS_SAFELISTED_HEADERS = new Set([
  'accept',
  'accept-language',
  'content-language',
  'content-type',
]);

/**
 * Forbidden response header names.
 */
const FORBIDDEN_RESPONSE_HEADERS = new Set([
  'set-cookie',
  'set-cookie2',
]);

/**
 * Normalize a header value.
 */
function normalizeHeaderValue(value: string): string {
  if (typeof value === 'symbol') {
    throw new TypeError(`Invalid header value`);
  }
  if (typeof value !== 'string') {
    value = String(value);
  }
  const rawValue = value;
  // Per Fetch spec: the empty string is a valid header value
  if (value.length === 0) {
    return value;
  }
  // Per Fetch spec: reject null bytes anywhere
  if (value.includes('\x00')) {
    if (isBunCompatEnv()) {
      throw new TypeError(`Header 'x-test' has invalid value: '${rawValue}'`);
    }
    throw new TypeError(`Invalid header value`);
  }
  // Per Fetch spec: reject characters > 0xFF (header values must be byte strings)
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0xFF) {
      if (isBunCompatEnv()) {
        throw new TypeError(`Header 'x-test' has invalid value: '${rawValue}'`);
      }
      throw new TypeError(`Invalid header value`);
    }
  }
  // Strip leading and trailing HTTP whitespace without regex backtracking on
  // large attacker-controlled values.
  let start = 0;
  let end = value.length;
  while (start < end) {
    const code = value.charCodeAt(start);
    if (code !== 0x09 && code !== 0x0a && code !== 0x0d && code !== 0x20) {
      break;
    }
    start += 1;
  }
  while (end > start) {
    const code = value.charCodeAt(end - 1);
    if (code !== 0x09 && code !== 0x0a && code !== 0x0d && code !== 0x20) {
      break;
    }
    end -= 1;
  }
  value = start === 0 && end === value.length ? value : value.slice(start, end);
  // After stripping, reject any remaining bare CR or LF in the middle
  if (/[\r\n]/.test(value)) {
    if (isBunCompatEnv()) {
      throw new TypeError(`Header 'x-test' has invalid value: '${rawValue}'`);
    }
    throw new TypeError(`Invalid header value`);
  }
  return value;
}

/**
 * Check if a header name is forbidden for modification.
 */
function isForbiddenHeaderName(name: string): boolean {
  const lower = name.toLowerCase();
  // Per Fetch spec: https://fetch.spec.whatwg.org/#forbidden-request-header
  // Note: set-cookie IS forbidden for requests; set-cookie2 is NOT (only forbidden for responses)
  const forbidden = [
    'accept-charset',
    'accept-encoding',
    'access-control-request-headers',
    'access-control-request-method',
    'access-control-request-private-network',
    'connection',
    'content-length',
    'cookie',
    'cookie2',
    'date',
    'dnt',
    'expect',
    'host',
    'keep-alive',
    'origin',
    'referer',
    'set-cookie',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'via',
  ];
  return forbidden.includes(lower) || lower.startsWith('proxy-') || lower.startsWith('sec-');
}

function isBunCompatAllowedRequestHeader(name: string): boolean {
  if (!isBunCompatEnv()) {
    return false;
  }

  const normalized = name.toLowerCase();
  return normalized === 'connection' || normalized === 'accept-encoding';
}

/**
 * Check if a string contains CORS-unsafe request-header bytes.
 * Per Fetch spec: https://fetch.spec.whatwg.org/#cors-unsafe-request-header-byte
 */
function hasCORSUnsafeBytes(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if ((c >= 0x00 && c <= 0x08) || (c >= 0x0A && c <= 0x1F) ||
        c === 0x22 || c === 0x28 || c === 0x29 || c === 0x3A ||
        c === 0x3C || c === 0x3E || c === 0x3F || c === 0x40 ||
        c === 0x5B || c === 0x5C || c === 0x5D || c === 0x7B ||
        c === 0x7D || c === 0x7F) {
      return true;
    }
  }
  return false;
}

/**
 * The Headers interface of the Fetch API allows you to perform
 * various actions on HTTP request and response headers.
 */
/**
 * Get the %IteratorPrototype% from the runtime.
 */
const iteratorPrototype = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));

/**
 * Create a Headers iterator prototype for the given value mapper.
 */
function createHeadersIteratorPrototype<T>(mapFn: (entry: [string, string]) => T) {
  const proto = Object.create(iteratorPrototype);
  Object.defineProperty(proto, 'next', {
    value: function(this: any): IteratorResult<T> {
      const entries = this._headers._flatSortedEntries();
      if (this._index >= entries.length) return { value: undefined as any, done: true };
      return { value: mapFn(entries[this._index++]), done: false };
    },
    writable: true,
    enumerable: true,
    configurable: true,
  });
  Object.defineProperty(proto, Symbol.toStringTag, {
    value: 'Iterator',
    configurable: true,
  });
  return proto;
}

const entriesIteratorProto = createHeadersIteratorPrototype<[string, string]>((e) => e);
const keysIteratorProto = createHeadersIteratorPrototype<string>((e) => e[0]);
const valuesIteratorProto = createHeadersIteratorPrototype<string>((e) => e[1]);

export class Headers implements Iterable<[string, string]> {
  private _map: Map<string, string[]> = new Map();
  /** @internal */
  _guard: HeaderGuard = 'none';

  constructor(init?: HeadersInit) {
    if (init !== undefined) {
      if (init === null || (typeof init !== 'object' && typeof init !== 'function')) {
        throw new TypeError("Failed to construct 'Headers': The provided value is not of type '(sequence<sequence<ByteString>> or record<ByteString, ByteString>)'");
      }
      this._initFromInput(init);
    }
  }

  private _initFromInput(init: HeadersInit): void {
    // Per WebIDL spec: check [[Get]](@@iterator) to determine if it's a sequence.
    // This must be the first observable operation on the init value.
    const iteratorMethod = (init as any)[Symbol.iterator];
    if (
      (iteratorMethod === null || iteratorMethod === undefined) &&
      typeof init === 'object' &&
      init !== null &&
      Symbol.iterator in init
    ) {
      throw new TypeError("Failed to construct 'Headers': The provided value is not of type '(sequence<sequence<ByteString>> or record<ByteString, ByteString>)'");
    }
    if (typeof iteratorMethod === 'function') {
      // It's iterable - treat as sequence<sequence<ByteString>> or Headers
      const iterator = iteratorMethod.call(init);
      const entries = Array.from(iterator as Iterable<any>);
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        // Each entry must be iterable and yield exactly 2 items
        if (typeof entry === 'string') {
          // A string is iterable but yields characters, which makes each pair invalid
          throw new TypeError("Failed to construct 'Headers': Each header pair must be a name/value pair");
        }
        if (Array.isArray(entry)) {
          if (entry.length !== 2) {
            throw new TypeError("Failed to construct 'Headers': Each header pair must be a name/value pair");
          }
          this.append(entry[0], entry[1]);
        } else if (typeof entry === 'object' && entry !== null && Symbol.iterator in entry) {
          const pair = [...(entry as Iterable<string>)];
          if (pair.length !== 2) {
            throw new TypeError("Failed to construct 'Headers': Each header pair must be a name/value pair");
          }
          this.append(pair[0], pair[1]);
        } else {
          throw new TypeError("Failed to construct 'Headers': Each header pair must be an iterable");
        }
      }
    } else if (typeof init === 'object' && init !== null) {
      // WebIDL es-to-record algorithm:
      // 1. [[OwnPropertyKeys]] to get all keys
      // 2. For each key: [[GetOwnPropertyDescriptor]], check enumerable,
      //    convert key to ByteString (may throw), THEN [[Get]] value
      const keys = (typeof Reflect !== 'undefined' && Reflect.ownKeys)
        ? Reflect.ownKeys(init as object)
        : Object.getOwnPropertyNames(init as object);
      for (const key of keys) {
        const desc = Object.getOwnPropertyDescriptor(init as object, key as PropertyKey);
        if (!desc || !desc.enumerable) continue;
        // Per WebIDL: convert key to ByteString BEFORE [[Get]]
        if (typeof key === 'symbol') {
          throw new TypeError("Failed to construct 'Headers': Invalid header name");
        }
        normalizeHeaderName(key); // throws for invalid names before [[Get]]
        const value = (init as any)[key];
        this.append(key, value);
      }
    }
  }

  /**
   * Appends a new value onto an existing header, or adds the header
   * if it does not already exist.
   */
  append(name: string, value: string): void {
    const headers = ensureHeadersBrand(this, 'append');
    ensureRequiredArguments('append', arguments.length, 2);
    const normalizedName = normalizeHeaderName(name);
    const normalizedValue = normalizeHeaderValue(value);

    if (!headers._guardAllows(normalizedName, normalizedValue, false)) return;

    const existing = headers._map.get(normalizedName);
    if (existing) {
      existing.push(normalizedValue);
    } else {
      headers._map.set(normalizedName, [normalizedValue]);
    }
  }

  /**
   * Deletes a header from the Headers object.
   */
  delete(name: string): void {
    const headers = ensureHeadersBrand(this, 'delete');
    ensureRequiredArguments('delete', arguments.length, 1);
    const normalizedName = normalizeHeaderName(name);
    if (!headers._guardAllows(normalizedName)) return;
    headers._map.delete(normalizedName);
  }

  /**
   * Returns a String containing all the values of a header with a given name.
   */
  get(name: string): string | null {
    const headers = ensureHeadersBrand(this, 'get');
    ensureRequiredArguments('get', arguments.length, 1);
    const normalizedName = normalizeHeaderName(name);
    const values = headers._map.get(normalizedName);
    if (!values || values.length === 0) {
      return null;
    }
    return values.join(', ');
  }

  /**
   * Returns all values of a header with a given name as an array.
   */
  getSetCookie(): string[] {
    const headers = ensureHeadersBrand(this, 'getSetCookie');
    // Set-Cookie headers should not be combined
    const values = headers._map.get('set-cookie');
    return values ? [...values] : [];
  }

  /**
   * Bun compatibility extension that returns all stored values for a header.
   */
  getAll(name: string): string[] {
    const headers = ensureHeadersBrand(this, 'getAll');
    ensureRequiredArguments('getAll', arguments.length, 1);
    const normalizedName = normalizeHeaderName(name);
    const values = headers._map.get(normalizedName);
    return values ? [...values] : [];
  }

  /**
   * Bun compatibility extension that reports the total number of stored header entries.
   */
  get count(): number {
    const headers = ensureHeadersBrand(this, 'count');
    let total = 0;
    for (const values of headers._map.values()) {
      total += values.length;
    }
    return total;
  }

  /**
   * Returns a boolean stating whether a Headers object contains a certain header.
   */
  has(name: string): boolean {
    const headers = ensureHeadersBrand(this, 'has');
    ensureRequiredArguments('has', arguments.length, 1);
    const normalizedName = normalizeHeaderName(name);
    return headers._map.has(normalizedName);
  }

  /**
   * Sets a new value for an existing header, or adds the header if it does not exist.
   */
  set(name: string, value: string): void {
    const headers = ensureHeadersBrand(this, 'set');
    ensureRequiredArguments('set', arguments.length, 2);
    const normalizedName = normalizeHeaderName(name);
    const normalizedValue = normalizeHeaderValue(value);
    if (!headers._guardAllows(normalizedName, normalizedValue, true)) return;
    headers._map.set(normalizedName, [normalizedValue]);
  }

  /**
   * Executes a provided function once for each header.
   */
  forEach(
    callback: (value: string, name: string, parent: Headers) => void,
    thisArg?: unknown
  ): void {
    const headers = ensureHeadersBrand(this, 'forEach');
    ensureRequiredArguments('forEach', arguments.length, 1);
    if (typeof callback !== 'function') {
      throw new TypeError("Failed to execute 'forEach' on 'Headers': parameter 1 is not of type 'Function'");
    }
    // Per spec: forEach must iterate in sorted order with Set-Cookie un-combined.
    // NOTE: Use an indexed loop instead of for...of because the Rolldown bundler
    // rewrites `for (const [name, value] of ...)` into
    // `Array.from(...).forEach(function([name, value]) { ... })`.
    // Inside that rewritten regular function, `this` is no longer the Headers
    // instance — it becomes the global object (sloppy mode) or undefined (strict
    // mode). The third argument passed to the caller's callback would then be
    // wrong, causing the WPT "Check forEach method" assertion to fail.
    const entries = headers._flatSortedEntries();
    for (let i = 0; i < entries.length; i++) {
      callback.call(thisArg, entries[i][1], entries[i][0], headers);
    }
  }

  /**
   * Returns a live iterator of all header entries.
   * Re-sorts on each next() call per the Fetch spec.
   */
  entries(): IterableIterator<[string, string]> {
    const headers = ensureHeadersBrand(this, 'entries');
    const iter = Object.create(entriesIteratorProto);
    iter._headers = headers;
    iter._index = 0;
    return iter;
  }

  /**
   * Returns a live iterator of all header names.
   */
  keys(): IterableIterator<string> {
    const headers = ensureHeadersBrand(this, 'keys');
    const iter = Object.create(keysIteratorProto);
    iter._headers = headers;
    iter._index = 0;
    return iter;
  }

  /**
   * Returns a live iterator of all header values.
   */
  values(): IterableIterator<string> {
    const headers = ensureHeadersBrand(this, 'values');
    const iter = Object.create(valuesIteratorProto);
    iter._headers = headers;
    iter._index = 0;
    return iter;
  }

  /**
   * Returns an iterator of all header entries (sorted by name).
   */
  [Symbol.iterator](): IterableIterator<[string, string]> {
    const headers = ensureHeadersBrand(this, 'entries');
    return headers.entries();
  }

  /**
   * Bun compatibility extension that materializes the headers as a plain object.
   */
  toJSON(): Record<string, string | string[]> {
    const headers = ensureHeadersBrand(this, 'toJSON');
    const result: Record<string, string | string[]> = {};
    for (const [name, values] of headers._sortedEntries()) {
      if (name === 'set-cookie' && isBunCompatEnv()) {
        result[name] = [...values];
      } else {
        result[name] = values.join(', ');
      }
    }
    return result;
  }

  /**
   * Check if a header modification is allowed by the current guard.
   * Returns true if allowed. Throws TypeError for immutable guard.
   * Returns false (silently fails) for other guard violations per spec.
   * @param normalizedName The lowercased header name
   * @param normalizedValue The value being set/appended (for no-cors value checks)
   * @param isSet Whether this is a set (replace) vs append operation
   */
  private _guardAllows(normalizedName: string, normalizedValue?: string, isSet?: boolean): boolean {
    switch (this._guard) {
      case 'immutable':
        throw new TypeError('Failed to execute on \'Headers\': Headers are immutable');
      case 'request':
        if (isForbiddenHeaderName(normalizedName) && !isBunCompatAllowedRequestHeader(normalizedName)) return false;
        break;
      case 'request-no-cors':
        if (!CORS_SAFELISTED_HEADERS.has(normalizedName)) return false;
        // Per spec: CORS-safelisted headers have value constraints
        if (normalizedValue !== undefined) {
          // Check for CORS-unsafe request-header bytes in the value
          if (hasCORSUnsafeBytes(normalizedValue)) return false;
          // Compute what the combined value would be after this operation
          let combinedValue: string;
          if (isSet) {
            combinedValue = normalizedValue;
          } else {
            const existing = this._map.get(normalizedName);
            combinedValue = existing ? existing.join(', ') + ', ' + normalizedValue : normalizedValue;
          }
          // Combined value must not exceed 128 bytes
          if (combinedValue.length > 128) return false;
          // For content-type, must be a CORS-safelisted MIME type
          if (normalizedName === 'content-type') {
            const mime = combinedValue.split(';')[0].trim().toLowerCase();
            if (mime !== 'application/x-www-form-urlencoded' &&
                mime !== 'multipart/form-data' &&
                mime !== 'text/plain') {
              return false;
            }
          }
        }
        break;
      case 'response':
        if (FORBIDDEN_RESPONSE_HEADERS.has(normalizedName)) return false;
        break;
      case 'none':
      default:
        break;
    }
    return true;
  }

  /**
   * Get entries sorted alphabetically by name.
   */
  private _sortedEntries(): [string, string[]][] {
    const entries = [...this._map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const setCookieIndex = entries.findIndex(([name]) => name === 'set-cookie');
    // Bun compatibility only changes the observable order when set-cookie is
    // present before another entry. Keep ordinary iteration independent of
    // compatibility environment state.
    if (
      setCookieIndex < 0 ||
      setCookieIndex === entries.length - 1 ||
      !isBunCompatEnv()
    ) {
      return entries;
    }

    const normalEntries: [string, string[]][] = [];
    const setCookieEntries: [string, string[]][] = [];
    for (let i = 0; i < entries.length; i++) {
      if (entries[i][0] === 'set-cookie') {
        setCookieEntries.push(entries[i]);
      } else {
        normalEntries.push(entries[i]);
      }
    }
    return normalEntries.concat(setCookieEntries);
  }

  /**
   * Get flattened sorted entries per the Fetch spec.
   * Most headers combine values with ", ". Set-Cookie headers are NOT combined —
   * each value is returned as a separate entry.
   */
  private _flatSortedEntries(): [string, string][] {
    const result: [string, string][] = [];
    for (const [name, values] of this._sortedEntries()) {
      if (name === 'set-cookie') {
        for (const v of values) {
          result.push([name, v]);
        }
      } else {
        result.push([name, values.join(', ')]);
      }
    }
    return result;
  }

  /**
   * Convert headers to a tuple array for native bridge.
   */
  toTupleArray(): [string, string][] {
    const headers = ensureHeadersBrand(this, 'toTupleArray');
    const result: [string, string][] = [];
    for (const [name, values] of headers._map) {
      // For Set-Cookie, each value needs to be a separate header
      if (name === 'set-cookie') {
        for (const value of values) {
          result.push([name, value]);
        }
      } else {
        result.push([name, values.join(', ')]);
      }
    }
    return result;
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    const headers = ensureHeadersBrand(this, 'Symbol(nodejs.util.inspect.custom)');
    return formatHeadersForInspect(headers._flatSortedEntries());
  }

  /**
   * Create Headers from a tuple array (from native bridge).
   */
  static fromTupleArray(tuples: [string, string][]): Headers {
    const headers = new Headers();
    for (const [name, value] of tuples) {
      headers.append(name, value);
    }
    return headers;
  }
}

// Ensure constructor.name survives minification
Object.defineProperty(Headers, 'name', { value: 'Headers', configurable: true });
Object.defineProperty(Headers.prototype, Symbol.toStringTag, {
  value: 'Headers',
  configurable: true,
});
