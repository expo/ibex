/**
 * Object inspection utility (similar to Node's util.inspect, Bun.inspect, Deno.inspect)
 *
 * Pretty-prints objects with colors, depth limiting, and smart formatting.
 */

export interface InspectOptions {
  /** Show colors (ANSI escape codes) */
  colors?: boolean;
  /** Maximum depth to traverse */
  depth?: number;
  /** Show hidden (non-enumerable) properties */
  showHidden?: boolean;
  /** Maximum array/object elements to show */
  maxArrayLength?: number;
  /** Maximum string length */
  maxStringLength?: number;
  /** Compact mode (less whitespace) */
  compact?: boolean;
}

const DEFAULT_OPTIONS: Required<InspectOptions> = {
  colors: true,
  depth: 4,
  showHidden: false,
  maxArrayLength: 100,
  maxStringLength: 10000,
  compact: true,
};

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',

  // Types
  number: '\x1b[33m',      // yellow
  string: '\x1b[32m',      // green
  boolean: '\x1b[33m',     // yellow
  null: '\x1b[1m',         // bold
  undefined: '\x1b[2m',    // dim
  symbol: '\x1b[32m',      // green
  function: '\x1b[36m',    // cyan

  // Structures
  key: '\x1b[0m',          // reset
  special: '\x1b[36m',     // cyan (Date, RegExp, etc.)
  bracket: '\x1b[2m',      // dim
};

function colorize(text: string, color: string, useColors: boolean): string {
  return useColors ? color + text + colors.reset : text;
}

function inspectPrimitive(value: any, opts: Required<InspectOptions>): string {
  if (value === null) {
    return colorize('null', colors.null, opts.colors);
  }

  if (value === undefined) {
    return colorize('undefined', colors.undefined, opts.colors);
  }

  if (typeof value === 'number') {
    return colorize(String(value), colors.number, opts.colors);
  }

  if (typeof value === 'boolean') {
    return colorize(String(value), colors.boolean, opts.colors);
  }

  if (typeof value === 'string') {
    const truncated = value.length > opts.maxStringLength
      ? value.slice(0, opts.maxStringLength) + '...'
      : value;
    const escaped = JSON.stringify(truncated);
    return colorize(escaped, colors.string, opts.colors);
  }

  if (typeof value === 'symbol') {
    return colorize(String(value), colors.symbol, opts.colors);
  }

  if (typeof value === 'function') {
    const name = value.name || 'anonymous';
    const params = 'a0, a1, a2'; // Simplified - we don't have access to Function.length easily
    return colorize(`[Function: ${name}]`, colors.function, opts.colors);
  }

  return String(value);
}

function inspectArray(arr: any[], depth: number, opts: Required<InspectOptions>, seen: Set<any>): string {
  if (depth >= opts.depth) {
    return colorize('[Array]', colors.special, opts.colors);
  }

  const items: string[] = [];
  const limit = Math.min(arr.length, opts.maxArrayLength);

  for (let i = 0; i < limit; i++) {
    items.push(inspectValue(arr[i], depth + 1, opts, seen));
  }

  if (arr.length > opts.maxArrayLength) {
    items.push(colorize(`... ${arr.length - opts.maxArrayLength} more items`, colors.dim, opts.colors));
  }

  const open = colorize('[', colors.bracket, opts.colors);
  const close = colorize(']', colors.bracket, opts.colors);

  if (opts.compact) {
    return open + ' ' + items.join(', ') + ' ' + close;
  } else {
    return open + '\n  ' + items.join(',\n  ') + '\n' + close;
  }
}

function indentMultiline(text: string, prefix: string): string {
  return text.replace(/\n/g, `\n${prefix}`);
}

function isURLSearchParamsLike(value: any): boolean {
  return !!value &&
    typeof value === 'object' &&
    typeof value.append === 'function' &&
    typeof value.get === 'function' &&
    typeof value.getAll === 'function' &&
    typeof value.entries === 'function' &&
    typeof value.toString === 'function';
}

function inspectURLSearchParamsLike(value: any): string | null {
  try {
    const groups: Array<{ key: string; values: string[] }> = [];

    for (const entry of value.entries()) {
      const key = String(entry[0]);
      const entryValue = String(entry[1]);
      const group = groups.find(item => item.key === key);

      if (group) {
        group.values.push(entryValue);
      } else {
        groups.push({ key, values: [entryValue] });
      }
    }

    if (groups.length === 0) {
      return 'URLSearchParams {}';
    }

    const lines = groups.map(group => {
      const renderedValue = group.values.length === 1
        ? JSON.stringify(group.values[0])
        : `[ ${group.values.map(item => JSON.stringify(item)).join(', ')} ]`;
      return `  ${JSON.stringify(group.key)}: ${renderedValue},`;
    });

    return `URLSearchParams {\n${lines.join('\n')}\n}`;
  } catch {
    return null;
  }
}

function isURLLike(value: any): boolean {
  return !!value &&
    typeof value === 'object' &&
    typeof value.href === 'string' &&
    typeof value.origin === 'string' &&
    typeof value.protocol === 'string' &&
    typeof value.username === 'string' &&
    typeof value.password === 'string' &&
    typeof value.host === 'string' &&
    typeof value.hostname === 'string' &&
    typeof value.port === 'string' &&
    typeof value.pathname === 'string' &&
    typeof value.hash === 'string' &&
    typeof value.search === 'string' &&
    value.searchParams &&
    typeof value.searchParams === 'object' &&
    typeof value.toJSON === 'function' &&
    typeof value.toString === 'function';
}

function inspectURLLike(obj: any, depth: number, opts: Required<InspectOptions>, seen: Set<any>): string {
  const searchParams = indentMultiline(inspectValue(obj.searchParams, depth + 1, opts, seen), '  ');

  return `URL {
  href: ${JSON.stringify(obj.href)},
  origin: ${JSON.stringify(obj.origin)},
  protocol: ${JSON.stringify(obj.protocol)},
  username: ${JSON.stringify(obj.username)},
  password: ${JSON.stringify(obj.password)},
  host: ${JSON.stringify(obj.host)},
  hostname: ${JSON.stringify(obj.hostname)},
  port: ${JSON.stringify(obj.port)},
  pathname: ${JSON.stringify(obj.pathname)},
  hash: ${JSON.stringify(obj.hash)},
  search: ${JSON.stringify(obj.search)},
  searchParams: ${searchParams},
  toJSON: [Function: toJSON],
  toString: [Function: toString],
}`;
}

function inspectObject(obj: any, depth: number, opts: Required<InspectOptions>, seen: Set<any>): string {
  if (depth >= opts.depth) {
    return colorize('[Object]', colors.special, opts.colors);
  }

  // Special cases - use duck typing instead of instanceof for cross-realm compatibility
  if (isURLSearchParamsLike(obj)) {
    const inspected = inspectURLSearchParamsLike(obj);
    if (inspected !== null) {
      return inspected;
    }
  }

  if (isURLLike(obj)) {
    return inspectURLLike(obj, depth, opts, seen);
  }

  if (typeof obj.toISOString === 'function' && typeof obj.getMonth === 'function') {
    // Date object
    try {
      return colorize(obj.toISOString(), colors.special, opts.colors);
    } catch {
      return colorize(String(obj), colors.special, opts.colors);
    }
  }

  if (typeof obj.test === 'function' && typeof obj.exec === 'function' && obj.source !== undefined) {
    // RegExp object
    return colorize(String(obj), colors.special, opts.colors);
  }

  if (obj.name && obj.message && obj.stack) {
    // Error object
    return colorize(`${obj.name}: ${obj.message}`, colors.special, opts.colors);
  }

  if (typeof obj.get === 'function' && typeof obj.set === 'function' && typeof obj.has === 'function' && typeof obj.entries === 'function' && obj.size !== undefined) {
    // Map object
    try {
      const entries: string[] = [];
      let count = 0;
      for (const [key, value] of obj.entries()) {
        if (count++ >= opts.maxArrayLength) break;
        entries.push(
          inspectValue(key, depth + 1, opts, seen) + ' => ' +
          inspectValue(value, depth + 1, opts, seen)
        );
      }
      if (obj.size > opts.maxArrayLength) {
        entries.push(colorize(`... ${obj.size - opts.maxArrayLength} more entries`, colors.dim, opts.colors));
      }
      return colorize('Map(', colors.special, opts.colors) + obj.size + ') { ' + entries.join(', ') + ' }';
    } catch {
      // Fall through to regular object handling
    }
  }

  if (typeof obj.has === 'function' && typeof obj.add === 'function' && typeof obj.values === 'function' && obj.size !== undefined) {
    // Set object
    try {
      const values: string[] = [];
      let count = 0;
      for (const value of obj.values()) {
        if (count++ >= opts.maxArrayLength) break;
        values.push(inspectValue(value, depth + 1, opts, seen));
      }
      if (obj.size > opts.maxArrayLength) {
        values.push(colorize(`... ${obj.size - opts.maxArrayLength} more items`, colors.dim, opts.colors));
      }
      return colorize('Set(', colors.special, opts.colors) + obj.size + ') { ' + values.join(', ') + ' }';
    } catch {
      // Fall through to regular object handling
    }
  }

  // Module object (check for CommonJS/ES module markers)
  // CommonJS modules often have __esModule or are returned from require()
  if (obj.__esModule || obj.default !== undefined || obj.exports !== undefined) {
    // Show as Module with exported names
    const keys = Object.keys(obj).filter(k => k !== '__esModule');
    if (keys.length === 0) {
      return colorize('Module { }', colors.special, opts.colors);
    } else if (keys.length <= 5) {
      const exports = keys.map(k => colorize(k, colors.key, opts.colors)).join(', ');
      return colorize('Module { ', colors.special, opts.colors) + exports + colorize(' }', colors.special, opts.colors);
    } else {
      const firstFive = keys.slice(0, 5).map(k => colorize(k, colors.key, opts.colors)).join(', ');
      const remaining = keys.length - 5;
      return colorize('Module { ', colors.special, opts.colors) +
             firstFive +
             colorize(`, ...${remaining} more`, colors.dim, opts.colors) +
             colorize(' }', colors.special, opts.colors);
    }
  }

  // Promise object (check for .then method)
  if (typeof obj.then === 'function' && typeof obj.catch === 'function') {
    try {
      // Try to inspect Hermes promise internals for state
      // _x: 0 = pending, 1 = fulfilled, 2 = rejected
      // _z: resolved/rejected value
      const state = (obj as any)._x;
      const value = (obj as any)._z;

      // If there's a value (even if state is still technically pending due to microtask queue)
      // show it as fulfilled. This matches Chrome DevTools behavior.
      if (value !== undefined && value !== null && state !== 2) {
        return colorize('Promise { ', colors.special, opts.colors) +
               colorize('<fulfilled>', colors.dim, opts.colors) + ': ' +
               inspectValue(value, depth + 1, opts, seen) +
               colorize(' }', colors.special, opts.colors);
      } else if (state === 2) {
        return colorize('Promise { ', colors.special, opts.colors) +
               colorize('<rejected>', colors.dim, opts.colors) + ': ' +
               inspectValue(value, depth + 1, opts, seen) +
               colorize(' }', colors.special, opts.colors);
      } else {
        // Truly pending (no value yet)
        return colorize('Promise { ', colors.special, opts.colors) +
               colorize('<pending>', colors.dim, opts.colors) +
               colorize(' }', colors.special, opts.colors);
      }
    } catch {
      // Fall back to generic Promise label
      return colorize('Promise { ... }', colors.special, opts.colors);
    }
  }

  // Regular object
  const keys = opts.showHidden
    ? Object.getOwnPropertyNames(obj)
    : Object.keys(obj);

  if (keys.length === 0) {
    return '{}';
  }

  const pairs: string[] = [];
  const limit = Math.min(keys.length, opts.maxArrayLength);

  for (let i = 0; i < limit; i++) {
    const key = keys[i];
    const needsQuotes = !/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key);
    const keyStr = needsQuotes ? JSON.stringify(key) : key;
    const coloredKey = colorize(keyStr, colors.key, opts.colors);
    const value = inspectValue(obj[key], depth + 1, opts, seen);
    pairs.push(coloredKey + ': ' + value);
  }

  if (keys.length > opts.maxArrayLength) {
    pairs.push(colorize(`... ${keys.length - opts.maxArrayLength} more keys`, colors.dim, opts.colors));
  }

  const open = colorize('{', colors.bracket, opts.colors);
  const close = colorize('}', colors.bracket, opts.colors);

  if (opts.compact) {
    return open + ' ' + pairs.join(', ') + ' ' + close;
  } else {
    return open + '\n  ' + pairs.join(',\n  ') + '\n' + close;
  }
}

function inspectTypedArray(value: { length: number; [index: number]: number; constructor?: { name?: string }; [Symbol.toStringTag]?: string }, depth: number, opts: Required<InspectOptions>): string {
  const isBuffer = value[Symbol.toStringTag] === 'Buffer' || (value.constructor && value.constructor.name === 'Buffer');
  const typeName = isBuffer ? 'Buffer' : (value.constructor?.name || 'TypedArray');

  if (isBuffer) {
    // Node.js style: <Buffer 23 20 45 78 61 63 74 0a ...>
    const maxBytes = 50;
    const hexParts: string[] = [];
    const limit = Math.min(value.length, maxBytes);
    for (let i = 0; i < limit; i++) {
      hexParts.push(value[i].toString(16).padStart(2, '0'));
    }
    const truncated = value.length > maxBytes
      ? ` ... ${value.length - maxBytes} more bytes`
      : '';
    return colorize(`<Buffer ${hexParts.join(' ')}${truncated}>`, colors.special, opts.colors);
  }

  // Other TypedArrays: Uint8Array(5) [ 1, 2, 3, 4, 5 ]
  const maxItems = Math.min(value.length, opts.maxArrayLength);
  const items: string[] = [];
  for (let i = 0; i < maxItems; i++) {
    items.push(colorize(String(value[i]), colors.number, opts.colors));
  }
  const truncated = value.length > opts.maxArrayLength
    ? colorize(` ... ${value.length - opts.maxArrayLength} more items`, colors.dim, opts.colors)
    : '';
  return `${typeName}(${value.length}) [ ${items.join(', ')}${truncated} ]`;
}

function inspectValue(value: any, depth: number, opts: Required<InspectOptions>, seen: Set<any>): string {
  const type = typeof value;

  // Primitives and functions
  if (type !== 'object' || value === null) {
    return inspectPrimitive(value, opts);
  }

  // Circular reference detection
  if (seen.has(value)) {
    return colorize('[Circular]', colors.special, opts.colors);
  }
  seen.add(value);

  try {
    // Buffer / TypedArray - show hex bytes like Node.js
    if (ArrayBuffer.isView(value) && !(value instanceof DataView)) {
      return inspectTypedArray(value as any, depth, opts);
    }

    // Arrays
    if (Array.isArray(value)) {
      return inspectArray(value, depth, opts, seen);
    }

    // Objects (including special types)
    return inspectObject(value, depth, opts, seen);
  } finally {
    seen.delete(value);
  }
}

/**
 * Inspect a value and return a formatted string representation
 * Similar to Node's util.inspect, Bun.inspect, and Deno.inspect
 */
export function inspect(value: any, options?: InspectOptions): string {
  const opts: Required<InspectOptions> = {
    ...DEFAULT_OPTIONS,
    ...options,
  };

  return inspectValue(value, 0, opts, new Set());
}

// Install on the Exact global — defensively: hosts may already provide an
// `inspect` (possibly as a getter-only accessor), and a convenience install
// must never hard-fail module evaluation (it broke native agent boot as the
// follow-on failure behind LLP 0176).
if (typeof globalThis.Exact !== 'undefined') {
  const exactGlobal = (globalThis as { Exact?: Record<string, unknown> }).Exact!;
  const descriptor = Object.getOwnPropertyDescriptor(exactGlobal, 'inspect');
  if (!descriptor || descriptor.configurable || descriptor.writable) {
    try {
      Object.defineProperty(exactGlobal, 'inspect', {
        value: inspect,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } catch {
      // The host owns Exact.inspect; keep its implementation.
    }
  }
}
