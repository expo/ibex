/**
 * Object inspection utility (similar to Node's util.inspect, Bun.inspect, Deno.inspect)
 *
 * Pretty-prints objects with colors, depth limiting, and smart formatting.
 *
 * Because this backs `console.log`, three properties are load-bearing (ENG-22980):
 *   1. It must NEVER throw. Reading an object's members can trigger arbitrary
 *      user code (accessor getters, Proxy traps, module-namespace TDZ bindings).
 *      Such reads are either avoided (own accessors are described, not invoked)
 *      or wrapped so a throw is reported inline instead of escaping console.log.
 *   2. It must not silently invoke accessor getters as a logging side effect —
 *      own accessors render as `[Getter]`/`[Setter]`/`[Getter/Setter]` like Node.
 *   3. It must not be able to run unbounded: a cumulative output budget caps the
 *      total work so a huge/DAG-shaped value cannot hang the event loop or OOM.
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
  /**
   * Maximum cumulative output length (characters) across the whole tree before
   * truncation. Bounds total work so large/shared/cyclic structures cannot hang
   * the event loop or exhaust memory.
   */
  maxOutputLength?: number;
}

const DEFAULT_OPTIONS: Required<InspectOptions> = {
  colors: true,
  depth: 4,
  showHidden: false,
  maxArrayLength: 100,
  maxStringLength: 10000,
  compact: true,
  // ~1M chars is far above any legitimate console.log while still bounding the
  // pathological ~10^8-visit / multi-MB case that would otherwise stall or OOM.
  maxOutputLength: 1_000_000,
};

/**
 * Shared, mutable output budget threaded through a single inspect() call.
 * `remaining` counts down as output is produced; once it reaches zero, further
 * values render as an ellipsis and traversal stops.
 */
interface Budget {
  remaining: number;
  truncated: boolean;
}

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

/**
 * Read a property without letting a throwing accessor or Proxy trap escape.
 * Used only for structural duck-typing checks (Date/Map/Promise/... detection),
 * where we need the live value but must tolerate revoked Proxies and TDZ.
 */
function safeGet(obj: any, key: PropertyKey): any {
  try {
    return obj[key];
  } catch {
    return undefined;
  }
}

function errorMessage(err: unknown): string {
  try {
    if (err instanceof Error && typeof err.message === 'string') {
      return err.message;
    }
    return String(err);
  } catch {
    return 'error';
  }
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
    return colorize(`[Function: ${name}]`, colors.function, opts.colors);
  }

  return String(value);
}

function inspectArray(arr: any[], depth: number, opts: Required<InspectOptions>, seen: Set<any>, budget: Budget): string {
  if (depth >= opts.depth) {
    return colorize('[Array]', colors.special, opts.colors);
  }

  const items: string[] = [];
  const limit = Math.min(arr.length, opts.maxArrayLength);

  let i = 0;
  for (; i < limit; i++) {
    if (budget.remaining <= 0) {
      budget.truncated = true;
      break;
    }
    items.push(inspectValue(arr[i], depth + 1, opts, seen, budget));
  }

  const hidden = arr.length - i;
  if (hidden > 0) {
    items.push(colorize(`... ${hidden} more items`, colors.dim, opts.colors));
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
  try {
    return !!value &&
      typeof value === 'object' &&
      typeof value.append === 'function' &&
      typeof value.get === 'function' &&
      typeof value.getAll === 'function' &&
      typeof value.entries === 'function' &&
      typeof value.toString === 'function';
  } catch {
    return false;
  }
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
  try {
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
  } catch {
    return false;
  }
}

function inspectURLLike(obj: any, depth: number, opts: Required<InspectOptions>, seen: Set<any>, budget: Budget): string {
  const searchParams = indentMultiline(inspectValue(obj.searchParams, depth + 1, opts, seen, budget), '  ');

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

function inspectObject(obj: any, depth: number, opts: Required<InspectOptions>, seen: Set<any>, budget: Budget): string {
  if (depth >= opts.depth) {
    return colorize('[Object]', colors.special, opts.colors);
  }

  // Special cases - use duck typing instead of instanceof for cross-realm
  // compatibility. Every probe below goes through safeGet so a revoked Proxy or
  // TDZ binding can't throw out of console.log (ENG-22980).
  if (isURLSearchParamsLike(obj)) {
    const inspected = inspectURLSearchParamsLike(obj);
    if (inspected !== null) {
      return inspected;
    }
  }

  if (isURLLike(obj)) {
    return inspectURLLike(obj, depth, opts, seen, budget);
  }

  if (typeof safeGet(obj, 'toISOString') === 'function' && typeof safeGet(obj, 'getMonth') === 'function') {
    // Date object
    try {
      return colorize(obj.toISOString(), colors.special, opts.colors);
    } catch {
      return colorize(String(obj), colors.special, opts.colors);
    }
  }

  if (typeof safeGet(obj, 'test') === 'function' && typeof safeGet(obj, 'exec') === 'function' && safeGet(obj, 'source') !== undefined) {
    // RegExp object
    return colorize(String(obj), colors.special, opts.colors);
  }

  const errName = safeGet(obj, 'name');
  const errMsg = safeGet(obj, 'message');
  if (errName && errMsg && safeGet(obj, 'stack')) {
    // Error object
    return colorize(`${errName}: ${errMsg}`, colors.special, opts.colors);
  }

  if (typeof safeGet(obj, 'get') === 'function' && typeof safeGet(obj, 'set') === 'function' && typeof safeGet(obj, 'has') === 'function' && typeof safeGet(obj, 'entries') === 'function' && safeGet(obj, 'size') !== undefined) {
    // Map object
    try {
      const entries: string[] = [];
      let count = 0;
      for (const [key, value] of obj.entries()) {
        if (count++ >= opts.maxArrayLength || budget.remaining <= 0) break;
        entries.push(
          inspectValue(key, depth + 1, opts, seen, budget) + ' => ' +
          inspectValue(value, depth + 1, opts, seen, budget)
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

  if (typeof safeGet(obj, 'has') === 'function' && typeof safeGet(obj, 'add') === 'function' && typeof safeGet(obj, 'values') === 'function' && safeGet(obj, 'size') !== undefined) {
    // Set object
    try {
      const values: string[] = [];
      let count = 0;
      for (const value of obj.values()) {
        if (count++ >= opts.maxArrayLength || budget.remaining <= 0) break;
        values.push(inspectValue(value, depth + 1, opts, seen, budget));
      }
      if (obj.size > opts.maxArrayLength) {
        values.push(colorize(`... ${obj.size - opts.maxArrayLength} more items`, colors.dim, opts.colors));
      }
      return colorize('Set(', colors.special, opts.colors) + obj.size + ') { ' + values.join(', ') + ' }';
    } catch {
      // Fall through to regular object handling
    }
  }

  // Promise object (check for .then method)
  if (typeof safeGet(obj, 'then') === 'function' && typeof safeGet(obj, 'catch') === 'function') {
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
               inspectValue(value, depth + 1, opts, seen, budget) +
               colorize(' }', colors.special, opts.colors);
      } else if (state === 2) {
        return colorize('Promise { ', colors.special, opts.colors) +
               colorize('<rejected>', colors.dim, opts.colors) + ': ' +
               inspectValue(value, depth + 1, opts, seen, budget) +
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

  // Genuine ES module namespace objects carry Symbol.toStringTag === 'Module'.
  // We deliberately do NOT infer "module" from plain `default`/`exports`/
  // `__esModule` keys: an ordinary object like `{ default: 'dark', options: [...] }`
  // must render with its values, not as a value-less `Module { ... }` (ENG-22980).
  const isModule = safeGet(obj, Symbol.toStringTag) === 'Module';
  const label = isModule ? colorize('Module ', colors.special, opts.colors) : '';

  // Regular object (module namespaces fall through here so their values show).
  let keys: string[];
  try {
    keys = opts.showHidden
      ? Object.getOwnPropertyNames(obj)
      : Object.keys(obj);
  } catch (err) {
    // Enumerating own keys ran a Proxy ownKeys/getOwnPropertyDescriptor trap
    // that threw (e.g. a revoked Proxy). Report it safely instead of throwing
    // or pretending the object was empty (ENG-22980).
    return label + colorize(`[unlistable: ${errorMessage(err)}]`, colors.special, opts.colors);
  }

  if (keys.length === 0) {
    return label + '{}';
  }

  const pairs: string[] = [];
  const limit = Math.min(keys.length, opts.maxArrayLength);

  let i = 0;
  for (; i < limit; i++) {
    if (budget.remaining <= 0) {
      budget.truncated = true;
      break;
    }
    const key = keys[i];
    const needsQuotes = !/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key);
    const keyStr = needsQuotes ? JSON.stringify(key) : key;
    const coloredKey = colorize(keyStr, colors.key, opts.colors);

    // Describe accessors instead of invoking them: matches Node, avoids running
    // arbitrary getters as a logging side effect, and can't throw (ENG-22980).
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(obj, key);
    } catch {
      descriptor = undefined;
    }

    let valueStr: string;
    if (descriptor && (descriptor.get || descriptor.set)) {
      const accessor = descriptor.get && descriptor.set
        ? '[Getter/Setter]'
        : descriptor.get ? '[Getter]' : '[Setter]';
      valueStr = colorize(accessor, colors.special, opts.colors);
    } else if (descriptor) {
      valueStr = inspectValue(descriptor.value, depth + 1, opts, seen, budget);
    } else {
      // No descriptor (property vanished, or a Proxy trap hid it) — read
      // defensively so a throwing trap is reported inline, not propagated.
      try {
        valueStr = inspectValue((obj as any)[key], depth + 1, opts, seen, budget);
      } catch (err) {
        valueStr = colorize(`[Thrown: ${errorMessage(err)}]`, colors.special, opts.colors);
      }
    }

    pairs.push(coloredKey + ': ' + valueStr);
  }

  const hidden = keys.length - i;
  if (hidden > 0) {
    pairs.push(colorize(`... ${hidden} more keys`, colors.dim, opts.colors));
  }

  const open = colorize('{', colors.bracket, opts.colors);
  const close = colorize('}', colors.bracket, opts.colors);

  if (opts.compact) {
    return label + open + ' ' + pairs.join(', ') + ' ' + close;
  } else {
    return label + open + '\n  ' + pairs.join(',\n  ') + '\n' + close;
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

function inspectValue(value: any, depth: number, opts: Required<InspectOptions>, seen: Set<any>, budget: Budget): string {
  // Cumulative output budget: stop producing output once exhausted so a huge or
  // heavily-shared (DAG) structure can't stall the event loop or OOM.
  if (budget.remaining <= 0) {
    budget.truncated = true;
    return colorize('...', colors.dim, opts.colors);
  }

  const type = typeof value;

  // Primitives and functions
  if (type !== 'object' || value === null) {
    const primitive = inspectPrimitive(value, opts);
    budget.remaining -= primitive.length;
    return primitive;
  }

  // Circular reference detection
  if (seen.has(value)) {
    const circular = colorize('[Circular]', colors.special, opts.colors);
    budget.remaining -= circular.length;
    return circular;
  }
  seen.add(value);

  let result: string;
  try {
    // Buffer / TypedArray - show hex bytes like Node.js
    if (ArrayBuffer.isView(value) && !(value instanceof DataView)) {
      result = inspectTypedArray(value as any, depth, opts);
    } else if (Array.isArray(value)) {
      // Arrays
      result = inspectArray(value, depth, opts, seen, budget);
    } else {
      // Objects (including special types)
      result = inspectObject(value, depth, opts, seen, budget);
    }
  } catch (err) {
    // Last-resort guard: inspection must never throw out of console.log.
    result = colorize(`[uninspectable: ${errorMessage(err)}]`, colors.special, opts.colors);
  } finally {
    seen.delete(value);
  }

  // Charge the produced output against the budget. Container output includes
  // its children (already charged), so this over-counts by roughly the depth
  // factor — intentionally conservative: pathological trees truncate sooner.
  budget.remaining -= result.length;
  return result;
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

  const budget: Budget = { remaining: opts.maxOutputLength, truncated: false };
  return inspectValue(value, 0, opts, new Set(), budget);
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
