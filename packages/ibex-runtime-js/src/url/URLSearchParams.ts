/**
 * URLSearchParams - WHATWG URL Standard Implementation
 *
 * @see https://url.spec.whatwg.org/#urlsearchparams
 */

import type { URL } from "./URL";

/**
 * WebIDL USVString conversion: replace lone surrogates with U+FFFD. All
 * name/value arguments pass through this, so a lone surrogate (a routine
 * result of slicing through an emoji) can never reach the percent-encoder
 * and throw URIError.
 */
function toUSVString(value: unknown): string {
  const str = String(value);
  let out = "";
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += str[i] + str[i + 1];
        i++;
      } else {
        out += "�";
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      out += "�";
    } else {
      out += str[i];
    }
  }
  return out;
}

function toHex(code: number): string {
  const hex = code.toString(16).toUpperCase();
  return hex.length === 1 ? `0${hex}` : hex;
}

/**
 * WHATWG "UTF-8 decode without BOM" with U+FFFD replacement (maximal-subpart
 * semantics: each invalid byte run yields replacement characters instead of
 * throwing like decodeURIComponent does).
 */
function utf8DecodeWithReplacement(bytes: number[]): string {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    if (b <= 0x7f) {
      out += String.fromCharCode(b);
      i++;
      continue;
    }
    let needed: number;
    let codePoint: number;
    let lower = 0x80;
    let upper = 0xbf;
    if (b >= 0xc2 && b <= 0xdf) {
      needed = 1;
      codePoint = b & 0x1f;
    } else if (b >= 0xe0 && b <= 0xef) {
      needed = 2;
      codePoint = b & 0x0f;
      if (b === 0xe0) lower = 0xa0;
      if (b === 0xed) upper = 0x9f;
    } else if (b >= 0xf0 && b <= 0xf4) {
      needed = 3;
      codePoint = b & 0x07;
      if (b === 0xf0) lower = 0x90;
      if (b === 0xf4) upper = 0x8f;
    } else {
      out += "�";
      i++;
      continue;
    }
    let j = i + 1;
    let ok = true;
    for (let k = 0; k < needed; k++) {
      const nb = bytes[j];
      const lo = k === 0 ? lower : 0x80;
      const hi = k === 0 ? upper : 0xbf;
      if (nb === undefined || nb < lo || nb > hi) {
        ok = false;
        break;
      }
      codePoint = (codePoint << 6) | (nb & 0x3f);
      j++;
    }
    if (!ok) {
      // Resume at the offending byte so it can start a new sequence.
      out += "�";
      i = j;
      continue;
    }
    out += String.fromCodePoint(codePoint);
    i = j;
  }
  return out;
}

export class URLSearchParams {
  private _params: Array<[string, string]> = [];
  private _url: URL | null = null;

  constructor(
    init?:
      | string
      | URLSearchParams
      | Record<string, string>
      | Iterable<[string, string]>
  ) {
    if (init === undefined || init === null) {
      return;
    }

    if (typeof init === "string") {
      this._parseString(init);
    } else if (init instanceof URLSearchParams) {
      this._params = [...init._params];
    } else if (typeof init === "object") {
      if (Symbol.iterator in init) {
        // Iterable of [key, value] pairs
        const entries = Array.from(init as Iterable<[string, string]>);
        for (let i = 0; i < entries.length; i++) {
          const [key, value] = entries[i];
          this._params.push([toUSVString(key), toUSVString(value)]);
        }
      } else {
        // Plain object
        const keys = Object.keys(init as Record<string, string>);
        for (let i = 0; i < keys.length; i++) {
          const key = keys[i];
          this._params.push([
            toUSVString(key),
            toUSVString((init as Record<string, string>)[key]),
          ]);
        }
      }
    }
  }

  private _parseString(input: string): void {
    // Remove leading ?
    let str = input;
    if (str.startsWith("?")) {
      str = str.slice(1);
    }

    if (!str) return;

    // Split by &
    const pairs = str.split("&");
    for (const pair of pairs) {
      if (!pair) continue;

      const eqIndex = pair.indexOf("=");
      if (eqIndex === -1) {
        this._params.push([this._decode(pair), ""]);
      } else {
        const key = this._decode(pair.slice(0, eqIndex));
        const value = this._decode(pair.slice(eqIndex + 1));
        this._params.push([key, value]);
      }
    }
  }

  private _decode(str: string): string {
    // Plus-to-space conversion happens BEFORE percent-decoding and must
    // happen even when a malformed escape ("%zz") makes decoding partial.
    const input = str.replace(/\+/g, " ");
    try {
      return toUSVString(decodeURIComponent(input));
    } catch {
      // Malformed escapes: decode each maximal %XX run individually with
      // U+FFFD replacement instead of returning the input untouched
      // ("q=a+b%zz" must still yield "a b%zz", "%E4" yields U+FFFD).
      return toUSVString(
        input.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
          const bytes: number[] = [];
          for (let i = 0; i < run.length; i += 3) {
            bytes.push(parseInt(run.slice(i + 1, i + 3), 16));
          }
          return utf8DecodeWithReplacement(bytes);
        }),
      );
    }
  }

  private _encode(str: string): string {
    // WHATWG application/x-www-form-urlencoded serializer: only ASCII
    // alphanumerics and * - . _ pass through, space becomes "+", everything
    // else is percent-encoded. encodeURIComponent alone under-encodes
    // ! ' ( ) ~ (breaking byte-exact query signing) and throws URIError on
    // lone surrogates instead of USVString-replacing them. (ENG-23038 port)
    const value = toUSVString(str);
    let out = "";
    for (const ch of value) {
      const code = ch.codePointAt(0)!;
      if (code === 0x20) {
        out += "+";
        continue;
      }
      if (
        (code >= 0x30 && code <= 0x39) || // 0-9
        (code >= 0x41 && code <= 0x5a) || // A-Z
        (code >= 0x61 && code <= 0x7a) || // a-z
        code === 0x2a || // *
        code === 0x2d || // -
        code === 0x2e || // .
        code === 0x5f //    _
      ) {
        out += ch;
        continue;
      }
      if (code <= 0x7f) {
        out += `%${toHex(code)}`;
        continue;
      }
      // Non-ASCII: UTF-8 percent-encode. `value` is a USVString, so this
      // cannot throw.
      out += encodeURIComponent(ch);
    }
    return out;
  }

  private _update(): void {
    if (this._url) {
      this._url._updateSearch(this.toString());
    }
  }

  /** @internal */
  _setURL(url: URL): void {
    this._url = url;
  }

  /**
   * Replace this instance's list in place from a URL query string. Used by the
   * URL search/href setters so the single per-URL URLSearchParams object is
   * re-filled rather than replaced. Does not call `_update()` — the owning URL
   * has already set its serialized `search`, which stays authoritative.
   * @internal
   */
  _resetFromSearch(search: string): void {
    this._params = [];
    this._parseString(search);
  }

  append(name: string, value: string): void {
    this._params.push([toUSVString(name), toUSVString(value)]);
    this._update();
  }

  delete(name: string, value?: string): void {
    const key = toUSVString(name);
    if (value === undefined) {
      this._params = this._params.filter(([k]) => k !== key);
    } else {
      const val = toUSVString(value);
      this._params = this._params.filter(([k, v]) => !(k === key && v === val));
    }
    this._update();
  }

  get(name: string): string | null {
    const key = toUSVString(name);
    const entry = this._params.find(([k]) => k === key);
    return entry ? entry[1] : null;
  }

  getAll(name: string): string[] {
    const key = toUSVString(name);
    return this._params.filter(([k]) => k === key).map(([, v]) => v);
  }

  has(name: string, value?: string): boolean {
    const key = toUSVString(name);
    if (value === undefined) {
      return this._params.some(([k]) => k === key);
    }
    const val = toUSVString(value);
    return this._params.some(([k, v]) => k === key && v === val);
  }

  set(name: string, value: string): void {
    const key = toUSVString(name);
    const val = toUSVString(value);

    // Remove all existing entries with this name except the first
    let found = false;
    this._params = this._params.filter(([k]) => {
      if (k === key) {
        if (!found) {
          found = true;
          return true;
        }
        return false;
      }
      return true;
    });

    // Set or append
    if (found) {
      const index = this._params.findIndex(([k]) => k === key);
      this._params[index] = [key, val];
    } else {
      this._params.push([key, val]);
    }

    this._update();
  }

  sort(): void {
    this._params.sort((a, b) => {
      if (a[0] < b[0]) return -1;
      if (a[0] > b[0]) return 1;
      return 0;
    });
    this._update();
  }

  get size(): number {
    return this._params.length;
  }

  get length(): number {
    return this._params.length;
  }

  toString(): string {
    return this._params
      .map(([k, v]) => `${this._encode(k)}=${this._encode(v)}`)
      .join("&");
  }

  toJSON(): Record<string, string | string[]> {
    const result: Record<string, string | string[]> = {};

    for (let i = 0; i < this._params.length; i++) {
      const [key, value] = this._params[i];
      const existing = result[key];

      if (existing === undefined) {
        result[key] = value;
      } else if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        result[key] = [existing, value];
      }
    }

    return result;
  }

  forEach(
    callback: (value: string, name: string, parent: URLSearchParams) => void,
    thisArg?: any
  ): void {
    // Use indexed loop to avoid the Rolldown for-of → forEach transform which
    // rewrites `this` inside the callback to the global object.
    const params = this._params;
    for (let i = 0; i < params.length; i++) {
      callback.call(thisArg, params[i][1], params[i][0], this);
    }
  }

  *entries(): IterableIterator<[string, string]> {
    for (const entry of this._params) {
      yield entry;
    }
  }

  *keys(): IterableIterator<string> {
    for (const [key] of this._params) {
      yield key;
    }
  }

  *values(): IterableIterator<string> {
    for (const [, value] of this._params) {
      yield value;
    }
  }

  [Symbol.iterator](): IterableIterator<[string, string]> {
    return this.entries();
  }
}

for (const key of ["size", "length"] as const) {
  const descriptor = Object.getOwnPropertyDescriptor(URLSearchParams.prototype, key);
  if (descriptor) {
    Object.defineProperty(URLSearchParams.prototype, key, {
      ...descriptor,
      enumerable: true,
    });
  }
}
