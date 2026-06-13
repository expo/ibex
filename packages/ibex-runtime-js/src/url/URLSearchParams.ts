/**
 * URLSearchParams - WHATWG URL Standard Implementation
 *
 * @see https://url.spec.whatwg.org/#urlsearchparams
 */

import type { URL } from "./URL";

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
          this._params.push([String(key), String(value)]);
        }
      } else {
        // Plain object
        const keys = Object.keys(init as Record<string, string>);
        for (let i = 0; i < keys.length; i++) {
          const key = keys[i];
          this._params.push([key, String((init as Record<string, string>)[key])]);
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
    try {
      return decodeURIComponent(str.replace(/\+/g, " "));
    } catch {
      return str;
    }
  }

  private _encode(str: string): string {
    return encodeURIComponent(str).replace(/%20/g, "+");
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

  append(name: string, value: string): void {
    this._params.push([String(name), String(value)]);
    this._update();
  }

  delete(name: string, value?: string): void {
    const key = String(name);
    if (value === undefined) {
      this._params = this._params.filter(([k]) => k !== key);
    } else {
      const val = String(value);
      this._params = this._params.filter(([k, v]) => !(k === key && v === val));
    }
    this._update();
  }

  get(name: string): string | null {
    const key = String(name);
    const entry = this._params.find(([k]) => k === key);
    return entry ? entry[1] : null;
  }

  getAll(name: string): string[] {
    const key = String(name);
    return this._params.filter(([k]) => k === key).map(([, v]) => v);
  }

  has(name: string, value?: string): boolean {
    const key = String(name);
    if (value === undefined) {
      return this._params.some(([k]) => k === key);
    }
    const val = String(value);
    return this._params.some(([k, v]) => k === key && v === val);
  }

  set(name: string, value: string): void {
    const key = String(name);
    const val = String(value);

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
