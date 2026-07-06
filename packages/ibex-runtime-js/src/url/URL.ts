/**
 * URL - WHATWG URL Standard Implementation
 *
 * @see https://url.spec.whatwg.org/
 */

import { URLSearchParams } from "./URLSearchParams";

// Special schemes that have default ports
const DEFAULT_PORTS: Record<string, string> = {
  ftp: "21",
  http: "80",
  https: "443",
  ws: "80",
  wss: "443",
};

// Special schemes (cannot have opaque path)
const SPECIAL_SCHEMES = new Set(["ftp", "file", "http", "https", "ws", "wss"]);
const OBJECT_URL_PREFIX = "blob:exact:";
const objectURLRegistry = new Map<string, unknown>();
let objectURLCounter = 0;
const HOST_URL_CONSTRUCTOR: typeof globalThis.URL | undefined =
  typeof globalThis.URL === "function" ? globalThis.URL : undefined;

function makeMissingArgsError(argumentName: string): TypeError {
  const error = new TypeError(`The "${argumentName}" argument must be specified`);
  (error as any).code = "ERR_MISSING_ARGS";
  return error;
}

function makeInvalidBlobError(object: unknown): TypeError {
  let received = `type ${typeof object}`;
  if (object === null) {
    received = "null";
  } else if (object !== undefined && typeof object === "object") {
    const ctorName = (object as { constructor?: { name?: string } }).constructor?.name;
    received = ctorName ? `an instance of ${ctorName}` : "an instance of Object";
  }
  const error = new TypeError(
    `The "obj" argument must be an instance of Blob. Received ${received}`,
  );
  (error as any).code = "ERR_INVALID_ARG_TYPE";
  return error;
}

function resolveHostURLConstructor(): typeof globalThis.URL | undefined {
  if (
    typeof HOST_URL_CONSTRUCTOR === "function" &&
    HOST_URL_CONSTRUCTOR !== (URL as any)
  ) {
    return HOST_URL_CONSTRUCTOR;
  }

  const globalURL = globalThis.URL;
  if (typeof globalURL === "function" && globalURL !== (URL as any)) {
    return globalURL;
  }

  const globalRef = globalThis as any;
  for (const loaderName of ["__exactRequire", "require"]) {
    const loader = globalRef[loaderName];
    if (typeof loader !== "function") {
      continue;
    }

    try {
      const urlModule = loader("url");
      const moduleURL = urlModule?.URL;
      if (typeof moduleURL === "function" && moduleURL !== (URL as any)) {
        return moduleURL;
      }
    } catch {
      // Fall through to the custom parser if no host URL implementation exists.
    }
  }

  return undefined;
}

function canonicalizeSpecialHost(value: string): string {
  const hostURL = resolveHostURLConstructor();
  if (typeof hostURL !== "function") {
    // Locked-down compartments have no host parser; special-scheme hosts are
    // ASCII-lowercased per the WHATWG host parser so origin comparisons work.
    return value.toLowerCase();
  }
  const parsed = new hostURL(`https://${value}`);
  return parsed.hostname;
}

function toHex(code: number): string {
  const hex = code.toString(16).toUpperCase();
  return hex.length === 1 ? `0${hex}` : hex;
}

// WHATWG percent-encode sets (https://url.spec.whatwg.org/#percent-encoded-bytes).
// The C0 control set is the base; the fragment/query/path sets extend it. Code
// points > 0x7F are always UTF-8 percent-encoded, so these predicates only need
// to classify the ASCII range.
function inC0ControlPercentEncodeSet(code: number): boolean {
  return code <= 0x1f || code > 0x7e;
}
function inFragmentPercentEncodeSet(code: number): boolean {
  return (
    inC0ControlPercentEncodeSet(code) ||
    code === 0x20 || // space
    code === 0x22 || // "
    code === 0x3c || // <
    code === 0x3e || // >
    code === 0x60 //    `
  );
}
function inQueryPercentEncodeSet(code: number): boolean {
  return (
    inC0ControlPercentEncodeSet(code) ||
    code === 0x20 || // space
    code === 0x22 || // "
    code === 0x23 || // #
    code === 0x3c || // <
    code === 0x3e //    >
  );
}
function inSpecialQueryPercentEncodeSet(code: number): boolean {
  return inQueryPercentEncodeSet(code) || code === 0x27; // '
}
function inPathPercentEncodeSet(code: number): boolean {
  return (
    inQueryPercentEncodeSet(code) ||
    code === 0x3f || // ?
    code === 0x60 || // `
    code === 0x7b || // {
    code === 0x7d //    }
  );
}

/**
 * UTF-8 percent-encode `input`, encoding every code point that falls in
 * `inSet` plus every non-ASCII code point. Other characters pass through
 * unchanged; note `%` is in none of the URL sets, so existing %XX escapes are
 * preserved rather than double-encoded.
 */
function percentEncode(input: string, inSet: (code: number) => boolean): string {
  let out = "";
  for (const ch of input) {
    const code = ch.codePointAt(0)!;
    if (code > 0x7f) {
      try {
        out += encodeURIComponent(ch);
      } catch {
        out += "%EF%BF%BD"; // U+FFFD replacement for lone surrogates
      }
    } else if (inSet(code)) {
      out += `%${toHex(code)}`;
    } else {
      out += ch;
    }
  }
  return out;
}

function canonicalizeHost(value: string, protocol: string): string {
  const isSpecial = protocol && SPECIAL_SCHEMES.has(protocol.slice(0, -1));
  if (isSpecial) {
    try {
      return canonicalizeSpecialHost(value);
    } catch {
      return value.toLowerCase();
    }
  }
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const char = value.charAt(i);
    if (char.charCodeAt(0) >= 128) {
      out += encodeURIComponent(char);
      continue;
    }
    if (
      char === "%" &&
      i + 2 < value.length &&
      /[0-9A-Fa-f]/.test(value.charAt(i + 1)) &&
      /[0-9A-Fa-f]/.test(value.charAt(i + 2))
    ) {
      out += `%${value.charAt(i + 1).toUpperCase()}${value.charAt(i + 2).toUpperCase()}`;
      i += 2;
      continue;
    }
    out += char.toLowerCase();
  }
  return out;
}

function normalizePort(value: string): string {
  if (!value) {
    return "";
  }
  const match = value.match(/^[0-9]+/);
  if (!match) {
    return "";
  }
  value = match[0];
  return value.replace(/^0+(?=\d)/, "");
}

function sanitizeUserinfo(value: string): string {
  value = String(value);
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const c = value.charAt(i);
    if (
      c === "%" &&
      __needsHexDigit(value.charAt(i + 1)) &&
      __needsHexDigit(value.charAt(i + 2))
    ) {
      out += value.slice(i, i + 3);
      i += 2;
      continue;
    }

    if (__isUserinfoUnescaped(c)) {
      out += c;
      continue;
    }

    out += encodeURIComponent(c);
  }
  return out;
}

function __needsHexDigit(char: string): boolean {
  return !!char && /^[0-9A-Fa-f]$/.test(char);
}

function __isUserinfoUnescaped(c: string): boolean {
  const code = c.charCodeAt(0);
  if (code >= 0x30 && code <= 0x39) return true;
  if (code >= 0x41 && code <= 0x5A) return true;
  if (code >= 0x61 && code <= 0x7A) return true;
  return (
    code === 0x21 ||
    code === 0x24 ||
    code === 0x26 ||
    code === 0x27 ||
    code === 0x28 ||
    code === 0x29 ||
    code === 0x2A ||
    code === 0x2B ||
    code === 0x2C ||
    code === 0x2D ||
    code === 0x2E ||
    code === 0x25
  );
}

function sanitizeHost(value: string, protocol: string): string | null {
  value = String(value);
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0) {
      return null;
    }
    if (protocol === "https:" && code === 0x1f) {
      return null;
    }
    if (code >= 0 && code < 0x20) {
      if (code === 0x09 || code === 0x0a || code === 0x0d) {
        continue;
      }
      out += `%${toHex(code)}`;
      continue;
    }
    out += value.charAt(i);
  }
  return out;
}

function parseHostInput(value: string, isSpecial: boolean = false): string {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 47 || c === 63 || c === 35 || (isSpecial && c === 92)) {
      return value.slice(0, i);
    }
  }
  return value;
}

function stripProtocolControlChars(value: string): string {
  value = String(value);
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code === 0x09 || code === 0x0a || code === 0x0d) {
      continue;
    }
    out += value.charAt(i);
  }
  return out;
}

/**
 * Create a TypeError matching the WHATWG URL spec error format.
 * Redacts base URLs that contain passwords.
 */
function _makeURLError(input: string, baseInput?: string): TypeError {
  let msg: string;
  if (baseInput !== undefined) {
    // Redact base if it contains credentials (password portion)
    const hasCredentials = /:[^/].*@/.test(baseInput);
    const displayBase = hasCredentials ? "<redacted>" : JSON.stringify(baseInput);
    msg = `${JSON.stringify(input)} cannot be parsed as a URL against ${displayBase}`;
  } else {
    msg = `${JSON.stringify(input)} cannot be parsed as a URL`;
  }
  const err = new TypeError(msg);
  (err as any).code = "ERR_INVALID_URL";
  return err;
}

type ParsedURLParts = {
  protocol: string;
  username: string;
  password: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  // WHATWG hosts are null-vs-empty-string distinct: file: URLs have an EMPTY
  // host ("file:///tmp/x") while opaque-path URLs ("mailto:x") have NO host.
  // The serializer must emit "//" whenever a host is present, even if empty.
  hostPresent: boolean;
};

function splitPathSearchHash(input: string): { path: string; search: string; hash: string } {
  let value = input;
  let hash = "";
  const hashIndex = value.indexOf("#");
  if (hashIndex !== -1) {
    hash = value.slice(hashIndex);
    value = value.slice(0, hashIndex);
  }
  let search = "";
  const searchIndex = value.indexOf("?");
  if (searchIndex !== -1) {
    search = value.slice(searchIndex);
    value = value.slice(0, searchIndex);
  }
  return { path: value, search, hash };
}

function normalizePathname(path: string): string {
  // WHATWG path state: single/double dot segments (including their
  // percent-encoded spellings) are resolved, but EMPTY segments are kept —
  // "/a//b" must stay "/a//b", not collapse to "/a/b".
  if (!path) return "/";
  if (!path.startsWith("/")) path = "/" + path;
  const segments = path.split("/").slice(1);
  const out: string[] = [];
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    const lower = segment.toLowerCase();
    const isLast = i === segments.length - 1;
    if (lower === ".." || lower === "%2e." || lower === ".%2e" || lower === "%2e%2e") {
      if (out.length > 0) out.pop();
      if (isLast) out.push("");
    } else if (lower === "." || lower === "%2e") {
      if (isLast) out.push("");
    } else {
      out.push(segment);
    }
  }
  return "/" + out.join("/");
}

// Percent-encode the "?query" / "#fragment" tails produced by
// splitPathSearchHash, preserving the leading delimiter.
function encodeSearchTail(search: string, isSpecial: boolean): string {
  if (!search) return "";
  const encodeSet = isSpecial ? inSpecialQueryPercentEncodeSet : inQueryPercentEncodeSet;
  return "?" + percentEncode(search.slice(1), encodeSet);
}

function encodeHashTail(hash: string): string {
  if (!hash) return "";
  return "#" + percentEncode(hash.slice(1), inFragmentPercentEncodeSet);
}

function parseAuthorityUrl(protocol: string, rest: string): ParsedURLParts | null {
  const scheme = protocol.slice(0, -1);
  const isSpecial = SPECIAL_SCHEMES.has(scheme);
  // file: and non-special schemes accept an empty host ("file:///x",
  // "foo:///x"); the other special schemes require one.
  const allowEmptyHost = !isSpecial || scheme === "file";
  const authorityEnd = rest.search(/[/?#]/);
  const authority = authorityEnd === -1 ? rest : rest.slice(0, authorityEnd);
  const pathTail = authorityEnd === -1 ? "" : rest.slice(authorityEnd);
  if (!authority && !allowEmptyHost) {
    return null;
  }

  let hostPort = authority;
  let username = "";
  let password = "";
  const at = hostPort.lastIndexOf("@");
  if (at !== -1) {
    const rawUserinfo = hostPort.slice(0, at);
    hostPort = hostPort.slice(at + 1);
    const colon = rawUserinfo.indexOf(":");
    if (colon === -1) {
      username = sanitizeUserinfo(rawUserinfo);
    } else {
      username = sanitizeUserinfo(rawUserinfo.slice(0, colon));
      password = sanitizeUserinfo(rawUserinfo.slice(colon + 1));
    }
  }

  let hostname = "";
  let port = "";
  if (hostPort.startsWith("[")) {
    const close = hostPort.indexOf("]");
    if (close === -1) return null;
    hostname = hostPort.slice(0, close + 1).toLowerCase();
    if (close + 1 < hostPort.length) {
      if (hostPort.charAt(close + 1) !== ":") return null;
      port = normalizePort(hostPort.slice(close + 2));
    }
  } else {
    const colon = hostPort.lastIndexOf(":");
    if (colon !== -1) {
      hostname = canonicalizeHost(hostPort.slice(0, colon), protocol);
      port = normalizePort(hostPort.slice(colon + 1));
    } else {
      hostname = canonicalizeHost(hostPort, protocol);
    }
  }
  if (!hostname && !allowEmptyHost) return null;
  // A file: host of "localhost" is normalized to the empty host.
  if (scheme === "file" && hostname === "localhost") hostname = "";
  if (port) {
    const portNumber = Number(port);
    if (!Number.isInteger(portNumber) || portNumber > 65535) return null;
    if (port === DEFAULT_PORTS[scheme]) port = "";
  }

  const { path, search, hash } = splitPathSearchHash(pathTail);
  // Special schemes always have at least "/" as the path; non-special URLs
  // keep an empty path ("foo://h" serializes without a trailing slash).
  const pathname = path !== "" || isSpecial ? normalizePathname(path) : "";
  return {
    protocol,
    username,
    password,
    hostname,
    port,
    hostPresent: true,
    pathname: percentEncode(pathname, inPathPercentEncodeSet),
    search: encodeSearchTail(search, isSpecial),
    hash: encodeHashTail(hash),
  };
}

function parseBasicUrl(input: string, base: URL | null): ParsedURLParts | null {
  let value = stripProtocolControlChars(String(input).trim());
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(value);
  if (scheme) {
    const protocol = `${scheme[1].toLowerCase()}:`;
    const schemeName = protocol.slice(0, -1);
    const isSpecial = SPECIAL_SCHEMES.has(schemeName);
    let rest = value.slice(scheme[0].length);
    if (isSpecial) {
      // The WHATWG parser treats "\" as "/" for special schemes
      // ("http:\\example.com\path" is an authority, not an opaque path).
      rest = rest.replace(/\\/g, "/");
    }
    if (schemeName === "file") {
      if (rest.startsWith("//")) {
        return parseAuthorityUrl(protocol, rest.slice(2));
      }
      // file: URLs always carry a (possibly empty) host: "file:/tmp/x" and
      // "file:" normalize to the empty-host, absolute-path form.
      const { path, search, hash } = splitPathSearchHash(rest);
      return {
        protocol,
        username: "",
        password: "",
        hostname: "",
        port: "",
        hostPresent: true,
        pathname: percentEncode(normalizePathname(path), inPathPercentEncodeSet),
        search: encodeSearchTail(search, true),
        hash: encodeHashTail(hash),
      };
    }
    if (isSpecial) {
      // "special authority ignore slashes": any run of leading slashes (or
      // none at all — "http:example.com") precedes the authority.
      return parseAuthorityUrl(protocol, rest.replace(/^\/+/, ""));
    }
    if (rest.startsWith("//")) {
      return parseAuthorityUrl(protocol, rest.slice(2));
    }
    const { path, search, hash } = splitPathSearchHash(rest);
    const hierarchical = path.startsWith("/");
    return {
      protocol,
      username: "",
      password: "",
      hostname: "",
      port: "",
      hostPresent: false,
      pathname: hierarchical
        ? percentEncode(normalizePathname(path), inPathPercentEncodeSet)
        : percentEncode(path, inC0ControlPercentEncodeSet),
      search: encodeSearchTail(search, false),
      hash: encodeHashTail(hash),
    };
  }

  if (!base) {
    return null;
  }
  const baseScheme = base.protocol.slice(0, -1);
  const baseIsSpecial = SPECIAL_SCHEMES.has(baseScheme);
  if (baseIsSpecial) {
    value = value.replace(/\\/g, "/");
  }
  if (value.startsWith("//")) {
    return parseAuthorityUrl(base.protocol, value.slice(2));
  }
  const { path, search, hash } = splitPathSearchHash(value);
  const basePath = base.pathname || "/";
  let pathname = basePath;
  if (path) {
    if (path.startsWith("/")) {
      pathname = normalizePathname(path);
    } else {
      const slash = basePath.lastIndexOf("/");
      const dir = slash === -1 ? "/" : basePath.slice(0, slash + 1);
      pathname = normalizePathname(dir + path);
    }
  }
  return {
    protocol: base.protocol,
    username: base.username,
    password: base.password,
    hostname: base.hostname,
    port: base.port,
    hostPresent: (base as unknown as { _hasHost: boolean })._hasHost,
    pathname: percentEncode(pathname, inPathPercentEncodeSet),
    search: search
      ? encodeSearchTail(search, baseIsSpecial)
      : path
        ? ""
        : base.search,
    hash: encodeHashTail(hash),
  };
}

export class URL {
  private _protocol: string = "";
  private _username: string = "";
  private _password: string = "";
  private _hostname: string = "";
  private _port: string = "";
  private _pathname: string = "";
  private _search: string = "";
  private _hash: string = "";
  // Whether the URL has a host at all (WHATWG null-vs-empty host). file: URLs
  // have an EMPTY host (serialize with "//"); opaque-path URLs have NO host.
  private _hasHost: boolean = false;
  private _searchParams: URLSearchParams;

  constructor(url: string, base?: string | URL) {
    if (arguments.length === 0) {
      const error = new TypeError('The "url" argument must be specified');
      (error as any).code = "ERR_MISSING_ARGS";
      throw error;
    }

    // Per WHATWG URL spec: convert url and base to USVString
    const urlStr = String(url);

    // Parse base URL if provided
    let baseURL: URL | null = null;
    const baseStr = base !== undefined ? (base instanceof URL ? base.href : String(base)) : undefined;
    if (base !== undefined) {
      if (base instanceof URL) {
        baseURL = base;
      } else {
        try {
          baseURL = new URL(String(base));
        } catch {
          throw _makeURLError(urlStr, baseStr);
        }
      }
    }

    // Parse the URL
    this._parse(urlStr, baseURL, baseStr);

    // Initialize search params
    this._searchParams = new URLSearchParams(this._search);
    this._searchParams._setURL(this);
  }

  private _parse(input: string, base: URL | null, baseStr?: string): void {
    const hostURL = resolveHostURLConstructor();
    if (typeof hostURL === "function") {
      try {
        const parsed = base ? new hostURL(input, base.href) : new hostURL(input);
        this._protocol = parsed.protocol;
        this._username = parsed.username;
        this._password = parsed.password;
        this._hostname = parsed.hostname;
        this._port = parsed.port;
        this._pathname = parsed.pathname;
        this._search = parsed.search;
        this._hash = parsed.hash;
        // Host implementations expose hostname "" both for empty hosts
        // (file:///x) and absent hosts (mailto:x); the serialized href is the
        // only reliable signal. A null-host URL never serializes "//" right
        // after the scheme (paths starting "//" get a "/." guard).
        this._hasHost = parsed.href.startsWith(`${parsed.protocol}//`);
        return;
      } catch {
        throw _makeURLError(input, baseStr);
      }
    }

    const parsed = parseBasicUrl(input, base);
    if (!parsed) throw _makeURLError(input, baseStr);
    this._protocol = parsed.protocol;
    this._username = parsed.username;
    this._password = parsed.password;
    this._hostname = parsed.hostname;
    this._port = parsed.port;
    this._pathname = parsed.pathname;
    this._search = parsed.search;
    this._hash = parsed.hash;
    this._hasHost = parsed.hostPresent;
  }

  private _normalizePath(path: string): string {
    if (!path) return "/";

    const segments = path.split("/");
    const normalized: string[] = [];

    for (const segment of segments) {
      if (segment === ".") {
        continue;
      } else if (segment === "..") {
        normalized.pop();
      } else {
        normalized.push(segment);
      }
    }

    let result = normalized.join("/");
    if (!result.startsWith("/")) {
      result = "/" + result;
    }

    return result;
  }

  // Getters and setters
  get href(): string {
    // WHATWG URL serializer: the "//" authority prefix is emitted whenever a
    // host is PRESENT, including the empty-string host of file: URLs —
    // "file:///tmp/x" must not degrade to "file:/tmp/x", and "file:////x"
    // must not corrupt into "file://x" (which re-parses with host "x").
    let result = this._protocol;

    if (this._hasHost) {
      result += "//";

      if (this._username || this._password) {
        result += this._username;
        if (this._password) {
          result += ":" + this._password;
        }
        result += "@";
      }

      result += this._hostname;

      if (this._port) {
        result += ":" + this._port;
      }
    } else if (this._pathname.startsWith("//")) {
      // No host but a path starting "//": prepend "/." so the path cannot be
      // re-parsed as an authority.
      result += "/.";
    }

    result += this._pathname;
    result += this._search;
    result += this._hash;

    return result;
  }

  set href(value: string) {
    const newURL = new URL(value);
    this._protocol = newURL._protocol;
    this._username = newURL._username;
    this._password = newURL._password;
    this._hostname = newURL._hostname;
    this._port = newURL._port;
    this._pathname = newURL._pathname;
    this._search = newURL._search;
    this._hash = newURL._hash;
    this._hasHost = newURL._hasHost;
    // Per the spec there is exactly one URLSearchParams object per URL for its
    // lifetime; re-fill the existing instance rather than vending a new one.
    this._searchParams._resetFromSearch(this._search);
  }

  get origin(): string {
    const scheme = this._protocol.slice(0, -1);

    // blob: URLs derive origin from their inner URL
    if (scheme === "blob") {
      try {
        let innerHref = this._pathname + this._search + this._hash;
        if (
          innerHref.startsWith("/") &&
          /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(innerHref.slice(1))
        ) {
          innerHref = innerHref.slice(1);
        }
        const innerURL = new URL(innerHref);
        if (innerURL.protocol === "file:") {
          return innerURL.host ? `file://${innerURL.host}` : "file://";
        }
        return innerURL.origin;
      } catch {
        return "null";
      }
    }

    // file: always has null origin per the URL spec
    if (scheme === "file") {
      return "null";
    }

    // Only http, https, ftp, ws, wss have a meaningful origin
    if (scheme === "http" || scheme === "https" || scheme === "ftp" || scheme === "ws" || scheme === "wss") {
      return `${this._protocol}//${this.host}`;
    }

    return "null";
  }

  get protocol(): string {
    return this._protocol;
  }

  set protocol(value: string) {
    let proto = stripProtocolControlChars(String(value)).toLowerCase();
    if (!proto.endsWith(":")) {
      proto += ":";
    }
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:$/.test(proto)) {
      return;
    }
    if (proto === "file:" && (this._username || this._password || this._port)) {
      return;
    }
    this._protocol = proto;
  }

  get username(): string {
    return this._username;
  }

  set username(value: string) {
    if (this._protocol === "file:" || this._protocol === "unix:") {
      return;
    }
    this._username = sanitizeUserinfo(String(value));
  }

  get password(): string {
    return this._password;
  }

  set password(value: string) {
    if (this._protocol === "file:" || this._protocol === "unix:") {
      return;
    }
    this._password = sanitizeUserinfo(String(value));
  }

  get host(): string {
    if (this._port) {
      return `${this._hostname}:${this._port}`;
    }
    return this._hostname;
  }

  set host(value: string) {
    const input = sanitizeHost(value, this._protocol);
    if (input === null) {
      return;
    }
    const isSpecial = SPECIAL_SCHEMES.has(this._protocol.slice(0, -1));
    if (!this._hostname && !isSpecial) {
      return;
    }
    const hostInput = parseHostInput(input, isSpecial);
    if (hostInput === "") {
      if (!isSpecial && this._hostname) {
        this._hostname = "";
        this._port = "";
      }
      return;
    }
    if (hostInput.indexOf(" ") !== -1) {
      return;
    }
    if (hostInput.indexOf("@") !== -1) {
      return;
    }
    if (hostInput.indexOf("\\") !== -1 && !isSpecial) {
      return;
    }

    const colonIndex = hostInput.lastIndexOf(":");
    if (colonIndex !== -1 && !input.includes("[")) {
      this._hostname = canonicalizeHost(hostInput.slice(0, colonIndex), this._protocol);
      this._hasHost = true;
      if (colonIndex < hostInput.length - 1) {
        const port = hostInput.slice(colonIndex + 1);
        const parsedPort = normalizePort(port);
        if (parsedPort) {
          const portNumber = Number(parsedPort);
          if (!Number.isNaN(portNumber) && portNumber <= 65535) {
            this._port = parsedPort;
          }
        } else if (port === "") {
          this._port = "";
        }
        if (this._port && this._protocol.slice(0, -1) && this._port === DEFAULT_PORTS[this._protocol.slice(0, -1)]) {
          this._port = "";
        }
      }
    } else if (hostInput !== "") {
        this._hostname = canonicalizeHost(hostInput, this._protocol);
        this._hasHost = true;
    } else {
      this._hostname = "";
      this._port = "";
    }
  }

  get hostname(): string {
    return this._hostname;
  }

  set hostname(value: string) {
    const input = sanitizeHost(value, this._protocol);
    if (input === null) {
      return;
    }
    const isSpecial = SPECIAL_SCHEMES.has(this._protocol.slice(0, -1));
    if (!this._hostname && !isSpecial) {
      return;
    }
    const hostInput = parseHostInput(input, isSpecial);
    if (hostInput === "" || hostInput.indexOf(" ") !== -1) {
      return;
    }
    if (hostInput.indexOf("@") !== -1) {
      return;
    }
    if (hostInput.indexOf("\\") !== -1 && !isSpecial) {
      return;
    }
    this._hostname = canonicalizeHost(hostInput, this._protocol);
    this._hasHost = true;
  }

  get port(): string {
    return this._port;
  }

  set port(value: string) {
    // file: URLs cannot carry a port (matches the protocol/username setters).
    if (this._protocol === "file:") {
      return;
    }
    const port = String(value);
    if (port === "") {
      this._port = "";
      return;
    }
    // Per the WHATWG port state, consume the leading ASCII digits. If there are
    // none, or the value overflows 2^16-1, the setter is a no-op rather than
    // storing a non-numeric string that would make the serialized href
    // unparseable.
    const match = port.match(/^[0-9]+/);
    if (!match) {
      return;
    }
    if (Number(match[0]) > 65535) {
      return;
    }
    const normalized = normalizePort(port);
    this._port =
      normalized === DEFAULT_PORTS[this._protocol.slice(0, -1)] ? "" : normalized;
  }

  get pathname(): string {
    return this._pathname;
  }

  set pathname(value: string) {
    // Normalize dot segments, then percent-encode with the path set so control
    // characters, spaces and query/fragment delimiters can't leak into the
    // authority-less serialization.
    this._pathname = percentEncode(
      this._normalizePath(String(value)),
      inPathPercentEncodeSet,
    );
  }

  get search(): string {
    return this._search;
  }

  set search(value: string) {
    let search = String(value);
    if (search === "") {
      this._search = "";
    } else {
      if (search.startsWith("?")) {
        search = search.slice(1);
      }
      // Percent-encode with the query set (special schemes also encode '), so a
      // '#' or space in the query can't round-trip through href as a fragment.
      const encodeSet = SPECIAL_SCHEMES.has(this._protocol.slice(0, -1))
        ? inSpecialQueryPercentEncodeSet
        : inQueryPercentEncodeSet;
      this._search = "?" + percentEncode(search, encodeSet);
    }
    // Re-fill the persistent searchParams instance instead of replacing it, so
    // any previously vended reference keeps observing this URL.
    this._searchParams._resetFromSearch(this._search);
  }

  get searchParams(): URLSearchParams {
    return this._searchParams;
  }

  get hash(): string {
    return this._hash;
  }

  set hash(value: string) {
    let hash = String(value);
    if (hash === "") {
      this._hash = "";
      return;
    }
    if (hash.startsWith("#")) {
      hash = hash.slice(1);
    }
    // Percent-encode with the fragment set so spaces and control characters
    // survive an href round-trip.
    this._hash = "#" + percentEncode(hash, inFragmentPercentEncodeSet);
  }

  toString(): string {
    return this.href;
  }

  toJSON(): string {
    return this.href;
  }

  /**
   * Update search string from URLSearchParams
   * @internal
   */
  _updateSearch(search: string): void {
    this._search = search ? "?" + search : "";
  }

  /**
   * Check if a string can be parsed as a URL
   *
   * Per Node.js spec, throws ERR_MISSING_ARGS if called with no arguments.
   */
  static canParse(url: string, base?: string): boolean {
    // @ts-ignore - check at runtime since TypeScript doesn't track arguments.length
    if (arguments.length === 0) {
      throw makeMissingArgsError("url");
    }
    try {
      new URL(url, base);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Parse a URL string, returning null instead of throwing on invalid input.
   *
   * @see https://url.spec.whatwg.org/#dom-url-parse
   */
  static parse(url: string, base?: string | URL): URL | null {
    try {
      return new URL(url, base);
    } catch {
      return null;
    }
  }

  static createObjectURL(object: unknown): string {
    // @ts-ignore - runtime arity check
    if (arguments.length === 0) {
      throw makeMissingArgsError("obj");
    }
    if (typeof Blob !== "function" || !(object instanceof Blob)) {
      throw makeInvalidBlobError(object);
    }
    const url = `${OBJECT_URL_PREFIX}${++objectURLCounter}`;
    objectURLRegistry.set(url, object);
    return url;
  }

  static revokeObjectURL(url: unknown): void {
    // @ts-ignore - runtime arity check
    if (arguments.length === 0) {
      throw makeMissingArgsError("url");
    }
    objectURLRegistry.delete(String(url));
  }
}

// @internal — shared with URLPattern's component canonicalization and with the
// fallback-parser unit tests. Not part of the public URL API surface.
export {
  percentEncode as _percentEncode,
  inPathPercentEncodeSet as _inPathPercentEncodeSet,
  inQueryPercentEncodeSet as _inQueryPercentEncodeSet,
  inFragmentPercentEncodeSet as _inFragmentPercentEncodeSet,
  parseBasicUrl as _parseBasicUrl,
  DEFAULT_PORTS as _DEFAULT_PORTS,
};
