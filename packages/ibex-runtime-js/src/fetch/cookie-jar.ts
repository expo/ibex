/**
 * Cookie Jar Implementation (RFC 6265)
 *
 * A self-contained, spec-aligned cookie store for the Ibex runtime.
 * Cookies are managed entirely in the JS fetch layer — the native HTTP
 * backends are stateless pipes with no implicit cookie handling.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6265
 */

import type { RequestCredentials, RequestMode } from './types.js';

// =============================================================================
// Types
// =============================================================================

export interface StoredCookie {
  name: string;
  value: string;
  /** Normalized domain: lowercase, with leading dot for domain cookies */
  domain: string;
  /** Defaults to request path up to last '/' */
  path: string;
  /** Unix ms timestamp, null = session cookie */
  expires: number | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  /** true if no Domain attribute was set (exact host match required) */
  hostOnly: boolean;
  creationTime: number;
  lastAccessTime: number;
}

// =============================================================================
// Constants
// =============================================================================

const MAX_COOKIES_PER_DOMAIN = 300;
const MAX_COOKIES_TOTAL = 3000;
const MAX_COOKIE_SIZE = 4096; // name + value bytes

// =============================================================================
// Runtime Origin
// =============================================================================

let _runtimeOrigin: URL | null = null;

/**
 * Set the runtime origin for same-origin credential checks.
 */
export function setRuntimeOrigin(origin: string): void {
  _runtimeOrigin = new URL(origin);
}

/**
 * Get the runtime origin. Falls back to location.href, then exact://app.
 */
export function getRuntimeOrigin(): URL {
  if (_runtimeOrigin) return _runtimeOrigin;

  // Try globalThis.location
  const location = (globalThis as any).location;
  if (location && typeof location === 'object') {
    const href = typeof location.href === 'string' ? location.href : null;
    if (href) {
      try {
        _runtimeOrigin = new URL(href);
        return _runtimeOrigin;
      } catch {
        // invalid, fall through
      }
    }
  }

  // Fallback
  _runtimeOrigin = new URL('exact://app');
  return _runtimeOrigin;
}

// =============================================================================
// Helpers
// =============================================================================

/**
 * Get the default cookie path from a request URL.
 * Per RFC 6265 Section 5.1.4.
 */
function defaultCookiePath(url: URL): string {
  const uriPath = url.pathname;
  if (!uriPath || uriPath[0] !== '/' || uriPath === '/') {
    return '/';
  }
  const lastSlash = uriPath.lastIndexOf('/');
  if (lastSlash <= 0) return '/';
  return uriPath.substring(0, lastSlash);
}

/**
 * Check if a cookie domain matches a request host.
 * Per RFC 6265 Section 5.1.3.
 */
function domainMatch(cookieDomain: string, requestHost: string): boolean {
  // Exact match
  if (cookieDomain === requestHost) return true;

  // requestHost must end with cookieDomain and the character before the suffix must be a dot
  if (requestHost.endsWith(cookieDomain)) {
    const prefixLen = requestHost.length - cookieDomain.length;
    if (prefixLen > 0 && requestHost[prefixLen - 1] === '.') {
      // Also, requestHost must not be an IP address
      if (!isIPAddress(requestHost)) {
        return true;
      }
    }
  }

  // Leading-dot domain match: .example.com matches sub.example.com
  if (cookieDomain.startsWith('.')) {
    const withoutDot = cookieDomain.substring(1);
    if (requestHost === withoutDot || requestHost.endsWith('.' + withoutDot)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a cookie path matches a request path.
 * Per RFC 6265 Section 5.1.4.
 */
function pathMatch(cookiePath: string, requestPath: string): boolean {
  if (cookiePath === requestPath) return true;
  if (requestPath.startsWith(cookiePath)) {
    if (cookiePath.endsWith('/')) return true;
    if (requestPath[cookiePath.length] === '/') return true;
  }
  return false;
}

/**
 * Rough check for IP address (IPv4 or IPv6).
 */
function isIPAddress(host: string): boolean {
  // IPv6
  if (host.includes(':')) return true;
  // IPv4: all parts are digits
  const parts = host.split('.');
  return parts.length === 4 && parts.every(p => /^\d+$/.test(p));
}

/**
 * Get the registrable domain (eTLD+1) from a hostname.
 * Simplified: returns last two labels (e.g. "example.com" from "sub.example.com").
 */
function getRegistrableDomain(host: string): string {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  return parts.slice(-2).join('.');
}

/**
 * Check if two URLs are same-site (same registrable domain).
 */
function isSameSite(a: URL, b: URL): boolean {
  const domainA = getRegistrableDomain(a.hostname.toLowerCase());
  const domainB = getRegistrableDomain(b.hostname.toLowerCase());
  return domainA === domainB;
}

/**
 * Check if two URLs are same-origin.
 */
function isSameOrigin(a: URL, b: URL): boolean {
  return a.origin === b.origin;
}

/**
 * Parse a date string from Expires attribute.
 * Returns unix ms timestamp or NaN.
 */
function parseExpiresDate(dateStr: string): number {
  const ms = Date.parse(dateStr);
  return ms;
}

// =============================================================================
// Set-Cookie Parser
// =============================================================================

interface ParsedSetCookie {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  expires?: number;    // unix ms
  maxAge?: number;     // seconds
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none';
}

/**
 * Parse a single Set-Cookie header value.
 * Per RFC 6265 Section 5.2.
 */
function parseSetCookie(header: string): ParsedSetCookie | null {
  // Split on first ';' to separate name-value from attributes
  const semiIndex = header.indexOf(';');
  const nameValuePart = semiIndex === -1 ? header : header.substring(0, semiIndex);
  const attributesPart = semiIndex === -1 ? '' : header.substring(semiIndex + 1);

  // Split name=value on first '='
  const eqIndex = nameValuePart.indexOf('=');
  if (eqIndex === -1) return null; // no name=value pair

  const name = nameValuePart.substring(0, eqIndex).trim();
  const value = nameValuePart.substring(eqIndex + 1).trim();

  if (!name) return null; // empty name

  const result: ParsedSetCookie = {
    name,
    value,
    secure: false,
    httpOnly: false,
    sameSite: 'lax', // default per modern browser behavior
  };

  // Parse attributes
  if (attributesPart) {
    const attrs = attributesPart.split(';');
    for (const attr of attrs) {
      const trimmed = attr.trim();
      if (!trimmed) continue;

      const attrEq = trimmed.indexOf('=');
      const attrName = (attrEq === -1 ? trimmed : trimmed.substring(0, attrEq)).trim().toLowerCase();
      const attrValue = attrEq === -1 ? '' : trimmed.substring(attrEq + 1).trim();

      switch (attrName) {
        case 'domain': {
          let d = attrValue.toLowerCase();
          if (d.startsWith('.')) d = d.substring(1);
          result.domain = d;
          break;
        }
        case 'path':
          result.path = attrValue;
          break;
        case 'expires': {
          const ms = parseExpiresDate(attrValue);
          if (!isNaN(ms)) {
            result.expires = ms;
          }
          break;
        }
        case 'max-age': {
          const seconds = parseInt(attrValue, 10);
          if (!isNaN(seconds)) {
            result.maxAge = seconds;
          }
          break;
        }
        case 'secure':
          result.secure = true;
          break;
        case 'httponly':
          result.httpOnly = true;
          break;
        case 'samesite': {
          const sv = attrValue.toLowerCase();
          if (sv === 'strict') result.sameSite = 'strict';
          else if (sv === 'lax') result.sameSite = 'lax';
          else if (sv === 'none') result.sameSite = 'none';
          break;
        }
      }
    }
  }

  return result;
}

// =============================================================================
// CookieJar
// =============================================================================

export class CookieJar {
  /** Cookies stored by domain */
  private _store: Map<string, StoredCookie[]> = new Map();
  private _totalCount = 0;

  /**
   * Parse a Set-Cookie header and store the cookie.
   * Per RFC 6265 Section 5.3.
   */
  setCookie(setCookieHeader: string, requestUrl: URL): void {
    const parsed = parseSetCookie(setCookieHeader);
    if (!parsed) return;

    const now = Date.now();
    const requestHost = requestUrl.hostname.toLowerCase();

    // Determine domain
    let domain: string;
    let hostOnly: boolean;

    if (parsed.domain) {
      // Domain attribute was set — check domain-match
      if (!domainMatch(parsed.domain, requestHost) &&
          parsed.domain !== requestHost) {
        return; // reject: domain doesn't match request
      }
      domain = parsed.domain;
      hostOnly = false;
    } else {
      // No Domain attribute — host-only cookie
      domain = requestHost;
      hostOnly = true;
    }

    // Determine path
    const path = parsed.path || defaultCookiePath(requestUrl);

    // Determine expiry: Max-Age takes precedence over Expires
    let expires: number | null = null;
    if (parsed.maxAge !== undefined) {
      if (parsed.maxAge <= 0) {
        expires = 0; // delete cookie
      } else {
        expires = now + parsed.maxAge * 1000;
      }
    } else if (parsed.expires !== undefined) {
      expires = parsed.expires;
    }

    // Check cookie size limit
    if (parsed.name.length + parsed.value.length > MAX_COOKIE_SIZE) {
      return; // too large
    }

    if (parsed.sameSite === 'none' && !parsed.secure) {
      return; // SameSite=None requires Secure
    }

    const cookie: StoredCookie = {
      name: parsed.name,
      value: parsed.value,
      domain,
      path,
      expires,
      secure: parsed.secure,
      httpOnly: parsed.httpOnly,
      sameSite: parsed.sameSite,
      hostOnly,
      creationTime: now,
      lastAccessTime: now,
    };

    // If expires is in the past, this is a delete
    if (expires !== null && expires <= now) {
      this._removeCookie(domain, parsed.name, path);
      return;
    }

    // Store: replace existing cookie with same name/domain/path
    let domainCookies = this._store.get(domain);
    if (!domainCookies) {
      domainCookies = [];
      this._store.set(domain, domainCookies);
    }

    const existingIdx = domainCookies.findIndex(
      c => c.name === cookie.name && c.path === cookie.path
    );

    if (existingIdx !== -1) {
      // Preserve creation time from existing cookie
      cookie.creationTime = domainCookies[existingIdx].creationTime;
      domainCookies[existingIdx] = cookie;
    } else {
      // Enforce per-domain limit
      if (domainCookies.length >= MAX_COOKIES_PER_DOMAIN) {
        this._evictFromDomain(domainCookies);
      }
      // Enforce total limit
      if (this._totalCount >= MAX_COOKIES_TOTAL) {
        this._evictGlobal();
      }
      domainCookies.push(cookie);
      this._totalCount++;
    }
  }

  /**
   * Get the Cookie header value for a request URL + credentials mode.
   * Returns null if no cookies match.
   */
  getCookieHeader(
    requestUrl: URL,
    credentials: RequestCredentials,
    requestOrigin: URL,
    requestMode?: RequestMode,
    requestMethod?: string
  ): string | null {
    if (credentials === 'omit') return null;

    // Per Fetch spec: same-origin credentials in CORS mode should not send cookies
    if (credentials === 'same-origin' && requestMode === 'cors') {
      return null;
    }

    // same-origin check
    if (credentials === 'same-origin') {
      if (!isSameOrigin(requestUrl, requestOrigin)) {
        return null;
      }
    }

    const now = Date.now();
    const requestHost = requestUrl.hostname.toLowerCase();
    const requestPath = requestUrl.pathname || '/';
    const isSecure = requestUrl.protocol === 'https:' || requestUrl.protocol === 'wss:';
    const upperMethod = (requestMethod || 'GET').toUpperCase();
    const isSafeMethod = upperMethod === 'GET' || upperMethod === 'HEAD';

    const matches: StoredCookie[] = [];

    for (const [domain, cookies] of this._store) {
      for (const cookie of cookies) {
        // Check expiry
        if (cookie.expires !== null && cookie.expires <= now) continue;

        // Domain match
        if (cookie.hostOnly) {
          if (domain !== requestHost) continue;
        } else {
          if (!domainMatch(domain, requestHost)) continue;
        }

        // Path match
        if (!pathMatch(cookie.path, requestPath)) continue;

        // Secure check
        if (cookie.secure && !isSecure) continue;

        // SameSite check
        if (cookie.sameSite === 'strict') {
          if (!isSameSite(requestUrl, requestOrigin)) continue;
        } else if (cookie.sameSite === 'lax') {
          // Lax: allow on same-site, or cross-site safe (GET/HEAD) top-level requests
          if (!isSameSite(requestUrl, requestOrigin)) {
            // Cross-site: only allow safe methods (GET/HEAD)
            if (!isSafeMethod) continue;
          }
        }
        // 'none' always passes (but requires Secure — enforced at set time)

        cookie.lastAccessTime = now;
        matches.push(cookie);
      }
    }

    if (matches.length === 0) return null;

    // Sort per RFC 6265 Section 5.4:
    // 1. Longer paths first
    // 2. Earlier creation time first (for same path length)
    matches.sort((a, b) => {
      if (b.path.length !== a.path.length) return b.path.length - a.path.length;
      return a.creationTime - b.creationTime;
    });

    return matches.map(c => `${c.name}=${c.value}`).join('; ');
  }

  /**
   * Clear all cookies.
   */
  clearAll(): void {
    this._store.clear();
    this._totalCount = 0;
  }

  /**
   * Remove expired cookies from the store.
   */
  pruneExpired(): void {
    const now = Date.now();
    for (const [domain, cookies] of this._store) {
      const filtered = cookies.filter(c => c.expires === null || c.expires > now);
      const removed = cookies.length - filtered.length;
      if (removed > 0) {
        this._totalCount -= removed;
        if (filtered.length === 0) {
          this._store.delete(domain);
        } else {
          this._store.set(domain, filtered);
        }
      }
    }
  }

  /**
   * Get the number of stored cookies (for testing/debugging).
   */
  get count(): number {
    return this._totalCount;
  }

  // =========================================================================
  // Private helpers
  // =========================================================================

  private _removeCookie(domain: string, name: string, path: string): void {
    const cookies = this._store.get(domain);
    if (!cookies) return;
    const idx = cookies.findIndex(c => c.name === name && c.path === path);
    if (idx !== -1) {
      cookies.splice(idx, 1);
      this._totalCount--;
      if (cookies.length === 0) {
        this._store.delete(domain);
      }
    }
  }

  private _evictFromDomain(domainCookies: StoredCookie[]): void {
    // Evict the cookie with the oldest lastAccessTime
    let oldestIdx = 0;
    for (let i = 1; i < domainCookies.length; i++) {
      if (domainCookies[i].lastAccessTime < domainCookies[oldestIdx].lastAccessTime) {
        oldestIdx = i;
      }
    }
    domainCookies.splice(oldestIdx, 1);
    this._totalCount--;
  }

  private _evictGlobal(): void {
    // Find the cookie with the oldest lastAccessTime across all domains
    let oldestTime = Infinity;
    let oldestDomain = '';
    let oldestIdx = -1;

    for (const [domain, cookies] of this._store) {
      for (let i = 0; i < cookies.length; i++) {
        if (cookies[i].lastAccessTime < oldestTime) {
          oldestTime = cookies[i].lastAccessTime;
          oldestDomain = domain;
          oldestIdx = i;
        }
      }
    }

    if (oldestIdx !== -1) {
      const cookies = this._store.get(oldestDomain)!;
      cookies.splice(oldestIdx, 1);
      this._totalCount--;
      if (cookies.length === 0) {
        this._store.delete(oldestDomain);
      }
    }
  }
}

/** Global cookie jar instance shared by the fetch pipeline */
export const cookieJar = new CookieJar();
