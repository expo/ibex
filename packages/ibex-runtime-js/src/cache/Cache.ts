/**
 * Cache API Implementation (In-Memory)
 *
 * Implements the WHATWG Cache API interface for the Exact runtime.
 * This is a purely in-memory cache with no persistence.
 *
 * @see https://w3c.github.io/ServiceWorker/#cache-interface
 */

import { Request, type RequestInput } from '../fetch/Request';
import { Response } from '../fetch/Response';
import { Headers } from '../fetch/Headers';

/**
 * Options for Cache matching operations.
 */
export interface CacheQueryOptions {
  /** If true, the query string portion of the URL is ignored during matching. */
  ignoreSearch?: boolean;
  /** If true, the HTTP method is ignored during matching (normally only GET is matched). */
  ignoreMethod?: boolean;
  /** If true, the Vary header is ignored during matching. */
  ignoreVary?: boolean;
}

/**
 * Internal cache entry storing a request/response pair.
 */
interface CacheEntry {
  request: Request;
  response: Response;
}

/**
 * Strip the query string (search) from a URL string.
 */
function stripSearch(url: string): string {
  const idx = url.indexOf('?');
  if (idx === -1) return url;
  // Also need to keep the hash if present
  const hashIdx = url.indexOf('#', idx);
  if (hashIdx === -1) return url.substring(0, idx);
  return url.substring(0, idx) + url.substring(hashIdx);
}

/**
 * Normalize input into a Request object.
 */
function toRequest(input: RequestInput): Request {
  if (input instanceof Request) {
    return input;
  }
  return new Request(input);
}

function toFetchHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, name) => {
    result[name] = value;
  });
  return result;
}

/**
 * The Cache interface provides a persistent storage mechanism for
 * Request/Response object pairs. In this implementation, storage
 * is purely in-memory with no disk persistence.
 */
export class Cache {
  private _entries: CacheEntry[] = [];

  /**
   * Check if a request URL matches a cached entry URL.
   */
  private _urlMatches(
    cachedUrl: string,
    requestUrl: string,
    options?: CacheQueryOptions
  ): boolean {
    if (options?.ignoreSearch) {
      return stripSearch(cachedUrl) === stripSearch(requestUrl);
    }
    return cachedUrl === requestUrl;
  }

  /**
   * Check if a request matches a cached entry considering all options.
   */
  private _requestMatches(
    cachedRequest: Request,
    request: Request,
    options?: CacheQueryOptions
  ): boolean {
    // Check method unless ignoreMethod is set
    if (!options?.ignoreMethod && cachedRequest.method !== request.method) {
      return false;
    }

    // Check URL
    if (!this._urlMatches(cachedRequest.url, request.url, options)) {
      return false;
    }

    // Check Vary header unless ignoreVary is set
    if (!options?.ignoreVary) {
      const varyHeader = this._getVaryHeaderForEntry(cachedRequest);
      if (varyHeader) {
        const varyFields = varyHeader.split(',').map((f) => f.trim().toLowerCase());
        if (varyFields.includes('*')) {
          // Vary: * means the response varies on everything, so never match
          return false;
        }
        for (const field of varyFields) {
          const cachedValue = cachedRequest.headers.get(field);
          const requestValue = request.headers.get(field);
          if (cachedValue !== requestValue) {
            return false;
          }
        }
      }
    }

    return true;
  }

  /**
   * Get the Vary header value for a cached entry's response.
   */
  private _getVaryHeaderForEntry(cachedRequest: Request): string | null {
    const entry = this._entries.find((e) => e.request === cachedRequest);
    return entry?.response.headers.get('vary') ?? null;
  }

  /**
   * Returns the first matching Response for a given request, or undefined.
   *
   * @param request - The request to match against cached entries.
   * @param options - Options to control matching behavior.
   * @returns A Promise resolving to the matching Response, or undefined.
   */
  async match(
    request: RequestInput,
    options?: CacheQueryOptions
  ): Promise<Response | undefined> {
    const req = toRequest(request);

    // Per spec, only GET requests are matched unless ignoreMethod is set
    if (!options?.ignoreMethod && req.method !== 'GET') {
      return undefined;
    }

    for (const entry of this._entries) {
      if (this._requestMatches(entry.request, req, options)) {
        return entry.response.clone();
      }
    }

    return undefined;
  }

  /**
   * Returns all matching Responses for a given request.
   * If no request is provided, returns all cached responses.
   *
   * @param request - The request to match, or undefined to return all.
   * @param options - Options to control matching behavior.
   * @returns A Promise resolving to an array of matching Responses.
   */
  async matchAll(
    request?: RequestInput,
    options?: CacheQueryOptions
  ): Promise<Response[]> {
    if (request === undefined) {
      return this._entries.map((entry) => entry.response.clone());
    }

    const req = toRequest(request);

    // Per spec, only GET requests are matched unless ignoreMethod is set
    if (!options?.ignoreMethod && req.method !== 'GET') {
      return [];
    }

    const results: Response[] = [];
    for (const entry of this._entries) {
      if (this._requestMatches(entry.request, req, options)) {
        results.push(entry.response.clone());
      }
    }

    return results;
  }

  /**
   * Fetches a URL and adds the response to the cache.
   * Throws if the response is not ok (status 200-299).
   *
   * @param request - The request or URL to fetch and cache.
   */
  async add(request: RequestInput): Promise<void> {
    await this.addAll([request]);
  }

  /**
   * Fetches multiple URLs and adds all responses to the cache.
   * Throws if any response is not ok (status 200-299).
   *
   * @param requests - The requests or URLs to fetch and cache.
   */
  async addAll(requests: RequestInput[]): Promise<void> {
    const reqs = requests.map((r) => toRequest(r));

    // Validate: only GET requests
    for (const req of reqs) {
      if (req.method !== 'GET') {
        throw new TypeError('Request method must be GET for Cache.add/addAll');
      }
    }

    // Fetch all requests
    const fetchFn =
      typeof globalThis.fetch === 'function' ? globalThis.fetch : null;
    if (!fetchFn) {
      throw new TypeError(
        'Cache.add/addAll requires a global fetch function'
      );
    }

    const responses = await Promise.all(
      reqs.map((req) => fetchFn(req.url, {
        method: req.method,
        headers: toFetchHeaders(req.headers),
      }))
    );

    // Validate all responses
    for (let i = 0; i < responses.length; i++) {
      const response = responses[i];
      if (!response.ok) {
        throw new TypeError(
          `Request failed with status ${response.status}: ${reqs[i].url}`
        );
      }
    }

    // Store all entries
    for (let i = 0; i < reqs.length; i++) {
      await this.put(reqs[i], responses[i] as unknown as Response);
    }
  }

  /**
   * Stores a request/response pair in the cache.
   * The response is cloned before storing so the original can still be used.
   * Any existing entry with the same URL is replaced.
   *
   * @param request - The request to use as the cache key.
   * @param response - The response to store.
   */
  async put(request: RequestInput, response: Response): Promise<void> {
    const req = toRequest(request);

    // Per spec, only GET requests can be stored
    if (req.method !== 'GET') {
      throw new TypeError('Request method must be GET for Cache.put');
    }

    // Per spec, cannot store responses with status 206 (Partial Content)
    if (response.status === 206) {
      throw new TypeError('Cannot cache partial (206) responses');
    }

    // Remove any existing entry with the same URL
    this._entries = this._entries.filter(
      (entry) => entry.request.url !== req.url
    );

    // Clone request and response so the caller retains ownership of the originals.
    // Per Fetch/Cache semantics, stored requests should not retain lifecycle signals.
    this._entries.push({
      request: new Request(req.url, {
        method: req.method,
        headers: toFetchHeaders(req.headers),
        mode: req.mode,
        credentials: req.credentials,
        cache: req.cache,
        redirect: req.redirect,
        referrer: req.referrer,
        referrerPolicy: req.referrerPolicy,
        integrity: req.integrity,
        signal: null,
      }),
      response: response.clone(),
    });
  }

  /**
   * Deletes all cached entries matching the given request.
   *
   * @param request - The request to match for deletion.
   * @param options - Options to control matching behavior.
   * @returns A Promise resolving to true if any entry was deleted, false otherwise.
   */
  async delete(
    request: RequestInput,
    options?: CacheQueryOptions
  ): Promise<boolean> {
    const req = toRequest(request);
    const initialLength = this._entries.length;

    this._entries = this._entries.filter(
      (entry) => !this._requestMatches(entry.request, req, options)
    );

    return this._entries.length < initialLength;
  }

  /**
   * Returns all cached request keys.
   * If a request is provided, only matching keys are returned.
   *
   * @param request - Optional request to filter keys.
   * @param options - Options to control matching behavior.
   * @returns A Promise resolving to an array of cached Request objects.
   */
  async keys(
    request?: RequestInput,
    options?: CacheQueryOptions
  ): Promise<Request[]> {
    if (request === undefined) {
      return this._entries.map((entry) => entry.request.clone());
    }

    const req = toRequest(request);
    const results: Request[] = [];

    for (const entry of this._entries) {
      if (this._requestMatches(entry.request, req, options)) {
        results.push(entry.request.clone());
      }
    }

    return results;
  }

  get [Symbol.toStringTag](): string {
    return 'Cache';
  }
}
