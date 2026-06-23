/**
 * CacheStorage API Implementation (In-Memory)
 *
 * Implements the WHATWG CacheStorage interface for the Ibex runtime.
 * Manages multiple named Cache instances, all purely in-memory.
 *
 * @see https://w3c.github.io/ServiceWorker/#cachestorage-interface
 */

import { Cache, type CacheQueryOptions } from './Cache';
import { Request, type RequestInput } from '../fetch/Request';
import { Response } from '../fetch/Response';

/**
 * The CacheStorage interface represents the storage for Cache objects.
 * It provides a master directory of all named caches accessible to the runtime.
 */
export class CacheStorage {
  private _caches: Map<string, Cache> = new Map();

  /**
   * Opens and returns the named cache. If the cache does not exist,
   * a new empty cache is created with that name.
   *
   * @param cacheName - The name of the cache to open.
   * @returns A Promise resolving to the Cache object.
   */
  async open(cacheName: string): Promise<Cache> {
    let cache = this._caches.get(cacheName);
    if (!cache) {
      cache = new Cache();
      this._caches.set(cacheName, cache);
    }
    return cache;
  }

  /**
   * Checks if a cache with the given name exists.
   *
   * @param cacheName - The name of the cache to check.
   * @returns A Promise resolving to true if the cache exists, false otherwise.
   */
  async has(cacheName: string): Promise<boolean> {
    return this._caches.has(cacheName);
  }

  /**
   * Deletes the named cache.
   *
   * @param cacheName - The name of the cache to delete.
   * @returns A Promise resolving to true if the cache was deleted, false if it didn't exist.
   */
  async delete(cacheName: string): Promise<boolean> {
    return this._caches.delete(cacheName);
  }

  /**
   * Returns the names of all caches managed by this CacheStorage.
   *
   * @returns A Promise resolving to an array of cache names.
   */
  async keys(): Promise<string[]> {
    return [...this._caches.keys()];
  }

  /**
   * Searches all caches (in creation order) for the first matching response.
   *
   * @param request - The request to match.
   * @param options - Options to control matching behavior.
   * @returns A Promise resolving to the first matching Response, or undefined.
   */
  async match(
    request: RequestInput,
    options?: CacheQueryOptions
  ): Promise<Response | undefined> {
    for (const cache of this._caches.values()) {
      const response = await cache.match(request, options);
      if (response !== undefined) {
        return response;
      }
    }
    return undefined;
  }

  get [Symbol.toStringTag](): string {
    return 'CacheStorage';
  }
}
