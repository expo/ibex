/**
 * Cache API
 *
 * In-memory implementation of the WHATWG Cache API for the Exact runtime.
 *
 * @see https://w3c.github.io/ServiceWorker/#cache-interface
 * @see https://w3c.github.io/ServiceWorker/#cachestorage-interface
 *
 * @example
 * ```typescript
 * import { Cache, CacheStorage } from '@exact/runtime/cache';
 *
 * const caches = new CacheStorage();
 * const cache = await caches.open('my-cache');
 *
 * await cache.put(
 *   new Request('https://api.example.com/data'),
 *   new Response('{"cached": true}')
 * );
 *
 * const response = await cache.match('https://api.example.com/data');
 * const data = await response?.json();
 * ```
 */

export { Cache, type CacheQueryOptions } from './Cache';
export { CacheStorage } from './CacheStorage';
