// ENG-22973 — Cache.put() evicted every entry sharing the request URL before
// inserting, ignoring the Vary header. Per "Batch Cache Operations" the put
// step replaces only entries that the new request matches via Query Cache,
// which honors each stored response's Vary. Storing a French variant must not
// evict a cached English one keyed by `Vary: Accept-Language`.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { Cache } from './Cache.ts';
import { Request } from '../fetch/Request.ts';
import { Response } from '../fetch/Response.ts';

const URL = 'http://example.com/greeting';

function variant(lang: string): Request {
  return new Request(URL, { headers: { 'Accept-Language': lang } });
}

function response(body: string): Response {
  return new Response(body, { headers: { Vary: 'Accept-Language' } });
}

test('put keeps distinct Vary variants for the same URL', async () => {
  const cache = new Cache();

  await cache.put(variant('en'), response('Hello'));
  await cache.put(variant('fr'), response('Bonjour'));

  // Both variants coexist.
  const keys = await cache.keys();
  expect(keys.length).toBe(2);

  const en = await cache.match(variant('en'));
  const fr = await cache.match(variant('fr'));
  expect(await en?.text()).toBe('Hello');
  expect(await fr?.text()).toBe('Bonjour');
});

test('put replaces a matching Vary variant', async () => {
  const cache = new Cache();

  await cache.put(variant('en'), response('Hello'));
  await cache.put(variant('en'), response('Hello again'));

  const keys = await cache.keys();
  expect(keys.length).toBe(1);
  const en = await cache.match(variant('en'));
  expect(await en?.text()).toBe('Hello again');
});

test('put still replaces a non-varying entry sharing the URL', async () => {
  const cache = new Cache();

  await cache.put(new Request(URL), new Response('first'));
  await cache.put(new Request(URL), new Response('second'));

  const keys = await cache.keys();
  expect(keys.length).toBe(1);
  const hit = await cache.match(new Request(URL));
  expect(await hit?.text()).toBe('second');
});
