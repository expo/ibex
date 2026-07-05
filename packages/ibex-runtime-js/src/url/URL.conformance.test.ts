// ENG-22973 — WHATWG URL conformance regressions:
//  1. URL.search / URL.href replaced the URLSearchParams instance instead of
//     re-filling the single per-URL object, so a previously vended
//     `searchParams` reference could silently rewrite the query.
//  2. The search/hash/pathname setters never percent-encoded, and the port
//     setter stored non-numeric strings verbatim — both making href
//     unparseable on round-trip.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { URL } from './URL.ts';

test('searchParams identity is stable across the search setter', () => {
  const u = new URL('http://x/?a=1');
  const sp = u.searchParams;

  // Same object every time.
  expect(u.searchParams).toBe(sp);

  u.search = '?b=2';
  // The setter must re-fill the SAME instance, not vend a new one.
  expect(u.searchParams).toBe(sp);
  expect(sp.get('b')).toBe('2');
  expect(sp.get('a')).toBe(null);

  // Mutating the (still-live) reference must not resurrect the old query.
  sp.append('c', '3');
  expect(u.search).toBe('?b=2&c=3');
});

test('searchParams identity is stable across the href setter', () => {
  const u = new URL('http://x/?a=1');
  const sp = u.searchParams;
  u.href = 'http://y/?z=9';
  expect(u.searchParams).toBe(sp);
  expect(sp.get('z')).toBe('9');
  expect(sp.get('a')).toBe(null);
});

test('search setter percent-encodes with the query set (# does not become a fragment)', () => {
  const u = new URL('http://x/');
  u.search = 'a#b';
  expect(u.search).toBe('?a%23b');
  expect(u.hash).toBe('');
  // href must round-trip without the query leaking into the fragment.
  const round = new URL(u.href);
  expect(round.search).toBe('?a%23b');
  expect(round.hash).toBe('');
});

test('search setter encodes spaces and quotes', () => {
  const u = new URL('http://x/');
  u.search = 'q=a b"c<d>e';
  expect(u.search).toBe('?q=a%20b%22c%3Cd%3Ee');
  expect(() => new URL(u.href)).not.toThrow();
});

test('hash setter percent-encodes with the fragment set', () => {
  const u = new URL('http://x/');
  u.hash = 'a b"c<';
  expect(u.hash).toBe('#a%20b%22c%3C');
  expect(new URL(u.href).hash).toBe('#a%20b%22c%3C');
});

test('pathname setter percent-encodes control/space characters', () => {
  const u = new URL('http://x/');
  u.pathname = '/a b?c';
  // space and ? are in the path set.
  expect(u.pathname).toBe('/a%20b%3Fc');
  const round = new URL(u.href);
  expect(round.pathname).toBe('/a%20b%3Fc');
  expect(round.search).toBe('');
});

test('port setter rejects non-numeric values and keeps href parseable', () => {
  const u = new URL('http://x:8080/');
  u.port = 'abc';
  // Non-numeric: no-op, previous port retained.
  expect(u.port).toBe('8080');

  u.port = '9090';
  expect(u.port).toBe('9090');
  expect(new URL(u.href).port).toBe('9090');

  // Leading digits are consumed; a value overflowing 2^16-1 is ignored.
  u.port = '99999';
  expect(u.port).toBe('9090');

  // Default port for the scheme normalizes to empty.
  u.port = '80';
  expect(u.port).toBe('');
});

test('setting an empty search/hash clears them', () => {
  const u = new URL('http://x/?a=1#f');
  u.search = '';
  expect(u.search).toBe('');
  expect(u.searchParams.size).toBe(0);
  u.hash = '';
  expect(u.hash).toBe('');
});
