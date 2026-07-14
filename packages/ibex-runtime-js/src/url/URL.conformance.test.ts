// ENG-22973 — WHATWG URL conformance regressions:
//  1. URL.search / URL.href replaced the URLSearchParams instance instead of
//     re-filling the single per-URL object, so a previously vended
//     `searchParams` reference could silently rewrite the query.
//  2. The search/hash/pathname setters never percent-encoded, and the port
//     setter stored non-numeric strings verbatim — both making href
//     unparseable on round-trip.
// ENG-23138 — href serializer and fallback parser:
//  3. The href serializer emitted "//" only for non-empty hostnames; WHATWG
//     file: URLs have an EMPTY (non-null) host, so "file:///tmp/x" degraded
//     to "file:/tmp/x" and "file:////share/x" corrupted into "file://share/x"
//     (which re-parses with host "share"). Null-host paths starting "//"
//     also need the "/." guard.
//  4. The fallback parser (locked-down compartments, exercised via
//     _parseBasicUrl) rejected "file:///x", kept host case, parsed
//     "http:\\x" as an opaque path, collapsed empty path segments, and never
//     percent-encoded.
// Expected values verified against Node v25 as a WHATWG oracle.
// Run with: bun test.

import { expect, test } from 'bun:test';
import { URL, _parseBasicUrl } from './URL.ts';

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

// ---------------------------------------------------------------------------
// ENG-23138 §3 — href keeps "//" for empty-string hosts
// ---------------------------------------------------------------------------

test('file: hrefs keep the empty-host authority prefix', () => {
  expect(new URL('file:///tmp/x').href).toBe('file:///tmp/x');
  expect(new URL('file:///tmp/x').toString()).toBe('file:///tmp/x');
});

test('file: UNC-style paths round-trip without gaining a host', () => {
  const u = new URL('file:////share/x');
  expect(u.href).toBe('file:////share/x');
  const round = new URL(u.href);
  expect(round.hostname).toBe('');
  expect(round.pathname).toBe('//share/x');
  expect(round.href).toBe('file:////share/x');
});

test('null-host URLs serialize without "//", with the "/." guard when needed', () => {
  expect(new URL('mailto:x@y.com').href).toBe('mailto:x@y.com');
  // A host-less path starting "//" must not re-parse as an authority.
  const u = new URL('web+demo:/.//not-a-host/x');
  expect(u.pathname).toBe('//not-a-host/x');
  expect(u.href).toBe('web+demo:/.//not-a-host/x');
  expect(new URL(u.href).pathname).toBe('//not-a-host/x');
});

test('password-only credentials serialize into href', () => {
  expect(new URL('http://:pw@h/').href).toBe('http://:pw@h/');
});

test('setting a host on a previously host-less special URL emits "//"', () => {
  const u = new URL('file:///a');
  u.hostname = 'h';
  expect(u.href).toBe('file://h/a');
});

test('WebSocket special URLs retain their authority and explicit port', () => {
  const href = 'ws://127.0.0.1:50139/';
  const u = new URL(href);
  expect(u.href).toBe(href);
  expect(u.hostname).toBe('127.0.0.1');
  expect(u.port).toBe('50139');
});

// ---------------------------------------------------------------------------
// ENG-23138 §4 — fallback parser (compartments without a host URL parser).
// The public URL class delegates to the host implementation when one exists
// (as under bun), so these exercise _parseBasicUrl directly.
// ---------------------------------------------------------------------------

function fallbackHref(input: string): string {
  const p = _parseBasicUrl(input, null);
  if (!p) return 'PARSE-FAIL';
  let out = p.protocol;
  if (p.hostPresent) {
    out += '//';
    if (p.username || p.password) {
      out += p.username;
      if (p.password) out += ':' + p.password;
      out += '@';
    }
    out += p.hostname;
    if (p.port) out += ':' + p.port;
  } else if (p.pathname.startsWith('//')) {
    out += '/.';
  }
  return out + p.pathname + p.search + p.hash;
}

test('fallback: file: URLs parse with an empty host', () => {
  expect(fallbackHref('file:///tmp/x')).toBe('file:///tmp/x');
  expect(fallbackHref('file:/tmp/x')).toBe('file:///tmp/x');
  expect(fallbackHref('file:')).toBe('file:///');
  expect(fallbackHref('file://localhost/x')).toBe('file:///x');
  expect(fallbackHref('file:////share/x')).toBe('file:////share/x');
});

test('fallback: WebSocket special URLs retain their authority', () => {
  expect(fallbackHref('ws://127.0.0.1:50139/')).toBe(
    'ws://127.0.0.1:50139/',
  );
});

test('fallback: special hosts are lowercased', () => {
  expect(fallbackHref('http://EXAMPLE.com')).toBe('http://example.com/');
  expect(fallbackHref('http://user:pass@HOST.com:8080/p')).toBe(
    'http://user:pass@host.com:8080/p',
  );
});

test('fallback: backslashes are slashes for special schemes', () => {
  expect(fallbackHref('http:\\\\example.com\\path')).toBe('http://example.com/path');
});

test('fallback: empty path segments are preserved, dot segments resolved', () => {
  expect(fallbackHref('http://x/a//b')).toBe('http://x/a//b');
  expect(fallbackHref('http://x/a/./b')).toBe('http://x/a/b');
  expect(fallbackHref('http://x/a/b/..')).toBe('http://x/a/');
  expect(fallbackHref('http://x/%2e%2E/a')).toBe('http://x/a');
});

test('fallback: path/query/fragment are percent-encoded on parse', () => {
  expect(fallbackHref('http://x/a b?q=a b#f g')).toBe('http://x/a%20b?q=a%20b#f%20g');
});

test('fallback: default ports are stripped, invalid authorities rejected', () => {
  expect(fallbackHref('http://h:80/x')).toBe('http://h/x');
  expect(fallbackHref('https://h:8443/x')).toBe('https://h:8443/x');
  expect(_parseBasicUrl('http:', null)).toBe(null);
  expect(_parseBasicUrl('http://', null)).toBe(null);
});

test('fallback: non-special schemes keep null-vs-empty host distinction', () => {
  expect(fallbackHref('foo://')).toBe('foo://');
  expect(fallbackHref('foo:///x')).toBe('foo:///x');
  expect(fallbackHref('mailto:x@y.com')).toBe('mailto:x@y.com');
  expect(fallbackHref('web+demo:/.//not-a-host/x')).toBe('web+demo:/.//not-a-host/x');
});
