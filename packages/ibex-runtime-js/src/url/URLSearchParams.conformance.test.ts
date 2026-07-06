// ENG-23138 — URLSearchParams WHATWG conformance regressions:
//  1. `_encode` called bare encodeURIComponent, which throws URIError on lone
//     surrogates (spec: USVString-convert to U+FFFD, never throw) and
//     under-encodes ! ' ( ) ~ (spec percent-encodes them; breaks byte-exact
//     query signing). Port of the ENG-23038 fix that had only landed in
//     src/builtins/url.js.
//  2. `_decode` returned its input untouched when decodeURIComponent threw,
//     skipping the plus-to-space conversion ("q=a+b%zz" must still yield
//     "a b%zz") and never applying U+FFFD replacement to invalid UTF-8.
// Expected values verified against Node v25's implementations as a WHATWG
// oracle. Run with: bun test.

import { expect, test } from 'bun:test';
import { URL } from './URL.ts';
import { URLSearchParams } from './URLSearchParams.ts';

test('serializer percent-encodes the exact form-urlencoded set', () => {
  // encodeURIComponent leaves !'()~ alone; the spec serializer does not.
  expect(new URLSearchParams([['a', "!'()~"]]).toString()).toBe('a=%21%27%28%29%7E');
  // ...but * - . _ and alphanumerics pass through, and space becomes "+".
  expect(new URLSearchParams([['a', 'b c*-._']]).toString()).toBe('a=b+c*-._');
});

test('lone surrogates are USVString-replaced, never a URIError', () => {
  const p = new URLSearchParams();
  p.append('q', '\uD800');
  expect(p.toString()).toBe('q=%EF%BF%BD');
  // The stored value is already U+FFFD (WebIDL conversion at the boundary).
  expect(p.get('q')).toBe('�');

  // Well-formed pairs are untouched.
  const emoji = new URLSearchParams();
  emoji.append('e', '😀');
  expect(emoji.toString()).toBe('e=%F0%9F%98%80');
});

test('appending a lone surrogate to a URL-attached instance updates href without throwing', () => {
  const u = new URL('http://x/');
  u.searchParams.append('q', '\uD800');
  expect(u.href).toBe('http://x/?q=%EF%BF%BD');
});

test('malformed percent-escapes still get plus-to-space and partial decoding', () => {
  // "+" conversion must happen even when "%zz" makes the decode partial.
  expect(new URLSearchParams('q=a+b%zz').get('q')).toBe('a b%zz');
  // Lone invalid UTF-8 bytes decode to U+FFFD instead of staying "%E4".
  expect(new URLSearchParams('a=%E4').get('a')).toBe('�');
  // A valid sequence followed by a stray continuation byte keeps the valid
  // part (maximal-subpart replacement).
  expect(new URLSearchParams('a=%E4%BD%A0%80').get('a')).toBe('你�');
  // Fully valid input is unaffected.
  expect(new URLSearchParams('a=%E4%BD%A0').get('a')).toBe('你');
  expect(new URLSearchParams('a=%F0%9F%98%80').get('a')).toBe('😀');
});
