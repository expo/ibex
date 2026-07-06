// ENG-23138 — URLPattern conformance regressions:
//  1. The ? / + / * modifiers after :name/(regex)/* groups compiled as
//     literals or extra wildcards, so "/users/:id?" matched nothing and
//     "/files/:path*" failed on "/files" — routing tables copied from MDN
//     silently 404'd.
//  2. Inputs were matched without canonicalization (hostname case, default
//     ports, baseURL resolution), `new URLPattern()` threw, and a relative
//     pattern string with no baseURL silently wildcarded protocol/host.
// Expected values verified against Node v25's native URLPattern as a WHATWG
// oracle. Run with: bun test.

import { expect, test } from 'bun:test';
import { URLPattern } from './URLPattern.ts';

test(':name? makes the group and its "/" prefix optional', () => {
  const p = new URLPattern({ pathname: '/users/:id?' });
  expect(p.test({ pathname: '/users' })).toBe(true);
  expect(p.test({ pathname: '/users/123' })).toBe(true);
  expect(p.test({ pathname: '/users/' })).toBe(false);
  expect(p.test({ pathname: '/users/a/b' })).toBe(false);
  expect(p.exec({ pathname: '/users/123' })!.pathname.groups).toEqual({ id: '123' });
  expect(p.exec({ pathname: '/users' })!.pathname.groups).toEqual({ id: undefined });
});

test(':name* matches zero or more segments, captured with separators', () => {
  const p = new URLPattern({ pathname: '/files/:path*' });
  expect(p.test({ pathname: '/files' })).toBe(true);
  expect(p.test({ pathname: '/files/' })).toBe(false);
  expect(p.test({ pathname: '/files/a/b/c' })).toBe(true);
  expect(p.exec({ pathname: '/files/a/b/c' })!.pathname.groups).toEqual({ path: 'a/b/c' });
});

test(':name+ requires at least one segment', () => {
  const p = new URLPattern({ pathname: '/files/:path+' });
  expect(p.test({ pathname: '/files' })).toBe(false);
  expect(p.test({ pathname: '/files/a' })).toBe(true);
  expect(p.exec({ pathname: '/files/a/b' })!.pathname.groups).toEqual({ path: 'a/b' });
});

test('modifiers compose with custom-regex groups and wildcards', () => {
  const re = new URLPattern({ pathname: '/u/:id(\\d+)?' });
  expect(re.test({ pathname: '/u' })).toBe(true);
  expect(re.test({ pathname: '/u/12' })).toBe(true);
  expect(re.test({ pathname: '/u/ab' })).toBe(false);

  const star = new URLPattern({ pathname: '/a/*?' });
  expect(star.test({ pathname: '/a' })).toBe(true);
  expect(star.test({ pathname: '/a/b/c' })).toBe(true);
});

test('hostname groups do not fold a delimiter prefix', () => {
  const p = new URLPattern({ hostname: ':sub?.example.com' });
  expect(p.test({ hostname: 'example.com' })).toBe(false);
  expect(p.test({ hostname: 'a.example.com' })).toBe(true);
});

test('double modifiers are a pattern syntax error', () => {
  expect(() => new URLPattern({ pathname: '/a/:b??' })).toThrow(TypeError);
  expect(() => new URLPattern({ pathname: '/a/:b*?' })).toThrow(TypeError);
  expect(() => new URLPattern({ pathname: '/a/:b?+' })).toThrow(TypeError);
  // "*" after "?" is a new wildcard part, not a modifier sequence.
  expect(() => new URLPattern({ pathname: '/a/:b?*' })).not.toThrow();
});

test('"?" after a group in a pattern string is a modifier, not the search delimiter', () => {
  const p = new URLPattern('https://x.co/users/:id?');
  expect(p.pathname).toBe('/users/:id?');
  expect(p.search).toBe('*');
  expect(p.test('https://x.co/users')).toBe(true);

  const q = new URLPattern('https://x.co/path?q=1');
  expect(q.pathname).toBe('/path');
  expect(q.search).toBe('q=1');
});

test('inputs are canonicalized: hostname case, default ports, dot segments', () => {
  expect(new URLPattern('https://example.com/*').test('https://EXAMPLE.com/')).toBe(true);
  expect(new URLPattern('https://example.com:443/*').test('https://example.com/x')).toBe(true);
  const r = new URLPattern().exec('HTTP://EX.COM:80/A/../B?Q#F')!;
  expect(r.protocol.input).toBe('http');
  expect(r.hostname.input).toBe('ex.com');
  expect(r.port.input).toBe('');
  expect(r.pathname.input).toBe('/B');
  expect(r.search.input).toBe('Q');
  expect(r.hash.input).toBe('F');
  // Object inputs are canonicalized too.
  expect(new URLPattern({ hostname: 'example.com' }).test({ hostname: 'EXAMPLE.com' })).toBe(true);
  expect(new URLPattern({ port: '' }).test({ protocol: 'https', port: '443' })).toBe(true);
  expect(new URLPattern().exec({ pathname: '/a/./b c' })!.pathname.input).toBe('/a/b%20c');
});

test('pattern components are canonicalized: case, default port, encoding', () => {
  expect(new URLPattern('https://example.com:443/*').port).toBe('');
  expect(new URLPattern({ protocol: 'HTTPS' }).protocol).toBe('https');
  // Literals are lowercased/encoded but group syntax is preserved.
  expect(new URLPattern({ hostname: 'API.:tld' }).hostname).toBe('api.:tld');
  expect(new URLPattern({ pathname: '/a b' }).pathname).toBe('/a%20b');
  expect(new URLPattern({ pathname: '/a b' }).test({ pathname: '/a b' })).toBe(true);
});

test('new URLPattern() is the all-wildcard pattern', () => {
  const p = new URLPattern();
  expect(p.protocol).toBe('*');
  expect(p.hostname).toBe('*');
  expect(p.pathname).toBe('*');
  expect(p.test('https://anything.example/x/y?q#h')).toBe(true);
});

test('a relative pattern string requires a baseURL', () => {
  expect(() => new URLPattern('/api/*')).toThrow(TypeError);
  expect(() => new URLPattern('*')).toThrow(TypeError);
  expect(() => new URLPattern('/api/*', 'https://example.com')).not.toThrow();
});

test('string patterns resolve against baseURL with structural inheritance', () => {
  const p = new URLPattern('/api/*', 'https://example.com');
  expect(p.protocol).toBe('https');
  expect(p.hostname).toBe('example.com');
  expect(p.pathname).toBe('/api/*');
  // Components more specific than the given pathname do NOT inherit.
  expect(p.search).toBe('*');
  expect(p.hash).toBe('*');
  expect(p.test('https://example.com/api/v1')).toBe(true);
  expect(p.test('https://other.com/api/v1')).toBe(false);

  // Relative pathnames resolve against the base directory.
  expect(new URLPattern('api/:v', 'https://h.co/base/dir/page').pathname).toBe('/base/dir/api/:v');

  // An init object's baseURL follows the same inheritance rule.
  const init = new URLPattern({ pathname: '/a', baseURL: 'https://u:p@example.com:8443/zz?q=1#h' });
  expect(init.protocol).toBe('https');
  expect(init.hostname).toBe('example.com');
  expect(init.port).toBe('8443');
  expect(init.username).toBe('*'); // username/password never inherit
  expect(init.search).toBe('*');
  expect(init.hash).toBe('*');
});

test('string inputs resolve against the baseURL argument', () => {
  const p = new URLPattern({ pathname: '/api/:v' });
  expect(p.test('/api/v1', 'https://x.com')).toBe(true);
  expect(p.test('../api/v1', 'https://x.com/a/b/')).toBe(false); // resolves to /a/api/v1
  // A relative string input with no base still matches pathname patterns.
  expect(p.test('/api/v1')).toBe(true);
});
