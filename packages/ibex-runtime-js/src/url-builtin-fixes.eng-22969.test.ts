// ENG-22969 — regression coverage for three WHATWG-divergence bugs in
// src/builtins/url.js. Node's own URL / url module is used as the oracle.
//
// url.js has two code paths: a "host" path that delegates to a spec-compliant
// native URL (used when globalThis.URL passes a compliance probe) and a
// "fallback" path with a hand-written URL parser (used when it does not, e.g.
// on a bare Hermes runtime). Findings #1 and #2 live in the fallback parser;
// finding #3 lives in the host path. We load the module in isolated vm
// sandboxes so we can drive BOTH paths from one Bun/Node process without
// mutating this process's real global URL.

import { expect, test, describe } from 'bun:test';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';

const SRC = fs.readFileSync(
  path.join(import.meta.dir, '../../../src/builtins/url.js'),
  'utf8',
);

function baseSandbox(): any {
  const sandbox: any = {
    module: { exports: {} },
    console,
    process,
    TextEncoder,
    TextDecoder,
    Buffer,
  };
  sandbox.globalThis = sandbox;
  return sandbox;
}

// Load the module with a spec-compliant native URL available -> host path.
// A subclass of the real URL keeps the module's prototype patching off of this
// process's global URL.
function loadHost(): any {
  const sandbox = baseSandbox();
  sandbox.URL = class extends URL {};
  sandbox.URLSearchParams = URLSearchParams;
  if (typeof DOMException === 'function') sandbox.DOMException = DOMException;
  vm.runInContext(SRC, vm.createContext(sandbox), { filename: 'url.js' });
  return sandbox.module.exports;
}

// Load the module with no URL / URLSearchParams globals -> fallback path.
function loadFallback(): any {
  const sandbox = baseSandbox();
  vm.runInContext(SRC, vm.createContext(sandbox), { filename: 'url.js' });
  return sandbox.module.exports;
}

const host = loadHost();
const fallback = loadFallback();
const FbURL = fallback.URL;

test('module paths resolve as expected (fallback uses the hand-written parser)', () => {
  expect(host.URL === URL).toBe(false); // subclass, not the raw global
  expect(FbURL === URL).toBe(false);
  expect(new FbURL('http://a/').href).toBe('http://a/');
});

// ---------------------------------------------------------------------------
// Finding #1 — href setter must not leak stale authority/credentials.
// ---------------------------------------------------------------------------
describe('#1 href setter resets authority (fallback URL)', () => {
  test('assigning a credential-less href drops the previous user:pass and host', () => {
    const u = new FbURL('http://user:pass@example.com:8080/');
    u.href = 'http://other.com/';

    // Oracle: real URL.
    const oracle = new URL('http://user:pass@example.com:8080/');
    oracle.href = 'http://other.com/';

    expect(u.href).toBe('http://other.com/');
    expect(u.href).toBe(oracle.href);
    expect(u.username).toBe('');
    expect(u.password).toBe('');
    expect(u.port).toBe('');
  });

  test('assigning an href WITH new credentials still applies them', () => {
    const u = new FbURL('http://user:pass@example.com/');
    u.href = 'http://neo:matrix@host.example/path';
    expect(u.href).toBe('http://neo:matrix@host.example/path');
    expect(u.username).toBe('neo');
    expect(u.password).toBe('matrix');
    expect(u.hostname).toBe('host.example');
  });

  test('re-parsing to an authority-less scheme clears the old host', () => {
    const u = new FbURL('http://user:pass@example.com/');
    u.href = 'mailto:someone@elsewhere.test';
    const oracle = new URL('http://user:pass@example.com/');
    oracle.href = 'mailto:someone@elsewhere.test';
    expect(u.href).toBe(oracle.href);
    expect(u.username).toBe('');
    expect(u.hostname).toBe('');
  });
});

// ---------------------------------------------------------------------------
// Finding #2 — scheme-only special URL with a base: compare against the base
// scheme, not a hardcoded "http:".
// ---------------------------------------------------------------------------
describe('#2 scheme-only special URL + base (fallback URL)', () => {
  const cases: Array<[string, string]> = [
    ['https:foo', 'https://example.com/dir/'], // equal schemes -> relative
    ['http:foo', 'https://example.com/dir/'], //  differing schemes -> authority
    ['http:foo', 'http://example.com/dir/'], //   equal schemes -> relative
    ['ftp:bar', 'ftp://example.com/dir/'], //     equal (non-http) -> relative
    ['ws:baz', 'http://example.com/dir/'], //     differing -> authority
    ['https://x/y', 'https://example.com/'], //   explicit // -> authority
  ];
  for (const [input, base] of cases) {
    test(`new URL(${JSON.stringify(input)}, ${JSON.stringify(base)})`, () => {
      const oracle = new URL(input, base).href;
      expect(new FbURL(input, base).href).toBe(oracle);
    });
  }

  test('explicit ticket expectations', () => {
    expect(new FbURL('https:foo', 'https://example.com/dir/').href).toBe(
      'https://example.com/dir/foo',
    );
    expect(new FbURL('http:foo', 'https://example.com/dir/').href).toBe(
      'http://foo/',
    );
  });
});

// ---------------------------------------------------------------------------
// Finding #3 — pathToFileURL must percent-ENCODE (never decode); fileURLToPath
// must reject non-file: URL strings.
// ---------------------------------------------------------------------------
describe('#3 pathToFileURL encodes / fileURLToPath rejects non-file (host path)', () => {
  test('percent signs are encoded, not decoded', () => {
    expect(host.pathToFileURL('/tmp/a%2Fb').href).toBe('file:///tmp/a%252Fb');
  });

  test('a bare percent no longer throws URIError', () => {
    expect(host.pathToFileURL('/tmp/100%.txt').href).toBe(
      'file:///tmp/100%25.txt',
    );
  });

  test('"?" and "#" in a filename are encoded, not treated as query/fragment', () => {
    const u = host.pathToFileURL('/tmp/a?b#c');
    expect(u.href).toBe('file:///tmp/a%3Fb%23c');
    expect(u.search).toBe('');
    expect(u.hash).toBe('');
  });

  test('spaces are encoded and ordinary paths round-trip', () => {
    expect(host.pathToFileURL('/tmp/a b').href).toBe('file:///tmp/a%20b');
    expect(host.pathToFileURL('/tmp/foo').href).toBe('file:///tmp/foo');
  });

  test('pathToFileURL -> fileURLToPath round-trips the literal path', () => {
    for (const p of ['/tmp/a%2Fb', '/tmp/100%.txt', '/tmp/a b', '/tmp/ünïcöde']) {
      expect(host.fileURLToPath(host.pathToFileURL(p))).toBe(p);
    }
  });

  test('fileURLToPath throws on a non-file: URL string (was returned verbatim)', () => {
    for (const s of [
      'ftp://host/path',
      'http://host/path',
      'https://host/path',
      'ws://host/path',
      'mailto:someone@host',
    ]) {
      let threw: any = null;
      try {
        host.fileURLToPath(s);
      } catch (e) {
        threw = e;
      }
      expect(threw && threw.code).toBe('ERR_INVALID_URL_SCHEME');
    }
  });

  test('plain filesystem path strings are still returned as-is', () => {
    expect(host.fileURLToPath('/plain/abs/path')).toBe('/plain/abs/path');
    expect(host.fileURLToPath('relative/path')).toBe('relative/path');
    expect(host.fileURLToPath('C:\\Users\\me')).toBe('C:\\Users\\me');
  });

  test('a genuine file: URL still yields its path', () => {
    expect(host.fileURLToPath('file:///tmp/foo')).toBe('/tmp/foo');
  });
});
