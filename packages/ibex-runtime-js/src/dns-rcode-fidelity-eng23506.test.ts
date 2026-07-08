// ENG-23506 — DNS resolver error-code fidelity. The native resolver now
// preserves resolver rcodes (SERVFAIL/REFUSED/...) and timeout/connrefused
// detail as a Node-style `.code` on the rejected error (also echoed as a token
// in the message), and dns.js maps that through instead of flattening every
// failure to ENOTFOUND. Two layers are covered here without any public-network
// dependency:
//
//  1. Stubbed `__exactDns*Async` natives: the JS mapping layer (code property
//     preferred, message-token fallback, unknown-cause flattening preserved).
//  2. A real loopback mock DNS server driven through the custom-server
//     resolver path (dns.setServers / new dns.Resolver), which must map raw
//     response rcodes to ESERVFAIL/EREFUSED/ENOTFOUND/ENODATA and timeouts to
//     ETIMEOUT.
//
// The default-native-path equivalent (real ibex binary + IBEX_DNS_SERVER
// override) is covered by tests/native_dns_rcode.rs. Expected codes/messages
// oracle-checked against Node v25 (queryTxt ESERVFAIL example.com, etc.).
// Run with: bun test.

import { expect, test, describe, beforeEach, afterEach } from 'bun:test';
import { createRequire } from 'module';
import * as dgram from 'dgram';

const g = globalThis as Record<string, any>;
const require = createRequire(import.meta.url);

const dnsPath = require.resolve('../../../src/builtins/dns.js');
const dnsGlobals = [
  '__exactDnsLookup', '__exactDnsLookupAsync',
  '__exactDnsResolve', '__exactDnsResolveAsync',
  '__exactDnsReverse', '__exactDnsReverseAsync',
];

// dns.js captures `typeof __exactDns*` into module-level flags at load time,
// so each test installs its stubs first, then loads a fresh module instance.
function loadFreshDns() {
  delete (require as any).cache[dnsPath];
  return require('../../../src/builtins/dns.js');
}

function clearDnsGlobals() {
  for (const k of dnsGlobals) delete g[k];
}

describe('dns error-code fidelity via native detail (ENG-23506)', () => {
  beforeEach(() => clearDnsGlobals());
  afterEach(() => {
    clearDnsGlobals();
    delete (require as any).cache[dnsPath];
  });

  test('resolve rejection with a code property surfaces as that code', async () => {
    const cause: any = new Error('DNS query failed for example.com type TXT (ESERVFAIL)');
    cause.code = 'ESERVFAIL';
    g.__exactDnsResolveAsync = () => Promise.reject(cause);
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.resolveTxt('example.com', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ESERVFAIL');
    expect(err.syscall).toBe('queryTXT');
    expect(err.hostname).toBe('example.com');
    expect(err.message).toBe('queryTXT ESERVFAIL example.com');
  });

  test('resolve rejection maps from a message token when no code property crosses', async () => {
    g.__exactDnsResolveAsync = () =>
      Promise.reject(new Error('DNS query failed for example.com type MX (EREFUSED)'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.resolveMx('example.com', (e: any) => resolve(e));
    });
    expect(err.code).toBe('EREFUSED');
    expect(err.syscall).toBe('queryMX');
  });

  test('resolve timeout detail surfaces as ETIMEOUT', async () => {
    const cause: any = new Error('DNS query failed for example.com type SRV (ETIMEOUT)');
    cause.code = 'ETIMEOUT';
    g.__exactDnsResolveAsync = () => Promise.reject(cause);
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.resolveSrv('example.com', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ETIMEOUT');
  });

  test('resolve rejection without recognizable detail still flattens to ENOTFOUND', async () => {
    g.__exactDnsResolveAsync = () => Promise.reject(new Error('resolver exploded'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.resolveTxt('example.com', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ENOTFOUND');
    expect(String(err.message)).toContain('queryTXT');
    expect(String(err.message)).toContain('resolver exploded');
  });

  test('lookup rejection preserves EAI_AGAIN with getaddrinfo syscall', async () => {
    const cause: any = new Error('getaddrinfo failed for example.com: try again (EAI_AGAIN)');
    cause.code = 'EAI_AGAIN';
    g.__exactDnsLookupAsync = () => Promise.reject(cause);
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.lookup('example.com', (e: any) => resolve(e));
    });
    expect(err.code).toBe('EAI_AGAIN');
    expect(err.syscall).toBe('getaddrinfo');
    expect(err.hostname).toBe('example.com');
    expect(err.message).toBe('getaddrinfo EAI_AGAIN example.com');
  });

  test('lookup rejection without detail keeps the ENOTFOUND shape', async () => {
    g.__exactDnsLookupAsync = () => Promise.reject(new Error('resolver down'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.lookup('nope.invalid', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ENOTFOUND');
    expect(err.hostname).toBe('nope.invalid');
    expect(err.message).toBe('getaddrinfo ENOTFOUND nope.invalid');
  });

  test('reverse rejection preserves native detail with getHostByAddr syscall', async () => {
    g.__exactDnsReverseAsync = () =>
      Promise.reject(new Error('getnameinfo failed for 192.0.2.1: try again (ETIMEOUT)'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.reverse('192.0.2.1', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ETIMEOUT');
    expect(err.syscall).toBe('getHostByAddr');
  });

  test('reverse rejection without detail still flattens to ENOTFOUND', async () => {
    g.__exactDnsReverseAsync = () => Promise.reject(new Error('no ptr anywhere'));
    const dns = loadFreshDns();
    const err: any = await new Promise((resolve) => {
      dns.reverse('192.0.2.1', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ENOTFOUND');
    expect(String(err.message)).toContain('getHostByAddr');
  });
});

// ---------------------------------------------------------------------------
// Custom-server resolver path against a real loopback mock DNS server. This is
// the ENG-23449 machinery (setServers routing, UDP query encode/decode) — its
// behavior must remain intact — now with rcode-faithful error mapping.
// ---------------------------------------------------------------------------
describe('dns custom-server rcode fidelity via loopback mock server (ENG-23506)', () => {
  type MockMode = 'servfail' | 'refused' | 'nxdomain' | 'empty' | 'timeout' | 'answer';
  let server: ReturnType<typeof dgram.createSocket> | null = null;

  beforeEach(() => clearDnsGlobals());
  afterEach(() => {
    clearDnsGlobals();
    delete (require as any).cache[dnsPath];
    if (server) {
      try { server.close(); } catch (_) {}
      server = null;
    }
  });

  function startMockServer(mode: MockMode): Promise<number> {
    return new Promise((resolve) => {
      const sock = dgram.createSocket('udp4');
      server = sock;
      sock.on('message', (msg, rinfo) => {
        if (mode === 'timeout') return; // never respond
        const rcode = mode === 'servfail' ? 2 : mode === 'refused' ? 5 : mode === 'nxdomain' ? 3 : 0;
        const head = Buffer.from(msg);
        head.writeUInt16BE(0x8180 | rcode, 2); // QR|RD|RA + rcode
        head.writeUInt16BE(mode === 'answer' ? 1 : 0, 6); // ANCOUNT
        let resp = head;
        if (mode === 'answer') {
          const txt = Buffer.from('eng-23506');
          const rr = Buffer.alloc(12 + 1 + txt.length);
          rr.writeUInt16BE(0xc00c, 0); // name: pointer to question
          rr.writeUInt16BE(16, 2); // TXT
          rr.writeUInt16BE(1, 4); // IN
          rr.writeUInt32BE(60, 6); // TTL
          rr.writeUInt16BE(1 + txt.length, 10); // RDLENGTH
          rr.writeUInt8(txt.length, 12);
          txt.copy(rr, 13);
          resp = Buffer.concat([head, rr]);
        }
        sock.send(resp, rinfo.port, rinfo.address);
      });
      sock.bind(0, '127.0.0.1', () => resolve((sock.address() as any).port));
    });
  }

  async function queryViaResolver(mode: MockMode): Promise<{ err: any; records: any }> {
    const port = await startMockServer(mode);
    const dns = loadFreshDns();
    const resolver = new dns.Resolver({ timeout: 300, tries: 1 });
    resolver.setServers(['127.0.0.1:' + port]);
    return new Promise((resolve) => {
      resolver.resolveTxt('rcode.example', (err: any, records: any) => resolve({ err, records }));
    });
  }

  test('SERVFAIL response surfaces as ESERVFAIL', async () => {
    const { err } = await queryViaResolver('servfail');
    expect(err.code).toBe('ESERVFAIL');
    expect(err.syscall).toBe('queryTXT');
    expect(err.hostname).toBe('rcode.example');
  });

  test('REFUSED response surfaces as EREFUSED', async () => {
    const { err } = await queryViaResolver('refused');
    expect(err.code).toBe('EREFUSED');
  });

  test('NXDOMAIN response surfaces as ENOTFOUND', async () => {
    const { err } = await queryViaResolver('nxdomain');
    expect(err.code).toBe('ENOTFOUND');
  });

  test('NOERROR with an empty answer section surfaces as ENODATA', async () => {
    const { err } = await queryViaResolver('empty');
    expect(err.code).toBe('ENODATA');
  });

  test('no response surfaces as ETIMEOUT', async () => {
    const { err } = await queryViaResolver('timeout');
    expect(err.code).toBe('ETIMEOUT');
  });

  test('a real TXT answer still resolves (ENG-23449 behavior intact)', async () => {
    const { err, records } = await queryViaResolver('answer');
    expect(err).toBeNull();
    expect(records).toEqual([['eng-23506']]);
  });

  test('module-level setServers routing still maps rcodes (ENG-23449 behavior intact)', async () => {
    const port = await startMockServer('servfail');
    const dns = loadFreshDns();
    dns.setServers(['127.0.0.1:' + port]);
    const err: any = await new Promise((resolve) => {
      dns.resolveTxt('rcode.example', (e: any) => resolve(e));
    });
    expect(err.code).toBe('ESERVFAIL');
  });
});
