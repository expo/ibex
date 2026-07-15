// ENG-22966 — regression coverage for three correctness bugs in the
// `src/builtins/crypto.js` runtime builtin, all of which silently produced
// wrong crypto results rather than erroring:
//
//   1. timingSafeEqual returned true for ANY equal-length DataViews/
//      ArrayBuffers (undefined !== undefined is false, loop never runs) and for
//      any equal-length strings ('a' ^ 'x' is NaN ^ NaN === 0).
//   2. Hash/Hmac.update dropped DataView chunks (no .length), hashed multi-byte
//      TypedArrays by element value instead of raw bytes, and the native
//      __exactHmacSync UTF-8-re-encoded binary keys/data (bytes >= 0x80 -> two
//      bytes) so MACs over binary input matched no other runtime.
//   3. randomFillSync wrote random bytes into element indices of multi-byte
//      TypedArrays, discarding most of the entropy (Uint32Array collapsed from
//      2^32 to 256 per element) instead of filling the underlying byte buffer.
//
// The builtin talks to native host functions (__exactHashRaw/__exactHashSync/
// __exactRandomBytes). Here we stub those with Node's own crypto as the byte
// primitive, then check the builtin against Node's crypto as an independent
// oracle. Run with: bun test.

import { afterAll, expect, test, describe } from 'bun:test';
import { createRequire } from 'module';
import * as nodeCrypto from 'node:crypto';

// --- Install native host-function stubs BEFORE requiring the builtin. ---
const g = globalThis as Record<string, any>;

function normAlgoToNode(algo: string): string {
  const map: Record<string, string> = {
    md5: 'md5', sha1: 'sha1', sha224: 'sha224', sha256: 'sha256',
    sha384: 'sha384', sha512: 'sha512',
    sha3224: 'sha3-224', sha3256: 'sha3-256', sha3384: 'sha3-384', sha3512: 'sha3-512',
  };
  return map[algo] || algo;
}

function toBuf(data: any): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (data instanceof ArrayBuffer) return Buffer.from(new Uint8Array(data));
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  return Buffer.from(data);
}

// Raw-byte hash primitive (matches native extractBytes semantics: raw bytes).
g.__exactHashRaw = (algo: string, data: any) =>
  Uint8Array.from(nodeCrypto.createHash(normAlgoToNode(algo)).update(toBuf(data)).digest());
g.__exactHashSync = (algo: string, data: any) =>
  nodeCrypto.createHash(normAlgoToNode(algo)).update(toBuf(data)).digest('hex');

// Deterministic RNG stub so randomFillSync placement is exactly assertable:
// byte i = (i + 1) & 0xff  ->  [1, 2, 3, ...].
g.__exactRandomBytes = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i + 1) & 0xff;
  return out;
};

const require = createRequire(import.meta.url);
const crypto = require('../../../src/builtins/crypto.js');

describe('RSA-OAEP native bridge ABI', () => {
  const originalEncrypt = g.__exactRsaOaepEncrypt;
  const originalDecrypt = g.__exactRsaOaepDecrypt;
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  g.__exactRsaOaepEncrypt = (
    key: string,
    hash: string,
    label: Uint8Array,
    plaintext: Uint8Array,
  ) => {
    expect(hash).toBe('SHA-1');
    expect(Array.from(label)).toEqual([]);
    return nodeCrypto.publicEncrypt(
      { key, oaepHash: 'sha1', oaepLabel: Buffer.from(label) },
      Buffer.from(plaintext),
    );
  };
  g.__exactRsaOaepDecrypt = (
    key: string,
    hash: string,
    label: Uint8Array,
    ciphertext: Uint8Array,
  ) => {
    expect(hash).toBe('SHA-1');
    expect(Array.from(label)).toEqual([]);
    return nodeCrypto.privateDecrypt(
      { key, oaepHash: 'sha1', oaepLabel: Buffer.from(label) },
      Buffer.from(ciphertext),
    );
  };

  test('publicEncrypt/privateDecrypt pass the complete four-argument ABI', () => {
    const plaintext = Buffer.from('ibex-output-shape');
    const ciphertext = crypto.publicEncrypt(publicKey, plaintext);
    expect(Buffer.from(crypto.privateDecrypt(privateKey, ciphertext))).toEqual(
      plaintext,
    );
  });

  afterAll(() => {
    if (originalEncrypt === undefined) delete g.__exactRsaOaepEncrypt;
    else g.__exactRsaOaepEncrypt = originalEncrypt;
    if (originalDecrypt === undefined) delete g.__exactRsaOaepDecrypt;
    else g.__exactRsaOaepDecrypt = originalDecrypt;
  });
});

describe('timingSafeEqual (ENG-22966 #1)', () => {
  test('equal Buffers compare equal, unequal do not', () => {
    const a = Buffer.from([0, 1, 2, 3, 4]);
    expect(crypto.timingSafeEqual(a, Buffer.from([0, 1, 2, 3, 4]))).toBe(true);
    expect(crypto.timingSafeEqual(a, Buffer.from([0, 1, 2, 3, 9]))).toBe(false);
  });

  test('equal-length DataViews with different contents compare UNEQUAL (was: always true)', () => {
    const dv1 = new DataView(Uint8Array.from([1, 2, 3, 4]).buffer);
    const dv2 = new DataView(Uint8Array.from([1, 2, 3, 9]).buffer);
    expect(crypto.timingSafeEqual(dv1, dv2)).toBe(false);
    const dv3 = new DataView(Uint8Array.from([1, 2, 3, 4]).buffer);
    expect(crypto.timingSafeEqual(dv1, dv3)).toBe(true);
  });

  test('different byteLength throws RangeError (was: returned true for DataViews)', () => {
    const dv1 = new DataView(new ArrayBuffer(4));
    const dv2 = new DataView(new ArrayBuffer(8));
    expect(() => crypto.timingSafeEqual(dv1, dv2)).toThrow(RangeError);
  });

  test('ArrayBuffer args are compared by content, not always-equal', () => {
    const ab1 = Uint8Array.from([9, 9, 9, 9]).buffer;
    const ab2 = Uint8Array.from([9, 9, 9, 0]).buffer;
    expect(crypto.timingSafeEqual(ab1, ab2)).toBe(false);
  });

  test('string arguments throw ERR_INVALID_ARG_TYPE (Node rejects strings)', () => {
    let err: any;
    try { crypto.timingSafeEqual('abc', 'abc'); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(TypeError);
    expect(err.code).toBe('ERR_INVALID_ARG_TYPE');
  });

  test('cross-type views of identical bytes compare equal', () => {
    const bytes = [0xde, 0xad, 0xbe, 0xef];
    expect(crypto.timingSafeEqual(Buffer.from(bytes), Uint8Array.from(bytes))).toBe(true);
  });
});

describe('Hash.update binary handling (ENG-22966 #2)', () => {
  const highBytes = Uint8Array.from([0x00, 0x80, 0xff, 0x41, 0x90, 0x7f, 0xc3, 0xa9]);
  const oracleHex = (bytes: Uint8Array, algo = 'sha256') =>
    nodeCrypto.createHash(algo).update(Buffer.from(bytes)).digest('hex');

  test('DataView chunk is hashed (was: silently dropped -> empty-input hash)', () => {
    const dv = new DataView(highBytes.buffer, highBytes.byteOffset, highBytes.byteLength);
    const got = crypto.createHash('sha256').update(dv).digest('hex');
    expect(got).toBe(oracleHex(highBytes));
    // And crucially NOT the hash of empty input.
    const emptyHash = nodeCrypto.createHash('sha256').digest('hex');
    expect(got).not.toBe(emptyHash);
  });

  test('multi-byte TypedArray is hashed by raw bytes, not element values', () => {
    const u32 = new Uint32Array([0x01020304, 0xffeeddcc, 0x00000090]);
    const asBytes = new Uint8Array(u32.buffer, u32.byteOffset, u32.byteLength);
    const got = crypto.createHash('sha256').update(u32).digest('hex');
    expect(got).toBe(oracleHex(asBytes));
  });

  test('Buffer with high bytes still hashes correctly (no regression)', () => {
    const buf = Buffer.from(highBytes);
    expect(crypto.createHash('sha512').update(buf).digest('hex'))
      .toBe(oracleHex(highBytes, 'sha512'));
  });

  test('digest() buffer output matches oracle', () => {
    const out = crypto.createHash('sha256').update(Buffer.from(highBytes)).digest();
    expect(Buffer.isBuffer(out) || out instanceof Uint8Array).toBe(true);
    expect(Buffer.from(out).toString('hex')).toBe(oracleHex(highBytes));
  });
});

describe('Hmac binary handling (ENG-22966 #2)', () => {
  const key = Uint8Array.from([0x80, 0xff, 0x00, 0x41, 0x90, 0xc3, 0xa9, 0x01]);
  const data = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x80, 0x7f, 0xff, 0x10]);

  const oracle = (algo: string, k: Buffer | Uint8Array | string, d: Buffer | Uint8Array) =>
    nodeCrypto.createHmac(algo, k as any).update(Buffer.from(d)).digest('hex');

  for (const algo of ['sha256', 'sha1', 'sha512', 'sha384', 'md5']) {
    test(`${algo}: binary key + binary data matches Node (was: UTF-8-mangled)`, () => {
      const got = crypto.createHmac(algo, Buffer.from(key)).update(Buffer.from(data)).digest('hex');
      expect(got).toBe(oracle(algo, Buffer.from(key), data));
    });
  }

  test('DataView data is included (was: dropped)', () => {
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const got = crypto.createHmac('sha256', Buffer.from(key)).update(dv).digest('hex');
    expect(got).toBe(oracle('sha256', Buffer.from(key), data));
  });

  test('multi-byte TypedArray data hashed by bytes', () => {
    const u16 = new Uint16Array([0x8081, 0xffee, 0x0090]);
    const asBytes = new Uint8Array(u16.buffer, u16.byteOffset, u16.byteLength);
    const got = crypto.createHmac('sha256', Buffer.from(key)).update(u16).digest('hex');
    expect(got).toBe(oracle('sha256', Buffer.from(key), asBytes));
  });

  test('key longer than block size is pre-hashed like Node', () => {
    const longKey = Buffer.alloc(200);
    for (let i = 0; i < longKey.length; i++) longKey[i] = (i * 37 + 5) & 0xff;
    const got = crypto.createHmac('sha256', longKey).update(Buffer.from(data)).digest('hex');
    expect(got).toBe(oracle('sha256', longKey, data));
  });

  test('string key is UTF-8 encoded (Node semantics) incl. non-ASCII', () => {
    const strKey = 'sécrét-kéy-\u{1F510}';
    const got = crypto.createHmac('sha256', strKey).update(Buffer.from(data)).digest('hex');
    expect(got).toBe(oracle('sha256', strKey, data));
  });

  test('string data honors non-default encodings (base64)', () => {
    const b64 = Buffer.from(data).toString('base64');
    const got = crypto.createHmac('sha256', Buffer.from(key)).update(b64, 'base64').digest('hex');
    expect(got).toBe(oracle('sha256', Buffer.from(key), data));
  });

  test('buffer + base64 output encodings match oracle', () => {
    const macBuf = crypto.createHmac('sha256', Buffer.from(key)).update(Buffer.from(data)).digest();
    const oracleBuf = nodeCrypto.createHmac('sha256', Buffer.from(key)).update(Buffer.from(data)).digest();
    expect(Buffer.from(macBuf).equals(oracleBuf)).toBe(true);
    const macB64 = crypto.createHmac('sha256', Buffer.from(key)).update(Buffer.from(data)).digest('base64');
    expect(macB64).toBe(oracleBuf.toString('base64'));
  });
});

describe('randomFillSync byte-buffer fill (ENG-22966 #3)', () => {
  test('multi-byte TypedArray is filled across its whole byte buffer', () => {
    // Stub RNG yields bytes [1,2,3,...]. A Uint32Array(4) has 16 bytes.
    const u32 = new Uint32Array(4);
    crypto.randomFillSync(u32);
    const bytes = new Uint8Array(u32.buffer);
    for (let i = 0; i < 16; i++) expect(bytes[i]).toBe((i + 1) & 0xff);
    // Every element carries full 32-bit entropy (little-endian [1,2,3,4] -> 0x04030201).
    expect(u32[0]).toBe(0x04030201);
    expect(u32[3]).toBe(0x100f0e0d);
    // Regression guard: not collapsed to 0..255 per element, and no zeroed tail.
    expect(u32.every((v) => v <= 255)).toBe(false);
  });

  test('offset and size confine the fill to the requested byte range', () => {
    const u8 = new Uint8Array(10); // all zero
    crypto.randomFillSync(u8, 2, 3); // fill bytes [2,5) with [1,2,3]
    expect(Array.from(u8)).toEqual([0, 0, 1, 2, 3, 0, 0, 0, 0, 0]);
  });

  test('DataView fill writes underlying bytes', () => {
    const dv = new DataView(new ArrayBuffer(4));
    crypto.randomFillSync(dv);
    const bytes = new Uint8Array(dv.buffer);
    expect(Array.from(bytes)).toEqual([1, 2, 3, 4]);
  });

  test('Buffer fill unaffected (no regression)', () => {
    const buf = Buffer.alloc(5);
    crypto.randomFillSync(buf);
    expect(Array.from(buf)).toEqual([1, 2, 3, 4, 5]);
  });
});

// ENG-23017 — crypto.sign/verify must hand the native __exactSignSync/
// __exactVerifySync bridge the RAW message bytes. The bridge takes a Uint8Array
// byte-for-byte but UTF-8-re-encodes a string arg, so passing a Latin-1 byte
// string (the old code) expanded every message byte >= 0x80 and produced
// signatures external verifiers reject. Stub the bridge with Node's crypto using
// the same extractBytes semantics (Uint8Array/Buffer -> raw bytes, string ->
// UTF-8); had crypto.js passed a string, toBuf would UTF-8-expand it and the
// signature would not match Node's over the raw bytes.
describe('sign/verify pass raw message bytes (ENG-23017)', () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  g.__exactSignSync = (hash: string, data: any, keyPem: string) =>
    Uint8Array.from(nodeCrypto.sign(normAlgoToNode(hash), toBuf(data), keyPem));
  g.__exactVerifySync = (hash: string, sig: any, data: any, keyPem: string) =>
    nodeCrypto.verify(normAlgoToNode(hash), toBuf(data), keyPem, toBuf(sig));

  // A message with bytes on both sides of 0x80 — the ones that UTF-8 expansion
  // would corrupt.
  const highByteMsg = Buffer.from([0x00, 0x41, 0x7f, 0x80, 0x81, 0xc3, 0xa9, 0xfe, 0xff]);

  test('crypto.sign over a high-byte Buffer verifies against Node', () => {
    const sig = crypto.sign('sha256', highByteMsg, privateKey);
    // Node verifies the signature over the SAME raw bytes -> byte-accurate.
    expect(nodeCrypto.verify('sha256', highByteMsg, publicKey, toBuf(sig))).toBe(true);
    // The builtin's own verify agrees.
    expect(crypto.verify('sha256', highByteMsg, publicKey, sig)).toBe(true);
    // A flipped message byte must fail.
    const tampered = Buffer.from(highByteMsg);
    tampered[3] ^= 0xff;
    expect(nodeCrypto.verify('sha256', tampered, publicKey, toBuf(sig))).toBe(false);
  });

  test('createSign/createVerify streaming over high bytes matches Node', () => {
    const sig = crypto.createSign('sha256').update(highByteMsg).sign(privateKey);
    expect(nodeCrypto.verify('sha256', highByteMsg, publicKey, toBuf(sig))).toBe(true);
    expect(crypto.createVerify('sha256').update(highByteMsg).verify(publicKey, sig)).toBe(true);
  });
});
