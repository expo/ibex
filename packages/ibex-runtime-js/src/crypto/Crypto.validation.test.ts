// ENG-23455 — WebCrypto validation-layer conformance tests for SubtleCrypto.
//
// Covers the spec-mandated checks that were previously absent:
//   (a) request algorithm must match the key's algorithm (InvalidAccessError)
//   (b) AES-CTR honors AesCtrParams.length (counter wrap + validation)
//   (c) AES-GCM tagLength / non-empty iv validation
//   (d) PBKDF2 iterations and PBKDF2/HKDF deriveBits length validation
//   (e) importKey usage and JWK consistency validation
//   (f) getRandomValues TypeMismatchError for non-integer views
//   (g) KMAC generateKey removed (was generating unusable keys)
// plus the ENG-23455 finding-2 residue: exportKey native errors wrapped as
// DOMException, and ECDH/X25519 deriveBits public-key validation.
//
// Node's WebCrypto (node:crypto webcrypto) is the conformance oracle.
// Run with: bun test.

import { expect, test, beforeAll, afterEach } from "bun:test";
import { webcrypto, createCipheriv } from "node:crypto";
import { SubtleCrypto, Crypto } from "./Crypto.ts";
import {
  Capabilities,
  disableTestMode,
  enableTestMode,
  onCapabilityAudit,
  setNativeCapabilityModule,
} from "../security/Capabilities.ts";
import {
  getNativeCryptoModule,
  setNativeCryptoModule,
} from "../native/NativeModules.ts";

const nodeSubtle = webcrypto.subtle as any;
const ibex = new SubtleCrypto();
const ibexCrypto = new Crypto();

beforeAll(() => {
  (globalThis as any).__EXACT_TEST_MODE__ = true;
  enableTestMode({
    grants: [Capabilities.CRYPTO_SUBTLE, Capabilities.CRYPTO_RANDOM, "*"],
    silent: true,
  });
});

afterEach(() => {
  delete (globalThis as any).__exactAesCtrEncrypt;
  delete (globalThis as any).__exactExportKeySpki;
});

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: ArrayBuffer | Uint8Array) =>
  Array.from(b instanceof Uint8Array ? b : new Uint8Array(b), (x) =>
    x.toString(16).padStart(2, "0")
  ).join("");

async function expectDomError(p: Promise<unknown>, name: string) {
  let err: any = null;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect(err).not.toBeNull();
  expect(err.name).toBe(name);
}

// ---------------------------------------------------------------------------
// (a) algorithm/key match
// ---------------------------------------------------------------------------
test("operations reject when the request algorithm does not match the key (a)", async () => {
  const cbcKey: any = await ibex.importKey("raw", new Uint8Array(16), "AES-CBC", false, [
    "encrypt",
    "decrypt",
  ]);
  await expectDomError(
    ibex.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, cbcKey, enc("x")),
    "InvalidAccessError"
  );
  await expectDomError(
    ibex.decrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, cbcKey, enc("x")),
    "InvalidAccessError"
  );

  // sign({name:'HMAC'}, nonHmacKey) used to HMAC the raw key bytes.
  const ecPair = await nodeSubtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const ecPriv: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", ecPair.privateKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  await expectDomError(ibex.sign({ name: "HMAC" }, ecPriv, enc("x")), "InvalidAccessError");
  await expectDomError(
    ibex.verify({ name: "HMAC" }, ecPriv, new Uint8Array(32), enc("x")),
    "InvalidAccessError"
  );

  // Oracle: Node throws InvalidAccessError for the same mismatch.
  const nodeCbc = await nodeSubtle.importKey("raw", new Uint8Array(16), "AES-CBC", false, [
    "encrypt",
  ]);
  await expectDomError(
    nodeSubtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(12) }, nodeCbc, enc("x")),
    "InvalidAccessError"
  );

  // deriveBits: HKDF request with a PBKDF2 key.
  const pb: any = await ibex.importKey("raw", enc("pw"), "PBKDF2", false, ["deriveBits"]);
  await expectDomError(
    ibex.deriveBits(
      { name: "HKDF", salt: new Uint8Array(8), info: new Uint8Array(0), hash: "SHA-256" },
      pb,
      128
    ),
    "InvalidAccessError"
  );
});

// ---------------------------------------------------------------------------
// (b) AES-CTR length semantics. The native bridge is emulated with
// node:crypto's aes-128-ctr, which increments the full 128-bit block exactly
// like the real OpenSSL bridge; Node WebCrypto is the conformance oracle.
// ---------------------------------------------------------------------------
const CTR_KEY_BYTES = new Uint8Array(16).fill(7);

function installNodeCtrBridge(): { calls: number } {
  const stats = { calls: 0 };
  (globalThis as any).__exactAesCtrEncrypt = (
    key: Uint8Array,
    counter: Uint8Array,
    data: Uint8Array
  ) => {
    stats.calls += 1;
    const cipher = createCipheriv(
      key.length === 16 ? "aes-128-ctr" : key.length === 24 ? "aes-192-ctr" : "aes-256-ctr",
      Buffer.from(key),
      Buffer.from(counter)
    );
    return new Uint8Array(Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]));
  };
  return stats;
}

async function ctrKeys() {
  const ibexKey: any = await ibex.importKey("raw", CTR_KEY_BYTES, "AES-CTR", false, [
    "encrypt",
    "decrypt",
  ]);
  const nodeKey = await nodeSubtle.importKey("raw", CTR_KEY_BYTES, "AES-CTR", false, [
    "encrypt",
    "decrypt",
  ]);
  return { ibexKey, nodeKey };
}

test("AES-CTR honors length across a counter wrap and matches Node (b)", async () => {
  const { ibexKey, nodeKey } = await ctrKeys();
  const data = new Uint8Array(48).fill(0xab);

  for (const [counter, length, bytes] of [
    [new Uint8Array(16).fill(0xff), 32, data], // low 32 bits wrap after block 0
    [new Uint8Array(16).fill(0xff), 128, data], // full-width counter wrap
    [(() => { const c = new Uint8Array(16); c[15] = 0x01; return c; })(), 1, data.slice(0, 32)], // 1-bit counter
    [new Uint8Array(16), 32, data], // no wrap
    [new Uint8Array(16).fill(0x55), 13, data], // partial-byte length, no wrap
  ] as const) {
    const stats = installNodeCtrBridge();
    const ours = new Uint8Array(
      await ibex.encrypt({ name: "AES-CTR", counter, length }, ibexKey, bytes)
    );
    const oracle = new Uint8Array(
      await nodeSubtle.encrypt({ name: "AES-CTR", counter, length }, nodeKey, bytes)
    );
    expect(hex(ours)).toBe(hex(oracle));
    expect(stats.calls).toBeGreaterThan(0);

    // decrypt is the same operation and must round-trip.
    const back = new Uint8Array(
      await ibex.decrypt({ name: "AES-CTR", counter, length }, ibexKey, ours)
    );
    expect(hex(back)).toBe(hex(bytes));
  }
});

test("AES-CTR rejects invalid params like Node (b)", async () => {
  const { ibexKey } = await ctrKeys();
  installNodeCtrBridge();
  const counter = new Uint8Array(16);

  // length is required (TypeError, matching Node's IDL failure).
  await expect(
    ibex.encrypt({ name: "AES-CTR", counter } as any, ibexKey, enc("x"))
  ).rejects.toThrow(TypeError);
  await expectDomError(
    ibex.encrypt({ name: "AES-CTR", counter, length: 0 }, ibexKey, enc("x")),
    "OperationError"
  );
  await expectDomError(
    ibex.encrypt({ name: "AES-CTR", counter, length: 129 }, ibexKey, enc("x")),
    "OperationError"
  );
  await expectDomError(
    ibex.encrypt({ name: "AES-CTR", counter: new Uint8Array(15), length: 64 }, ibexKey, enc("x")),
    "OperationError"
  );

  // More blocks than the counter space: length 1 starting at 1 -> 2-block
  // space, 3 blocks of data must fail (Node: OperationError).
  const one = new Uint8Array(16);
  one[15] = 0x01;
  await expectDomError(
    ibex.encrypt({ name: "AES-CTR", counter: one, length: 1 }, ibexKey, new Uint8Array(48)),
    "OperationError"
  );
  // ...but exactly 2 blocks fits.
  const two = new Uint8Array(
    await ibex.encrypt({ name: "AES-CTR", counter: one, length: 1 }, ibexKey, new Uint8Array(32))
  );
  expect(two.length).toBe(32);
});

// ---------------------------------------------------------------------------
// (c) AES-GCM param validation
// ---------------------------------------------------------------------------
test("AES-GCM rejects invalid tagLength and empty iv (c)", async () => {
  const key: any = await ibex.importKey("raw", new Uint8Array(16), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  await expectDomError(
    ibex.encrypt({ name: "AES-GCM", iv: new Uint8Array(12), tagLength: 100 }, key, enc("x")),
    "OperationError"
  );
  await expectDomError(
    ibex.encrypt({ name: "AES-GCM", iv: new Uint8Array(0) }, key, enc("x")),
    "OperationError"
  );
  await expectDomError(
    ibex.decrypt({ name: "AES-GCM", iv: new Uint8Array(0) }, key, new Uint8Array(16)),
    "OperationError"
  );
});

// ---------------------------------------------------------------------------
// (d) PBKDF2 / HKDF deriveBits validation + oracle equality via JS fallbacks
// ---------------------------------------------------------------------------
test("PBKDF2 deriveBits validates iterations and length like Node (d)", async () => {
  const pb: any = await ibex.importKey("raw", enc("pw"), "PBKDF2", false, ["deriveBits"]);
  const base = { name: "PBKDF2", salt: new Uint8Array(8).fill(3), hash: "SHA-256" };

  await expectDomError(ibex.deriveBits({ ...base, iterations: 0 }, pb, 128), "OperationError");
  await expectDomError(
    ibex.deriveBits({ ...base, iterations: 10 }, pb, null as any),
    "OperationError"
  );
  await expectDomError(ibex.deriveBits({ ...base, iterations: 10 }, pb, 12), "OperationError");
  // length 0 is valid and yields an empty result (Node does the same).
  expect(
    (await ibex.deriveBits({ ...base, iterations: 10 }, pb, 0)).byteLength
  ).toBe(0);

  // Oracle equality on a real derivation (pure-JS fallback vs Node).
  const nodePb = await nodeSubtle.importKey("raw", enc("pw"), "PBKDF2", false, ["deriveBits"]);
  const ours = await ibex.deriveBits({ ...base, iterations: 7 }, pb, 256);
  const oracle = await nodeSubtle.deriveBits({ ...base, iterations: 7 }, nodePb, 256);
  expect(hex(new Uint8Array(ours))).toBe(hex(new Uint8Array(oracle)));
});

test("HKDF deriveBits validates length like Node (d)", async () => {
  const hk: any = await ibex.importKey("raw", enc("ikm"), "HKDF", false, ["deriveBits"]);
  const base = {
    name: "HKDF",
    salt: new Uint8Array(8).fill(9),
    info: enc("ctx"),
    hash: "SHA-256",
  };
  await expectDomError(ibex.deriveBits(base, hk, null as any), "OperationError");
  await expectDomError(ibex.deriveBits(base, hk, 12), "OperationError");
  expect((await ibex.deriveBits(base, hk, 0)).byteLength).toBe(0);

  const nodeHk = await nodeSubtle.importKey("raw", enc("ikm"), "HKDF", false, ["deriveBits"]);
  const ours = await ibex.deriveBits(base, hk, 264);
  const oracle = await nodeSubtle.deriveBits(base, nodeHk, 264);
  expect(hex(new Uint8Array(ours))).toBe(hex(new Uint8Array(oracle)));
});

// ---------------------------------------------------------------------------
// (e) importKey usage + JWK consistency validation
// ---------------------------------------------------------------------------
test("importKey rejects usages the algorithm does not support (e)", async () => {
  await expectDomError(
    ibex.importKey("raw", new Uint8Array(16), "AES-GCM", true, ["sign"] as any),
    "SyntaxError"
  );
  await expectDomError(
    ibex.importKey("raw", new Uint8Array(16), { name: "HMAC", hash: "SHA-256" }, true, [
      "encrypt",
    ] as any),
    "SyntaxError"
  );
  // Secret keys with empty usages are rejected.
  await expectDomError(ibex.importKey("raw", enc("pw"), "PBKDF2", false, []), "SyntaxError");
  await expectDomError(ibex.importKey("raw", new Uint8Array(16), "AES-GCM", true, []), "SyntaxError");

  // Raw Ed25519 public keys only allow 'verify'; ECDH/X25519 public keys
  // allow no usages at all (Node agrees on both).
  const ed = await nodeSubtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edRaw = new Uint8Array(await nodeSubtle.exportKey("raw", ed.publicKey));
  await expectDomError(ibex.importKey("raw", edRaw, "Ed25519", true, ["sign"] as any), "SyntaxError");
  const okEd: any = await ibex.importKey("raw", edRaw, "Ed25519", true, ["verify"]);
  expect(okEd.type).toBe("public");

  const ec = await nodeSubtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const pubJwk = await nodeSubtle.exportKey("jwk", ec.publicKey);
  await expectDomError(
    ibex.importKey("jwk", pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ] as any),
    "SyntaxError"
  );
  // Runtime oracle: real Node throws SyntaxError here; Bun's WebCrypto (which
  // backs `node:crypto` under `bun test`) reports DataError, so only assert
  // that a conformant implementation rejects it.
  let oracleErr: any = null;
  try {
    await nodeSubtle.importKey("jwk", pubJwk, { name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ]);
  } catch (e) {
    oracleErr = e;
  }
  expect(oracleErr).not.toBeNull();
});

test("importKey('jwk') enforces JWK consistency like Node (e)", async () => {
  const aes = await nodeSubtle.generateKey({ name: "AES-GCM", length: 128 }, true, [
    "encrypt",
    "decrypt",
  ]);
  const jwk = await nodeSubtle.exportKey("jwk", aes);

  const cases: Array<[any, string]> = [
    [{ ...jwk, ext: false }, "DataError"], // ext:false but extractable:true
    [{ ...jwk, key_ops: ["decrypt"] }, "DataError"], // key_ops missing usage
    [{ ...jwk, use: "sig" }, "DataError"], // wrong use for an enc algorithm
    [{ ...jwk, alg: "A256GCM" }, "DataError"], // alg contradicts the 128-bit key
    [{ ...jwk, kty: "EC" }, "DataError"], // kty mismatch
  ];
  for (const [bad, name] of cases) {
    await expectDomError(ibex.importKey("jwk", bad, "AES-GCM", true, ["encrypt"]), name);
    await expectDomError(nodeSubtle.importKey("jwk", bad, "AES-GCM", true, ["encrypt"]), name);
  }

  // The untampered JWK still imports and round-trips.
  const ok: any = await ibex.importKey("jwk", jwk, "AES-GCM", true, ["encrypt", "decrypt"]);
  expect(hex(new Uint8Array((await ibex.exportKey("raw", ok)) as ArrayBuffer))).toBe(
    hex(new Uint8Array(await nodeSubtle.exportKey("raw", aes)))
  );
});

// ---------------------------------------------------------------------------
// (f) getRandomValues TypeMismatchError
// ---------------------------------------------------------------------------
test("getRandomValues throws TypeMismatchError for non-integer views (f)", () => {
  for (const bad of [new Float32Array(2), new Float64Array(2), new DataView(new ArrayBuffer(8))]) {
    let err: any = null;
    try {
      ibexCrypto.getRandomValues(bad as any);
    } catch (e) {
      err = e;
    }
    expect(err).not.toBeNull();
    // Real Node and browsers throw a TypeMismatchError DOMException (verified
    // against node v25.9.0); Bun's WebCrypto under `bun test` fills float
    // arrays without throwing, so no runtime oracle here.
    expect(err.name).toBe("TypeMismatchError");
  }
  // A non-view is still a TypeError.
  expect(() => ibexCrypto.getRandomValues([] as any)).toThrow(TypeError);
});

test("ordinary randomness returns without consulting capability authority", () => {
  const previousCrypto = getNativeCryptoModule();
  let capabilityChecks = 0;
  const auditEvents: unknown[] = [];
  const unsubscribe = onCapabilityAudit((event) => auditEvents.push(event));

  disableTestMode();
  setNativeCapabilityModule({
    checkCapability() {
      capabilityChecks += 1;
      return false;
    },
    async requestCapability() {
      return false;
    },
    getGrantedCapabilities() {
      return [];
    },
  });
  setNativeCryptoModule({
    getRandomValues(array) {
      array.fill(7);
      return array;
    },
    randomUUID() {
      return "00000000-0000-4000-8000-000000000000";
    },
    async sha256() { return new ArrayBuffer(32); },
    async sha384() { return new ArrayBuffer(48); },
    async sha512() { return new ArrayBuffer(64); },
    async sha1() { return new ArrayBuffer(20); },
  });

  try {
    const crypto = new Crypto();
    expect(Array.from(crypto.getRandomValues(new Uint8Array(4)))).toEqual([7, 7, 7, 7]);
    expect(crypto.randomUUID()).toBe("00000000-0000-4000-8000-000000000000");
    expect(capabilityChecks).toBe(0);
    expect(auditEvents).toEqual([]);
  } finally {
    unsubscribe();
    setNativeCryptoModule(previousCrypto as any);
    enableTestMode({
      grants: [Capabilities.CRYPTO_SUBTLE, Capabilities.CRYPTO_RANDOM, "*"],
      silent: true,
    });
  }
});

// ---------------------------------------------------------------------------
// (g) KMAC generateKey removed
// ---------------------------------------------------------------------------
test("generateKey rejects KMAC (unimplemented sign/verify) (g)", async () => {
  await expectDomError(
    ibex.generateKey({ name: "KMAC128", length: 128 } as any, true, ["sign", "verify"]),
    "NotSupportedError"
  );
  await expectDomError(
    ibex.generateKey({ name: "KMAC256", length: 256 } as any, true, ["sign", "verify"]),
    "NotSupportedError"
  );
});

// ---------------------------------------------------------------------------
// finding 2 residue: exportKey native errors surface as DOMException
// ---------------------------------------------------------------------------
test("exportKey wraps native bridge errors as DOMException (finding 2)", async () => {
  const ed = await nodeSubtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edRaw = new Uint8Array(await nodeSubtle.exportKey("raw", ed.publicKey));
  const key: any = await ibex.importKey("raw", edRaw, "Ed25519", true, ["verify"]);

  (globalThis as any).__exactExportKeySpki = () => {
    throw new Error("boom from native");
  };
  let err: any = null;
  try {
    await ibex.exportKey("spki", key);
  } catch (e) {
    err = e;
  }
  expect(err).not.toBeNull();
  expect(err.name).toBe("OperationError"); // DOMException name, not a bare Error
  expect(String(err.message)).toContain("boom from native");
});

// ---------------------------------------------------------------------------
// ECDH/X25519 deriveBits public-key validation
// ---------------------------------------------------------------------------
test("ECDH deriveBits validates the public parameter like Node (a/finding 3)", async () => {
  const a256 = await nodeSubtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const b384 = await nodeSubtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, true, [
    "deriveBits",
  ]);
  const priv: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", a256.privateKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const privAgain: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", a256.privateKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const pub384: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", b384.publicKey),
    { name: "ECDH", namedCurve: "P-384" },
    false,
    []
  );

  // public must be a public key.
  await expectDomError(
    ibex.deriveBits({ name: "ECDH", public: privAgain }, priv, 128),
    "InvalidAccessError"
  );
  // named curves must match.
  await expectDomError(
    ibex.deriveBits({ name: "ECDH", public: pub384 }, priv, 128),
    "InvalidAccessError"
  );
  // Oracle.
  await expectDomError(
    nodeSubtle.deriveBits({ name: "ECDH", public: a256.privateKey }, a256.privateKey, 128),
    "InvalidAccessError"
  );
  await expectDomError(
    nodeSubtle.deriveBits({ name: "ECDH", public: b384.publicKey }, a256.privateKey, 128),
    "InvalidAccessError"
  );
});
