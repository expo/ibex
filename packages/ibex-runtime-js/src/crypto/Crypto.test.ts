// ENG-22983 — WebCrypto conformance regression tests for SubtleCrypto.
//
// Covers six interop bugs where signatures/MACs round-tripped inside ibex but
// failed against any spec-compliant implementation:
//   1. RSA generateKey threw for the canonical 3-byte publicExponent.
//   2. HMAC sign/verify corrupted key/data bytes >= 0x80 (UTF-8 round-trip).
//   3. RSA sign/verify signed the UTF-8 re-encoding of the message.
//   4. RSA-PSS silently produced a PKCS#1 v1.5 signature.
//   5. ECDSA emitted X9.62 DER instead of raw IEEE P1363 r||s.
//   6. HMAC generate/deriveKey defaulted length to the digest size, not the
//      hash block size.
//
// Node's WebCrypto (node:crypto webcrypto) and node:crypto's DER signer are used
// as independent oracles. Run with: bun test.

import { expect, test, beforeAll, afterEach } from "bun:test";
import {
  webcrypto,
  createSign,
  createVerify,
  createPrivateKey,
  createPublicKey,
  createHmac,
  generateKeyPairSync,
  diffieHellman,
} from "node:crypto";
import { SubtleCrypto } from "./Crypto.ts";
import { enableTestMode, Capabilities } from "../security/Capabilities.ts";

const nodeSubtle = webcrypto.subtle as any;
const ibex = new SubtleCrypto();

beforeAll(() => {
  (globalThis as any).__EXACT_TEST_MODE__ = true; // allow insecure getRandomValues fallback
  enableTestMode({
    grants: [Capabilities.CRYPTO_SUBTLE, Capabilities.CRYPTO_RANDOM, "*"],
    silent: true,
  });
});

afterEach(() => {
  delete (globalThis as any).__exactGenerateKeyPairSync;
});

const enc = (s: string) => new TextEncoder().encode(s);
const bytesOf = (b: ArrayBuffer | Uint8Array) =>
  b instanceof Uint8Array ? b : new Uint8Array(b);
const hex = (b: ArrayBuffer | Uint8Array) =>
  Array.from(bytesOf(b), (x) => x.toString(16).padStart(2, "0")).join("");

// ---------------------------------------------------------------------------
// Bug 6 — HMAC default key length is the hash block size, not the digest size
// ---------------------------------------------------------------------------
test("HMAC generateKey default length is the hash block size (bug 6)", async () => {
  for (const [hash, expectedBits] of [
    ["SHA-1", 512],
    ["SHA-256", 512],
    ["SHA-384", 1024],
    ["SHA-512", 1024],
  ] as const) {
    const key: any = await ibex.generateKey({ name: "HMAC", hash }, true, ["sign", "verify"]);
    expect(key.algorithm.length).toBe(expectedBits);
    const raw = await ibex.exportKey("raw", key);
    expect((raw as ArrayBuffer).byteLength * 8).toBe(expectedBits);

    // Oracle: Node produces the same default length.
    const nodeKey = await nodeSubtle.generateKey({ name: "HMAC", hash }, true, ["sign"]);
    const nodeRaw = await nodeSubtle.exportKey("raw", nodeKey);
    expect(nodeRaw.byteLength * 8).toBe(expectedBits);
  }
});

test("HMAC generateKey honours an explicit length (bug 6)", async () => {
  const key: any = await ibex.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 128 },
    true,
    ["sign"]
  );
  expect(key.algorithm.length).toBe(128);
  expect((await ibex.exportKey("raw", key) as ArrayBuffer).byteLength).toBe(16);
});

// ---------------------------------------------------------------------------
// Bug 1 — RSA generateKey accepts the canonical 3-byte publicExponent
// ---------------------------------------------------------------------------
test("RSA generateKey accepts the canonical 3-byte publicExponent (bug 1)", async () => {
  let captured: any = null;
  (globalThis as any).__exactGenerateKeyPairSync = (type: string, opts: any) => {
    captured = { type, opts };
    // Return dummy PEMs; this test only asserts the exponent was parsed.
    return {
      publicKey: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n",
      privateKey: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
    };
  };

  // The canonical exponent 65537 as the standard 3-byte array — used to throw
  // RangeError -> OperationError.
  const pair: any = await ibex.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
  expect(pair.publicKey).toBeDefined();
  expect(captured.opts.publicExponent).toBe(65537);

  // A single-byte exponent (3) must also parse.
  await ibex.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([0x03]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );
  expect(captured.opts.publicExponent).toBe(3);
});

// ---------------------------------------------------------------------------
// Bug 2 — HMAC is byte-accurate for non-ASCII key/data (bytes >= 0x80)
// ---------------------------------------------------------------------------
test("HMAC signs raw bytes >= 0x80 and matches Node (bug 2)", async () => {
  const rawKey = new Uint8Array([0x00, 0x80, 0xff, 0xa5, 0x10, 0xc3, 0x7f, 0x81]);
  const data = new Uint8Array([0x80, 0x81, 0xfe, 0xff, 0x00, 0x41]);

  for (const hash of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] as const) {
    const ibexKey: any = await ibex.importKey("raw", rawKey, { name: "HMAC", hash }, false, [
      "sign",
      "verify",
    ]);
    const sig = await ibex.sign({ name: "HMAC" }, ibexKey, data);

    const nodeKey = await nodeSubtle.importKey("raw", rawKey, { name: "HMAC", hash }, false, ["sign"]);
    const nodeSig = await nodeSubtle.sign({ name: "HMAC" }, nodeKey, data);

    expect(hex(sig)).toBe(hex(nodeSig));

    // Cross-verify: a signature produced by Node must verify in ibex.
    const ok = await ibex.verify({ name: "HMAC" }, ibexKey, new Uint8Array(nodeSig), data);
    expect(ok).toBe(true);
    // A tampered signature must fail.
    const bad = new Uint8Array(nodeSig);
    bad[0] ^= 0xff;
    expect(await ibex.verify({ name: "HMAC" }, ibexKey, bad, data)).toBe(false);
  }
});

// ---------------------------------------------------------------------------
// Bugs 3 & 4 — RSA sign/verify is byte-accurate and PSS != PKCS#1 v1.5
// ---------------------------------------------------------------------------
async function rsaJwksForIbex(scheme: "RSASSA-PKCS1-v1_5" | "RSA-PSS", hash: string) {
  const pair = await nodeSubtle.generateKey(
    { name: scheme, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash },
    true,
    ["sign", "verify"]
  );
  const privJwk = await nodeSubtle.exportKey("jwk", pair.privateKey);
  const pubJwk = await nodeSubtle.exportKey("jwk", pair.publicKey);
  return { pair, privJwk, pubJwk };
}

test("RSASSA-PKCS1-v1_5 sign/verify round-trips with binary data and Node (bug 3)", async () => {
  const { privJwk, pubJwk } = await rsaJwksForIbex("RSASSA-PKCS1-v1_5", "SHA-256");
  const data = new Uint8Array([0x80, 0xff, 0x00, 0x7f, 0xc2, 0xa9]); // includes bytes >= 0x80

  const ibexPriv: any = await ibex.importKey(
    "jwk", privJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await ibex.sign({ name: "RSASSA-PKCS1-v1_5" }, ibexPriv, data);

  // Node (an independent implementation) must accept the ibex signature over the
  // exact byte string — the old UTF-8 round-trip corrupted 0x80/0xff/0xc2.
  const nodePub = await nodeSubtle.importKey(
    "jwk", pubJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  expect(await nodeSubtle.verify({ name: "RSASSA-PKCS1-v1_5" }, nodePub, sig, data)).toBe(true);

  // And ibex must verify a Node-produced signature.
  const nodePriv = await nodeSubtle.importKey(
    "jwk", privJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const nodeSig = await nodeSubtle.sign({ name: "RSASSA-PKCS1-v1_5" }, nodePriv, data);
  const ibexPub: any = await ibex.importKey(
    "jwk", pubJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  expect(await ibex.verify({ name: "RSASSA-PKCS1-v1_5" }, ibexPub, new Uint8Array(nodeSig), data)).toBe(true);
});

test("RSA-PSS produces a genuine PSS signature, not PKCS#1 v1.5 (bug 4)", async () => {
  const { privJwk, pubJwk } = await rsaJwksForIbex("RSA-PSS", "SHA-256");
  const data = new Uint8Array([0x81, 0x00, 0xaa, 0xff]);
  const saltLength = 32;

  const ibexPriv: any = await ibex.importKey(
    "jwk", privJwk, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await ibex.sign({ name: "RSA-PSS", saltLength }, ibexPriv, data);

  // A genuine PSS verifier accepts it...
  const pssPub = await nodeSubtle.importKey(
    "jwk", pubJwk, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]
  );
  expect(await nodeSubtle.verify({ name: "RSA-PSS", saltLength }, pssPub, sig, data)).toBe(true);

  // ...and a PKCS#1 v1.5 verifier rejects it (proving it isn't silently v1.5).
  // Reimport the same modulus/exponent under the PKCS1 algorithm.
  const v15Pub = await nodeSubtle.importKey(
    "jwk",
    { kty: pubJwk.kty, n: pubJwk.n, e: pubJwk.e },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  expect(await nodeSubtle.verify({ name: "RSASSA-PKCS1-v1_5" }, v15Pub, sig, data)).toBe(false);

  // ibex verifies a Node PSS signature.
  const nodePriv = await nodeSubtle.importKey(
    "jwk", privJwk, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]
  );
  const nodeSig = await nodeSubtle.sign({ name: "RSA-PSS", saltLength }, nodePriv, data);
  const ibexPub: any = await ibex.importKey(
    "jwk", pubJwk, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]
  );
  expect(await ibex.verify({ name: "RSA-PSS", saltLength }, ibexPub, new Uint8Array(nodeSig), data)).toBe(true);
});

// ---------------------------------------------------------------------------
// Bug 5 — ECDSA DER <-> P1363 conversion at the native bridge boundary
// ---------------------------------------------------------------------------
// The conversion is exercised by feeding the native bridge shims a DER blob (as
// the OpenSSL EVP bridge would return) and asserting the boundary yields raw
// P1363, cross-checked against Node's DER signer and Node's P1363 WebCrypto.
async function ecKeyMaterial(curve: string, nodeCurveName: string) {
  const pair = await nodeSubtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, [
    "sign",
    "verify",
  ]);
  const privJwk = await nodeSubtle.exportKey("jwk", pair.privateKey);
  const pubJwk = await nodeSubtle.exportKey("jwk", pair.publicKey);
  const privPem = createPrivateKey({ key: privJwk, format: "jwk" });
  const pubPem = createPublicKey({ key: pubJwk, format: "jwk" });
  return { pair, privJwk, pubJwk, privPem, pubPem };
}

test("ECDSA sign output is converted DER->P1363 and verifies under Node (bug 5)", async () => {
  const coordSize = 32; // P-256
  const { pair, privPem, pubJwk } = await ecKeyMaterial("P-256", "prime256v1");
  const data = new Uint8Array([1, 2, 3, 0x80, 0xff, 4]);

  // The native ECDSA bridge returns X9.62 DER; emulate it, then let ibex's
  // sign() boundary convert to P1363.
  const derSig = createSign("SHA256").update(data).sign(privPem); // DER
  (globalThis as any).__exactEcdsaSign = () => new Uint8Array(derSig);
  try {
    const ibexKey: any = {
      type: "private",
      extractable: false,
      algorithm: { name: "ECDSA", namedCurve: "P-256" },
      usages: ["sign"],
      _keyData: new Uint8Array(0),
    };
    const p1363 = bytesOf(await ibex.sign({ name: "ECDSA", hash: "SHA-256" }, ibexKey, data));
    expect(p1363.length).toBe(coordSize * 2); // 64 bytes, raw r||s

    // Node's P1363 WebCrypto verifier accepts the converted signature.
    const nodePub = await nodeSubtle.importKey(
      "jwk", pubJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
    );
    expect(await nodeSubtle.verify({ name: "ECDSA", hash: "SHA-256" }, nodePub, p1363, data)).toBe(true);
    void pair;
  } finally {
    delete (globalThis as any).__exactEcdsaSign;
  }
});

test("ECDSA verify converts P1363->DER for the native bridge (bug 5)", async () => {
  const { privJwk, pubPem } = await ecKeyMaterial("P-256", "prime256v1");
  const data = new Uint8Array([9, 8, 7, 0xfe]);

  // Node WebCrypto produces a raw P1363 signature (what a browser/Chrome emits).
  const nodePriv = await nodeSubtle.importKey(
    "jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const p1363 = new Uint8Array(await nodeSubtle.sign({ name: "ECDSA", hash: "SHA-256" }, nodePriv, data));
  expect(p1363.length).toBe(64);

  // ibex's verify() boundary must convert P1363->DER before the native verifier
  // (emulated here with node:crypto's DER verifier) sees it.
  let derSeenByBridge: Uint8Array | null = null;
  (globalThis as any).__exactEcdsaVerify = (
    _curve: string,
    _hash: string,
    _pub: Uint8Array,
    sig: Uint8Array,
    d: Uint8Array
  ) => {
    derSeenByBridge = sig;
    return createVerify("SHA256").update(d).verify(pubPem, sig); // expects DER
  };
  try {
    const ibexKey: any = {
      type: "public",
      extractable: true,
      algorithm: { name: "ECDSA", namedCurve: "P-256" },
      usages: ["verify"],
      _keyData: new Uint8Array(0),
    };
    const ok = await ibex.verify({ name: "ECDSA", hash: "SHA-256" }, ibexKey, p1363, data);
    expect(ok).toBe(true);
    // The bridge saw a DER SEQUENCE (0x30 ...), not the raw 64-byte P1363.
    expect(derSeenByBridge).not.toBeNull();
    expect(derSeenByBridge![0]).toBe(0x30);
    expect(derSeenByBridge!.length).not.toBe(64);
  } finally {
    delete (globalThis as any).__exactEcdsaVerify;
  }
});

// ---------------------------------------------------------------------------
// ENG-23037 finding 3 - HMAC-SHA-224 was accepted at import but threw on use
// (getJsDigest had no SHA-224 case). Node supports HMAC-SHA-224.
// ---------------------------------------------------------------------------
test("HMAC-SHA-224 sign/verify match Node (ENG-23037 finding 3)", async () => {
  const keyBytes = new Uint8Array(40);
  for (let i = 0; i < keyBytes.length; i++) keyBytes[i] = (i * 7 + 0x81) & 0xff; // bytes >= 0x80
  const data = enc("hmac-sha224 interop \u{1F512}ÿ");

  const key: any = await ibex.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-224" }, false, ["sign", "verify"]
  );
  const mac = new Uint8Array(await ibex.sign({ name: "HMAC" }, key, data));
  const nodeMac = new Uint8Array(
    createHmac("sha224", Buffer.from(keyBytes)).update(Buffer.from(data)).digest()
  );

  expect(mac.length).toBe(28); // SHA-224 digest size
  expect(hex(mac)).toBe(hex(nodeMac));
  expect(await ibex.verify({ name: "HMAC" }, key, mac, data)).toBe(true);
  expect(await ibex.verify({ name: "HMAC" }, key, new Uint8Array(28), data)).toBe(false);
});

// ---------------------------------------------------------------------------
// ENG-23037 finding 2 - ECDSA sign/verify with a JWK-imported EC key threw
// ("failed to import EC private key") because the raw 0x04||x||y||d point was
// handed to a PEM/DER-only native bridge. We now convert it to PKCS#8/SPKI DER
// at the call site; Node parses that DER as the oracle key.
// ---------------------------------------------------------------------------
test("ECDSA sign with a JWK-imported EC private key (ENG-23037 finding 2)", async () => {
  const pair: any = await nodeSubtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const privJwk = await nodeSubtle.exportKey("jwk", pair.privateKey);
  const ibexKey: any = await ibex.importKey(
    "jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );

  let derParsedOk = false;
  (globalThis as any).__exactEcdsaSign = (
    _curve: string, _hash: string, keyData: Uint8Array, data: Uint8Array
  ) => {
    // The JWK's raw point must have been converted to a parseable PKCS#8 DER.
    const keyObj = createPrivateKey({ key: Buffer.from(keyData), format: "der", type: "pkcs8" });
    derParsedOk = true;
    return new Uint8Array(createSign("SHA256").update(Buffer.from(data)).sign(keyObj)); // X9.62 DER
  };
  try {
    const msg = enc("ecdsa jwk sign ÿ");
    const p1363 = new Uint8Array(await ibex.sign({ name: "ECDSA", hash: "SHA-256" }, ibexKey, msg));
    expect(derParsedOk).toBe(true);
    expect(p1363.length).toBe(64); // raw IEEE P1363 r||s
    // Node's own public key verifies ibex's signature => the PKCS#8 DER encodes
    // exactly the JWK's private key.
    const ok = await nodeSubtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, p1363, msg);
    expect(ok).toBe(true);
  } finally {
    delete (globalThis as any).__exactEcdsaSign;
  }
});

test("ECDSA verify with a JWK-imported EC public key (ENG-23037 finding 2)", async () => {
  const pair: any = await nodeSubtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
  );
  const pubJwk = await nodeSubtle.exportKey("jwk", pair.publicKey);
  const ibexKey: any = await ibex.importKey(
    "jwk", pubJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );

  const msg = enc("ecdsa jwk verify þ");
  const p1363Sig = new Uint8Array(
    await nodeSubtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, msg)
  );

  let spkiParsedOk = false;
  (globalThis as any).__exactEcdsaVerify = (
    _c: string, _h: string, keyData: Uint8Array, derSig: Uint8Array, data: Uint8Array
  ) => {
    const keyObj = createPublicKey({ key: Buffer.from(keyData), format: "der", type: "spki" });
    spkiParsedOk = true;
    return createVerify("SHA256").update(Buffer.from(data)).verify(keyObj, Buffer.from(derSig));
  };
  try {
    const ok = await ibex.verify({ name: "ECDSA", hash: "SHA-256" }, ibexKey, p1363Sig, msg);
    expect(spkiParsedOk).toBe(true);
    expect(ok).toBe(true);
    // A tampered signature must not verify.
    const bad = p1363Sig.slice();
    bad[0] ^= 0xff;
    expect(await ibex.verify({ name: "ECDSA", hash: "SHA-256" }, ibexKey, bad, msg)).toBe(false);
  } finally {
    delete (globalThis as any).__exactEcdsaVerify;
  }
});

// ---------------------------------------------------------------------------
// ENG-23120 — WebCrypto key export/derivation fixes.
//
// finding 1: exportKey('jwk') of generated EC/Ed25519/X25519 keys emitted
//   base64url fragments of the native bridge's PEM text as coordinates.
// finding 2: ECDH/X25519 deriveBits ignored `length` (deriveKey minted an
//   AES-256 key when AES-128 was requested).
// finding 3: ECDH deriveBits threw for a JWK-imported private key (raw
//   0x04||x||y||d never converted to PKCS#8 for the PEM/DER-only bridge).
// finding 4: ECDSA verify threw OperationError for a wrong-length signature
//   instead of returning false.
//
// The native generator/derive bridges are emulated exactly like the real
// OpenSSL implementations (PEM output for generate, PEM/DER parsing + full
// field-size secret for derive) via node:crypto; Node WebCrypto and Node's
// JWK exporter are the conformance oracles.
// ---------------------------------------------------------------------------

function nodePemPair(type: "ec" | "ed25519" | "x25519", namedCurve?: string) {
  if (type === "ec") {
    return generateKeyPairSync("ec", {
      namedCurve:
        namedCurve === "P-384" ? "secp384r1" : namedCurve === "P-521" ? "secp521r1" : "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
  }
  return generateKeyPairSync(type as any, {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  } as any) as unknown as { publicKey: string; privateKey: string };
}

test("exportKey('jwk') of a generated EC key emits the real coordinates (ENG-23120 finding 1)", async () => {
  const pems = nodePemPair("ec", "P-256");
  (globalThis as any).__exactGenerateKeyPairSync = () => pems;

  const pair: any = await ibex.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const pubJwk: any = await ibex.exportKey("jwk", pair.publicKey);
  const privJwk: any = await ibex.exportKey("jwk", pair.privateKey);

  // Node's JWK view of the exact same PEMs is the oracle.
  const nodePub: any = createPublicKey(pems.publicKey).export({ format: "jwk" });
  const nodePriv: any = createPrivateKey(pems.privateKey).export({ format: "jwk" });

  expect(pubJwk.kty).toBe("EC");
  expect(pubJwk.crv).toBe("P-256");
  expect(pubJwk.x).toBe(nodePub.x);
  expect(pubJwk.y).toBe(nodePub.y);
  expect(privJwk.x).toBe(nodePriv.x);
  expect(privJwk.y).toBe(nodePriv.y);
  expect(privJwk.d).toBe(nodePriv.d);

  // The exported private JWK must round-trip into a conformant WebCrypto.
  const reloaded = await nodeSubtle.importKey(
    "jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  expect(reloaded.type).toBe("private");
});

test("exportKey('jwk') of generated Ed25519/X25519 keys emits real scalars incl. x on private keys (ENG-23120 finding 1)", async () => {
  for (const type of ["ed25519", "x25519"] as const) {
    const pems = nodePemPair(type);
    (globalThis as any).__exactGenerateKeyPairSync = () => pems;

    const algName = type === "ed25519" ? "Ed25519" : "X25519";
    const usages = type === "ed25519" ? ["sign", "verify"] : ["deriveBits", "deriveKey"];
    const pair: any = await ibex.generateKey({ name: algName }, true, usages as any);

    const pubJwk: any = await ibex.exportKey("jwk", pair.publicKey);
    const privJwk: any = await ibex.exportKey("jwk", pair.privateKey);
    const nodePub: any = createPublicKey(pems.publicKey).export({ format: "jwk" });
    const nodePriv: any = createPrivateKey(pems.privateKey).export({ format: "jwk" });

    expect(pubJwk.kty).toBe("OKP");
    expect(pubJwk.crv).toBe(algName);
    expect(pubJwk.x).toBe(nodePub.x);
    // The old code exported the whole private PEM as `d` with no `x`.
    expect(privJwk.d).toBe(nodePriv.d);
    expect(privJwk.x).toBe(nodePriv.x);
  }
});

/** Emulate the OpenSSL __exactEcdhDeriveBits bridge: PEM/DER keys in, full field-size secret out. */
function installNodeEcdhBridge() {
  (globalThis as any).__exactEcdhDeriveBits = (
    _curve: string,
    priv: Uint8Array,
    pub: Uint8Array
  ) => {
    const privateKey =
      priv[0] === 0x2d
        ? createPrivateKey(Buffer.from(priv).toString())
        : createPrivateKey({ key: Buffer.from(priv), format: "der", type: "pkcs8" });
    const publicKey =
      pub[0] === 0x2d
        ? createPublicKey(Buffer.from(pub).toString())
        : createPublicKey({ key: Buffer.from(pub), format: "der", type: "spki" });
    return new Uint8Array(diffieHellman({ privateKey, publicKey }));
  };
}

async function ecdhFixture() {
  // Both usages: the exported JWK's key_ops must cover everything the ibex
  // import requests, now that JWK consistency is enforced (ENG-23455).
  const alice = await nodeSubtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits", "deriveKey"]);
  const bob = await nodeSubtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits", "deriveKey"]);
  const ibexPriv: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", alice.privateKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits", "deriveKey"]
  );
  const ibexPub: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", bob.publicKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  return { alice, bob, ibexPriv, ibexPub };
}

test("ECDH deriveBits honors length and accepts JWK-imported keys (ENG-23120 findings 2+3)", async () => {
  const { alice, bob, ibexPriv, ibexPub } = await ecdhFixture();

  // The conformant peer's answer for 128 bits.
  const nodeBits = new Uint8Array(
    await nodeSubtle.deriveBits({ name: "ECDH", public: bob.publicKey }, alice.privateKey, 128)
  );

  installNodeEcdhBridge();
  try {
    // finding 3: this call used to throw OperationError ("failed to import EC
    // private key") for any JWK-imported private key.
    const bits = new Uint8Array(await ibex.deriveBits({ name: "ECDH", public: ibexPub }, ibexPriv, 128));
    // finding 2: 128 bits means 16 bytes, matching the conformant peer.
    expect(bits.length).toBe(16);
    expect(hex(bits)).toBe(hex(nodeBits));

    const full = new Uint8Array(await ibex.deriveBits({ name: "ECDH", public: ibexPub }, ibexPriv, 256));
    expect(full.length).toBe(32);
    expect(hex(full.slice(0, 16))).toBe(hex(nodeBits));

    // More bits than the shared secret has is an OperationError.
    await expect(
      ibex.deriveBits({ name: "ECDH", public: ibexPub }, ibexPriv, 264)
    ).rejects.toThrow();
  } finally {
    delete (globalThis as any).__exactEcdhDeriveBits;
  }
});

test("ECDH deriveKey(AES-GCM 128) mints an AES-128 key, not AES-256 (ENG-23120 finding 2)", async () => {
  const { alice, bob, ibexPriv, ibexPub } = await ecdhFixture();
  const nodeBits = new Uint8Array(
    await nodeSubtle.deriveBits({ name: "ECDH", public: bob.publicKey }, alice.privateKey, 128)
  );

  installNodeEcdhBridge();
  try {
    const aesKey: any = await ibex.deriveKey(
      { name: "ECDH", public: ibexPub },
      ibexPriv,
      { name: "AES-GCM", length: 128 },
      true,
      ["encrypt", "decrypt"]
    );
    expect(aesKey.algorithm.length).toBe(128);
    const raw = (await ibex.exportKey("raw", aesKey)) as ArrayBuffer;
    expect(raw.byteLength).toBe(16);
    // Interoperates with the conformant peer's AES-128 derivation.
    expect(hex(raw)).toBe(hex(nodeBits));
  } finally {
    delete (globalThis as any).__exactEcdhDeriveBits;
  }
});

test("X25519 deriveBits honors length (ENG-23120 finding 2)", async () => {
  // Bun's WebCrypto lacks X25519, so the oracle is node:crypto's stateless
  // diffieHellman over the same key material; per the WebCrypto X25519
  // deriveBits algorithm, 64 bits = the first 8 bytes of that secret.
  const aPems = nodePemPair("x25519");
  const bPems = nodePemPair("x25519");
  const aPrivJwk = createPrivateKey(aPems.privateKey).export({ format: "jwk" });
  const bPubJwk = createPublicKey(bPems.publicKey).export({ format: "jwk" });
  const fullSecret = new Uint8Array(
    diffieHellman({
      privateKey: createPrivateKey(aPems.privateKey),
      publicKey: createPublicKey(bPems.publicKey),
    })
  );
  const nodeBits = fullSecret.slice(0, 8);

  // Emulate the raw-scalar OpenSSL bridge via RFC 8410 fixed DER prefixes.
  (globalThis as any).__exactX25519DeriveBits = (priv: Uint8Array, pub: Uint8Array) => {
    const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(priv)]);
    const spki = Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(pub)]);
    return new Uint8Array(
      diffieHellman({
        privateKey: createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }),
        publicKey: createPublicKey({ key: spki, format: "der", type: "spki" }),
      })
    );
  };
  try {
    const ibexPriv: any = await ibex.importKey(
      "jwk", aPrivJwk, { name: "X25519" }, false, ["deriveBits"]
    );
    const ibexPub: any = await ibex.importKey(
      "jwk", bPubJwk, { name: "X25519" }, false, []
    );
    const bits = new Uint8Array(await ibex.deriveBits({ name: "X25519", public: ibexPub }, ibexPriv, 64));
    expect(bits.length).toBe(8);
    expect(hex(bits)).toBe(hex(nodeBits));
    await expect(
      ibex.deriveBits({ name: "X25519", public: ibexPub }, ibexPriv, 512)
    ).rejects.toThrow();
  } finally {
    delete (globalThis as any).__exactX25519DeriveBits;
  }
});

test("ECDSA verify returns false for a wrong-length signature (ENG-23120 finding 4)", async () => {
  const pair: any = await nodeSubtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const ibexPub: any = await ibex.importKey(
    "jwk",
    await nodeSubtle.exportKey("jwk", pair.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  let bridgeCalled = false;
  (globalThis as any).__exactEcdsaVerify = () => {
    bridgeCalled = true;
    return true;
  };
  try {
    for (const len of [0, 63, 65, 128]) {
      // Used to reject with OperationError (p1363ToDer DataError); the
      // WebCrypto ECDSA verify algorithm requires `false`.
      expect(
        await ibex.verify({ name: "ECDSA", hash: "SHA-256" }, ibexPub, new Uint8Array(len), enc("m"))
      ).toBe(false);
    }
    expect(bridgeCalled).toBe(false);
  } finally {
    delete (globalThis as any).__exactEcdsaVerify;
  }
});

test("exportKey('spki'/'pkcs8') of generated OKP keys reaches the raw native path (ENG-23120)", async () => {
  const pems = nodePemPair("ed25519");
  (globalThis as any).__exactGenerateKeyPairSync = () => pems;
  const pair: any = await ibex.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);

  let spkiArgs: { t: string; len: number } | null = null;
  let pkcs8Args: { t: string; len: number } | null = null;
  // The real bridge only takes its raw-32 fast path for lowercase key types;
  // emulate it with the RFC 8410 fixed prefixes.
  (globalThis as any).__exactExportKeySpki = (t: string, k: Uint8Array) => {
    spkiArgs = { t, len: k.length };
    return new Uint8Array(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(k)]));
  };
  (globalThis as any).__exactExportKeyPkcs8 = (t: string, k: Uint8Array) => {
    pkcs8Args = { t, len: k.length };
    return new Uint8Array(Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(k)]));
  };
  try {
    const spkiOut = Buffer.from((await ibex.exportKey("spki", pair.publicKey)) as ArrayBuffer);
    expect(spkiArgs).toEqual({ t: "ed25519", len: 32 });
    expect(
      spkiOut.equals(createPublicKey(pems.publicKey).export({ format: "der", type: "spki" }) as Buffer)
    ).toBe(true);

    const pkcs8Out = Buffer.from((await ibex.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
    // The d[32] || x[32] private blob must be sliced to the bare scalar.
    expect(pkcs8Args).toEqual({ t: "ed25519", len: 32 });
    expect(
      pkcs8Out.equals(createPrivateKey(pems.privateKey).export({ format: "der", type: "pkcs8" }) as Buffer)
    ).toBe(true);
  } finally {
    delete (globalThis as any).__exactExportKeySpki;
    delete (globalThis as any).__exactExportKeyPkcs8;
  }
});
