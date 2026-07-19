/**
 * Source-bound public probes for builtin exports whose classification can be
 * demonstrated by importing and exercising the exact export through Hermes.
 *
 * A generic read probe is emitted only for a source-proven data property or
 * root accessor. Callables are executable only when their exact source module
 * and export have an authored bounded template below. Each template supplies
 * setup, receiver, arguments, and an expected return type; a throw at any
 * point is a failed probe rather than evidence that the function body ran.
 *
 * @ref LLP 0004#the-builtin-module-surface — builtin aliases share one
 * source-derived export inventory.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * inventory references are not evidence; the bound engine must execute each
 * authored public probe.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const BUILTIN_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer,openssl-crypto",
  "capsec_public_noncap_builtin_recipe_batch",
  "--",
  "--test-threads=1",
  "--nocapture",
]);

const READ_INVOCATION_SCHEMA = "ibex/capsec-builtin-export-invocation/1";
const CALL_INVOCATION_SCHEMA = "ibex/capsec-builtin-call-invocation/1";
const EVENT_LOOP_COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});

const jsonArgument = (value) => ({ kind: "json", value });
const noopArgument = () => ({ kind: "noop-function" });
const throwingArgument = () => ({
  kind: "throwing-function",
  errorMessage: "ibex-capsec-authored-throw",
});
const regexpArgument = (source, flags = "") => ({
  kind: "regexp",
  source,
  flags,
});
const eventEmitterArgument = () => ({ kind: "event-emitter" });
const uint8ArrayArgument = (bytes) => ({ kind: "uint8-array", bytes });
const bufferArgument = (bytes) => ({ kind: "buffer", bytes });
const bigintArgument = (value) => ({ kind: "bigint", value: String(value) });
const setupValueArgument = (name) => ({ kind: "setup-value", name });
const constantFunctionArgument = (value) => ({
  kind: "constant-function",
  value,
});
const streamInstanceArgument = (ownerExportName, ended = false) => ({
  kind: "stream-instance",
  ownerExportName,
  ended,
});
const abortSignalArgument = () => ({ kind: "abort-signal" });
const zlibInputArgument = (ownerExportName) => ({
  kind: "zlib-input",
  ownerExportName,
});
const ownValue = (object, key) =>
  object && Object.prototype.hasOwnProperty.call(object, key)
    ? object[key]
    : null;

function callSpec(setup, arguments_, resultType) {
  return { setup, arguments: arguments_, resultType };
}

const rootCall = (arguments_, resultType) =>
  callSpec({ kind: "root-call" }, arguments_, resultType);
const constructTarget = (arguments_, resultType = "object") =>
  callSpec({ kind: "construct-target" }, arguments_, resultType);
const constructedOwner = (
  ownerExportName,
  arguments_,
  resultType,
  constructorArguments = [],
) =>
  callSpec(
    {
      kind: "constructed-owner",
      ownerExportName,
      constructorArguments,
    },
    arguments_,
    resultType,
  );

const ZLIB_OWNER_NAMES = Object.freeze([
  "BrotliCompress",
  "BrotliDecompress",
  "Deflate",
  "DeflateRaw",
  "Gunzip",
  "Gzip",
  "Inflate",
  "InflateRaw",
  "Unzip",
  "ZstdCompress",
  "ZstdDecompress",
]);
const ZLIB_OWNER_SET = new Set(ZLIB_OWNER_NAMES);
const ZLIB_NATIVE_OWNER_SET = new Set([
  "Deflate",
  "DeflateRaw",
  "Gunzip",
  "Gzip",
  "Inflate",
  "InflateRaw",
  "Unzip",
]);
const ZLIB_ONE_SHOT_EXPORTS = Object.freeze({
  brotliCompress: "BrotliCompress",
  brotliCompressSync: "BrotliCompress",
  brotliDecompress: "BrotliDecompress",
  brotliDecompressSync: "BrotliDecompress",
  deflate: "Deflate",
  deflateRaw: "DeflateRaw",
  deflateRawSync: "DeflateRaw",
  deflateSync: "Deflate",
  gunzip: "Gunzip",
  gunzipSync: "Gunzip",
  gzip: "Gzip",
  gzipSync: "Gzip",
  inflate: "Inflate",
  inflateRaw: "InflateRaw",
  inflateRawSync: "InflateRaw",
  inflateSync: "Inflate",
  unzip: "Unzip",
  unzipSync: "Unzip",
});

function zlibRootCallSpecs() {
  const specs = Object.create(null);
  for (const ownerExportName of ZLIB_OWNER_NAMES) {
    specs[ownerExportName] = constructTarget([]);
    specs[`create${ownerExportName}`] = rootCall([], "object");
  }
  specs.crc32 = rootCall([jsonArgument("ibex")], "number");
  for (const [exportName, ownerExportName] of Object.entries(
    ZLIB_ONE_SHOT_EXPORTS,
  )) {
    const input = zlibInputArgument(ownerExportName);
    specs[exportName] = exportName.endsWith("Sync")
      ? rootCall([input], "object")
      : rootCall([input, noopArgument()], "undefined");
  }
  return Object.freeze(specs);
}

const ZLIB_ROOT_CALL_SPECS = zlibRootCallSpecs();

const STREAM_OWNER_NAMES = Object.freeze([
  "Duplex",
  "PassThrough",
  "Readable",
  "Stream",
  "Transform",
  "Writable",
  "default",
]);
const STREAM_OWNER_SET = new Set(STREAM_OWNER_NAMES);
const STREAM_READABLE_OWNER_SET = new Set([
  "Duplex",
  "PassThrough",
  "Readable",
  "Transform",
]);
const STREAM_DEFERRED_METHOD_SET = new Set([
  "every",
  "find",
  "forEach",
  "reduce",
  "some",
  "toArray",
  "wrap",
]);

function streamRootCallSpecs() {
  const specs = Object.create(null);
  for (const ownerExportName of STREAM_OWNER_NAMES) {
    specs[ownerExportName] = constructTarget([]);
  }
  specs.addAbortSignal = rootCall(
    [abortSignalArgument(), streamInstanceArgument("Readable")],
    "object",
  );
  specs.addAbortSignalNoValidate = rootCall(
    [abortSignalArgument(), streamInstanceArgument("Readable")],
    "object",
  );
  // compose() owns a live pipeline after it returns. A one-shot invocation
  // cannot prove that the asynchronous pipeline was drained and cleaned up,
  // so leave it residual instead of leaking work into later probes.
  specs.destroy = rootCall(
    // The one-argument form intentionally injects an asynchronously-emitted
    // AbortError. Passing an explicit null exercises the same source body
    // without leaving an error event behind after the probe returns.
    [streamInstanceArgument("Readable"), jsonArgument(null)],
    "object",
  );
  specs.duplexPair = rootCall([], "object");
  specs.finished = rootCall(
    [streamInstanceArgument("Readable", true), noopArgument()],
    "function",
  );
  specs.getDefaultHighWaterMark = rootCall(
    [jsonArgument(false)],
    "number",
  );
  for (const exportName of [
    "isDisturbed",
    "isErrored",
    "isReadable",
    "isWritable",
  ]) {
    specs[exportName] = rootCall(
      [streamInstanceArgument("Readable")],
      "boolean",
    );
  }
  // pipeline() completes after the source call returns. That work can execute
  // inside a later observation session, so a normal synchronous return is not
  // bounded evidence for this surface.
  return Object.freeze(specs);
}

const STREAM_ROOT_CALL_SPECS = streamRootCallSpecs();

const CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  jsonArgument("sha256"),
]);
const CRYPTO_HMAC_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  jsonArgument("sha256"),
  jsonArgument("ibex-key"),
]);
const CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  jsonArgument("sha256"),
]);
const CRYPTO_DH_GROUP_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  jsonArgument("modp14"),
]);
const CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  jsonArgument("prime256v1"),
]);

function exactCryptoCallSpecs() {
  const specs = {
    Hash: constructTarget([...CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS]),
    Hmac: constructTarget([...CRYPTO_HMAC_CONSTRUCTOR_ARGUMENTS]),
    KeyObject: constructTarget([
      jsonArgument("secret"),
      uint8ArrayArgument([0x69, 0x62, 0x65, 0x78]),
    ]),
    createHash: rootCall([...CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS], "object"),
    createHmac: rootCall([...CRYPTO_HMAC_CONSTRUCTOR_ARGUMENTS], "object"),
    createDiffieHellmanGroup: rootCall(
      [...CRYPTO_DH_GROUP_CONSTRUCTOR_ARGUMENTS],
      "object",
    ),
    createECDH: rootCall([...CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS], "object"),
    createSign: rootCall([...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS], "object"),
    createSecretKey: rootCall(
      [uint8ArrayArgument([0x69, 0x62, 0x65, 0x78])],
      "object",
    ),
    createVerify: rootCall([...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS], "object"),
    DiffieHellmanGroup: constructTarget([
      ...CRYPTO_DH_GROUP_CONSTRUCTOR_ARGUMENTS,
    ]),
    ECDH: constructTarget([...CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS]),
    generateKeySync: rootCall(
      [jsonArgument("hmac"), jsonArgument({ length: 64 })],
      "object",
    ),
    generatePrimeSync: rootCall(
      [jsonArgument(16), jsonArgument({ bigint: true })],
      "bigint",
    ),
    getCipherInfo: rootCall([jsonArgument("aes-128-gcm")], "object"),
    getCiphers: rootCall([], "object"),
    getCurves: rootCall([], "object"),
    getFips: rootCall([], "number"),
    getHashes: rootCall([], "object"),
    getDiffieHellman: rootCall(
      [...CRYPTO_DH_GROUP_CONSTRUCTOR_ARGUMENTS],
      "object",
    ),
    hash: rootCall(
      [jsonArgument("sha256"), jsonArgument("ibex"), jsonArgument("hex")],
      "string",
    ),
    hkdfSync: rootCall(
      [
        jsonArgument("sha256"),
        jsonArgument("ibex-key"),
        jsonArgument("ibex-salt"),
        jsonArgument("ibex-info"),
        jsonArgument(16),
      ],
      "object",
    ),
    pbkdf2Sync: rootCall(
      [
        jsonArgument("ibex-password"),
        jsonArgument("ibex-salt"),
        jsonArgument(2),
        jsonArgument(16),
        jsonArgument("sha256"),
      ],
      "object",
    ),
    randomBytes: rootCall([jsonArgument(8)], "object"),
    randomFillSync: rootCall(
      [uint8ArrayArgument([0, 0, 0, 0])],
      "object",
    ),
    randomInt: rootCall([jsonArgument(0), jsonArgument(16)], "number"),
    scryptSync: rootCall(
      [
        jsonArgument("ibex-password"),
        jsonArgument("ibex-salt"),
        jsonArgument(16),
        jsonArgument({ N: 16, r: 1, p: 1, maxmem: 1024 * 1024 }),
      ],
      "object",
    ),
    timingSafeEqual: rootCall(
      [
        uint8ArrayArgument([0x69, 0x62, 0x65, 0x78]),
        uint8ArrayArgument([0x69, 0x62, 0x65, 0x78]),
      ],
      "boolean",
    ),
    checkPrimeSync: rootCall([bigintArgument(17)], "boolean"),
    Sign: constructTarget([...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS]),
    Verify: constructTarget([...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS]),
  };
  for (const alias of ["prng", "pseudoRandomBytes", "rng"]) {
    specs[alias] = rootCall([jsonArgument(8)], "object");
  }
  for (const [ownerExportName, constructorArguments] of [
    ["Hash", CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS],
    ["Hmac", CRYPTO_HMAC_CONSTRUCTOR_ARGUMENTS],
  ]) {
    specs[`${ownerExportName}.constructor`] = constructTarget([
      ...constructorArguments,
    ]);
    // _flush() pushes into the Transform readable side and schedules later
    // stream work. It and end() need a draining harness, not a synchronous
    // normal-return claim.
    specs[`${ownerExportName}._transform`] = constructedOwner(
      ownerExportName,
      [jsonArgument("ibex"), jsonArgument("utf8"), noopArgument()],
      "undefined",
      [...constructorArguments],
    );
    specs[`${ownerExportName}.digest`] = constructedOwner(
      ownerExportName,
      [jsonArgument("hex")],
      "string",
      [...constructorArguments],
    );
    specs[`${ownerExportName}.update`] = constructedOwner(
      ownerExportName,
      [jsonArgument("ibex")],
      "object",
      [...constructorArguments],
    );
  }
  specs["Hash.copy"] = constructedOwner(
    "Hash",
    [],
    "object",
    [...CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS],
  );
  specs["KeyObject.export"] = constructedOwner(
    "KeyObject",
    [],
    "object",
    [jsonArgument("secret"), uint8ArrayArgument([0x69, 0x62, 0x65, 0x78])],
  );
  for (const ownerExportName of ["Sign", "Verify"]) {
    specs[`${ownerExportName}.constructor`] = constructTarget([
      ...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS,
    ]);
    specs[`${ownerExportName}.end`] = constructedOwner(
      ownerExportName,
      [jsonArgument("ibex")],
      "object",
      [...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS],
    );
    specs[`${ownerExportName}.update`] = constructedOwner(
      ownerExportName,
      [jsonArgument("ibex")],
      "object",
      [...CRYPTO_SIGN_CONSTRUCTOR_ARGUMENTS],
    );
  }
  for (const methodName of [
    "getGenerator",
    "getPrime",
    "getPrivateKey",
    "getPublicKey",
  ]) {
    specs[`DiffieHellmanGroup.${methodName}`] = constructedOwner(
      "DiffieHellmanGroup",
      [],
      "object",
      [...CRYPTO_DH_GROUP_CONSTRUCTOR_ARGUMENTS],
    );
  }
  for (const methodName of ["getPrivateKey", "getPublicKey"]) {
    specs[`ECDH.${methodName}`] = constructedOwner(
      "ECDH",
      [],
      "object",
      [...CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS],
    );
  }
  for (const methodName of ["setPrivateKey", "setPublicKey"]) {
    specs[`ECDH.${methodName}`] = constructedOwner(
      "ECDH",
      [uint8ArrayArgument([1, 2, 3, 4])],
      "undefined",
      [...CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS],
    );
  }
  return Object.freeze(specs);
}

const EXACT_CRYPTO_CALL_SPECS = exactCryptoCallSpecs();

const NODE_NET_CALL_SPECS = Object.freeze({
  BlockList: constructTarget([]),
  "BlockList.addAddress": constructedOwner(
    "BlockList",
    [jsonArgument("127.0.0.1"), jsonArgument("ipv4")],
    "undefined",
  ),
  "BlockList.addRange": constructedOwner(
    "BlockList",
    [
      jsonArgument("127.0.0.1"),
      jsonArgument("127.0.0.2"),
      jsonArgument("ipv4"),
    ],
    "undefined",
  ),
  "BlockList.addSubnet": constructedOwner(
    "BlockList",
    [jsonArgument("127.0.0.0"), jsonArgument(8), jsonArgument("ipv4")],
    "undefined",
  ),
  "BlockList.check": constructedOwner(
    "BlockList",
    [jsonArgument("127.0.0.1"), jsonArgument("ipv4")],
    "boolean",
  ),
  Server: constructTarget([]),
  "Server.ref": constructedOwner("Server", [], "object"),
  "Server.unref": constructedOwner("Server", [], "object"),
  SocketAddress: constructTarget([
    jsonArgument({ address: "127.0.0.1", family: "ipv4", port: 0 }),
  ]),
  _normalizeArgs: rootCall([jsonArgument([8080, "127.0.0.1"])], "object"),
  createServer: rootCall([], "object"),
  getDefaultAutoSelectFamily: rootCall([], "boolean"),
  getDefaultAutoSelectFamilyAttemptTimeout: rootCall([], "number"),
  isIP: rootCall([jsonArgument("127.0.0.1")], "number"),
  isIPv4: rootCall([jsonArgument("127.0.0.1")], "boolean"),
  isIPv6: rootCall([jsonArgument("::1")], "boolean"),
});

// These tables are deliberately keyed by the scanner's sourceKey and exact
// exportName. They are an allowlist derived from the corresponding builtin
// source, not a generic "call every function" mechanism.
const ROOT_CALL_SPECS = Object.freeze({
  exact_crypto: EXACT_CRYPTO_CALL_SPECS,
  node_module: Object.freeze({
    _nodeModulePaths: rootCall([jsonArgument("/ibex/project/src")], "object"),
    isBuiltin: rootCall([jsonArgument("node:path")], "boolean"),
    wrap: rootCall([jsonArgument("return 'ibex';")], "string"),
  }),
  node_net: NODE_NET_CALL_SPECS,
  node_perf_hooks: Object.freeze({
    Performance: constructTarget([]),
    "Performance.clearMarks": constructedOwner(
      "Performance",
      [],
      "undefined",
    ),
    "Performance.clearMeasures": constructedOwner(
      "Performance",
      [],
      "undefined",
    ),
    "Performance.clearResourceTimings": constructedOwner(
      "Performance",
      [],
      "undefined",
    ),
    "Performance.getEntries": constructedOwner("Performance", [], "object"),
    "Performance.getEntriesByName": constructedOwner(
      "Performance",
      [jsonArgument("ibex")],
      "object",
    ),
    "Performance.getEntriesByType": constructedOwner(
      "Performance",
      [jsonArgument("mark")],
      "object",
    ),
    "Performance.mark": constructedOwner(
      "Performance",
      [jsonArgument("ibex"), jsonArgument({ startTime: 0 })],
      "object",
    ),
    "Performance.markResourceTiming": constructedOwner(
      "Performance",
      [
        jsonArgument({
          startTime: 0,
          endTime: 1,
          encodedBodySize: 4,
          decodedBodySize: 4,
          finalConnectionTimingInfo: { ALPNNegotiatedProtocol: "h2" },
        }),
        jsonArgument("https://example.test/ibex"),
        jsonArgument("fetch"),
        jsonArgument(null),
        jsonArgument(""),
        jsonArgument({}),
        jsonArgument(200),
        jsonArgument(""),
      ],
      "object",
    ),
    "Performance.measure": constructedOwner(
      "Performance",
      [
        jsonArgument("ibex-measure"),
        jsonArgument({ start: 0, duration: 1 }),
      ],
      "object",
    ),
    "Performance.now": constructedOwner("Performance", [], "number"),
    "Performance.toJSON": constructedOwner("Performance", [], "object"),
    PerformanceMark: constructTarget([
      jsonArgument("ibex-mark"),
      jsonArgument({ startTime: 0 }),
    ]),
    "PerformanceMark.constructor": constructTarget([
      jsonArgument("ibex-mark"),
      jsonArgument({ startTime: 0 }),
    ]),
    "PerformanceMark.toJSON": constructedOwner(
      "PerformanceMark",
      [],
      "object",
      [jsonArgument("ibex-mark"), jsonArgument({ startTime: 0 })],
    ),
    PerformanceObserver: constructTarget([noopArgument()]),
    "PerformanceObserver.disconnect": constructedOwner(
      "PerformanceObserver",
      [],
      "undefined",
      [noopArgument()],
    ),
    "PerformanceObserver.takeRecords": constructedOwner(
      "PerformanceObserver",
      [],
      "object",
      [noopArgument()],
    ),
  }),
  node_path: Object.freeze({
    _makeLong: rootCall([jsonArgument("/ibex")], "string"),
    basename: rootCall([jsonArgument("/ibex/file.txt")], "string"),
    dirname: rootCall([jsonArgument("/ibex/file.txt")], "string"),
    extname: rootCall([jsonArgument("/ibex/file.txt")], "string"),
    format: rootCall(
      [jsonArgument({ dir: "/ibex", name: "file", ext: ".txt" })],
      "string",
    ),
    isAbsolute: rootCall([jsonArgument("/ibex")], "boolean"),
    join: rootCall(
      [jsonArgument("/ibex"), jsonArgument("child")],
      "string",
    ),
    normalize: rootCall([jsonArgument("/ibex/../probe/")], "string"),
    parse: rootCall([jsonArgument("/ibex/file.txt")], "object"),
    relative: rootCall(
      [jsonArgument("/ibex"), jsonArgument("/ibex/child")],
      "string",
    ),
    resolve: rootCall(
      [jsonArgument("/ibex"), jsonArgument("child")],
      "string",
    ),
    toNamespacedPath: rootCall([jsonArgument("/ibex")], "string"),
  }),
  node_querystring: Object.freeze({
    decode: rootCall([jsonArgument("a=1&a=2&b=ibex")], "object"),
    encode: rootCall(
      [jsonArgument({ a: ["1", "2"], b: "ibex" })],
      "string",
    ),
    escape: rootCall([jsonArgument("ibex probe")], "string"),
    parse: rootCall([jsonArgument("a=1&a=2&b=ibex")], "object"),
    stringify: rootCall(
      [jsonArgument({ a: ["1", "2"], b: "ibex" })],
      "string",
    ),
    unescape: rootCall([jsonArgument("ibex%20probe")], "string"),
  }),
  node_string_decoder: Object.freeze({
    default: constructTarget([jsonArgument("utf8")]),
    StringDecoder: constructTarget([jsonArgument("utf8")]),
    "StringDecoder.end": constructedOwner(
      "StringDecoder",
      [bufferArgument([0x69, 0x62, 0x65, 0x78])],
      "string",
      [jsonArgument("utf8")],
    ),
    "StringDecoder.fillLast": constructedOwner(
      "StringDecoder",
      [bufferArgument([0x69])],
      "string",
      [jsonArgument("utf8")],
    ),
    "StringDecoder.text": constructedOwner(
      "StringDecoder",
      [bufferArgument([0x69, 0x62, 0x65, 0x78]), jsonArgument(0)],
      "string",
      [jsonArgument("utf8")],
    ),
    "StringDecoder.toString": constructedOwner(
      "StringDecoder",
      [],
      "string",
      [jsonArgument("utf8")],
    ),
    "StringDecoder.write": constructedOwner(
      "StringDecoder",
      [bufferArgument([0x69, 0x62, 0x65, 0x78])],
      "string",
      [jsonArgument("utf8")],
    ),
  }),
  node_stream: STREAM_ROOT_CALL_SPECS,
  node_url: Object.freeze({
    canParse: rootCall(
      [jsonArgument("https://example.test/ibex")],
      "boolean",
    ),
    fileURLToPath: rootCall(
      [jsonArgument("file:///tmp/ibex")],
      "string",
    ),
    format: rootCall(
      [
        jsonArgument({
          protocol: "https:",
          slashes: true,
          hostname: "example.test",
          pathname: "/ibex",
          search: "?probe=1",
          hash: "#bounded",
        }),
      ],
      "string",
    ),
    parse: rootCall([jsonArgument("https://example.test/ibex")], "object"),
    pathToFileURL: rootCall([jsonArgument("/tmp/ibex")], "object"),
    resolve: rootCall(
      [
        jsonArgument("https://example.test/base/"),
        jsonArgument("../ibex"),
      ],
      "string",
    ),
    resolveObject: rootCall(
      [
        jsonArgument("https://example.test/base/"),
        jsonArgument("../ibex"),
      ],
      "object",
    ),
    Url: constructTarget([]),
    "Url.resolveObject": constructedOwner(
      "Url",
      [jsonArgument("https://example.test/ibex")],
      "object",
    ),
    urlToHttpOptions: rootCall(
      [
        jsonArgument({
          protocol: "https:",
          hostname: "example.test",
          pathname: "/ibex",
          search: "?probe=1",
          hash: "#bounded",
          href: "https://example.test/ibex?probe=1#bounded",
          port: "443",
          username: "",
          password: "",
        }),
      ],
      "object",
    ),
  }),
  node_util: Object.freeze({
    _extend: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ b: 2 })],
      "object",
    ),
    callbackify: rootCall([noopArgument()], "function"),
    deprecate: rootCall(
      [noopArgument(), jsonArgument("ibex bounded probe")],
      "function",
    ),
    format: rootCall(
      [jsonArgument("%s:%d"), jsonArgument("ibex"), jsonArgument(1)],
      "string",
    ),
    formatWithOptions: rootCall(
      [jsonArgument({}), jsonArgument("%s"), jsonArgument("ibex")],
      "string",
    ),
    getSystemErrorName: rootCall([jsonArgument(-2)], "string"),
    inherits: rootCall([noopArgument(), noopArgument()], "undefined"),
    inspect: rootCall([jsonArgument({ ibex: true })], "string"),
    isDeepStrictEqual: rootCall(
      [jsonArgument({ ibex: [1] }), jsonArgument({ ibex: [1] })],
      "boolean",
    ),
    parseArgs: rootCall(
      [
        jsonArgument({
          args: ["--probe", "ibex"],
          options: { probe: { type: "string" } },
        }),
      ],
      "object",
    ),
    promisify: rootCall([noopArgument()], "function"),
  }),
  node_punycode: Object.freeze({
    decode: rootCall([jsonArgument("maana-pta")], "string"),
    encode: rootCall([jsonArgument("mañana")], "string"),
    toASCII: rootCall([jsonArgument("mañana.example")], "string"),
    toUnicode: rootCall(
      [jsonArgument("xn--maana-pta.example")],
      "string",
    ),
  }),
  node_assert: Object.freeze({
    AssertionError: constructTarget([
      jsonArgument({ actual: 1, expected: 2, operator: "strictEqual" }),
    ]),
    CallTracker: constructTarget([]),
    _isDeepStrictEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 1 })],
      "boolean",
    ),
    deepEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 1 })],
      "undefined",
    ),
    deepStrictEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 1 })],
      "undefined",
    ),
    default: rootCall([jsonArgument(true)], "undefined"),
    doesNotMatch: rootCall(
      [jsonArgument("ibex"), regexpArgument("z")],
      "undefined",
    ),
    doesNotThrow: rootCall([noopArgument()], "undefined"),
    equal: rootCall([jsonArgument(1), jsonArgument("1")], "undefined"),
    ifError: rootCall([jsonArgument(null)], "undefined"),
    match: rootCall(
      [jsonArgument("ibex"), regexpArgument("ib")],
      "undefined",
    ),
    notDeepEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 2 })],
      "undefined",
    ),
    notDeepStrictEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 2 })],
      "undefined",
    ),
    notEqual: rootCall([jsonArgument(1), jsonArgument(2)], "undefined"),
    notStrictEqual: rootCall(
      [jsonArgument(1), jsonArgument("1")],
      "undefined",
    ),
    ok: rootCall([jsonArgument(true)], "undefined"),
    partialDeepStrictEqual: rootCall(
      [jsonArgument({ a: 1, b: 2 }), jsonArgument({ a: 1 })],
      "undefined",
    ),
    strict: rootCall([jsonArgument(true)], "undefined"),
    strictEqual: rootCall(
      [jsonArgument("ibex"), jsonArgument("ibex")],
      "undefined",
    ),
    throws: rootCall([throwingArgument()], "undefined"),
  }),
  node_events: Object.freeze({
    EventEmitter: constructTarget([]),
    EventEmitterAsyncResource: constructTarget([jsonArgument("ibex-probe")]),
    default: constructTarget([]),
    getEventListeners: rootCall(
      [eventEmitterArgument(), jsonArgument("ibex")],
      "object",
    ),
    getMaxListeners: rootCall([eventEmitterArgument()], "number"),
    listenerCount: rootCall(
      [eventEmitterArgument(), jsonArgument("ibex")],
      "number",
    ),
    on: rootCall(
      [eventEmitterArgument(), jsonArgument("ibex")],
      "object",
    ),
    once: rootCall(
      [eventEmitterArgument(), jsonArgument("ibex")],
      "object",
    ),
    setMaxListeners: rootCall(
      [jsonArgument(11), eventEmitterArgument()],
      "undefined",
    ),
  }),
  node_buffer: Object.freeze({
    Buffer: constructTarget([jsonArgument(8)]),
    SlowBuffer: constructTarget([jsonArgument(8)]),
    isAscii: rootCall([uint8ArrayArgument([73, 98, 101, 120])], "boolean"),
    isUtf8: rootCall([uint8ArrayArgument([73, 98, 101, 120])], "boolean"),
  }),
  node_zlib: ZLIB_ROOT_CALL_SPECS,
  node_v8: Object.freeze({
    cachedDataVersionTag: rootCall([], "number"),
  }),
});

const ASSERT_PROTOTYPE_SPECS = Object.freeze({
  "AssertionError.constructor": constructTarget([
    jsonArgument({ actual: 1, expected: 2, operator: "strictEqual" }),
  ]),
  "CallTracker._getContext": callSpec(
    {
      kind: "call-tracker-owner",
      ownerExportName: "CallTracker",
      trackedExpectedCalls: 1,
    },
    [setupValueArgument("tracked")],
    "object",
  ),
  "CallTracker.calls": constructedOwner(
    "CallTracker",
    [noopArgument(), jsonArgument(1)],
    "function",
  ),
  "CallTracker.getCalls": callSpec(
    {
      kind: "call-tracker-owner",
      ownerExportName: "CallTracker",
      trackedExpectedCalls: 1,
    },
    [setupValueArgument("tracked")],
    "object",
  ),
  "CallTracker.report": constructedOwner("CallTracker", [], "object"),
  "CallTracker.reset": constructedOwner("CallTracker", [], "undefined"),
  "CallTracker.verify": constructedOwner("CallTracker", [], "undefined"),
});

const EVENT_EMITTER_METHOD_SPECS = Object.freeze({
  addListener: [[jsonArgument("ibex"), noopArgument()], "object"],
  emit: [[jsonArgument("ibex")], "boolean"],
  eventNames: [[], "object"],
  getMaxListeners: [[], "number"],
  listenerCount: [[jsonArgument("ibex")], "number"],
  listeners: [[jsonArgument("ibex")], "object"],
  off: [[jsonArgument("ibex"), noopArgument()], "object"],
  on: [[jsonArgument("ibex"), noopArgument()], "object"],
  once: [[jsonArgument("ibex"), noopArgument()], "object"],
  prependListener: [[jsonArgument("ibex"), noopArgument()], "object"],
  prependOnceListener: [[jsonArgument("ibex"), noopArgument()], "object"],
  rawListeners: [[jsonArgument("ibex")], "object"],
  removeAllListeners: [[jsonArgument("ibex")], "object"],
  removeListener: [[jsonArgument("ibex"), noopArgument()], "object"],
  setMaxListeners: [[jsonArgument(11)], "object"],
});

function eventPrototypeSpec(exportName) {
  const [ownerExportName, methodName] = exportName.split(".");
  if (!ownerExportName || !methodName || exportName.split(".").length !== 2) {
    return null;
  }
  if (
    !new Set(["EventEmitter", "EventEmitterAsyncResource", "default"]).has(
      ownerExportName,
    )
  ) {
    return null;
  }
  if (
    ownerExportName === "EventEmitterAsyncResource" &&
    methodName === "constructor"
  ) {
    return constructTarget([jsonArgument("ibex-probe")]);
  }
  const method = ownValue(EVENT_EMITTER_METHOD_SPECS, methodName);
  if (!method) return null;
  const constructorArguments =
    ownerExportName === "EventEmitterAsyncResource"
      ? [jsonArgument("ibex-probe")]
      : [];
  return constructedOwner(
    ownerExportName,
    method[0],
    method[1],
    constructorArguments,
  );
}

const BUFFER_METHOD_SPECS = Object.freeze({
  _toByteString: [[jsonArgument("utf8")], "string"],
  asciiSlice: [[jsonArgument(0), jsonArgument(8)], "string"],
  asciiWrite: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(1)],
    "number",
  ],
  base64Slice: [[jsonArgument(0), jsonArgument(8)], "string"],
  base64Write: [
    [jsonArgument("YQ=="), jsonArgument(0), jsonArgument(1)],
    "number",
  ],
  base64urlSlice: [[jsonArgument(0), jsonArgument(8)], "string"],
  base64urlWrite: [
    [jsonArgument("YQ"), jsonArgument(0), jsonArgument(1)],
    "number",
  ],
  compare: [[bufferArgument([0, 1, 2, 3, 4, 5, 6, 7])], "number"],
  copy: [
    [
      bufferArgument([0, 0, 0, 0, 0, 0, 0, 0]),
      jsonArgument(0),
      jsonArgument(0),
      jsonArgument(8),
    ],
    "number",
  ],
  equals: [[bufferArgument([0, 1, 2, 3, 4, 5, 6, 7])], "boolean"],
  fill: [[jsonArgument(1), jsonArgument(0), jsonArgument(8)], "object"],
  hexSlice: [[jsonArgument(0), jsonArgument(8)], "string"],
  hexWrite: [
    [jsonArgument("61"), jsonArgument(0), jsonArgument(1)],
    "number",
  ],
  includes: [[jsonArgument(1)], "boolean"],
  indexOf: [[jsonArgument(1)], "number"],
  inspect: [[], "string"],
  lastIndexOf: [[jsonArgument(1)], "number"],
  latin1Slice: [[jsonArgument(0), jsonArgument(8)], "string"],
  latin1Write: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(1)],
    "number",
  ],
  readBigInt64BE: [[jsonArgument(0)], "bigint"],
  readBigInt64LE: [[jsonArgument(0)], "bigint"],
  readBigUInt64BE: [[jsonArgument(0)], "bigint"],
  readBigUInt64LE: [[jsonArgument(0)], "bigint"],
  readDoubleBE: [[jsonArgument(0)], "number"],
  readDoubleLE: [[jsonArgument(0)], "number"],
  readFloatBE: [[jsonArgument(0)], "number"],
  readFloatLE: [[jsonArgument(0)], "number"],
  readInt16BE: [[jsonArgument(0)], "number"],
  readInt16LE: [[jsonArgument(0)], "number"],
  readInt32BE: [[jsonArgument(0)], "number"],
  readInt32LE: [[jsonArgument(0)], "number"],
  readInt8: [[jsonArgument(0)], "number"],
  readIntBE: [[jsonArgument(0), jsonArgument(6)], "number"],
  readIntLE: [[jsonArgument(0), jsonArgument(6)], "number"],
  readUInt16BE: [[jsonArgument(0)], "number"],
  readUInt16LE: [[jsonArgument(0)], "number"],
  readUInt32BE: [[jsonArgument(0)], "number"],
  readUInt32LE: [[jsonArgument(0)], "number"],
  readUInt8: [[jsonArgument(0)], "number"],
  readUIntBE: [[jsonArgument(0), jsonArgument(6)], "number"],
  readUIntLE: [[jsonArgument(0), jsonArgument(6)], "number"],
  slice: [[jsonArgument(0), jsonArgument(4)], "object"],
  subarray: [[jsonArgument(0), jsonArgument(4)], "object"],
  swap16: [[], "object"],
  swap32: [[], "object"],
  swap64: [[], "object"],
  toJSON: [[], "object"],
  toString: [
    [jsonArgument("utf8"), jsonArgument(0), jsonArgument(8)],
    "string",
  ],
  ucs2Slice: [[jsonArgument(0), jsonArgument(8)], "string"],
  ucs2Write: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(2)],
    "number",
  ],
  utf16beWrite: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(2)],
    "number",
  ],
  utf16leWrite: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(2)],
    "number",
  ],
  utf8Slice: [[jsonArgument(0), jsonArgument(8)], "string"],
  utf8Write: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(1)],
    "number",
  ],
  write: [
    [
      jsonArgument("a"),
      jsonArgument(0),
      jsonArgument(1),
      jsonArgument("utf8"),
    ],
    "number",
  ],
  writeBigInt64BE: [[bigintArgument(-1), jsonArgument(0)], "number"],
  writeBigInt64LE: [[bigintArgument(-1), jsonArgument(0)], "number"],
  writeBigUInt64BE: [[bigintArgument(1), jsonArgument(0)], "number"],
  writeBigUInt64LE: [[bigintArgument(1), jsonArgument(0)], "number"],
  writeDoubleBE: [[jsonArgument(1.5), jsonArgument(0)], "number"],
  writeDoubleLE: [[jsonArgument(1.5), jsonArgument(0)], "number"],
  writeFloatBE: [[jsonArgument(1.5), jsonArgument(0)], "number"],
  writeFloatLE: [[jsonArgument(1.5), jsonArgument(0)], "number"],
  writeInt16BE: [[jsonArgument(-1), jsonArgument(0)], "number"],
  writeInt16LE: [[jsonArgument(-1), jsonArgument(0)], "number"],
  writeInt32BE: [[jsonArgument(-1), jsonArgument(0)], "number"],
  writeInt32LE: [[jsonArgument(-1), jsonArgument(0)], "number"],
  writeInt8: [[jsonArgument(-1), jsonArgument(0)], "number"],
  writeIntBE: [
    [jsonArgument(-1), jsonArgument(0), jsonArgument(6)],
    "number",
  ],
  writeIntLE: [
    [jsonArgument(-1), jsonArgument(0), jsonArgument(6)],
    "number",
  ],
  writeUInt16BE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt16LE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt32BE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt32LE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt8: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUIntBE: [
    [jsonArgument(1), jsonArgument(0), jsonArgument(6)],
    "number",
  ],
  writeUIntLE: [
    [jsonArgument(1), jsonArgument(0), jsonArgument(6)],
    "number",
  ],
});

const BUFFER_METHOD_ALIASES = Object.freeze({
  readBigUint64BE: "readBigUInt64BE",
  readBigUint64LE: "readBigUInt64LE",
  readUint16BE: "readUInt16BE",
  readUint16LE: "readUInt16LE",
  readUint32BE: "readUInt32BE",
  readUint32LE: "readUInt32LE",
  readUint8: "readUInt8",
  readUintBE: "readUIntBE",
  readUintLE: "readUIntLE",
  toLocaleString: "toString",
  writeBigUint64BE: "writeBigUInt64BE",
  writeBigUint64LE: "writeBigUInt64LE",
  writeUint16BE: "writeUInt16BE",
  writeUint16LE: "writeUInt16LE",
  writeUint32BE: "writeUInt32BE",
  writeUint32LE: "writeUInt32LE",
  writeUint8: "writeUInt8",
  writeUintBE: "writeUIntBE",
  writeUintLE: "writeUIntLE",
});

function bufferPrototypeSpec(exportName) {
  const [ownerExportName, methodName] = exportName.split(".");
  if (
    !new Set(["Buffer", "SlowBuffer"]).has(ownerExportName) ||
    !methodName ||
    exportName.split(".").length !== 2
  ) {
    return null;
  }
  const canonicalMethodName =
    ownValue(BUFFER_METHOD_ALIASES, methodName) ?? methodName;
  const method = ownValue(BUFFER_METHOD_SPECS, canonicalMethodName);
  if (!method) return null;
  return callSpec(
    {
      kind: "buffer-owner",
      ownerExportName,
      bytes: [0, 1, 2, 3, 4, 5, 6, 7],
    },
    method[0],
    method[1],
  );
}

function zlibOwnerCall(
  ownerExportName,
  arguments_,
  resultType,
  ensureNativeStream = false,
) {
  return callSpec(
    {
      kind: "zlib-owner",
      ownerExportName,
      ensureNativeStream,
    },
    arguments_,
    resultType,
  );
}

function zlibPrototypeSpec(exportName) {
  const segments = exportName.split(".");
  if (segments.length !== 2 || !ZLIB_OWNER_SET.has(segments[0])) return null;
  const [ownerExportName, methodName] = segments;
  if (methodName === "constructor") return constructTarget([]);
  if (methodName === "_closeNativeStream") {
    return zlibOwnerCall(ownerExportName, [], "undefined");
  }
  if (methodName === "_destroy") {
    return zlibOwnerCall(
      ownerExportName,
      [jsonArgument(null), noopArgument()],
      "undefined",
    );
  }
  if (methodName === "_ensureNativeStream") {
    return zlibOwnerCall(ownerExportName, [], "boolean");
  }
  if (methodName === "_flush") {
    return zlibOwnerCall(ownerExportName, [noopArgument()], "undefined");
  }
  if (methodName === "_processChunk") {
    if (ownerExportName.startsWith("Zstd")) return null;
    return zlibOwnerCall(
      ownerExportName,
      [zlibInputArgument(ownerExportName), jsonArgument(4)],
      "object",
    );
  }
  if (methodName === "_pushNativeOutput") {
    return zlibOwnerCall(
      ownerExportName,
      [uint8ArrayArgument([105, 98, 101, 120])],
      "object",
    );
  }
  if (methodName === "_transform") {
    return zlibOwnerCall(
      ownerExportName,
      [
        zlibInputArgument(ownerExportName),
        jsonArgument("utf8"),
        noopArgument(),
      ],
      "undefined",
    );
  }
  if (methodName === "_writeNative") {
    if (!ZLIB_NATIVE_OWNER_SET.has(ownerExportName)) return null;
    return zlibOwnerCall(
      ownerExportName,
      [
        zlibInputArgument(ownerExportName),
        jsonArgument(0),
        jsonArgument(false),
      ],
      "object",
      true,
    );
  }
  if (methodName === "close") {
    return zlibOwnerCall(ownerExportName, [noopArgument()], "object");
  }
  if (methodName === "flush") {
    return zlibOwnerCall(ownerExportName, [noopArgument()], "object");
  }
  if (methodName === "params") {
    return zlibOwnerCall(
      ownerExportName,
      [jsonArgument(-1), jsonArgument(0), noopArgument()],
      "object",
    );
  }
  if (methodName === "reset") {
    return zlibOwnerCall(ownerExportName, [], "object");
  }
  if (methodName === "setEncoding") {
    return zlibOwnerCall(
      ownerExportName,
      [jsonArgument("utf8")],
      "object",
    );
  }
  if (methodName === "write") {
    return zlibOwnerCall(
      ownerExportName,
      [zlibInputArgument(ownerExportName), noopArgument()],
      "boolean",
    );
  }
  return null;
}

function streamOwnerCall(
  ownerExportName,
  arguments_,
  resultType,
  endedInput = false,
) {
  return callSpec(
    {
      kind: "stream-owner",
      ownerExportName,
      endedInput,
    },
    arguments_,
    resultType,
  );
}

function streamPrototypeSpec(exportName) {
  const segments = exportName.split(".");
  if (segments.length !== 2 || !STREAM_OWNER_SET.has(segments[0])) return null;
  const [ownerExportName, methodName] = segments;
  // node:stream is itself the default Stream export; it does not expose a
  // `default.prototype` property at runtime. The inventory's module-value
  // alias is exact for the root constructor but not for prototype traversal.
  if (ownerExportName === "default") return null;
  // Duplex copies Writable prototype descriptors dynamically. Until that
  // copy idiom is represented by the inventory, its inherited _undestroy
  // descriptor would deliberately fail the exact own/inherited access check.
  if (ownerExportName === "Duplex" && methodName === "_undestroy") return null;
  if (methodName === "constructor") return constructTarget([]);
  if (methodName === "_close") {
    return streamOwnerCall(ownerExportName, [jsonArgument(true)], "undefined");
  }
  if (methodName === "_emitClose" || methodName === "_undestroy") {
    return streamOwnerCall(ownerExportName, [], "undefined");
  }
  if (methodName === "destroy") {
    return streamOwnerCall(ownerExportName, [], "object");
  }
  if (methodName === "pipe") {
    if (ownerExportName === "Writable") return null;
    return streamOwnerCall(
      ownerExportName,
      [streamInstanceArgument("Writable")],
      "object",
    );
  }
  if (methodName === "unpipe") {
    return streamOwnerCall(ownerExportName, [], "object");
  }
  if (STREAM_READABLE_OWNER_SET.has(ownerExportName)) {
    if (
      new Set([
        "_emitReadableIfNeeded",
        "_read",
        "_readFromSource",
        "_syncReadableState",
      ]).has(methodName)
    ) {
      const arguments_ = new Set(["_read", "_readFromSource"]).has(methodName)
        ? [jsonArgument(0)]
        : [];
      return streamOwnerCall(ownerExportName, arguments_, "undefined");
    }
    if (methodName === "_updateReadableLength") {
      return streamOwnerCall(ownerExportName, [jsonArgument(0)], "undefined");
    }
    // Like the root helper, the prototype compose() call leaves an
    // asynchronously-owned pipeline behind after its normal return.
    if (methodName === "compose") return null;
    if (methodName === "drop") {
      return streamOwnerCall(ownerExportName, [jsonArgument(0)], "object");
    }
    if (methodName === "emit") {
      return streamOwnerCall(
        ownerExportName,
        [jsonArgument("ibex")],
        "boolean",
      );
    }
    if (methodName === "filter") {
      return streamOwnerCall(
        ownerExportName,
        [constantFunctionArgument(true)],
        "object",
      );
    }
    if (methodName === "flatMap") {
      return streamOwnerCall(
        ownerExportName,
        [constantFunctionArgument([])],
        "object",
      );
    }
    if (methodName === "isPaused") {
      return streamOwnerCall(ownerExportName, [], "boolean");
    }
    if (methodName === "iterator") {
      return streamOwnerCall(ownerExportName, [], "object");
    }
    if (methodName === "map") {
      return streamOwnerCall(
        ownerExportName,
        [constantFunctionArgument("ibex")],
        "object",
      );
    }
    if (methodName === "on") {
      return streamOwnerCall(
        ownerExportName,
        [jsonArgument("ibex"), noopArgument()],
        "object",
      );
    }
    if (methodName === "pause") {
      return streamOwnerCall(ownerExportName, [], "object");
    }
    if (methodName === "push" || methodName === "unshift") {
      return streamOwnerCall(ownerExportName, [jsonArgument("")], "boolean");
    }
    if (methodName === "read") {
      return streamOwnerCall(ownerExportName, [jsonArgument(0)], "null");
    }
    if (methodName === "resume") {
      return streamOwnerCall(ownerExportName, [], "object", true);
    }
    if (methodName === "setEncoding") {
      return streamOwnerCall(ownerExportName, [jsonArgument("utf8")], "object");
    }
    if (methodName === "take") {
      return streamOwnerCall(ownerExportName, [jsonArgument(1)], "object");
    }
    // Promise-returning consumers and wrap() retain source work after this
    // synchronous harness returns. Leave them residual until an awaited,
    // resource-draining recipe can prove completion inside one observation.
    if (STREAM_DEFERRED_METHOD_SET.has(methodName)) {
      return null;
    }
  }
  if (methodName === "_transform" && ownerExportName === "PassThrough") {
    return streamOwnerCall(
      ownerExportName,
      [jsonArgument("ibex"), jsonArgument("utf8"), noopArgument()],
      "undefined",
    );
  }
  if (
    methodName === "_write" &&
    new Set(["PassThrough", "Transform"]).has(ownerExportName)
  ) {
    return streamOwnerCall(
      ownerExportName,
      [jsonArgument("ibex"), jsonArgument("utf8"), noopArgument()],
      "undefined",
    );
  }
  if (ownerExportName === "Writable") {
    if (methodName === "_flushWriteQueue") {
      return streamOwnerCall(ownerExportName, [], "undefined");
    }
    if (methodName === "cork" || methodName === "uncork") {
      return streamOwnerCall(ownerExportName, [], "undefined");
    }
    if (methodName === "end") {
      return streamOwnerCall(ownerExportName, [noopArgument()], "object");
    }
    if (methodName === "setDefaultEncoding") {
      return streamOwnerCall(ownerExportName, [jsonArgument("utf8")], "object");
    }
    if (methodName === "write") {
      return streamOwnerCall(
        ownerExportName,
        [jsonArgument("ibex"), noopArgument()],
        "boolean",
      );
    }
  }
  return null;
}

const CALL_TEMPLATE_IDS = Object.freeze({
  exact_crypto: "exact-crypto-bounded-v1",
  node_assert: "node-assert-bounded-v1",
  node_buffer: "node-buffer-bounded-v1",
  node_events: "node-events-bounded-v1",
  node_module: "node-module-pure-v1",
  node_net: "node-net-bounded-v1",
  node_perf_hooks: "node-perf-hooks-bounded-v1",
  node_path: "node-path-pure-v1",
  node_punycode: "node-punycode-pure-v1",
  node_querystring: "node-querystring-pure-v1",
  node_stream: "node-stream-bounded-v1",
  node_string_decoder: "node-string-decoder-bounded-v1",
  node_url: "node-url-pure-v1",
  node_util: "node-util-pure-v1",
  node_zlib: "node-zlib-bounded-v1",
  node_v8: "node-v8-pure-v1",
});

function callTemplateFor(descriptor) {
  const sourceRootSpecs = ownValue(ROOT_CALL_SPECS, descriptor.sourceKey);
  const rootSpec = ownValue(sourceRootSpecs, descriptor.exportName);
  let spec = rootSpec ?? null;
  if (!spec && descriptor.sourceKey === "node_assert") {
    spec = ownValue(ASSERT_PROTOTYPE_SPECS, descriptor.exportName);
  }
  if (!spec && descriptor.sourceKey === "node_events") {
    spec = eventPrototypeSpec(descriptor.exportName);
  }
  if (!spec && descriptor.sourceKey === "node_buffer") {
    spec = bufferPrototypeSpec(descriptor.exportName);
  }
  if (!spec && descriptor.sourceKey === "node_zlib") {
    spec = zlibPrototypeSpec(descriptor.exportName);
  }
  if (!spec && descriptor.sourceKey === "node_stream") {
    spec = streamPrototypeSpec(descriptor.exportName);
  }
  const templateId = ownValue(CALL_TEMPLATE_IDS, descriptor.sourceKey);
  if (!spec || !templateId) return null;

  const prototypeAccess = new Set([
    "prototype-property",
    "inherited-prototype-property",
  ]).has(descriptor.access.kind);
  const setupKind = spec.setup.kind;
  if (
    (prototypeAccess &&
      !new Set([
        "buffer-owner",
        "call-tracker-owner",
        "construct-target",
        "constructed-owner",
        "zlib-owner",
        "stream-owner",
      ]).has(setupKind)) ||
    (!prototypeAccess &&
      !new Set(["construct-target", "root-call"]).has(setupKind))
  ) {
    return null;
  }
  return {
    templateId,
    setup: spec.setup,
    arguments: spec.arguments,
    bodyEntryProof: {
      kind: "normal-return-from-source-call",
      resultType: spec.resultType,
    },
  };
}

const PROTOTYPE_IDIOMS = new Set([
  "exported-constructor-prototype",
  "exported-constructor-inherited-prototype",
]);
const KNOWN_PLATFORMS = new Set(["android", "darwin", "linux"]);
// These modules perform capability-bearing work while their body initializes
// on the bound runtime. Their otherwise scalar exports cannot use a generic
// zero-decision import-and-read recipe.
const NONCAP_GENERIC_EXPORT_EXCLUSIONS = new Set([
  "node_cluster",
  "node_http",
  "node_os",
]);

// Windows installs the deliberately smaller crypto module authored by
// makeWindowsCryptoModule() in the bootstrap loader; it does not evaluate the
// full src/builtins/crypto.js export object. Keep source-union exports residual
// unless their root is present in that target implementation.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const WINDOWS_CRYPTO_EXPORT_ROOTS = new Set([
  "Hash",
  "Hmac",
  "createHash",
  "createHmac",
  "default",
  "getHashes",
  "getRandomValues",
  "hash",
  "randomBytes",
  "randomFill",
  "randomFillSync",
  "randomUUID",
  "subtle",
  "timingSafeEqual",
  "webcrypto",
]);
const WINDOWS_CRYPTO_MEMBER_EXPORTS = new Set([
  "Hash.constructor",
  "Hash.copy",
  "Hash.digest",
  "Hash.update",
  "Hmac.constructor",
  "Hmac.digest",
  "Hmac.update",
]);
const WINDOWS_ZLIB_CONSTRUCTION_EXPORTS = new Set([
  "crc32",
  ...ZLIB_OWNER_NAMES,
  ...ZLIB_OWNER_NAMES.map((owner) => `create${owner}`),
  ...ZLIB_OWNER_NAMES.map((owner) => `${owner}.constructor`),
]);

function targetSourceUnavailableReason(surface, target) {
  const triple =
    typeof target === "string"
      ? target
      : typeof target?.triple === "string"
        ? target.triple
        : null;
  const metadata = surface?.metadata;
  if (
    !triple?.includes("-windows-") ||
    metadata?.sourceKey !== "exact_crypto" ||
    typeof metadata.exportName !== "string"
  ) {
    return null;
  }
  const rootExportName = metadata.exportName.split(".")[0];
  const installed = metadata.exportName.includes(".")
    ? WINDOWS_CRYPTO_MEMBER_EXPORTS.has(metadata.exportName)
    : WINDOWS_CRYPTO_EXPORT_ROOTS.has(rootExportName);
  return installed ? null : "builtin-export-not-installed-on-target";
}

function targetCallUnavailableReason(surface, target) {
  const triple =
    typeof target === "string"
      ? target
      : typeof target?.triple === "string"
        ? target.triple
        : null;
  const metadata = surface?.metadata;
  if (
    !triple?.includes("-windows-") ||
    metadata?.sourceKey !== "node_zlib" ||
    metadata.valueShape !== "callable" ||
    typeof metadata.exportName !== "string" ||
    WINDOWS_ZLIB_CONSTRUCTION_EXPORTS.has(metadata.exportName)
  ) {
    return null;
  }
  // The JS module is installed on Windows, but its native deflate, Brotli,
  // Zstd, and stream bridges are not. Constructors remain valid public
  // no-decision evidence; exercising backend-dependent methods does not.
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
  return "builtin-call-backend-not-installed-on-target";
}

function platformForTarget(target) {
  const triple =
    typeof target === "string"
      ? target
      : typeof target?.triple === "string"
        ? target.triple
        : null;
  if (!triple) return null;
  if (triple.includes("android")) return "android";
  if (triple.includes("apple-darwin")) return "darwin";
  if (triple.includes("linux")) return "linux";
  return null;
}

function platformAvailability(metadata) {
  const availability = metadata?.platformAvailability;
  if (availability === undefined) return null;
  if (
    !Array.isArray(availability) ||
    availability.length === 0 ||
    !availability.every((platform) => KNOWN_PLATFORMS.has(platform)) ||
    canonicalJson(availability) !== canonicalJson(canonicalSet(availability))
  ) {
    return false;
  }
  return availability;
}

function canonicalModuleSpecifier(specifiers) {
  const ranked = canonicalSet(specifiers).sort((left, right) => {
    const rank = (value) =>
      value.startsWith("node:")
        ? 0
        : value.startsWith("exact:")
          ? 1
          : value.startsWith("bun:")
            ? 2
            : value.startsWith("internal/")
              ? 3
              : 4;
    return rank(left) - rank(right) || compareText(left, right);
  });
  return ranked[0] ?? null;
}

function exportAccess(exportName, exportIdioms) {
  if (exportName.includes("[[") || exportName.includes("]]")) return null;
  const segments = exportName.split(".");
  if (segments.some((segment) => segment.length === 0)) return null;
  const prototype = exportIdioms.filter((idiom) => PROTOTYPE_IDIOMS.has(idiom));
  if (prototype.length > 0) {
    if (prototype.length !== exportIdioms.length || segments.length < 2) {
      return null;
    }
    return {
      kind:
        prototype[0] === "exported-constructor-inherited-prototype"
          ? "inherited-prototype-property"
          : "prototype-property",
      path: [segments[0], "prototype", ...segments.slice(1)],
    };
  }
  if (
    exportName === "default" &&
    exportIdioms.includes("module-exports-assignment")
  ) {
    return { kind: "module-value", path: [] };
  }
  return { kind: "export-property", path: segments };
}

function sourceDescriptor(
  surface,
  target,
  allowedValueShapes,
  { allowTargetAbsence = false } = {},
) {
  const metadata = surface?.metadata;
  const availability = platformAvailability(metadata);
  const targetPlatform = platformForTarget(target);
  if (
    metadata?.surfaceType !== "export" ||
    metadata.importReachability !== "public" ||
    typeof metadata.sourceKey !== "string" ||
    metadata.sourceKey.length === 0 ||
    NONCAP_GENERIC_EXPORT_EXCLUSIONS.has(metadata.sourceKey) ||
    !allowedValueShapes.has(metadata.valueShape) ||
    typeof metadata.exportName !== "string" ||
    metadata.exportName.length === 0 ||
    !Array.isArray(metadata.exportIdioms) ||
    metadata.exportIdioms.length === 0 ||
    canonicalJson(metadata.exportIdioms) !==
      canonicalJson(canonicalSet(metadata.exportIdioms)) ||
    !Array.isArray(metadata.publicModuleSpecifiers) ||
    metadata.publicModuleSpecifiers.length === 0 ||
    !metadata.publicModuleSpecifiers.every(
      (specifier) => typeof specifier === "string" && specifier.length > 0,
    ) ||
    canonicalJson(metadata.publicModuleSpecifiers) !==
      canonicalJson(canonicalSet(metadata.publicModuleSpecifiers)) ||
    availability === false ||
    (!allowTargetAbsence &&
      availability &&
      (!targetPlatform || !availability.includes(targetPlatform))) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1
  ) {
    return null;
  }
  const expectedObservedKey = `builtin:export:${metadata.sourceKey}:${metadata.exportName}`;
  if (surface.observedKey !== expectedObservedKey) return null;
  const access = exportAccess(metadata.exportName, metadata.exportIdioms);
  const moduleSpecifier = canonicalModuleSpecifier(
    metadata.publicModuleSpecifiers,
  );
  if (!access || !moduleSpecifier) {
    return null;
  }
  const descriptor = {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: [...metadata.publicModuleSpecifiers],
    sourceRef: surface.sourceRefs[0],
    valueShape: metadata.valueShape,
    access,
  };
  if (availability) descriptor.platformAvailability = [...availability];
  return descriptor;
}

export function authoredNonCapabilityBuiltinProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  target,
}) {
  if (
    plan.classification !== "non-capability" ||
    scenario !== "non-capability" ||
    plan.actionIds.length !== 0 ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const alternative = route.alternatives[0];
  if (
    alternative.terminalObservedKey !== surfaceObservedKey ||
    !Array.isArray(alternative.proofPaths) ||
    alternative.proofPaths.length === 0
  ) {
    return null;
  }
  const surface = liveByObservedKey.get(surfaceObservedKey);
  if (!surfaceObservedKey.startsWith("builtin:export:")) {
    return null;
  }
  if (
    targetSourceUnavailableReason(surface, target) ||
    targetCallUnavailableReason(surface, target)
  ) {
    return null;
  }
  const availability = platformAvailability(surface?.metadata);
  const targetPlatform = platformForTarget(target);
  const targetAbsent =
    Array.isArray(availability) &&
    targetPlatform !== null &&
    !availability.includes(targetPlatform);
  const readDescriptor = sourceDescriptor(
    surface,
    target,
    new Set(["accessor", "data"]),
    { allowTargetAbsence: targetAbsent },
  );
  const readEligible =
    readDescriptor &&
    new Set(["export-property", "module-value"]).has(
      readDescriptor.access.kind,
    ) &&
    (readDescriptor.valueShape !== "accessor" ||
      readDescriptor.access.kind === "export-property");
  const callDescriptor = readEligible
    ? null
    : sourceDescriptor(surface, target, new Set(["callable"]));
  const callTemplate = callDescriptor
    ? callTemplateFor(callDescriptor)
    : null;
  const descriptor = readEligible ? readDescriptor : callDescriptor;
  if (!descriptor || (!readEligible && !callTemplate)) return null;
  const moduleSpecifier = canonicalModuleSpecifier(descriptor.moduleSpecifiers);
  if (readEligible) {
    return {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: [...BUILTIN_BATCH_COMMAND],
      invocation: {
        invocationSchema: READ_INVOCATION_SCHEMA,
        kind: "builtin-export-read",
        moduleSpecifier,
        exportName: descriptor.exportName,
        sourceDescriptor: descriptor,
        sourceDescriptorDigest: taggedDigest(descriptor),
        arguments: [],
        setup: { kind: "none" },
        completion: { ...EVENT_LOOP_COMPLETION },
        requiredAuthority: [],
        expectedResult: targetAbsent ? "absent" : "return",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    };
  }
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...BUILTIN_BATCH_COMMAND],
    invocation: {
      invocationSchema: CALL_INVOCATION_SCHEMA,
      kind: "builtin-export-call",
      moduleSpecifier,
      exportName: descriptor.exportName,
      sourceDescriptor: descriptor,
      sourceDescriptorDigest: taggedDigest(descriptor),
      templateId: callTemplate.templateId,
      arguments: callTemplate.arguments,
      setup: callTemplate.setup,
      bodyEntryProof: callTemplate.bodyEntryProof,
      completion: { ...EVENT_LOOP_COMPLETION },
      requiredAuthority: [],
      expectedResult: "normal-return",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

export function nonCapabilityBuiltinProbeResidualReason({
  route,
  liveByObservedKey,
  target,
}) {
  if (route.surfaceObservedKeys.length !== 1) return null;
  const surface = liveByObservedKey.get(route.surfaceObservedKeys[0]);
  if (
    surface?.metadata?.surfaceType === "export" &&
    surface.metadata.importReachability === "bootstrap-internal"
  ) {
    return "builtin-export-resolves-to-bootstrap-internal";
  }
  if (
    surface?.metadata?.surfaceType === "export" &&
    surface.metadata.importReachability === "private-manifest"
  ) {
    return "builtin-export-not-publicly-importable";
  }
  const targetUnavailable = targetSourceUnavailableReason(surface, target);
  if (targetUnavailable) return targetUnavailable;
  const targetCallUnavailable = targetCallUnavailableReason(surface, target);
  if (targetCallUnavailable) return targetCallUnavailable;
  const availability = platformAvailability(surface?.metadata);
  const targetPlatform = platformForTarget(target);
  if (
    availability &&
    targetPlatform &&
    !availability.includes(targetPlatform)
  ) {
    return "builtin-export-not-available-on-target";
  }
  return null;
}
