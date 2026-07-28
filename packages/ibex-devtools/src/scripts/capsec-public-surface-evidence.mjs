/**
 * Validate content-addressed evidence that every exact-target recipe invoked
 * its authored public surface and observed the selected enforcement terminal.
 * Typed-adapter probes are deliberately a different schema and are never
 * accepted here.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * target promotion requires executed public obligations, not adapter checks.
 */

import crypto from "node:crypto";
import path from "node:path";
import {
  assertRecipeCatalogComplete,
  validateRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { reviewedPublicSurfaceExecutorDescriptor } from "./capsec-public-executors.mjs";
import {
  canonicalJson,
  capsecRoot,
  readJsonStrict,
} from "./capsec-contract.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const builtinCacheSourceId = (sourceKey) =>
  `ibex-source-id-v1:${Buffer.from(
    canonicalJson({
      kind: "builtin",
      key: sourceKey,
      sourceIdSchema: "ibex.source-id.v1",
    }),
    "utf8",
  ).toString("base64url")}`;
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value), "utf8")
    .digest("base64url")}`;
const SEMANTIC_REGISTRY_IDENTITY = (() => {
  const registryBundle = readJsonStrict(
    path.join(capsecRoot, "examples/registry-digest-bundle.canonical.json"),
  );
  const digestVectors = readJsonStrict(
    path.join(capsecRoot, "examples/digest-vectors.canonical.json"),
  );
  const vocabDigest = registryBundle.members?.find(
    (member) => member.logicalName === "vocab-digest",
  )?.document?.digest;
  const registryDigest = digestVectors.vectors?.find(
    (vector) => vector.id === "registry",
  )?.expectedDigest;
  if (
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(vocabDigest ?? "") ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(registryDigest ?? "")
  ) {
    throw new Error("public evidence semantic digest identities are unavailable");
  }
  return Object.freeze({ vocabDigest, registryDigest });
})();
const ROOT_GLOBAL_DISPOSITIONS = (() => {
  const manifest = readJsonStrict(
    path.join(
      capsecRoot,
      "generated/root-global-disposition-manifest.json",
    ),
  );
  if (
    manifest?.rootGlobalDispositionManifestSchema !==
      "ibex/root-global-disposition-manifest/1" ||
    !Array.isArray(manifest.rows)
  ) {
    throw new Error("root-global disposition manifest is unavailable");
  }
  return manifest.rows;
})();
const rootGlobalDispositionByInstallId = (installId) => {
  const matches = ROOT_GLOBAL_DISPOSITIONS.filter(
    (row) => row.installId === installId,
  );
  return matches.length === 1 ? matches[0] : null;
};
const BUILTIN_RUNTIME_INVOCATION_SCHEMAS = new Set([
  "ibex/capsec-builtin-export-invocation/1",
  "ibex/capsec-builtin-call-invocation/1",
]);
const REVIEWED_DNS_PROMISE_ERROR_CODES = new Set([
  "ADDRGETNETWORKPARAMS",
  "BADFAMILY",
  "BADFLAGS",
  "BADHINTS",
  "BADNAME",
  "BADQUERY",
  "BADRESP",
  "BADSTR",
  "CANCELLED",
  "CONNREFUSED",
  "DESTRUCTION",
  "EOF",
  "FILE",
  "FORMERR",
  "LOADIPHLPAPI",
  "NODATA",
  "NOMEM",
  "NONAME",
  "NOTFOUND",
  "NOTIMP",
  "NOTINITIALIZED",
  "REFUSED",
  "SERVFAIL",
  "TIMEOUT",
]);
const REVIEWED_POST_INITIALIZATION_VALUE_EXPORTS = new Map(
  [
    ["node_cluster", "SCHED_NONE", "data", "number", ["member-assignment"], ["cluster", "node:cluster"], "src/builtins/cluster.js#exports:SCHED_NONE"],
    ["node_cluster", "SCHED_RR", "data", "number", ["member-assignment"], ["cluster", "node:cluster"], "src/builtins/cluster.js#exports:SCHED_RR"],
    ["node_cluster", "isMaster", "data", "boolean", ["member-assignment"], ["cluster", "node:cluster"], "src/builtins/cluster.js#exports:isMaster"],
    ["node_cluster", "isPrimary", "data", "boolean", ["member-assignment"], ["cluster", "node:cluster"], "src/builtins/cluster.js#exports:isPrimary"],
    ["node_cluster", "isWorker", "unknown", "boolean", ["member-assignment"], ["cluster", "node:cluster"], "src/builtins/cluster.js#exports:isWorker"],
    ["node_http", "METHODS", "data", "object", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:METHODS"],
    ["node_http", "STATUS_CODES", "data", "object", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:STATUS_CODES"],
    ["node_http", "kConnectionsCheckingInterval", "unknown", "symbol", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:kConnectionsCheckingInterval"],
    ["node_http", "kHighWaterMark", "unknown", "symbol", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:kHighWaterMark"],
    ["node_http", "kTimeout", "unknown", "symbol", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:kTimeout"],
    ["node_http", "maxHeaderSize", "unknown", "number", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:maxHeaderSize"],
    ["node_http", "methods", "data", "object", ["module-exports-object"], ["_http_agent", "_http_common", "_http_incoming", "_http_outgoing", "_http_server", "http", "node:http"], "src/builtins/http.js#exports:methods"],
    ["node_os", "EOL", "data", "string", ["define-property"], ["node:os", "os"], "src/builtins/os.js#exports:EOL"],
    ["node_os", "constants", "data", "object", ["module-exports-object"], ["node:os", "os"], "src/builtins/os.js#exports:constants"],
    ["node_os", "devNull", "data", "string", ["module-exports-object"], ["node:os", "os"], "src/builtins/os.js#exports:devNull"],
    ["exact_crypto", "subtle", "unknown", "object", ["object-binding", "object-source"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:subtle"],
    ["exact_crypto", "webcrypto", "unknown", "object", ["object-binding", "object-source"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:webcrypto"],
    ["node_console", "default", "unknown", "object", ["module-exports-assignment"], ["console", "node:console"], "src/builtins/console.js#exports:default"],
    ["node_events", "captureRejectionSymbol", "unknown", "symbol", ["member-assignment"], ["events", "node:events"], "src/builtins/events.js#exports:captureRejectionSymbol"],
    ["node_events", "errorMonitor", "unknown", "symbol", ["member-assignment"], ["events", "node:events"], "src/builtins/events.js#exports:errorMonitor"],
    ["node_fs", "constants", "unknown", "object", ["module-exports-object"], ["bun:fs", "fs", "node:fs"], "src/builtins/fs.js#exports:constants"],
    ["node_fs_promises", "constants", "unknown", "object", ["object-binding", "object-source"], ["bun:fs/promises", "fs/promises", "internal/fs/promises", "node:fs/promises"], "src/builtins/fs-promises.js#exports:constants"],
    ["node_http2", "sensitiveHeaders", "unknown", "symbol", ["module-exports-object"], ["http2", "node:http2"], "src/builtins/http2.js#exports:sensitiveHeaders"],
    ["node_module", "builtinModules", "unknown", "object", ["member-assignment", "object-binding", "object-source"], ["module", "node:module"], "src/builtins/module.js#exports:builtinModules"],
    ["node_dns", "default", "unknown", "object", ["member-assignment", "module-exports-assignment"], ["dns", "node:dns"], "src/builtins/dns.js#exports:default"],
    ["node_dns_promises", "default", "unknown", "object", ["module-exports-assignment"], ["dns/promises", "node:dns/promises"], "src/builtins/dns-promises.js#exports:default"],
    ["node_perf_hooks", "performance", "unknown", "object", ["module-exports-object"], ["node:perf_hooks", "perf_hooks"], "src/builtins/perf-hooks.js#exports:performance"],
    ["node_stream_web", "ByteLengthQueuingStrategy", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ByteLengthQueuingStrategy"],
    ["node_stream_web", "CountQueuingStrategy", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:CountQueuingStrategy"],
    ["node_stream_web", "ReadableStream", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ReadableStream"],
    ["node_stream_web", "ReadableStreamBYOBReader", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ReadableStreamBYOBReader"],
    ["node_stream_web", "ReadableStreamDefaultReader", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ReadableStreamDefaultReader"],
    ["node_stream_web", "TransformStream", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:TransformStream"],
    ["node_stream_web", "WritableStream", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:WritableStream"],
    ["node_stream_web", "WritableStreamDefaultWriter", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:WritableStreamDefaultWriter"],
    ["node_timers_promises", "scheduler", "unknown", "object", ["module-exports-object"], ["node:timers/promises", "timers/promises"], "src/builtins/timers-promises.js#exports:scheduler"],
    ["path_posix_alias", "default", "unknown", "object", ["module-exports-assignment"], ["node:path/posix", "path/posix"], "modules.ts#sources:path_posix_alias:exports:default"],
    ["path_win32_alias", "default", "unknown", "object", ["module-exports-assignment"], ["node:path/win32", "path/win32"], "modules.ts#sources:path_win32_alias:exports:default"],
  ].map(
    ([
      sourceKey,
      exportName,
      valueShape,
      expectedValueType,
      exportIdioms,
      moduleSpecifiers,
      sourceRef,
    ]) => [
      `${sourceKey}:${exportName}`,
      {
        sourceKey,
        exportName,
        valueShape,
        expectedValueType,
        exportIdioms,
        moduleSpecifiers,
        sourceRef,
      },
    ],
  ),
);
const REVIEWED_PROTOTYPE_VALUE_EXPORTS = new Map(
  [
    ["exact_crypto", "KeyObject.asymmetricKeyDetails", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:KeyObject.asymmetricKeyDetails"],
    ["exact_crypto", "KeyObject.asymmetricKeyType", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:KeyObject.asymmetricKeyType"],
    ["exact_crypto", "KeyObject.symmetricKeySize", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:KeyObject.symmetricKeySize"],
    ["exact_crypto", "KeyObject.type", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:KeyObject.type"],
    ["exact_crypto", "X509Certificate.fingerprint", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.fingerprint"],
    ["exact_crypto", "X509Certificate.fingerprint256", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.fingerprint256"],
    ["exact_crypto", "X509Certificate.infoAccess", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.infoAccess"],
    ["exact_crypto", "X509Certificate.issuer", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.issuer"],
    ["exact_crypto", "X509Certificate.issuerCertificate", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.issuerCertificate"],
    ["exact_crypto", "X509Certificate.keyUsage", "accessor", "object", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.keyUsage"],
    ["exact_crypto", "X509Certificate.publicKey", "unknown", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.publicKey"],
    ["exact_crypto", "X509Certificate.serialNumber", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.serialNumber"],
    ["exact_crypto", "X509Certificate.subject", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.subject"],
    ["exact_crypto", "X509Certificate.subjectAltName", "accessor", "undefined", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.subjectAltName"],
    ["exact_crypto", "X509Certificate.validFrom", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.validFrom"],
    ["exact_crypto", "X509Certificate.validTo", "accessor", "string", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.validTo"],
    ["node_buffer", "Buffer.__isExactBuffer", "data", "boolean", ["exported-constructor-prototype"], ["buffer", "node:buffer"], "src/builtins/buffer.js#exports:Buffer.__isExactBuffer"],
    ["node_buffer", "SlowBuffer.__isExactBuffer", "data", "boolean", ["exported-constructor-prototype"], ["buffer", "node:buffer"], "src/builtins/buffer.js#exports:SlowBuffer.__isExactBuffer"],
    ["node_perf_hooks", "Performance.timeOrigin", "unknown", "number", ["exported-constructor-prototype"], ["node:perf_hooks", "perf_hooks"], "src/builtins/perf-hooks.js#exports:Performance.timeOrigin"],
    ["node_stream", "default.destroyed", "data", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:default.destroyed"],
    ["node_stream", "Duplex.destroyed", "data", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Duplex.destroyed"],
    ["node_stream", "PassThrough.destroyed", "data", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:PassThrough.destroyed"],
    ["node_stream", "Readable.destroyed", "data", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Readable.destroyed"],
    ["node_stream", "Stream.destroyed", "data", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Stream.destroyed"],
    ["node_stream", "Transform.destroyed", "data", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Transform.destroyed"],
    ["node_stream", "Writable.__exactWritableProtoPatched", "data", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Writable.__exactWritableProtoPatched"],
    ["node_stream", "Writable.destroyed", "data", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Writable.destroyed"],
    ["ws", "WebSocket.CLOSED", "data", "number", ["exported-constructor-prototype"], ["ws"], "src/builtins/ws.js#exports:WebSocket.CLOSED"],
    ["ws", "WebSocket.CLOSING", "data", "number", ["exported-constructor-prototype"], ["ws"], "src/builtins/ws.js#exports:WebSocket.CLOSING"],
    ["ws", "WebSocket.CONNECTING", "data", "number", ["exported-constructor-prototype"], ["ws"], "src/builtins/ws.js#exports:WebSocket.CONNECTING"],
    ["ws", "WebSocket.OPEN", "data", "number", ["exported-constructor-prototype"], ["ws"], "src/builtins/ws.js#exports:WebSocket.OPEN"],
  ].map(
    ([
      sourceKey,
      exportName,
      valueShape,
      expectedValueType,
      exportIdioms,
      moduleSpecifiers,
      sourceRef,
    ]) => [
      `${sourceKey}:${exportName}`,
      {
        sourceKey,
        exportName,
        valueShape,
        expectedValueType,
        exportIdioms,
        moduleSpecifiers,
        sourceRef,
      },
    ],
  ),
);
const REVIEWED_STREAM_INSTANCE_VALUE_EXPORTS = new Map(
  [
    ["node_stream", "default.closed", "unknown", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:default.closed"],
    ["node_stream", "Duplex.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Duplex.closed"],
    ["node_stream", "PassThrough.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:PassThrough.closed"],
    ["node_stream", "Readable.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Readable.closed"],
    ["node_stream", "Stream.closed", "unknown", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Stream.closed"],
    ["node_stream", "Transform.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Transform.closed"],
    ["node_stream", "Writable.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Writable.closed"],
  ].map(
    ([
      sourceKey,
      exportName,
      valueShape,
      expectedValueType,
      exportIdioms,
      moduleSpecifiers,
      sourceRef,
    ]) => [
      `${sourceKey}:${exportName}`,
      {
        sourceKey,
        exportName,
        valueShape,
        expectedValueType,
        exportIdioms,
        moduleSpecifiers,
        sourceRef,
      },
    ],
  ),
);
const REVIEWED_X509_RAW_INSTANCE_VALUE = Object.freeze({
  sourceKey: "exact_crypto",
  exportName: "X509Certificate.raw",
  valueShape: "accessor",
  expectedValueType: "object",
  exportIdioms: ["exported-constructor-prototype"],
  moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
  sourceRef: "src/builtins/crypto.js#exports:X509Certificate.raw",
});
const REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUE = Object.freeze({
  sourceKey: "node_tls",
  exportName: "SecureContext.context",
  valueShape: "unknown",
  expectedValueType: "object",
  exportIdioms: ["exported-constructor-prototype"],
  moduleSpecifiers: ["node:tls", "tls"],
  sourceRef: "src/builtins/tls.js#exports:SecureContext.context",
});
const EFFECT_BUILTIN_MODULE_IMPORT_ALIASES = new Map(
  [
    ["node:sys", "node_util", true, true, "env:read"],
    ["node:util", "node_util", true, true, "env:read"],
    ["node:util/types", "node_util_types_alias", true, true, "env:read"],
    ["sys", "node_util", true, true, "env:read"],
    ["util", "node_util", true, true, "env:read"],
    ["util/types", "util_types_alias", true, true, "env:read"],
  ].map(
    ([moduleSpecifier, sourceKey, bundleExternal, moduleBuiltin, actionId]) => [
      moduleSpecifier,
      { sourceKey, bundleExternal, moduleBuiltin, actionId },
    ],
  ),
);
const NONCAP_BUILTIN_MODULE_IMPORT_ALIASES = new Map(
  [
    ["buffer", "node_buffer", true, "object"],
    ["bun:sqlite", "exact_sqlite", false, "function"],
    ["console", "node_console", true, "object"],
    ["dns", "node_dns", true, "object"],
    ["dns/promises", "node_dns_promises", true, "object"],
    ["exact:clipboard", "exact_clipboard", false, "object"],
    ["exact:http", "exact_http", false, "object"],
    ["exact:sqlite", "exact_sqlite", false, "function"],
    ["module", "node_module", true, "object"],
    ["node:buffer", "node_buffer", true, "object"],
    ["node:console", "node_console", true, "object"],
    ["node:dns", "node_dns", true, "object"],
    ["node:dns/promises", "node_dns_promises", true, "object"],
    ["node:module", "node_module", true, "object"],
    ["node:path", "node_path", true, "object"],
    ["node:path/posix", "path_posix_alias", true, "object"],
    ["node:path/win32", "path_win32_alias", true, "object"],
    ["node:punycode", "node_punycode", true, "object"],
    ["node:querystring", "node_querystring", true, "object"],
    ["node:string_decoder", "node_string_decoder", true, "function"],
    ["node:timers", "node_timers", true, "object"],
    ["node:timers/promises", "node_timers_promises", true, "object"],
    ["node:trace_events", "node_trace_events", true, "object"],
    ["node:v8", "node_v8", true, "object"],
    ["path", "node_path", true, "object"],
    ["path/posix", "path_posix_alias", true, "object"],
    ["path/win32", "path_win32_alias", true, "object"],
    ["punycode", "node_punycode", true, "object"],
    ["querystring", "node_querystring", true, "object"],
    ["string_decoder", "node_string_decoder", true, "function"],
    ["timers", "node_timers", true, "object"],
    ["timers/promises", "node_timers_promises", true, "object"],
    ["trace_events", "node_trace_events", true, "object"],
    ["v8", "node_v8", true, "object"],
  ].map(([moduleSpecifier, sourceKey, moduleBuiltin, expectedRootType]) => [
    moduleSpecifier,
    { sourceKey, bundleExternal: true, moduleBuiltin, expectedRootType },
  ]),
);
const EFFECT_BUILTIN_IMPORT_SCENARIOS = new Set([
  "allow",
  "deny",
  "malformed",
  "missing-attribution",
  "wrong-principal",
]);
const NORMAL_RETURN_RESULT_TYPES = new Set([
  "bigint",
  "boolean",
  "function",
  "null",
  "number",
  "object",
  "string",
  "undefined",
]);
const NORMAL_RETURN_PROOF_KINDS = new Set([
  "normal-return-from-source-call",
  "settled-return-from-source-call",
]);
const NORMAL_RETURN_DISPATCH_KINDS = new Map([
  ["root-call", "call"],
  ["construct-target", "construct"],
  ["tls-server-root-call", "call"],
  ["tls-server-construct-target", "construct"],
  ["constructed-owner", "prototype-call"],
  ["key-object-pair-owner", "prototype-call"],
  ["net-terminal-owner", "prototype-call"],
  ["readline-interface-owner", "prototype-call"],
  ["readline-interface-pause-owner", "prototype-call"],
  ["buffer-owner", "prototype-call"],
  ["call-tracker-owner", "prototype-call"],
  ["stream-owner", "prototype-call"],
  ["zlib-owner", "prototype-call"],
]);
const SETTLED_STREAM_CONSUMER_CONTRACTS = new Map([
  [
    "every",
    {
      arguments: [{ kind: "constant-function", value: true }],
      resultType: "boolean",
    },
  ],
  [
    "find",
    {
      arguments: [{ kind: "constant-function", value: true }],
      resultType: "undefined",
    },
  ],
  [
    "forEach",
    { arguments: [{ kind: "noop-function" }], resultType: "undefined" },
  ],
  [
    "reduce",
    {
      arguments: [
        { kind: "constant-function", value: "ibex" },
        { kind: "json", value: "ibex-initial" },
      ],
      resultType: "string",
    },
  ],
  [
    "some",
    {
      arguments: [{ kind: "constant-function", value: true }],
      resultType: "boolean",
    },
  ],
  ["toArray", { arguments: [], resultType: "object" }],
]);
const SETTLED_STREAM_CONSUMER_OWNERS = new Set([
  "Duplex",
  "PassThrough",
  "Readable",
  "Transform",
]);
// Independently restate the bounded explicit-parameter DiffieHellman family.
// The fixed prime avoids generation; these receipts may only construct,
// project, or replace inert instance bytes.
const EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS = [
  { kind: "uint8-array", bytes: [23] },
  { kind: "json", value: 5 },
];
const EXPLICIT_DH_CALL_CONTRACTS = new Map([
  [
    "DiffieHellman",
    {
      setup: { kind: "construct-target" },
      arguments: EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS,
      resultType: "object",
    },
  ],
  [
    "createDiffieHellman",
    {
      setup: { kind: "root-call" },
      arguments: EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS,
      resultType: "object",
    },
  ],
  ...["getGenerator", "getPrime", "getPrivateKey", "getPublicKey"].map(
    (method) => [
      `DiffieHellman.${method}`,
      {
        setup: {
          kind: "constructed-owner",
          ownerExportName: "DiffieHellman",
          constructorArguments: EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS,
        },
        arguments: [],
        resultType: "object",
      },
    ],
  ),
  ...["setPrivateKey", "setPublicKey"].map((method) => [
    `DiffieHellman.${method}`,
    {
      setup: {
        kind: "constructed-owner",
        ownerExportName: "DiffieHellman",
        constructorArguments: EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS,
      },
      arguments: [{ kind: "uint8-array", bytes: [3] }],
      resultType: "undefined",
    },
  ]),
]);
const X509_STATE_CALL_CONTRACTS = new Map([
  [
    "X509Certificate.toString",
    {
      setup: {
        kind: "constructed-owner",
        ownerExportName: "X509Certificate",
        constructorArguments: [
          { kind: "json", value: "ibex-x509-fixture" },
        ],
      },
      arguments: [],
      resultType: "string",
    },
  ],
]);
// Independently repeat the three source-only compatibility helpers whose
// bounded literals cannot reach a native key store or terminal stream.
const PURE_COMPATIBILITY_CALL_CONTRACTS = new Map([
  ...["createPrivateKey", "createPublicKey"].map((exportName) => [
    `exact_crypto:${exportName}`,
    {
      moduleSpecifier: "node:crypto",
      templateId: "exact-crypto-bounded-v1",
      exportIdioms: ["object-binding", "object-source"],
      moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
      sourceRef: `src/builtins/crypto.js#exports:${exportName}`,
      arguments: [{ kind: "json", value: "ibex-key" }],
      resultType: "object",
    },
  ]),
  [
    "node_readline:CSI",
    {
      moduleSpecifier: "node:readline",
      templateId: "node-readline-pure-v1",
      exportIdioms: ["module-exports-object"],
      moduleSpecifiers: [
        "node:readline",
        "node:readline/promises",
        "readline",
        "readline/promises",
      ],
      sourceRef: "src/builtins/readline.js#exports:CSI",
      arguments: [{ kind: "json", value: ["31m"] }],
      resultType: "string",
    },
  ],
]);
const KEY_OBJECT_EQUALS_CONTRACT = {
  moduleSpecifier: "node:crypto",
  templateId: "exact-crypto-bounded-v1",
  sourceDescriptor: {
    kind: "builtin-export",
    sourceKey: "exact_crypto",
    exportName: "KeyObject.equals",
    exportIdioms: ["exported-constructor-prototype"],
    moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
    sourceRef: "src/builtins/crypto.js#exports:KeyObject.equals",
    valueShape: "callable",
    access: {
      kind: "prototype-property",
      path: ["KeyObject", "prototype", "equals"],
    },
  },
  setup: {
    kind: "key-object-pair-owner",
    ownerExportName: "KeyObject",
    keyType: "secret",
    bytes: [0x69, 0x62, 0x65, 0x78],
  },
  arguments: [{ kind: "setup-value", name: "peer" }],
  resultType: "boolean",
};
const READLINE_INTERFACE_CLOSE_CONTRACT = {
  moduleSpecifier: "node:readline",
  templateId: "node-readline-pure-v1",
  sourceDescriptor: {
    kind: "builtin-export",
    sourceKey: "node_readline",
    exportName: "Interface.close",
    exportIdioms: ["exported-constructor-prototype"],
    moduleSpecifiers: [
      "node:readline",
      "node:readline/promises",
      "readline",
      "readline/promises",
    ],
    sourceRef: "src/builtins/readline.js#exports:Interface.close",
    valueShape: "callable",
    access: {
      kind: "prototype-property",
      path: ["Interface", "prototype", "close"],
    },
  },
  setup: {
    kind: "readline-interface-owner",
    ownerExportName: "Interface",
    terminal: false,
  },
  arguments: [],
  resultType: "undefined",
};
const READLINE_INTERFACE_PAUSE_CONTRACT = {
  ...READLINE_INTERFACE_CLOSE_CONTRACT,
  sourceDescriptor: {
    ...READLINE_INTERFACE_CLOSE_CONTRACT.sourceDescriptor,
    exportName: "Interface.pause",
    sourceRef: "src/builtins/readline.js#exports:Interface.pause",
    access: {
      kind: "prototype-property",
      path: ["Interface", "prototype", "pause"],
    },
  },
  setup: {
    kind: "readline-interface-pause-owner",
    ownerExportName: "Interface",
    terminal: false,
    cleanupMethod: "close",
  },
  resultType: "object",
};
const BASE_STREAM_MODULE_VALUE_CALL_CONTRACTS = new Map([
  [
    "default._close",
    {
      setup: {
        kind: "stream-owner",
        ownerExportName: "default",
        endedInput: false,
      },
      arguments: [{ kind: "json", value: true }],
      resultType: "undefined",
    },
  ],
  ...["_emitClose", "_undestroy"].map((method) => [
    `default.${method}`,
    {
      setup: {
        kind: "stream-owner",
        ownerExportName: "default",
        endedInput: false,
      },
      arguments: [],
      resultType: "undefined",
    },
  ]),
  [
    "default.constructor",
    {
      setup: { kind: "construct-target" },
      arguments: [],
      resultType: "object",
    },
  ],
  ...["destroy", "unpipe"].map((method) => [
    `default.${method}`,
    {
      setup: {
        kind: "stream-owner",
        ownerExportName: "default",
        endedInput: false,
      },
      arguments: [],
      resultType: "object",
    },
  ]),
]);
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — A
// fresh net Server, Socket, or legacy Stream owns no listener or transport.
// These exact terminal calls must still deliver one close event and prove the
// receiver reached its final in-memory state before the fixture completes.
const IDLE_NET_TERMINAL_CALL_CONTRACTS = new Map([
  [
    "Server.close",
    {
      setup: {
        kind: "net-terminal-owner",
        ownerExportName: "Server",
      },
      arguments: [],
      resultType: "object",
    },
  ],
  ...["Socket", "Stream"].flatMap((ownerExportName) =>
    ["close", "resetAndDestroy"].map((methodName) => [
      `${ownerExportName}.${methodName}`,
      {
        setup: {
          kind: "net-terminal-owner",
          ownerExportName,
        },
        arguments: [],
        resultType: "object",
      },
    ]),
  ),
]);
// Independently restate the only HTTP calls whose fresh receivers own no
// socket, listener, timer, or native selector, or whose root validators inspect
// only fixed harness-owned strings during the observed operation.
const BOUNDED_HTTP_CALL_CONTRACTS = new Map([
  ...[
    ["_checkInvalidHeaderChar", ["ibex"], "boolean"],
    ["_checkIsHttpToken", ["x-ibex"], "boolean"],
    ["validateHeaderName", ["x-ibex"], "undefined"],
    ["validateHeaderValue", ["x-ibex", "ibex"], "undefined"],
  ].map(([exportName, values, resultType]) => [
    exportName,
    {
      setup: { kind: "root-call" },
      arguments: values.map((value) => ({ kind: "json", value })),
      resultType,
    },
  ]),
  [
    "Agent.destroy",
    {
      setup: {
        kind: "constructed-owner",
        ownerExportName: "Agent",
        constructorArguments: [],
      },
      arguments: [],
      resultType: "undefined",
    },
  ],
  [
    "Server",
    {
      setup: { kind: "construct-target" },
      arguments: [],
      resultType: "object",
    },
  ],
  ...[
    ["close", "object"],
    ["closeAllConnections", "undefined"],
    ["closeIdleConnections", "undefined"],
    ["ref", "object"],
    ["unref", "object"],
  ].map(([method, resultType]) => [
    `Server.${method}`,
    {
      setup: {
        kind: "constructed-owner",
        ownerExportName: "Server",
        constructorArguments: [],
      },
      arguments: [],
      resultType,
    },
  ]),
  [
    "Server.constructor",
    {
      setup: { kind: "construct-target" },
      arguments: [],
      resultType: "object",
    },
  ],
  [
    "createServer",
    {
      setup: { kind: "root-call" },
      arguments: [],
      resultType: "object",
    },
  ],
]);
const BOUNDED_HTTP_MODULE_SPECIFIERS = [
  "_http_agent",
  "_http_common",
  "_http_incoming",
  "_http_outgoing",
  "_http_server",
  "http",
  "node:http",
];
// A TLSSocket constructed without a transport has no native owner token,
// engine, selector, listener, or pending timer. Keep this closed lifecycle set
// separate from transport-binding TLS operations.
const IDLE_TLS_SOCKET_CALL_CONTRACTS = new Map([
  [
    "TLSSocket",
    {
      setup: { kind: "construct-target" },
      arguments: [],
      resultType: "object",
    },
  ],
  ...["close", "destroy", "ref", "unref"].map((methodName) => [
    `TLSSocket.${methodName}`,
    {
      setup: {
        kind: "constructed-owner",
        ownerExportName: "TLSSocket",
        constructorArguments: [],
      },
      arguments: [],
      resultType: "object",
    },
  ]),
]);
// Fresh TLS Server construction owns no transport or native listener, but it
// does mint one private TLS owner token and install registry listeners. The
// loaded harness must close the result, observe its close event, and prove the
// delayed retirement made the guarded server terminal.
const IDLE_TLS_SERVER_CALL_CONTRACTS = new Map(
  [
    [
      "node_tls",
      "node-tls-pure-v1",
      "node:tls",
      ["node:tls", "tls"],
      "tls.js",
    ],
    [
      "node_https",
      "node-https-idle-v1",
      "node:https",
      ["https", "node:https"],
      "https.js",
    ],
  ].flatMap(
    ([
      sourceKey,
      templateId,
      moduleSpecifier,
      moduleSpecifiers,
      sourceFile,
    ]) =>
      ["Server", "Server.constructor", "createServer"].map((exportName) => [
        `${sourceKey}:${exportName}`,
        {
          setup: {
            kind:
              exportName === "createServer"
                ? "tls-server-root-call"
                : "tls-server-construct-target",
          },
          arguments: [],
          resultType: "object",
          templateId,
          moduleSpecifier,
          moduleSpecifiers,
          sourceRef: `src/builtins/${sourceFile}#exports:${exportName}`,
        },
      ]),
  ),
);
// A fresh udp4 wrapper owns only an authenticated principal stamp. The
// constructor does not allocate a native handle; ref/unref see no poll timer,
// and close only schedules the terminal close event required by quiescence.
const IDLE_DGRAM_CALL_CONTRACTS = new Map([
  ...["Socket", "Socket.constructor"].map((exportName) => [
    exportName,
    {
      setup: { kind: "construct-target" },
      arguments: [{ kind: "json", value: "udp4" }],
      resultType: "object",
    },
  ]),
  ...["close", "ref", "unref"].map((method) => [
    `Socket.${method}`,
    {
      setup: {
        kind: "constructed-owner",
        ownerExportName: "Socket",
        constructorArguments: [{ kind: "json", value: "udp4" }],
      },
      arguments: [],
      resultType: "object",
    },
  ]),
  [
    "createSocket",
    {
      setup: { kind: "root-call" },
      arguments: [{ kind: "json", value: "udp4" }],
      resultType: "object",
    },
  ],
]);
const IDLE_DGRAM_MODULE_SPECIFIERS = ["dgram", "node:dgram"];
const ZLIB_IDLE_DESTROY_OWNERS = new Set([
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
const NATIVE_FILESYSTEM_DENIAL_GLOBALS = new Set([
  "__exactAppendFile",
  "__exactFsOpen",
  "__exactFsOpenAsync",
  "__exactFsPathAsync",
  "__exactFsReadFileAsync",
  "__exactLstat",
  "__exactMkdir",
  "__exactReadFile",
  "__exactReaddir",
  "__exactRealpath",
  "__exactStat",
  "__exactStatfs",
  "__exactTruncate",
  "__exactWriteFile",
]);
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — the
// dispatcher remains the public surface, while typed evidence must select its
// exact source-chosen worker rather than any allowed auxiliary edge.
const NATIVE_ASYNC_WORKER_TERMINALS = new Map([
  ["mkdir", "native-op:__exactMkdir"],
  ["readdir", "native-op:__exactReaddir"],
  ["realpath", "native-op:__exactRealpath"],
  ["statfs", "native-op:__exactStatfs"],
  ["truncate", "native-op:__exactTruncate"],
]);
const POSIX_RETAINED_FS_OPEN_TERMINALS = new Set([
  "__exactFsFdAsync",
  "__exactFsFchmodSync",
  "__exactFsFstatSync",
  "__exactFsFtruncateSync",
  "__exactFsFutimesSync",
  "__exactFsRead",
  "__exactFsReadFileAsync",
  "__exactFsReadv",
  "__exactFsWrite",
]);
const CLOSED_SQLITE_CARRIER_OPERATIONS = new Set([
  "sqlite-cr-sqlite-enable",
  "sqlite-extension-load",
]);

export function nativeAsyncWorkerTerminals(authored) {
  if (
    authored?.invocationSchema !==
      "ibex/capsec-native-global-invocation/1" ||
    authored.kind !== "native-global-function"
  ) {
    return null;
  }
  const posixSource =
    typeof authored.sourceDescriptor?.sourceRef === "string" &&
    !authored.sourceDescriptor.sourceRef.includes("_windows.cc#");
  const retainedDescriptorSetup = authored.setup?.some((setup) =>
    ["fs-read-file", "fs-write-file"].includes(setup.kind),
  );
  if (
    posixSource &&
    retainedDescriptorSetup &&
    authored.globalName === "__exactFsReadFileAsync"
  ) {
    return [
      "native-op:__exactFsOpen",
      "native-op:__exactFsReadFileAsync",
    ];
  }
  if (
    posixSource &&
    (authored.globalName === "__exactFsOpenAsync" ||
      (retainedDescriptorSetup &&
        POSIX_RETAINED_FS_OPEN_TERMINALS.has(authored.globalName)))
  ) {
    return ["native-op:__exactFsOpen"];
  }
  if (authored.globalName !== "__exactFsPathAsync") return null;
  const operation = authored.arguments?.[0];
  const terminal =
    operation?.kind === "json-literal"
      ? NATIVE_ASYNC_WORKER_TERMINALS.get(operation.value) ?? null
      : null;
  return terminal === null ? null : [terminal];
}

export function nativeAsyncWorkerTerminal(authored) {
  const terminals = nativeAsyncWorkerTerminals(authored);
  return terminals?.length === 1 ? terminals[0] : null;
}

export function validateNativeFilesystemDenialRecipeDescriptor(authored) {
  if (
    authored?.invocationSchema !==
      "ibex/capsec-native-global-invocation/1" ||
    authored.kind !== "native-global-function" ||
    !NATIVE_FILESYSTEM_DENIAL_GLOBALS.has(authored.globalName) ||
    authored.expectedDenyMessageFragment !== "filesystem policy denied"
  ) {
    throw new Error("unreviewed native denial expectation");
  }
  return authored;
}

// Independent verifier authority for the small curated startup family. Keep
// this separate from recipe authorship so descriptor tampering cannot change
// both the claim and its validator through one shared table.
const STARTUP_EXPECTATIONS = new Map(
  [
    [
      "runtime-create",
      "runtime-created",
      "src/engine/hermes_runtime.cc#ex_hermes_create_armed",
      ["engine-can-evaluate"],
      null,
    ],
    [
      "globals-install",
      "globals-installed",
      "src/engine/hermes_runtime.cc#installGlobals",
      ["console-installed", "timers-installed"],
      null,
    ],
    [
      "module-loader-install",
      "module-loader-installed",
      "src/engine/hermes_bootstrap.cc#installModuleLoader",
      ["module-loader-installed"],
      null,
    ],
    [
      "shared-runtime-install",
      "shared-runtime-installed",
      "src/engine/hermes_bootstrap.cc#installSharedRuntimeBundle",
      ["shared-runtime-loaded"],
      null,
    ],
    [
      "capability-hardening-seal",
      "capability-hatches-sealed",
      "src/engine/hermes_runtime.cc#kCapabilityHardeningJS",
      ["capability-hatches-absent"],
      null,
    ],
    [
      "eager-native-seal",
      "lazy-installers-sealed",
      "src/engine/hermes_runtime.cc#kEagerInstallSealJS",
      ["lazy-installers-absent"],
      null,
    ],
    [
      "lockdown-install",
      "lockdown-installed",
      "src/engine/hermes_runtime.cc#lockdownJS",
      ["lockdown-flag-pinned", "eval-tamed", "object-prototype-frozen"],
      null,
    ],
    [
      "freeze-seal",
      "freeze-hatches-sealed",
      "src/engine/hermes_runtime.cc#kFreezeSealJS",
      ["freeze-hatches-absent"],
      null,
    ],
    [
      "compartment-registry-install",
      "compartment-registry-installed",
      "src/engine/hermes_runtime.cc#kCompartmentRegistryJS",
      ["compartment-registry-pinned"],
      null,
    ],
    [
      "web-streams-install",
      "web-streams-installed",
      "src/engine/hermes_bootstrap.cc#installWebStreamsPolyfill",
      ["web-stream-constructors-installed"],
      { name: "EX_WEB_STREAMS_POLYFILL", value: "1" },
    ],
  ].map(
    ([surfaceName, postcondition, sourceRef, requiredFacts, environment]) => [
      surfaceName,
      { postcondition, sourceRef, requiredFacts, environment },
    ],
  ),
);

// Independent verifier authority for startup environment source carriers.
// This intentionally does not import the recipe template: a template edit
// must not be able to rewrite both the claim and the verifier in one place.
const STARTUP_ENVIRONMENT_EXPECTATIONS = new Map([
  [
    "NODE_DEBUG",
    {
      sourceRef: "src/builtins/http.js#process.env:NODE_DEBUG:read",
      liveSourceRefs: [
        "src/builtins/http.js#process.env:NODE_DEBUG:read",
        "src/builtins/util.js#process.env:NODE_DEBUG:read",
      ],
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:http",
      preloadModuleSpecifiers: ["node:events", "node:stream", "node:util"],
      observedEnvironmentNames: ["NODE_DEBUG"],
      observedEnvironmentAccesses: ["NODE_DEBUG"],
    },
  ],
  [
    "EXACT_DEBUG_EMIT_LISTENER",
    {
      sourceRef:
        "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
      liveSourceRefs: [
        "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
      ],
      mechanism: "event-emitter-emit",
      moduleSpecifier: "node:events",
      preloadModuleSpecifiers: [],
      observedEnvironmentNames: ["EXACT_DEBUG_EMIT_LISTENER"],
      observedEnvironmentAccesses: ["EXACT_DEBUG_EMIT_LISTENER"],
    },
  ],
  [
    "TZ",
    {
      sourceRef:
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
      liveSourceRefs: [
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
        "src/bin/ibex/engine/hermes.rs#Command::env:TZ:write",
        "src/bin/ibex/runtime.rs#Command::env:TZ:write",
        "src/module_loader/mod.rs#Command::env:TZ:write",
      ],
      mechanism: "date-to-string",
      moduleSpecifier: null,
      preloadModuleSpecifiers: [],
      observedEnvironmentNames: ["TZ"],
      observedEnvironmentAccesses: ["TZ"],
    },
  ],
  [
    "EXACT_PIPELINE_DEBUG",
    {
      sourceRef:
        "src/builtins/stream.js#process.env:EXACT_PIPELINE_DEBUG:read",
      liveSourceRefs: [
        "src/builtins/stream.js#process.env:EXACT_PIPELINE_DEBUG:read",
      ],
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:stream",
      preloadModuleSpecifiers: [
        "node:events",
        "node:string_decoder",
        "node:util",
      ],
      observedEnvironmentNames: [
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ],
      observedEnvironmentAccesses: [
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ],
    },
  ],
  [
    "EXACT_PIPELINE_STATE_DEBUG",
    {
      sourceRef:
        "src/builtins/stream.js#process.env:EXACT_PIPELINE_STATE_DEBUG:read",
      liveSourceRefs: [
        "src/builtins/stream.js#process.env:EXACT_PIPELINE_STATE_DEBUG:read",
      ],
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:stream",
      preloadModuleSpecifiers: [
        "node:events",
        "node:string_decoder",
        "node:util",
      ],
      observedEnvironmentNames: [
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ],
      observedEnvironmentAccesses: [
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ],
    },
  ],
  [
    "COLUMNS",
    {
      sourceRef: "src/builtins/tty.js#process.env:COLUMNS:read",
      liveSourceRefs: ["src/builtins/tty.js#process.env:COLUMNS:read"],
      mechanism: "tty-refresh-size",
      moduleSpecifier: "node:tty",
      preloadModuleSpecifiers: ["node:tty"],
      observedEnvironmentNames: ["COLUMNS", "LINES"],
      observedEnvironmentAccesses: ["COLUMNS", "LINES"],
    },
  ],
  [
    "LINES",
    {
      sourceRef: "src/builtins/tty.js#process.env:LINES:read",
      liveSourceRefs: ["src/builtins/tty.js#process.env:LINES:read"],
      mechanism: "tty-refresh-size",
      moduleSpecifier: "node:tty",
      preloadModuleSpecifiers: ["node:tty"],
      observedEnvironmentNames: ["COLUMNS", "LINES"],
      observedEnvironmentAccesses: ["COLUMNS", "LINES"],
    },
  ],
  [
    "FORCE_COLOR",
    {
      sourceRef: "src/builtins/tty.js#process.env:FORCE_COLOR:read",
      liveSourceRefs: [
        "src/builtins/tty.js#process.env:FORCE_COLOR:read",
        "src/engine/bootstrap/stream-enhance.js#process.env:FORCE_COLOR:read",
      ],
      mechanism: "tty-color-depth",
      moduleSpecifier: "node:tty",
      preloadModuleSpecifiers: ["node:tty"],
      observedEnvironmentNames: [
        "COLORTERM",
        "FORCE_COLOR",
        "NO_COLOR",
        "TERM",
      ],
      observedEnvironmentAccesses: [
        "NO_COLOR",
        "FORCE_COLOR",
        "COLORTERM",
        "COLORTERM",
        "TERM",
      ],
    },
  ],
  [
    "COLORTERM",
    {
      sourceRef: "src/builtins/tty.js#process.env:COLORTERM:read",
      liveSourceRefs: [
        "src/builtins/tty.js#process.env:COLORTERM:read",
        "src/engine/bootstrap/stream-enhance.js#process.env:COLORTERM:read",
      ],
      mechanism: "tty-color-depth",
      moduleSpecifier: "node:tty",
      preloadModuleSpecifiers: ["node:tty"],
      observedEnvironmentNames: [
        "COLORTERM",
        "FORCE_COLOR",
        "NO_COLOR",
        "TERM",
      ],
      observedEnvironmentAccesses: [
        "NO_COLOR",
        "FORCE_COLOR",
        "COLORTERM",
        "COLORTERM",
        "TERM",
      ],
    },
  ],
  [
    "NO_COLOR",
    {
      sourceRef: "src/builtins/tty.js#process.env:NO_COLOR:read",
      liveSourceRefs: [
        "src/bin/ibex/terminal_session.rs#env::var_os:NO_COLOR:read",
        "src/builtins/tty.js#process.env:NO_COLOR:read",
        "src/engine/bootstrap/stream-enhance.js#process.env:NO_COLOR:read",
      ],
      mechanism: "tty-color-depth",
      moduleSpecifier: "node:tty",
      preloadModuleSpecifiers: ["node:tty"],
      observedEnvironmentNames: [
        "COLORTERM",
        "FORCE_COLOR",
        "NO_COLOR",
        "TERM",
      ],
      observedEnvironmentAccesses: [
        "NO_COLOR",
        "FORCE_COLOR",
        "COLORTERM",
        "COLORTERM",
        "TERM",
      ],
    },
  ],
  [
    "TERM",
    {
      sourceRef: "src/builtins/tty.js#process.env:TERM:read",
      liveSourceRefs: [
        "src/bin/ibex/terminal_session.rs#env::var_os:TERM:read",
        "src/builtins/tty.js#process.env:TERM:read",
        "src/engine/bootstrap/stream-enhance.js#process.env:TERM:read",
      ],
      mechanism: "tty-color-depth",
      moduleSpecifier: "node:tty",
      preloadModuleSpecifiers: ["node:tty"],
      observedEnvironmentNames: [
        "COLORTERM",
        "FORCE_COLOR",
        "NO_COLOR",
        "TERM",
      ],
      observedEnvironmentAccesses: [
        "NO_COLOR",
        "FORCE_COLOR",
        "COLORTERM",
        "COLORTERM",
        "TERM",
      ],
    },
  ],
]);

const PRINCIPAL_ENVIRONMENT_SURFACE =
  "native-op:global:process.env.[[dynamic-table:principal-environment-overlay-properties]]";
const PRINCIPAL_ENVIRONMENT_NAME = "IBEX_CAPSEC_PUBLIC_ENV_PROPERTY";
const PRINCIPAL_ENVIRONMENT_SOURCE_REFS = [
  "packages/ibex-runtime-js/src/node/process.ts#Process.prototype.env",
  "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy",
  "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy:Proxy.deleteProperty",
  "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy:Proxy.get",
  "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy:Proxy.ownKeys",
  "packages/ibex-runtime-js/src/node/process.ts#createEnvProxy:Proxy.set",
];

function hasExactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort(compareText)) ===
      canonicalJson([...keys].sort(compareText))
  );
}

function exactKeys(value, keys, label) {
  if (!hasExactKeys(value, keys)) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function isReviewedDnsPromiseErrorDescriptor(descriptor) {
  const exportName = descriptor?.exportName;
  return (
    REVIEWED_DNS_PROMISE_ERROR_CODES.has(exportName) &&
    canonicalJson(descriptor) ===
      canonicalJson({
        kind: "builtin-export",
        sourceKey: "node_dns_promises",
        exportName,
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["dns/promises", "node:dns/promises"],
        sourceRef: `src/builtins/dns-promises.js#exports:${exportName}`,
        valueShape: "unknown",
        access: { kind: "export-property", path: [exportName] },
        expectedValueType: "string",
      })
  );
}

function isReviewedPostInitializationValueDescriptor(descriptor) {
  const expected = REVIEWED_POST_INITIALIZATION_VALUE_EXPORTS.get(
    `${descriptor?.sourceKey}:${descriptor?.exportName}`,
  );
  return (
    expected !== undefined &&
    canonicalJson(descriptor) ===
      canonicalJson({
        kind: "builtin-export",
        sourceKey: expected.sourceKey,
        exportName: expected.exportName,
        exportIdioms: expected.exportIdioms,
        moduleSpecifiers: expected.moduleSpecifiers,
        sourceRef: expected.sourceRef,
        valueShape: expected.valueShape,
        access:
          expected.exportName === "default" &&
          expected.exportIdioms.includes("module-exports-assignment")
            ? { kind: "module-value", path: [] }
            : {
                kind: "export-property",
                path: [expected.exportName],
              },
        expectedValueType: expected.expectedValueType,
      })
  );
}

function isReviewedPrototypeValueDescriptor(descriptor) {
  const expected = REVIEWED_PROTOTYPE_VALUE_EXPORTS.get(
    `${descriptor?.sourceKey}:${descriptor?.exportName}`,
  );
  if (expected === undefined) return false;
  const segments = expected.exportName.split(".");
  const inherited = expected.exportIdioms.includes(
    "exported-constructor-inherited-prototype",
  );
  const accessPath =
    expected.sourceKey === "node_stream" &&
    expected.exportName === "default.destroyed"
      ? ["prototype", "destroyed"]
      : [segments[0], "prototype", ...segments.slice(1)];
  return (
    segments.length >= 2 &&
    canonicalJson(descriptor) ===
      canonicalJson({
        kind: "builtin-export",
        sourceKey: expected.sourceKey,
        exportName: expected.exportName,
        exportIdioms: expected.exportIdioms,
        moduleSpecifiers: expected.moduleSpecifiers,
        sourceRef: expected.sourceRef,
        valueShape: expected.valueShape,
        access: {
          kind: inherited
            ? "inherited-prototype-property"
            : "prototype-property",
          path: accessPath,
        },
        expectedValueType: expected.expectedValueType,
      })
  );
}

function isReviewedStreamInstanceValueDescriptor(descriptor) {
  const expected = REVIEWED_STREAM_INSTANCE_VALUE_EXPORTS.get(
    `${descriptor?.sourceKey}:${descriptor?.exportName}`,
  );
  return (
    expected !== undefined &&
    canonicalJson(descriptor) ===
      canonicalJson({
        kind: "builtin-export",
        sourceKey: expected.sourceKey,
        exportName: expected.exportName,
        exportIdioms: expected.exportIdioms,
        moduleSpecifiers: expected.moduleSpecifiers,
        sourceRef: expected.sourceRef,
        valueShape: expected.valueShape,
        access: {
          kind: "constructed-instance-property",
          path: ["closed"],
        },
        expectedValueType: expected.expectedValueType,
      })
  );
}

function isReviewedX509RawInstanceValueDescriptor(descriptor) {
  const expected = REVIEWED_X509_RAW_INSTANCE_VALUE;
  return (
    canonicalJson(descriptor) ===
    canonicalJson({
      kind: "builtin-export",
      sourceKey: expected.sourceKey,
      exportName: expected.exportName,
      exportIdioms: expected.exportIdioms,
      moduleSpecifiers: expected.moduleSpecifiers,
      sourceRef: expected.sourceRef,
      valueShape: expected.valueShape,
      access: {
        kind: "constructed-instance-property",
        path: ["raw"],
      },
      expectedValueType: expected.expectedValueType,
    })
  );
}

function isReviewedTlsSecureContextInstanceValueDescriptor(descriptor) {
  const expected = REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUE;
  return (
    canonicalJson(descriptor) ===
    canonicalJson({
      kind: "builtin-export",
      sourceKey: expected.sourceKey,
      exportName: expected.exportName,
      exportIdioms: expected.exportIdioms,
      moduleSpecifiers: expected.moduleSpecifiers,
      sourceRef: expected.sourceRef,
      valueShape: expected.valueShape,
      access: {
        kind: "constructed-instance-property",
        path: ["context"],
      },
      expectedValueType: expected.expectedValueType,
    })
  );
}

function effectBuiltinModuleImportAuthority(actionId) {
  if (actionId === "env:read") {
    return [
      {
        cap: "env:read",
        resource: {
          kind: "environment-name",
          target: "principal-overlay",
          name: "NODE_DEBUG",
        },
      },
    ];
  }
  return null;
}

function validateEffectBuiltinModuleImportInvocation(
  invocation,
  authored,
  recipe,
) {
  const expectation = EFFECT_BUILTIN_MODULE_IMPORT_ALIASES.get(
    authored.moduleSpecifier,
  );
  const surfaceObservedKey = `builtin:${authored.moduleSpecifier}`;
  const descriptor = authored.sourceDescriptor;
  const sourceMetadata = descriptor?.sourceMetadata;
  const decisionIdentity = invocation.decisionIdentity;
  const denial = recipe.scenario === "deny";
  const expectedAuthority = expectation
    ? effectBuiltinModuleImportAuthority(expectation.actionId)
    : null;
  const expectedStages = denial ? ["requested"] : ["requested", "commit"];

  exactKeys(
    invocation,
    [
      "invocationSchema",
      "kind",
      "surfaceObservedKey",
      "moduleSpecifier",
      "sourceDescriptorDigest",
      "decisionIdentity",
      "result",
    ],
    `${recipe.fixtureId}: builtin module-import runtime invocation`,
  );
  exactKeys(
    authored,
    [
      "invocationSchema",
      "kind",
      "moduleSpecifier",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "arguments",
      "setup",
      "requiredAuthority",
      "expectedResult",
      "expectedTypedDecisionCount",
      "expectedTypedStages",
      "allowedCoverageEdgeIds",
      "expectedActionIds",
    ],
    `${recipe.fixtureId}: authored builtin module import`,
  );
  exactKeys(
    descriptor,
    [
      "kind",
      "moduleSpecifier",
      "sourceKey",
      "sourceRef",
      "sourceMetadata",
      "carrierEdgeId",
      "auxiliaryDecisionEdgeId",
    ],
    `${recipe.fixtureId}: builtin module-import source descriptor`,
  );
  exactKeys(
    sourceMetadata,
    ["sourceKey", "bundleExternal", "importReachability", "moduleBuiltin"],
    `${recipe.fixtureId}: builtin module-import source metadata`,
  );
  exactKeys(
    decisionIdentity,
    [
      "profile",
      "semanticCore",
      "vocabDigest",
      "registryDigest",
      "policyDigest",
      "armedSnapshotDigest",
    ],
    `${recipe.fixtureId}: builtin module-import decision identity`,
  );
  exactKeys(
    authored.setup,
    ["kind"],
    `${recipe.fixtureId}: builtin module-import setup`,
  );
  exactKeys(
    recipe.route,
    ["surfaceObservedKeys", "alternatives", "ambiguousCallees"],
    `${recipe.fixtureId}: builtin module-import route`,
  );
  if (recipe.route.alternatives?.length === 1) {
    exactKeys(
      recipe.route.alternatives[0],
      ["terminalObservedKey", "proofPaths"],
      `${recipe.fixtureId}: builtin module-import route alternative`,
    );
  }

  if (
    recipe.classification !== "effects" ||
    !EFFECT_BUILTIN_IMPORT_SCENARIOS.has(recipe.scenario) ||
    expectation === undefined ||
    expectedAuthority === null ||
    authored.invocationSchema !==
      "ibex/capsec-builtin-module-import-invocation/1" ||
    authored.kind !== "builtin-module-import" ||
    invocation.kind !== authored.kind ||
    invocation.moduleSpecifier !== authored.moduleSpecifier ||
    recipe.publicSurfaceProbe?.surfaceObservedKey !== surfaceObservedKey ||
    invocation.surfaceObservedKey !== surfaceObservedKey ||
    recipe.terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.surfaceObservedKeys) !==
      canonicalJson([surfaceObservedKey]) ||
    recipe.route.alternatives?.length !== 1 ||
    recipe.route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.alternatives[0].proofPaths) !==
      canonicalJson([surfaceObservedKey]) ||
    canonicalJson(recipe.route.ambiguousCallees) !== canonicalJson([]) ||
    !Array.isArray(recipe.edgeIds) ||
    recipe.edgeIds.length !== 1 ||
    descriptor.carrierEdgeId !== recipe.edgeIds[0] ||
    typeof descriptor.auxiliaryDecisionEdgeId !== "string" ||
    descriptor.auxiliaryDecisionEdgeId.length === 0 ||
    canonicalJson(authored.allowedCoverageEdgeIds) !==
      canonicalJson([descriptor.auxiliaryDecisionEdgeId]) ||
    canonicalJson(recipe.actionIds) !==
      canonicalJson([expectation.actionId]) ||
    canonicalJson(authored.expectedActionIds) !==
      canonicalJson([expectation.actionId]) ||
    descriptor.kind !== "builtin-module-alias" ||
    descriptor.moduleSpecifier !== authored.moduleSpecifier ||
    descriptor.sourceKey !== expectation.sourceKey ||
    descriptor.sourceRef !==
      `modules.ts#specifiers:${expectation.sourceKey}` ||
    sourceMetadata.sourceKey !== expectation.sourceKey ||
    sourceMetadata.bundleExternal !== expectation.bundleExternal ||
    sourceMetadata.importReachability !== "public" ||
    sourceMetadata.moduleBuiltin !== expectation.moduleBuiltin ||
    decisionIdentity.profile !== "ibex/capsec/1" ||
    decisionIdentity.semanticCore !== "capsec/semantics/1" ||
    decisionIdentity.vocabDigest !== SEMANTIC_REGISTRY_IDENTITY.vocabDigest ||
    decisionIdentity.registryDigest !==
      SEMANTIC_REGISTRY_IDENTITY.registryDigest ||
    !isTaggedDigest(decisionIdentity.policyDigest) ||
    !isTaggedDigest(decisionIdentity.armedSnapshotDigest) ||
    canonicalJson(authored.arguments) !== canonicalJson([]) ||
    authored.setup.kind !== "none" ||
    canonicalJson(authored.requiredAuthority) !==
      canonicalJson(expectedAuthority) ||
    authored.expectedResult !== "return" ||
    authored.expectedTypedDecisionCount !== expectedStages.length ||
    canonicalJson(authored.expectedTypedStages) !==
      canonicalJson(expectedStages)
  ) {
    throw new Error(
      `${recipe.fixtureId}: builtin module-import invocation descriptor drift`,
    );
  }
}

function validateNonCapabilityBuiltinModuleImportInvocation(
  invocation,
  authored,
  recipe,
) {
  const expectation = NONCAP_BUILTIN_MODULE_IMPORT_ALIASES.get(
    authored.moduleSpecifier,
  );
  const surfaceObservedKey = `builtin:${authored.moduleSpecifier}`;
  const descriptor = authored.sourceDescriptor;
  const sourceMetadata = descriptor?.sourceMetadata;

  exactKeys(
    invocation,
    [
      "invocationSchema",
      "kind",
      "surfaceObservedKey",
      "moduleSpecifier",
      "sourceDescriptorDigest",
      "sourceExecution",
      "completion",
      "result",
    ],
    `${recipe.fixtureId}: non-capability builtin module-import runtime invocation`,
  );
  exactKeys(
    invocation.sourceExecution,
    [
      "schema",
      "observationId",
      "runtimeNonce",
      "moduleSpecifier",
      "sourceId",
      "cacheMiss",
      "bodyCompleted",
    ],
    `${recipe.fixtureId}: authenticated builtin source execution`,
  );
  exactKeys(
    authored,
    [
      "invocationSchema",
      "kind",
      "moduleSpecifier",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "arguments",
      "setup",
      "completion",
      "requiredAuthority",
      "expectedResult",
      "expectedTypedDecisionCount",
      "expectedTypedStages",
      "allowedCoverageEdgeIds",
      "expectedActionIds",
    ],
    `${recipe.fixtureId}: authored non-capability builtin module import`,
  );
  exactKeys(
    descriptor,
    [
      "kind",
      "moduleSpecifier",
      "sourceKey",
      "sourceRef",
      "sourceMetadata",
      "expectedRootType",
      "carrierEdgeId",
    ],
    `${recipe.fixtureId}: non-capability builtin module-import source descriptor`,
  );
  exactKeys(
    sourceMetadata,
    ["sourceKey", "bundleExternal", "importReachability", "moduleBuiltin"],
    `${recipe.fixtureId}: non-capability builtin module-import source metadata`,
  );
  exactKeys(
    authored.setup,
    ["kind"],
    `${recipe.fixtureId}: non-capability builtin module-import setup`,
  );
  exactKeys(
    authored.completion,
    ["kind", "timeoutMilliseconds"],
    `${recipe.fixtureId}: authored non-capability builtin completion`,
  );
  exactKeys(
    invocation.completion,
    ["kind", "status", "timeoutMilliseconds"],
    `${recipe.fixtureId}: non-capability builtin runtime completion`,
  );
  exactKeys(
    recipe.route,
    ["surfaceObservedKeys", "alternatives", "ambiguousCallees"],
    `${recipe.fixtureId}: non-capability builtin module-import route`,
  );
  if (recipe.route.alternatives?.length === 1) {
    exactKeys(
      recipe.route.alternatives[0],
      ["terminalObservedKey", "proofPaths"],
      `${recipe.fixtureId}: non-capability builtin module-import route alternative`,
    );
  }

  if (
    recipe.classification !== "non-capability" ||
    recipe.scenario !== "non-capability" ||
    expectation === undefined ||
    authored.invocationSchema !==
      "ibex/capsec-builtin-module-import-no-effect-invocation/1" ||
    authored.kind !== "builtin-module-import" ||
    invocation.kind !== authored.kind ||
    invocation.moduleSpecifier !== authored.moduleSpecifier ||
    recipe.publicSurfaceProbe?.surfaceObservedKey !== surfaceObservedKey ||
    invocation.surfaceObservedKey !== surfaceObservedKey ||
    recipe.terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.surfaceObservedKeys) !==
      canonicalJson([surfaceObservedKey]) ||
    recipe.route.alternatives?.length !== 1 ||
    recipe.route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.alternatives[0].proofPaths) !==
      canonicalJson([surfaceObservedKey]) ||
    canonicalJson(recipe.route.ambiguousCallees) !== canonicalJson([]) ||
    !Array.isArray(recipe.edgeIds) ||
    recipe.edgeIds.length !== 1 ||
    descriptor.carrierEdgeId !== recipe.edgeIds[0] ||
    canonicalJson(recipe.actionIds) !== canonicalJson([]) ||
    descriptor.kind !== "builtin-module-alias" ||
    descriptor.moduleSpecifier !== authored.moduleSpecifier ||
    descriptor.sourceKey !== expectation.sourceKey ||
    descriptor.sourceRef !==
      `modules.ts#specifiers:${expectation.sourceKey}` ||
    sourceMetadata.sourceKey !== expectation.sourceKey ||
    sourceMetadata.bundleExternal !== expectation.bundleExternal ||
    sourceMetadata.importReachability !== "public" ||
    sourceMetadata.moduleBuiltin !== expectation.moduleBuiltin ||
    descriptor.expectedRootType !== expectation.expectedRootType ||
    canonicalJson(authored.arguments) !== canonicalJson([]) ||
    authored.setup.kind !== "none" ||
    authored.completion.kind !== "event-loop-quiescence" ||
    authored.completion.timeoutMilliseconds !== 1_000 ||
    invocation.completion.kind !== authored.completion.kind ||
    invocation.completion.timeoutMilliseconds !==
      authored.completion.timeoutMilliseconds ||
    invocation.completion.status !== "quiescent" ||
    invocation.sourceExecution.schema !==
      "ibex/capsec-authenticated-builtin-source-execution/1" ||
    invocation.sourceExecution.observationId !== recipe.fixtureId ||
    !isTaggedRuntimeNonce(invocation.sourceExecution.runtimeNonce) ||
    invocation.sourceExecution.moduleSpecifier !== authored.moduleSpecifier ||
    invocation.sourceExecution.sourceId !==
      builtinCacheSourceId(expectation.sourceKey) ||
    invocation.sourceExecution.cacheMiss !== true ||
    invocation.sourceExecution.bodyCompleted !== true ||
    canonicalJson(authored.requiredAuthority) !== canonicalJson([]) ||
    authored.expectedResult !== "return" ||
    authored.expectedTypedDecisionCount !== 0 ||
    canonicalJson(authored.expectedTypedStages) !== canonicalJson([]) ||
    canonicalJson(authored.allowedCoverageEdgeIds) !== canonicalJson([]) ||
    canonicalJson(authored.expectedActionIds) !== canonicalJson([])
  ) {
    throw new Error(
      `${recipe.fixtureId}: non-capability builtin module-import invocation descriptor drift`,
    );
  }
}

function evidenceDigest(evidence) {
  const { evidenceDigest: _digest, ...payload } = evidence;
  return taggedDigest(payload);
}

export function computePublicSurfaceExecutionDigest(artifact) {
  const { publicSurfaceExecutionDigest: _digest, ...payload } = artifact;
  return taggedDigest(payload);
}

export function mergePublicBatchExecutions({
  batches,
  recipeCatalog,
  loadedEngineIdentity,
}) {
  if (!Array.isArray(batches)) {
    throw new Error("public fixture batches must be an array");
  }
  const knownFixtures = new Set(
    recipeCatalog.recipes.map((recipe) => recipe.fixtureId),
  );
  const seen = new Set();
  const executions = [];
  for (const [index, entry] of batches.entries()) {
    exactKeys(
      entry,
      ["batch", "expectedFixtureIds"],
      `public fixture batch binding ${index}`,
    );
    const { batch, expectedFixtureIds } = entry;
    exactKeys(
      batch,
      [
        "publicBatchEvidenceSchema",
        "recipeCatalogDigest",
        "loadedEngineIdentity",
        "executions",
      ],
      `public fixture batch ${index}`,
    );
    if (
      batch.publicBatchEvidenceSchema !==
        "ibex/capsec-public-batch-evidence/1" ||
      batch.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
      canonicalJson(batch.loadedEngineIdentity) !==
        canonicalJson(loadedEngineIdentity) ||
      !Array.isArray(batch.executions) ||
      !Array.isArray(expectedFixtureIds) ||
      new Set(expectedFixtureIds).size !== expectedFixtureIds.length ||
      expectedFixtureIds.some((fixtureId) => !knownFixtures.has(fixtureId))
    ) {
      throw new Error(`public fixture batch ${index} is stale or malformed`);
    }
    const observedFixtureIds = batch.executions.map(
      (execution) => execution?.fixtureId,
    );
    if (
      observedFixtureIds.some((fixtureId) => typeof fixtureId !== "string") ||
      new Set(observedFixtureIds).size !== observedFixtureIds.length ||
      canonicalJson([...observedFixtureIds].sort(compareText)) !==
        canonicalJson([...expectedFixtureIds].sort(compareText))
    ) {
      throw new Error(
        `public fixture batch ${index} is missing, duplicates, or adds fixtures`,
      );
    }
    for (const execution of batch.executions) {
      if (seen.has(execution.fixtureId)) {
        throw new Error(
          `${execution.fixtureId}: duplicate public execution across batch commands`,
        );
      }
      seen.add(execution.fixtureId);
      executions.push(structuredClone(execution));
    }
  }
  return executions.sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
}

function executionSummary(recipeCatalog, executions) {
  return {
    requiredFixtures: recipeCatalog.summary.requiredFixtures,
    executableFixtures: recipeCatalog.summary.fullyExecutableFixtures,
    internallyVerifiedFixtures:
      recipeCatalog.summary.internallyVerifiedFixtures,
    residualFixtures: recipeCatalog.summary.unresolvedFixtures,
    executedFixtures: executions.length,
    passedFixtures: executions.filter(
      (execution) => execution.outcome === "passed",
    ).length,
    failedFixtures: executions.filter(
      (execution) => execution.outcome === "failed",
    ).length,
    missingFixtures: recipeCatalog.summary.requiredFixtures - executions.length,
  };
}

export function buildPublicSurfaceExecutionArtifact({
  recipeCatalog,
  sourceRevision,
  sourceTreeDigest,
  target,
  engine,
  coverage = null,
  executions = [],
}) {
  validateRecipeCatalog(recipeCatalog, { target });
  const sortedExecutions = [...executions].sort((left, right) =>
    compareText(left.fixtureId, right.fixtureId),
  );
  const artifact = {
    publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest,
    target: structuredClone(target),
    engine: structuredClone(engine),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    summary: executionSummary(recipeCatalog, sortedExecutions),
    executions: sortedExecutions,
  };
  artifact.publicSurfaceExecutionDigest =
    computePublicSurfaceExecutionDigest(artifact);
  return validatePublicSurfaceExecutionArtifact(artifact, {
    recipeCatalog,
    target,
    sourceRevision,
    sourceTreeDigest,
    engine,
    coverage,
  });
}

function coverageTerminalMap(coverage) {
  if (!Array.isArray(coverage?.edges)) {
    throw new Error(
      "runtime public evidence requires the bound coverage registry",
    );
  }
  const terminals = new Map();
  for (const edge of coverage.edges) {
    const kind = edge?.surface?.kind;
    const name = edge?.surface?.name;
    if (
      typeof edge?.id !== "string" ||
      typeof kind !== "string" ||
      typeof name !== "string" ||
      terminals.has(edge.id)
    ) {
      throw new Error(
        "bound coverage registry has malformed or duplicate edges",
      );
    }
    terminals.set(edge.id, `${kind}:${name}`);
  }
  return terminals;
}

const isTaggedDigest = (value) =>
  typeof value === "string" && /^sha256-[A-Za-z0-9_-]{43}$/u.test(value);
const isTaggedRuntimeNonce = (value) =>
  typeof value === "string" &&
  /^u64:[1-9][0-9]*$/u.test(value) &&
  BigInt(value.slice(4)) <= 18_446_744_073_709_551_615n;

const EXACT_OPERATION_MANIFEST_DIGEST =
  "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
const EXACT_EMBEDDER_NON_CAPABILITY_SURFACES = new Map([
  [
    "callback:exact-host-call-async-resolve",
    ["callback-attribution-carrier", "exact-host-call-round-trip"],
  ],
  [
    "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback",
    ["callback-attribution-carrier", "exact-host-call-round-trip"],
  ],
  [
    "host-abi:ex_hermes_resolve_exact_host_call",
    ["callback-attribution-carrier", "exact-host-call-round-trip"],
  ],
  [
    "host-abi:ex_hermes_set_exact_host_call_async",
    ["authority-control-plane", "exact-endowment-install"],
  ],
  [
    "host-abi:ex_host_authorize_exact_endowment",
    ["authority-control-plane", "exact-endowment-authorize"],
  ],
  [
    "host-abi:ex_host_build_exact_armed_embedder_artifacts",
    ["authority-control-plane", "exact-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_prepare_armed_embedder_artifacts",
    ["authority-control-plane", "exact-artifact-prepare-round-trip"],
  ],
  [
    "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
    ["authority-control-plane", "exact-artifact-prepare-round-trip"],
  ],
]);

function validateGenerationSet(value, label) {
  exactKeys(value, ["negative", "dynamic", "handle"], label);
  if (
    ![value.negative, value.dynamic, value.handle].every(
      (generation) => Number.isSafeInteger(generation) && generation >= 0,
    )
  ) {
    throw new Error(`${label} is not a non-negative typed generation set`);
  }
}

function validateRootPrincipal(value, label) {
  exactKeys(value, ["kind", "identity"], label);
  if (value.kind !== "root" || value.identity !== "project-root") {
    throw new Error(`${label} is not the armed project root`);
  }
}

function validateCallbackPackagePrincipal(value, label) {
  exactKeys(value, ["kind", "name", "integrity", "locator"], label);
  if (
    value.kind !== "package" ||
    value.name !== "image-lib" ||
    value.locator !== "image-lib@2.4.1" ||
    !isTaggedDigest(value.integrity)
  ) {
    throw new Error(`${label} is not the authenticated callback package`);
  }
}

function validateCallbackInvariantResult(result, authored, fixtureId) {
  exactKeys(
    result,
    ["kind", "scenario", "outcome", "checks"],
    `${fixtureId}: callback invariant runtime result`,
  );
  if (
    result.kind !== "callback-security-invariant" ||
    result.scenario !== authored.scenario ||
    result.outcome !== "passed"
  ) {
    throw new Error(
      `${fixtureId}: callback invariant did not pass its authored scenario`,
    );
  }
  const checks = result.checks;
  const label = `${fixtureId}: ${authored.scenario} checks`;
  if (authored.scenario === "attribution-missing-deny") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "actualPrincipal",
        "invalidAttributionDenied",
        "runtimeNonce",
      ],
      label,
    );
    validateRootPrincipal(checks.actualPrincipal, `${label} actual principal`);
    if (
      checks.callbackExecuted !== true ||
      checks.invalidAttributionDenied !== true ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(
        `${label} did not prove fail-closed callback attribution`,
      );
    }
    return;
  }
  if (authored.scenario === "generation-recheck") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "actualPrincipal",
        "generationsBefore",
        "generationsAfter",
        "generationAdvanced",
        "scheduledDecisionRechecked",
        "runtimeNonce",
      ],
      label,
    );
    validateCallbackPackagePrincipal(
      checks.actualPrincipal,
      `${label} actual principal`,
    );
    validateGenerationSet(
      checks.generationsBefore,
      `${label} generations before`,
    );
    validateGenerationSet(
      checks.generationsAfter,
      `${label} generations after`,
    );
    if (
      checks.callbackExecuted !== true ||
      checks.generationAdvanced !== true ||
      checks.scheduledDecisionRechecked !== true ||
      checks.generationsAfter.negative <= checks.generationsBefore.negative ||
      checks.generationsAfter.dynamic <= checks.generationsBefore.dynamic ||
      checks.generationsAfter.handle !== checks.generationsBefore.handle ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(
        `${label} did not prove a post-revocation decision recheck`,
      );
    }
    return;
  }
  if (authored.scenario === "principal-restore") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "callbackPrincipal",
        "restoredPrincipal",
        "principalRestored",
        "runtimeNonce",
      ],
      label,
    );
    validateCallbackPackagePrincipal(
      checks.callbackPrincipal,
      `${label} callback principal`,
    );
    validateRootPrincipal(
      checks.restoredPrincipal,
      `${label} restored principal`,
    );
    if (
      checks.callbackExecuted !== true ||
      checks.principalRestored !== true ||
      !isTaggedRuntimeNonce(checks.runtimeNonce)
    ) {
      throw new Error(`${label} did not prove callback-principal restoration`);
    }
    return;
  }
  if (authored.scenario === "snapshot-mismatch-deny") {
    exactKeys(
      checks,
      [
        "callbackExecuted",
        "actualPrincipal",
        "sourceSnapshotDigest",
        "targetSnapshotDigest",
        "snapshotDigestsDiffer",
        "foreignBearerDenied",
        "sourceRuntimeNonce",
        "targetRuntimeNonce",
      ],
      label,
    );
    validateRootPrincipal(checks.actualPrincipal, `${label} actual principal`);
    if (
      checks.callbackExecuted !== true ||
      !isTaggedDigest(checks.sourceSnapshotDigest) ||
      !isTaggedDigest(checks.targetSnapshotDigest) ||
      checks.sourceSnapshotDigest === checks.targetSnapshotDigest ||
      checks.snapshotDigestsDiffer !== true ||
      checks.foreignBearerDenied !== true ||
      !isTaggedRuntimeNonce(checks.sourceRuntimeNonce) ||
      !isTaggedRuntimeNonce(checks.targetRuntimeNonce) ||
      checks.sourceRuntimeNonce === checks.targetRuntimeNonce
    ) {
      throw new Error(`${label} did not prove cross-snapshot bearer rejection`);
    }
    return;
  }
  if (authored.scenario === "cannot-widen-authority") {
    exactKeys(
      checks,
      [
        "bridgeExecuted",
        "requestRefused",
        "generationsBefore",
        "generationsAfter",
        "generationsUnchanged",
      ],
      label,
    );
    validateGenerationSet(
      checks.generationsBefore,
      `${label} generations before`,
    );
    validateGenerationSet(
      checks.generationsAfter,
      `${label} generations after`,
    );
    if (
      checks.bridgeExecuted !== true ||
      checks.requestRefused !== true ||
      checks.generationsUnchanged !== true ||
      canonicalJson(checks.generationsBefore) !==
        canonicalJson(checks.generationsAfter)
    ) {
      throw new Error(
        `${label} did not prove that the bridge cannot widen authority`,
      );
    }
    return;
  }
  if (authored.scenario === "post-lockdown-invariant") {
    const booleanChecks = [
      "bridgeExecuted",
      "structuralLockdown",
      "intrinsicsFrozen",
      "evaluatorsTamed",
      "hatchesAbsent",
      "compartmentWithholdsAuthority",
      "prototypeMutationBlocked",
      "authorityRequestRefused",
      "generationsUnchanged",
    ];
    exactKeys(
      checks,
      [...booleanChecks, "generationsBefore", "generationsAfter"],
      label,
    );
    validateGenerationSet(
      checks.generationsBefore,
      `${label} generations before`,
    );
    validateGenerationSet(
      checks.generationsAfter,
      `${label} generations after`,
    );
    if (
      !booleanChecks.every((name) => checks[name] === true) ||
      canonicalJson(checks.generationsBefore) !==
        canonicalJson(checks.generationsAfter)
    ) {
      throw new Error(`${label} did not prove the post-lockdown invariant`);
    }
    return;
  }
  if (authored.scenario === "non-capability") {
    const mechanism = authored.sourceDescriptor?.executionMechanism;
    if (checks.executionMechanism !== mechanism) {
      throw new Error(`${label} did not execute its source-bound mechanism`);
    }
    if (mechanism === "exact-host-call-round-trip") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "setterInstalled",
          "immutableCapability",
          "genericBridgeAbsent",
          "callbackExecuted",
          "operationId",
          "payloadLength",
          "completion",
          "completionTargetsConsumed",
          "completionCallbacksQueued",
          "completionCallbacksDelivered",
          "singleUseCompletion",
        ],
        label,
      );
      if (
        checks.setterInstalled !== true ||
        checks.immutableCapability !== true ||
        checks.genericBridgeAbsent !== true ||
        checks.callbackExecuted !== true ||
        checks.operationId !== 7 ||
        checks.payloadLength !== 3 ||
        checks.completion !== "9,8" ||
        checks.completionTargetsConsumed !== 1 ||
        checks.completionCallbacksQueued !== 1 ||
        checks.completionCallbacksDelivered !== 1 ||
        checks.singleUseCompletion !== true
      ) {
        throw new Error(
          `${label} did not prove the single-use Exact completion route`,
        );
      }
      return;
    }
    if (mechanism === "exact-endowment-install") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "setterInstalled",
          "immutableCapability",
          "genericBridgeAbsent",
          "baselineFinalized",
          "refreshHookRemoved",
          "callbackExecuted",
        ],
        label,
      );
      if (
        checks.setterInstalled !== true ||
        checks.immutableCapability !== true ||
        checks.genericBridgeAbsent !== true ||
        checks.baselineFinalized !== true ||
        checks.refreshHookRemoved !== true ||
        checks.callbackExecuted !== false
      ) {
        throw new Error(
          `${label} did not prove immutable Exact endowment installation`,
        );
      }
      return;
    }
    if (mechanism === "exact-endowment-authorize") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "contextClaimed",
          "endowmentAuthorized",
          "narrowedEndowmentRejected",
          "contextKind",
          "operationIds",
          "operationManifestDigest",
        ],
        label,
      );
      if (
        checks.contextClaimed !== true ||
        checks.endowmentAuthorized !== true ||
        checks.narrowedEndowmentRejected !== true ||
        checks.contextKind !== "app" ||
        canonicalJson(checks.operationIds) !== canonicalJson([7, 11]) ||
        checks.operationManifestDigest !== EXACT_OPERATION_MANIFEST_DIGEST
      ) {
        throw new Error(`${label} did not prove exact-set authorization`);
      }
      return;
    }
    if (mechanism === "exact-artifact-prepare-round-trip") {
      exactKeys(
        checks,
        [
          "executionMechanism",
          "artifactPrepared",
          "artifactSchema",
          "nonceFreshened",
          "digestRebound",
          "sourceDigest",
          "preparedDigest",
          "preparedPairAuthenticated",
        ],
        label,
      );
      if (
        checks.artifactPrepared !== true ||
        checks.artifactSchema !== "ibex/armed-embedder-artifacts/1" ||
        checks.nonceFreshened !== true ||
        checks.digestRebound !== true ||
        !isTaggedDigest(checks.sourceDigest) ||
        !isTaggedDigest(checks.preparedDigest) ||
        checks.sourceDigest === checks.preparedDigest ||
        checks.preparedPairAuthenticated !== true
      ) {
        throw new Error(
          `${label} did not prove authenticated artifact freshening`,
        );
      }
      return;
    }
  }
  throw new Error(`${fixtureId}: unsupported callback invariant scenario`);
}

/**
 * Check a source-derived startup-environment recipe against verifier-owned
 * carrier authority. Keeping this callable independently of runtime evidence
 * lets the fast recipe suite catch inventory/authority drift before a full
 * physical conformance run reaches final artifact validation.
 */
export function validateStartupEnvironmentRecipeDescriptor(recipe) {
  const authored = recipe?.publicSurfaceProbe?.invocation;
  if (
    authored?.invocationSchema !==
    "ibex/capsec-startup-environment-invocation/1"
  ) {
    throw new Error(
      `${recipe?.fixtureId ?? "unknown fixture"}: not a startup environment recipe`,
    );
  }
  const descriptor = authored.sourceDescriptor;
  const operation = authored.operation;
  exactKeys(
    descriptor,
    [
      "kind",
      "surfaceObservedKey",
      "environmentName",
      "sourceRef",
      "liveSourceRefs",
      "carrierEdgeId",
      "implementationBranchIds",
      "enforcementBranchIds",
      "selectedBranch",
      "executionMechanism",
      "moduleSpecifier",
      "preloadModuleSpecifiers",
      "observedEnvironmentNames",
      "observedEnvironmentAccesses",
      "principalMode",
      "auxiliaryDecisionEdgeId",
    ],
    `${recipe.fixtureId}: startup environment source descriptor`,
  );
  exactKeys(
    operation,
    [
      "kind",
      "moduleSpecifier",
      "preloadModuleSpecifiers",
      "observedEnvironmentNames",
      "observedEnvironmentAccesses",
      "environment",
      "principalMode",
    ],
    `${recipe.fixtureId}: startup environment operation`,
  );
  exactKeys(
    operation.environment,
    ["name", "presence"],
    `${recipe.fixtureId}: startup environment setup`,
  );
  const environmentName = operation.environment.name;
  const sourceExpectation =
    STARTUP_ENVIRONMENT_EXPECTATIONS.get(environmentName);
  const expectedPrincipalMode =
    authored.scenario === "deny" ? "package-denied" : "root-authorized";
  if (
    authored.kind !== "startup-environment-source" ||
    authored.surfaceKind !== "startup" ||
    authored.surfaceName !== `env:${environmentName}` ||
    ![
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
      "branch-selection",
    ].includes(authored.scenario) ||
    descriptor.kind !== "startup-environment-source" ||
    descriptor.surfaceObservedKey !== `startup:env:${environmentName}` ||
    descriptor.environmentName !== environmentName ||
    sourceExpectation === undefined ||
    descriptor.sourceRef !== sourceExpectation?.sourceRef ||
    canonicalJson(descriptor.liveSourceRefs) !==
      canonicalJson(sourceExpectation?.liveSourceRefs) ||
    descriptor.carrierEdgeId !== recipe.edgeIds?.[0] ||
    canonicalJson(descriptor.implementationBranchIds) !==
      canonicalJson(recipe.implementationBranchIds) ||
    canonicalJson(descriptor.enforcementBranchIds) !==
      canonicalJson(recipe.enforcementBranchIds) ||
    descriptor.selectedBranch?.id !== "absent" ||
    descriptor.executionMechanism !== sourceExpectation?.mechanism ||
    operation.kind !== sourceExpectation?.mechanism ||
    descriptor.moduleSpecifier !== sourceExpectation?.moduleSpecifier ||
    operation.moduleSpecifier !== sourceExpectation?.moduleSpecifier ||
    canonicalJson(descriptor.preloadModuleSpecifiers) !==
      canonicalJson(sourceExpectation?.preloadModuleSpecifiers) ||
    canonicalJson(operation.preloadModuleSpecifiers) !==
      canonicalJson(sourceExpectation?.preloadModuleSpecifiers) ||
    canonicalJson(descriptor.observedEnvironmentNames) !==
      canonicalJson(sourceExpectation?.observedEnvironmentNames) ||
    canonicalJson(operation.observedEnvironmentNames) !==
      canonicalJson(sourceExpectation?.observedEnvironmentNames) ||
    canonicalJson(descriptor.observedEnvironmentAccesses) !==
      canonicalJson(sourceExpectation?.observedEnvironmentAccesses) ||
    canonicalJson(operation.observedEnvironmentAccesses) !==
      canonicalJson(sourceExpectation?.observedEnvironmentAccesses) ||
    canonicalJson(authored.expectedResourceNames) !==
      canonicalJson(sourceExpectation?.observedEnvironmentNames) ||
    !sourceExpectation?.observedEnvironmentNames.includes(environmentName) ||
    descriptor.principalMode !== expectedPrincipalMode ||
    operation.principalMode !== expectedPrincipalMode ||
    operation.environment.presence !== "absent" ||
    !Array.isArray(operation.preloadModuleSpecifiers)
  ) {
    throw new Error(
      `${recipe.fixtureId}: startup environment runtime invocation descriptor drift`,
    );
  }
  return recipe;
}

export function validatePrincipalEnvironmentRecipeDescriptor(recipe) {
  const authored = recipe?.publicSurfaceProbe?.invocation;
  if (
    authored?.invocationSchema !==
    "ibex/capsec-principal-environment-invocation/1"
  ) {
    throw new Error(
      `${recipe?.fixtureId ?? "unknown fixture"}: not a principal environment recipe`,
    );
  }
  const descriptor = authored.sourceDescriptor;
  const operation = authored.operation;
  exactKeys(
    descriptor,
    [
      "kind",
      "surfaceObservedKey",
      "carrierEdgeId",
      "implementationBranchIds",
      "enforcementBranchIds",
      "selectedBranch",
      "sourceContract",
      "selectedProxyTrap",
      "auxiliaryObservedKey",
      "auxiliaryDecisionEdgeId",
      "principalMode",
    ],
    `${recipe.fixtureId}: principal environment source descriptor`,
  );
  exactKeys(
    operation,
    ["kind", "environmentName", "value", "principalMode"],
    `${recipe.fixtureId}: principal environment operation`,
  );
  const actionId =
    operation.kind === "read"
      ? "env:read"
      : operation.kind === "write"
        ? "env:write"
        : null;
  const expectedTrap = operation.kind === "read" ? "get" : "set";
  const expectedBridge =
    operation.kind === "read" ? "__exactGetEnv" : "__exactSetEnv";
  const expectedAuxiliaryObservedKey = `native-op:${expectedBridge}`;
  const expectedPrincipalMode =
    authored.scenario === "deny" ? "package-denied" : "root-authorized";
  const contract = descriptor.sourceContract;
  if (
    authored.kind !== "principal-environment-property" ||
    ![
      "allow",
      "deny",
      "malformed",
      "missing-attribution",
      "wrong-principal",
      "branch-selection",
    ].includes(authored.scenario) ||
    descriptor.kind !== "principal-environment-property" ||
    descriptor.surfaceObservedKey !== PRINCIPAL_ENVIRONMENT_SURFACE ||
    descriptor.carrierEdgeId !== recipe.edgeIds?.[0] ||
    canonicalJson(descriptor.implementationBranchIds) !==
      canonicalJson(recipe.implementationBranchIds) ||
    canonicalJson(descriptor.enforcementBranchIds) !==
      canonicalJson(recipe.enforcementBranchIds) ||
    descriptor.selectedBranch?.id !== operation.kind ||
    canonicalJson(descriptor.selectedBranch?.when) !==
      canonicalJson([
        {
          fact: "environment.property.operation",
          equals: operation.kind,
        },
      ]) ||
    contract?.schema !==
      "ibex/principal-environment-overlay-source-contract/1" ||
    contract.surfaceName !==
      PRINCIPAL_ENVIRONMENT_SURFACE.slice("native-op:".length) ||
    contract.dynamicMember !==
      "[[dynamic-table:principal-environment-overlay-properties]]" ||
    contract.globalPath !== "process.env" ||
    contract.binding?.factory !== "createEnvProxy" ||
    contract.binding?.member !== "Process.prototype.env" ||
    contract.factory?.name !== "createEnvProxy" ||
    canonicalJson(contract.nativeBridges) !==
      canonicalJson(["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"]) ||
    canonicalJson(contract.sourceRefs) !==
      canonicalJson(PRINCIPAL_ENVIRONMENT_SOURCE_REFS) ||
    contract.proxyTraps?.length !== 4 ||
    descriptor.selectedProxyTrap?.name !== expectedTrap ||
    descriptor.selectedProxyTrap?.sourceRef !==
      `packages/ibex-runtime-js/src/node/process.ts#createEnvProxy:Proxy.${expectedTrap}` ||
    !descriptor.selectedProxyTrap?.nativeBridges?.includes(expectedBridge) ||
    descriptor.auxiliaryObservedKey !== expectedAuxiliaryObservedKey ||
    typeof descriptor.auxiliaryDecisionEdgeId !== "string" ||
    descriptor.principalMode !== expectedPrincipalMode ||
    operation.principalMode !== expectedPrincipalMode ||
    operation.environmentName !== PRINCIPAL_ENVIRONMENT_NAME ||
    operation.value !==
      (operation.kind === "write" ? "ibex-capsec-value" : null) ||
    actionId === null ||
    canonicalJson(recipe.actionIds) !== canonicalJson([actionId])
  ) {
    throw new Error(
      `${recipe.fixtureId}: principal environment runtime invocation descriptor drift`,
    );
  }
  return recipe;
}

const REVIEWED_MODULE_LOADER_EXECUTION_POINTS = new Map([
  [
    "function:javascript:checkImportGate",
    "function:javascript:checkImportGate",
  ],
  [
    "function:javascript:__exactResolvedPath",
    "function:javascript:__exactResolvedPath",
  ],
  ["function:javascript:idToModuleId", "function:javascript:idToModuleId"],
  [
    "function:javascript:privateBridgesForBuiltin",
    "function:javascript:privateBridgesForBuiltin",
  ],
  [
    "function:javascript:privateResolverPath",
    "function:javascript:privateResolverPath",
  ],
  [
    "function:javascript:rejectRuntimeLoaderOptions",
    "function:javascript:rejectRuntimeLoaderOptions",
  ],
  [
    "function:javascript:resolverVirtualPath",
    "function:javascript:resolverVirtualPath",
  ],
  [
    "function:javascript:stripViteImportQuery",
    "function:javascript:stripViteImportQuery",
  ],
  ["import-needs", "function:javascript:rejectRuntimeLoaderOptions"],
  ["import-policy-bare", "function:javascript:checkImportGate"],
  ["internal-route:assert/strict", "internal-route:assert/strict"],
  [
    "internal-route:internal/fs/utils",
    "internal-route:internal/fs/utils",
  ],
  ["kind:builtin", "kind:builtin"],
]);

function expectedModuleLoaderExecutionPoint(descriptor) {
  return (
    REVIEWED_MODULE_LOADER_EXECUTION_POINTS.get(descriptor?.surfaceName) ??
    null
  );
}

function validateCapturedModuleLoaderRuntimeInvocation(
  invocation,
  authored,
  recipe,
) {
  const descriptor = authored.sourceDescriptor;
  const captured = authored.capturedOutputInvocation;
  const capturedDescriptor = captured?.sourceDescriptor;
  const route = captured?.route;
  const capturedAsync =
    captured?.completion?.kind === "event-loop-quiescence";
  exactKeys(
    authored,
    [
      "invocationSchema",
      "kind",
      "coverageEdgeId",
      "coverageClassification",
      "moduleSpecifier",
      "entrypoint",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "capturedOutputInvocation",
      "capturedOutputInvocationDigest",
      "completion",
      "requiredAuthority",
      "expectedResult",
      "expectedTypedStages",
      "expectedTypedDecisionCount",
      "allowedCoverageEdgeIds",
      "expectedActionIds",
    ],
    `${recipe.fixtureId}: authored captured module-loader invocation`,
  );
  exactKeys(
    descriptor,
    [
      "kind",
      "surfaceName",
      "evidenceType",
      "sourceRefs",
      "executionPoint",
      "outputSourceDescriptorDigest",
    ],
    `${recipe.fixtureId}: module-loader public source descriptor`,
  );
  exactKeys(
    captured,
    [
      "invocationSchema",
      "kind",
      "coverageEdgeId",
      "coverageClassification",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "route",
      "completion",
    ],
    `${recipe.fixtureId}: captured loader output invocation`,
  );
  exactKeys(
    capturedDescriptor,
    ["kind", "surfaceName", "evidenceType", "sourceRefs"],
    `${recipe.fixtureId}: captured loader output source descriptor`,
  );
  exactKeys(
    route,
    ["operation", "entrypoint", "specifier"],
    `${recipe.fixtureId}: captured loader output route`,
  );
  exactKeys(
    authored.completion,
    ["kind", "timeoutMilliseconds"],
    `${recipe.fixtureId}: authored loader completion`,
  );
  exactKeys(
    captured.completion,
    capturedAsync ? ["kind", "timeoutMilliseconds"] : ["kind"],
    `${recipe.fixtureId}: captured loader output completion`,
  );
  exactKeys(
    invocation,
    [
      "invocationSchema",
      "kind",
      "surfaceObservedKey",
      "moduleSpecifier",
      "entrypoint",
      "sourceDescriptorDigest",
      "completion",
      "sourceExecution",
      "result",
    ],
    `${recipe.fixtureId}: captured module-loader runtime invocation`,
  );
  exactKeys(
    invocation.completion,
    ["kind", "timeoutMilliseconds", "status"],
    `${recipe.fixtureId}: captured module-loader runtime completion`,
  );
  exactKeys(
    invocation.sourceExecution,
    [
      "schema",
      "observationId",
      "runtimeNonce",
      "executionPoint",
      "matchCount",
      "loaderPrivate",
    ],
    `${recipe.fixtureId}: loader-private source execution`,
  );
  exactKeys(
    invocation.result,
    [
      "kind",
      "sourceOperationAttempted",
      "entrypointProof",
      "rawOutput",
    ],
    `${recipe.fixtureId}: captured loader result`,
  );
  exactKeys(
    invocation.result.entrypointProof,
    ["presence", "descriptorKind", "valueType"],
    `${recipe.fixtureId}: loader entrypoint proof`,
  );
  exactKeys(
    invocation.result.rawOutput,
    ["kind", "rawValueShape", "value", "errorCode"],
    `${recipe.fixtureId}: loader raw output`,
  );
  exactKeys(
    recipe.route,
    ["surfaceObservedKeys", "alternatives", "ambiguousCallees"],
    `${recipe.fixtureId}: module-loader recipe route`,
  );
  if (recipe.route.alternatives?.length === 1) {
    exactKeys(
      recipe.route.alternatives[0],
      ["terminalObservedKey", "proofPaths"],
      `${recipe.fixtureId}: module-loader route alternative`,
    );
  }
  const surfaceObservedKey = `loader:${descriptor.surfaceName}`;
  const expectedPoint = expectedModuleLoaderExecutionPoint(descriptor);
  if (
    authored.invocationSchema !==
      "ibex/capsec-loader-captured-invocation/1" ||
    authored.kind !== "module-loader-captured-route" ||
    recipe.classification !== "non-capability" ||
    recipe.scenario !== "non-capability" ||
    canonicalJson(recipe.actionIds) !== canonicalJson([]) ||
    canonicalJson(recipe.edgeIds) !==
      canonicalJson([authored.coverageEdgeId]) ||
    authored.coverageClassification !== "non-capability" ||
    canonicalJson(authored.allowedCoverageEdgeIds) !==
      canonicalJson([authored.coverageEdgeId]) ||
    authored.expectedResult !== "source-completion" ||
    authored.expectedTypedDecisionCount !== 0 ||
    canonicalJson(authored.expectedTypedStages) !== canonicalJson([]) ||
    canonicalJson(authored.expectedActionIds) !== canonicalJson([]) ||
    canonicalJson(authored.requiredAuthority) !== canonicalJson([]) ||
    descriptor.kind !== "module-loader-public-route" ||
    typeof descriptor.surfaceName !== "string" ||
    descriptor.surfaceName.length === 0 ||
    expectedPoint === null ||
    descriptor.executionPoint !== expectedPoint ||
    !Array.isArray(descriptor.sourceRefs) ||
    descriptor.sourceRefs.length === 0 ||
    !descriptor.sourceRefs.every(
      (sourceRef) => typeof sourceRef === "string" && sourceRef.length > 0,
    ) ||
    !descriptor.sourceRefs.some((sourceRef) =>
      sourceRef.startsWith("src/engine/bootstrap/module-loader.js#"),
    ) ||
    captured.invocationSchema !==
      "ibex/capsec-loader-output-invocation/1" ||
    captured.kind !== "loader-output" ||
    captured.coverageEdgeId !== authored.coverageEdgeId ||
    captured.coverageClassification !== authored.coverageClassification ||
    captured.sourceDescriptorDigest !==
      descriptor.outputSourceDescriptorDigest ||
    captured.sourceDescriptorDigest !== taggedDigest(capturedDescriptor) ||
    capturedDescriptor.kind !== "module-loader-surface" ||
    capturedDescriptor.surfaceName !== descriptor.surfaceName ||
    capturedDescriptor.evidenceType !== descriptor.evidenceType ||
    canonicalJson(capturedDescriptor.sourceRefs) !==
      canonicalJson(descriptor.sourceRefs) ||
    authored.capturedOutputInvocationDigest !== taggedDigest(captured) ||
    route.operation !== "invoke-public-loader" ||
    Object.hasOwn(route, "authority") ||
    route.entrypoint !== authored.entrypoint ||
    route.specifier !== authored.moduleSpecifier ||
    !new Set([
      "exact-require",
      "global-import",
      "global-require",
      "import-module",
      "require-resolve",
    ]).has(authored.entrypoint) ||
    !new Set([
      "synchronous-loaded-runtime",
      "event-loop-quiescence",
    ]).has(captured.completion.kind) ||
    (capturedAsync && captured.completion.timeoutMilliseconds !== 1_000) ||
    authored.completion.kind !== "event-loop-quiescence" ||
    authored.completion.timeoutMilliseconds !== 1_000 ||
    recipe.publicSurfaceProbe.surfaceObservedKey !== surfaceObservedKey ||
    recipe.terminalObservedKey !== surfaceObservedKey ||
    canonicalJson(recipe.route.surfaceObservedKeys) !==
      canonicalJson([surfaceObservedKey]) ||
    recipe.route.alternatives?.length !== 1 ||
    recipe.route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    !Array.isArray(recipe.route.alternatives[0].proofPaths) ||
    recipe.route.alternatives[0].proofPaths.length === 0 ||
    canonicalJson(recipe.route.ambiguousCallees) !== canonicalJson([]) ||
    invocation.kind !== authored.kind ||
    invocation.moduleSpecifier !== authored.moduleSpecifier ||
    invocation.entrypoint !== authored.entrypoint ||
    invocation.completion.kind !== authored.completion.kind ||
    invocation.completion.timeoutMilliseconds !==
      authored.completion.timeoutMilliseconds ||
    invocation.completion.status !== "quiescent" ||
    invocation.sourceExecution.schema !==
      "ibex/capsec-loader-source-point-execution/1" ||
    invocation.sourceExecution.observationId !== recipe.fixtureId ||
    !isTaggedRuntimeNonce(invocation.sourceExecution.runtimeNonce) ||
    invocation.sourceExecution.executionPoint !== expectedPoint ||
    !Number.isSafeInteger(invocation.sourceExecution.matchCount) ||
    invocation.sourceExecution.matchCount < 1 ||
    invocation.sourceExecution.loaderPrivate !== true ||
    invocation.result.kind !== "return" ||
    invocation.result.sourceOperationAttempted !== true ||
    invocation.result.entrypointProof.valueType !== "function" ||
    invocation.result.rawOutput.kind !== "return" ||
    invocation.result.rawOutput.errorCode !== null
  ) {
    throw new Error(
      `${recipe.fixtureId}: captured module-loader invocation descriptor drift`,
    );
  }
}

function validateRuntimeInvocation(observation, recipe) {
  const invocation = observation.invocation;
  const authored = recipe.publicSurfaceProbe?.invocation;
  if (!authored || typeof authored.invocationSchema !== "string") {
    throw new Error(
      `${recipe.fixtureId}: public probe has no typed invocation descriptor`,
    );
  }
  const commonKeys = [
    "invocationSchema",
    "kind",
    "surfaceObservedKey",
    "sourceDescriptorDigest",
    "result",
  ];
  if (
    invocation?.invocationSchema ===
    "ibex/capsec-loader-captured-invocation/1"
  ) {
    validateCapturedModuleLoaderRuntimeInvocation(
      invocation,
      authored,
      recipe,
    );
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-global-callable-invocation/1"
  ) {
    exactKeys(
      authored,
      [
        "invocationSchema",
        "kind",
        "coverageEdgeId",
        "coverageClassification",
        "sourceDescriptor",
        "sourceDescriptorDigest",
        "route",
        "completion",
        "expectedResult",
        "expectedTypedStages",
        "expectedTypedDecisionCount",
        "allowedCoverageEdgeIds",
        "expectedActionIds",
      ],
      `${recipe.fixtureId}: authored global callable invocation`,
    );
    exactKeys(
      invocation,
      [...commonKeys, "globalName", "memberName", "completion"],
      `${recipe.fixtureId}: global callable runtime invocation`,
    );
    exactKeys(
      authored.sourceDescriptor,
      ["kind", "globalName", "memberName", "memberKinds", "sourceRefs"],
      `${recipe.fixtureId}: global callable source descriptor`,
    );
    exactKeys(
      authored.completion,
      ["kind", "timeoutMilliseconds"],
      `${recipe.fixtureId}: authored global callable completion`,
    );
    exactKeys(
      invocation.completion,
      ["kind", "status", "timeoutMilliseconds"],
      `${recipe.fixtureId}: global callable runtime completion`,
    );
    const descriptor = authored.sourceDescriptor;
    const memberSuffix =
      descriptor.memberName === null ? "" : `.${descriptor.memberName}`;
    const sharedRuntimeObservedKey =
      `native-op:global:${descriptor.globalName}${memberSuffix}`;
    const expectedObservedKeys = new Set([
      sharedRuntimeObservedKey,
      ...(descriptor.memberName === null
        ? [`native-op:${descriptor.globalName}`]
        : []),
    ]);
    if (
      recipe.classification !== "non-capability" ||
      recipe.scenario !== "non-capability" ||
      recipe.actionIds.length !== 0 ||
      recipe.edgeIds.length !== 1 ||
      authored.kind !== "global-callable-invocation" ||
      authored.coverageClassification !== "non-capability" ||
      authored.coverageEdgeId !== recipe.edgeIds[0] ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson([authored.coverageEdgeId]) ||
      authored.expectedResult !== "source-completion" ||
      authored.expectedTypedDecisionCount !== 0 ||
      authored.expectedTypedStages.length !== 0 ||
      authored.expectedActionIds.length !== 0 ||
      descriptor.kind !== "global-api-callable" ||
      typeof descriptor.globalName !== "string" ||
      descriptor.globalName.length === 0 ||
      (descriptor.memberName !== null &&
        (typeof descriptor.memberName !== "string" ||
          descriptor.memberName.length === 0)) ||
      !Array.isArray(descriptor.memberKinds) ||
      descriptor.memberKinds.length === 0 ||
      !descriptor.memberKinds.every(
        (kind) => typeof kind === "string" && kind.length > 0,
      ) ||
      !Array.isArray(descriptor.sourceRefs) ||
      descriptor.sourceRefs.length === 0 ||
      !descriptor.sourceRefs.every(
        (sourceRef) =>
          typeof sourceRef === "string" && sourceRef.length > 0,
      ) ||
      !expectedObservedKeys.has(
        recipe.publicSurfaceProbe.surfaceObservedKey,
      ) ||
      recipe.route.surfaceObservedKeys.length !== 1 ||
      recipe.route.surfaceObservedKeys[0] !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      recipe.route.alternatives.length !== 1 ||
      recipe.route.alternatives[0].terminalObservedKey !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      recipe.route.ambiguousCallees.length !== 0 ||
      !new Set(["call", "construct", "get"]).has(
        authored.route?.operation,
      ) ||
      Object.hasOwn(authored.route, "authority") ||
      authored.completion.kind !== "event-loop-quiescence" ||
      authored.completion.timeoutMilliseconds !== 1_000 ||
      invocation.kind !== authored.kind ||
      invocation.globalName !== descriptor.globalName ||
      invocation.memberName !== descriptor.memberName ||
      invocation.completion.kind !== authored.completion.kind ||
      invocation.completion.timeoutMilliseconds !==
        authored.completion.timeoutMilliseconds ||
      invocation.completion.status !== "quiescent"
    ) {
      throw new Error(
        `${recipe.fixtureId}: global callable runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    const requiresCompletion = authored.completion !== undefined;
    exactKeys(
      invocation,
      [
        ...commonKeys,
        "globalName",
        "executionProof",
        ...(requiresCompletion ? ["completion"] : []),
      ],
      `${recipe.fixtureId}: native runtime invocation`,
    );
    if (
      !new Set([
        "global-property-read",
        "native-global-function",
        "private-native-facade-function",
      ]).has(invocation.kind) ||
      invocation.kind !== authored.kind ||
      invocation.globalName !== authored.globalName
    ) {
      throw new Error(
        `${recipe.fixtureId}: native runtime invocation descriptor drift`,
      );
    }
    const hasPublicAccess = Object.hasOwn(authored, "publicAccess");
    const hasPublicAccessDigest = Object.hasOwn(authored, "publicAccessDigest");
    const hasTopLevelDenyFragment = Object.hasOwn(
      authored,
      "expectedDenyMessageFragment",
    );
    if (authored.kind === "private-native-facade-function") {
      const access = authored.publicAccess;
      const publicDisposition = rootGlobalDispositionByInstallId(
        access?.installId,
      );
      const privateDisposition = rootGlobalDispositionByInstallId(
        access?.privateTerminal?.installId,
      );
      exactKeys(
        access,
        [
          "kind",
          "observedKey",
          "installId",
          "path",
          "sourceRefs",
          "privateTerminal",
          "expectedDenyMessageFragment",
        ],
        `${recipe.fixtureId}: private native facade access`,
      );
      exactKeys(
        access.privateTerminal,
        ["observedKey", "installId", "privateConsumer", "liveExpectation"],
        `${recipe.fixtureId}: private native facade terminal`,
      );
      if (
        authored.globalName !== "__exactGetCwd" ||
        recipe.publicSurfaceProbe.surfaceObservedKey !==
          "native-op:__exactGetCwd" ||
        hasPublicAccess !== true ||
        hasPublicAccessDigest !== true ||
        hasTopLevelDenyFragment ||
        authored.publicAccessDigest !== taggedDigest(access) ||
        access.kind !== "captured-private-global-function" ||
        access.observedKey !== "native-op:global:process.cwd" ||
        canonicalJson(access.path) !== canonicalJson(["process", "cwd"]) ||
        publicDisposition?.observedKey !== access.observedKey ||
        publicDisposition?.branch?.activation !== "always" ||
        publicDisposition?.disposition !== "converted" ||
        publicDisposition?.liveExpectation !== "reachable" ||
        canonicalJson(publicDisposition?.property) !==
          canonicalJson({
            root: { kind: "string", value: "process" },
            path: [{ kind: "string", value: "cwd" }],
          }) ||
        canonicalJson(access.sourceRefs) !==
          canonicalJson(publicDisposition?.branch?.sourceRefs) ||
        access.privateTerminal.observedKey !== "native-op:__exactGetCwd" ||
        access.privateTerminal.privateConsumer !==
          "trusted-path-process-builtins" ||
        access.privateTerminal.liveExpectation !== "absent" ||
        privateDisposition?.observedKey !==
          access.privateTerminal.observedKey ||
        privateDisposition?.branch?.activation !== "always" ||
        privateDisposition?.disposition !== "private" ||
        privateDisposition?.privateConsumer !==
          access.privateTerminal.privateConsumer ||
        privateDisposition?.liveExpectation !==
          access.privateTerminal.liveExpectation ||
        canonicalJson(privateDisposition?.property) !==
          canonicalJson({
            root: { kind: "string", value: "__exactGetCwd" },
            path: [],
          }) ||
        access.expectedDenyMessageFragment !== "filesystem policy denied"
      ) {
        throw new Error(
          `${recipe.fixtureId}: private native facade provenance drift`,
        );
      }
    } else {
      if (hasPublicAccess || hasPublicAccessDigest) {
        throw new Error(
          `${recipe.fixtureId}: ordinary native invocation carries private facade authority`,
        );
      }
      if (hasTopLevelDenyFragment) {
        try {
          validateNativeFilesystemDenialRecipeDescriptor(authored);
        } catch {
          throw new Error(
            `${recipe.fixtureId}: unreviewed native denial expectation`,
          );
        }
      }
    }
    if (requiresCompletion) {
      exactKeys(
        authored.completion,
        ["kind", "timeoutMilliseconds"],
        `${recipe.fixtureId}: authored native completion`,
      );
      exactKeys(
        invocation.completion,
        ["kind", "status", "timeoutMilliseconds"],
        `${recipe.fixtureId}: native runtime completion`,
      );
      if (
        authored.completion.kind !== "event-loop-quiescence" ||
        authored.completion.timeoutMilliseconds !== 1_000 ||
        invocation.completion.kind !== authored.completion.kind ||
        invocation.completion.timeoutMilliseconds !==
          authored.completion.timeoutMilliseconds ||
        invocation.completion.status !== "quiescent"
      ) {
        throw new Error(
          `${recipe.fixtureId}: native work escaped its observation session`,
        );
      }
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-host-abi-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "functionName"],
      `${recipe.fixtureId}: host ABI runtime invocation`,
    );
    const sqliteMemory = authored.operation?.kind === "sqlite-memory";
    const moduleRunner =
      authored.operation?.kind === "module-runner-source-graph";
    if (
      invocation.kind !== "host-abi-function" ||
      invocation.functionName !== authored.functionName ||
      (!sqliteMemory && !moduleRunner) ||
      authored.sourceDescriptor?.kind !== "host-abi-function" ||
      authored.sourceDescriptor?.functionName !== authored.functionName ||
      (sqliteMemory &&
        (authored.operation?.selectedBranch?.id !== "memory" ||
          canonicalJson(authored.sourceDescriptor?.selectedBranch) !==
            canonicalJson(authored.operation?.selectedBranch))) ||
      (moduleRunner &&
        canonicalJson(authored.sourceDescriptor?.sourceRefs) !==
          canonicalJson([
            `src/engine/hermes_module_runner.cc#${authored.functionName}`,
          ]))
    ) {
      throw new Error(
        `${recipe.fixtureId}: host ABI runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-module-loader-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceName"],
      `${recipe.fixtureId}: module-loader runtime invocation`,
    );
    const operations = new Map([
      ["module-runner-edge-authorization", "authorize-edge"],
      ["module-runner-trusted-source-acquisition", "source-acquisition"],
      ["module-runner-cache-access", "cache-read"],
      ["module-runner-prepared-carrier-access", "prepared-carrier-read"],
    ]);
    const expectedOperation = operations.get(authored.surfaceName);
    const expectedFunction =
      expectedOperation === "authorize-edge"
        ? "authorize"
        : "authorize_then_access";
    if (
      invocation.kind !== "module-loader-authority" ||
      invocation.surfaceName !== authored.surfaceName ||
      !expectedOperation ||
      authored.operation?.kind !== expectedOperation ||
      authored.sourceDescriptor?.kind !== "module-loader-function" ||
      authored.sourceDescriptor?.surfaceName !== authored.surfaceName ||
      canonicalJson(authored.sourceDescriptor?.sourceRefs) !==
        canonicalJson([
          `src/module_loader/security.rs#${expectedFunction}`,
        ])
    ) {
      throw new Error(
        `${recipe.fixtureId}: module-loader runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-builtin-module-import-no-effect-invocation/1"
  ) {
    validateNonCapabilityBuiltinModuleImportInvocation(
      invocation,
      authored,
      recipe,
    );
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-builtin-module-import-invocation/1"
  ) {
    validateEffectBuiltinModuleImportInvocation(invocation, authored, recipe);
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-builtin-noncap-captured-invocation/1"
  ) {
    const captured = authored.capturedOutputInvocation;
    const descriptor = authored.sourceDescriptor;
    const route = captured?.route;
    exactKeys(
      authored,
      [
        "invocationSchema",
        "kind",
        "moduleSpecifier",
        "exportName",
        "sourceDescriptor",
        "sourceDescriptorDigest",
        "arguments",
        "setup",
        "completion",
        "capturedOutputInvocation",
        "requiredAuthority",
        "expectedResult",
        "expectedTypedDecisionCount",
        "expectedTypedStages",
        "allowedCoverageEdgeIds",
        "expectedActionIds",
      ],
      `${recipe.fixtureId}: authored captured non-capability builtin invocation`,
    );
    exactKeys(
      invocation,
      [...commonKeys, "moduleSpecifier", "exportName", "completion"],
      `${recipe.fixtureId}: captured non-capability builtin runtime invocation`,
    );
    exactKeys(
      captured,
      [
        "invocationSchema",
        "kind",
        "coverageEdgeId",
        "coverageClassification",
        "surfaceObservedKey",
        "moduleSpecifier",
        "sourceDescriptor",
        "sourceDescriptorDigest",
        "route",
        "completion",
      ],
      `${recipe.fixtureId}: captured output invocation`,
    );
    exactKeys(
      descriptor,
      [
        "kind",
        "sourceKey",
        "exportName",
        "exportIdioms",
        "moduleSpecifiers",
        "sourceRef",
        "valueShape",
        "importReachability",
        "access",
        ...(Object.hasOwn(descriptor ?? {}, "platformAvailability")
          ? ["platformAvailability"]
          : []),
      ],
      `${recipe.fixtureId}: captured builtin source descriptor`,
    );
    exactKeys(
      descriptor.access,
      ["kind", "path"],
      `${recipe.fixtureId}: captured builtin source access`,
    );
    exactKeys(
      route,
      [
        "operation",
        ...(Object.hasOwn(route ?? {}, "receiver") ? ["receiver"] : []),
        "arguments",
        "cleanup",
        ...(Object.hasOwn(route ?? {}, "awaitResult") ? ["awaitResult"] : []),
        ...(Object.hasOwn(route ?? {}, "inheritedTemplateId")
          ? ["inheritedTemplateId"]
          : []),
        ...(Object.hasOwn(route ?? {}, "dependencyModuleSpecifiers")
          ? ["dependencyModuleSpecifiers"]
          : []),
        "outcomeCapture",
      ],
      `${recipe.fixtureId}: captured builtin source route`,
    );
    exactKeys(
      authored.setup,
      ["kind"],
      `${recipe.fixtureId}: captured builtin setup`,
    );
    exactKeys(
      authored.completion,
      ["kind", "timeoutMilliseconds"],
      `${recipe.fixtureId}: authored captured builtin completion`,
    );
    exactKeys(
      invocation.completion,
      ["kind", "status", "timeoutMilliseconds"],
      `${recipe.fixtureId}: captured builtin runtime completion`,
    );
    const routeMatchesValueShape =
      (route.operation === "call" &&
        new Set(["callable", "unknown"]).has(descriptor.valueShape)) ||
      (route.operation === "construct" &&
        new Set(["callable", "data", "unknown"]).has(
          descriptor.valueShape,
        )) ||
      (route.operation === "get" &&
        new Set(["accessor", "data", "unknown"]).has(
          descriptor.valueShape,
        ));
    if (
      recipe.classification !== "non-capability" ||
      recipe.scenario !== "non-capability" ||
      recipe.actionIds.length !== 0 ||
      recipe.edgeIds.length !== 1 ||
      authored.kind !== "builtin-noncap-captured-call" ||
      authored.moduleSpecifier !== captured.moduleSpecifier ||
      authored.exportName !== descriptor.exportName ||
      authored.sourceDescriptorDigest !== taggedDigest(descriptor) ||
      captured.invocationSchema !==
        "ibex/capsec-builtin-noncap-closed-output-invocation/1" ||
      captured.kind !== "builtin-noncap-closed-output" ||
      captured.coverageClassification !== "non-capability" ||
      captured.coverageEdgeId !== recipe.edgeIds[0] ||
      captured.surfaceObservedKey !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      captured.sourceDescriptorDigest !== authored.sourceDescriptorDigest ||
      canonicalJson(captured.sourceDescriptor) !==
        canonicalJson(descriptor) ||
      descriptor.kind !== "builtin-export" ||
      descriptor.importReachability !== "public" ||
      !routeMatchesValueShape ||
      !Array.isArray(descriptor.exportIdioms) ||
      descriptor.exportIdioms.length === 0 ||
      !Array.isArray(descriptor.moduleSpecifiers) ||
      !descriptor.moduleSpecifiers.includes(authored.moduleSpecifier) ||
      typeof descriptor.sourceRef !== "string" ||
      descriptor.sourceRef.length === 0 ||
      !Array.isArray(descriptor.access?.path) ||
      (descriptor.access.kind !== "module-value" &&
        descriptor.access.path.length === 0) ||
      !new Set([
        "export-property",
        "prototype-property",
        "inherited-prototype-property",
        "module-value",
      ]).has(descriptor.access.kind) ||
      !new Set(["call", "construct", "get"]).has(route.operation) ||
      !Array.isArray(route.arguments) ||
      !route.cleanup ||
      typeof route.cleanup.kind !== "string" ||
      route.cleanup.kind.length === 0 ||
      route.outcomeCapture !== "public-builtin-family" ||
      Object.hasOwn(route, "authority") ||
      canonicalJson(authored.arguments) !== canonicalJson([]) ||
      authored.setup.kind !== "captured-output-route" ||
      canonicalJson(authored.requiredAuthority) !== canonicalJson([]) ||
      authored.expectedResult !== "captured-source-return" ||
      authored.expectedTypedDecisionCount !== 0 ||
      canonicalJson(authored.expectedTypedStages) !== canonicalJson([]) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !== canonicalJson([]) ||
      canonicalJson(authored.expectedActionIds) !== canonicalJson([]) ||
      authored.completion.kind !== "event-loop-quiescence" ||
      authored.completion.timeoutMilliseconds !== 1_000 ||
      canonicalJson(captured.completion) !==
        canonicalJson(authored.completion) ||
      invocation.kind !== authored.kind ||
      invocation.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.exportName !== authored.exportName ||
      invocation.completion.kind !== authored.completion.kind ||
      invocation.completion.timeoutMilliseconds !==
        authored.completion.timeoutMilliseconds ||
      invocation.completion.status !== "quiescent"
    ) {
      throw new Error(
        `${recipe.fixtureId}: captured non-capability builtin invocation descriptor drift`,
      );
    }
  } else if (
    BUILTIN_RUNTIME_INVOCATION_SCHEMAS.has(invocation?.invocationSchema)
  ) {
    const requiresCompletion = recipe.classification === "non-capability";
    exactKeys(
      invocation,
      [
        ...commonKeys,
        "moduleSpecifier",
        "exportName",
        ...(requiresCompletion ? ["completion"] : []),
      ],
      `${recipe.fixtureId}: builtin runtime invocation`,
    );
    const expectedKind =
      invocation.invocationSchema === "ibex/capsec-builtin-call-invocation/1"
        ? "builtin-export-call"
        : null;
    if (authored.kind === "builtin-export-read") {
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "sourceKey",
          "exportName",
          "exportIdioms",
          "moduleSpecifiers",
          "sourceRef",
          "valueShape",
          "access",
          ...(Object.hasOwn(descriptor ?? {}, "expectedValueType")
            ? ["expectedValueType"]
            : []),
          ...(Object.hasOwn(descriptor ?? {}, "platformAvailability")
            ? ["platformAvailability"]
            : []),
        ],
        `${recipe.fixtureId}: builtin read source descriptor`,
      );
      if (
        (Object.hasOwn(descriptor, "expectedValueType") ||
          descriptor.valueShape === "unknown") &&
        !isReviewedDnsPromiseErrorDescriptor(descriptor) &&
        !isReviewedPostInitializationValueDescriptor(descriptor) &&
        !isReviewedPrototypeValueDescriptor(descriptor) &&
        !isReviewedStreamInstanceValueDescriptor(descriptor) &&
        !isReviewedX509RawInstanceValueDescriptor(descriptor) &&
        !isReviewedTlsSecureContextInstanceValueDescriptor(descriptor)
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin read has an unreviewed runtime value-type expectation`,
        );
      }
    }
    if (
      (expectedKind
        ? invocation.kind !== expectedKind
        : !["builtin-export-call", "builtin-export-read"].includes(
            invocation.kind,
          )) ||
      (invocation.invocationSchema ===
        "ibex/capsec-builtin-call-invocation/1" &&
        authored.expectedResult !== "normal-return") ||
      invocation.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.exportName !== (authored.exportName ?? null)
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin runtime invocation descriptor drift`,
      );
    }
    if (requiresCompletion) {
      exactKeys(
        authored.completion,
        ["kind", "timeoutMilliseconds"],
        `${recipe.fixtureId}: authored builtin completion`,
      );
      exactKeys(
        invocation.completion,
        ["kind", "status", "timeoutMilliseconds"],
        `${recipe.fixtureId}: builtin runtime completion`,
      );
      if (
        authored.completion.kind !== "event-loop-quiescence" ||
        authored.completion.timeoutMilliseconds !== 1_000 ||
        invocation.completion.kind !== authored.completion.kind ||
        invocation.completion.timeoutMilliseconds !==
          authored.completion.timeoutMilliseconds ||
        invocation.completion.status !== "quiescent"
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin work escaped its observation session`,
        );
      }
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-startup-surface-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName"],
      `${recipe.fixtureId}: startup runtime invocation`,
    );
    const expectation = STARTUP_EXPECTATIONS.get(authored.surfaceName);
    const descriptor = authored.sourceDescriptor;
    const operation = authored.operation;
    exactKeys(
      descriptor,
      [
        "kind",
        "surfaceName",
        "postcondition",
        "requiredFacts",
        "sourceRefs",
        "sourceMetadata",
        "environment",
      ],
      `${recipe.fixtureId}: startup source descriptor`,
    );
    exactKeys(
      operation,
      ["kind", "postcondition", "requiredFacts", "environment"],
      `${recipe.fixtureId}: startup operation`,
    );
    if (
      invocation.kind !== "startup-loaded-engine" ||
      invocation.surfaceKind !== "startup" ||
      invocation.surfaceName !== authored.surfaceName ||
      expectation === undefined ||
      descriptor.kind !== "startup-loaded-engine-postcondition" ||
      descriptor.surfaceName !== authored.surfaceName ||
      descriptor.postcondition !== expectation.postcondition ||
      canonicalJson(descriptor.requiredFacts) !==
        canonicalJson(expectation.requiredFacts) ||
      canonicalJson(descriptor.sourceRefs) !==
        canonicalJson([expectation.sourceRef]) ||
      descriptor.sourceMetadata !== null ||
      canonicalJson(descriptor.environment) !==
        canonicalJson(expectation.environment) ||
      operation.kind !== "loaded-engine-startup" ||
      operation.postcondition !== expectation.postcondition ||
      canonicalJson(operation.requiredFacts) !==
        canonicalJson(expectation.requiredFacts) ||
      canonicalJson(operation.environment) !==
        canonicalJson(expectation.environment)
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-startup-environment-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "scenario"],
      `${recipe.fixtureId}: startup environment runtime invocation`,
    );
    validateStartupEnvironmentRecipeDescriptor(recipe);
    const operation = authored.operation;
    const environmentName = operation.environment.name;
    if (
      invocation.kind !== "startup-environment-source" ||
      invocation.surfaceKind !== "startup" ||
      invocation.surfaceName !== `env:${environmentName}` ||
      invocation.scenario !== authored.scenario
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup environment runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-principal-environment-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "scenario"],
      `${recipe.fixtureId}: principal environment runtime invocation`,
    );
    validatePrincipalEnvironmentRecipeDescriptor(recipe);
    if (
      invocation.kind !== "principal-environment-property" ||
      invocation.scenario !== authored.scenario
    ) {
      throw new Error(
        `${recipe.fixtureId}: principal environment runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-target-absence-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "targetTriple"],
      `${recipe.fixtureId}: target-absence runtime invocation`,
    );
    if (
      invocation.kind !== "target-absence" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName ||
      invocation.targetTriple !== authored.targetTriple
    ) {
      throw new Error(
        `${recipe.fixtureId}: target-absence runtime invocation descriptor drift`,
      );
    }
  } else if (
    invocation?.invocationSchema === "ibex/capsec-closed-surface-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName"],
      `${recipe.fixtureId}: closed-surface runtime invocation`,
    );
    if (
      invocation.kind !== "closed-surface" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed-surface runtime invocation descriptor drift`,
      );
    }
    if (authored.operation?.kind === "module-runner-namespace") {
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed module-runner source descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "expectedError"],
        `${recipe.fixtureId}: closed module-runner operation`,
      );
      const functionName = "ex_hermes_module_record_namespace_json";
      if (
        authored.surfaceKind !== "host-abi" ||
        authored.surfaceName !== functionName ||
        descriptor.kind !== "closed-module-runner-namespace" ||
        descriptor.surfaceObservedKey !== `host-abi:${functionName}` ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            `src/engine/hermes_module_runner.cc#${functionName}`,
          ]) ||
        descriptor.sourceMetadata?.definitions?.length !== 1 ||
        descriptor.sourceMetadata.definitions[0].language !== "c++" ||
        descriptor.sourceMetadata.definitions[0].sourceRef !==
          descriptor.sourceRefs[0] ||
        authored.operation.expectedError !==
          "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup"
      ) {
        throw new Error(
          `${recipe.fixtureId}: closed module-runner descriptor drift`,
        );
      }
    }
    if (authored.operation?.kind === "loader-executable-file") {
      throw new Error(
        `${recipe.fixtureId}: authenticated VFS imports cannot prove the legacy loader facet`,
      );
    }
    if (authored.operation?.kind === "terminal-builtin-import") {
      const terminalBuiltin = new Map([
        ["node_async_hooks", ["async_hooks", ["async_hooks", "node:async_hooks"]]],
        [
          "node_inspector",
          [
            "inspector",
            [
              "inspector",
              "inspector/promises",
              "node:inspector",
              "node:inspector/promises",
            ],
          ],
        ],
        ["node_vm", ["vm", ["node:vm", "vm"]]],
        ["node_wasi", ["wasi", ["node:wasi", "wasi"]]],
        [
          "node_worker_threads",
          ["worker_threads", ["node:worker_threads", "worker_threads"]],
        ],
      ]).get(authored.sourceDescriptor?.sourceKey);
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceKey",
          ...(descriptor.exportName === undefined ? [] : ["exportName"]),
          "moduleSpecifiers",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed terminal builtin source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "terminalBuiltinRoot",
          "moduleSpecifiers",
          "expectedRejectionFragment",
        ],
        `${recipe.fixtureId}: closed terminal builtin operation`,
      );
      const exportSurface = descriptor.exportName !== undefined;
      const expectedSurfaceName = exportSurface
        ? `export:${descriptor.sourceKey}:${descriptor.exportName}`
        : descriptor.surfaceObservedKey?.slice("builtin:".length);
      if (
        terminalBuiltin === undefined ||
        authored.surfaceKind !== "builtin" ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !== `builtin:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-terminal-builtin" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        canonicalJson(descriptor.moduleSpecifiers) !==
          canonicalJson(terminalBuiltin[1]) ||
        !Array.isArray(descriptor.sourceRefs) ||
        descriptor.sourceRefs.length !== 1 ||
        descriptor.sourceMetadata?.sourceKey !== descriptor.sourceKey ||
        descriptor.sourceMetadata?.importReachability !== "public" ||
        authored.operation.terminalBuiltinRoot !== terminalBuiltin[0] ||
        canonicalJson(authored.operation.moduleSpecifiers) !==
          canonicalJson(terminalBuiltin[1]) ||
        authored.operation.expectedRejectionFragment !== "Import denied:" ||
        (exportSurface
          ? descriptor.sourceMetadata?.surfaceType !== "export" ||
            descriptor.sourceMetadata?.exportName !== descriptor.exportName ||
            canonicalJson(
              descriptor.sourceMetadata?.publicModuleSpecifiers,
            ) !== canonicalJson(terminalBuiltin[1])
          : descriptor.sourceMetadata?.surfaceType !== undefined ||
            descriptor.sourceMetadata?.moduleBuiltin !== true ||
            descriptor.sourceMetadata?.bundleExternal !== true ||
            !terminalBuiltin[1].includes(expectedSurfaceName) ||
            descriptor.sourceRefs[0] !==
              `modules.ts#specifiers:${descriptor.sourceKey}`)
      ) {
        throw new Error(
          `${recipe.fixtureId}: terminal builtin closure is not bound to the authenticated import gate`,
        );
      }
    }
    if (authored.operation?.kind === "sqlite-extension-load") {
      const descriptor = authored.sourceDescriptor;
      const constructorExportName = new Map([
        ["Database.loadExtension", "Database"],
        ["default.loadExtension", "default"],
      ]).get(descriptor?.exportName);
      const moduleSpecifiers = ["bun:sqlite", "exact:sqlite"];
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceKey",
          "exportName",
          "constructorExportName",
          "moduleSpecifiers",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed SQLite extension source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "constructorExportName",
          "methodName",
          "moduleSpecifiers",
          "databasePath",
          "extensionPath",
          "expectedRejectionFragment",
        ],
        `${recipe.fixtureId}: closed SQLite extension operation`,
      );
      const expectedSurfaceName =
        `export:exact_sqlite:${descriptor.exportName}`;
      if (
        constructorExportName === undefined ||
        authored.surfaceKind !== "builtin" ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !== `builtin:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-sqlite-extension-load" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.sourceKey !== "exact_sqlite" ||
        descriptor.constructorExportName !== constructorExportName ||
        canonicalJson(descriptor.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            `packages/ibex-runtime-js/src/sqlite/module.js#exports:${descriptor.exportName}`,
          ]) ||
        descriptor.sourceMetadata?.sourceKey !== "exact_sqlite" ||
        descriptor.sourceMetadata?.surfaceType !== "export" ||
        descriptor.sourceMetadata?.exportName !== descriptor.exportName ||
        descriptor.sourceMetadata?.valueShape !== "callable" ||
        descriptor.sourceMetadata?.importReachability !== "public" ||
        canonicalJson(descriptor.sourceMetadata?.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceMetadata?.publicModuleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(
          descriptor.sourceMetadata?.enforcementRouteEvidence?.terminals,
        ) !== canonicalJson(["__exactSqliteLoadExtension"]) ||
        canonicalJson(recipe.route?.surfaceObservedKeys) !==
          canonicalJson([recipe.terminalObservedKey]) ||
        canonicalJson(
          recipe.route?.alternatives?.map(
            (alternative) => alternative.terminalObservedKey,
          ),
        ) !== canonicalJson(["native-op:__exactSqliteLoadExtension"]) ||
        authored.operation.constructorExportName !== constructorExportName ||
        authored.operation.methodName !== "loadExtension" ||
        canonicalJson(authored.operation.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        authored.operation.databasePath !== ":memory:" ||
        authored.operation.extensionPath !==
          "ibex-capsec-closed-extension" ||
        authored.operation.expectedRejectionFragment !==
          "Extension loading not supported"
      ) {
        throw new Error(
          `${recipe.fixtureId}: SQLite extension closure is not bound to the public memory-database call`,
        );
      }
    }
    if (authored.operation?.kind === "sqlite-cr-sqlite-enable") {
      const descriptor = authored.sourceDescriptor;
      const constructorExportName = new Map([
        ["Database.enableCrSqlite", "Database"],
        ["default.enableCrSqlite", "default"],
      ]).get(descriptor?.exportName);
      const moduleSpecifiers = ["bun:sqlite", "exact:sqlite"];
      const expectedTerminals = [
        "__exactCrSqlitePath",
        "__exactSqliteLoadCrSqlite",
        "__exactSqliteLoadExtension",
      ];
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "sourceKey",
          "exportName",
          "constructorExportName",
          "moduleSpecifiers",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed cr-sqlite source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "constructorExportName",
          "methodName",
          "moduleSpecifiers",
          "databasePath",
          "expectedRejectionFragment",
        ],
        `${recipe.fixtureId}: closed cr-sqlite operation`,
      );
      const expectedSurfaceName =
        `export:exact_sqlite:${descriptor.exportName}`;
      if (
        constructorExportName === undefined ||
        authored.surfaceKind !== "builtin" ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !== `builtin:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-sqlite-crsqlite-enable" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.sourceKey !== "exact_sqlite" ||
        descriptor.constructorExportName !== constructorExportName ||
        canonicalJson(descriptor.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            `packages/ibex-runtime-js/src/sqlite/module.js#exports:${descriptor.exportName}`,
          ]) ||
        descriptor.sourceMetadata?.sourceKey !== "exact_sqlite" ||
        descriptor.sourceMetadata?.surfaceType !== "export" ||
        descriptor.sourceMetadata?.exportName !== descriptor.exportName ||
        descriptor.sourceMetadata?.valueShape !== "callable" ||
        descriptor.sourceMetadata?.importReachability !== "public" ||
        canonicalJson(descriptor.sourceMetadata?.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(descriptor.sourceMetadata?.publicModuleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        canonicalJson(
          [...(
            descriptor.sourceMetadata?.enforcementRouteEvidence?.terminals ??
            []
          )].sort(),
        ) !== canonicalJson([...expectedTerminals].sort()) ||
        canonicalJson(recipe.route?.surfaceObservedKeys) !==
          canonicalJson([recipe.terminalObservedKey]) ||
        canonicalJson(
          [
            ...(recipe.route?.alternatives?.map(
              (alternative) => alternative.terminalObservedKey,
            ) ?? []),
          ].sort(),
        ) !==
          canonicalJson(
            expectedTerminals.map((terminal) => `native-op:${terminal}`).sort(),
          ) ||
        authored.operation.constructorExportName !== constructorExportName ||
        authored.operation.methodName !== "enableCrSqlite" ||
        canonicalJson(authored.operation.moduleSpecifiers) !==
          canonicalJson(moduleSpecifiers) ||
        authored.operation.databasePath !== ":memory:" ||
        authored.operation.expectedRejectionFragment !==
          "cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support."
      ) {
        throw new Error(
          `${recipe.fixtureId}: cr-sqlite closure is not bound to the public memory-database call`,
        );
      }
    }
    if (authored.operation?.kind === "debugger-abi-disabled") {
      const debuggerExpectation = new Map([
        ["enable", ["ex_hermes_debugger_enable", "integer-zero"]],
        ["eval", ["ex_hermes_debugger_eval", "null-pointer"]],
        [
          "get-script-source",
          ["ex_hermes_debugger_get_script_source", "null-pointer"],
        ],
        ["get-scripts", ["ex_hermes_debugger_get_scripts", "null-pointer"]],
        ["next-event", ["ex_hermes_debugger_next_event", "null-pointer"]],
        ["pause", ["ex_hermes_debugger_pause", "no-event"]],
        [
          "remove-breakpoint",
          ["ex_hermes_debugger_remove_breakpoint", "no-event"],
        ],
        ["resume", ["ex_hermes_debugger_resume", "no-event"]],
        [
          "set-breakpoint",
          ["ex_hermes_debugger_set_breakpoint", "null-pointer"],
        ],
      ]);
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "functionName",
          "selectedSourceRef",
          "targetTriple",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed debugger ABI source descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "functionName", "expectedCallResult", "expectedError"],
        `${recipe.fixtureId}: closed debugger ABI operation`,
      );
      const operationSlug = [...debuggerExpectation].find(
        ([, [functionName]]) =>
          functionName === authored.operation.functionName,
      )?.[0];
      const expected = debuggerExpectation.get(operationSlug);
      const functionName = authored.operation.functionName;
      const defaultSourceRef =
        `src/engine/hermes_runtime_debugger.cc#${functionName}`;
      const windowsSourceRef =
        `src/engine/hermes_runtime_platform_windows.cc#${functionName}`;
      const selectedSourceRefByTarget = new Map([
        ["aarch64-apple-darwin", defaultSourceRef],
        ["x86_64-pc-windows-msvc", windowsSourceRef],
      ]);
      const expectedSelectedSourceRef = selectedSourceRefByTarget.get(
        descriptor.targetTriple,
      );
      const expectedSurfaceName =
        authored.surfaceKind === "host-abi"
          ? functionName
          : `inspector.debugger-${operationSlug}`;
      const alternative = (targetVariant, sourceRef) => ({
        id: targetVariant,
        kind: "alternative",
        sourceRefs: [sourceRef],
        stubDisposition: "not-structurally-proven",
        targetVariant,
      });
      const alternatives = [
        alternative("default", defaultSourceRef),
        alternative("windows", windowsSourceRef),
      ];
      const expectedReturnKind = new Map([
        ["integer-zero", "scalar"],
        ["no-event", "void"],
        ["null-pointer", "pointer"],
      ]).get(expected?.[1]);
      const metadata = descriptor.sourceMetadata;
      const definitions = metadata?.definitions;
      const outputContracts = metadata?.outputContracts;
      const metadataSources = [
        ["default", defaultSourceRef],
        ["windows", windowsSourceRef],
      ];
      const resolvedOutputContract = (contract, sourceRef) => {
        if (
          !hasExactKeys(contract, [
            "bufferLengthPairs",
            "functionName",
            "language",
            "outputChannels",
            "parameters",
            "return",
            "schema",
            "sourceRef",
            "status",
            "unresolved",
          ]) ||
          contract.schema !== "ibex/host-abi-output-contract/1" ||
          contract.language !== "c++" ||
          contract.functionName !== functionName ||
          contract.sourceRef !== sourceRef ||
          contract.status !== "resolved" ||
          !Array.isArray(contract.bufferLengthPairs) ||
          !Array.isArray(contract.outputChannels) ||
          !Array.isArray(contract.parameters) ||
          !hasExactKeys(contract.return, ["kind", "ownership", "role", "type"]) ||
          contract.return.kind !== expectedReturnKind ||
          canonicalJson(contract.unresolved) !== canonicalJson([])
        ) {
          return false;
        }
        return expectedReturnKind === "void"
          ? contract.outputChannels.length === 0
          : contract.outputChannels.length === 1 &&
              contract.outputChannels[0]?.kind === expectedReturnKind &&
              contract.outputChannels[0]?.role === "return" &&
              contract.outputChannels[0]?.selector === "[[return]]";
      };
      const hostMetadataBound =
        hasExactKeys(metadata, [
          "alternatives",
          "branches",
          "definitions",
          "outputContracts",
          "provenanceLimitation",
        ]) &&
        canonicalJson(metadata.alternatives) === canonicalJson(alternatives) &&
        canonicalJson(metadata.branches) === canonicalJson(alternatives) &&
        metadata.provenanceLimitation ===
          "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures." &&
        Array.isArray(definitions) &&
        definitions.length === metadataSources.length &&
        Array.isArray(outputContracts) &&
        outputContracts.length === metadataSources.length &&
        metadataSources.every(([targetVariant, sourceRef], index) => {
          const definition = definitions[index];
          const contract = outputContracts[index];
          return (
            hasExactKeys(definition, [
              "language",
              "outputContract",
              "sourceRef",
              "targetVariant",
              "unsafe",
              "weak",
            ]) &&
            definition.language === "c++" &&
            definition.sourceRef === sourceRef &&
            definition.targetVariant === targetVariant &&
            definition.unsafe === false &&
            definition.weak === false &&
            canonicalJson(definition.outputContract) ===
              canonicalJson(contract) &&
            resolvedOutputContract(contract, sourceRef)
          );
        });
      const sourceMetadataBound =
        authored.surfaceKind === "host-abi"
          ? hostMetadataBound
          : descriptor.sourceMetadata === null;
      if (
        expected === undefined ||
        !["host-abi", "native-op"].includes(authored.surfaceKind) ||
        authored.surfaceName !== expectedSurfaceName ||
        recipe.terminalObservedKey !==
          `${authored.surfaceKind}:${expectedSurfaceName}` ||
        descriptor.kind !== "closed-debugger-abi" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.functionName !== functionName ||
        expectedSelectedSourceRef === undefined ||
        descriptor.selectedSourceRef !== expectedSelectedSourceRef ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([defaultSourceRef, windowsSourceRef]) ||
        sourceMetadataBound !== true ||
        authored.operation.expectedCallResult !== expected[1] ||
        authored.operation.expectedError !==
          `debugger ABI ${functionName} is unavailable in the no-debugger exact target`
      ) {
        throw new Error(
          `${recipe.fixtureId}: debugger ABI closure is not bound to the physical no-debugger target`,
        );
      }
    }
    if (authored.operation?.kind === "shared-runtime-global-absence") {
      const reviewedSurfaces = new Set([
        "__exactAllowNativesSyntax",
        "__exactCompatEval",
        "__exactDebugModuleSource",
        "__exactDebugModuleSources",
        "__exactDebugModuleSources.length",
        "__exactInstallAsyncIpcListenerPatch",
        "__exactInstallProcessIpcBootstrap",
        "__exactNativeWrapState",
        "__exactNativeWrapState.Pipe",
        "__exactNativeWrapState.TCP",
        "__exactNativeWrapState.TCPConnectWrap",
        "__exactNativeWrapState.UV_EINVAL",
        "__exactNativeWrapState.byFd",
        "__exactNativeWrapState.pipeConstants",
        "__exactNativeWrapState.tcpConstants",
        "__exactStreamWrapState",
        "__exactSyncTrackedIpcListenersAfterDispatch",
        "global:Bun.gc",
        "global:Cache",
        "global:Cache.add",
        "global:Cache.addAll",
        "global:Cache.delete",
        "global:Cache.keys",
        "global:Cache.match",
        "global:Cache.matchAll",
        "global:Cache.put",
        "global:CacheStorage",
        "global:CacheStorage.delete",
        "global:CacheStorage.has",
        "global:CacheStorage.keys",
        "global:CacheStorage.match",
        "global:CacheStorage.open",
        "global:Bun.accessibility",
        "global:Bun.accessibility.addEventListener",
        "global:Bun.accessibility.announce",
        "global:Bun.accessibility.colorScheme",
        "global:Bun.accessibility.dynamicTypeSize",
        "global:Bun.accessibility.fontScale",
        "global:Bun.accessibility.get",
        "global:Bun.accessibility.isBoldTextEnabled",
        "global:Bun.accessibility.isGrayscaleEnabled",
        "global:Bun.accessibility.isInvertColorsEnabled",
        "global:Bun.accessibility.isScreenReaderEnabled",
        "global:Bun.accessibility.prefersHighContrast",
        "global:Bun.accessibility.prefersReducedMotion",
        "global:Bun.accessibility.prefersReducedTransparency",
        "global:Exact.accessibility",
        "global:Exact.accessibility.addEventListener",
        "global:Exact.accessibility.announce",
        "global:Exact.accessibility.colorScheme",
        "global:Exact.accessibility.dynamicTypeSize",
        "global:Exact.accessibility.fontScale",
        "global:Exact.accessibility.get",
        "global:Exact.accessibility.isBoldTextEnabled",
        "global:Exact.accessibility.isGrayscaleEnabled",
        "global:Exact.accessibility.isInvertColorsEnabled",
        "global:Exact.accessibility.isScreenReaderEnabled",
        "global:Exact.accessibility.prefersHighContrast",
        "global:Exact.accessibility.prefersReducedMotion",
        "global:Exact.accessibility.prefersReducedTransparency",
        "global:Exact.gc",
      ]);
      const reviewedRoots = new Set([
        "BroadcastChannel",
        "caches",
        "IDBCursor",
        "IDBCursorWithValue",
        "IDBDatabase",
        "IDBIndex",
        "IDBKeyRange",
        "IDBObjectStore",
        "IDBOpenDBRequest",
        "IDBRequest",
        "IDBTransaction",
        "indexedDB",
        "localStorage",
        "MessageChannel",
        "MessagePort",
        "sessionStorage",
      ]);
      const reviewedSurface =
        reviewedSurfaces.has(authored.surfaceName) ||
        (authored.surfaceName.startsWith("global:") &&
          reviewedRoots.has(
            authored.surfaceName.slice("global:".length).split(".", 1)[0],
          ));
      const descriptor = authored.sourceDescriptor;
      const exactTarget = new Set([
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
      ]).has(descriptor.targetTriple);
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "globalName",
          ...(descriptor.memberName === undefined ? [] : ["memberName"]),
          "targetTriple",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed shared-runtime global descriptor`,
      );
      exactKeys(
        authored.operation,
        ["kind", "globalName", "memberName", "expectedError"],
        `${recipe.fixtureId}: closed shared-runtime global operation`,
      );
      const metadata = descriptor.sourceMetadata;
      const memberName = authored.operation.memberName;
      const exportName =
        memberName === null
          ? authored.operation.globalName
          : `${authored.operation.globalName}.${memberName}`;
      const branches = metadata?.installationBranches;
      const branch = branches?.[0];
      const sharedRuntimeInstallation =
        metadata?.sourceKey === "shared_runtime";
      const reviewedSharedRuntimeBranch =
        branch?.route === "shared-runtime" &&
        branch.targetVariant === "all" &&
        canonicalJson(branch.routes) === canonicalJson(["shared-runtime"]);
      const reviewedComposedSharedRuntimeBranch =
        branch?.route === "composed:legacy-bootstrap+shared-runtime" &&
        branch.targetVariant === "default" &&
        canonicalJson(branch.routes) ===
          canonicalJson(["legacy-bootstrap", "shared-runtime"]);
      const reviewedLegacySourceKeys = new Set([
        "global_compat_polyfills",
        "global_exact_global",
        "global_ipc_listener",
        "global_module_loader",
        "global_process_compat_fix",
        "global_web_storage",
      ]);
      const reviewedLegacyBranch =
        reviewedLegacySourceKeys.has(metadata?.sourceKey) &&
        branch?.route === "legacy-bootstrap" &&
        branch.targetVariant === "default" &&
        canonicalJson(branch.routes) === canonicalJson(["legacy-bootstrap"]);
      const reviewedInstallation =
        Array.isArray(branches) &&
        branches.length === 1 &&
        canonicalJson(branch.sourceRefs) === canonicalJson(descriptor.sourceRefs) &&
        (sharedRuntimeInstallation
          ? reviewedSharedRuntimeBranch ||
            reviewedComposedSharedRuntimeBranch
          : reviewedLegacyBranch);
      if (
        !reviewedSurface ||
        authored.surfaceKind !== "native-op" ||
        descriptor.kind !== "closed-shared-runtime-global-absence" ||
        descriptor.surfaceObservedKey !==
          `native-op:${authored.surfaceName}` ||
        recipe.terminalObservedKey !== descriptor.surfaceObservedKey ||
        descriptor.globalName !== authored.operation.globalName ||
        (descriptor.memberName ?? null) !== memberName ||
        !exactTarget ||
        !Array.isArray(descriptor.sourceRefs) ||
        descriptor.sourceRefs.length === 0 ||
        metadata?.surfaceType !== "global-api" ||
        metadata.globalName !== authored.operation.globalName ||
        metadata.memberName !== memberName ||
        metadata.exportName !== exportName ||
        !reviewedInstallation ||
        authored.operation.expectedError !==
          `armed shared runtime does not expose ${exportName}`
      ) {
        throw new Error(
          `${recipe.fixtureId}: shared-runtime global closure is not bound to a reviewed installation path`,
        );
      }
    }
    if (authored.operation?.kind === "armed-native-global-absence") {
      const reviewedDirectGlobals = new Set([
        "__exactExit",
        "__exactGetGCStats",
        "__exactGetHeapInfo",
        "__exactGetSourceCacheStats",
        "__exactIpcRecvMsg",
        "__exactIpcSendMsg",
        "__exactPollSignal",
        "__exactResetSignal",
        "__exactSetCwd",
      ]);
      const reviewedWorkletGlobals = new Set([
        "global:measure",
        "global:scheduleOnAppRuntime",
        "global:worklet",
        "global:worklet.capture",
        "global:worklet.captureGet",
        "global:worklet.captureSet",
        "global:worklet.clamp",
        "global:worklet.lerp",
        "global:worklet.output",
        "global:worklet.runOnJS",
        "global:worklet.sharedValue",
      ]);
      const directArmedGlobal = reviewedDirectGlobals.has(
        authored.surfaceName,
      );
      const appRuntimeAbsentWorkletGlobal = reviewedWorkletGlobals.has(
        authored.surfaceName,
      );
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "globalName",
          ...(descriptor.memberName === undefined ? [] : ["memberName"]),
          "targetTriple",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed armed native global descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "globalName",
          ...(authored.operation.memberName === undefined
            ? []
            : ["memberName"]),
          "expectedError",
        ],
        `${recipe.fixtureId}: closed armed native global operation`,
      );
      const metadata = descriptor.sourceMetadata;
      const branches = metadata?.installationBranches;
      const publicInvocation = metadata?.publicInvocation;
      const memberName = authored.operation.memberName ?? null;
      const exportName =
        memberName === null
          ? authored.operation.globalName
          : `${authored.operation.globalName}.${memberName}`;
      const directBranch = branches?.find(
        (branch) =>
          branch.route === "native-jsi-global" &&
          (branch.targetVariant === "default" ||
            (branch.targetVariant === "posix" &&
              descriptor.targetTriple === "aarch64-apple-darwin")),
      );
      const workletBranch = branches?.find(
        (branch) =>
          ["evaluated-native-script", "native-jsi-global"].includes(
            branch.route,
          ) && branch.targetVariant === "worklet",
      );
      const exactTarget = new Set([
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
      ]).has(descriptor.targetTriple);
      const reviewedDirectGlobal =
        directArmedGlobal &&
        metadata?.sourceKey === "native_jsi_global" &&
        metadata.globalName === authored.surfaceName &&
        metadata.memberName === null &&
        canonicalJson(metadata.memberKinds) ===
          canonicalJson(["native-root"]) &&
        publicInvocation?.kind === "native-global-function" &&
        publicInvocation.globalName === metadata.globalName &&
        Number.isSafeInteger(publicInvocation.arity) &&
        publicInvocation.arity >= 0 &&
        typeof publicInvocation.sourceRef === "string" &&
        descriptor.sourceRefs.includes(publicInvocation.sourceRef) &&
        directBranch?.sourceRefs.includes(publicInvocation.sourceRef);
      const reviewedWorkletGlobal =
        appRuntimeAbsentWorkletGlobal &&
        authored.surfaceName === `global:${exportName}` &&
        Array.isArray(branches) &&
        branches.length === 1 &&
        canonicalJson(workletBranch?.sourceRefs) ===
          canonicalJson(descriptor.sourceRefs) &&
        (metadata?.sourceKey === "native_jsi_global"
          ? workletBranch?.route === "native-jsi-global" &&
            canonicalJson(workletBranch.routes) ===
              canonicalJson(["native-jsi-global"]) &&
            canonicalJson(metadata.memberKinds) ===
              canonicalJson([
                memberName === null ? "native-root" : "native-object-member",
              ]) &&
            publicInvocation?.kind === "native-global-function" &&
            publicInvocation.globalName === metadata.globalName &&
            Number.isSafeInteger(publicInvocation.arity) &&
            publicInvocation.arity >= 0 &&
            typeof publicInvocation.sourceRef === "string" &&
            descriptor.sourceRefs.includes(publicInvocation.sourceRef)
          : metadata?.sourceKey === "evaluated_native_script" &&
            workletBranch?.route === "evaluated-native-script" &&
            canonicalJson(workletBranch.routes) ===
              canonicalJson(["evaluated-native-script"]) &&
            metadata.evaluatedScript === "kPrelude" &&
            canonicalJson(metadata.sourceUrls) ===
              canonicalJson(["worklet-prelude.js"]));
      if (
        (!directArmedGlobal && !appRuntimeAbsentWorkletGlobal) ||
        authored.surfaceKind !== "native-op" ||
        descriptor.kind !== "closed-armed-native-global-absence" ||
        descriptor.surfaceObservedKey !== `native-op:${authored.surfaceName}` ||
        recipe.terminalObservedKey !== descriptor.surfaceObservedKey ||
        descriptor.globalName !== authored.operation.globalName ||
        (descriptor.memberName ?? null) !== memberName ||
        !exactTarget ||
        !Array.isArray(descriptor.sourceRefs) ||
        descriptor.sourceRefs.length === 0 ||
        metadata?.surfaceType !== "global-api" ||
        metadata.globalName !== authored.operation.globalName ||
        metadata.memberName !== memberName ||
        metadata.exportName !== exportName ||
        !Array.isArray(branches) ||
        (!reviewedDirectGlobal && !reviewedWorkletGlobal) ||
        authored.operation.expectedError !==
          `armed runtime does not expose ${exportName}`
      ) {
        throw new Error(
          `${recipe.fixtureId}: armed native global closure is not bound to the reviewed source-derived JSI path`,
        );
      }
    }
    if (authored.operation?.kind === "exact-unendowed-operation") {
      const descriptor = authored.sourceDescriptor;
      exactKeys(
        descriptor,
        [
          "kind",
          "surfaceObservedKey",
          "globalName",
          "memberName",
          "sourceRefs",
          "sourceMetadata",
        ],
        `${recipe.fixtureId}: closed Exact source descriptor`,
      );
      exactKeys(
        authored.operation,
        [
          "kind",
          "contextKind",
          "operationManifestDigest",
          "endowedOperationIds",
          "selectedOperationId",
          "expectedError",
        ],
        `${recipe.fixtureId}: closed Exact operation`,
      );
      if (
        authored.surfaceKind !== "native-op" ||
        authored.surfaceName !== "global:exact.invokeHostAsync" ||
        recipe.terminalObservedKey !==
          "native-op:global:exact.invokeHostAsync" ||
        descriptor.kind !== "closed-exact-unendowed-operation" ||
        descriptor.surfaceObservedKey !== recipe.terminalObservedKey ||
        descriptor.globalName !== "exact" ||
        descriptor.memberName !== "invokeHostAsync" ||
        canonicalJson(descriptor.sourceRefs) !==
          canonicalJson([
            "src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync",
          ]) ||
        descriptor.sourceMetadata?.surfaceType !== "global-api" ||
        descriptor.sourceMetadata?.sourceKey !== "native_jsi_global" ||
        descriptor.sourceMetadata?.globalName !== "exact" ||
        descriptor.sourceMetadata?.memberName !== "invokeHostAsync" ||
        canonicalJson(descriptor.sourceMetadata?.memberKinds) !==
          canonicalJson(["native-object-member"]) ||
        authored.operation.contextKind !== "app" ||
        authored.operation.operationManifestDigest !==
          EXACT_OPERATION_MANIFEST_DIGEST ||
        canonicalJson(authored.operation.endowedOperationIds) !==
          canonicalJson([7, 11]) ||
        authored.operation.selectedOperationId !== 8 ||
        authored.operation.endowedOperationIds.includes(
          authored.operation.selectedOperationId,
        ) ||
        authored.operation.expectedError !==
          "exact.invokeHostAsync operation is not endowed"
      ) {
        throw new Error(
          `${recipe.fixtureId}: closed Exact invocation is not bound to the authenticated unendowed operation`,
        );
      }
    }
  } else if (
    invocation?.invocationSchema ===
    "ibex/capsec-callback-invariant-invocation/1"
  ) {
    exactKeys(
      invocation,
      [...commonKeys, "surfaceKind", "surfaceName", "scenario"],
      `${recipe.fixtureId}: callback invariant runtime invocation`,
    );
    if (
      invocation.kind !== "callback-security-invariant" ||
      invocation.surfaceKind !== authored.surfaceKind ||
      invocation.surfaceName !== authored.surfaceName ||
      invocation.scenario !== authored.scenario ||
      recipe.publicSurfaceProbe.kind !== "public-surface-invocation" ||
      authored.scenario !== "non-capability" ||
      authored.sourceDescriptor?.proofScope !== "source-bound-exact-mechanism"
    ) {
      throw new Error(
        `${recipe.fixtureId}: callback invariant runtime invocation descriptor drift`,
      );
    }
    const expected = EXACT_EMBEDDER_NON_CAPABILITY_SURFACES.get(
      recipe.publicSurfaceProbe.surfaceObservedKey,
    );
    const descriptor = authored.sourceDescriptor;
    exactKeys(
      descriptor,
      [
        "kind",
        "proofScope",
        "scenario",
        "rationaleId",
        "surfaceObservedKey",
        "edgeId",
        "branchId",
        "sourceRefs",
        "coverageEdge",
        "implementationBranch",
        "liveSurface",
        "executionMechanism",
        "auxiliaryDecisionEdgeId",
      ],
      `${recipe.fixtureId}: Exact non-capability source descriptor`,
    );
    if (
      recipe.classification !== "non-capability" ||
      expected === undefined ||
      descriptor.kind !== "callback-security-invariant" ||
      descriptor.proofScope !== "source-bound-exact-mechanism" ||
      descriptor.scenario !== "non-capability" ||
      descriptor.rationaleId !== expected[0] ||
      descriptor.executionMechanism !== expected[1] ||
      descriptor.surfaceObservedKey !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      descriptor.edgeId !== recipe.edgeIds[0] ||
      descriptor.branchId !== recipe.implementationBranchIds[0] ||
      descriptor.auxiliaryDecisionEdgeId !== null ||
      descriptor.coverageEdge?.id !== recipe.edgeIds[0] ||
      descriptor.implementationBranch?.branchId !==
        recipe.implementationBranchIds[0] ||
      descriptor.liveSurface?.observedKey !==
        recipe.publicSurfaceProbe.surfaceObservedKey ||
      !Array.isArray(descriptor.sourceRefs) ||
      descriptor.sourceRefs.length === 0 ||
      !descriptor.sourceRefs.some((sourceRef) =>
        descriptor.liveSurface?.sourceRefs?.includes(sourceRef),
      )
    ) {
      throw new Error(
        `${recipe.fixtureId}: Exact non-capability invocation is not source-bound`,
      );
    }
  } else {
    throw new Error(
      `${recipe.fixtureId}: unsupported runtime invocation schema`,
    );
  }
  if (
    invocation.invocationSchema !== authored.invocationSchema ||
    invocation.kind !== authored.kind ||
    invocation.surfaceObservedKey !==
      recipe.publicSurfaceProbe.surfaceObservedKey ||
    invocation.sourceDescriptorDigest !== authored.sourceDescriptorDigest ||
    authored.sourceDescriptorDigest !== taggedDigest(authored.sourceDescriptor)
  ) {
    throw new Error(
      `${recipe.fixtureId}: runtime invocation is not source-descriptor bound`,
    );
  }
  const callbackInvariant =
    authored.invocationSchema === "ibex/capsec-callback-invariant-invocation/1";
  const startupEnvironment =
    authored.invocationSchema ===
    "ibex/capsec-startup-environment-invocation/1";
  const principalEnvironment =
    authored.invocationSchema ===
    "ibex/capsec-principal-environment-invocation/1";
  const effectBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-invocation/1";
  const noncapBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-no-effect-invocation/1";
  const outcomeDeclaredCarrier =
    callbackInvariant || startupEnvironment || principalEnvironment;
  const auxiliaryCarrier =
    outcomeDeclaredCarrier || effectBuiltinModuleImport;
  if (
    !Number.isSafeInteger(authored.expectedTypedDecisionCount) ||
    authored.expectedTypedDecisionCount < 0 ||
    !Array.isArray(authored.expectedTypedStages) ||
    authored.expectedTypedDecisionCount !==
      authored.expectedTypedStages.length ||
    !Array.isArray(authored.allowedCoverageEdgeIds) ||
    !Array.isArray(authored.expectedActionIds) ||
    !authored.expectedTypedStages.every(
      (stage) => typeof stage === "string" && stage.length > 0,
    ) ||
    !authored.allowedCoverageEdgeIds.every(
      (edgeId) => typeof edgeId === "string" && edgeId.length > 0,
    ) ||
    !authored.expectedActionIds.every(
      (actionId) => typeof actionId === "string" && actionId.length > 0,
    ) ||
    (!auxiliaryCarrier &&
      authored.expectedActionIds.some(
        (actionId) => !recipe.actionIds.includes(actionId),
      )) ||
    (authored.expectedTypedDecisionCount > 0 &&
      authored.expectedActionIds.length === 0) ||
    canonicalJson(authored.allowedCoverageEdgeIds) !==
      canonicalJson(canonicalSet(authored.allowedCoverageEdgeIds)) ||
    canonicalJson(authored.expectedActionIds) !==
      canonicalJson(canonicalSet(authored.expectedActionIds))
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed authored runtime expectations`,
    );
  }
  if (
    outcomeDeclaredCarrier &&
    (!Array.isArray(authored.expectedTypedOutcomes) ||
      authored.expectedTypedOutcomes.length !==
        authored.expectedTypedDecisionCount ||
      !authored.expectedTypedOutcomes.every((outcome) =>
        ["allow", "deny"].includes(outcome),
      ) ||
      !Array.isArray(authored.expectedTypedReasons) ||
      authored.expectedTypedReasons.length !==
        authored.expectedTypedDecisionCount ||
      !authored.expectedTypedReasons.every(
        (reason) => typeof reason === "string" && reason.length > 0,
      ))
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed auxiliary carrier expectations`,
    );
  }
  if (
    startupEnvironment &&
    (!Array.isArray(authored.expectedResourceNames) ||
      canonicalJson(authored.expectedResourceNames) !==
        canonicalJson(canonicalSet(authored.expectedResourceNames)) ||
      authored.expectedResourceNames.length === 0 ||
      !authored.expectedResourceNames.includes(
        authored.operation.environment.name,
      ) ||
      !Array.isArray(authored.operation.observedEnvironmentAccesses) ||
      authored.operation.observedEnvironmentAccesses.length === 0 ||
      authored.operation.observedEnvironmentAccesses.some(
        (name) => !authored.expectedResourceNames.includes(name),
      ) ||
      authored.expectedTypedDecisionCount !==
        authored.operation.observedEnvironmentAccesses.length *
          (authored.operation.principalMode === "package-denied" ? 1 : 2))
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed startup environment resource binding`,
    );
  }
  if (
    principalEnvironment &&
    (!Array.isArray(authored.expectedResourceNames) ||
      canonicalJson(authored.expectedResourceNames) !==
        canonicalJson(canonicalSet(authored.expectedResourceNames)) ||
      authored.expectedResourceNames.length !== 1 ||
      authored.expectedResourceNames[0] !==
        authored.operation.environmentName)
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed principal environment resource binding`,
    );
  }
  if (!invocation.result || typeof invocation.result !== "object") {
    throw new Error(`${recipe.fixtureId}: runtime invocation has no result`);
  }
  const builtinExportInvocation =
    authored.invocationSchema ===
      "ibex/capsec-builtin-export-invocation/1" &&
    authored.kind === "builtin-export-call";
  const builtinCleanupExpectation =
    builtinExportInvocation && authored.moduleSpecifier === "node:fs"
      ? new Map([
          [
            "openSync",
            {
              cleanup: "closed-fs-file-descriptor",
              valueType: "number",
              path: null,
            },
          ],
          [
            "opendirSync",
            {
              cleanup: "closed-fs-directory",
              valueType: "object",
              path: "/project/capsec-directory-fixture",
            },
          ],
        ]).get(authored.exportName)
      : undefined;
  // @ref LLP 0037#materialized-directory-object-evidence-opendirsync — The aggregate independently binds the returned directory path and close lifecycle.
  // @ref LLP 0037#flag-selected-descriptor-evidence-opensync — A successful descriptor claim is incomplete unless the public harness closed it.
  if (
    (builtinCleanupExpectation &&
      ((authored.expectedResult === "return" &&
        authored.expectedCleanup !== builtinCleanupExpectation.cleanup) ||
        (authored.expectedResult !== "return" &&
          authored.expectedCleanup !== undefined))) ||
    (!builtinCleanupExpectation &&
      builtinExportInvocation &&
      authored.expectedCleanup !== undefined)
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed builtin descriptor cleanup expectation`,
    );
  }
  if (authored.expectedResult === "captured-source-return") {
    exactKeys(
      invocation.result,
      [
        "kind",
        "sourceOperationAttempted",
        "descriptorProof",
        "cleanupPerformed",
        "rawOutput",
        "engineExecuted",
        "projectCodeExecuted",
      ],
      `${recipe.fixtureId}: captured builtin source return`,
    );
    exactKeys(
      invocation.result.descriptorProof,
      ["accessKind", "descriptorKind"],
      `${recipe.fixtureId}: captured builtin descriptor proof`,
    );
    exactKeys(
      invocation.result.rawOutput,
      ["kind", "rawValueShape", "value", "errorCode"],
      `${recipe.fixtureId}: captured builtin raw return`,
    );
    const descriptor = authored.sourceDescriptor;
    if (
      authored.invocationSchema !==
        "ibex/capsec-builtin-noncap-captured-invocation/1" ||
      authored.kind !== "builtin-noncap-captured-call" ||
      invocation.result.kind !== "captured-source-return" ||
      invocation.result.sourceOperationAttempted !== true ||
      invocation.result.cleanupPerformed !== true ||
      invocation.result.engineExecuted !== true ||
      invocation.result.projectCodeExecuted !== true ||
      invocation.result.rawOutput.kind !== "return" ||
      !new Set([
        "array",
        "bigint",
        "boolean",
        "function",
        "null",
        "number",
        "object",
        "string",
        "undefined",
      ]).has(
        invocation.result.rawOutput.rawValueShape,
      ) ||
      invocation.result.rawOutput.errorCode !== null ||
      invocation.result.descriptorProof.accessKind !==
        descriptor.access.kind ||
      !new Set(["data", "accessor", "module-value"]).has(
        invocation.result.descriptorProof.descriptorKind,
      ) ||
      (descriptor.access.kind === "module-value" &&
        invocation.result.descriptorProof.descriptorKind !== "module-value")
    ) {
      throw new Error(
        `${recipe.fixtureId}: loaded engine did not prove the captured builtin source return`,
      );
    }
  } else if (
    authored.expectedResult === "source-completion" &&
    authored.invocationSchema ===
      "ibex/capsec-loader-captured-invocation/1"
  ) {
    // The source-point receipt, loader result, and quiescence account were
    // validated together by validateCapturedModuleLoaderRuntimeInvocation.
  } else if (authored.expectedResult === "source-completion") {
    exactKeys(
      invocation.result,
      [
        "kind",
        "sourceCompletionKind",
        "sourceOperationAttempted",
        "descriptorProof",
        "cleanupPerformed",
        "cleanupError",
        "rawOutput",
        "engineExecuted",
        "projectCodeExecuted",
      ],
      `${recipe.fixtureId}: global callable source completion`,
    );
    exactKeys(
      invocation.result.descriptorProof,
      ["presence", "descriptorKind", "valueType"],
      `${recipe.fixtureId}: global callable descriptor proof`,
    );
    const raw = invocation.result.rawOutput;
    const rawKind = raw?.kind;
    exactKeys(
      raw,
      [
        "kind",
        "rawValueShape",
        "value",
        "errorCode",
        ...(Object.hasOwn(raw ?? {}, "errorName") ? ["errorName"] : []),
      ],
      `${recipe.fixtureId}: global callable raw completion`,
    );
    const validRaw =
      (rawKind === "return" &&
        typeof raw.rawValueShape === "string" &&
        !["throw", "absent"].includes(raw.rawValueShape) &&
        raw.errorCode === null) ||
      (rawKind === "throw" &&
        raw.rawValueShape === "throw" &&
        raw.value === null &&
        (raw.errorCode === null ||
          (typeof raw.errorCode === "string" &&
            raw.errorCode.length > 0)) &&
        (raw.errorName === undefined ||
          (typeof raw.errorName === "string" &&
            raw.errorName.length > 0)) &&
        ((typeof raw.errorCode === "string" &&
          raw.errorCode.length > 0) ||
          (typeof raw.errorName === "string" &&
            raw.errorName.length > 0))) ||
      (rawKind === "absent" &&
        raw.rawValueShape === "absent" &&
        raw.value === null &&
        raw.errorCode === null &&
        raw.errorName === undefined);
    const descriptorKind =
      invocation.result.descriptorProof.descriptorKind;
    const descriptorMatches =
      (rawKind === "absent" && descriptorKind === "absent") ||
      (["return", "throw"].includes(rawKind) &&
        ["data", "accessor"].includes(descriptorKind));
    if (
      authored.invocationSchema !==
        "ibex/capsec-global-callable-invocation/1" ||
      invocation.result.kind !== "source-completion" ||
      invocation.result.sourceCompletionKind !== rawKind ||
      invocation.result.sourceOperationAttempted !== true ||
      invocation.result.cleanupPerformed !== true ||
      invocation.result.cleanupError !== null ||
      invocation.result.engineExecuted !== true ||
      invocation.result.projectCodeExecuted !== true ||
      !validRaw ||
      !descriptorMatches
    ) {
      throw new Error(
        `${recipe.fixtureId}: loaded engine did not prove the exact callable source completion`,
      );
    }
  } else if (authored.expectedResult === "normal-return") {
    if (
      authored.invocationSchema !== "ibex/capsec-builtin-call-invocation/1" ||
      authored.kind !== "builtin-export-call" ||
      !authored.bodyEntryProof ||
      !NORMAL_RETURN_PROOF_KINDS.has(authored.bodyEntryProof.kind) ||
      !NORMAL_RETURN_RESULT_TYPES.has(authored.bodyEntryProof.resultType) ||
      !authored.setup ||
      typeof authored.setup.kind !== "string"
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored normal-return proof`,
      );
    }
    if (
      authored.bodyEntryProof.kind === "settled-return-from-source-call" &&
      (() => {
        const [owner, method, ...extra] = authored.exportName.split(".");
        const contract = SETTLED_STREAM_CONSUMER_CONTRACTS.get(method);
        return (
          extra.length !== 0 ||
          !SETTLED_STREAM_CONSUMER_OWNERS.has(owner) ||
          !contract ||
          authored.setup.kind !== "stream-owner" ||
          authored.setup.ownerExportName !== owner ||
          authored.setup.endedInput !== true ||
          authored.sourceDescriptor.sourceKey !== "node_stream" ||
          authored.sourceDescriptor.exportName !== authored.exportName ||
          authored.bodyEntryProof.resultType !== contract.resultType ||
          canonicalJson(authored.arguments) !== canonicalJson(contract.arguments)
        );
      })()
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored settled-return proof`,
      );
    }
    const explicitDhContract =
      authored.sourceDescriptor.sourceKey === "exact_crypto"
        ? EXPLICIT_DH_CALL_CONTRACTS.get(authored.exportName)
        : null;
    if (
      explicitDhContract &&
      (authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          explicitDhContract.resultType ||
        canonicalJson(authored.setup) !==
          canonicalJson(explicitDhContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(explicitDhContract.arguments))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored explicit DiffieHellman proof`,
      );
    }
    const x509StateContract =
      authored.sourceDescriptor.sourceKey === "exact_crypto"
        ? X509_STATE_CALL_CONTRACTS.get(authored.exportName)
        : null;
    if (
      x509StateContract &&
      (authored.templateId !== "exact-crypto-bounded-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          x509StateContract.resultType ||
        authored.sourceDescriptor.access.kind !== "prototype-property" ||
        canonicalJson(authored.sourceDescriptor.access.path) !==
          canonicalJson([
            "X509Certificate",
            "prototype",
            "toString",
          ]) ||
        canonicalJson(authored.setup) !==
          canonicalJson(x509StateContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(x509StateContract.arguments))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored X509 state proof`,
      );
    }
    const pureCompatibilityContract = PURE_COMPATIBILITY_CALL_CONTRACTS.get(
      `${authored.sourceDescriptor.sourceKey}:${authored.exportName}`,
    );
    const readlineInterfaceContract =
      authored.sourceDescriptor.sourceKey !== "node_readline"
        ? null
        : authored.exportName === "Interface.close"
          ? READLINE_INTERFACE_CLOSE_CONTRACT
          : authored.exportName === "Interface.pause"
            ? READLINE_INTERFACE_PAUSE_CONTRACT
            : null;
    if (
      authored.sourceDescriptor.sourceKey === "node_readline" &&
      !pureCompatibilityContract &&
      !readlineInterfaceContract
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored pure compatibility proof`,
      );
    }
    if (
      pureCompatibilityContract &&
      (authored.moduleSpecifier !==
        pureCompatibilityContract.moduleSpecifier ||
        authored.templateId !== pureCompatibilityContract.templateId ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          pureCompatibilityContract.resultType ||
        authored.sourceDescriptor.kind !== "builtin-export" ||
        authored.sourceDescriptor.valueShape !== "callable" ||
        canonicalJson(authored.sourceDescriptor.exportIdioms) !==
          canonicalJson(pureCompatibilityContract.exportIdioms) ||
        canonicalJson(authored.sourceDescriptor.moduleSpecifiers) !==
          canonicalJson(pureCompatibilityContract.moduleSpecifiers) ||
        authored.sourceDescriptor.sourceRef !==
          pureCompatibilityContract.sourceRef ||
        authored.sourceDescriptor.access.kind !== "export-property" ||
        canonicalJson(authored.sourceDescriptor.access.path) !==
          canonicalJson([authored.exportName]) ||
        canonicalJson(authored.setup) !==
          canonicalJson({ kind: "root-call" }) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(pureCompatibilityContract.arguments))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored pure compatibility proof`,
      );
    }
    if (
      readlineInterfaceContract &&
      (authored.moduleSpecifier !==
        readlineInterfaceContract.moduleSpecifier ||
        authored.templateId !==
          readlineInterfaceContract.templateId ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          readlineInterfaceContract.resultType ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(readlineInterfaceContract.sourceDescriptor) ||
        canonicalJson(authored.setup) !==
          canonicalJson(readlineInterfaceContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(readlineInterfaceContract.arguments))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored readline Interface lifecycle proof`,
      );
    }
    if (
      authored.sourceDescriptor.sourceKey === "exact_crypto" &&
      authored.exportName === "KeyObject.equals" &&
      (authored.moduleSpecifier !==
        KEY_OBJECT_EQUALS_CONTRACT.moduleSpecifier ||
        authored.templateId !== KEY_OBJECT_EQUALS_CONTRACT.templateId ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          KEY_OBJECT_EQUALS_CONTRACT.resultType ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(KEY_OBJECT_EQUALS_CONTRACT.sourceDescriptor) ||
        canonicalJson(authored.setup) !==
          canonicalJson(KEY_OBJECT_EQUALS_CONTRACT.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(KEY_OBJECT_EQUALS_CONTRACT.arguments))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored KeyObject.equals proof`,
      );
    }
    const baseStreamContract =
      authored.sourceDescriptor.sourceKey === "node_stream"
        ? BASE_STREAM_MODULE_VALUE_CALL_CONTRACTS.get(authored.exportName)
        : null;
    if (
      baseStreamContract &&
      (authored.templateId !== "node-stream-bounded-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          baseStreamContract.resultType ||
        authored.sourceDescriptor.access.kind !== "prototype-property" ||
        canonicalJson(authored.sourceDescriptor.access.path) !==
          canonicalJson([
            "prototype",
            authored.exportName.split(".").at(-1),
          ]) ||
        canonicalJson(authored.setup) !==
          canonicalJson(baseStreamContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(baseStreamContract.arguments))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored base Stream module-value proof`,
      );
    }
    const idleNetTerminalContract =
      authored.sourceDescriptor.sourceKey === "node_net"
        ? IDLE_NET_TERMINAL_CALL_CONTRACTS.get(authored.exportName)
        : null;
    const idleNetOwner = idleNetTerminalContract
      ? authored.exportName.split(".")[0]
      : null;
    const expectedIdleNetTerminalDescriptor = idleNetTerminalContract
      ? {
          kind: "builtin-export",
          sourceKey: "node_net",
          exportName: authored.exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["net", "node:net"],
          sourceRef: `src/builtins/net.js#exports:${authored.exportName}`,
          valueShape: "callable",
          access: {
            kind: "prototype-property",
            path: [
              idleNetOwner,
              "prototype",
              authored.exportName.split(".")[1],
            ],
          },
        }
      : null;
    if (
      idleNetTerminalContract &&
      (authored.moduleSpecifier !== "node:net" ||
        authored.templateId !== "node-net-bounded-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          idleNetTerminalContract.resultType ||
        canonicalJson(authored.setup) !==
          canonicalJson(idleNetTerminalContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(idleNetTerminalContract.arguments) ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(expectedIdleNetTerminalDescriptor))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored idle net terminal proof`,
      );
    }
    if (
      authored.setup.kind === "net-terminal-owner" &&
      !idleNetTerminalContract
    ) {
      throw new Error(
        `${recipe.fixtureId}: unreviewed authored net terminal proof`,
      );
    }
    const boundedHttpContract =
      authored.sourceDescriptor.sourceKey === "node_http"
        ? BOUNDED_HTTP_CALL_CONTRACTS.get(authored.exportName)
        : null;
    const boundedHttpPrototype =
      boundedHttpContract && authored.exportName.includes(".");
    const expectedBoundedHttpDescriptor = boundedHttpContract
      ? {
          kind: "builtin-export",
          sourceKey: "node_http",
          exportName: authored.exportName,
          exportIdioms: [
            boundedHttpPrototype
              ? "exported-constructor-prototype"
              : "module-exports-object",
          ],
          moduleSpecifiers: BOUNDED_HTTP_MODULE_SPECIFIERS,
          sourceRef: `src/builtins/http.js#exports:${authored.exportName}`,
          valueShape: "callable",
          access: boundedHttpPrototype
            ? {
                kind: "prototype-property",
                path: [
                  authored.exportName.split(".")[0],
                  "prototype",
                  authored.exportName.split(".")[1],
                ],
              }
            : {
                kind: "export-property",
                path: [authored.exportName],
              },
        }
      : null;
    if (
      authored.sourceDescriptor.sourceKey === "node_http" &&
      (!boundedHttpContract ||
        authored.templateId !== "node-http-idle-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !== boundedHttpContract.resultType ||
        canonicalJson(authored.setup) !==
          canonicalJson(boundedHttpContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(boundedHttpContract.arguments) ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(expectedBoundedHttpDescriptor))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored bounded HTTP proof`,
      );
    }
    const idleTlsSocketContract =
      authored.sourceDescriptor.sourceKey === "node_tls"
        ? IDLE_TLS_SOCKET_CALL_CONTRACTS.get(authored.exportName)
        : null;
    const idleTlsServerContract = IDLE_TLS_SERVER_CALL_CONTRACTS.get(
      `${authored.sourceDescriptor.sourceKey}:${authored.exportName}`,
    );
    const idleTlsSocketPrototype =
      idleTlsSocketContract && authored.exportName.includes(".");
    const expectedIdleTlsSocketDescriptor = idleTlsSocketContract
      ? {
          kind: "builtin-export",
          sourceKey: "node_tls",
          exportName: authored.exportName,
          exportIdioms: [
            idleTlsSocketPrototype
              ? "exported-constructor-prototype"
              : "module-exports-object",
          ],
          moduleSpecifiers: ["node:tls", "tls"],
          sourceRef: `src/builtins/tls.js#exports:${authored.exportName}`,
          valueShape: "callable",
          access: idleTlsSocketPrototype
            ? {
                kind: "prototype-property",
                path: [
                  "TLSSocket",
                  "prototype",
                  authored.exportName.split(".")[1],
                ],
              }
            : {
                kind: "export-property",
                path: ["TLSSocket"],
              },
        }
      : null;
    if (
      idleTlsSocketContract &&
      (authored.templateId !== "node-tls-pure-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          idleTlsSocketContract.resultType ||
        canonicalJson(authored.setup) !==
          canonicalJson(idleTlsSocketContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(idleTlsSocketContract.arguments) ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(expectedIdleTlsSocketDescriptor))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored idle TLS socket proof`,
      );
    }
    const idleTlsServerPrototype =
      authored.exportName === "Server.constructor";
    const expectedIdleTlsServerDescriptor = idleTlsServerContract
      ? {
          kind: "builtin-export",
          sourceKey: authored.sourceDescriptor.sourceKey,
          exportName: authored.exportName,
          exportIdioms: [
            idleTlsServerPrototype
              ? "exported-constructor-prototype"
              : authored.sourceDescriptor.sourceKey === "node_https"
                ? "member-assignment"
                : "module-exports-object",
          ],
          moduleSpecifiers: idleTlsServerContract.moduleSpecifiers,
          sourceRef: idleTlsServerContract.sourceRef,
          valueShape: "callable",
          access: idleTlsServerPrototype
            ? {
                kind: "prototype-property",
                path: ["Server", "prototype", "constructor"],
              }
            : {
                kind: "export-property",
                path: [authored.exportName],
              },
        }
      : null;
    if (
      idleTlsServerContract &&
      (authored.moduleSpecifier !== idleTlsServerContract.moduleSpecifier ||
        authored.templateId !== idleTlsServerContract.templateId ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !==
          idleTlsServerContract.resultType ||
        canonicalJson(authored.setup) !==
          canonicalJson(idleTlsServerContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(idleTlsServerContract.arguments) ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(expectedIdleTlsServerDescriptor))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored idle TLS Server proof`,
      );
    }
    if (
      authored.sourceDescriptor.sourceKey === "node_tls" &&
      authored.exportName !== "getCiphers" &&
      !idleTlsSocketContract &&
      !idleTlsServerContract
    ) {
      throw new Error(`${recipe.fixtureId}: unreviewed authored TLS proof`);
    }
    if (
      authored.sourceDescriptor.sourceKey === "node_https" &&
      !idleTlsServerContract
    ) {
      throw new Error(`${recipe.fixtureId}: unreviewed authored HTTPS proof`);
    }
    const idleDgramContract =
      authored.sourceDescriptor.sourceKey === "node_dgram"
        ? IDLE_DGRAM_CALL_CONTRACTS.get(authored.exportName)
        : null;
    const idleDgramPrototype =
      idleDgramContract && authored.exportName.includes(".");
    const expectedIdleDgramDescriptor = idleDgramContract
      ? {
          kind: "builtin-export",
          sourceKey: "node_dgram",
          exportName: authored.exportName,
          exportIdioms: [
            idleDgramPrototype
              ? "exported-constructor-prototype"
              : "module-exports-object",
          ],
          moduleSpecifiers: IDLE_DGRAM_MODULE_SPECIFIERS,
          sourceRef: `src/builtins/dgram.js#exports:${authored.exportName}`,
          valueShape: "callable",
          access: idleDgramPrototype
            ? {
                kind: "prototype-property",
                path: [
                  authored.exportName.split(".")[0],
                  "prototype",
                  authored.exportName.split(".")[1],
                ],
              }
            : {
                kind: "export-property",
                path: [authored.exportName],
              },
        }
      : null;
    if (
      authored.sourceDescriptor.sourceKey === "node_dgram" &&
      (!idleDgramContract ||
        authored.moduleSpecifier !== "node:dgram" ||
        authored.templateId !== "node-dgram-idle-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !== idleDgramContract.resultType ||
        canonicalJson(authored.setup) !==
          canonicalJson(idleDgramContract.setup) ||
        canonicalJson(authored.arguments) !==
          canonicalJson(idleDgramContract.arguments) ||
        canonicalJson(authored.sourceDescriptor) !==
          canonicalJson(expectedIdleDgramDescriptor))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored idle UDP socket proof`,
      );
    }
    const [zlibOwner, zlibMethod, ...zlibExtra] =
      authored.exportName.split(".");
    const zlibIdleDestroy =
      authored.sourceDescriptor.sourceKey === "node_zlib" &&
      zlibExtra.length === 0 &&
      zlibMethod === "destroy" &&
      ZLIB_IDLE_DESTROY_OWNERS.has(zlibOwner);
    if (
      zlibIdleDestroy &&
      (authored.templateId !== "node-zlib-bounded-v1" ||
        authored.bodyEntryProof.kind !== "normal-return-from-source-call" ||
        authored.bodyEntryProof.resultType !== "object" ||
        authored.sourceDescriptor.access.kind !==
          "inherited-prototype-property" ||
        canonicalJson(authored.sourceDescriptor.access.path) !==
          canonicalJson([zlibOwner, "prototype", "destroy"]) ||
        canonicalJson(authored.setup) !==
          canonicalJson({
            kind: "zlib-owner",
            ownerExportName: zlibOwner,
            ensureNativeStream: false,
          }) ||
        canonicalJson(authored.arguments) !== canonicalJson([]))
    ) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored idle zlib destroy proof`,
      );
    }
    if (!NORMAL_RETURN_DISPATCH_KINDS.has(authored.setup.kind)) {
      throw new Error(
        `${recipe.fixtureId}: malformed authored normal-return setup`,
      );
    }
    const cleanupRequired = new Set([
      "net-terminal-owner",
      "readline-interface-owner",
      "readline-interface-pause-owner",
      "tls-server-construct-target",
      "tls-server-root-call",
      "zlib-owner",
    ]).has(authored.setup.kind);
    const readlineLifecycleRequired = new Set([
      "readline-interface-owner",
      "readline-interface-pause-owner",
    ]).has(authored.setup.kind);
    const tlsServerLifecycleRequired = new Set([
      "tls-server-construct-target",
      "tls-server-root-call",
    ]).has(authored.setup.kind);
    const netLifecycleRequired =
      authored.setup.kind === "net-terminal-owner";
    exactKeys(
      invocation.result,
      [
        "kind",
        "moduleSpecifier",
        "exportName",
        "valueType",
        "dispatchKind",
        "bodyEntryProof",
        ...(cleanupRequired ? ["cleanupPerformed"] : []),
        ...(readlineLifecycleRequired ? ["inputLifecycleVerified"] : []),
        ...(tlsServerLifecycleRequired
          ? ["tlsServerLifecycleVerified"]
          : []),
        ...(netLifecycleRequired ? ["netLifecycleVerified"] : []),
      ],
      `${recipe.fixtureId}: builtin normal-return result`,
    );
    const expectedDispatchKind = NORMAL_RETURN_DISPATCH_KINDS.get(
      authored.setup.kind,
    );
    if (
      invocation.result.kind !== "return" ||
      invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.result.exportName !== authored.exportName ||
      invocation.result.valueType !== authored.bodyEntryProof.resultType ||
      invocation.result.dispatchKind !== expectedDispatchKind ||
      invocation.result.bodyEntryProof !== authored.bodyEntryProof.kind ||
      (cleanupRequired && invocation.result.cleanupPerformed !== true) ||
      (readlineLifecycleRequired &&
        invocation.result.inputLifecycleVerified !== true) ||
      (tlsServerLifecycleRequired &&
        invocation.result.tlsServerLifecycleVerified !== true) ||
      (netLifecycleRequired &&
        invocation.result.netLifecycleVerified !== true)
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin call did not prove its exact normal return`,
      );
    }
  } else if (authored.expectedResult === "return") {
    if (invocation.result.kind !== "return") {
      throw new Error(`${recipe.fixtureId}: public invocation did not return`);
    }
    if (
      authored.expectedStringValue !== undefined &&
      authored.expectedCleanup !== undefined
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin return cannot bind both a string and cleanup`,
      );
    }
    if (authored.expectedStringValue !== undefined) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "moduleSpecifier",
          "exportName",
          "valueType",
          "stringValue",
        ],
        `${recipe.fixtureId}: builtin string result`,
      );
      if (
        authored.invocationSchema !==
          "ibex/capsec-builtin-export-invocation/1" ||
        authored.kind !== "builtin-export-call" ||
        authored.moduleSpecifier !== "node:fs" ||
        authored.exportName !== "readlinkSync" ||
        typeof authored.expectedStringValue !== "string" ||
        authored.expectedStringValue.length === 0 ||
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        invocation.result.valueType !== "string" ||
        invocation.result.stringValue !== authored.expectedStringValue
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin string return did not match its authored value`,
        );
      }
    }
    if (builtinCleanupExpectation) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "moduleSpecifier",
          "exportName",
          "valueType",
          "cleanup",
          ...(builtinCleanupExpectation.path === null ? [] : ["path"]),
        ],
        `${recipe.fixtureId}: builtin cleanup result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        invocation.result.valueType !== builtinCleanupExpectation.valueType ||
        invocation.result.cleanup !== authored.expectedCleanup ||
        (builtinCleanupExpectation.path !== null &&
          invocation.result.path !== builtinCleanupExpectation.path)
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin descriptor cleanup did not match its authored result`,
        );
      }
    }
    if (
      (effectBuiltinModuleImport || noncapBuiltinModuleImport)
    ) {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "valueType"],
        `${recipe.fixtureId}: builtin module-import result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.valueType !==
          (noncapBuiltinModuleImport
            ? authored.sourceDescriptor.expectedRootType
            : "object")
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module import returned the wrong module`,
        );
      }
    }
    if (authored.kind === "builtin-export-read") {
      const streamInstanceRead =
        isReviewedStreamInstanceValueDescriptor(authored.sourceDescriptor);
      const x509RawInstanceRead =
        isReviewedX509RawInstanceValueDescriptor(
          authored.sourceDescriptor,
        );
      const tlsSecureContextInstanceRead =
        isReviewedTlsSecureContextInstanceValueDescriptor(
          authored.sourceDescriptor,
        );
      const expectedReadSetup = streamInstanceRead
        ? {
            kind: "stream-owner",
            ownerExportName: authored.exportName.split(".")[0],
            endedInput: false,
          }
        : x509RawInstanceRead
          ? {
              kind: "constructed-owner",
              ownerExportName: "X509Certificate",
              constructorArguments: [
                { kind: "json", value: "ibex-x509-fixture" },
              ],
            }
          : tlsSecureContextInstanceRead
            ? {
                kind: "constructed-owner",
                ownerExportName: "SecureContext",
                constructorArguments: [],
              }
            : { kind: "none" };
      if (
        canonicalJson(authored.setup) !== canonicalJson(expectedReadSetup)
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin read setup did not match its reviewed receiver`,
        );
      }
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "exportName", "valueType"],
        `${recipe.fixtureId}: builtin read result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        typeof invocation.result.valueType !== "string" ||
        (authored.sourceDescriptor.expectedValueType !== undefined &&
          invocation.result.valueType !==
            authored.sourceDescriptor.expectedValueType)
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin read returned the wrong export`,
        );
      }
    }
    if (
      authored.invocationSchema === "ibex/capsec-native-global-invocation/1" &&
      authored.kind === "native-global-function"
    ) {
      const armedEnvironmentEnumeration =
        authored.globalName === "__exactGetAllEnv";
      exactKeys(
        invocation.result,
        [
          "kind",
          "globalName",
          "valueType",
          "cleanup",
          ...(armedEnvironmentEnumeration ? ["valuePropertyCount"] : []),
        ],
        `${recipe.fixtureId}: native call result`,
      );
      if (
        invocation.result.globalName !== authored.globalName ||
        typeof invocation.result.valueType !== "string" ||
        typeof invocation.result.cleanup !== "string" ||
        (armedEnvironmentEnumeration &&
          (invocation.result.valueType !== "object" ||
            invocation.result.valuePropertyCount !== 0 ||
            invocation.result.cleanup !== "none")) ||
        (authored.expectedCleanup !== undefined &&
          invocation.result.cleanup !== authored.expectedCleanup)
      ) {
        throw new Error(
          `${recipe.fixtureId}: native call did not prove its authored cleanup`,
        );
      }
    }
    if (
      authored.invocationSchema === "ibex/capsec-native-global-invocation/1" &&
      authored.kind === "global-property-read"
    ) {
      exactKeys(
        invocation.result,
        ["kind", "globalName", "valueType", "ownerDepths", "cleanup"],
        `${recipe.fixtureId}: global read result`,
      );
      const descriptor = authored.sourceDescriptor;
      const inherited = descriptor?.memberKinds?.includes("inherited") === true;
      const ownerDepths = invocation.result.ownerDepths;
      const valueType = invocation.result.valueType;
      if (
        invocation.result.globalName !== authored.globalName ||
        !new Set([
          "bigint",
          "boolean",
          "function",
          "null",
          "number",
          "object",
          "string",
          "symbol",
          "undefined",
        ]).has(valueType) ||
        (descriptor?.valueShape === "data" && valueType === "function") ||
        invocation.result.cleanup !== "none" ||
        !Array.isArray(descriptor?.access?.path) ||
        !Array.isArray(ownerDepths) ||
        ownerDepths.length !== descriptor.access.path.length ||
        !ownerDepths.every(
          (depth) => Number.isSafeInteger(depth) && depth >= 0,
        ) ||
        (inherited &&
          (descriptor.valueShape !== "data" ||
            !descriptor.memberKinds.includes("static") ||
            ownerDepths.at(-1) === 0))
      ) {
        throw new Error(
          `${recipe.fixtureId}: global read did not prove its exact property owner chain`,
        );
      }
    }
    if (
      authored.invocationSchema === "ibex/capsec-host-abi-invocation/1"
    ) {
      if (authored.operation.kind === "sqlite-memory") {
        exactKeys(
          invocation.result,
          ["kind", "functionName", "operation", "cleanup"],
          `${recipe.fixtureId}: host ABI runtime result`,
        );
        if (
          invocation.result.functionName !== authored.functionName ||
          invocation.result.operation !== "sqlite-memory" ||
          invocation.result.cleanup !== "released-sqlite-memory-state"
        ) {
          throw new Error(
            `${recipe.fixtureId}: host ABI runtime result did not prove bounded cleanup`,
          );
        }
      } else {
        exactKeys(
          invocation.result,
          [
            "kind",
            "functionName",
            "operation",
            "observedFunctionNames",
            "cleanup",
          ],
          `${recipe.fixtureId}: module-runner host ABI runtime result`,
        );
        if (
          invocation.result.functionName !== authored.functionName ||
          invocation.result.operation !== "module-runner-source-graph" ||
          invocation.result.cleanup !== "released-module-graph" ||
          !Array.isArray(invocation.result.observedFunctionNames) ||
          !invocation.result.observedFunctionNames.includes(
            authored.functionName,
          )
        ) {
          throw new Error(
            `${recipe.fixtureId}: module-runner graph did not enter the exact host ABI`,
          );
        }
      }
    } else if (
      authored.invocationSchema ===
      "ibex/capsec-module-loader-invocation/1"
    ) {
      exactKeys(
        invocation.result,
        ["kind", "surfaceName", "operation", "accessExecuted", "cleanup"],
        `${recipe.fixtureId}: module-loader runtime result`,
      );
      const isAccess = authored.operation.kind !== "authorize-edge";
      if (
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.operation !== authored.operation.kind ||
        invocation.result.accessExecuted !== isAccess ||
        invocation.result.cleanup !== "none"
      ) {
        throw new Error(
          `${recipe.fixtureId}: module-loader runtime result did not prove its exact access`,
        );
      }
    } else if (
      authored.invocationSchema === "ibex/capsec-startup-surface-invocation/1"
    ) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "surfaceKind",
          "surfaceName",
          "mechanism",
          "postcondition",
          "engineExecuted",
          "projectCodeExecuted",
          "observedFacts",
        ],
        `${recipe.fixtureId}: startup runtime result`,
      );
      const expectation = STARTUP_EXPECTATIONS.get(authored.surfaceName);
      exactKeys(
        invocation.result.observedFacts,
        expectation.requiredFacts,
        `${recipe.fixtureId}: startup observed facts`,
      );
      if (
        invocation.result.surfaceKind !== "startup" ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.mechanism !== "loaded-engine-startup" ||
        invocation.result.postcondition !== expectation.postcondition ||
        invocation.result.engineExecuted !== true ||
        invocation.result.projectCodeExecuted !== true ||
        !expectation.requiredFacts.every(
          (fact) => invocation.result.observedFacts[fact] === true,
        )
      ) {
        throw new Error(
          `${recipe.fixtureId}: loaded engine did not prove the startup postcondition`,
        );
      }
    } else if (startupEnvironment) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "surfaceKind",
          "surfaceName",
          "mechanism",
          "moduleSpecifier",
          "environmentName",
          "observedEnvironmentNames",
          "observedEnvironmentAccesses",
          "environmentPresence",
          "principalMode",
          "engineExecuted",
          "projectCodeExecuted",
          "sourceOutcome",
          "errorName",
          "errorMessage",
        ],
        `${recipe.fixtureId}: startup environment runtime result`,
      );
      const operation = authored.operation;
      const denial = authored.scenario === "deny";
      if (
        invocation.result.surfaceKind !== "startup" ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.mechanism !== operation.kind ||
        invocation.result.moduleSpecifier !== operation.moduleSpecifier ||
        invocation.result.environmentName !== operation.environment.name ||
        canonicalJson(invocation.result.observedEnvironmentNames) !==
          canonicalJson(operation.observedEnvironmentNames) ||
        canonicalJson(invocation.result.observedEnvironmentAccesses) !==
          canonicalJson(operation.observedEnvironmentAccesses) ||
        invocation.result.environmentPresence !== "absent" ||
        invocation.result.principalMode !== operation.principalMode ||
        invocation.result.engineExecuted !== true ||
        invocation.result.projectCodeExecuted !== true ||
        invocation.result.sourceOutcome !==
          (denial ? "denied-as-absent" : "source-observed") ||
        invocation.result.errorName !== null ||
        invocation.result.errorMessage !== null
      ) {
        throw new Error(
          `${recipe.fixtureId}: loaded engine did not prove the startup environment source outcome`,
        );
      }
    } else if (principalEnvironment) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "surfaceKind",
          "surfaceName",
          "mechanism",
          "operationKind",
          "environmentName",
          "principalMode",
          "engineExecuted",
          "projectCodeExecuted",
          "sourceOutcome",
          "errorName",
          "errorMessage",
        ],
        `${recipe.fixtureId}: principal environment runtime result`,
      );
      const operation = authored.operation;
      const denial = authored.scenario === "deny";
      const deniedWrite = denial && operation.kind === "write";
      if (
        invocation.result.kind !== (deniedWrite ? "throw" : "return") ||
        invocation.result.surfaceKind !== "native-op" ||
        invocation.result.surfaceName !==
          PRINCIPAL_ENVIRONMENT_SURFACE.slice("native-op:".length) ||
        invocation.result.mechanism !== "process-env-proxy" ||
        invocation.result.operationKind !== operation.kind ||
        invocation.result.environmentName !== operation.environmentName ||
        invocation.result.principalMode !== operation.principalMode ||
        invocation.result.engineExecuted !== true ||
        invocation.result.projectCodeExecuted !== true ||
        invocation.result.sourceOutcome !==
          (denial
            ? operation.kind === "read"
              ? "denied-as-absent"
              : "permission-denied"
            : "source-observed") ||
        (deniedWrite
          ? typeof invocation.result.errorMessage !== "string" ||
            !invocation.result.errorMessage.includes("Permission denied") ||
            typeof invocation.result.errorName !== "string" ||
            invocation.result.errorName.length === 0
          : invocation.result.errorName !== null ||
            invocation.result.errorMessage !== null)
      ) {
        throw new Error(
          `${recipe.fixtureId}: loaded engine did not prove the principal environment source outcome`,
        );
      }
    }
  } else if (authored.expectedResult === "boolean-return") {
    exactKeys(
      invocation.result,
      [
        "kind",
        "moduleSpecifier",
        "exportName",
        "valueType",
        "booleanValue",
      ],
      `${recipe.fixtureId}: builtin boolean-return result`,
    );
    if (
      authored.invocationSchema !==
        "ibex/capsec-builtin-export-invocation/1" ||
      authored.kind !== "builtin-export-call" ||
      authored.moduleSpecifier !== "node:fs" ||
      authored.exportName !== "existsSync" ||
      typeof authored.expectedBooleanValue !== "boolean" ||
      authored.expectedBooleanValue !== (recipe.scenario !== "deny") ||
      invocation.result.kind !== "return" ||
      invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
      invocation.result.exportName !== authored.exportName ||
      invocation.result.valueType !== "boolean" ||
      invocation.result.booleanValue !== authored.expectedBooleanValue
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin boolean return did not match its authored value`,
      );
    }
  } else if (authored.expectedResult === "permission-denied") {
    const builtinModuleImport =
      authored.invocationSchema ===
      "ibex/capsec-builtin-module-import-invocation/1";
    if (builtinModuleImport) {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "errorName", "errorMessage"],
        `${recipe.fixtureId}: denied builtin module-import result`,
      );
      if (
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        typeof invocation.result.errorName !== "string" ||
        invocation.result.errorName.length === 0
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module import denied the wrong module`,
        );
      }
    }
    const authoredFragment =
      authored.expectedDenyMessageFragment ??
      authored.publicAccess?.expectedDenyMessageFragment;
    const expectedFragment = authoredFragment ?? "Permission denied";
    const errorMessage = invocation.result.errorMessage;
    const fragmentMatched =
      typeof errorMessage === "string" &&
      (authoredFragment === undefined
        ? errorMessage.toLowerCase().includes(expectedFragment.toLowerCase())
        : errorMessage.includes(expectedFragment));
    if (
      invocation.result.kind !== "throw" ||
      !fragmentMatched
    ) {
      throw new Error(`${recipe.fixtureId}: public invocation did not deny`);
    }
    if (principalEnvironment) {
      exactKeys(
        invocation.result,
        [
          "kind",
          "surfaceKind",
          "surfaceName",
          "mechanism",
          "operationKind",
          "environmentName",
          "principalMode",
          "engineExecuted",
          "projectCodeExecuted",
          "sourceOutcome",
          "errorName",
          "errorMessage",
        ],
        `${recipe.fixtureId}: denied principal environment runtime result`,
      );
      if (
        authored.scenario !== "deny" ||
        authored.operation.kind !== "write" ||
        invocation.result.surfaceKind !== "native-op" ||
        invocation.result.surfaceName !==
          PRINCIPAL_ENVIRONMENT_SURFACE.slice("native-op:".length) ||
        invocation.result.mechanism !== "process-env-proxy" ||
        invocation.result.operationKind !== "write" ||
        invocation.result.environmentName !==
          authored.operation.environmentName ||
        invocation.result.principalMode !== "package-denied" ||
        invocation.result.engineExecuted !== true ||
        invocation.result.projectCodeExecuted !== true ||
        invocation.result.sourceOutcome !== "permission-denied" ||
        typeof invocation.result.errorName !== "string" ||
        invocation.result.errorName.length === 0
      ) {
        throw new Error(
          `${recipe.fixtureId}: denied principal environment source outcome drift`,
        );
      }
    }
  } else if (authored.expectedResult === "invalid-handle") {
    exactKeys(
      invocation.result,
      ["kind", "globalName", "errorName", "errorMessage"],
      `${recipe.fixtureId}: retained-object refusal result`,
    );
    if (
      invocation.result.kind !== "throw" ||
      invocation.result.globalName !== authored.globalName ||
      invocation.result.errorName !== "Error" ||
      typeof invocation.result.errorMessage !== "string" ||
      !invocation.result.errorMessage.endsWith(": invalid handle")
    ) {
      throw new Error(
        `${recipe.fixtureId}: public invocation did not prove its exact retained-object refusal`,
      );
    }
  } else if (authored.expectedResult === "absent") {
    if (
      invocation.invocationSchema ===
        "ibex/capsec-builtin-export-invocation/1" &&
      invocation.kind === "builtin-export-read"
    ) {
      exactKeys(
        invocation.result,
        ["kind", "moduleSpecifier", "exportName", "segment", "available"],
        `${recipe.fixtureId}: target-absent builtin result`,
      );
      const availability = authored.sourceDescriptor?.platformAvailability;
      const accessPath = authored.sourceDescriptor?.access?.path;
      if (
        invocation.result.kind !== "missing" ||
        invocation.result.moduleSpecifier !== authored.moduleSpecifier ||
        invocation.result.exportName !== authored.exportName ||
        invocation.result.segment !== authored.exportName ||
        !Array.isArray(invocation.result.available) ||
        invocation.result.available.includes(authored.exportName) ||
        !Array.isArray(availability) ||
        availability.length === 0 ||
        availability.includes("darwin") ||
        !Array.isArray(accessPath) ||
        accessPath.at(-1) !== authored.exportName
      ) {
        throw new Error(
          `${recipe.fixtureId}: public builtin did not prove source-bound target absence`,
        );
      }
    } else if (
      invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
    ) {
      if (invocation.result.kind !== "missing") {
        throw new Error(
          `${recipe.fixtureId}: public native global was not absent`,
        );
      }
    } else {
      const probeMode = authored.sourceDescriptor?.probeMode;
      if (
        invocation.result.kind !== "absent" ||
        invocation.result.surfaceKind !== authored.surfaceKind ||
        invocation.result.surfaceName !== authored.surfaceName ||
        invocation.result.targetTriple !== authored.targetTriple ||
        invocation.result.compiledTargetOs !== "macos" ||
        invocation.result.compiledTargetArch !== "aarch64" ||
        invocation.result.probeMode !== probeMode?.kind
      ) {
        throw new Error(
          `${recipe.fixtureId}: target-absence probe did not prove absence`,
        );
      }
      if (probeMode?.kind === "runtime-global-property") {
        exactKeys(
          invocation.result,
          [
            "kind",
            "surfaceKind",
            "surfaceName",
            "targetTriple",
            "compiledTargetOs",
            "compiledTargetArch",
            "probeMode",
            "globalName",
            "memberName",
            "surfacePresent",
          ],
          `${recipe.fixtureId}: native-global target-absence runtime result`,
        );
        if (
          invocation.result.globalName !== probeMode.globalName ||
          invocation.result.memberName !== probeMode.memberName ||
          invocation.result.surfacePresent !== false
        ) {
          throw new Error(
            `${recipe.fixtureId}: runtime-global probe did not prove absence`,
          );
        }
      } else {
        exactKeys(
          invocation.result,
          [
            "kind",
            "surfaceKind",
            "surfaceName",
            "targetTriple",
            "compiledTargetOs",
            "compiledTargetArch",
            "probeMode",
            "symbolName",
            "symbolPresent",
          ],
          `${recipe.fixtureId}: symbol target-absence runtime result`,
        );
        if (
          !["dynamic-symbol", "platform-bridge"].includes(probeMode?.kind) ||
          invocation.result.symbolName !== probeMode.symbolName ||
          invocation.result.symbolPresent !== false
        ) {
          throw new Error(
            `${recipe.fixtureId}: symbol probe did not prove absence`,
          );
        }
      }
    }
  } else if (authored.expectedResult === "closed") {
    const filesystemMutation =
      authored.operation?.kind === "filesystem-unbound-mutation";
    exactKeys(
      invocation.result,
      [
        "kind",
        "surfaceKind",
        "surfaceName",
        "mechanism",
        "errorName",
        ...(filesystemMutation
          ? [
              "errorCode",
              "callbackCalled",
              "filesystemBeforeDigest",
              "filesystemAfterDigest",
            ]
          : []),
        "errorMessage",
        ...(authored.operation?.kind === "loader-executable-file"
          ? ["errorCode"]
          : []),
        "engineExecuted",
        "projectCodeExecuted",
      ],
      `${recipe.fixtureId}: closed-surface runtime result`,
    );
    if (
      invocation.result.kind !== "closed" ||
      invocation.result.surfaceKind !== authored.surfaceKind ||
      invocation.result.surfaceName !== authored.surfaceName ||
      invocation.result.mechanism !== authored.operation?.kind ||
      invocation.result.errorName !==
        (filesystemMutation ? "Error" : "ClosedSurface") ||
      typeof invocation.result.errorMessage !== "string" ||
      invocation.result.errorMessage.length === 0 ||
      typeof invocation.result.engineExecuted !== "boolean" ||
      invocation.result.projectCodeExecuted !== false
    ) {
      throw new Error(
        `${recipe.fixtureId}: public closed surface did not fail closed`,
      );
    }
    if (
      filesystemMutation &&
      (invocation.result.engineExecuted !== true ||
        authored.operation.expectedErrorCode !== "EPERM" ||
        invocation.result.errorCode !== authored.operation.expectedErrorCode ||
        typeof authored.operation.guardOperation !== "string" ||
        authored.operation.guardOperation.length === 0 ||
        invocation.result.callbackCalled !==
          (authored.operation.invocationStyle === "callback-deferred") ||
        !invocation.result.errorMessage.includes(
          authored.operation.expectedErrorFragment,
        ) ||
        !invocation.result.errorMessage.includes(
          authored.operation.guardOperation,
        ) ||
        !isTaggedDigest(invocation.result.filesystemBeforeDigest) ||
        invocation.result.filesystemBeforeDigest !==
          invocation.result.filesystemAfterDigest)
    ) {
      throw new Error(
        `${recipe.fixtureId}: filesystem mutation did not prove pre-lookup EPERM closure with unchanged physical state`,
      );
    }
    if (
      authored.operation?.kind === "startup-environment" &&
      (invocation.result.engineExecuted !== false ||
        !invocation.result.errorMessage.includes(
          "rejects closed environment controls",
        ) ||
        !invocation.result.errorMessage.includes(
          authored.operation.environmentName,
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed startup control reached engine execution or the wrong rejection`,
      );
    }
    if (
      authored.operation?.kind === "cli-control" &&
      (invocation.result.engineExecuted !== false ||
        !Array.isArray(authored.operation.expectedRejectionFragments) ||
        authored.operation.expectedRejectionFragments.length === 0 ||
        !authored.operation.expectedRejectionFragments.every(
          (fragment) =>
            typeof fragment === "string" &&
            fragment.length > 0 &&
            invocation.result.errorMessage.includes(fragment),
        ) ||
        !Array.isArray(authored.operation.argumentVectors) ||
        authored.operation.argumentVectors.length === 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: closed CLI control reached execution or the wrong rejection`,
      );
    }
    if (
      authored.operation?.kind === "tamed-evaluator" &&
      (invocation.result.engineExecuted !== true ||
        !invocation.result.errorMessage.includes("disabled under lockdown") ||
        !new Set([
          "global-eval",
          "global-function",
          "async-function-constructor",
          "generator-function-constructor",
        ]).has(authored.operation.accessMode))
    ) {
      throw new Error(
        `${recipe.fixtureId}: evaluator was not closed by the reviewed loaded-engine taming path`,
      );
    }
    if (
      authored.operation?.kind === "exact-unendowed-operation" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: Exact invocation did not fail closed before the embedder callback`,
      );
    }
    if (
      authored.operation?.kind === "module-runner-namespace" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: armed module namespace inspection did not fail closed`,
      );
    }
    if (
      authored.operation?.kind === "terminal-builtin-import" &&
      (invocation.result.engineExecuted !== true ||
        !invocation.result.errorMessage.includes(
          authored.operation.expectedRejectionFragment,
        ) ||
        !authored.operation.moduleSpecifiers.every(
          (specifier) =>
            invocation.result.errorMessage
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(`${specifier}: `) &&
                  line.includes(authored.operation.expectedRejectionFragment),
              ),
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: terminal builtin aliases did not fail closed at the authenticated import gate`,
      );
    }
    if (
      authored.operation?.kind === "sqlite-extension-load" &&
      (invocation.result.engineExecuted !== true ||
        !authored.operation.moduleSpecifiers.every(
          (specifier) =>
            invocation.result.errorMessage
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(`${specifier}: `) &&
                  line.includes(
                    authored.operation.expectedRejectionFragment,
                  ),
              ),
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: SQLite extension loading did not fail closed through every public alias`,
      );
    }
    if (
      authored.operation?.kind === "sqlite-cr-sqlite-enable" &&
      (invocation.result.engineExecuted !== true ||
        !authored.operation.moduleSpecifiers.every(
          (specifier) =>
            invocation.result.errorMessage
              .split("\n")
              .some(
                (line) =>
                  line.startsWith(`${specifier}: `) &&
                  line.includes(
                    authored.operation.expectedRejectionFragment,
                  ),
              ),
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: cr-sqlite enablement did not fail closed through every public alias`,
      );
    }
    if (
      authored.operation?.kind === "debugger-abi-disabled" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: debugger ABI did not prove the no-debugger physical result`,
      );
    }
    if (
      authored.operation?.kind === "shared-runtime-global-absence" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: armed shared-runtime global was not physically absent`,
      );
    }
    if (
      authored.operation?.kind === "armed-native-global-absence" &&
      (invocation.result.engineExecuted !== true ||
        invocation.result.errorMessage !== authored.operation.expectedError)
    ) {
      throw new Error(
        `${recipe.fixtureId}: armed native global was not physically absent`,
      );
    }
    const loaderExecutableExpectation = new Map([
      [
        "native-addon",
        { extension: ".node", rejectionFragment: "Native addons are closed" },
      ],
      [
        "wasm",
        {
          extension: ".wasm",
          rejectionFragment: "WebAssembly modules are closed",
        },
      ],
    ]).get(authored.operation?.loaderKind);
    if (
      authored.operation?.kind === "loader-executable-file" &&
      (invocation.result.engineExecuted !== true ||
        authored.surfaceKind !== "loader" ||
        loaderExecutableExpectation === undefined ||
        authored.operation.extension !==
          loaderExecutableExpectation.extension ||
        authored.operation.rejectionFragment !==
          loaderExecutableExpectation.rejectionFragment ||
        authored.operation.publicErrorCode !== "ERR_IBEX_MODULE_RESOLUTION" ||
        authored.operation.publicErrorMessage !== "Module resolution failed" ||
        invocation.result.errorCode !== authored.operation.publicErrorCode ||
        invocation.result.errorMessage !==
          authored.operation.publicErrorMessage)
    ) {
      throw new Error(
        `${recipe.fixtureId}: executable loader kind did not fail closed at resolution`,
      );
    }
  } else if (authored.expectedResult === "invariant-passed") {
    if (!callbackInvariant) {
      throw new Error(
        `${recipe.fixtureId}: non-callback probe claimed an invariant result`,
      );
    }
    validateCallbackInvariantResult(
      invocation.result,
      authored,
      recipe.fixtureId,
    );
  } else {
    throw new Error(`${recipe.fixtureId}: unsupported expected public result`);
  }
  if (
    invocation.invocationSchema === "ibex/capsec-native-global-invocation/1"
  ) {
    const armedEnvironmentEnumeration =
      authored.globalName === "__exactGetAllEnv" &&
      authored.expectedResult === "return";
    exactKeys(
      invocation.executionProof,
      [
        "kind",
        "bodyEntered",
        ...(armedEnvironmentEnumeration ? ["propertyCount"] : []),
      ],
      `${recipe.fixtureId}: native execution proof`,
    );
    const expectedProof =
      armedEnvironmentEnumeration
        ? ["armed-empty-environment-enumeration", true]
        : authored.expectedResult === "return"
        ? [
            authored.kind === "global-property-read"
              ? "global-property-read"
              : "native-return",
            true,
          ]
        : authored.expectedResult === "permission-denied"
          ? ["typed-permission-denial", true]
          : authored.expectedResult === "invalid-handle"
            ? ["retained-object-refusal", true]
          : ["exact-global-absence", false];
    if (
      invocation.executionProof.kind !== expectedProof[0] ||
      invocation.executionProof.bodyEntered !== expectedProof[1] ||
      (armedEnvironmentEnumeration &&
        invocation.executionProof.propertyCount !== 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: native execution proof disagrees with result`,
      );
    }
  }
}

export function validatePublicFixtureRuntimeObservation(
  observation,
  recipe,
  coverage,
) {
  exactKeys(
    observation,
    [
      "observationSchema",
      "invocation",
      "legacyObservationCount",
      "typedDecisions",
    ],
    `${recipe.fixtureId}: runtime public observation`,
  );
  validateRuntimeInvocation(observation, recipe);
  const authored = recipe.publicSurfaceProbe.invocation;
  if (
    observation.observationSchema !==
      "ibex/capsec-runtime-public-observation/1" ||
    observation.legacyObservationCount !== 0 ||
    !Array.isArray(observation.typedDecisions) ||
    observation.typedDecisions.length !== authored?.expectedTypedDecisionCount
  ) {
    throw new Error(
      `${recipe.fixtureId}: malformed runtime public observation`,
    );
  }
  const stages = [];
  const actions = new Set();
  const edgeIds = new Set();
  const terminals = new Set();
  const terminalByEdge =
    observation.typedDecisions.length === 0
      ? null
      : coverageTerminalMap(coverage);
  const callbackInvariant =
    authored.invocationSchema === "ibex/capsec-callback-invariant-invocation/1";
  const startupEnvironment =
    authored.invocationSchema ===
    "ibex/capsec-startup-environment-invocation/1";
  const principalEnvironment =
    authored.invocationSchema ===
    "ibex/capsec-principal-environment-invocation/1";
  const effectBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-invocation/1";
  const nonCapabilityBuiltinModuleImport =
    authored.invocationSchema ===
    "ibex/capsec-builtin-module-import-no-effect-invocation/1";
  const capturedNonCapabilityBuiltin =
    authored.invocationSchema ===
    "ibex/capsec-builtin-noncap-captured-invocation/1";
  // The aggregate independently repeats the producer's narrow D2 allowance:
  // only these reviewed open-then-act exports may observe fs:list in addition
  // to their declared semantic operation.
  // @ref LLP 0037#d2--declared-vs-incidental-capabilities-in-the-coverage-edge
  const builtinOpenThenActDescriptor = new Map([
    [
      "appendFileSync",
      { expectedActions: ["fs:write"], operationPrefix: "fs-open:" },
    ],
    [
      "mkdirSync",
      { expectedActions: ["fs:write"], operationPrefix: "fs-mkdir:" },
    ],
    [
      "readFileSync",
      { expectedActions: ["fs:read"], operationPrefix: "fs-open:" },
    ],
    [
      "readlinkSync",
      { expectedActions: ["fs:read"], operationPrefix: "fs-readlink:" },
    ],
    [
      "openSync",
      {
        expectedActions: authored.expectedActionIds,
        operationPrefix: "fs-open:",
      },
    ],
    [
      "truncateSync",
      { expectedActions: ["fs:write"], operationPrefix: "fs-truncate:" },
    ],
    [
      "writeFileSync",
      { expectedActions: ["fs:write"], operationPrefix: "fs-open:" },
    ],
  ]).get(authored.exportName);
  const builtinOpenThenAct =
    authored.invocationSchema ===
      "ibex/capsec-builtin-export-invocation/1" &&
    authored.kind === "builtin-export-call" &&
    authored.moduleSpecifier === "node:fs" &&
    Array.isArray(builtinOpenThenActDescriptor?.expectedActions) &&
    builtinOpenThenActDescriptor.expectedActions.length > 0 &&
    typeof builtinOpenThenActDescriptor.operationPrefix === "string" &&
    canonicalJson(authored.expectedActionIds) ===
      canonicalJson(builtinOpenThenActDescriptor.expectedActions) &&
    (authored.exportName !== "openSync" ||
      [
        ["fs:list", "fs:read"],
        ["fs:list", "fs:write"],
        ["fs:list", "fs:read", "fs:write"],
      ].some(
        (actions) =>
          canonicalJson(actions) ===
          canonicalJson(authored.expectedActionIds),
      ));
  const outcomeDeclaredCarrier =
    callbackInvariant || startupEnvironment || principalEnvironment;
  const auxiliaryCarrier =
    outcomeDeclaredCarrier ||
    effectBuiltinModuleImport ||
    nonCapabilityBuiltinModuleImport;
  const effectBuiltinAuxiliaryDescriptors =
    authored.invocationSchema ===
      "ibex/capsec-builtin-export-invocation/1" &&
    authored.kind === "builtin-export-call" &&
    Array.isArray(authored.sourceDescriptor?.auxiliaryDecisionEdges)
      ? authored.sourceDescriptor.auxiliaryDecisionEdges
      : [];
  const effectBuiltinAuxiliaryCarrier =
    effectBuiltinAuxiliaryDescriptors.length > 0;
  const effectBuiltinAuxiliaryByEdge = new Map();
  const effectBuiltinDenialTerminalEdgeId =
    effectBuiltinAuxiliaryCarrier
      ? authored.sourceDescriptor.denialTerminalEdgeId
      : null;
  if (effectBuiltinAuxiliaryCarrier) {
    for (const descriptor of effectBuiltinAuxiliaryDescriptors) {
      exactKeys(
        descriptor,
        ["edgeId", "observedKey", "actionIds"],
        `${recipe.fixtureId}: effect-builtin auxiliary descriptor`,
      );
      const edge = coverage?.edges?.find(
        (candidate) => candidate.id === descriptor.edgeId,
      );
      const observedKey = edge
        ? `${edge.surface?.kind}:${edge.surface?.name}`
        : null;
      const actionIds = canonicalSet(
        (edge?.effects ?? []).map((effect) => effect.cap),
      );
      if (
        edge?.classification !== "effects" ||
        observedKey !== descriptor.observedKey ||
        canonicalJson(actionIds) !==
          canonicalJson(canonicalSet(descriptor.actionIds)) ||
        effectBuiltinAuxiliaryByEdge.has(descriptor.edgeId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: effect-builtin auxiliary decision is not coverage-bound`,
        );
      }
      effectBuiltinAuxiliaryByEdge.set(
        descriptor.edgeId,
        new Set(actionIds),
      );
    }
    const exactRealpathCarrier =
      authored.moduleSpecifier === "node:fs" &&
      authored.exportName === "realpathSync" &&
      canonicalJson(
        effectBuiltinAuxiliaryDescriptors.map(
          ({ observedKey, actionIds }) => ({
            observedKey,
            actionIds,
          }),
        ),
      ) ===
        canonicalJson([
          {
            observedKey: "native-op:__exactGetCwd",
            actionIds: ["path:cwd-observe"],
          },
          {
            observedKey: "native-op:__exactLstat",
            actionIds: ["fs:list"],
          },
        ]) &&
      effectBuiltinAuxiliaryDescriptors.find(
        ({ observedKey }) => observedKey === "native-op:__exactLstat",
      )?.edgeId === effectBuiltinDenialTerminalEdgeId;
    const routeEdgeIds = (recipe.route?.alternatives ?? []).map(
      ({ terminalObservedKey }) =>
        coverage?.edges?.find(
          (edge) =>
            `${edge.surface?.kind}:${edge.surface?.name}` ===
            terminalObservedKey,
        )?.id,
    );
    const expectedAllowedEdges = canonicalSet([
      ...routeEdgeIds,
      ...effectBuiltinAuxiliaryByEdge.keys(),
    ]);
    if (
      !exactRealpathCarrier ||
      routeEdgeIds.some((edgeId) => typeof edgeId !== "string") ||
      !effectBuiltinAuxiliaryByEdge.has(
        effectBuiltinDenialTerminalEdgeId,
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson(expectedAllowedEdges)
    ) {
      throw new Error(
        `${recipe.fixtureId}: unsupported effect-builtin auxiliary carrier`,
      );
    }
  } else if (
    authored.sourceDescriptor?.denialTerminalEdgeId !== undefined
  ) {
    throw new Error(
      `${recipe.fixtureId}: denial terminal has no authenticated auxiliary edge`,
    );
  }
  const effectBuiltinDenialCarrier =
    effectBuiltinAuxiliaryCarrier && recipe.scenario === "deny";
  const runtimeAuxiliaryCarrier =
    auxiliaryCarrier || effectBuiltinDenialCarrier;
  const nativeWorkerTerminals = nativeAsyncWorkerTerminals(authored);
  let effectBuiltinModuleImportIdentity = null;
  if (callbackInvariant) {
    // Callback/control surfaces are non-capabilities, but their invariant can
    // exercise one separately reviewed effect edge. Bind that auxiliary
    // decision to checked coverage instead of attributing it to the carrier.
    const auxiliaryEdgeId =
      authored.sourceDescriptor?.auxiliaryDecisionEdgeId ?? null;
    const expectedAuxiliaryEdgeIds = auxiliaryEdgeId ? [auxiliaryEdgeId] : [];
    const auxiliaryEdge = auxiliaryEdgeId
      ? coverage?.edges?.find((edge) => edge.id === auxiliaryEdgeId)
      : null;
    const auxiliaryActions = auxiliaryEdge
      ? canonicalSet((auxiliaryEdge.effects ?? []).map((effect) => effect.cap))
      : [];
    const auxiliaryStages = auxiliaryEdge
      ? new Set(
          (auxiliaryEdge.effects ?? []).flatMap(
            (effect) => effect.stages ?? [],
          ),
        )
      : new Set();
    if (
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson(expectedAuxiliaryEdgeIds) ||
      (auxiliaryEdgeId !== null &&
        (auxiliaryEdge?.classification !== "effects" ||
          canonicalJson(auxiliaryActions) !==
            canonicalJson(authored.expectedActionIds) ||
          !authored.expectedTypedStages.every((stage) =>
            auxiliaryStages.has(stage),
          ))) ||
      (auxiliaryEdgeId === null &&
        (authored.expectedTypedDecisionCount !== 0 ||
          authored.expectedActionIds.length !== 0 ||
          authored.expectedTypedStages.length !== 0))
    ) {
      throw new Error(
        `${recipe.fixtureId}: callback auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (startupEnvironment) {
    const descriptor = authored.sourceDescriptor;
    const auxiliaryEdgeId = descriptor?.auxiliaryDecisionEdgeId ?? null;
    const auxiliaryEdge = coverage?.edges?.find(
      (edge) => edge.id === auxiliaryEdgeId,
    );
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const selectedBranch = carrierEdge?.logicalBranches?.find(
      (branch) => branch.id === descriptor?.selectedBranch?.id,
    );
    const environmentName = authored.operation?.environment?.name;
    const expectedFact = `environment.startup.${environmentName?.toLowerCase()}`;
    const auxiliaryActions = canonicalSet(
      (auxiliaryEdge?.effects ?? []).map((effect) => effect.cap),
    );
    const auxiliaryStages = new Set(
      (auxiliaryEdge?.effects ?? []).flatMap((effect) => effect.stages ?? []),
    );
    if (
      auxiliaryEdge?.classification !== "effects" ||
      canonicalJson(auxiliaryActions) !== canonicalJson(["env:read"]) ||
      !authored.expectedTypedStages.every((stage) =>
        auxiliaryStages.has(stage),
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson([auxiliaryEdgeId]) ||
      canonicalJson(authored.expectedActionIds) !==
        canonicalJson(["env:read"]) ||
      carrierEdge?.classification !== "effects" ||
      carrierEdge?.surface?.kind !== "startup" ||
      carrierEdge?.surface?.name !== `env:${environmentName}` ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      canonicalJson(selectedBranch) !==
        canonicalJson(descriptor.selectedBranch) ||
      canonicalJson(selectedBranch?.when) !==
        canonicalJson([{ fact: expectedFact, equals: "absent" }]) ||
      canonicalJson(
        canonicalSet(
          (selectedBranch?.effects ?? []).map((effect) => effect.cap),
        ),
      ) !== canonicalJson(recipe.actionIds) ||
      recipe.terminalObservedKey !== `startup:env:${environmentName}` ||
      descriptor.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(
        `${recipe.fixtureId}: startup environment auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (principalEnvironment) {
    const descriptor = authored.sourceDescriptor;
    const auxiliaryEdgeId = descriptor?.auxiliaryDecisionEdgeId ?? null;
    const auxiliaryEdge = coverage?.edges?.find(
      (edge) => edge.id === auxiliaryEdgeId,
    );
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const selectedBranch = carrierEdge?.logicalBranches?.find(
      (branch) => branch.id === descriptor?.selectedBranch?.id,
    );
    const actionId =
      authored.operation?.kind === "read" ? "env:read" : "env:write";
    const expectedAuxiliaryName =
      authored.operation?.kind === "read"
        ? "__exactGetEnv"
        : "__exactSetEnv";
    const auxiliaryActions = canonicalSet(
      (auxiliaryEdge?.effects ?? []).map((effect) => effect.cap),
    );
    const auxiliaryStages = new Set(
      (auxiliaryEdge?.effects ?? []).flatMap((effect) => effect.stages ?? []),
    );
    if (
      auxiliaryEdge?.classification !== "effects" ||
      auxiliaryEdge?.surface?.kind !== "native-op" ||
      auxiliaryEdge?.surface?.name !== expectedAuxiliaryName ||
      descriptor.auxiliaryObservedKey !==
        `native-op:${expectedAuxiliaryName}` ||
      canonicalJson(auxiliaryActions) !== canonicalJson([actionId]) ||
      !authored.expectedTypedStages.every((stage) =>
        auxiliaryStages.has(stage),
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson([auxiliaryEdgeId]) ||
      canonicalJson(authored.expectedActionIds) !==
        canonicalJson([actionId]) ||
      carrierEdge?.classification !== "effects" ||
      carrierEdge?.surface?.kind !== "native-op" ||
      `native-op:${carrierEdge?.surface?.name}` !==
        PRINCIPAL_ENVIRONMENT_SURFACE ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      canonicalJson(selectedBranch) !==
        canonicalJson(descriptor.selectedBranch) ||
      canonicalJson(selectedBranch?.when) !==
        canonicalJson([
          {
            fact: "environment.property.operation",
            equals: authored.operation.kind,
          },
        ]) ||
      canonicalJson(
        canonicalSet(
          (selectedBranch?.effects ?? []).map((effect) => effect.cap),
        ),
      ) !== canonicalJson(recipe.actionIds) ||
      recipe.terminalObservedKey !== PRINCIPAL_ENVIRONMENT_SURFACE ||
      descriptor.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(
        `${recipe.fixtureId}: principal environment auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (effectBuiltinModuleImport) {
    const descriptor = authored.sourceDescriptor;
    const auxiliaryEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.auxiliaryDecisionEdgeId,
    );
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const auxiliaryActions = canonicalSet(
      (auxiliaryEdge?.effects ?? []).map((effect) => effect.cap),
    );
    const auxiliaryStages = new Set(
      (auxiliaryEdge?.effects ?? []).flatMap((effect) => effect.stages ?? []),
    );
    if (
      auxiliaryEdge?.classification !== "effects" ||
      auxiliaryEdge?.surface?.kind !== "native-op" ||
      auxiliaryEdge?.surface?.name !== "__exactGetEnv" ||
      canonicalJson(auxiliaryActions) !== canonicalJson(["env:read"]) ||
      !authored.expectedTypedStages.every((stage) =>
        auxiliaryStages.has(stage),
      ) ||
      canonicalJson(authored.allowedCoverageEdgeIds) !==
        canonicalJson([descriptor.auxiliaryDecisionEdgeId]) ||
      canonicalJson(authored.expectedActionIds) !==
        canonicalJson(["env:read"]) ||
      carrierEdge?.classification !== "effects" ||
      carrierEdge?.surface?.kind !== "builtin" ||
      carrierEdge?.surface?.name !== authored.moduleSpecifier ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      descriptor.carrierEdgeId !== carrierEdge.id ||
      recipe.terminalObservedKey !== `builtin:${authored.moduleSpecifier}`
    ) {
      throw new Error(
        `${recipe.fixtureId}: builtin module-import auxiliary decision is not coverage-bound`,
      );
    }
  }
  if (nonCapabilityBuiltinModuleImport) {
    const descriptor = authored.sourceDescriptor;
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === descriptor?.carrierEdgeId,
    );
    const expectation = NONCAP_BUILTIN_MODULE_IMPORT_ALIASES.get(
      authored.moduleSpecifier,
    );
    if (
      expectation === undefined ||
      carrierEdge?.classification !== "non-capability" ||
      carrierEdge?.surface?.kind !== "builtin" ||
      carrierEdge?.surface?.name !== authored.moduleSpecifier ||
      carrierEdge?.rationaleId !== "module-reachability-only" ||
      (carrierEdge.effects?.length ?? 0) !== 0 ||
      carrierEdge?.id !== recipe.edgeIds?.[0] ||
      descriptor.carrierEdgeId !== carrierEdge.id ||
      descriptor.sourceKey !== expectation.sourceKey ||
      descriptor.sourceMetadata?.sourceKey !== expectation.sourceKey ||
      descriptor.expectedRootType !== expectation.expectedRootType ||
      recipe.terminalObservedKey !== `builtin:${authored.moduleSpecifier}`
    ) {
      throw new Error(
        `${recipe.fixtureId}: non-capability builtin module import is not coverage-bound`,
      );
    }
  }
  if (capturedNonCapabilityBuiltin) {
    const carrierEdge = coverage?.edges?.find(
      (edge) => edge.id === authored.capturedOutputInvocation?.coverageEdgeId,
    );
    if (
      carrierEdge?.classification !== "non-capability" ||
      carrierEdge?.surface?.kind !== "builtin" ||
      `builtin:${carrierEdge?.surface?.name}` !==
        recipe.terminalObservedKey ||
      (carrierEdge.effects?.length ?? 0) !== 0 ||
      carrierEdge.id !== recipe.edgeIds?.[0] ||
      authored.capturedOutputInvocation.surfaceObservedKey !==
        recipe.terminalObservedKey ||
      authored.sourceDescriptor.sourceKey !==
        recipe.terminalObservedKey.split(":")[2] ||
      authored.sourceDescriptor.exportName !==
        recipe.terminalObservedKey.split(":").slice(3).join(":")
    ) {
      throw new Error(
        `${recipe.fixtureId}: captured non-capability builtin is not coverage-bound`,
      );
    }
  }
  for (const [
    decisionIndex,
    decision,
  ] of observation.typedDecisions.entries()) {
    exactKeys(
      decision,
      ["decisionSet", "gates", "evidence"],
      `${recipe.fixtureId}: observed typed decision`,
    );
    const set = decision.decisionSet;
    if (
      !set?.context ||
      typeof set.context.stage !== "string" ||
      !Array.isArray(set.effects) ||
      !Array.isArray(decision.gates) ||
      decision.gates.length !== set.effects.length
    ) {
      throw new Error(`${recipe.fixtureId}: malformed observed typed decision`);
    }
    stages.push(set.context.stage);
    const decisionEdgeIds = decision.gates.map(
      (gate) => gate?.coverageEdgeId,
    );
    const decisionIsAuxiliary =
      effectBuiltinAuxiliaryCarrier &&
      decisionEdgeIds.every((edgeId) =>
        effectBuiltinAuxiliaryByEdge.has(edgeId),
      );
    const decisionHasAuxiliary =
      effectBuiltinAuxiliaryCarrier &&
      decisionEdgeIds.some((edgeId) =>
        effectBuiltinAuxiliaryByEdge.has(edgeId),
      );
    const decisionIsDesignatedDenialTerminal =
      effectBuiltinDenialCarrier &&
      decisionEdgeIds.every(
        (edgeId) => edgeId === effectBuiltinDenialTerminalEdgeId,
      );
    if (decisionHasAuxiliary && !decisionIsAuxiliary) {
      throw new Error(
        `${recipe.fixtureId}: auxiliary and operation effects share one decision`,
      );
    }
    for (const [effectIndex, effect] of set.effects.entries()) {
      if (typeof effect?.cap !== "string") {
        throw new Error(`${recipe.fixtureId}: observed effect has no action`);
      }
      const edgeId = decision.gates[effectIndex]?.coverageEdgeId;
      const auxiliaryActions = effectBuiltinAuxiliaryByEdge.get(edgeId);
      if (
        auxiliaryActions !== undefined &&
        !auxiliaryActions.has(effect.cap)
      ) {
        throw new Error(
          `${recipe.fixtureId}: auxiliary decision observed an unbound action`,
        );
      }
      if (!decisionIsAuxiliary || decisionIsDesignatedDenialTerminal) {
        actions.add(effect.cap);
      }
    }
    for (const gate of decision.gates) {
      const edgeId = gate?.coverageEdgeId;
      if (
        typeof edgeId !== "string" ||
        gate.targetCell !== "complete" ||
        gate.definitionAndEdgePredicatesSatisfied !== true ||
        set.atomicityGroup !== `${edgeId}.decision` ||
        !authored.allowedCoverageEdgeIds.includes(edgeId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: observed an unbound or incomplete typed gate`,
        );
      }
      edgeIds.add(edgeId);
      const terminal = terminalByEdge.get(edgeId);
      if (!terminal) {
        throw new Error(
          `${recipe.fixtureId}: observed an unknown coverage edge`,
        );
      }
      if (
        !effectBuiltinAuxiliaryByEdge.has(edgeId) ||
        decisionIsDesignatedDenialTerminal
      ) {
        terminals.add(terminal);
      }
    }
    const deniedReturningModuleImport =
      authored.invocationSchema ===
        "ibex/capsec-builtin-module-import-invocation/1" &&
      recipe.scenario === "deny";
    const decisionActions = canonicalSet(
      set.effects.map((effect) => effect.cap),
    );
    const openTraversalDecision =
      builtinOpenThenAct &&
      canonicalJson(decisionActions) === canonicalJson(["fs:list"]);
    if (
      builtinOpenThenAct &&
      decisionActions.includes("fs:list") &&
      !openTraversalDecision
    ) {
      throw new Error(
        `${recipe.fixtureId}: incidental fs:list was mixed into an operation decision`,
      );
    }
    if (openTraversalDecision) {
      // Surplus fs:list is accepted only when the decision itself proves an
      // ambient path-opening traversal. A directory-listing operation cannot
      // borrow this exception by carrying the same capability name.
      const actor = set.context.actor;
      const decisiveEvidence = decision.evidence?.evidence;
      const decisiveEntry = decisiveEvidence?.[0];
      if (
        !new Set(["requested", "discovery", "repeat"]).has(
          set.context.stage,
        ) ||
        typeof set.operationId !== "string" ||
        !set.operationId.startsWith(
          builtinOpenThenActDescriptor.operationPrefix,
        ) ||
        !set.effects.every(
          (effect) =>
            effect.resource?.kind === "path-occurrence" &&
            canonicalJson(effect.effectOwner) === canonicalJson(actor),
        ) ||
        !Array.isArray(decisiveEvidence) ||
        decisiveEvidence.length !== 1 ||
        decisiveEntry?.effectIndex !== 0 ||
        canonicalJson(decisiveEntry?.principal) !== canonicalJson(actor) ||
        decisiveEntry?.stratum !== "ambient-root" ||
        decisiveEntry?.reason !== "ambient-root" ||
        decisiveEntry?.sourceId !== null
      ) {
        throw new Error(
          `${recipe.fixtureId}: incidental fs:list decision is not an ambient open traversal`,
        );
      }
    }
    const deniedByExpectedResult =
      (authored.expectedResult === "permission-denied" ||
        (authored.expectedResult === "boolean-return" &&
          recipe.scenario === "deny")) &&
      !openTraversalDecision &&
      (!decisionIsAuxiliary || decisionIsDesignatedDenialTerminal);
    const expectedOutcome = outcomeDeclaredCarrier
      ? authored.expectedTypedOutcomes[decisionIndex]
      : deniedByExpectedResult || deniedReturningModuleImport
        ? "deny"
        : "allow";
    if (decision.evidence?.outcome !== expectedOutcome) {
      throw new Error(
        `${recipe.fixtureId}: observed typed outcome disagrees with invocation`,
      );
    }
    if (
      outcomeDeclaredCarrier &&
      (!Array.isArray(decision.evidence?.evidence) ||
        decision.evidence.evidence.length === 0 ||
        decision.evidence.evidence.find(
          (entry) =>
            canonicalJson(entry?.principal) ===
            canonicalJson(decision.decisionSet.context.actor),
        )?.reason !== authored.expectedTypedReasons[decisionIndex])
    ) {
      throw new Error(
        `${recipe.fixtureId}: observed typed reason disagrees with carrier`,
      );
    }
    if (startupEnvironment) {
      const actor = set.context.actor;
      const packageMode = authored.operation.principalMode === "package-denied";
      const decisionsPerResource = packageMode ? 1 : 2;
      const environmentName =
        authored.operation.observedEnvironmentAccesses[
          Math.floor(decisionIndex / decisionsPerResource)
        ];
      const expectedActor = packageMode
        ? actor?.kind === "package" &&
          actor.name === "image-lib" &&
          actor.locator === "image-lib@2.4.1" &&
          typeof actor.integrity === "string" &&
          /^sha256-[A-Za-z0-9_-]{43}$/.test(actor.integrity)
        : canonicalJson(actor) ===
          canonicalJson({ kind: "root", identity: "project-root" });
      const expectedConstrained = packageMode
        ? [{ kind: "root", identity: "project-root" }, actor]
        : [actor];
      const effect = set.effects[0];
      if (
        set.effects.length !== 1 ||
        decision.gates.length !== 1 ||
        expectedActor !== true ||
        canonicalJson(set.context.constrainedPrincipals) !==
          canonicalJson(expectedConstrained) ||
        canonicalJson(effect?.effectOwner) !== canonicalJson(actor) ||
        effect?.cap !== "env:read" ||
        canonicalJson(effect?.resource) !==
          canonicalJson({
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name: environmentName,
            },
            valueOrigin: "principal-overlay",
          })
      ) {
        throw new Error(
          `${recipe.fixtureId}: startup environment decision lost its exact resource or principal binding`,
        );
      }
    }
    if (principalEnvironment) {
      const environmentName = authored.operation.environmentName;
      const actionId =
        authored.operation.kind === "read" ? "env:read" : "env:write";
      const actor = set.context.actor;
      const packageMode =
        authored.operation.principalMode === "package-denied";
      const expectedActor = packageMode
        ? actor?.kind === "package" &&
          actor.name === "image-lib" &&
          actor.locator === "image-lib@2.4.1" &&
          typeof actor.integrity === "string" &&
          /^sha256-[A-Za-z0-9_-]{43}$/.test(actor.integrity)
        : canonicalJson(actor) ===
          canonicalJson({ kind: "root", identity: "project-root" });
      const expectedConstrained = packageMode
        ? [{ kind: "root", identity: "project-root" }, actor]
        : [actor];
      const effect = set.effects[0];
      if (
        set.effects.length !== 1 ||
        decision.gates.length !== 1 ||
        expectedActor !== true ||
        canonicalJson(set.context.constrainedPrincipals) !==
          canonicalJson(expectedConstrained) ||
        canonicalJson(effect?.effectOwner) !== canonicalJson(actor) ||
        effect?.cap !== actionId ||
        canonicalJson(effect?.resource) !==
          canonicalJson({
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name: environmentName,
            },
            valueOrigin: "principal-overlay",
          })
      ) {
        throw new Error(
          `${recipe.fixtureId}: principal environment decision lost its exact resource or principal binding`,
        );
      }
    }
    if (effectBuiltinModuleImport) {
      const actor = { kind: "root", identity: "project-root" };
      const context = set.context;
      const effect = set.effects[0];
      const gate = decision.gates[0];
      const typedEvidence = decision.evidence;
      const identity = typedEvidence?.identity;
      const generations = typedEvidence?.generations;
      const decisiveEvidence = decision.evidence?.evidence;
      const decisiveEntry = decisiveEvidence?.[0];
      const denial = recipe.scenario === "deny";
      const expectedStratum = denial ? "principal-denial" : "static-floor";
      const expectedSourceKind = denial ? "denial" : "floor";
      const expectedOperationId =
        'environment-read:0:{"kind":"environment-name","target":"principal-overlay","name":"NODE_DEBUG"}';
      const canonicalIdentity = identity ? canonicalJson(identity) : null;
      if (decisiveEntry !== undefined) {
        exactKeys(
          decisiveEntry,
          ["effectIndex", "principal", "stratum", "reason", "sourceId"],
          `${recipe.fixtureId}: builtin module-import decisive evidence`,
        );
      }
      if (
        !hasExactKeys(set, [
          "decisionSetSchema",
          "operationId",
          "atomicityGroup",
          "combination",
          "context",
          "effects",
        ]) ||
        !hasExactKeys(context, [
          "stage",
          "actor",
          "constrainedPrincipals",
          "presentedHandleIds",
        ]) ||
        !hasExactKeys(effect, ["cap", "effectOwner", "resource"]) ||
        !hasExactKeys(gate, [
          "coverageEdgeId",
          "targetCell",
          "definitionAndEdgePredicatesSatisfied",
        ]) ||
        !hasExactKeys(typedEvidence, [
          "identity",
          "generations",
          "operationId",
          "stage",
          "actor",
          "effectOwners",
          "constrainedPrincipals",
          "outcome",
          "evidence",
        ]) ||
        !hasExactKeys(identity, [
          "profile",
          "semanticCore",
          "vocabDigest",
          "registryDigest",
          "policyDigest",
          "armedSnapshotDigest",
        ]) ||
        !hasExactKeys(generations, ["negative", "dynamic", "handle"]) ||
        set.decisionSetSchema !== "ibex/capsec-decision-set/1" ||
        set.operationId !== expectedOperationId ||
        set.combination !== "conjunction" ||
        typedEvidence.operationId !== set.operationId ||
        typedEvidence.stage !== context.stage ||
        canonicalJson(typedEvidence.actor) !== canonicalJson(actor) ||
        canonicalJson(typedEvidence.effectOwners) !== canonicalJson([actor]) ||
        canonicalJson(typedEvidence.constrainedPrincipals) !==
          canonicalJson([actor]) ||
        identity.profile !== "ibex/capsec/1" ||
        identity.semanticCore !== "capsec/semantics/1" ||
        ![
          identity.vocabDigest,
          identity.registryDigest,
          identity.policyDigest,
          identity.armedSnapshotDigest,
        ].every(isTaggedDigest) ||
        canonicalIdentity !==
          canonicalJson(observation.invocation.decisionIdentity) ||
        (effectBuiltinModuleImportIdentity !== null &&
          canonicalIdentity !== effectBuiltinModuleImportIdentity) ||
        canonicalJson(generations) !==
          canonicalJson({ negative: 0, dynamic: 0, handle: 0 })
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module-import decision lost its exact typed envelope`,
        );
      }
      effectBuiltinModuleImportIdentity = canonicalIdentity;
      if (
        set.effects.length !== 1 ||
        decision.gates.length !== 1 ||
        canonicalJson(context.actor) !== canonicalJson(actor) ||
        canonicalJson(context.constrainedPrincipals) !==
          canonicalJson([actor]) ||
        canonicalJson(context.presentedHandleIds) !== canonicalJson([]) ||
        canonicalJson(effect?.effectOwner) !== canonicalJson(actor) ||
        effect?.cap !== "env:read" ||
        canonicalJson(effect?.resource) !==
          canonicalJson({
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name: "NODE_DEBUG",
            },
            valueOrigin: "principal-overlay",
          }) ||
        gate?.coverageEdgeId !==
          authored.sourceDescriptor.auxiliaryDecisionEdgeId ||
        !Array.isArray(decisiveEvidence) ||
        decisiveEvidence.length !== 1 ||
        decisiveEntry?.effectIndex !== 0 ||
        canonicalJson(decisiveEntry?.principal) !== canonicalJson(actor) ||
        decisiveEntry?.stratum !== expectedStratum ||
        decisiveEntry?.reason !== expectedStratum ||
        typeof decisiveEntry?.sourceId !== "string" ||
        !new RegExp(
          `^principal\\.[0-9]{6}\\.${expectedSourceKind}\\.[0-9]{6}$`,
          "u",
        ).test(decisiveEntry.sourceId)
      ) {
        throw new Error(
          `${recipe.fixtureId}: builtin module-import decision lost its exact NODE_DEBUG authority binding`,
        );
      }
    }
  }
  if (callbackInvariant) {
    const checks = observation.invocation.result.checks;
    const actorAt = (index) =>
      observation.typedDecisions[index]?.decisionSet?.context?.actor;
    const same = (left, right) => canonicalJson(left) === canonicalJson(right);
    if (
      authored.scenario === "attribution-missing-deny" &&
      !observation.typedDecisions.every((decision) =>
        same(decision.decisionSet.context.actor, checks.actualPrincipal),
      )
    ) {
      throw new Error(
        `${recipe.fixtureId}: attribution evidence used the wrong actor`,
      );
    }
    if (
      authored.scenario === "generation-recheck" &&
      (!observation.typedDecisions.every((decision) =>
        same(decision.decisionSet.context.actor, checks.actualPrincipal),
      ) ||
        !same(
          observation.typedDecisions[0]?.evidence?.generations,
          checks.generationsBefore,
        ) ||
        !same(
          observation.typedDecisions[1]?.evidence?.generations,
          checks.generationsBefore,
        ) ||
        !same(
          observation.typedDecisions[2]?.evidence?.generations,
          checks.generationsAfter,
        ))
    ) {
      throw new Error(
        `${recipe.fixtureId}: generation evidence is not decision-bound`,
      );
    }
    if (
      authored.scenario === "principal-restore" &&
      (!same(actorAt(0), checks.callbackPrincipal) ||
        !same(actorAt(1), checks.callbackPrincipal) ||
        !same(actorAt(2), checks.restoredPrincipal) ||
        !same(actorAt(3), checks.restoredPrincipal))
    ) {
      throw new Error(
        `${recipe.fixtureId}: principal restoration is not decision-bound`,
      );
    }
    if (
      authored.scenario === "snapshot-mismatch-deny" &&
      observation.typedDecisions.length !== 0
    ) {
      throw new Error(
        `${recipe.fixtureId}: snapshot evidence is not decision-bound`,
      );
    }
  }
  const expectedActions =
    authored.expectedResult === "absent" ? [] : authored.expectedActionIds;
  const observedActions = [...actions].sort(compareText);
  const observedActionSet = new Set(observedActions);
  const actionSetMatches = builtinOpenThenAct
    ? expectedActions.every((action) => observedActionSet.has(action)) &&
      observedActions.every(
        (action) => expectedActions.includes(action) || action === "fs:list",
      )
    : canonicalJson(observedActions) ===
      canonicalJson([...expectedActions].sort(compareText));
  if (
    canonicalJson(stages) !== canonicalJson(authored.expectedTypedStages) ||
    !actionSetMatches ||
    (observation.typedDecisions.length > 0 && edgeIds.size === 0)
  ) {
    throw new Error(
      `${recipe.fixtureId}: observed typed stages, actions, or gates drifted`,
    );
  }

  let terminalObservedKey;
  if (runtimeAuxiliaryCarrier) {
    if (observation.typedDecisions.length > 0 && terminals.size !== 1) {
      throw new Error(
        `${recipe.fixtureId}: carrier evidence selected multiple auxiliaries`,
      );
    }
    if (
      effectBuiltinDenialCarrier &&
      !terminals.has(
        terminalByEdge.get(effectBuiltinDenialTerminalEdgeId),
      )
    ) {
      throw new Error(
        `${recipe.fixtureId}: public denial reached the wrong auxiliary terminal`,
      );
    }
    terminalObservedKey = observation.invocation.surfaceObservedKey;
  } else if (observation.typedDecisions.length === 0) {
    const validZeroDecisionScenario =
      (recipe.classification === "non-capability" &&
        recipe.scenario === "non-capability") ||
      (recipe.classification === "closed" && recipe.scenario === "closed") ||
      (recipe.classification === "effects" &&
        recipe.actionIds.length === 0 &&
        ["branch-selection", "no-effect"].includes(recipe.scenario)) ||
      recipe.scenario === "absent";
    if (
      !validZeroDecisionScenario ||
      authored.expectedTypedStages.length !== 0 ||
      (authored.expectedResult !== "absent" &&
        authored.expectedActionIds.length !== 0)
    ) {
      throw new Error(
        `${recipe.fixtureId}: absence of a typed decision is not evidence here`,
      );
    }
    const nativeExactAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema ===
        "ibex/capsec-native-global-invocation/1";
    if (
      nativeExactAbsence &&
      observation.invocation.surfaceObservedKey !== recipe.terminalObservedKey
    ) {
      throw new Error(`${recipe.fixtureId}: malformed exact-absence evidence`);
    }
    const builtinTargetAbsence =
      authored.expectedResult === "absent" &&
      observation.invocation.invocationSchema ===
        "ibex/capsec-builtin-export-invocation/1";
    const sourceVariantAbsence =
      authored.expectedResult === "absent" &&
      !builtinTargetAbsence &&
      observation.invocation.invocationSchema !==
        "ibex/capsec-native-global-invocation/1";
    terminalObservedKey = builtinTargetAbsence
      ? observation.invocation.surfaceObservedKey
      : sourceVariantAbsence
        ? `${observation.invocation.result.surfaceKind}:${observation.invocation.result.surfaceName}`
        : observation.invocation.surfaceObservedKey;
  } else if (nativeWorkerTerminals !== null) {
    if (
      canonicalJson([...terminals].sort(compareText)) !==
      canonicalJson([...nativeWorkerTerminals].sort(compareText))
    ) {
      throw new Error(
        `${recipe.fixtureId}: async invocation did not remain on its source-selected worker`,
      );
    }
    terminalObservedKey = observation.invocation.surfaceObservedKey;
  } else {
    if (terminals.size !== 1) {
      throw new Error(
        `${recipe.fixtureId}: typed gates selected multiple terminals`,
      );
    }
    terminalObservedKey = [...terminals][0];
  }
  const directTerminalBuiltinClosure =
    recipe.classification === "closed" &&
    recipe.scenario === "closed" &&
    authored.operation?.kind === "terminal-builtin-import" &&
    recipe.route?.alternatives?.length === 0 &&
    canonicalJson(recipe.route?.surfaceObservedKeys) ===
      canonicalJson([terminalObservedKey]);
  const closedSqliteCarrierClosure =
    recipe.classification === "closed" &&
    recipe.scenario === "closed" &&
    CLOSED_SQLITE_CARRIER_OPERATIONS.has(authored.operation?.kind) &&
    observation.typedDecisions.length === 0 &&
    terminalObservedKey === recipe.terminalObservedKey;
  const directFilesystemMutationClosure =
    recipe.classification === "closed" &&
    recipe.scenario === "closed" &&
    authored.operation?.kind === "filesystem-unbound-mutation" &&
    observation.typedDecisions.length === 0 &&
    terminalObservedKey === recipe.terminalObservedKey &&
    canonicalJson(recipe.route?.surfaceObservedKeys) ===
      canonicalJson([terminalObservedKey]);
  const allowed = runtimeAuxiliaryCarrier
    ? [recipe.publicSurfaceProbe.surfaceObservedKey]
    : directTerminalBuiltinClosure ||
        closedSqliteCarrierClosure ||
        directFilesystemMutationClosure
      ? [terminalObservedKey]
      : recipe.route?.alternatives?.map(
          (alternative) => alternative.terminalObservedKey,
        );
  const exactTargetAbsence =
    authored.expectedResult === "absent" &&
    recipe.expectedObservation?.kind === "target-absence";
  if (
    runtimeAuxiliaryCarrier
      ? !allowed.includes(terminalObservedKey)
      : exactTargetAbsence
        ? allowed?.length !== 0 ||
          terminalObservedKey !== recipe.terminalObservedKey
        : !allowed?.includes(terminalObservedKey)
  ) {
    throw new Error(
      `${recipe.fixtureId}: runtime-derived terminal is outside the bound route`,
    );
  }
  return terminalObservedKey;
}

function validateExecution(execution, recipe, engineBinaryDigest, coverage) {
  exactKeys(
    execution,
    ["fixtureId", "outcome", "executor", "evidence"],
    `${recipe.fixtureId}: public execution`,
  );
  exactKeys(
    execution.evidence,
    [
      "evidenceSchema",
      "fixtureId",
      "planDigest",
      "engineBinaryDigest",
      "probe",
      "terminalObservedKey",
      "exitCode",
      "resultMarker",
      "observation",
      "runtimeObservation",
      "evidenceDigest",
    ],
    `${recipe.fixtureId}: public execution evidence`,
  );
  const evidence = execution.evidence;
  const expectedExecutor = reviewedPublicSurfaceExecutorDescriptor(
    recipe.publicSurfaceProbe?.command,
  )?.executor;
  if (
    execution.fixtureId !== recipe.fixtureId ||
    evidence.evidenceSchema !==
      "ibex/capsec-public-surface-fixture-evidence/2" ||
    evidence.fixtureId !== recipe.fixtureId ||
    typeof execution.executor !== "string" ||
    execution.executor.length === 0 ||
    /adapter/iu.test(execution.executor) ||
    (expectedExecutor !== undefined && execution.executor !== expectedExecutor) ||
    evidence.planDigest !== recipe.planDigest ||
    evidence.engineBinaryDigest !== engineBinaryDigest ||
    canonicalJson(evidence.probe) !==
      canonicalJson(recipe.publicSurfaceProbe) ||
    evidence.evidenceDigest !== evidenceDigest(evidence)
  ) {
    throw new Error(
      `${recipe.fixtureId}: adapter-only, stale, or malformed public-surface evidence`,
    );
  }
  const runtimeTerminal = validatePublicFixtureRuntimeObservation(
    evidence.runtimeObservation,
    recipe,
    coverage,
  );
  const passedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:passed`;
  const failedMarker = `ibex-capsec-public-fixture:${recipe.fixtureId}:failed`;
  const derivedOutcome =
    evidence.exitCode === 0 && evidence.resultMarker === passedMarker
      ? "passed"
      : evidence.exitCode !== 0 || evidence.resultMarker === failedMarker
        ? "failed"
        : null;
  if (!derivedOutcome || derivedOutcome !== execution.outcome) {
    throw new Error(
      `${recipe.fixtureId}: public result marker disagrees with outcome`,
    );
  }
  const expectedObservation = {
    ...recipe.expectedObservation,
    result: derivedOutcome,
  };
  if (
    canonicalJson(evidence.observation) !== canonicalJson(expectedObservation)
  ) {
    throw new Error(
      `${recipe.fixtureId}: public observation selected the wrong branch`,
    );
  }
  if (runtimeTerminal !== evidence.terminalObservedKey) {
    throw new Error(
      `${recipe.fixtureId}: claimed terminal differs from runtime typed gates`,
    );
  }
}

export function validatePublicSurfaceExecutionArtifact(
  artifact,
  {
    recipeCatalog,
    target = null,
    sourceRevision = null,
    sourceTreeDigest = null,
    engine = null,
    coverage = null,
  },
) {
  if (artifact?.adapterEvidenceSchema) {
    throw new Error("adapter-only evidence cannot advertise a target");
  }
  exactKeys(
    artifact,
    [
      "publicSurfaceExecutionSchema",
      "profile",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "engine",
      "recipeCatalogDigest",
      "summary",
      "executions",
      "publicSurfaceExecutionDigest",
    ],
    "public-surface execution artifact",
  );
  if (
    artifact.publicSurfaceExecutionSchema !==
      "ibex/capsec-public-surface-executions/1" ||
    artifact.profile !== "ibex/capsec/1" ||
    !Array.isArray(artifact.executions) ||
    artifact.recipeCatalogDigest !== recipeCatalog.recipeCatalogDigest ||
    artifact.publicSurfaceExecutionDigest !==
      computePublicSurfaceExecutionDigest(artifact) ||
    (target && canonicalJson(artifact.target) !== canonicalJson(target)) ||
    (sourceRevision && artifact.sourceRevision !== sourceRevision) ||
    (sourceTreeDigest && artifact.sourceTreeDigest !== sourceTreeDigest) ||
    (engine && canonicalJson(artifact.engine) !== canonicalJson(engine))
  ) {
    throw new Error(
      "public-surface execution artifact has stale or mismatched bindings",
    );
  }
  validateRecipeCatalog(recipeCatalog, { target: artifact.target });
  const recipes = new Map(
    recipeCatalog.recipes.map((recipe) => [recipe.fixtureId, recipe]),
  );
  const seen = new Set();
  const authenticatedSourceRuntimeNonces = new Set();
  for (const execution of artifact.executions) {
    const recipe = recipes.get(execution?.fixtureId);
    if (!recipe || seen.has(execution.fixtureId)) {
      throw new Error(
        "public-surface executions contain an unknown or duplicate fixture",
      );
    }
    seen.add(execution.fixtureId);
    validateExecution(
      execution,
      recipe,
      artifact.engine?.binaryDigest,
      coverage,
    );
    const authenticatedSourceRuntimeNonce =
      execution.evidence?.runtimeObservation?.invocation?.sourceExecution
        ?.runtimeNonce;
    if (authenticatedSourceRuntimeNonce !== undefined) {
      if (
        authenticatedSourceRuntimeNonces.has(authenticatedSourceRuntimeNonce)
      ) {
        throw new Error(
          "authenticated source executions reused a runtime nonce",
        );
      }
      authenticatedSourceRuntimeNonces.add(authenticatedSourceRuntimeNonce);
    }
  }
  if (
    canonicalJson(artifact.executions.map((row) => row.fixtureId)) !==
    canonicalJson([...seen].sort(compareText))
  ) {
    throw new Error(
      "public-surface executions are not in canonical fixture order",
    );
  }
  if (
    canonicalJson(artifact.summary) !==
    canonicalJson(executionSummary(recipeCatalog, artifact.executions))
  ) {
    throw new Error(
      "public-surface execution summary disagrees with its evidence",
    );
  }
  return artifact;
}

export function assertPublicSurfaceExecutionComplete(
  artifact,
  recipeCatalog,
  options = {},
) {
  assertRecipeCatalogComplete(recipeCatalog, {
    target: options.target ?? artifact.target,
    expectedFixtureIds: options.expectedFixtureIds ?? null,
  });
  validatePublicSurfaceExecutionArtifact(artifact, {
    ...options,
    recipeCatalog,
  });
  if (
    artifact.summary.residualFixtures !== 0 ||
    artifact.summary.failedFixtures !== 0 ||
    artifact.summary.missingFixtures !==
      artifact.summary.internallyVerifiedFixtures ||
    artifact.summary.executedFixtures !==
      artifact.summary.executableFixtures ||
    artifact.summary.passedFixtures !== artifact.summary.executableFixtures
  ) {
    throw new Error(
      "public-surface execution artifact cannot advertise with residual, failed, or missing public obligations",
    );
  }
}

export function buildPublicFixtureEvidence({
  recipe,
  engineBinaryDigest,
  runtimeObservation,
  coverage,
  outcome = "passed",
  executor = "ibex-public-surface-harness",
}) {
  const terminalObservedKey = validatePublicFixtureRuntimeObservation(
    runtimeObservation,
    recipe,
    coverage,
  );
  const evidence = {
    evidenceSchema: "ibex/capsec-public-surface-fixture-evidence/2",
    fixtureId: recipe.fixtureId,
    planDigest: recipe.planDigest,
    engineBinaryDigest,
    probe: structuredClone(recipe.publicSurfaceProbe),
    terminalObservedKey,
    exitCode: outcome === "passed" ? 0 : 1,
    resultMarker: `ibex-capsec-public-fixture:${recipe.fixtureId}:${outcome}`,
    observation: { ...recipe.expectedObservation, result: outcome },
    runtimeObservation: structuredClone(runtimeObservation),
  };
  evidence.evidenceDigest = evidenceDigest(evidence);
  return {
    fixtureId: recipe.fixtureId,
    outcome,
    executor,
    evidence,
  };
}
