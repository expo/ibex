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
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const BUILTIN_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand(
    "capsec_public_noncap_builtin_recipe_batch",
    true,
  ),
);

const READ_INVOCATION_SCHEMA = "ibex/capsec-builtin-export-invocation/1";
const CALL_INVOCATION_SCHEMA = "ibex/capsec-builtin-call-invocation/1";
const MODULE_IMPORT_NO_EFFECT_INVOCATION_SCHEMA =
  "ibex/capsec-builtin-module-import-no-effect-invocation/1";
const EVENT_LOOP_COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});

// The deprecated root fs constants are accessors whose source contract emits
// DEP0176. That observable warning is not a zero-effect read, and armed
// runtimes deliberately disable process.emitWarning. The inert values remain
// available through the separately inventoried fs.constants object.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const DEPRECATED_FS_CONSTANT_ACCESSORS = new Set([
  "F_OK",
  "R_OK",
  "W_OK",
  "X_OK",
]);

// These are the module-root aliases whose current source has been reviewed as
// decision-free at import time. Each spelling is observed in a fresh engine;
// exported operations remain separate obligations. Keep this allowlist exact:
// a new alias or source must receive its own import-time review before it can
// become executable evidence.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const NONCAP_MODULE_ALIAS_SOURCES = new Map(
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

// The dns/promises carrier copies exactly these reviewed provider error codes
// through a computed loop, so the inventory correctly records their static
// shape as unknown. Do not widen generic unknown-shape reads: this independent
// exact-name set authors a read only when the loaded public value proves it is
// a string.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
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

// These value exports are read only after their module initialization has
// completed. Keep the set, provenance, and runtime types exact so this does
// not weaken the generic exclusion for effectful modules or unknown shapes.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const REVIEWED_POST_INITIALIZATION_VALUE_EXPORTS = new Map(
  [
    [
      "node_cluster",
      "SCHED_NONE",
      "data",
      "number",
      ["member-assignment"],
      ["cluster", "node:cluster"],
      "src/builtins/cluster.js#exports:SCHED_NONE",
    ],
    [
      "node_cluster",
      "SCHED_RR",
      "data",
      "number",
      ["member-assignment"],
      ["cluster", "node:cluster"],
      "src/builtins/cluster.js#exports:SCHED_RR",
    ],
    [
      "node_cluster",
      "isMaster",
      "data",
      "boolean",
      ["member-assignment"],
      ["cluster", "node:cluster"],
      "src/builtins/cluster.js#exports:isMaster",
    ],
    [
      "node_cluster",
      "isPrimary",
      "data",
      "boolean",
      ["member-assignment"],
      ["cluster", "node:cluster"],
      "src/builtins/cluster.js#exports:isPrimary",
    ],
    [
      "node_cluster",
      "isWorker",
      "unknown",
      "boolean",
      ["member-assignment"],
      ["cluster", "node:cluster"],
      "src/builtins/cluster.js#exports:isWorker",
    ],
    [
      "node_http",
      "METHODS",
      "data",
      "object",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:METHODS",
    ],
    [
      "node_http",
      "STATUS_CODES",
      "data",
      "object",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:STATUS_CODES",
    ],
    [
      "node_http",
      "kConnectionsCheckingInterval",
      "unknown",
      "symbol",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:kConnectionsCheckingInterval",
    ],
    [
      "node_http",
      "kHighWaterMark",
      "unknown",
      "symbol",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:kHighWaterMark",
    ],
    [
      "node_http",
      "kTimeout",
      "unknown",
      "symbol",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:kTimeout",
    ],
    [
      "node_http",
      "maxHeaderSize",
      "unknown",
      "number",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:maxHeaderSize",
    ],
    [
      "node_http",
      "methods",
      "data",
      "object",
      ["module-exports-object"],
      [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      "src/builtins/http.js#exports:methods",
    ],
    [
      "node_os",
      "EOL",
      "data",
      "string",
      ["define-property"],
      ["node:os", "os"],
      "src/builtins/os.js#exports:EOL",
    ],
    [
      "node_os",
      "constants",
      "data",
      "object",
      ["module-exports-object"],
      ["node:os", "os"],
      "src/builtins/os.js#exports:constants",
    ],
    [
      "node_os",
      "devNull",
      "data",
      "string",
      ["module-exports-object"],
      ["node:os", "os"],
      "src/builtins/os.js#exports:devNull",
    ],
    [
      "exact_crypto",
      "subtle",
      "unknown",
      "object",
      ["object-binding", "object-source"],
      ["crypto", "exact:crypto", "node:crypto"],
      "src/builtins/crypto.js#exports:subtle",
    ],
    [
      "exact_crypto",
      "webcrypto",
      "unknown",
      "object",
      ["object-binding", "object-source"],
      ["crypto", "exact:crypto", "node:crypto"],
      "src/builtins/crypto.js#exports:webcrypto",
    ],
    [
      "node_console",
      "default",
      "unknown",
      "object",
      ["module-exports-assignment"],
      ["console", "node:console"],
      "src/builtins/console.js#exports:default",
    ],
    [
      "node_events",
      "captureRejectionSymbol",
      "unknown",
      "symbol",
      ["member-assignment"],
      ["events", "node:events"],
      "src/builtins/events.js#exports:captureRejectionSymbol",
    ],
    [
      "node_events",
      "errorMonitor",
      "unknown",
      "symbol",
      ["member-assignment"],
      ["events", "node:events"],
      "src/builtins/events.js#exports:errorMonitor",
    ],
    [
      "node_fs",
      "constants",
      "unknown",
      "object",
      ["module-exports-object"],
      ["bun:fs", "fs", "node:fs"],
      "src/builtins/fs.js#exports:constants",
    ],
    [
      "node_fs_promises",
      "constants",
      "unknown",
      "object",
      ["object-binding", "object-source"],
      ["bun:fs/promises", "fs/promises", "internal/fs/promises", "node:fs/promises"],
      "src/builtins/fs-promises.js#exports:constants",
    ],
    [
      "node_http2",
      "sensitiveHeaders",
      "unknown",
      "symbol",
      ["module-exports-object"],
      ["http2", "node:http2"],
      "src/builtins/http2.js#exports:sensitiveHeaders",
    ],
    [
      "node_module",
      "builtinModules",
      "unknown",
      "object",
      ["member-assignment", "object-binding", "object-source"],
      ["module", "node:module"],
      "src/builtins/module.js#exports:builtinModules",
    ],
    [
      "node_perf_hooks",
      "performance",
      "unknown",
      "object",
      ["module-exports-object"],
      ["node:perf_hooks", "perf_hooks"],
      "src/builtins/perf-hooks.js#exports:performance",
    ],
    ["node_dns", "default", "unknown", "object", ["member-assignment", "module-exports-assignment"], ["dns", "node:dns"], "src/builtins/dns.js#exports:default"],
    ["node_dns_promises", "default", "unknown", "object", ["module-exports-assignment"], ["dns/promises", "node:dns/promises"], "src/builtins/dns-promises.js#exports:default"],
    ["node_stream_web", "ByteLengthQueuingStrategy", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ByteLengthQueuingStrategy"],
    ["node_stream_web", "CountQueuingStrategy", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:CountQueuingStrategy"],
    ["node_stream_web", "ReadableStream", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ReadableStream"],
    ["node_stream_web", "ReadableStreamBYOBReader", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ReadableStreamBYOBReader"],
    ["node_stream_web", "ReadableStreamDefaultReader", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:ReadableStreamDefaultReader"],
    ["node_stream_web", "TransformStream", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:TransformStream"],
    ["node_stream_web", "WritableStream", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:WritableStream"],
    ["node_stream_web", "WritableStreamDefaultWriter", "unknown", "function", ["object-assignment", "object-source"], ["node:stream/web", "stream/web"], "src/builtins/stream-web.js#exports:WritableStreamDefaultWriter"],
    [
      "node_timers_promises",
      "scheduler",
      "unknown",
      "object",
      ["module-exports-object"],
      ["node:timers/promises", "timers/promises"],
      "src/builtins/timers-promises.js#exports:scheduler",
    ],
    [
      "path_posix_alias",
      "default",
      "unknown",
      "object",
      ["module-exports-assignment"],
      ["node:path/posix", "path/posix"],
      "modules.ts#sources:path_posix_alias:exports:default",
    ],
    [
      "path_win32_alias",
      "default",
      "unknown",
      "object",
      ["module-exports-assignment"],
      ["node:path/win32", "path/win32"],
      "modules.ts#sources:path_win32_alias:exports:default",
    ],
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

// These exact prototype properties are safe to read on the exported
// prototype itself. Accessor rows below have source bodies that return only
// inert defaults when `this` is the prototype; `X509Certificate.raw`, the
// filesystem accessors and unreviewed instance-state projections are
// deliberately absent because they throw or require a constructed resource.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
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

// These exact inherited inventory rows describe an own accessor installed by
// the Stream constructor rather than a value that exists on the exported
// prototype. Execute the read only on a fresh, idle, harness-owned stream.
// The boolean projection is inert; mutable readableState/writableState graphs
// remain deliberately residual.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
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

// `raw` copies only bytes owned by a fresh compatibility X509Certificate.
// Keep this constructed-instance exception separate from the broader
// certificate accessor family and from resource-backed instance projections.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const REVIEWED_X509_INSTANCE_VALUE_EXPORTS = new Map([
  [
    "exact_crypto:X509Certificate.raw",
    {
      sourceKey: "exact_crypto",
      exportName: "X509Certificate.raw",
      valueShape: "accessor",
      expectedValueType: "object",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
      sourceRef: "src/builtins/crypto.js#exports:X509Certificate.raw",
      ownerExportName: "X509Certificate",
      constructorArguments: [{ kind: "json", value: "ibex-x509-fixture" }],
    },
  ],
]);

// `SecureContext.context` is an own frozen opaque object installed by a fresh
// source-only SecureContext constructor. It does not allocate a TLS engine or
// consult native trust state.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUE_EXPORTS = new Map([
  [
    "node_tls:SecureContext.context",
    {
      sourceKey: "node_tls",
      exportName: "SecureContext.context",
      valueShape: "unknown",
      expectedValueType: "object",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:tls", "tls"],
      sourceRef: "src/builtins/tls.js#exports:SecureContext.context",
      ownerExportName: "SecureContext",
      constructorArguments: [],
    },
  ],
]);

// `Socket._closed` is an own non-configurable accessor installed by a fresh
// udp4 Socket. The owner check projects one boolean from the source-only state;
// the receiver has no native handle, binding, poll timer, or peer route.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const REVIEWED_DGRAM_SOCKET_INSTANCE_VALUE_EXPORTS = new Map([
  [
    "node_dgram:Socket._closed",
    {
      sourceKey: "node_dgram",
      exportName: "Socket._closed",
      valueShape: "unknown",
      expectedValueType: "boolean",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["dgram", "node:dgram"],
      sourceRef: "src/builtins/dgram.js#exports:Socket._closed",
      ownerExportName: "Socket",
      constructorArguments: [{ kind: "json", value: "udp4" }],
    },
  ],
]);

const jsonArgument = (value) => ({ kind: "json", value });
const noopArgument = () => ({ kind: "noop-function" });
const timerCallbackArgument = () => ({ kind: "timer-callback" });
const zlibFlushCallbackArgument = () => ({ kind: "zlib-flush-callback" });
const zlibDirectFlushCallbackArgument = () => ({
  kind: "zlib-direct-flush-callback",
});
const zlibParamsCallbackArgument = () => ({ kind: "zlib-params-callback" });
const zlibTransformCallbackArgument = () => ({
  kind: "zlib-transform-callback",
});
const zlibWriteCallbackArgument = () => ({ kind: "zlib-write-callback" });
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
const zlibCallbackArgument = (resultContract) => ({
  kind: "zlib-callback",
  resultContract,
});
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
const ownValue = (object, key) =>
  object && Object.prototype.hasOwnProperty.call(object, key)
    ? object[key]
    : null;

function callSpec(
  setup,
  arguments_,
  resultType,
  proofKind = "normal-return-from-source-call",
) {
  return { setup, arguments: arguments_, resultType, proofKind };
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
const keyObjectPairOwner = (bytes) =>
  callSpec(
    {
      kind: "key-object-pair-owner",
      ownerExportName: "KeyObject",
      keyType: "secret",
      bytes,
    },
    [setupValueArgument("peer")],
    "boolean",
  );
const readlineInterfaceOwner = () =>
  callSpec(
    {
      kind: "readline-interface-owner",
      ownerExportName: "Interface",
      terminal: false,
    },
    [],
    "undefined",
  );
const readlineInterfacePauseOwner = () =>
  callSpec(
    {
      kind: "readline-interface-pause-owner",
      ownerExportName: "Interface",
      terminal: false,
      cleanupMethod: "close",
    },
    [],
    "object",
  );
const tlsServerConstructTarget = () =>
  callSpec({ kind: "tls-server-construct-target" }, [], "object");
const tlsServerRootCall = () =>
  callSpec({ kind: "tls-server-root-call" }, [], "object");
const netTerminalOwner = (ownerExportName) =>
  callSpec(
    {
      kind: "net-terminal-owner",
      ownerExportName,
    },
    [],
    "object",
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
const ZLIB_END_CONTRACTS = new Map([
  ["BrotliCompress", [[105, 98, 101, 120], "nonempty-byte-view"]],
  [
    "BrotliDecompress",
    [[139, 1, 128, 105, 98, 101, 120, 3], "exact-ibex-byte-view"],
  ],
  ["Deflate", [[105, 98, 101, 120], "nonempty-byte-view"]],
  ["DeflateRaw", [[105, 98, 101, 120], "nonempty-byte-view"]],
  [
    "Gunzip",
    [
      [
        31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
        109, 106, 4, 0, 0, 0,
      ],
      "exact-ibex-byte-view",
    ],
  ],
  ["Gzip", [[105, 98, 101, 120], "nonempty-byte-view"]],
  [
    "Inflate",
    [[120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169], "exact-ibex-byte-view"],
  ],
  [
    "InflateRaw",
    [[203, 76, 74, 173, 0, 0], "exact-ibex-byte-view"],
  ],
  [
    "Unzip",
    [
      [
        31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
        109, 106, 4, 0, 0, 0,
      ],
      "exact-ibex-byte-view",
    ],
  ],
]);
const ZLIB_PROCESS_CHUNK_CONTRACTS = new Map(
  [...ZLIB_END_CONTRACTS].map(([owner, [bytes, outputContract]]) => [
    owner,
    [bytes, outputContract],
  ]),
);
const ZLIB_WRITE_CONTRACTS = new Map(
  [...ZLIB_END_CONTRACTS].map(([owner, [bytes, outputContract]]) => [
    owner,
    [bytes, outputContract],
  ]),
);
const ZLIB_FLUSH_OWNERS = new Set([
  ...ZLIB_END_CONTRACTS.keys(),
  "ZstdCompress",
  "ZstdDecompress",
]);
const ZLIB_TRANSFORM_INPUTS = new Map([
  ...[...ZLIB_END_CONTRACTS].map(([owner, [bytes]]) => [owner, bytes]),
  ["ZstdCompress", [105, 98, 101, 120]],
  ["ZstdDecompress", [105, 98, 101, 120]],
]);
const ZLIB_DIRECT_FLUSH_CONTRACTS = new Map(
  [...ZLIB_TRANSFORM_INPUTS].map(([owner, prefillInput]) => [
    owner,
    [
      prefillInput,
      owner === "ZstdCompress" || owner === "ZstdDecompress"
        ? "ENOSYS"
        : null,
    ],
  ]),
);

const TIMER_ROOT_CALL_SPECS = Object.freeze({
  active: callSpec(
    { kind: "timer-legacy-root", operation: "active" },
    [setupValueArgument("timerRecord")],
    "undefined",
  ),
  _unrefActive: callSpec(
    { kind: "timer-legacy-root", operation: "_unrefActive" },
    [setupValueArgument("timerRecord")],
    "undefined",
  ),
  enroll: callSpec(
    { kind: "timer-legacy-root", operation: "enroll" },
    [setupValueArgument("timerRecord"), jsonArgument(60_000)],
    "undefined",
  ),
  unenroll: callSpec(
    { kind: "timer-legacy-root", operation: "unenroll" },
    [setupValueArgument("timerRecord")],
    "undefined",
  ),
  clearInterval: callSpec(
    { kind: "timer-clear-root", timerKind: "interval" },
    [setupValueArgument("timerHandle")],
    "undefined",
  ),
  clearTimeout: callSpec(
    { kind: "timer-clear-root", timerKind: "timeout" },
    [setupValueArgument("timerHandle")],
    "undefined",
  ),
  setImmediate: callSpec(
    { kind: "timer-factory-root", timerKind: "immediate" },
    [timerCallbackArgument()],
    "object",
  ),
  setInterval: callSpec(
    { kind: "timer-factory-root", timerKind: "interval" },
    [timerCallbackArgument(), jsonArgument(60_000)],
    "object",
  ),
  setTimeout: callSpec(
    { kind: "timer-factory-root", timerKind: "timeout" },
    [timerCallbackArgument(), jsonArgument(60_000)],
    "object",
  ),
});

function timerPrototypeSpec(exportName) {
  const [ownerExportName, methodName, ...extra] = exportName.split(".");
  if (
    extra.length !== 0 ||
    !new Set(["Immediate", "Timeout"]).has(ownerExportName)
  ) {
    return null;
  }
  const methods =
    ownerExportName === "Immediate"
      ? new Map([
          ["close", "object"],
          ["hasRef", "boolean"],
          ["ref", "object"],
          ["unref", "object"],
        ])
      : new Map([
          ["_scheduleNative", "undefined"],
          ["close", "object"],
          ["hasRef", "boolean"],
          ["ref", "object"],
          ["refresh", "object"],
          ["unref", "object"],
        ]);
  const resultType = methods.get(methodName);
  if (!resultType) return null;
  return callSpec(
    {
      kind: "timer-owner",
      ownerExportName,
      preclosed: methodName === "_scheduleNative",
    },
    [],
    resultType,
  );
}

function zlibRootCallSpecs() {
  const specs = Object.create(null);
  const deflateBytes = [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169];
  const deflateRawBytes = [203, 76, 74, 173, 0, 0];
  const gzipBytes = [
    31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30, 109,
    106, 4, 0, 0, 0,
  ];
  const brotliBytes = [139, 1, 128, 105, 98, 101, 120, 3];
  for (const ownerExportName of ZLIB_OWNER_NAMES) {
    specs[ownerExportName] = constructTarget([]);
    specs[`create${ownerExportName}`] = rootCall([], "object");
  }
  specs.crc32 = rootCall([jsonArgument("ibex")], "number");
  specs.deflateSync = rootCall(
    [bufferArgument([105, 98, 101, 120])],
    "object",
  );
  specs.deflateRawSync = rootCall(
    [bufferArgument([105, 98, 101, 120])],
    "object",
  );
  specs.gzipSync = rootCall(
    [bufferArgument([105, 98, 101, 120])],
    "object",
  );
  specs.brotliCompressSync = rootCall(
    [bufferArgument([105, 98, 101, 120])],
    "object",
  );
  specs.brotliDecompressSync = rootCall(
    [bufferArgument(brotliBytes)],
    "object",
  );
  specs.inflateSync = rootCall([bufferArgument(deflateBytes)], "object");
  specs.inflateRawSync = rootCall(
    [bufferArgument(deflateRawBytes)],
    "object",
  );
  specs.gunzipSync = rootCall([bufferArgument(gzipBytes)], "object");
  specs.unzipSync = rootCall([bufferArgument(gzipBytes)], "object");
  for (const exportName of ["deflate", "deflateRaw", "gzip"]) {
    specs[exportName] = rootCall(
      [
        bufferArgument([105, 98, 101, 120]),
        zlibCallbackArgument("nonempty-byte-view"),
      ],
      "undefined",
    );
  }
  for (const [exportName, bytes] of [
    ["brotliDecompress", brotliBytes],
    ["gunzip", gzipBytes],
    ["inflate", deflateBytes],
    ["inflateRaw", deflateRawBytes],
    ["unzip", gzipBytes],
  ]) {
    specs[exportName] = rootCall(
      [bufferArgument(bytes), zlibCallbackArgument("exact-ibex-byte-view")],
      "undefined",
    );
  }
  specs.brotliCompress = rootCall(
    [
      bufferArgument([105, 98, 101, 120]),
      zlibCallbackArgument("nonempty-byte-view"),
    ],
    "undefined",
  );
  // One-shot codec functions, synchronous and callback-based alike, enter
  // native codec work that currently can terminate the bound static-Hermes
  // process. Keep every unaudited member residual until each backend has
  // isolated physical proof; quiescence cannot turn a process crash into a
  // receipt.
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
const STREAM_SETTLED_CONSUMER_METHOD_SET = new Set([
  "every",
  "find",
  "forEach",
  "reduce",
  "some",
  "toArray",
]);
const STREAM_DEFAULT_MODULE_VALUE_METHOD_SET = new Set([
  "_close",
  "_emitClose",
  "_undestroy",
  "constructor",
  "destroy",
  "unpipe",
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
  specs.getDefaultHighWaterMark = rootCall([jsonArgument(false)], "number");
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
// Supplying the prime keeps construction and the state-only accessors out of
// prime generation and random-key generation. Twenty-three is a fixed prime;
// five is a valid generator for the tiny, evidence-only group.
const CRYPTO_EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  uint8ArrayArgument([23]),
  jsonArgument(5),
]);
const CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS = Object.freeze([
  jsonArgument("prime256v1"),
]);

function exactCryptoCallSpecs() {
  const specs = {
    DiffieHellman: constructTarget([
      ...CRYPTO_EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS,
    ]),
    Hash: constructTarget([...CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS]),
    Hmac: constructTarget([...CRYPTO_HMAC_CONSTRUCTOR_ARGUMENTS]),
    KeyObject: constructTarget([
      jsonArgument("secret"),
      uint8ArrayArgument([0x69, 0x62, 0x65, 0x78]),
    ]),
    "KeyObject.equals": keyObjectPairOwner([0x69, 0x62, 0x65, 0x78]),
    createHash: rootCall([...CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS], "object"),
    createHmac: rootCall([...CRYPTO_HMAC_CONSTRUCTOR_ARGUMENTS], "object"),
    // These compatibility constructors retain only the harness-owned key
    // bytes and classify their in-memory wrapper; they do not parse, import,
    // or consult a native key store.
    createPrivateKey: rootCall([jsonArgument("ibex-key")], "object"),
    createPublicKey: rootCall([jsonArgument("ibex-key")], "object"),
    createDiffieHellmanGroup: rootCall(
      [...CRYPTO_DH_GROUP_CONSTRUCTOR_ARGUMENTS],
      "object",
    ),
    createDiffieHellman: rootCall(
      [...CRYPTO_EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS],
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
    // Physical static-Hermes execution currently terminates in generateKeySync
    // before a result or cleanup receipt can be captured. Keep the source row
    // residual until the native crash is repaired; a declarative in-memory
    // argument list is not execution evidence.
    // generatePrimeSync shares the bound engine's current native
    // process-terminating defect with generateKeySync. It cannot furnish a
    // public normal-return receipt on the advertised target.
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
    // The synchronous KDF entry points currently share a process-terminating
    // native defect on the bound static-Hermes target. Keep hkdfSync,
    // pbkdf2Sync, and scryptSync residual until they can return and clean up.
    // Random-data helpers are deliberately absent from this generic call
    // table. Their exact output routes own bounded buffers, async quiescence,
    // and the physical loaded-engine receipts needed for promotion.
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
    if (ownerExportName === "Hash") {
      specs["Hash.digest"] = constructedOwner(
        "Hash",
        [jsonArgument("hex")],
        "string",
        [...constructorArguments],
      );
    }
    // Hmac.digest currently terminates the bound static-Hermes process. Its
    // source row remains residual until the native digest defect is repaired.
    specs[`${ownerExportName}.update`] = constructedOwner(
      ownerExportName,
      [jsonArgument("ibex")],
      "object",
      [...constructorArguments],
    );
  }
  specs["Hash.copy"] = constructedOwner("Hash", [], "object", [
    ...CRYPTO_HASH_CONSTRUCTOR_ARGUMENTS,
  ]);
  specs["KeyObject.export"] = constructedOwner("KeyObject", [], "object", [
    jsonArgument("secret"),
    uint8ArrayArgument([0x69, 0x62, 0x65, 0x78]),
  ]);
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
  // These explicit-parameter DiffieHellman methods only project or replace
  // in-memory byte arrays. generateKeys() and computeSecret() intentionally
  // remain residual because they cross into random or modular work.
  for (const methodName of [
    "getGenerator",
    "getPrime",
    "getPrivateKey",
    "getPublicKey",
  ]) {
    specs[`DiffieHellman.${methodName}`] = constructedOwner(
      "DiffieHellman",
      [],
      "object",
      [...CRYPTO_EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS],
    );
  }
  for (const methodName of ["setPrivateKey", "setPublicKey"]) {
    specs[`DiffieHellman.${methodName}`] = constructedOwner(
      "DiffieHellman",
      [uint8ArrayArgument([3])],
      "undefined",
      [...CRYPTO_EXPLICIT_DH_CONSTRUCTOR_ARGUMENTS],
    );
  }
  for (const methodName of ["getPrivateKey", "getPublicKey"]) {
    specs[`ECDH.${methodName}`] = constructedOwner("ECDH", [], "object", [
      ...CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS,
    ]);
  }
  for (const methodName of ["setPrivateKey", "setPublicKey"]) {
    specs[`ECDH.${methodName}`] = constructedOwner(
      "ECDH",
      [uint8ArrayArgument([1, 2, 3, 4])],
      "undefined",
      [...CRYPTO_ECDH_CONSTRUCTOR_ARGUMENTS],
    );
  }
  // AES-256-CBC has a fixed 32-byte key and 16-byte IV, and the Cipher /
  // Decipher bodies for these methods only mutate in-memory chunk/AAD/tag
  // state and return the receiver or an empty Buffer — they never reach the
  // native EVP bridge (that is deferred to final(), which stays residual).
  // Their one-shot construction and mutation therefore have a bounded normal
  // return with no observable capability decision.
  const CBC_CONSTRUCTOR_ARGUMENTS = Object.freeze([
    jsonArgument("aes-256-cbc"),
    uint8ArrayArgument([
      0x69, 0x62, 0x65, 0x78, 0x69, 0x62, 0x65, 0x78, 0x69, 0x62, 0x65, 0x78,
      0x69, 0x62, 0x65, 0x78, 0x69, 0x62, 0x65, 0x78, 0x69, 0x62, 0x65, 0x78,
      0x69, 0x62, 0x65, 0x78, 0x69, 0x62, 0x65, 0x78,
    ]),
    uint8ArrayArgument([
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
      0x63, 0x64, 0x65, 0x66,
    ]),
  ]);
  for (const rootName of [
    "createCipher",
    "createCipheriv",
    "createDecipher",
    "createDecipheriv",
  ]) {
    specs[rootName] = rootCall([...CBC_CONSTRUCTOR_ARGUMENTS], "object");
  }
  for (const ownerExportName of [
    "Cipher",
    "Cipheriv",
    "Decipher",
    "Decipheriv",
  ]) {
    specs[ownerExportName] = constructTarget([...CBC_CONSTRUCTOR_ARGUMENTS]);
    specs[`${ownerExportName}.constructor`] = constructTarget([
      ...CBC_CONSTRUCTOR_ARGUMENTS,
    ]);
    specs[`${ownerExportName}.update`] = constructedOwner(
      ownerExportName,
      [jsonArgument("ibex")],
      "object",
      [...CBC_CONSTRUCTOR_ARGUMENTS],
    );
    specs[`${ownerExportName}.setAutoPadding`] = constructedOwner(
      ownerExportName,
      [],
      "object",
      [...CBC_CONSTRUCTOR_ARGUMENTS],
    );
    specs[`${ownerExportName}.setAAD`] = constructedOwner(
      ownerExportName,
      [uint8ArrayArgument([0x69, 0x62, 0x65, 0x78])],
      "object",
      [...CBC_CONSTRUCTOR_ARGUMENTS],
    );
  }
  for (const ownerExportName of ["Decipher", "Decipheriv"]) {
    specs[`${ownerExportName}.setAuthTag`] = constructedOwner(
      ownerExportName,
      [uint8ArrayArgument([0x69, 0x62, 0x65, 0x78, 0x69, 0x62, 0x65, 0x78])],
      "object",
      [...CBC_CONSTRUCTOR_ARGUMENTS],
    );
  }
  // Certificate (SPKAC) is a validate-and-return compatibility shim: the
  // constructor takes no arguments, and exportChallenge/exportPublicKey/
  // verifySpkac only validate the SPKAC argument's type then return a fixed
  // empty Buffer / empty string / false. No native path is reached.
  specs.Certificate = constructTarget([]);
  specs["Certificate.exportChallenge"] = constructedOwner(
    "Certificate",
    [jsonArgument("ibex-spkac")],
    "object",
    [],
  );
  specs["Certificate.exportPublicKey"] = constructedOwner(
    "Certificate",
    [jsonArgument("ibex-spkac")],
    "string",
    [],
  );
  specs["Certificate.verifySpkac"] = constructedOwner(
    "Certificate",
    [jsonArgument("ibex-spkac")],
    "boolean",
    [],
  );
  // X509Certificate's constructor stores the raw/PEM bytes without parsing, and
  // check*/verify/toString/toJSON/toLegacyObject are trap-free stubs returning
  // undefined/false/the stored PEM/{}. Its value-bearing fields (subject,
  // publicKey, fingerprint, ...) are prototype accessors and stay residual.
  const X509_CONSTRUCTOR_ARGUMENTS = Object.freeze([
    jsonArgument("ibex-x509-fixture"),
  ]);
  specs.X509Certificate = constructTarget([...X509_CONSTRUCTOR_ARGUMENTS]);
  for (const [methodName, resultType] of [
    ["checkEmail", "undefined"],
    ["checkHost", "undefined"],
    ["checkIP", "undefined"],
    ["checkIssued", "boolean"],
    ["checkPrivateKey", "boolean"],
    ["toJSON", "string"],
    ["toLegacyObject", "object"],
    ["toString", "string"],
    ["verify", "boolean"],
  ]) {
    specs[`X509Certificate.${methodName}`] = constructedOwner(
      "X509Certificate",
      [],
      resultType,
      [...X509_CONSTRUCTOR_ARGUMENTS],
    );
  }
  return Object.freeze(specs);
}

const EXACT_CRYPTO_CALL_SPECS = exactCryptoCallSpecs();

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — A
// fresh net Server, Socket, or legacy Stream has no native transport. Terminal
// calls use a dedicated owner setup so close delivery and final in-memory
// state are part of the receipt instead of being inferred from quiescence.
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
  "Server.close": netTerminalOwner("Server"),
  "Server.ref": constructedOwner("Server", [], "object"),
  "Server.unref": constructedOwner("Server", [], "object"),
  // A freshly constructed Socket owns no native handle: destroy(), ref(),
  // close(), resetAndDestroy(), ref(), and unref() only update in-memory
  // lifecycle state and return the receiver. The terminal calls use a
  // dedicated setup that observes their close event and final state.
  // net.Stream is the exact source's legacy alias for Socket.
  "Socket.close": netTerminalOwner("Socket"),
  "Socket.destroy": constructedOwner("Socket", [], "object"),
  "Socket.ref": constructedOwner("Socket", [], "object"),
  "Socket.resetAndDestroy": netTerminalOwner("Socket"),
  "Socket.unref": constructedOwner("Socket", [], "object"),
  "Stream.close": netTerminalOwner("Stream"),
  "Stream.destroy": constructedOwner("Stream", [], "object"),
  "Stream.ref": constructedOwner("Stream", [], "object"),
  "Stream.resetAndDestroy": netTerminalOwner("Stream"),
  "Stream.unref": constructedOwner("Stream", [], "object"),
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

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — A
// fresh HTTP Agent or Server has no socket, listener, or native selector.
// These exact lifecycle operations either construct that idle wrapper, clear
// empty harness-owned collections, update only in-memory terminal state, or
// skip native ref/unref because no selector exists. Server.close may schedule
// its terminal close event, which the required quiescence observation drains.
// The four root validators inspect only fixed harness-owned header strings.
const NODE_HTTP_CALL_SPECS = Object.freeze({
  _checkInvalidHeaderChar: rootCall([jsonArgument("ibex")], "boolean"),
  _checkIsHttpToken: rootCall([jsonArgument("x-ibex")], "boolean"),
  "Agent.destroy": constructedOwner("Agent", [], "undefined"),
  Server: constructTarget([]),
  "Server.close": constructedOwner("Server", [], "object"),
  "Server.closeAllConnections": constructedOwner("Server", [], "undefined"),
  "Server.closeIdleConnections": constructedOwner("Server", [], "undefined"),
  "Server.constructor": constructTarget([]),
  "Server.ref": constructedOwner("Server", [], "object"),
  "Server.unref": constructedOwner("Server", [], "object"),
  createServer: rootCall([], "object"),
  validateHeaderName: rootCall([jsonArgument("x-ibex")], "undefined"),
  validateHeaderValue: rootCall(
    [jsonArgument("x-ibex"), jsonArgument("ibex")],
    "undefined",
  ),
});

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — An
// idle HTTPS Server layers one fresh HTTP wrapper over one fresh TLS Server.
// Neither layer binds a transport; the TLS layer still owns one private token.
// Reuse the dedicated TLS-server retirement setup so close must drain the
// outer HTTP close event and prove the inner TLS token is terminal.
const NODE_HTTPS_CALL_SPECS = Object.freeze({
  Server: tlsServerConstructTarget(),
  "Server.constructor": tlsServerConstructTarget(),
  createServer: tlsServerRootCall(),
});

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — A
// fresh UDP Socket owns a principal stamp but no native handle, binding, poll
// timer, or peer route. These exact construction and idle lifecycle calls use
// only that harness-owned wrapper; close's terminal event must drain before
// the shared quiescence observation completes, while dropMembership returns
// before its native hook because the fresh handle remains absent.
const NODE_DGRAM_CALL_SPECS = Object.freeze({
  Socket: constructTarget([jsonArgument("udp4")]),
  "Socket.close": constructedOwner(
    "Socket",
    [],
    "object",
    [jsonArgument("udp4")],
  ),
  "Socket.constructor": constructTarget([jsonArgument("udp4")]),
  "Socket.dropMembership": constructedOwner(
    "Socket",
    [jsonArgument("224.0.0.1")],
    "undefined",
    [jsonArgument("udp4")],
  ),
  "Socket.ref": constructedOwner(
    "Socket",
    [],
    "object",
    [jsonArgument("udp4")],
  ),
  "Socket.unref": constructedOwner(
    "Socket",
    [],
    "object",
    [jsonArgument("udp4")],
  ),
  createSocket: rootCall([jsonArgument("udp4")], "object"),
});

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — A
// TLSSocket constructed without a transport owns no native TLS owner token,
// engine, selector, listener, or timer. Fresh TLS Server construction does
// mint exactly one owner token and installs its private registry listeners, so
// its dedicated setup closes the idle server and proves the close event plus
// delayed token retirement before returning. Neither family binds a transport.
const NODE_TLS_CALL_SPECS = Object.freeze({
  getCiphers: rootCall([], "object"),
  Server: tlsServerConstructTarget(),
  "Server.constructor": tlsServerConstructTarget(),
  TLSSocket: constructTarget([]),
  "TLSSocket.close": constructedOwner("TLSSocket", [], "object"),
  "TLSSocket.destroy": constructedOwner("TLSSocket", [], "object"),
  "TLSSocket.ref": constructedOwner("TLSSocket", [], "object"),
  "TLSSocket.unref": constructedOwner("TLSSocket", [], "object"),
  createServer: tlsServerRootCall(),
});

const NODE_FS_CALL_SPECS = Object.freeze({
  _toUnixTimestamp: rootCall([jsonArgument(1)], "number"),
  Stats: constructTarget([
    jsonArgument({ is_file: true }),
    jsonArgument(false),
  ]),
  Dirent: constructTarget([
    jsonArgument("entry.txt"),
    jsonArgument(1),
  ]),
  "Dirent.isBlockDevice": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
  "Dirent.isCharacterDevice": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
  "Dirent.isDirectory": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
  "Dirent.isFIFO": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
  "Dirent.isFile": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
  "Dirent.isSocket": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
  "Dirent.isSymbolicLink": constructedOwner(
    "Dirent",
    [],
    "boolean",
    [jsonArgument("entry.txt"), jsonArgument(1)],
  ),
});

// These tables are deliberately keyed by the scanner's sourceKey and exact
// exportName. They are an allowlist derived from the corresponding builtin
// source, not a generic "call every function" mechanism.
const ROOT_CALL_SPECS = Object.freeze({
  exact_crypto: EXACT_CRYPTO_CALL_SPECS,
  // Pure reporters over compiled-in tables: neither reaches a capability,
  // descriptor, or native resolver, so both execute with zero decisions.
  node_dns: Object.freeze({
    getDefaultResultOrder: rootCall([], "string"),
  }),
  node_dgram: NODE_DGRAM_CALL_SPECS,
  node_http2: Object.freeze({
    getDefaultSettings: rootCall([], "object"),
  }),
  node_fs: NODE_FS_CALL_SPECS,
  node_http: NODE_HTTP_CALL_SPECS,
  node_https: NODE_HTTPS_CALL_SPECS,
  node_stream_web: Object.freeze({
    isReadableStream: rootCall([jsonArgument({})], "boolean"),
    isWritableStream: rootCall([jsonArgument({})], "boolean"),
  }),
  node_tls: NODE_TLS_CALL_SPECS,
  node_module: Object.freeze({
    _nodeModulePaths: rootCall([jsonArgument("/ibex/project/src")], "object"),
    isBuiltin: rootCall([jsonArgument("node:path")], "boolean"),
    wrap: rootCall([jsonArgument("return 'ibex';")], "string"),
  }),
  node_net: NODE_NET_CALL_SPECS,
  node_readline: Object.freeze({
    // CSI concatenates one harness-owned string array into a terminal escape
    // sequence; it opens no terminal and retains no stream.
    CSI: rootCall([jsonArgument(["31m"])], "string"),
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // exact listener teardown, not generic Interface compatibility.
    // A dedicated inert input shim proves Interface construction installs
    // exactly the reviewed listeners and resumes once. close must detach every
    // listener, pause once, mark the receiver closed, and emit one close event.
    "Interface.close": readlineInterfaceOwner(),
    // pause's normal return deliberately retains those listeners. Its separate
    // receipt proves the paused state first and then invokes exact close
    // cleanup before the fixture can complete.
    "Interface.pause": readlineInterfacePauseOwner(),
  }),
  node_perf_hooks: Object.freeze({
    Performance: constructTarget([]),
    "Performance.clearMarks": constructedOwner("Performance", [], "undefined"),
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
      [jsonArgument("ibex-measure"), jsonArgument({ start: 0, duration: 1 })],
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
    join: rootCall([jsonArgument("/ibex"), jsonArgument("child")], "string"),
    normalize: rootCall([jsonArgument("/ibex/../probe/")], "string"),
    parse: rootCall([jsonArgument("/ibex/file.txt")], "object"),
    relative: rootCall(
      [jsonArgument("/ibex"), jsonArgument("/ibex/child")],
      "string",
    ),
    resolve: rootCall([jsonArgument("/ibex"), jsonArgument("child")], "string"),
    toNamespacedPath: rootCall([jsonArgument("/ibex")], "string"),
  }),
  node_querystring: Object.freeze({
    decode: rootCall([jsonArgument("a=1&a=2&b=ibex")], "object"),
    encode: rootCall([jsonArgument({ a: ["1", "2"], b: "ibex" })], "string"),
    escape: rootCall([jsonArgument("ibex probe")], "string"),
    parse: rootCall([jsonArgument("a=1&a=2&b=ibex")], "object"),
    stringify: rootCall([jsonArgument({ a: ["1", "2"], b: "ibex" })], "string"),
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
    "StringDecoder.toString": constructedOwner("StringDecoder", [], "string", [
      jsonArgument("utf8"),
    ]),
    "StringDecoder.write": constructedOwner(
      "StringDecoder",
      [bufferArgument([0x69, 0x62, 0x65, 0x78])],
      "string",
      [jsonArgument("utf8")],
    ),
  }),
  node_stream: STREAM_ROOT_CALL_SPECS,
  node_timers: TIMER_ROOT_CALL_SPECS,
  node_url: Object.freeze({
    canParse: rootCall([jsonArgument("https://example.test/ibex")], "boolean"),
    fileURLToPath: rootCall([jsonArgument("file:///tmp/ibex")], "string"),
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
      [jsonArgument("https://example.test/base/"), jsonArgument("../ibex")],
      "string",
    ),
    resolveObject: rootCall(
      [jsonArgument("https://example.test/base/"), jsonArgument("../ibex")],
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
    toUnicode: rootCall([jsonArgument("xn--maana-pta.example")], "string"),
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
    match: rootCall([jsonArgument("ibex"), regexpArgument("ib")], "undefined"),
    notDeepEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 2 })],
      "undefined",
    ),
    notDeepStrictEqual: rootCall(
      [jsonArgument({ a: 1 }), jsonArgument({ a: 2 })],
      "undefined",
    ),
    notEqual: rootCall([jsonArgument(1), jsonArgument(2)], "undefined"),
    notStrictEqual: rootCall([jsonArgument(1), jsonArgument("1")], "undefined"),
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
    on: rootCall([eventEmitterArgument(), jsonArgument("ibex")], "object"),
    once: rootCall([eventEmitterArgument(), jsonArgument("ibex")], "object"),
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
  asciiWrite: [[jsonArgument("a"), jsonArgument(0), jsonArgument(1)], "number"],
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
  hexWrite: [[jsonArgument("61"), jsonArgument(0), jsonArgument(1)], "number"],
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
  ucs2Write: [[jsonArgument("a"), jsonArgument(0), jsonArgument(2)], "number"],
  utf16beWrite: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(2)],
    "number",
  ],
  utf16leWrite: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(2)],
    "number",
  ],
  utf8Slice: [[jsonArgument(0), jsonArgument(8)], "string"],
  utf8Write: [[jsonArgument("a"), jsonArgument(0), jsonArgument(1)], "number"],
  write: [
    [jsonArgument("a"), jsonArgument(0), jsonArgument(1), jsonArgument("utf8")],
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
  writeIntBE: [[jsonArgument(-1), jsonArgument(0), jsonArgument(6)], "number"],
  writeIntLE: [[jsonArgument(-1), jsonArgument(0), jsonArgument(6)], "number"],
  writeUInt16BE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt16LE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt32BE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt32LE: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUInt8: [[jsonArgument(1), jsonArgument(0)], "number"],
  writeUIntBE: [[jsonArgument(1), jsonArgument(0), jsonArgument(6)], "number"],
  writeUIntLE: [[jsonArgument(1), jsonArgument(0), jsonArgument(6)], "number"],
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
  if (methodName === "destroy") {
    // Construction establishes a principal-bound native selector, and the
    // owned destroy path synchronously authenticates before delegating to the
    // stream lifecycle. `_destroy` closes that idle selector; the harness then
    // performs an idempotent cleanup and waits for event-loop quiescence.
    return zlibOwnerCall(ownerExportName, [], "object");
  }
  if (methodName === "end") {
    const contract = ZLIB_END_CONTRACTS.get(ownerExportName);
    if (!contract) return null;
    return callSpec(
      {
        kind: "zlib-end-owner",
        ownerExportName,
        outputContract: contract[1],
      },
      [bufferArgument(contract[0])],
      "object",
    );
  }
  if (methodName === "_processChunk") {
    const contract = ZLIB_PROCESS_CHUNK_CONTRACTS.get(ownerExportName);
    if (!contract) return null;
    return callSpec(
      {
        kind: "zlib-process-chunk-owner",
        ownerExportName,
        outputContract: contract[1],
      },
      [bufferArgument(contract[0]), jsonArgument(4)],
      "object",
    );
  }
  if (methodName === "write") {
    const contract = ZLIB_WRITE_CONTRACTS.get(ownerExportName);
    if (!contract) return null;
    return callSpec(
      {
        kind: "zlib-write-owner",
        ownerExportName,
        outputContract: contract[1],
        terminalMethod: "end",
      },
      [bufferArgument(contract[0]), zlibWriteCallbackArgument()],
      "boolean",
    );
  }
  if (methodName === "flush" && ZLIB_FLUSH_OWNERS.has(ownerExportName)) {
    return callSpec(
      {
        kind: "zlib-flush-owner",
        ownerExportName,
        callbackPosition: "first-argument",
        flushKind: "default-full-flush",
        cleanupMethod: "destroy",
      },
      [zlibFlushCallbackArgument()],
      "object",
    );
  }
  if (methodName === "params" && ZLIB_FLUSH_OWNERS.has(ownerExportName)) {
    return callSpec(
      {
        kind: "zlib-params-owner",
        ownerExportName,
        level: 1,
        strategy: 0,
        cleanupMethod: "destroy",
      },
      [
        jsonArgument(1),
        jsonArgument(0),
        zlibParamsCallbackArgument(),
      ],
      "object",
    );
  }
  if (methodName === "_transform") {
    const input = ZLIB_TRANSFORM_INPUTS.get(ownerExportName);
    if (!input) return null;
    return callSpec(
      {
        kind: "zlib-transform-owner",
        ownerExportName,
        inputLength: input.length,
        cleanupMethod: "destroy",
      },
      [
        bufferArgument(input),
        jsonArgument("buffer"),
        zlibTransformCallbackArgument(),
      ],
      "undefined",
    );
  }
  if (methodName === "_flush") {
    const contract = ZLIB_DIRECT_FLUSH_CONTRACTS.get(ownerExportName);
    if (!contract) return null;
    return callSpec(
      {
        kind: "zlib-direct-flush-owner",
        ownerExportName,
        prefillInput: contract[0],
        expectedCallbackErrorCode: contract[1],
        cleanupMethod: "destroy",
      },
      [zlibDirectFlushCallbackArgument()],
      "undefined",
    );
  }
  if (
    new Set([
      "_writeNative",
    ]).has(methodName)
  ) {
    // These methods enter native codec work. At least BrotliCompress._flush
    // currently terminates the bound static-Hermes process, so this family
    // stays residual until each native lifecycle has isolated physical proof.
    return null;
  }
  if (methodName === "_pushNativeOutput") {
    return zlibOwnerCall(
      ownerExportName,
      [uint8ArrayArgument([105, 98, 101, 120])],
      "object",
    );
  }
  if (methodName === "close") {
    return zlibOwnerCall(ownerExportName, [noopArgument()], "object");
  }
  if (methodName === "reset") {
    return zlibOwnerCall(ownerExportName, [], "object");
  }
  if (methodName === "setEncoding") {
    return zlibOwnerCall(ownerExportName, [jsonArgument("utf8")], "object");
  }
  return null;
}

function streamOwnerCall(
  ownerExportName,
  arguments_,
  resultType,
  endedInput = false,
  proofKind = "normal-return-from-source-call",
) {
  return callSpec(
    {
      kind: "stream-owner",
      ownerExportName,
      endedInput,
    },
    arguments_,
    resultType,
    proofKind,
  );
}

function streamPrototypeSpec(exportName) {
  const segments = exportName.split(".");
  if (segments.length !== 2 || !STREAM_OWNER_SET.has(segments[0])) return null;
  const [ownerExportName, methodName] = segments;
  // node:stream is itself the default Stream export; it does not expose a
  // `default.prototype` property at runtime. Only this independently reviewed
  // lifecycle set receives module-value prototype traversal; every other
  // default-owner row remains residual.
  if (
    ownerExportName === "default" &&
    !STREAM_DEFAULT_MODULE_VALUE_METHOD_SET.has(methodName)
  ) {
    return null;
  }
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
    if (methodName === "addListener" || methodName === "on") {
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
    if (STREAM_SETTLED_CONSUMER_METHOD_SET.has(methodName)) {
      const argumentsByMethod = {
        every: [constantFunctionArgument(true)],
        find: [constantFunctionArgument(true)],
        forEach: [noopArgument()],
        reduce: [
          constantFunctionArgument("ibex"),
          jsonArgument("ibex-initial"),
        ],
        some: [constantFunctionArgument(true)],
        toArray: [],
      };
      const resultTypeByMethod = {
        every: "boolean",
        find: "undefined",
        forEach: "undefined",
        reduce: "string",
        some: "boolean",
        toArray: "object",
      };
      // These consumers own their Promise until the harness awaits it. An
      // already-ended, empty, harness-created stream gives each method a
      // deterministic terminal path; the outer event-loop quiescence proof
      // then establishes that no deferred source work escaped the receipt.
      return streamOwnerCall(
        ownerExportName,
        argumentsByMethod[methodName],
        resultTypeByMethod[methodName],
        true,
        "settled-return-from-source-call",
      );
    }
    // wrap() retains its delegated source after returning and needs a
    // separately owned source/cleanup recipe.
    if (methodName === "wrap") return null;
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
  node_dns: "node-dns-pure-v1",
  node_dgram: "node-dgram-idle-v1",
  node_http: "node-http-idle-v1",
  node_http2: "node-http2-pure-v1",
  node_https: "node-https-idle-v1",
  node_events: "node-events-bounded-v1",
  node_fs: "node-fs-pure-v1",
  node_module: "node-module-pure-v1",
  node_net: "node-net-bounded-v1",
  node_perf_hooks: "node-perf-hooks-bounded-v1",
  node_path: "node-path-pure-v1",
  node_punycode: "node-punycode-pure-v1",
  node_querystring: "node-querystring-pure-v1",
  node_readline: "node-readline-pure-v1",
  node_stream: "node-stream-bounded-v1",
  node_stream_web: "node-stream-web-pure-v1",
  node_string_decoder: "node-string-decoder-bounded-v1",
  node_timers: "node-timers-bounded-v1",
  node_tls: "node-tls-pure-v1",
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
  if (!spec && descriptor.sourceKey === "node_timers") {
    spec = timerPrototypeSpec(descriptor.exportName);
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
        "key-object-pair-owner",
        "net-terminal-owner",
        "readline-interface-owner",
        "readline-interface-pause-owner",
        "tls-server-construct-target",
        "timer-owner",
        "zlib-direct-flush-owner",
        "zlib-end-owner",
        "zlib-flush-owner",
        "zlib-owner",
        "zlib-params-owner",
        "zlib-process-chunk-owner",
        "zlib-transform-owner",
        "zlib-write-owner",
        "stream-owner",
      ]).has(setupKind)) ||
    (!prototypeAccess &&
      !new Set([
        "construct-target",
        "root-call",
        "tls-server-construct-target",
        "tls-server-root-call",
        "timer-clear-root",
        "timer-factory-root",
        "timer-legacy-root",
      ]).has(setupKind))
  ) {
    return null;
  }
  return {
    templateId,
    setup: spec.setup,
    arguments: spec.arguments,
    bodyEntryProof: {
      kind: spec.proofKind,
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

function targetUnavailablePublicExportReason(surface, target) {
  const triple =
    typeof target === "string"
      ? target
      : typeof target?.triple === "string"
        ? target.triple
        : null;
  const metadata = surface?.metadata;
  // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — Windows keeps Brotli constants but does not install the native codec globals required by callable Brotli exports.
  if (
    triple === "x86_64-pc-windows-msvc" &&
    metadata?.surfaceType === "export" &&
    metadata.sourceKey === "node_zlib" &&
    /^(?:Brotli|brotli|createBrotli)/u.test(metadata.exportName)
  ) {
    return "builtin-export-native-prerequisite-not-installed-on-target";
  }
  // The shared crypto builtin is reachable on Windows, but its reduced native
  // profile does not install the PBKDF2, scrypt, or HKDF host functions. Keep
  // their synchronous exports in the honest target gap instead of promoting
  // recipes that can only throw at runtime.
  // @ref LLP 0006#platform-native-crypto-with-honest-reduced-profiles
  if (
    triple === "x86_64-pc-windows-msvc" &&
    metadata?.surfaceType === "export" &&
    metadata.sourceKey === "exact_crypto" &&
    ["hkdfSync", "pbkdf2Sync", "scryptSync"].includes(metadata.exportName)
  ) {
    return "builtin-export-native-prerequisite-not-installed-on-target";
  }
  return null;
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

function reviewedRuntimeTypedValueAccess(expected) {
  // node:stream publishes its default Stream constructor as the module value,
  // not as a nested `default` property. Keep this correction scoped to the
  // exact reviewed row rather than teaching generic prototype authoring to
  // guess at module-export aliasing.
  if (
    expected.sourceKey === "node_stream" &&
    expected.exportName === "default.destroyed"
  ) {
    return { kind: "prototype-property", path: ["prototype", "destroyed"] };
  }
  return exportAccess(expected.exportName, expected.exportIdioms);
}

function sourceDescriptor(
  surface,
  target,
  allowedValueShapes,
  {
    allowTargetAbsence = false,
    allowReviewedPostInitializationValue = false,
    allowReviewedIdleHttpCall = false,
  } = {},
) {
  const metadata = surface?.metadata;
  const availability = platformAvailability(metadata);
  const targetPlatform = platformForTarget(target);
  if (
    metadata?.surfaceType !== "export" ||
    metadata.importReachability !== "public" ||
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // a source-proven cross-source shape is still only presence evidence. A
    // dedicated carrier/provider invocation must be authored before it can
    // receive execution credit, even if a future descriptor accepts multiple
    // source references.
    metadata.crossSourceExportProjection !== undefined ||
    metadata.constructorInstanceProjection !== undefined ||
    typeof metadata.sourceKey !== "string" ||
    metadata.sourceKey.length === 0 ||
    (NONCAP_GENERIC_EXPORT_EXCLUSIONS.has(metadata.sourceKey) &&
      !allowReviewedPostInitializationValue &&
      !(
        allowReviewedIdleHttpCall &&
        metadata.sourceKey === "node_http" &&
        ownValue(NODE_HTTP_CALL_SPECS, metadata.exportName)
      )) ||
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
    targetUnavailablePublicExportReason(surface, target) !== null ||
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
  const genericAccess = exportAccess(
    metadata.exportName,
    metadata.exportIdioms,
  );
  const [ownerExportName, methodName, ...extraSegments] =
    metadata.exportName.split(".");
  const access =
    metadata.sourceKey === "node_stream" &&
    ownerExportName === "default" &&
    extraSegments.length === 0 &&
    STREAM_DEFAULT_MODULE_VALUE_METHOD_SET.has(methodName)
      ? { kind: "prototype-property", path: ["prototype", methodName] }
      : genericAccess;
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

function isDeprecatedFsConstantAccessorDescriptor(descriptor) {
  return (
    descriptor?.sourceKey === "node_fs" &&
    DEPRECATED_FS_CONSTANT_ACCESSORS.has(descriptor.exportName) &&
    descriptor.valueShape === "accessor" &&
    canonicalJson(descriptor.exportIdioms) ===
      canonicalJson(["define-property"]) &&
    canonicalJson(descriptor.moduleSpecifiers) ===
      canonicalJson(["bun:fs", "fs", "node:fs"]) &&
    descriptor.sourceRef ===
      `src/builtins/fs.js#exports:${descriptor.exportName}` &&
    descriptor.access.kind === "export-property" &&
    canonicalJson(descriptor.access.path) ===
      canonicalJson([descriptor.exportName])
  );
}

function reviewedRuntimeTypedValueSourceDescriptor(
  surface,
  target,
  reviewedExports,
  allowedValueShapes,
) {
  const metadata = surface?.metadata;
  const expected =
    typeof metadata?.sourceKey === "string" &&
    typeof metadata?.exportName === "string"
      ? reviewedExports.get(
          `${metadata.sourceKey}:${metadata.exportName}`,
        )
      : null;
  if (!expected) return null;
  const descriptor = sourceDescriptor(
    surface,
    target,
    allowedValueShapes,
    { allowReviewedPostInitializationValue: true },
  );
  const access = reviewedRuntimeTypedValueAccess(expected);
  const reviewedDescriptor =
    descriptor && access ? { ...descriptor, access } : null;
  const expectedDescriptor = {
    kind: "builtin-export",
    sourceKey: expected.sourceKey,
    exportName: expected.exportName,
    exportIdioms: expected.exportIdioms,
    moduleSpecifiers: expected.moduleSpecifiers,
    sourceRef: expected.sourceRef,
    valueShape: expected.valueShape,
    access,
  };
  if (
    !reviewedDescriptor ||
    canonicalJson(reviewedDescriptor) !== canonicalJson(expectedDescriptor)
  ) {
    return null;
  }
  return {
    ...reviewedDescriptor,
    expectedValueType: expected.expectedValueType,
  };
}

function reviewedPostInitializationValueSourceDescriptor(surface, target) {
  return reviewedRuntimeTypedValueSourceDescriptor(
    surface,
    target,
    REVIEWED_POST_INITIALIZATION_VALUE_EXPORTS,
    new Set(["data", "unknown"]),
  );
}

function reviewedPrototypeValueSourceDescriptor(surface, target) {
  const descriptor = reviewedRuntimeTypedValueSourceDescriptor(
    surface,
    target,
    REVIEWED_PROTOTYPE_VALUE_EXPORTS,
    new Set(["accessor", "data", "unknown"]),
  );
  return descriptor &&
    new Set(["prototype-property", "inherited-prototype-property"]).has(
      descriptor.access.kind,
    )
    ? descriptor
    : null;
}

function reviewedStreamInstanceValueSourceDescriptor(surface, target) {
  const metadata = surface?.metadata;
  const expected =
    typeof metadata?.sourceKey === "string" &&
    typeof metadata?.exportName === "string"
      ? REVIEWED_STREAM_INSTANCE_VALUE_EXPORTS.get(
          `${metadata.sourceKey}:${metadata.exportName}`,
        )
      : null;
  if (!expected) return null;
  const descriptor = sourceDescriptor(
    surface,
    target,
    new Set(["unknown"]),
    { allowReviewedPostInitializationValue: true },
  );
  const access = { kind: "constructed-instance-property", path: ["closed"] };
  const reviewedDescriptor = descriptor ? { ...descriptor, access } : null;
  const expectedDescriptor = {
    kind: "builtin-export",
    sourceKey: expected.sourceKey,
    exportName: expected.exportName,
    exportIdioms: expected.exportIdioms,
    moduleSpecifiers: expected.moduleSpecifiers,
    sourceRef: expected.sourceRef,
    valueShape: expected.valueShape,
    access,
  };
  if (
    !reviewedDescriptor ||
    canonicalJson(reviewedDescriptor) !== canonicalJson(expectedDescriptor)
  ) {
    return null;
  }
  return {
    ...reviewedDescriptor,
    expectedValueType: expected.expectedValueType,
  };
}

function reviewedX509InstanceValueSourceDescriptor(surface, target) {
  const metadata = surface?.metadata;
  const expected =
    typeof metadata?.sourceKey === "string" &&
    typeof metadata?.exportName === "string"
      ? REVIEWED_X509_INSTANCE_VALUE_EXPORTS.get(
          `${metadata.sourceKey}:${metadata.exportName}`,
        )
      : null;
  if (!expected) return null;
  const descriptor = sourceDescriptor(
    surface,
    target,
    new Set(["accessor"]),
    { allowReviewedPostInitializationValue: true },
  );
  const access = { kind: "constructed-instance-property", path: ["raw"] };
  const reviewedDescriptor = descriptor ? { ...descriptor, access } : null;
  const expectedDescriptor = {
    kind: "builtin-export",
    sourceKey: expected.sourceKey,
    exportName: expected.exportName,
    exportIdioms: expected.exportIdioms,
    moduleSpecifiers: expected.moduleSpecifiers,
    sourceRef: expected.sourceRef,
    valueShape: expected.valueShape,
    access,
  };
  if (
    !reviewedDescriptor ||
    canonicalJson(reviewedDescriptor) !== canonicalJson(expectedDescriptor)
  ) {
    return null;
  }
  return {
    ...reviewedDescriptor,
    expectedValueType: expected.expectedValueType,
  };
}

function reviewedTlsSecureContextInstanceValueSourceDescriptor(
  surface,
  target,
) {
  const metadata = surface?.metadata;
  const expected =
    typeof metadata?.sourceKey === "string" &&
    typeof metadata?.exportName === "string"
      ? REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUE_EXPORTS.get(
          `${metadata.sourceKey}:${metadata.exportName}`,
        )
      : null;
  if (!expected) return null;
  const descriptor = sourceDescriptor(surface, target, new Set(["unknown"]), {
    allowReviewedPostInitializationValue: true,
  });
  const access = {
    kind: "constructed-instance-property",
    path: ["context"],
  };
  const reviewedDescriptor = descriptor ? { ...descriptor, access } : null;
  const expectedDescriptor = {
    kind: "builtin-export",
    sourceKey: expected.sourceKey,
    exportName: expected.exportName,
    exportIdioms: expected.exportIdioms,
    moduleSpecifiers: expected.moduleSpecifiers,
    sourceRef: expected.sourceRef,
    valueShape: expected.valueShape,
    access,
  };
  if (
    !reviewedDescriptor ||
    canonicalJson(reviewedDescriptor) !== canonicalJson(expectedDescriptor)
  ) {
    return null;
  }
  return {
    ...reviewedDescriptor,
    expectedValueType: expected.expectedValueType,
  };
}

function reviewedDgramSocketInstanceValueSourceDescriptor(surface, target) {
  const metadata = surface?.metadata;
  const expected =
    typeof metadata?.sourceKey === "string" &&
    typeof metadata?.exportName === "string"
      ? REVIEWED_DGRAM_SOCKET_INSTANCE_VALUE_EXPORTS.get(
          `${metadata.sourceKey}:${metadata.exportName}`,
        )
      : null;
  if (!expected) return null;
  const descriptor = sourceDescriptor(surface, target, new Set(["unknown"]), {
    allowReviewedPostInitializationValue: true,
  });
  const access = {
    kind: "constructed-instance-property",
    path: ["_closed"],
  };
  const reviewedDescriptor = descriptor ? { ...descriptor, access } : null;
  const expectedDescriptor = {
    kind: "builtin-export",
    sourceKey: expected.sourceKey,
    exportName: expected.exportName,
    exportIdioms: expected.exportIdioms,
    moduleSpecifiers: expected.moduleSpecifiers,
    sourceRef: expected.sourceRef,
    valueShape: expected.valueShape,
    access,
  };
  if (
    !reviewedDescriptor ||
    canonicalJson(reviewedDescriptor) !== canonicalJson(expectedDescriptor)
  ) {
    return null;
  }
  return {
    ...reviewedDescriptor,
    expectedValueType: expected.expectedValueType,
  };
}

function reviewedDnsPromiseErrorCodeSourceDescriptor(surface, target) {
  const descriptor = sourceDescriptor(surface, target, new Set(["unknown"]));
  if (
    !descriptor ||
    descriptor.sourceKey !== "node_dns_promises" ||
    !REVIEWED_DNS_PROMISE_ERROR_CODES.has(descriptor.exportName) ||
    canonicalJson(descriptor.exportIdioms) !==
      canonicalJson(["member-assignment"]) ||
    canonicalJson(descriptor.moduleSpecifiers) !==
      canonicalJson(["dns/promises", "node:dns/promises"]) ||
    descriptor.sourceRef !==
      `src/builtins/dns-promises.js#exports:${descriptor.exportName}` ||
    descriptor.valueShape !== "unknown" ||
    descriptor.access.kind !== "export-property" ||
    canonicalJson(descriptor.access.path) !==
      canonicalJson([descriptor.exportName]) ||
    descriptor.platformAvailability !== undefined
  ) {
    return null;
  }
  return {
    ...descriptor,
    expectedValueType: "string",
  };
}

function reviewedModuleAliasSourceDescriptor(surface, moduleSpecifier) {
  const expected = NONCAP_MODULE_ALIAS_SOURCES.get(moduleSpecifier);
  const metadata = surface?.metadata;
  if (
    !expected ||
    surface?.kind !== "builtin" ||
    surface.name !== moduleSpecifier ||
    surface.observedKey !== `builtin:${moduleSpecifier}` ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1 ||
    surface.sourceRefs[0] !==
      `modules.ts#specifiers:${expected.sourceKey}` ||
    canonicalJson(metadata) !==
      canonicalJson({
        sourceKey: expected.sourceKey,
        bundleExternal: expected.bundleExternal,
        importReachability: "public",
        moduleBuiltin: expected.moduleBuiltin,
      })
  ) {
    return null;
  }
  return {
    kind: "builtin-module-alias",
    moduleSpecifier,
    sourceKey: expected.sourceKey,
    sourceRef: surface.sourceRefs[0],
    sourceMetadata: structuredClone(metadata),
    expectedRootType: expected.expectedRootType,
  };
}

function authoredNonCapabilityBuiltinInvocationDefinition({
  surface,
  target,
  allowTargetAbsence = false,
}) {
  const availability = platformAvailability(surface?.metadata);
  const targetPlatform = platformForTarget(target);
  const targetAbsent =
    Array.isArray(availability) &&
    targetPlatform !== null &&
    !availability.includes(targetPlatform);
  const reviewedPrototypeDescriptor =
    reviewedPrototypeValueSourceDescriptor(surface, target);
  const reviewedStreamInstanceDescriptor =
    reviewedStreamInstanceValueSourceDescriptor(surface, target);
  const reviewedX509InstanceDescriptor =
    reviewedX509InstanceValueSourceDescriptor(surface, target);
  const reviewedTlsSecureContextInstanceDescriptor =
    reviewedTlsSecureContextInstanceValueSourceDescriptor(surface, target);
  const reviewedDgramSocketInstanceDescriptor =
    reviewedDgramSocketInstanceValueSourceDescriptor(surface, target);
  const readDescriptor =
    reviewedPostInitializationValueSourceDescriptor(surface, target) ??
    reviewedPrototypeDescriptor ??
    reviewedStreamInstanceDescriptor ??
    reviewedX509InstanceDescriptor ??
    reviewedTlsSecureContextInstanceDescriptor ??
    reviewedDgramSocketInstanceDescriptor ??
    reviewedDnsPromiseErrorCodeSourceDescriptor(surface, target) ??
    sourceDescriptor(surface, target, new Set(["accessor", "data"]), {
      allowTargetAbsence: allowTargetAbsence && targetAbsent,
    });
  if (isDeprecatedFsConstantAccessorDescriptor(readDescriptor)) return null;
  const readEligible =
    readDescriptor &&
    (readDescriptor === reviewedPrototypeDescriptor ||
      readDescriptor === reviewedStreamInstanceDescriptor ||
      readDescriptor === reviewedX509InstanceDescriptor ||
      readDescriptor === reviewedTlsSecureContextInstanceDescriptor ||
      readDescriptor === reviewedDgramSocketInstanceDescriptor ||
      (new Set(["export-property", "module-value"]).has(
        readDescriptor.access.kind,
      ) &&
        (readDescriptor.valueShape !== "accessor" ||
          readDescriptor.access.kind === "export-property")));
  const callDescriptor = readEligible
    ? null
    : sourceDescriptor(surface, target, new Set(["callable"]), {
        allowReviewedIdleHttpCall: true,
      });
  const callTemplate = callDescriptor ? callTemplateFor(callDescriptor) : null;
  const descriptor = readEligible ? readDescriptor : callDescriptor;
  if (!descriptor || (!readEligible && !callTemplate)) return null;
  const moduleSpecifier = canonicalModuleSpecifier(descriptor.moduleSpecifiers);
  const invocation = {
    invocationSchema: readEligible
      ? READ_INVOCATION_SCHEMA
      : CALL_INVOCATION_SCHEMA,
    kind: readEligible ? "builtin-export-read" : "builtin-export-call",
    moduleSpecifier,
    exportName: descriptor.exportName,
    sourceDescriptor: descriptor,
    sourceDescriptorDigest: taggedDigest(descriptor),
    ...(!readEligible ? { templateId: callTemplate.templateId } : {}),
    arguments: readEligible ? [] : callTemplate.arguments,
    setup: readEligible
      ? reviewedStreamInstanceDescriptor
        ? {
            kind: "stream-owner",
            ownerExportName:
              reviewedStreamInstanceDescriptor.exportName.split(".")[0],
            endedInput: false,
          }
        : reviewedX509InstanceDescriptor
          ? {
              kind: "constructed-owner",
              ownerExportName: "X509Certificate",
              constructorArguments: [
                { kind: "json", value: "ibex-x509-fixture" },
              ],
            }
          : reviewedTlsSecureContextInstanceDescriptor
            ? {
                kind: "constructed-owner",
                ownerExportName: "SecureContext",
                constructorArguments: [],
              }
            : reviewedDgramSocketInstanceDescriptor
              ? {
                  kind: "constructed-owner",
                  ownerExportName: "Socket",
                  constructorArguments: [
                    { kind: "json", value: "udp4" },
                  ],
                }
            : { kind: "none" }
      : callTemplate.setup,
    completion: { ...EVENT_LOOP_COMPLETION },
  };
  return {
    invocation,
    bodyEntryProof: readEligible ? null : callTemplate.bodyEntryProof,
    expectedResult: targetAbsent
      ? "absent"
      : readEligible
        ? "return"
        : "normal-return",
  };
}

/**
 * Return only the source-authored operation recipe needed to execute a public
 * non-capability builtin output. Conformance expectations and reviewed output
 * dispositions are deliberately absent so output-shape plans cannot echo
 * either policy into the loaded-engine executor.
 */
export function authoredNonCapabilityBuiltinOutputInvocation({
  surface,
  target,
}) {
  const definition = authoredNonCapabilityBuiltinInvocationDefinition({
    surface,
    target,
  });
  return definition ? structuredClone(definition.invocation) : null;
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
  if (
    !surfaceObservedKey.startsWith("builtin:export:") &&
    surfaceObservedKey.startsWith("builtin:") &&
    canonicalJson(alternative.proofPaths) ===
      canonicalJson([surfaceObservedKey]) &&
    Array.isArray(plan.edgeIds) &&
    plan.edgeIds.length === 1 &&
    typeof plan.edgeIds[0] === "string" &&
    plan.edgeIds[0].length > 0
  ) {
    const moduleSpecifier = surfaceObservedKey.slice("builtin:".length);
    const descriptor = reviewedModuleAliasSourceDescriptor(
      surface,
      moduleSpecifier,
    );
    if (!descriptor) return null;
    descriptor.carrierEdgeId = plan.edgeIds[0];
    return {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: [...BUILTIN_BATCH_COMMAND],
      invocation: {
        invocationSchema: MODULE_IMPORT_NO_EFFECT_INVOCATION_SCHEMA,
        kind: "builtin-module-import",
        moduleSpecifier,
        sourceDescriptor: descriptor,
        sourceDescriptorDigest: taggedDigest(descriptor),
        arguments: [],
        setup: { kind: "none" },
        completion: { ...EVENT_LOOP_COMPLETION },
        requiredAuthority: [],
        expectedResult: "return",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    };
  }
  if (!surfaceObservedKey.startsWith("builtin:export:")) {
    return null;
  }
  const definition = authoredNonCapabilityBuiltinInvocationDefinition({
    surface,
    target,
    allowTargetAbsence: true,
  });
  if (!definition) return null;
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...BUILTIN_BATCH_COMMAND],
    invocation: {
      ...structuredClone(definition.invocation),
      ...(definition.bodyEntryProof
        ? { bodyEntryProof: structuredClone(definition.bodyEntryProof) }
        : {}),
      requiredAuthority: [],
      expectedResult: definition.expectedResult,
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
  const readDescriptor = sourceDescriptor(
    surface,
    target,
    new Set(["accessor"]),
  );
  if (isDeprecatedFsConstantAccessorDescriptor(readDescriptor)) {
    return "builtin-export-requires-deprecation-warning";
  }
  const targetUnavailableReason = targetUnavailablePublicExportReason(
    surface,
    target,
  );
  if (targetUnavailableReason) {
    return targetUnavailableReason;
  }
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
