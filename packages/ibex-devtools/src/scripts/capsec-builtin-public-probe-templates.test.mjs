import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import {
  authoredNonCapabilityBuiltinProbe,
  authoredNonCapabilityBuiltinOutputInvocation,
  nonCapabilityBuiltinProbeResidualReason,
} from "./capsec-builtin-public-probe-templates.mjs";

const plan = {
  classification: "non-capability",
  actionIds: [],
};
const REVIEWED_DNS_PROMISE_ERROR_CODES = [
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
];
const REVIEWED_POST_INITIALIZATION_VALUES = [
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
];
const REVIEWED_PROTOTYPE_VALUES = [
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
];
const REVIEWED_STREAM_INSTANCE_VALUES = [
  ["node_stream", "default.closed", "unknown", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:default.closed"],
  ["node_stream", "Duplex.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Duplex.closed"],
  ["node_stream", "PassThrough.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:PassThrough.closed"],
  ["node_stream", "Readable.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Readable.closed"],
  ["node_stream", "Stream.closed", "unknown", "boolean", ["exported-constructor-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Stream.closed"],
  ["node_stream", "Transform.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Transform.closed"],
  ["node_stream", "Writable.closed", "unknown", "boolean", ["exported-constructor-inherited-prototype"], ["node:stream", "stream"], "src/builtins/stream.js#exports:Writable.closed"],
];
const REVIEWED_MODULE_IMPORTS = [
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
];
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const builtinInvocationHarness = new Function(
  "require",
  `return ${fs.readFileSync(
    path.join(
      __dirname,
      "../../../../src/bin/ibex/engine/capsec_public_noncap_builtin_invocation.js",
    ),
    "utf8",
  )};`,
)(createRequire(import.meta.url));

function probeFor({
  constructorInstanceProjection,
  crossSourceExportProjection,
  sourceKey = "node_constants",
  exportName = "ENOENT",
  exportIdioms = ["object-binding", "object-source"],
  importReachability = "public",
  moduleSpecifiers = ["constants", "node:constants"],
  publicModuleSpecifiers = moduleSpecifiers,
  sourceRefs = [`src/builtins/${sourceKey}.js#exports:${exportName}`],
  platformAvailability,
  target = "aarch64-apple-darwin",
  valueShape = "data",
} = {}) {
  const observedKey = `builtin:export:${sourceKey}:${exportName}`;
  return authoredNonCapabilityBuiltinProbe({
    plan,
    scenario: "non-capability",
    target,
    route: {
      surfaceObservedKeys: [observedKey],
      alternatives: [
        { terminalObservedKey: observedKey, proofPaths: [observedKey] },
      ],
      ambiguousCallees: [],
    },
    liveByObservedKey: new Map([
      [
        observedKey,
        {
          observedKey,
          sourceRefs,
          metadata: {
            sourceKey,
            ...(crossSourceExportProjection === undefined
              ? {}
              : { crossSourceExportProjection }),
            ...(constructorInstanceProjection === undefined
              ? {}
              : { constructorInstanceProjection }),
            exportName,
            exportIdioms,
            importReachability,
            moduleSpecifiers,
            publicModuleSpecifiers,
            platformAvailability,
            surfaceType: "export",
            valueShape,
          },
        },
      ],
    ]),
  });
}

describe("source-bound builtin public probes", () => {
  test("keeps cross-source export projections residual even with one source ref", () => {
    const input = {
      sourceKey: "node_dns_promises",
      exportName: "getDefaultResultOrder",
      exportIdioms: ["cross-source-required-member-object-property"],
      moduleSpecifiers: ["dns/promises", "node:dns/promises"],
      valueShape: "data",
    };
    expect(probeFor(input)).not.toBeNull();
    expect(
      probeFor({
        ...input,
        crossSourceExportProjection: {
          carrierSourceKey: "node_dns_promises",
          kind: "immutable-commonjs-member-object",
          providerSourceKey: "node_dns",
        },
      }),
    ).toBeNull();
  });

  test("reads only the exact reviewed dns/promises error-code strings", () => {
    for (const exportName of REVIEWED_DNS_PROMISE_ERROR_CODES) {
      const probe = probeFor({
        sourceKey: "node_dns_promises",
        exportName,
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["dns/promises", "node:dns/promises"],
        sourceRefs: [
          `src/builtins/dns-promises.js#exports:${exportName}`,
        ],
        valueShape: "unknown",
      });
      expect(probe).toMatchObject({
        kind: "public-surface-invocation",
        surfaceObservedKey: `builtin:export:node_dns_promises:${exportName}`,
        invocation: {
          invocationSchema: "ibex/capsec-builtin-export-invocation/1",
          kind: "builtin-export-read",
          moduleSpecifier: "node:dns/promises",
          exportName,
          sourceDescriptor: {
            kind: "builtin-export",
            sourceKey: "node_dns_promises",
            exportName,
            exportIdioms: ["member-assignment"],
            moduleSpecifiers: ["dns/promises", "node:dns/promises"],
            sourceRef: `src/builtins/dns-promises.js#exports:${exportName}`,
            valueShape: "unknown",
            access: { kind: "export-property", path: [exportName] },
            expectedValueType: "string",
          },
          arguments: [],
          setup: { kind: "none" },
          expectedResult: "return",
        },
      });
    }

    const nearMiss = {
      sourceKey: "node_dns_promises",
      exportName: "getDefaultResultOrder",
      exportIdioms: ["member-assignment"],
      moduleSpecifiers: ["dns/promises", "node:dns/promises"],
      sourceRefs: [
        "src/builtins/dns-promises.js#exports:getDefaultResultOrder",
      ],
      valueShape: "unknown",
    };
    expect(probeFor(nearMiss)).toBeNull();
    expect(
      probeFor({
        ...nearMiss,
        exportName: "NODATA",
        sourceRefs: ["src/builtins/dns-promises.js#exports:NODATA"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        ...nearMiss,
        exportName: "NODATA",
        sourceRefs: ["src/builtins/dns.js#exports:NODATA"],
      }),
    ).toBeNull();
  });

  test("reads only exact values after reviewed module initialization", () => {
    for (const [
      sourceKey,
      exportName,
      valueShape,
      expectedValueType,
      exportIdioms,
      moduleSpecifiers,
      sourceRef,
    ] of REVIEWED_POST_INITIALIZATION_VALUES) {
      expect(
        probeFor({
          sourceKey,
          exportName,
          exportIdioms,
          moduleSpecifiers,
          sourceRefs: [sourceRef],
          valueShape,
        }),
      ).toMatchObject({
        invocation: {
          kind: "builtin-export-read",
          exportName,
          sourceDescriptor: {
            sourceKey,
            exportName,
            exportIdioms,
            moduleSpecifiers,
            sourceRef,
            valueShape,
            access: {
              kind:
                exportName === "default"
                  ? "module-value"
                  : "export-property",
              path: exportName === "default" ? [] : [exportName],
            },
            expectedValueType,
          },
          expectedResult: "return",
        },
      });
    }

    for (const mutation of [
      { exportName: "schedulingPolicy" },
      { valueShape: "callable" },
      { sourceRefs: ["src/builtins/os.js#exports:SCHED_NONE"] },
      { moduleSpecifiers: ["node:cluster"] },
    ]) {
      expect(
        probeFor({
          sourceKey: "node_cluster",
          exportName: "SCHED_NONE",
          exportIdioms: ["member-assignment"],
          moduleSpecifiers: ["cluster", "node:cluster"],
          sourceRefs: ["src/builtins/cluster.js#exports:SCHED_NONE"],
          valueShape: "data",
          ...mutation,
        }),
      ).toBeNull();
    }
  });

  test("reads only the exact reviewed inert prototype values", () => {
    for (const [
      sourceKey,
      exportName,
      valueShape,
      expectedValueType,
      exportIdioms,
      moduleSpecifiers,
      sourceRef,
    ] of REVIEWED_PROTOTYPE_VALUES) {
      const segments = exportName.split(".");
      const inherited = exportIdioms.includes(
        "exported-constructor-inherited-prototype",
      );
      const expectedPath =
        sourceKey === "node_stream" && exportName === "default.destroyed"
          ? ["prototype", "destroyed"]
          : [segments[0], "prototype", ...segments.slice(1)];
      expect(
        probeFor({
          sourceKey,
          exportName,
          exportIdioms,
          moduleSpecifiers,
          sourceRefs: [sourceRef],
          valueShape,
        }),
      ).toMatchObject({
        invocation: {
          kind: "builtin-export-read",
          exportName,
          sourceDescriptor: {
            sourceKey,
            exportName,
            exportIdioms,
            moduleSpecifiers,
            sourceRef,
            valueShape,
            access: {
              kind: inherited
                ? "inherited-prototype-property"
                : "prototype-property",
              path: expectedPath,
            },
            expectedValueType,
          },
          expectedResult: "return",
        },
      });
    }

    for (const input of [
      {
        sourceKey: "node_fs",
        exportName: "Dir.path",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["bun:fs", "fs", "node:fs"],
        sourceRefs: ["src/builtins/fs.js#exports:Dir.path"],
        valueShape: "accessor",
      },
    ]) {
      expect(probeFor(input)).toBeNull();
    }
  });

  test("reads raw bytes only from a fresh owned X509Certificate", () => {
    const probe = probeFor({
      sourceKey: "exact_crypto",
      exportName: "X509Certificate.raw",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
      sourceRefs: [
        "src/builtins/crypto.js#exports:X509Certificate.raw",
      ],
      valueShape: "accessor",
    });
    expect(probe).toMatchObject({
      invocation: {
        kind: "builtin-export-read",
        exportName: "X509Certificate.raw",
        sourceDescriptor: {
          sourceKey: "exact_crypto",
          access: {
            kind: "constructed-instance-property",
            path: ["raw"],
          },
          expectedValueType: "object",
        },
        setup: {
          kind: "constructed-owner",
          ownerExportName: "X509Certificate",
          constructorArguments: [
            { kind: "json", value: "ibex-x509-fixture" },
          ],
        },
        expectedResult: "return",
      },
    });
  });

  test("reads only the opaque context from a fresh owned SecureContext", () => {
    const probe = probeFor({
      sourceKey: "node_tls",
      exportName: "SecureContext.context",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:tls", "tls"],
      sourceRefs: [
        "src/builtins/tls.js#exports:SecureContext.context",
      ],
      valueShape: "unknown",
    });
    expect(probe).toMatchObject({
      invocation: {
        kind: "builtin-export-read",
        exportName: "SecureContext.context",
        sourceDescriptor: {
          sourceKey: "node_tls",
          access: {
            kind: "constructed-instance-property",
            path: ["context"],
          },
          expectedValueType: "object",
        },
        setup: {
          kind: "constructed-owner",
          ownerExportName: "SecureContext",
          constructorArguments: [],
        },
        expectedResult: "return",
      },
    });
  });

  test("reads only the owner-checked close bit from a fresh UDP socket", () => {
    const probe = probeFor({
      sourceKey: "node_dgram",
      exportName: "Socket._closed",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["dgram", "node:dgram"],
      sourceRefs: ["src/builtins/dgram.js#exports:Socket._closed"],
      valueShape: "unknown",
    });
    expect(probe).toMatchObject({
      invocation: {
        kind: "builtin-export-read",
        exportName: "Socket._closed",
        sourceDescriptor: {
          sourceKey: "node_dgram",
          access: {
            kind: "constructed-instance-property",
            path: ["_closed"],
          },
          expectedValueType: "boolean",
        },
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Socket",
          constructorArguments: [{ kind: "json", value: "udp4" }],
        },
        expectedResult: "return",
      },
    });
  });

  test("reads only reviewed closed booleans on fresh stream instances", () => {
    for (const [
      sourceKey,
      exportName,
      valueShape,
      expectedValueType,
      exportIdioms,
      moduleSpecifiers,
      sourceRef,
    ] of REVIEWED_STREAM_INSTANCE_VALUES) {
      const ownerExportName = exportName.split(".")[0];
      const probe = probeFor({
        sourceKey,
        exportName,
        exportIdioms,
        moduleSpecifiers,
        sourceRefs: [sourceRef],
        valueShape,
      });
      expect(probe).toMatchObject({
        invocation: {
          kind: "builtin-export-read",
          exportName,
          sourceDescriptor: {
            sourceKey,
            exportName,
            exportIdioms,
            moduleSpecifiers,
            sourceRef,
            valueShape,
            access: {
              kind: "constructed-instance-property",
              path: ["closed"],
            },
            expectedValueType,
          },
          setup: {
            kind: "stream-owner",
            ownerExportName,
            endedInput: false,
          },
          expectedResult: "return",
        },
      });
    }

    for (const exportName of [
      "Readable.readableState",
      "Writable.writableState",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_stream",
          exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["node:stream", "stream"],
          sourceRefs: [`src/builtins/stream.js#exports:${exportName}`],
          valueShape: "unknown",
        }),
      ).toBeNull();
    }
  });

  test("keeps constructor-instance projections residual even with one source ref", () => {
    const input = {};
    expect(probeFor(input)).not.toBeNull();
    expect(
      probeFor({
        ...input,
        constructorInstanceProjection: {
          constructorExport: "Resolver",
          instancePath: "_handle.cancel",
          kind: "constructor-installed-nested-object",
        },
      }),
    ).toBeNull();
  });

  test("rejects incomplete, bootstrap-owned, and source-shadowed aliases", () => {
    for (const [moduleSpecifier, sourceKey, importReachability] of [
      ["node:path", "node_path", "public"],
      ["internal/fs/utils", "internal_fs_utils", "bootstrap-internal"],
      ["buffer", "node_buffer", "public"],
      ["bun:sqlite", "exact_sqlite", "public"],
      ["stream/consumers", "node_stream_consumers", "bootstrap-internal"],
      [
        "node:stream/consumers",
        "node_stream_consumers",
        "bootstrap-internal",
      ],
    ]) {
      const observedKey = `builtin:${moduleSpecifier}`;
      expect(
        authoredNonCapabilityBuiltinProbe({
          plan,
          scenario: "non-capability",
          route: {
            surfaceObservedKeys: [observedKey],
            alternatives: [
              { terminalObservedKey: observedKey, proofPaths: [observedKey] },
            ],
            ambiguousCallees: [],
          },
          liveByObservedKey: new Map([
            [
              observedKey,
              {
                kind: "builtin",
                name: moduleSpecifier,
                observedKey,
                sourceRefs: [`modules.ts#specifiers:${sourceKey}`],
                metadata: { importReachability, sourceKey },
              },
            ],
          ]),
        }),
      ).toBeNull();
    }
  });

  test("authors fresh-engine zero-decision probes for the exact reviewed aliases", () => {
    expect(REVIEWED_MODULE_IMPORTS).toHaveLength(34);
    for (const [
      moduleSpecifier,
      sourceKey,
      moduleBuiltin,
      expectedRootType,
    ] of REVIEWED_MODULE_IMPORTS) {
      const edgeId = `edge.${moduleSpecifier}`;
      const observedKey = `builtin:${moduleSpecifier}`;
      const probe = authoredNonCapabilityBuiltinProbe({
        plan: { ...plan, edgeIds: [edgeId] },
        scenario: "non-capability",
        route: {
          surfaceObservedKeys: [observedKey],
          alternatives: [
            { terminalObservedKey: observedKey, proofPaths: [observedKey] },
          ],
          ambiguousCallees: [],
        },
        liveByObservedKey: new Map([
          [
            observedKey,
            {
              kind: "builtin",
              name: moduleSpecifier,
              observedKey,
              sourceRefs: [`modules.ts#specifiers:${sourceKey}`],
              metadata: {
                sourceKey,
                bundleExternal: true,
                importReachability: "public",
                moduleBuiltin,
              },
            },
          ],
        ]),
      });
      expect(probe).toMatchObject({
        kind: "public-surface-invocation",
        surfaceObservedKey: observedKey,
        invocation: {
          invocationSchema:
            "ibex/capsec-builtin-module-import-no-effect-invocation/1",
          kind: "builtin-module-import",
          moduleSpecifier,
          arguments: [],
          setup: { kind: "none" },
          completion: {
            kind: "event-loop-quiescence",
            timeoutMilliseconds: 1_000,
          },
          requiredAuthority: [],
          expectedResult: "return",
          expectedTypedDecisionCount: 0,
          expectedTypedStages: [],
          allowedCoverageEdgeIds: [],
          expectedActionIds: [],
          sourceDescriptor: {
            kind: "builtin-module-alias",
            moduleSpecifier,
            sourceKey,
            sourceRef: `modules.ts#specifiers:${sourceKey}`,
            sourceMetadata: {
              sourceKey,
              bundleExternal: true,
              importReachability: "public",
              moduleBuiltin,
            },
            expectedRootType,
            carrierEdgeId: edgeId,
          },
        },
      });
      expect(probe.invocation).not.toHaveProperty("exportName");
    }
  });

  test("rejects near-miss reviewed import carriers and export-call conflation", () => {
    const invoke = ({
      moduleSpecifier = "node:dns",
      sourceKey = "node_dns",
      sourceRef = `modules.ts#specifiers:${sourceKey}`,
      metadata = {
        sourceKey,
        bundleExternal: true,
        importReachability: "public",
        moduleBuiltin: true,
      },
      proofPaths,
    } = {}) => {
      const observedKey = `builtin:${moduleSpecifier}`;
      return authoredNonCapabilityBuiltinProbe({
        plan: { ...plan, edgeIds: ["edge.node-dns"] },
        scenario: "non-capability",
        route: {
          surfaceObservedKeys: [observedKey],
          alternatives: [
            {
              terminalObservedKey: observedKey,
              proofPaths: proofPaths ?? [observedKey],
            },
          ],
          ambiguousCallees: [],
        },
        liveByObservedKey: new Map([
          [
            observedKey,
            {
              kind: "builtin",
              name: moduleSpecifier,
              observedKey,
              sourceRefs: [sourceRef],
              metadata,
            },
          ],
        ]),
      });
    };

    expect(
      invoke({
        moduleSpecifier: "node:stream/consumers",
        sourceKey: "node_stream_consumers",
      }),
    ).toBeNull();
    expect(invoke({ sourceKey: "node_dns_promises" })).toBeNull();
    expect(invoke({ sourceRef: "src/builtins/dns.js#exports:getServers" })).toBeNull();
    expect(
      invoke({
        metadata: {
          sourceKey: "node_dns",
          bundleExternal: true,
          importReachability: "public",
          moduleBuiltin: true,
          exportName: "getServers",
        },
      }),
    ).toBeNull();
    expect(
      invoke({
        proofPaths: [
          "builtin:node:dns",
          "builtin:export:node_dns:getServers",
        ],
      }),
    ).toBeNull();
  });

  test("reads an own export through the canonical public alias", () => {
    const probe = probeFor();
    expect(probe).toMatchObject({
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_constants:ENOENT",
      invocation: {
        kind: "builtin-export-read",
        moduleSpecifier: "node:constants",
        exportName: "ENOENT",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        sourceDescriptor: {
          access: { kind: "export-property", path: ["ENOENT"] },
          valueShape: "data",
        },
      },
    });
  });

  test("triggers source-proven root accessors", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Z_OK",
        exportIdioms: ["define-property"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "accessor",
      }).invocation.sourceDescriptor,
    ).toEqual({
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Z_OK",
      exportIdioms: ["define-property"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/node_zlib.js#exports:Z_OK",
      valueShape: "accessor",
      access: { kind: "export-property", path: ["Z_OK"] },
    });
  });

  test("calls only source-authored root functions with bounded arguments", () => {
    expect(
      probeFor({
        sourceKey: "node_path",
        exportName: "basename",
        moduleSpecifiers: ["node:path", "path"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        invocationSchema: "ibex/capsec-builtin-call-invocation/1",
        kind: "builtin-export-call",
        templateId: "node-path-pure-v1",
        arguments: [{ kind: "json", value: "/ibex/file.txt" }],
        setup: { kind: "root-call" },
        bodyEntryProof: {
          kind: "normal-return-from-source-call",
          resultType: "string",
        },
        completion: {
          kind: "event-loop-quiescence",
          timeoutMilliseconds: 1_000,
        },
        expectedResult: "normal-return",
      },
    });
  });

  test("constructs zero-effect node:fs values and their pure predicates", () => {
    expect(
      probeFor({
        sourceKey: "node_fs",
        exportName: "_toUnixTimestamp",
        moduleSpecifiers: ["fs", "node:fs"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-fs-pure-v1",
        arguments: [{ kind: "json", value: 1 }],
        setup: { kind: "root-call" },
        bodyEntryProof: { resultType: "number" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_fs",
        exportName: "Stats",
        moduleSpecifiers: ["fs", "node:fs"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-fs-pure-v1",
        arguments: [
          { kind: "json", value: { is_file: true } },
          { kind: "json", value: false },
        ],
        setup: { kind: "construct-target" },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_fs",
        exportName: "Dirent.isFile",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["fs", "node:fs"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-fs-pure-v1",
        arguments: [],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Dirent",
          constructorArguments: [
            { kind: "json", value: "entry.txt" },
            { kind: "json", value: 1 },
          ],
        },
        bodyEntryProof: { resultType: "boolean" },
      },
    });
  });

  test("exports expectation-free output invocations from the same authored recipes", () => {
    const invocation = authoredNonCapabilityBuiltinOutputInvocation({
      target: "aarch64-apple-darwin",
      surface: {
        observedKey: "builtin:export:node_path:basename",
        sourceRefs: ["src/builtins/path.js#exports:basename"],
        metadata: {
          sourceKey: "node_path",
          exportName: "basename",
          exportIdioms: ["object-binding", "object-source"],
          importReachability: "public",
          moduleSpecifiers: ["node:path", "path"],
          publicModuleSpecifiers: ["node:path", "path"],
          surfaceType: "export",
          valueShape: "callable",
        },
      },
    });
    expect(invocation).toMatchObject({
      invocationSchema: "ibex/capsec-builtin-call-invocation/1",
      kind: "builtin-export-call",
      moduleSpecifier: "node:path",
      exportName: "basename",
      templateId: "node-path-pure-v1",
      arguments: [{ kind: "json", value: "/ibex/file.txt" }],
      setup: { kind: "root-call" },
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      },
    });
    expect(Object.keys(invocation).sort()).toEqual([
      "arguments",
      "completion",
      "exportName",
      "invocationSchema",
      "kind",
      "moduleSpecifier",
      "setup",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "templateId",
    ]);
    expect(JSON.stringify(invocation)).not.toContain("expectedResult");
    expect(JSON.stringify(invocation)).not.toContain("bodyEntryProof");

    const returned = builtinInvocationHarness({
      ...invocation,
      captureRawOutput: true,
    });
    expect(returned).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      bodyEntryProof: "normal-return-from-source-call",
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value: "file.txt",
        errorCode: null,
      },
    });

    const thrown = builtinInvocationHarness({
      ...invocation,
      arguments: [{ kind: "json", value: {} }],
      captureRawOutput: true,
    });
    expect(thrown).toMatchObject({
      kind: "throw",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "throw",
        rawValueShape: "throw",
        value: null,
        errorCode: "ERR_INVALID_ARG_TYPE",
      },
    });
  });

  test("constructs explicit receivers for authored prototype methods", () => {
    expect(
      probeFor({
        sourceKey: "node_buffer",
        exportName: "Buffer.readUInt32LE",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["buffer", "node:buffer"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-buffer-bounded-v1",
        arguments: [{ kind: "json", value: 0 }],
        setup: {
          kind: "buffer-owner",
          ownerExportName: "Buffer",
          bytes: [0, 1, 2, 3, 4, 5, 6, 7],
        },
        sourceDescriptor: {
          access: {
            kind: "prototype-property",
            path: ["Buffer", "prototype", "readUInt32LE"],
          },
        },
        bodyEntryProof: { resultType: "number" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_buffer",
        exportName: "SlowBuffer.writeBigUint64BE",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["buffer", "node:buffer"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        arguments: [
          { kind: "bigint", value: "1" },
          { kind: "json", value: 0 },
        ],
        setup: {
          kind: "buffer-owner",
          ownerExportName: "SlowBuffer",
        },
        bodyEntryProof: { resultType: "number" },
      },
    });
  });

  test("authors bounded zlib setup and isolated sync codecs", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "createGzip",
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-zlib-bounded-v1",
        arguments: [],
        setup: { kind: "root-call" },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Gunzip._ensureNativeStream",
        exportIdioms: ["exported-constructor-inherited-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        arguments: [],
        setup: {
          kind: "zlib-owner",
          ownerExportName: "Gunzip",
          ensureNativeStream: false,
        },
        sourceDescriptor: {
          access: { kind: "inherited-prototype-property" },
        },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "Gzip.destroy",
        exportIdioms: ["exported-constructor-inherited-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        arguments: [],
        setup: {
          kind: "zlib-owner",
          ownerExportName: "Gzip",
          ensureNativeStream: false,
        },
        bodyEntryProof: { resultType: "object" },
      },
    });
    for (const exportName of [
      "brotliCompressSync",
      "deflateRawSync",
      "deflateSync",
      "gzipSync",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName,
          exportIdioms: ["object-binding", "object-source"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [
            { kind: "buffer", bytes: [105, 98, 101, 120] },
          ],
          setup: { kind: "root-call" },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    for (const [exportName, bytes] of [
      [
        "brotliDecompressSync",
        [139, 1, 128, 105, 98, 101, 120, 3],
      ],
      [
        "gunzipSync",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
      ],
      ["inflateRawSync", [203, 76, 74, 173, 0, 0]],
      ["inflateSync", [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169]],
      [
        "unzipSync",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
      ],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName,
          exportIdioms: ["object-binding", "object-source"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [{ kind: "buffer", bytes }],
          setup: { kind: "root-call" },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    for (const [exportName, bytes, resultContract] of [
      ["brotliCompress", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "brotliDecompress",
        [139, 1, 128, 105, 98, 101, 120, 3],
        "exact-ibex-byte-view",
      ],
      ["deflate", [105, 98, 101, 120], "nonempty-byte-view"],
      ["deflateRaw", [105, 98, 101, 120], "nonempty-byte-view"],
      ["gzip", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "gunzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
      [
        "inflate",
        [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
        "exact-ibex-byte-view",
      ],
      ["inflateRaw", [203, 76, 74, 173, 0, 0], "exact-ibex-byte-view"],
      [
        "unzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName,
          exportIdioms: ["object-binding", "object-source"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [
            { kind: "buffer", bytes },
            { kind: "zlib-callback", resultContract },
          ],
          setup: { kind: "root-call" },
          bodyEntryProof: { resultType: "undefined" },
        },
      });
    }
    for (const [ownerExportName, bytes, outputContract] of [
      ["BrotliCompress", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "BrotliDecompress",
        [139, 1, 128, 105, 98, 101, 120, 3],
        "exact-ibex-byte-view",
      ],
      ["Deflate", [105, 98, 101, 120], "nonempty-byte-view"],
      ["DeflateRaw", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "Gunzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
      ["Gzip", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "Inflate",
        [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
        "exact-ibex-byte-view",
      ],
      ["InflateRaw", [203, 76, 74, 173, 0, 0], "exact-ibex-byte-view"],
      [
        "Unzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName: `${ownerExportName}.end`,
          exportIdioms: ["exported-constructor-inherited-prototype"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [{ kind: "buffer", bytes }],
          setup: {
            kind: "zlib-end-owner",
            ownerExportName,
            outputContract,
          },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    for (const ownerExportName of [
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
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName: `${ownerExportName}.flush`,
          exportIdioms: ["exported-constructor-inherited-prototype"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [{ kind: "zlib-flush-callback" }],
          setup: {
            kind: "zlib-flush-owner",
            ownerExportName,
            callbackPosition: "first-argument",
            flushKind: "default-full-flush",
            cleanupMethod: "destroy",
          },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    for (const [ownerExportName, bytes] of [
      ["BrotliCompress", [105, 98, 101, 120]],
      ["BrotliDecompress", [139, 1, 128, 105, 98, 101, 120, 3]],
      ["Deflate", [105, 98, 101, 120]],
      ["DeflateRaw", [105, 98, 101, 120]],
      [
        "Gunzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
      ],
      ["Gzip", [105, 98, 101, 120]],
      ["Inflate", [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169]],
      ["InflateRaw", [203, 76, 74, 173, 0, 0]],
      [
        "Unzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
      ],
      ["ZstdCompress", [105, 98, 101, 120]],
      ["ZstdDecompress", [105, 98, 101, 120]],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName: `${ownerExportName}._transform`,
          exportIdioms: ["exported-constructor-inherited-prototype"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [
            { kind: "buffer", bytes },
            { kind: "json", value: "buffer" },
            { kind: "zlib-transform-callback" },
          ],
          setup: {
            kind: "zlib-transform-owner",
            ownerExportName,
            inputLength: bytes.length,
            cleanupMethod: "destroy",
          },
          bodyEntryProof: { resultType: "undefined" },
        },
      });
    }
    for (const ownerExportName of [
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
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName: `${ownerExportName}.params`,
          exportIdioms: ["exported-constructor-inherited-prototype"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [
            { kind: "json", value: 1 },
            { kind: "json", value: 0 },
            { kind: "zlib-params-callback" },
          ],
          setup: {
            kind: "zlib-params-owner",
            ownerExportName,
            level: 1,
            strategy: 0,
            cleanupMethod: "destroy",
          },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    for (const [ownerExportName, bytes, outputContract] of [
      ["BrotliCompress", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "BrotliDecompress",
        [139, 1, 128, 105, 98, 101, 120, 3],
        "exact-ibex-byte-view",
      ],
      ["Deflate", [105, 98, 101, 120], "nonempty-byte-view"],
      ["DeflateRaw", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "Gunzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
      ["Gzip", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "Inflate",
        [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
        "exact-ibex-byte-view",
      ],
      ["InflateRaw", [203, 76, 74, 173, 0, 0], "exact-ibex-byte-view"],
      [
        "Unzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName: `${ownerExportName}._processChunk`,
          exportIdioms: ["exported-constructor-inherited-prototype"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [
            { kind: "buffer", bytes },
            { kind: "json", value: 4 },
          ],
          setup: {
            kind: "zlib-process-chunk-owner",
            ownerExportName,
            outputContract,
          },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    for (const [ownerExportName, bytes, outputContract] of [
      ["BrotliCompress", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "BrotliDecompress",
        [139, 1, 128, 105, 98, 101, 120, 3],
        "exact-ibex-byte-view",
      ],
      ["Deflate", [105, 98, 101, 120], "nonempty-byte-view"],
      ["DeflateRaw", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "Gunzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
      ["Gzip", [105, 98, 101, 120], "nonempty-byte-view"],
      [
        "Inflate",
        [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
        "exact-ibex-byte-view",
      ],
      ["InflateRaw", [203, 76, 74, 173, 0, 0], "exact-ibex-byte-view"],
      [
        "Unzip",
        [
          31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 203, 76, 74, 173, 0, 0, 55, 30,
          109, 106, 4, 0, 0, 0,
        ],
        "exact-ibex-byte-view",
      ],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName: `${ownerExportName}.write`,
          exportIdioms: ["exported-constructor-inherited-prototype"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          arguments: [
            { kind: "buffer", bytes },
            { kind: "zlib-write-callback" },
          ],
          setup: {
            kind: "zlib-write-owner",
            ownerExportName,
            outputContract,
            terminalMethod: "end",
          },
          bodyEntryProof: { resultType: "boolean" },
        },
      });
    }
    for (const exportName of [
      "zstdDecompress",
      "ZstdCompress._processChunk",
      "ZstdCompress.end",
      "ZstdCompress.write",
      "ZstdDecompress.end",
      "ZstdDecompress._processChunk",
      "ZstdDecompress.write",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_zlib",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-inherited-prototype"]
            : ["object-binding", "object-source"],
          moduleSpecifiers: ["node:zlib", "zlib"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("authors only exact cancellable timer lifecycles", () => {
    const rootContracts = new Map([
      [
        "active",
        [
          { kind: "timer-legacy-root", operation: "active" },
          [{ kind: "setup-value", name: "timerRecord" }],
          "undefined",
        ],
      ],
      [
        "_unrefActive",
        [
          { kind: "timer-legacy-root", operation: "_unrefActive" },
          [{ kind: "setup-value", name: "timerRecord" }],
          "undefined",
        ],
      ],
      [
        "enroll",
        [
          { kind: "timer-legacy-root", operation: "enroll" },
          [
            { kind: "setup-value", name: "timerRecord" },
            { kind: "json", value: 60_000 },
          ],
          "undefined",
        ],
      ],
      [
        "unenroll",
        [
          { kind: "timer-legacy-root", operation: "unenroll" },
          [{ kind: "setup-value", name: "timerRecord" }],
          "undefined",
        ],
      ],
      ...[
        ["clearInterval", "interval"],
        ["clearTimeout", "timeout"],
      ].map(([exportName, timerKind]) => [
        exportName,
        [
          { kind: "timer-clear-root", timerKind },
          [{ kind: "setup-value", name: "timerHandle" }],
          "undefined",
        ],
      ]),
      [
        "setImmediate",
        [
          { kind: "timer-factory-root", timerKind: "immediate" },
          [{ kind: "timer-callback" }],
          "object",
        ],
      ],
      ...[
        ["setInterval", "interval"],
        ["setTimeout", "timeout"],
      ].map(([exportName, timerKind]) => [
        exportName,
        [
          { kind: "timer-factory-root", timerKind },
          [
            { kind: "timer-callback" },
            { kind: "json", value: 60_000 },
          ],
          "object",
        ],
      ]),
    ]);
    for (const [exportName, [setup, arguments_, resultType]] of rootContracts) {
      expect(
        probeFor({
          sourceKey: "node_timers",
          exportName,
          exportIdioms: ["module-exports-object"],
          moduleSpecifiers: ["node:timers", "timers"],
          sourceRefs: [`src/builtins/timers.js#exports:${exportName}`],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-timers-bounded-v1",
          setup,
          arguments: arguments_,
          bodyEntryProof: { resultType },
        },
      });
    }
    for (const [exportName, resultType] of [
      ["Immediate.close", "object"],
      ["Immediate.hasRef", "boolean"],
      ["Immediate.ref", "object"],
      ["Immediate.unref", "object"],
      ["Timeout._scheduleNative", "undefined"],
      ["Timeout.close", "object"],
      ["Timeout.hasRef", "boolean"],
      ["Timeout.ref", "object"],
      ["Timeout.refresh", "object"],
      ["Timeout.unref", "object"],
    ]) {
      const ownerExportName = exportName.split(".")[0];
      expect(
        probeFor({
          sourceKey: "node_timers",
          exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["node:timers", "timers"],
          sourceRefs: [`src/builtins/timers.js#exports:${exportName}`],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-timers-bounded-v1",
          setup: {
            kind: "timer-owner",
            ownerExportName,
            preclosed: exportName === "Timeout._scheduleNative",
          },
          arguments: [],
          bodyEntryProof: { resultType },
        },
      });
    }
    for (const exportName of ["clearImmediate", "Immediate", "Timeout"]) {
      expect(
        probeFor({
          sourceKey: "node_timers",
          exportName,
          exportIdioms: ["module-exports-object"],
          moduleSpecifiers: ["node:timers", "timers"],
          sourceRefs: [`src/builtins/timers.js#exports:${exportName}`],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("authors configured stream receivers and settled consumers while leaving retained sources residual", async () => {
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "Readable.read",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-stream-bounded-v1",
        arguments: [{ kind: "json", value: 0 }],
        setup: {
          kind: "stream-owner",
          ownerExportName: "Readable",
          endedInput: false,
        },
        bodyEntryProof: { resultType: "null" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "compose",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toBeNull();
    for (const exportName of ["pipeline", "Readable.wrap"]) {
      expect(
        probeFor({
          sourceKey: "node_stream",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["member-assignment"],
          moduleSpecifiers: ["node:stream", "stream"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
    const settledProbe = probeFor({
      sourceKey: "node_stream",
      exportName: "Readable.every",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:stream", "stream"],
      valueShape: "callable",
    });
    expect(settledProbe).toMatchObject({
      invocation: {
        arguments: [{ kind: "constant-function", value: true }],
        setup: {
          kind: "stream-owner",
          ownerExportName: "Readable",
          endedInput: true,
        },
        bodyEntryProof: {
          kind: "settled-return-from-source-call",
          resultType: "boolean",
        },
      },
    });
    expect(
      await builtinInvocationHarness(settledProbe.invocation),
    ).toMatchObject({
      kind: "return",
      valueType: "boolean",
      dispatchKind: "prototype-call",
      bodyEntryProof: "settled-return-from-source-call",
    });
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "destroy",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      })?.invocation.arguments,
    ).toEqual([
      {
        kind: "stream-instance",
        ownerExportName: "Readable",
        ended: false,
      },
      { kind: "json", value: null },
    ]);
    const defaultDestroyProbe = probeFor({
      sourceKey: "node_stream",
      exportName: "default.destroy",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:stream", "stream"],
      valueShape: "callable",
    });
    expect(defaultDestroyProbe).toMatchObject({
      invocation: {
        arguments: [],
        sourceDescriptor: {
          access: {
            kind: "prototype-property",
            path: ["prototype", "destroy"],
          },
        },
        setup: {
          kind: "stream-owner",
          ownerExportName: "default",
          endedInput: false,
        },
        bodyEntryProof: { resultType: "object" },
      },
    });
    for (const [exportName, resultType] of [
      ["default._close", "undefined"],
      ["default._emitClose", "undefined"],
      ["default._undestroy", "undefined"],
      ["default.constructor", "object"],
      ["default.destroy", "object"],
      ["default.unpipe", "object"],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_stream",
          exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["node:stream", "stream"],
          valueShape: "callable",
        })?.invocation,
      ).toMatchObject({
        sourceDescriptor: {
          access: {
            kind: "prototype-property",
            path: ["prototype", exportName.split(".").at(-1)],
          },
        },
        bodyEntryProof: { resultType },
      });
    }
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "default.pipe",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_stream",
        exportName: "Writable._write",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:stream", "stream"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors bounded string decoder, URL, and util calls", () => {
    expect(
      probeFor({
        sourceKey: "node_string_decoder",
        exportName: "StringDecoder.write",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:string_decoder", "string_decoder"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-string-decoder-bounded-v1",
        arguments: [{ kind: "buffer", bytes: [0x69, 0x62, 0x65, 0x78] }],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "StringDecoder",
          constructorArguments: [{ kind: "json", value: "utf8" }],
        },
        bodyEntryProof: { resultType: "string" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_url",
        exportName: "resolve",
        exportIdioms: ["module-exports-object"],
        moduleSpecifiers: ["node:url", "url"],
        valueShape: "callable",
      })?.invocation.bodyEntryProof.resultType,
    ).toBe("string");
    expect(
      probeFor({
        sourceKey: "node_util",
        exportName: "parseArgs",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["node:util", "util"],
        valueShape: "callable",
      })?.invocation.arguments,
    ).toEqual([
      {
        kind: "json",
        value: {
          args: ["--probe", "ibex"],
          options: { probe: { type: "string" } },
        },
      },
    ]);
    expect(
      probeFor({
        sourceKey: "node_string_decoder",
        exportName: "default.write",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:string_decoder", "string_decoder"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors bounded performance receivers without retaining observers", () => {
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "Performance.measure",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-perf-hooks-bounded-v1",
        arguments: [
          { kind: "json", value: "ibex-measure" },
          { kind: "json", value: { start: 0, duration: 1 } },
        ],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Performance",
          constructorArguments: [],
        },
        bodyEntryProof: { resultType: "object" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "PerformanceObserver.takeRecords",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      })?.invocation.setup.constructorArguments,
    ).toEqual([{ kind: "noop-function" }]);
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "PerformanceObserver.observe",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_perf_hooks",
        exportName: "PerformanceMeasure",
        exportIdioms: ["module-exports-object"],
        moduleSpecifiers: ["node:perf_hooks", "perf_hooks"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors bounded crypto operations and keeps native crashes residual", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "KeyObject.equals",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        sourceRefs: [
          "src/builtins/crypto.js#exports:KeyObject.equals",
        ],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "exact-crypto-bounded-v1",
        arguments: [{ kind: "setup-value", name: "peer" }],
        setup: {
          kind: "key-object-pair-owner",
          ownerExportName: "KeyObject",
          keyType: "secret",
          bytes: [0x69, 0x62, 0x65, 0x78],
        },
        bodyEntryProof: { resultType: "boolean" },
      },
    });
    for (const exportName of ["createPrivateKey", "createPublicKey"]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          exportIdioms: ["object-binding", "object-source"],
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          sourceRefs: [`src/builtins/crypto.js#exports:${exportName}`],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "exact-crypto-bounded-v1",
          arguments: [{ kind: "json", value: "ibex-key" }],
          setup: { kind: "root-call" },
          bodyEntryProof: { resultType: "object" },
        },
      });
    }
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "X509Certificate.toString",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "exact-crypto-bounded-v1",
        arguments: [],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "X509Certificate",
          constructorArguments: [
            { kind: "json", value: "ibex-x509-fixture" },
          ],
        },
        bodyEntryProof: { resultType: "string" },
      },
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Hash.digest",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "exact-crypto-bounded-v1",
        arguments: [{ kind: "json", value: "hex" }],
        setup: {
          kind: "constructed-owner",
          ownerExportName: "Hash",
          constructorArguments: [{ kind: "json", value: "sha256" }],
        },
        bodyEntryProof: { resultType: "string" },
      },
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Sign.update",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation.setup,
    ).toEqual({
      kind: "constructed-owner",
      ownerExportName: "Sign",
      constructorArguments: [{ kind: "json", value: "sha256" }],
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "DiffieHellmanGroup.getPrime",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation.setup.constructorArguments,
    ).toEqual([{ kind: "json", value: "modp14" }]);
    const explicitDhConstructorArguments = [
      { kind: "uint8-array", bytes: [23] },
      { kind: "json", value: 5 },
    ];
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "DiffieHellman",
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation,
    ).toMatchObject({
      arguments: explicitDhConstructorArguments,
      setup: { kind: "construct-target" },
      bodyEntryProof: { resultType: "object" },
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "createDiffieHellman",
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation,
    ).toMatchObject({
      arguments: explicitDhConstructorArguments,
      setup: { kind: "root-call" },
      bodyEntryProof: { resultType: "object" },
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "DiffieHellman.getPrime",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation,
    ).toMatchObject({
      arguments: [],
      setup: {
        kind: "constructed-owner",
        ownerExportName: "DiffieHellman",
        constructorArguments: explicitDhConstructorArguments,
      },
      bodyEntryProof: { resultType: "object" },
    });
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "DiffieHellman.setPrivateKey",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      })?.invocation,
    ).toMatchObject({
      arguments: [{ kind: "uint8-array", bytes: [3] }],
      setup: {
        kind: "constructed-owner",
        ownerExportName: "DiffieHellman",
        constructorArguments: explicitDhConstructorArguments,
      },
      bodyEntryProof: { resultType: "undefined" },
    });
    for (const exportName of [
      "DiffieHellman.computeSecret",
      "DiffieHellman.generateKeys",
    ]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "privateDecrypt",
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "callable",
      }),
    ).toBeNull();
    for (const exportName of [
      "generateKeySync",
      "generatePrimeSync",
      "hkdfSync",
      "Hmac.digest",
      "pbkdf2Sync",
      "scryptSync",
    ]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["object-binding", "object-source"],
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
    for (const exportName of ["Hash._flush", "Hash.end", "randomUUID"]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["object-binding", "object-source"],
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("binds shared Windows crypto probes but leaves native KDFs residual", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "createHash",
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        target: "x86_64-pc-windows-msvc",
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "exact-crypto-bounded-v1",
      },
    });

    for (const exportName of ["hkdfSync", "pbkdf2Sync", "scryptSync"]) {
      expect(
        probeFor({
          sourceKey: "exact_crypto",
          exportName,
          moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
          target: "x86_64-pc-windows-msvc",
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("does not schedule Brotli calls without the Windows native codec", () => {
    expect(
      probeFor({
        sourceKey: "node_zlib",
        exportName: "BrotliCompress._processChunk",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["node:zlib", "zlib"],
        target: "x86_64-pc-windows-msvc",
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("authors only the exact bounded HTTP family", () => {
    const contracts = [
      [
        "_checkInvalidHeaderChar",
        { kind: "root-call" },
        "boolean",
        [{ kind: "json", value: "ibex" }],
      ],
      [
        "_checkIsHttpToken",
        { kind: "root-call" },
        "boolean",
        [{ kind: "json", value: "x-ibex" }],
      ],
      [
        "Agent.destroy",
        {
          kind: "constructed-owner",
          ownerExportName: "Agent",
          constructorArguments: [],
        },
        "undefined",
      ],
      ["Server", { kind: "construct-target" }, "object"],
      [
        "Server.close",
        {
          kind: "constructed-owner",
          ownerExportName: "Server",
          constructorArguments: [],
        },
        "object",
      ],
      [
        "Server.closeAllConnections",
        {
          kind: "constructed-owner",
          ownerExportName: "Server",
          constructorArguments: [],
        },
        "undefined",
      ],
      [
        "Server.closeIdleConnections",
        {
          kind: "constructed-owner",
          ownerExportName: "Server",
          constructorArguments: [],
        },
        "undefined",
      ],
      ["Server.constructor", { kind: "construct-target" }, "object"],
      [
        "Server.ref",
        {
          kind: "constructed-owner",
          ownerExportName: "Server",
          constructorArguments: [],
        },
        "object",
      ],
      [
        "Server.unref",
        {
          kind: "constructed-owner",
          ownerExportName: "Server",
          constructorArguments: [],
        },
        "object",
      ],
      ["createServer", { kind: "root-call" }, "object"],
      [
        "validateHeaderName",
        { kind: "root-call" },
        "undefined",
        [{ kind: "json", value: "x-ibex" }],
      ],
      [
        "validateHeaderValue",
        { kind: "root-call" },
        "undefined",
        [
          { kind: "json", value: "x-ibex" },
          { kind: "json", value: "ibex" },
        ],
      ],
    ];
    for (const [exportName, setup, resultType, argumentsList = []] of contracts) {
      const prototype = exportName.includes(".");
      expect(
        probeFor({
          sourceKey: "node_http",
          exportName,
          exportIdioms: prototype
            ? ["exported-constructor-prototype"]
            : ["module-exports-object"],
          moduleSpecifiers: [
            "_http_agent",
            "_http_common",
            "_http_incoming",
            "_http_outgoing",
            "_http_server",
            "http",
            "node:http",
          ],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-http-idle-v1",
          arguments: argumentsList,
          setup,
          bodyEntryProof: {
            kind: "normal-return-from-source-call",
            resultType,
          },
        },
      });
    }
    for (const exportName of [
      "Agent.addRequest",
      "ClientRequest.destroy",
      "Server.getConnections",
      "Server.listen",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_http",
          exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["http", "node:http"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("authors only transport-free TLS socket lifecycle calls", () => {
    const contracts = [
      ["TLSSocket", { kind: "construct-target" }],
      [
        "TLSSocket.close",
        {
          kind: "constructed-owner",
          ownerExportName: "TLSSocket",
          constructorArguments: [],
        },
      ],
      [
        "TLSSocket.destroy",
        {
          kind: "constructed-owner",
          ownerExportName: "TLSSocket",
          constructorArguments: [],
        },
      ],
      [
        "TLSSocket.ref",
        {
          kind: "constructed-owner",
          ownerExportName: "TLSSocket",
          constructorArguments: [],
        },
      ],
      [
        "TLSSocket.unref",
        {
          kind: "constructed-owner",
          ownerExportName: "TLSSocket",
          constructorArguments: [],
        },
      ],
    ];
    for (const [exportName, setup] of contracts) {
      const prototype = exportName.includes(".");
      expect(
        probeFor({
          sourceKey: "node_tls",
          exportName,
          exportIdioms: prototype
            ? ["exported-constructor-prototype"]
            : ["module-exports-object"],
          moduleSpecifiers: ["node:tls", "tls"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-tls-pure-v1",
          arguments: [],
          setup,
          bodyEntryProof: {
            kind: "normal-return-from-source-call",
            resultType: "object",
          },
        },
      });
    }
    for (const exportName of [
      "TLSSocket.connect",
      "TLSSocket.end",
      "TLSSocket.write",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_tls",
          exportName,
          exportIdioms: exportName.includes(".")
            ? ["exported-constructor-prototype"]
            : ["module-exports-object"],
          moduleSpecifiers: ["node:tls", "tls"],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("authors TLS Server construction only with exact retirement cleanup", () => {
    for (const [exportName, setup] of [
      ["Server", { kind: "tls-server-construct-target" }],
      ["Server.constructor", { kind: "tls-server-construct-target" }],
      ["createServer", { kind: "tls-server-root-call" }],
    ]) {
      const prototype = exportName.includes(".");
      expect(
        probeFor({
          sourceKey: "node_tls",
          exportName,
          exportIdioms: prototype
            ? ["exported-constructor-prototype"]
            : ["module-exports-object"],
          moduleSpecifiers: ["node:tls", "tls"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-tls-pure-v1",
          arguments: [],
          setup,
          bodyEntryProof: {
            kind: "normal-return-from-source-call",
            resultType: "object",
          },
        },
      });
    }
  });

  test("authors HTTPS Server construction only with exact TLS retirement cleanup", () => {
    for (const [exportName, setup] of [
      ["Server", { kind: "tls-server-construct-target" }],
      ["Server.constructor", { kind: "tls-server-construct-target" }],
      ["createServer", { kind: "tls-server-root-call" }],
    ]) {
      const prototype = exportName.includes(".");
      expect(
        probeFor({
          sourceKey: "node_https",
          exportName,
          exportIdioms: prototype
            ? ["exported-constructor-prototype"]
            : ["member-assignment"],
          moduleSpecifiers: ["https", "node:https"],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-https-idle-v1",
          arguments: [],
          setup,
          bodyEntryProof: {
            kind: "normal-return-from-source-call",
            resultType: "object",
          },
        },
      });
    }
  });

  test("authors only the exact fresh UDP socket lifecycle family", () => {
    const udp4 = [{ kind: "json", value: "udp4" }];
    const contracts = [
      ["Socket", { kind: "construct-target" }, udp4, "object"],
      [
        "Socket.close",
        {
          kind: "constructed-owner",
          ownerExportName: "Socket",
          constructorArguments: udp4,
        },
        [],
        "object",
      ],
      ["Socket.constructor", { kind: "construct-target" }, udp4, "object"],
      [
        "Socket.dropMembership",
        {
          kind: "constructed-owner",
          ownerExportName: "Socket",
          constructorArguments: udp4,
        },
        [{ kind: "json", value: "224.0.0.1" }],
        "undefined",
      ],
      [
        "Socket.ref",
        {
          kind: "constructed-owner",
          ownerExportName: "Socket",
          constructorArguments: udp4,
        },
        [],
        "object",
      ],
      [
        "Socket.unref",
        {
          kind: "constructed-owner",
          ownerExportName: "Socket",
          constructorArguments: udp4,
        },
        [],
        "object",
      ],
      ["createSocket", { kind: "root-call" }, udp4, "object"],
    ];
    for (const [exportName, setup, arguments_, resultType] of contracts) {
      const prototype = exportName.includes(".");
      expect(
        probeFor({
          sourceKey: "node_dgram",
          exportName,
          exportIdioms: prototype
            ? ["exported-constructor-prototype"]
            : ["module-exports-object"],
          moduleSpecifiers: ["dgram", "node:dgram"],
          sourceRefs: [`src/builtins/dgram.js#exports:${exportName}`],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-dgram-idle-v1",
          arguments: arguments_,
          setup,
          bodyEntryProof: {
            kind: "normal-return-from-source-call",
            resultType,
          },
        },
      });
    }
    for (const exportName of [
      "Socket.address",
      "Socket.bind",
      "Socket.disconnect",
      "Socket.send",
    ]) {
      expect(
        probeFor({
          sourceKey: "node_dgram",
          exportName,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["dgram", "node:dgram"],
          sourceRefs: [`src/builtins/dgram.js#exports:${exportName}`],
          valueShape: "callable",
        }),
      ).toBeNull();
    }
  });

  test("authors pure IP, module, clock, URL, and version helpers", () => {
    expect(
      probeFor({
        sourceKey: "node_readline",
        exportName: "CSI",
        exportIdioms: ["module-exports-object"],
        moduleSpecifiers: [
          "node:readline",
          "node:readline/promises",
          "readline",
          "readline/promises",
        ],
        sourceRefs: ["src/builtins/readline.js#exports:CSI"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-readline-pure-v1",
        arguments: [{ kind: "json", value: ["31m"] }],
        setup: { kind: "root-call" },
        bodyEntryProof: { resultType: "string" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_readline",
        exportName: "Interface.close",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: [
          "node:readline",
          "node:readline/promises",
          "readline",
          "readline/promises",
        ],
        sourceRefs: ["src/builtins/readline.js#exports:Interface.close"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-readline-pure-v1",
        arguments: [],
        setup: {
          kind: "readline-interface-owner",
          ownerExportName: "Interface",
          terminal: false,
        },
        bodyEntryProof: {
          kind: "normal-return-from-source-call",
          resultType: "undefined",
        },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_readline",
        exportName: "Interface.pause",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: [
          "node:readline",
          "node:readline/promises",
          "readline",
          "readline/promises",
        ],
        sourceRefs: ["src/builtins/readline.js#exports:Interface.pause"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-readline-pure-v1",
        arguments: [],
        setup: {
          kind: "readline-interface-pause-owner",
          ownerExportName: "Interface",
          terminal: false,
          cleanupMethod: "close",
        },
        bodyEntryProof: {
          kind: "normal-return-from-source-call",
          resultType: "object",
        },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_net",
        exportName: "BlockList.addRange",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["net", "node:net"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-net-bounded-v1",
        setup: {
          kind: "constructed-owner",
          ownerExportName: "BlockList",
          constructorArguments: [],
        },
        bodyEntryProof: { resultType: "undefined" },
      },
    });
    expect(
      probeFor({
        sourceKey: "node_net",
        exportName: "Server.close",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["net", "node:net"],
        valueShape: "callable",
      }),
    ).toMatchObject({
      invocation: {
        templateId: "node-net-bounded-v1",
        arguments: [],
        setup: {
          kind: "net-terminal-owner",
          ownerExportName: "Server",
        },
        bodyEntryProof: { resultType: "object" },
      },
    });
    for (const [sourceKey, exportName, moduleSpecifiers, templateId] of [
      ["node_module", "isBuiltin", ["module", "node:module"], "node-module-pure-v1"],
      ["node_url", "canParse", ["node:url", "url"], "node-url-pure-v1"],
      ["node_v8", "cachedDataVersionTag", ["node:v8", "v8"], "node-v8-pure-v1"],
    ]) {
      expect(
        probeFor({
          sourceKey,
          exportName,
          moduleSpecifiers,
          valueShape: "callable",
        })?.invocation.templateId,
      ).toBe(templateId);
    }
  });

  test("authors only exact fresh net terminal lifecycles", () => {
    for (const [ownerExportName, methodName] of [
      ["Server", "close"],
      ["Socket", "close"],
      ["Socket", "resetAndDestroy"],
      ["Stream", "close"],
      ["Stream", "resetAndDestroy"],
    ]) {
      expect(
        probeFor({
          sourceKey: "node_net",
          exportName: `${ownerExportName}.${methodName}`,
          exportIdioms: ["exported-constructor-prototype"],
          moduleSpecifiers: ["net", "node:net"],
          sourceRefs: [
            `src/builtins/net.js#exports:${ownerExportName}.${methodName}`,
          ],
          valueShape: "callable",
        }),
      ).toMatchObject({
        invocation: {
          templateId: "node-net-bounded-v1",
          arguments: [],
          setup: {
            kind: "net-terminal-owner",
            ownerExportName,
          },
          bodyEntryProof: {
            kind: "normal-return-from-source-call",
            resultType: "object",
          },
        },
      });
    }
  });

  test("leaves un-authored callable families and throwing-only calls residual", () => {
    expect(
      probeFor({
        sourceKey: "exact_crypto",
        exportName: "Hash.update",
        exportIdioms: ["exported-constructor-prototype"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        valueShape: "data",
      }),
    ).toBeNull();
    for (const sourceKey of ["node_cluster", "node_http"]) {
      expect(
        probeFor({
          sourceKey,
          exportName: "scalar",
          moduleSpecifiers: [`node:${sourceKey.slice(5)}`],
          valueShape: "data",
        }),
      ).toBeNull();
    }
    expect(
      probeFor({
        sourceKey: "node_assert",
        exportName: "fail",
        exportIdioms: ["member-assignment"],
        moduleSpecifiers: ["assert", "node:assert"],
        valueShape: "callable",
      }),
    ).toBeNull();
    expect(
      probeFor({
        sourceKey: "node_path",
        exportName: "__proto__",
        moduleSpecifiers: ["node:path", "path"],
        valueShape: "callable",
      }),
    ).toBeNull();
  });

  test("leaves dynamic tables and non-self routes residual", () => {
    expect(
      probeFor({
        sourceKey: "node_constants",
        exportName: "[[dynamic-table:signal-number-overlay]]",
        exportIdioms: [
          "closed-dynamic-table:signal-number-overlay",
          "table-copy",
        ],
        moduleSpecifiers: ["node:constants"],
      }),
    ).toBeNull();

    const observedKey = "builtin:export:node_path:basename";
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route: {
          surfaceObservedKeys: [observedKey],
          alternatives: [
            {
              terminalObservedKey: "native-op:__unexpected",
              proofPaths: ["basename -> __unexpected"],
            },
          ],
          ambiguousCallees: [],
        },
        liveByObservedKey: new Map(),
      }),
    ).toBeNull();
  });

  test("keeps non-public manifest sources as explicit residuals", () => {
    const surfaceObservedKey =
      "builtin:export:internal_fs_utils:toPathIfFileURL";
    const route = {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    const liveByObservedKey = new Map([
      [
        surfaceObservedKey,
        {
          observedKey: surfaceObservedKey,
          sourceRefs: [
            "modules.ts#sources:internal_fs_utils:exports:toPathIfFileURL",
          ],
          metadata: {
            bootstrapInternalModuleSpecifiers: ["internal/fs/utils"],
            exportName: "toPathIfFileURL",
            exportIdioms: ["module-exports-object"],
            importReachability: "bootstrap-internal",
            moduleSpecifiers: ["internal/fs/utils"],
            publicModuleSpecifiers: [],
            sourceKey: "internal_fs_utils",
            surfaceType: "export",
            valueShape: "callable",
          },
        },
      ],
    ]);

    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBeNull();
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-resolves-to-bootstrap-internal");

    const metadata = liveByObservedKey.get(surfaceObservedKey).metadata;
    metadata.bootstrapInternalModuleSpecifiers = [];
    metadata.importReachability = "private-manifest";
    metadata.moduleSpecifiers = [];
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-not-publicly-importable");
  });

  test("proves source-bound target-absent constants through the public module", () => {
    const surfaceObservedKey = "builtin:export:node_constants:EDQUOT";
    const liveByObservedKey = new Map([
      [
        surfaceObservedKey,
        {
          observedKey: surfaceObservedKey,
          sourceRefs: ["src/builtins/constants.js#exports:EDQUOT"],
          metadata: {
            sourceKey: "node_constants",
            exportName: "EDQUOT",
            exportIdioms: ["object-binding", "object-source", "table-copy"],
            importReachability: "public",
            moduleSpecifiers: ["constants", "node:constants"],
            publicModuleSpecifiers: ["constants", "node:constants"],
            platformAvailability: ["android", "linux"],
            surfaceType: "export",
            valueShape: "data",
          },
        },
      ],
    ]);
    const route = {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toMatchObject({
      surfaceObservedKey,
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-read",
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
        sourceDescriptor: {
          exportName: "EDQUOT",
          platformAvailability: ["android", "linux"],
        },
      },
    });
    expect(
      nonCapabilityBuiltinProbeResidualReason({
        route,
        liveByObservedKey,
        target: "aarch64-apple-darwin",
      }),
    ).toBe("builtin-export-not-available-on-target");
    expect(
      authoredNonCapabilityBuiltinProbe({
        plan,
        scenario: "non-capability",
        route,
        liveByObservedKey,
        target: "aarch64-linux-android",
      })?.invocation.sourceDescriptor.platformAvailability,
    ).toEqual(["android", "linux"]);
  });
});
