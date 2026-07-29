import crypto from "node:crypto";
import path from "node:path";
import { describe, expect, test } from "bun:test";
import {
  assertPublicSurfaceExecutionComplete,
  buildPublicFixtureEvidence,
  buildPublicSurfaceExecutionArtifact,
  mergePublicBatchExecutions,
  nativeAsyncWorkerTerminal,
  nativeAsyncWorkerTerminals,
  validateNativeFilesystemDenialRecipeDescriptor,
  validatePublicSurfaceExecutionArtifact,
  validateStartupEnvironmentRecipeDescriptor,
} from "./capsec-public-surface-evidence.mjs";
import {
  computeRecipeCatalogDigest,
  assertRecipeCatalogComplete,
} from "./capsec-conformance-recipes.mjs";
import { authoredModuleLoaderCapturedInvocation } from "./capsec-loader-public-probe-templates.mjs";
import {
  canonicalJson,
  capsecRoot,
  readJsonStrict,
} from "./capsec-contract.mjs";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;
const registryBundle = readJsonStrict(
  path.join(capsecRoot, "examples/registry-digest-bundle.canonical.json"),
);
const digestVectors = readJsonStrict(
  path.join(capsecRoot, "examples/digest-vectors.canonical.json"),
);
const rootGlobalDispositions = readJsonStrict(
  path.join(
    capsecRoot,
    "generated/root-global-disposition-manifest.json",
  ),
).rows;
const semanticRegistryIdentity = {
  vocabDigest: registryBundle.members.find(
    (member) => member.logicalName === "vocab-digest",
  ).document.digest,
  registryDigest: digestVectors.vectors.find(
    (vector) => vector.id === "registry",
  ).expectedDigest,
};
const builtinCacheSourceId = (sourceKey) =>
  `ibex-source-id-v1:${Buffer.from(
    canonicalJson({
      kind: "builtin",
      key: sourceKey,
      sourceIdSchema: "ibex.source-id.v1",
    }),
    "utf8",
  ).toString("base64url")}`;
const NONCAP_MODULE_IMPORT_TEST_ALIASES = [
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
].map(([moduleSpecifier, sourceKey, moduleBuiltin, expectedRootType]) => ({
  moduleSpecifier,
  sourceKey,
  moduleBuiltin,
  expectedRootType,
  edgeId: `edge.noncap-module.${moduleSpecifier}`,
}));
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
const REVIEWED_X509_INSTANCE_VALUES = [
  ["exact_crypto", "X509Certificate.raw", "accessor", "object", ["exported-constructor-prototype"], ["crypto", "exact:crypto", "node:crypto"], "src/builtins/crypto.js#exports:X509Certificate.raw"],
];
const REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUES = [
  ["node_tls", "SecureContext.context", "unknown", "object", ["exported-constructor-prototype"], ["node:tls", "tls"], "src/builtins/tls.js#exports:SecureContext.context"],
];
const REVIEWED_DGRAM_SOCKET_INSTANCE_VALUES = [
  ["node_dgram", "Socket._closed", "unknown", "boolean", ["exported-constructor-prototype"], ["dgram", "node:dgram"], "src/builtins/dgram.js#exports:Socket._closed"],
];

const target = {
  triple: "aarch64-apple-darwin",
  features: ["frame-attribution", "native-lockdown"],
};
const engine = {
  kind: "hermes",
  engineArtifactPath: "/tmp/hermesvm",
  binaryDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  object: { platform: "apple", volume: "dev:1", file: "ino:2" },
  targetArchitecture: "aarch64",
  structuralFeatures: [...target.features],
};
const coverage = {
  edges: [
    {
      id: "edge.terminal",
      surface: { kind: "native-op", name: "__exactPublic" },
    },
    {
      id: "edge.global-callable",
      classification: "non-capability",
      surface: {
        kind: "native-op",
        name: "global:AbortController.abort",
      },
      effects: [],
    },
    {
      id: "edge.builtin-node-util",
      classification: "effects",
      surface: { kind: "builtin", name: "node:util" },
      effects: [{ cap: "env:read", stages: ["requested", "commit"] }],
    },
    {
      id: "edge.builtin-node-util-types",
      classification: "effects",
      surface: { kind: "builtin", name: "node:util/types" },
      effects: [{ cap: "env:read", stages: ["requested", "commit"] }],
    },
    {
      id: "edge.noncap-builtin",
      classification: "non-capability",
      surface: { kind: "builtin", name: "export:node_buffer:atob" },
      effects: [],
    },
    ...NONCAP_MODULE_IMPORT_TEST_ALIASES.map(({ edgeId, moduleSpecifier }) => ({
      id: edgeId,
      classification: "non-capability",
      surface: { kind: "builtin", name: moduleSpecifier },
      rationaleId: "module-reachability-only",
      rationale:
        "Loading or aliasing this module changes reachability only; every external operation remains classified at its own effect boundary.",
    })),
    {
      id: "edge.mkdir-worker",
      surface: { kind: "native-op", name: "__exactMkdir" },
    },
    {
      id: "edge.readlink-worker",
      surface: { kind: "native-op", name: "__exactReadlink" },
    },
    {
      id: "edge.readdir-worker",
      surface: { kind: "native-op", name: "__exactReaddir" },
    },
    {
      id: "edge.fsopen-worker",
      surface: { kind: "native-op", name: "__exactFsOpen" },
    },
    {
      id: "edge.truncate-worker",
      surface: { kind: "native-op", name: "__exactTruncate" },
    },
    {
      id: "edge.exists-access",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactAccess" },
      effects: [{ cap: "fs:list", stages: ["requested"] }],
    },
    {
      id: "edge.exists-ensure",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactEnsureFs" },
      effects: [{ cap: "fs:list", stages: ["requested"] }],
    },
    {
      id: "edge.realpath-cwd",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactGetCwd" },
      effects: [{ cap: "path:cwd-observe", stages: ["requested"] }],
    },
    {
      id: "edge.realpath-lstat",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactLstat" },
      effects: [{ cap: "fs:list", stages: ["requested"] }],
    },
    {
      id: "edge.realpath-terminal",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactRealpath" },
      effects: [{ cap: "fs:list", stages: ["requested"] }],
    },
    {
      id: "edge.callback-terminal",
      classification: "effects",
      surface: { kind: "native-op", name: "__exactGetEnv" },
      effects: [{ cap: "env:read", stages: ["requested", "commit"] }],
    },
    {
      id: "edge.startup-env-node-debug",
      classification: "effects",
      effectMode: "conditional",
      surface: { kind: "startup", name: "env:NODE_DEBUG" },
      logicalBranches: [
        {
          id: "absent",
          when: [
            {
              fact: "environment.startup.node_debug",
              equals: "absent",
            },
          ],
          effects: [{ cap: "env:read", stages: ["requested", "commit"] }],
        },
        {
          id: "present",
          when: [
            {
              fact: "environment.startup.node_debug",
              equals: "present",
            },
          ],
          effects: [
            { cap: "env:read", stages: ["requested", "commit"] },
            {
              cap: "stdio:write",
              stages: ["requested", "commit", "repeat"],
            },
          ],
        },
      ],
    },
    {
      id: "edge.host-sqlite",
      classification: "effects",
      surface: { kind: "host-abi", name: "ex_host_sqlite_open" },
      logicalBranches: [
        {
          id: "memory",
          when: [{ fact: "sqlite.open.mode", equals: "memory" }],
          effects: [],
        },
      ],
    },
    {
      id: "edge.startup",
      classification: "non-capability",
      surface: { kind: "startup", name: "lockdown-install" },
    },
    {
      id: "edge.exact-closed",
      classification: "closed",
      surface: { kind: "native-op", name: "global:exact.invokeHostAsync" },
    },
    {
      id: "edge.module-runner-namespace-closed",
      classification: "closed",
      surface: {
        kind: "host-abi",
        name: "ex_hermes_module_record_namespace_json",
      },
    },
  ],
};

function completeCatalog() {
  const recipe = {
    fixtureId: "fixture.public.allow",
    planDigest: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    classification: "effects",
    scenario: "allow",
    edgeIds: ["edge.public"],
    implementationBranchIds: ["edge.public.main"],
    enforcementBranchIds: ["enforcement.public"],
    actionIds: ["sys:read"],
    terminalObservedKey: "native-op:__exactPublic",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "enforcement.public",
    },
    route: {
      surfaceObservedKeys: ["builtin:export:node_test:read"],
      alternatives: [
        {
          terminalObservedKey: "native-op:__exactPublic",
          proofPaths: ["export:read -> __exactPublic"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "builtin:export:node_test:read",
      command: ["ibex", "capsec-public-fixture", "fixture.public.allow"],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-export-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:test",
        exportName: "read",
        sourceDescriptor: {
          kind: "builtin-export",
          sourceKey: "node_test",
          exportName: "read",
          moduleSpecifiers: ["node:test"],
          sourceRef: "src/builtins/test.js#exports:read",
        },
        arguments: [],
        expectedResult: "return",
        expectedTypedStages: ["requested"],
        expectedTypedDecisionCount: 1,
        allowedCoverageEdgeIds: ["edge.terminal", "edge.unselected"],
        expectedActionIds: ["sys:read"],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const descriptor = recipe.publicSurfaceProbe.invocation.sourceDescriptor;
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
    taggedDigest(descriptor);
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { allow: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function runtimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: { kind: "return", valueType: "string" },
    },
    legacyObservationCount: 0,
    typedDecisions: [
      {
        decisionSet: {
          decisionSetSchema: "ibex/capsec-decision-set/1",
          operationId: "fixture-public",
          atomicityGroup: "edge.terminal.decision",
          combination: "conjunction",
          context: {
            stage: "requested",
            actor: { kind: "root", identity: "project-root" },
            constrainedPrincipals: [{ kind: "root", identity: "project-root" }],
            presentedHandleIds: [],
          },
          effects: [
            {
              cap: "sys:read",
              effectOwner: { kind: "root", identity: "project-root" },
              resource: {
                kind: "system-info-occurrence",
                requested: { kind: "system-info", name: "platform" },
              },
            },
          ],
        },
        gates: [
          {
            coverageEdgeId: "edge.terminal",
            targetCell: "complete",
            definitionAndEdgePredicatesSatisfied: true,
          },
        ],
        evidence: { outcome: "allow" },
      },
    ],
  };
}

function globalCallableFixture() {
  const recipe = completeCatalog().recipes[0];
  const surfaceObservedKey =
    "native-op:global:AbortController.abort";
  Object.assign(recipe, {
    fixtureId: "fixture.global-callable.abort-controller-abort",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.global-callable"],
    actionIds: [],
    terminalObservedKey: surfaceObservedKey,
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.global-callable.main",
    },
    route: {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    },
  });
  const sourceDescriptor = {
    kind: "global-api-callable",
    globalName: "AbortController",
    memberName: "abort",
    memberKinds: ["prototype"],
    sourceRefs: [
      "packages/ibex-runtime-js/src/shared-runtime.ts#global:AbortController.abort",
    ],
  };
  recipe.publicSurfaceProbe = {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: ["cargo", "test", "capsec_public_global_callable_batch"],
    invocation: {
      invocationSchema: "ibex/capsec-global-callable-invocation/1",
      kind: "global-callable-invocation",
      coverageEdgeId: "edge.global-callable",
      coverageClassification: "non-capability",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      route: {
        operation: "call",
        receiver: {
          kind: "construct-global",
          globalName: "AbortController",
          arguments: [],
        },
        arguments: [],
      },
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      },
      expectedResult: "source-completion",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      allowedCoverageEdgeIds: ["edge.global-callable"],
      expectedActionIds: [],
    },
  };
  const observation = {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: "ibex/capsec-global-callable-invocation/1",
      kind: "global-callable-invocation",
      surfaceObservedKey,
      globalName: "AbortController",
      memberName: "abort",
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
        status: "quiescent",
      },
      result: {
        kind: "source-completion",
        sourceCompletionKind: "return",
        sourceOperationAttempted: true,
        descriptorProof: {
          presence: "own",
          descriptorKind: "data",
          valueType: "function",
        },
        cleanupPerformed: true,
        cleanupError: null,
        rawOutput: {
          kind: "return",
          rawValueShape: "undefined",
          value: null,
          errorCode: null,
        },
        engineExecuted: true,
        projectCodeExecuted: true,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
  return { recipe, observation };
}

function openThenActFixture(scenario = "allow", exportName = "readFileSync") {
  const catalog = completeCatalog();
  const recipe = catalog.recipes[0];
  const denial = scenario === "deny";
  const [terminal, edgeId, operationKey] =
    new Map([
      ["mkdirSync", ["__exactMkdir", "edge.mkdir-worker", "fs-mkdir"]],
      [
        "readlinkSync",
        ["__exactReadlink", "edge.readlink-worker", "fs-readlink"],
      ],
      [
        "truncateSync",
        ["__exactTruncate", "edge.truncate-worker", "fs-truncate"],
      ],
    ]).get(exportName) ??
    ["__exactFsOpen", "edge.fsopen-worker", "fs-open"];
  const action = new Set([
    "appendFileSync",
    "mkdirSync",
    "truncateSync",
    "writeFileSync",
  ]).has(exportName)
    ? "fs:write"
    : "fs:read";
  recipe.fixtureId = `fixture.public.${exportName}.${scenario}`;
  recipe.scenario = scenario;
  recipe.actionIds = [action];
  recipe.terminalObservedKey = `builtin:export:node_fs:${exportName}`;
  recipe.route = {
    surfaceObservedKeys: [recipe.terminalObservedKey],
    alternatives: [
      {
        terminalObservedKey: `native-op:${terminal}`,
        proofPaths: [`export:${exportName} -> ${terminal}`],
      },
    ],
    ambiguousCallees: [],
  };
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  const invocation = recipe.publicSurfaceProbe.invocation;
  invocation.moduleSpecifier = "node:fs";
  invocation.exportName = exportName;
  invocation.sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_fs",
    exportName,
    moduleSpecifiers: ["node:fs"],
    sourceRef: `src/builtins/fs.js#exports:${exportName}`,
  };
  invocation.sourceDescriptorDigest = taggedDigest(invocation.sourceDescriptor);
  invocation.expectedResult = denial ? "permission-denied" : "return";
  invocation.expectedTypedStages = ["requested", "commit"];
  invocation.expectedTypedDecisionCount = 2;
  invocation.allowedCoverageEdgeIds = [edgeId];
  invocation.expectedActionIds = [action];
  if (exportName === "readlinkSync" && !denial) {
    invocation.expectedStringValue = "fixture-target.txt";
  }
  catalog.summary.byScenario = { [scenario]: 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);

  const actor = { kind: "root", identity: "project-root" };
  const decision = ({ stage, action, outcome, traversal }) => ({
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `${operationKey}:0:fixture`,
      atomicityGroup: `${edgeId}.decision`,
      combination: "conjunction",
      context: {
        stage,
        actor,
        constrainedPrincipals: [actor],
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: action,
          effectOwner: actor,
          resource: traversal
            ? {
                kind: "path-occurrence",
                requested: {
                  root: "project",
                  components: [{ encoding: "utf8", value: "fixture.txt" }],
                },
                followMode: "follow-final",
                objectState: "unknown",
              }
            : {
                kind: "path-occurrence",
                requested: {
                  root: "project",
                  components: [{ encoding: "utf8", value: "fixture.txt" }],
                },
                followMode: "follow-final",
                objectState:
                  exportName === "mkdirSync" ? "absent-create" : "existing",
              },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: edgeId,
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: {
      outcome,
      evidence: traversal
        ? [
            {
              effectIndex: 0,
              principal: actor,
              stratum: "ambient-root",
              reason: "ambient-root",
              sourceId: null,
            },
          ]
        : [],
    },
  });
  const observation = runtimeObservation(recipe);
  observation.invocation.result = denial
    ? {
        kind: "throw",
        errorName: "Error",
        errorMessage: "Permission denied",
      }
    : exportName === "readlinkSync"
      ? {
          kind: "return",
          moduleSpecifier: "node:fs",
          exportName,
          valueType: "string",
          stringValue: "fixture-target.txt",
        }
      : { kind: "return", valueType: "object" };
  observation.typedDecisions = [
    decision({
      stage: "requested",
      action: "fs:list",
      outcome: "allow",
      traversal: true,
    }),
    decision({
      stage: "commit",
      action,
      outcome: denial ? "deny" : "allow",
      traversal: false,
    }),
  ];
  return { catalog, recipe, observation };
}

function openSyncFixture() {
  const fixture = openThenActFixture("allow", "openSync");
  const { catalog, recipe, observation } = fixture;
  const invocation = recipe.publicSurfaceProbe.invocation;
  recipe.actionIds = ["fs:list", "fs:read", "fs:write"];
  invocation.expectedActionIds = [...recipe.actionIds];
  invocation.expectedCleanup = "closed-fs-file-descriptor";
  invocation.requiredAuthority = ["fs:read", "fs:write"].map((cap) => ({
    cap,
    resource: {
      kind: "path-exact",
      path: {
        root: "project",
        components: [{ encoding: "utf8", value: "fixture.txt" }],
      },
    },
  }));
  observation.invocation.result = {
    kind: "return",
    moduleSpecifier: "node:fs",
    exportName: "openSync",
    valueType: "number",
    cleanup: "closed-fs-file-descriptor",
  };
  const commit = observation.typedDecisions[1];
  const readEffect = commit.decisionSet.effects[0];
  readEffect.cap = "fs:read";
  commit.decisionSet.effects.push({
    ...structuredClone(readEffect),
    cap: "fs:write",
  });
  commit.gates.push(structuredClone(commit.gates[0]));
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return fixture;
}

function opendirSyncFixture() {
  const fixture = openThenActFixture("allow", "opendirSync");
  const { catalog, recipe, observation } = fixture;
  const invocation = recipe.publicSurfaceProbe.invocation;
  recipe.actionIds = ["fs:list"];
  recipe.route.alternatives = [
    {
      terminalObservedKey: "native-op:__exactReaddir",
      proofPaths: ["export:opendirSync -> readdirSync -> __exactReaddir"],
    },
  ];
  invocation.expectedActionIds = ["fs:list"];
  invocation.expectedCleanup = "closed-fs-directory";
  invocation.allowedCoverageEdgeIds = ["edge.readdir-worker"];
  observation.invocation.result = {
    kind: "return",
    moduleSpecifier: "node:fs",
    exportName: "opendirSync",
    valueType: "object",
    cleanup: "closed-fs-directory",
    path: "/project/capsec-directory-fixture",
  };
  for (const decision of observation.typedDecisions) {
    decision.decisionSet.operationId = "fs-readdir:0:fixture";
    decision.decisionSet.atomicityGroup = "edge.readdir-worker.decision";
    for (const effect of decision.decisionSet.effects) {
      effect.cap = "fs:list";
    }
    for (const gate of decision.gates) {
      gate.coverageEdgeId = "edge.readdir-worker";
    }
  }
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return fixture;
}

function realpathAuxiliaryFixture(scenario = "allow") {
  const catalog = completeCatalog();
  const recipe = catalog.recipes[0];
  const denial = scenario === "deny";
  recipe.fixtureId = `fixture.public.realpath-sync.${scenario}`;
  recipe.scenario = scenario;
  recipe.actionIds = ["fs:list"];
  recipe.terminalObservedKey = "builtin:export:node_fs:realpathSync";
  recipe.route = {
    surfaceObservedKeys: [recipe.terminalObservedKey],
    alternatives: [
      {
        terminalObservedKey: "native-op:__exactRealpath",
        proofPaths: ["export:realpathSync -> __exactRealpath"],
      },
    ],
    ambiguousCallees: [],
  };
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  const invocation = recipe.publicSurfaceProbe.invocation;
  invocation.moduleSpecifier = "node:fs";
  invocation.exportName = "realpathSync";
  invocation.sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_fs",
    exportName: "realpathSync",
    moduleSpecifiers: ["node:fs"],
    sourceRef: "src/builtins/fs.js#exports:realpathSync",
    auxiliaryDecisionEdges: [
      {
        edgeId: "edge.realpath-cwd",
        observedKey: "native-op:__exactGetCwd",
        actionIds: ["path:cwd-observe"],
      },
      {
        edgeId: "edge.realpath-lstat",
        observedKey: "native-op:__exactLstat",
        actionIds: ["fs:list"],
      },
    ],
    denialTerminalEdgeId: "edge.realpath-lstat",
  };
  invocation.sourceDescriptorDigest = taggedDigest(invocation.sourceDescriptor);
  invocation.expectedResult = denial ? "permission-denied" : "return";
  invocation.expectedTypedStages = denial
    ? ["requested", "requested"]
    : ["requested", "requested", "requested"];
  invocation.expectedTypedDecisionCount =
    invocation.expectedTypedStages.length;
  invocation.allowedCoverageEdgeIds = [
    "edge.realpath-cwd",
    "edge.realpath-lstat",
    "edge.realpath-terminal",
  ];
  invocation.expectedActionIds = ["fs:list"];
  catalog.summary.byScenario = { [scenario]: 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);

  const actor = { kind: "root", identity: "project-root" };
  const decision = ({ edgeId, action, outcome }) => ({
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `${edgeId}:fixture`,
      atomicityGroup: `${edgeId}.decision`,
      combination: "conjunction",
      context: {
        stage: "requested",
        actor,
        constrainedPrincipals: [actor],
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: action,
          effectOwner: actor,
          resource: { kind: "fixture-occurrence" },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: edgeId,
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: { outcome },
  });
  const observation = runtimeObservation(recipe);
  observation.invocation.result = denial
    ? {
        kind: "throw",
        errorName: "Error",
        errorMessage: "Permission denied",
      }
    : { kind: "return", valueType: "string" };
  observation.typedDecisions = [
    decision({
      edgeId: "edge.realpath-cwd",
      action: "path:cwd-observe",
      outcome: "allow",
    }),
    decision({
      edgeId: "edge.realpath-lstat",
      action: "fs:list",
      outcome: denial ? "deny" : "allow",
    }),
    ...(!denial
      ? [
          decision({
            edgeId: "edge.realpath-terminal",
            action: "fs:list",
            outcome: "allow",
          }),
        ]
      : []),
  ];
  return { catalog, recipe, observation };
}

function existsSyncBooleanFixture(scenario = "allow") {
  const catalog = completeCatalog();
  const recipe = catalog.recipes[0];
  const denial = scenario === "deny";
  const surfaceObservedKey = "builtin:export:node_fs:existsSync";
  recipe.fixtureId = `fixture.public.exists-sync.${scenario}`;
  recipe.scenario = scenario;
  recipe.actionIds = ["fs:list"];
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route = {
    surfaceObservedKeys: [surfaceObservedKey],
    alternatives: [
      {
        terminalObservedKey: "native-op:__exactAccess",
        proofPaths: ["export:existsSync -> existsSync -> __exactAccess"],
      },
      {
        terminalObservedKey: "native-op:__exactEnsureFs",
        proofPaths: [
          "export:existsSync -> existsSync -> ensureExactFs -> __exactEnsureFs",
        ],
      },
    ],
    ambiguousCallees: [],
  };
  recipe.publicSurfaceProbe.surfaceObservedKey = surfaceObservedKey;
  const invocation = recipe.publicSurfaceProbe.invocation;
  invocation.moduleSpecifier = "node:fs";
  invocation.exportName = "existsSync";
  invocation.sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_fs",
    exportName: "existsSync",
    moduleSpecifiers: ["node:fs"],
    sourceRef: "src/builtins/fs.js#exports:existsSync",
  };
  invocation.sourceDescriptorDigest = taggedDigest(invocation.sourceDescriptor);
  invocation.expectedResult = "boolean-return";
  invocation.expectedBooleanValue = !denial;
  invocation.expectedTypedStages = ["requested"];
  invocation.expectedTypedDecisionCount = 1;
  invocation.allowedCoverageEdgeIds = [
    "edge.exists-access",
    "edge.exists-ensure",
  ];
  invocation.expectedActionIds = ["fs:list"];
  catalog.summary.byScenario = { [scenario]: 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);

  const actor = { kind: "root", identity: "project-root" };
  const observation = runtimeObservation(recipe);
  observation.invocation.result = {
    kind: "return",
    moduleSpecifier: "node:fs",
    exportName: "existsSync",
    valueType: "boolean",
    booleanValue: !denial,
  };
  observation.typedDecisions = [
    {
      decisionSet: {
        decisionSetSchema: "ibex/capsec-decision-set/1",
        operationId: "exists-sync:fixture",
        atomicityGroup: "edge.exists-access.decision",
        combination: "conjunction",
        context: {
          stage: "requested",
          actor,
          constrainedPrincipals: [actor],
          presentedHandleIds: [],
        },
        effects: [
          {
            cap: "fs:list",
            effectOwner: actor,
            resource: { kind: "fixture-occurrence" },
          },
        ],
      },
      gates: [
        {
          coverageEdgeId: "edge.exists-access",
          targetCell: "complete",
          definitionAndEdgePredicatesSatisfied: true,
        },
      ],
      evidence: { outcome: denial ? "deny" : "allow" },
    },
  ];
  return { catalog, recipe, observation };
}

function effectBuiltinModuleImportRecipe(
  scenario = "allow",
  moduleSpecifier = "node:util",
) {
  const expectation = new Map([
    [
      "node:util",
      {
        edgeId: "edge.builtin-node-util",
        sourceKey: "node_util",
        bundleExternal: true,
        moduleBuiltin: true,
        actionId: "env:read",
      },
    ],
    [
      "node:util/types",
      {
        edgeId: "edge.builtin-node-util-types",
        sourceKey: "node_util_types_alias",
        bundleExternal: true,
        moduleBuiltin: true,
        actionId: "env:read",
      },
    ],
  ]).get(moduleSpecifier);
  if (!expectation) throw new Error(`unknown test alias ${moduleSpecifier}`);
  const surfaceObservedKey = `builtin:${moduleSpecifier}`;
  const denial = scenario === "deny";
  const sourceDescriptor = {
    kind: "builtin-module-alias",
    moduleSpecifier,
    sourceKey: expectation.sourceKey,
    sourceRef: `modules.ts#specifiers:${expectation.sourceKey}`,
    sourceMetadata: {
      sourceKey: expectation.sourceKey,
      bundleExternal: expectation.bundleExternal,
      importReachability: "public",
      moduleBuiltin: expectation.moduleBuiltin,
    },
    carrierEdgeId: expectation.edgeId,
    auxiliaryDecisionEdgeId: "edge.callback-terminal",
  };
  const requiredAuthority = [
    {
      cap: "env:read",
      resource: {
        kind: "environment-name",
        target: "principal-overlay",
        name: "NODE_DEBUG",
      },
    },
  ];
  return {
    fixtureId: `fixture.builtin-module-import.${moduleSpecifier}.${scenario}`,
    planDigest: "sha256-IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
    classification: "effects",
    scenario,
    edgeIds: [expectation.edgeId],
    implementationBranchIds: [`${expectation.edgeId}.main`],
    enforcementBranchIds: [`${expectation.edgeId}.main`],
    actionIds: [expectation.actionId],
    terminalObservedKey: surfaceObservedKey,
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: `${expectation.edgeId}.main`,
    },
    route: {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: ["cargo", "test", "capsec_public_builtin_recipe_batch"],
      invocation: {
        invocationSchema:
          "ibex/capsec-builtin-module-import-invocation/1",
        kind: "builtin-module-import",
        moduleSpecifier,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        arguments: [],
        setup: { kind: "none" },
        requiredAuthority,
        expectedResult: "return",
        expectedTypedDecisionCount: denial ? 1 : 2,
        expectedTypedStages: denial
          ? ["requested"]
          : ["requested", "commit"],
        allowedCoverageEdgeIds: ["edge.callback-terminal"],
        expectedActionIds: [expectation.actionId],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
}

function effectBuiltinModuleImportObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const denial = recipe.scenario === "deny";
  const edgeId = invocation.allowedCoverageEdgeIds[0];
  const actionId = recipe.actionIds[0];
  const actor = { kind: "root", identity: "project-root" };
  const decisionIdentity = {
    profile: "ibex/capsec/1",
    semanticCore: "capsec/semantics/1",
    ...semanticRegistryIdentity,
    policyDigest: `sha256-${"P".repeat(43)}`,
    armedSnapshotDigest: `sha256-${"S".repeat(43)}`,
  };
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      decisionIdentity: { ...decisionIdentity },
      result: {
        kind: "return",
        moduleSpecifier: invocation.moduleSpecifier,
        valueType: "object",
      },
    },
    legacyObservationCount: 0,
    typedDecisions: invocation.expectedTypedStages.map((stage) => {
      const operationId =
        'environment-read:0:{"kind":"environment-name","target":"principal-overlay","name":"NODE_DEBUG"}';
      return {
        decisionSet: {
          decisionSetSchema: "ibex/capsec-decision-set/1",
          operationId,
          atomicityGroup: `${edgeId}.decision`,
          combination: "conjunction",
          context: {
            stage,
            actor,
            constrainedPrincipals: [actor],
            presentedHandleIds: [],
          },
          effects: [
            {
              cap: actionId,
              effectOwner: actor,
              resource: {
                kind: "environment-occurrence",
                requested: {
                  kind: "environment-name",
                  target: "principal-overlay",
                  name: "NODE_DEBUG",
                },
                valueOrigin: "principal-overlay",
              },
            },
          ],
        },
        gates: [
          {
            coverageEdgeId: edgeId,
            targetCell: "complete",
            definitionAndEdgePredicatesSatisfied: true,
          },
        ],
        evidence: {
          identity: { ...decisionIdentity },
          generations: { negative: 0, dynamic: 0, handle: 0 },
          operationId,
          stage,
          actor,
          effectOwners: [actor],
          constrainedPrincipals: [actor],
          outcome: denial ? "deny" : "allow",
          evidence: [
            {
              effectIndex: 0,
              principal: actor,
              stratum: denial ? "principal-denial" : "static-floor",
              reason: denial ? "principal-denial" : "static-floor",
              sourceId: denial
                ? "principal.000000.denial.000000"
                : "principal.000000.floor.000000",
            },
          ],
        },
      };
    }),
  };
}

function noncapModuleImportRecipe(moduleSpecifier = "node:dns") {
  const expectation = NONCAP_MODULE_IMPORT_TEST_ALIASES.find(
    (entry) => entry.moduleSpecifier === moduleSpecifier,
  );
  if (!expectation) {
    throw new Error(`unknown non-capability test alias ${moduleSpecifier}`);
  }
  const { sourceKey, edgeId, moduleBuiltin, expectedRootType } = expectation;
  const surfaceObservedKey = `builtin:${moduleSpecifier}`;
  const sourceDescriptor = {
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
  };
  return {
    fixtureId: `fixture.noncap-module-import.${moduleSpecifier}`,
    planDigest: "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: [edgeId],
    implementationBranchIds: [`${edgeId}.main`],
    enforcementBranchIds: [`${edgeId}.main`],
    actionIds: [],
    terminalObservedKey: surfaceObservedKey,
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: `${edgeId}.main`,
    },
    route: {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: ["cargo", "test", "capsec_public_noncap_builtin_recipe_batch"],
      invocation: {
        invocationSchema:
          "ibex/capsec-builtin-module-import-no-effect-invocation/1",
        kind: "builtin-module-import",
        moduleSpecifier,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
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
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
}

function noncapModuleImportObservation(recipe, runtimeNonce = "u64:42") {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      sourceExecution: {
        schema: "ibex/capsec-authenticated-builtin-source-execution/1",
        observationId: recipe.fixtureId,
        runtimeNonce,
        moduleSpecifier: invocation.moduleSpecifier,
        sourceId: builtinCacheSourceId(
          invocation.sourceDescriptor.sourceKey,
        ),
        cacheMiss: true,
        bodyCompleted: true,
      },
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "return",
        moduleSpecifier: invocation.moduleSpecifier,
        valueType: invocation.sourceDescriptor.expectedRootType,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeModuleImportCatalog() {
  const recipes = NONCAP_MODULE_IMPORT_TEST_ALIASES.map(
    ({ moduleSpecifier }) => noncapModuleImportRecipe(moduleSpecifier),
  )
    .sort((left, right) => left.fixtureId.localeCompare(right.fixtureId));
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes,
    summary: {
      requiredFixtures: recipes.length,
      fullyExecutableFixtures: recipes.length,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { "non-capability": recipes.length },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeArtifact(catalog = completeCatalog()) {
  return buildPublicSurfaceExecutionArtifact({
    recipeCatalog: catalog,
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    target,
    engine,
    coverage,
    executions: [
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: runtimeObservation(catalog.recipes[0]),
        coverage,
      }),
    ],
  });
}

function completeNoncapBuiltinCallCatalog() {
  const surfaceObservedKey = "builtin:export:node_path:basename";
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_path",
    exportName: "basename",
    exportIdioms: ["object-binding", "object-source"],
    moduleSpecifiers: ["node:path", "path"],
    sourceRef: "src/builtins/path.js#exports:basename",
    valueShape: "callable",
    access: { kind: "export-property", path: ["basename"] },
  };
  const recipe = {
    fixtureId: "fixture.noncap-builtin.basename",
    planDigest: "sha256-NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.noncap-builtin"],
    implementationBranchIds: ["edge.noncap-builtin.main"],
    enforcementBranchIds: ["edge.noncap-builtin.main"],
    actionIds: [],
    terminalObservedKey: surfaceObservedKey,
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.noncap-builtin.main",
    },
    route: {
      surfaceObservedKeys: [surfaceObservedKey],
      alternatives: [
        {
          terminalObservedKey: surfaceObservedKey,
          proofPaths: [surfaceObservedKey],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: ["cargo", "test", "capsec_public_noncap_builtin_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-builtin-call-invocation/1",
        kind: "builtin-export-call",
        moduleSpecifier: "node:path",
        exportName: "basename",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
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
        requiredAuthority: [],
        expectedResult: "normal-return",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { "non-capability": 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function noncapBuiltinCallObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "return",
        moduleSpecifier: invocation.moduleSpecifier,
        exportName: invocation.exportName,
        valueType: invocation.bodyEntryProof.resultType,
        dispatchKind: "call",
        bodyEntryProof: invocation.bodyEntryProof.kind,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeDnsPromiseErrorReadCatalog() {
  const catalog = completeNoncapBuiltinCallCatalog();
  const recipe = catalog.recipes[0];
  const exportName = "NODATA";
  const surfaceObservedKey =
    `builtin:export:node_dns_promises:${exportName}`;
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_dns_promises",
    exportName,
    exportIdioms: ["member-assignment"],
    moduleSpecifiers: ["dns/promises", "node:dns/promises"],
    sourceRef: `src/builtins/dns-promises.js#exports:${exportName}`,
    valueShape: "unknown",
    access: { kind: "export-property", path: [exportName] },
    expectedValueType: "string",
  };
  recipe.fixtureId = "fixture.noncap-builtin.dns-promises-nodata";
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  recipe.route.alternatives = [
    {
      terminalObservedKey: surfaceObservedKey,
      proofPaths: [surfaceObservedKey],
    },
  ];
  recipe.publicSurfaceProbe.surfaceObservedKey = surfaceObservedKey;
  recipe.publicSurfaceProbe.invocation = {
    invocationSchema: "ibex/capsec-builtin-export-invocation/1",
    kind: "builtin-export-read",
    moduleSpecifier: "node:dns/promises",
    exportName,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
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
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function dnsPromiseErrorReadObservation(recipe, valueType = "string") {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "return",
        moduleSpecifier: invocation.moduleSpecifier,
        exportName: invocation.exportName,
        valueType,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completePostInitializationValueReadCatalog([
  sourceKey,
  exportName,
  valueShape,
  expectedValueType,
  exportIdioms,
  moduleSpecifiers,
  sourceRef,
]) {
  const catalog = completeDnsPromiseErrorReadCatalog();
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = `builtin:export:${sourceKey}:${exportName}`;
  const segments = exportName.split(".");
  const prototype = exportIdioms.includes(
    "exported-constructor-prototype",
  );
  const inheritedPrototype = exportIdioms.includes(
    "exported-constructor-inherited-prototype",
  );
  const streamInstance =
    sourceKey === "node_stream" && exportName.endsWith(".closed");
  const x509RawInstance =
    sourceKey === "exact_crypto" &&
    exportName === "X509Certificate.raw";
  const tlsSecureContextInstance =
    sourceKey === "node_tls" &&
    exportName === "SecureContext.context";
  const dgramSocketClosedInstance =
    sourceKey === "node_dgram" && exportName === "Socket._closed";
  const prototypePath =
    sourceKey === "node_stream" && exportName === "default.destroyed"
      ? ["prototype", "destroyed"]
      : [segments[0], "prototype", ...segments.slice(1)];
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey,
    exportName,
    exportIdioms,
    moduleSpecifiers,
    sourceRef,
    valueShape,
    access:
      streamInstance ||
      x509RawInstance ||
      tlsSecureContextInstance ||
      dgramSocketClosedInstance
      ? {
          kind: "constructed-instance-property",
          path: [
            streamInstance
              ? "closed"
              : x509RawInstance
                ? "raw"
                : tlsSecureContextInstance
                  ? "context"
                  : "_closed",
          ],
        }
      : prototype || inheritedPrototype
      ? {
          kind: inheritedPrototype
            ? "inherited-prototype-property"
            : "prototype-property",
          path: prototypePath,
        }
      : exportName === "default"
        ? { kind: "module-value", path: [] }
        : { kind: "export-property", path: [exportName] },
    expectedValueType,
  };
  recipe.fixtureId =
    `fixture.noncap-builtin.post-initialization-value.${sourceKey}.${exportName}`;
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  recipe.route.alternatives = [
    {
      terminalObservedKey: surfaceObservedKey,
      proofPaths: [surfaceObservedKey],
    },
  ];
  recipe.publicSurfaceProbe.surfaceObservedKey = surfaceObservedKey;
  recipe.publicSurfaceProbe.invocation.moduleSpecifier =
    moduleSpecifiers.find((specifier) => specifier.startsWith("node:")) ??
    moduleSpecifiers[0];
  recipe.publicSurfaceProbe.invocation.exportName = exportName;
  recipe.publicSurfaceProbe.invocation.sourceDescriptor = sourceDescriptor;
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
    taggedDigest(sourceDescriptor);
  recipe.publicSurfaceProbe.invocation.setup = streamInstance
    ? {
        kind: "stream-owner",
        ownerExportName: segments[0],
        endedInput: false,
      }
    : x509RawInstance
      ? {
          kind: "constructed-owner",
          ownerExportName: "X509Certificate",
          constructorArguments: [
            { kind: "json", value: "ibex-x509-fixture" },
          ],
        }
      : tlsSecureContextInstance
        ? {
            kind: "constructed-owner",
            ownerExportName: "SecureContext",
            constructorArguments: [],
          }
      : dgramSocketClosedInstance
        ? {
            kind: "constructed-owner",
            ownerExportName: "Socket",
            constructorArguments: [{ kind: "json", value: "udp4" }],
          }
      : { kind: "none" };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeCapturedNoncapBuiltinCatalog() {
  const catalog = completeNoncapBuiltinCallCatalog();
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = "builtin:export:node_buffer:atob";
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_buffer",
    exportName: "atob",
    exportIdioms: ["object-binding", "object-source"],
    moduleSpecifiers: ["buffer", "node:buffer"],
    sourceRef: "src/builtins/buffer.js#exports:atob",
    valueShape: "unknown",
    importReachability: "public",
    access: { kind: "export-property", path: ["atob"] },
  };
  const sourceDescriptorDigest = taggedDigest(sourceDescriptor);
  const completion = {
    kind: "event-loop-quiescence",
    timeoutMilliseconds: 1_000,
  };
  const capturedOutputInvocation = {
    invocationSchema:
      "ibex/capsec-builtin-noncap-closed-output-invocation/1",
    kind: "builtin-noncap-closed-output",
    coverageEdgeId: recipe.edgeIds[0],
    coverageClassification: "non-capability",
    surfaceObservedKey,
    moduleSpecifier: "node:buffer",
    sourceDescriptor,
    sourceDescriptorDigest,
    route: {
      operation: "call",
      receiver: { kind: "module-value" },
      arguments: [{ kind: "json", value: "SWJleA==" }],
      cleanup: { kind: "none" },
      outcomeCapture: "public-builtin-family",
    },
    completion,
  };
  recipe.fixtureId = "fixture.noncap-builtin.captured-atob";
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  recipe.route.alternatives = [
    {
      terminalObservedKey: surfaceObservedKey,
      proofPaths: [surfaceObservedKey],
    },
  ];
  recipe.publicSurfaceProbe.surfaceObservedKey = surfaceObservedKey;
  recipe.publicSurfaceProbe.invocation = {
    invocationSchema:
      "ibex/capsec-builtin-noncap-captured-invocation/1",
    kind: "builtin-noncap-captured-call",
    moduleSpecifier: "node:buffer",
    exportName: "atob",
    sourceDescriptor,
    sourceDescriptorDigest,
    arguments: [],
    setup: { kind: "captured-output-route" },
    completion,
    capturedOutputInvocation,
    requiredAuthority: [],
    expectedResult: "captured-source-return",
    expectedTypedDecisionCount: 0,
    expectedTypedStages: [],
    allowedCoverageEdgeIds: [],
    expectedActionIds: [],
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function capturedNoncapBuiltinObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "captured-source-return",
        sourceOperationAttempted: true,
        descriptorProof: {
          accessKind: invocation.sourceDescriptor.access.kind,
          descriptorKind: "data",
        },
        cleanupPerformed: true,
        rawOutput: {
          kind: "return",
          rawValueShape: "string",
          value: "Ibex",
          errorCode: null,
        },
        engineExecuted: true,
        projectCodeExecuted: true,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeNoncapBuiltinAbsenceCatalog() {
  const catalog = completeNoncapBuiltinCallCatalog();
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = "builtin:export:node_constants:EDQUOT";
  const sourceDescriptor = {
    kind: "builtin-export",
    sourceKey: "node_constants",
    exportName: "EDQUOT",
    exportIdioms: ["object-binding", "object-source", "table-copy"],
    moduleSpecifiers: ["constants", "node:constants"],
    sourceRef: "src/builtins/constants.js#exports:EDQUOT",
    valueShape: "data",
    platformAvailability: ["android", "linux"],
    access: { kind: "export-property", path: ["EDQUOT"] },
  };
  recipe.fixtureId = "fixture.noncap-builtin.target-absent";
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  recipe.route.alternatives = [
    {
      terminalObservedKey: surfaceObservedKey,
      proofPaths: [surfaceObservedKey],
    },
  ];
  recipe.publicSurfaceProbe.surfaceObservedKey = surfaceObservedKey;
  recipe.publicSurfaceProbe.invocation = {
    invocationSchema: "ibex/capsec-builtin-export-invocation/1",
    kind: "builtin-export-read",
    moduleSpecifier: "node:constants",
    exportName: "EDQUOT",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    arguments: [],
    setup: { kind: "none" },
    completion: {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 1_000,
    },
    requiredAuthority: [],
    expectedResult: "absent",
    expectedTypedDecisionCount: 0,
    expectedTypedStages: [],
    allowedCoverageEdgeIds: [],
    expectedActionIds: [],
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function noncapBuiltinAbsenceObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      moduleSpecifier: invocation.moduleSpecifier,
      exportName: invocation.exportName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      completion: {
        kind: invocation.completion.kind,
        timeoutMilliseconds: invocation.completion.timeoutMilliseconds,
        status: "quiescent",
      },
      result: {
        kind: "missing",
        moduleSpecifier: invocation.moduleSpecifier,
        exportName: invocation.exportName,
        segment: invocation.exportName,
        available: ["EACCES", "ENOENT"],
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeAbsenceCatalog() {
  const sourceDescriptor = {
    kind: "target-absent-host-abi",
    surfaceKind: "host-abi",
    surfaceName: "ex_android_initialize",
    sourceRefs: [
      "src/engine/native_android_networking.cc#ex_android_initialize",
    ],
    targetVariants: ["android"],
    sourceMetadata: {
      definitions: [
        {
          language: "c++",
          sourceRef:
            "src/engine/native_android_networking.cc#ex_android_initialize",
          targetVariant: "android",
          unsafe: false,
          weak: false,
        },
      ],
    },
    probeMode: { kind: "dynamic-symbol", symbolName: "ex_android_initialize" },
  };
  const recipe = {
    fixtureId: "fixture.host-abi.absent",
    planDigest: "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    classification: "non-capability",
    scenario: "absent",
    edgeIds: ["edge.absent"],
    implementationBranchIds: [],
    enforcementBranchIds: [],
    actionIds: [],
    terminalObservedKey: "host-abi:ex_android_initialize",
    expectedObservation: { kind: "target-absence", edgeId: "edge.absent" },
    route: { surfaceObservedKeys: [], alternatives: [], ambiguousCallees: [] },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "target-absence-probe",
      surfaceObservedKey: "host-abi:ex_android_initialize",
      command: ["ibex", "capsec-public-target-absence"],
      invocation: {
        invocationSchema: "ibex/capsec-target-absence-invocation/1",
        kind: "target-absence",
        surfaceKind: "host-abi",
        surfaceName: "ex_android_initialize",
        targetTriple: target.triple,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        expectedResult: "absent",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { absent: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function absenceRuntimeObservation(recipe, symbolPresent = false) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const probeMode = invocation.sourceDescriptor.probeMode;
  const result = {
    kind: "absent",
    surfaceKind: invocation.surfaceKind,
    surfaceName: invocation.surfaceName,
    targetTriple: invocation.targetTriple,
    compiledTargetOs: "macos",
    compiledTargetArch: "aarch64",
    probeMode: probeMode.kind,
    ...(probeMode.kind === "runtime-global-property"
      ? {
          globalName: probeMode.globalName,
          memberName: probeMode.memberName,
          surfacePresent: symbolPresent,
        }
      : {
          symbolName: probeMode.symbolName,
          symbolPresent,
        }),
  };
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      targetTriple: invocation.targetTriple,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result,
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeNativeAbsenceCatalog() {
  const catalog = structuredClone(completeAbsenceCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "target-absent-native-operation",
    surfaceKind: "native-op",
    surfaceName: "__exactAndroidLocation.getPermissionStatus",
    sourceRefs: [
      "src/engine/hermes_runtime_android.cc#jsi-global:__exactAndroidLocation.getPermissionStatus",
    ],
    targetVariants: ["android"],
    sourceMetadata: {
      installationBranches: [
        {
          sourceRefs: [
            "src/engine/hermes_runtime_android.cc#jsi-global:__exactAndroidLocation.getPermissionStatus",
          ],
          targetVariant: "android",
        },
      ],
    },
    probeMode: {
      kind: "runtime-global-property",
      globalName: "__exactAndroidLocation",
      memberName: "getPermissionStatus",
    },
  };
  recipe.fixtureId = "fixture.native-op.absent";
  recipe.terminalObservedKey =
    "native-op:__exactAndroidLocation.getPermissionStatus";
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "__exactAndroidLocation.getPermissionStatus",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedCatalog() {
  const sourceDescriptor = {
    kind: "closed-startup-environment",
    environmentName: "EX_SKIP_STARTUP_MODULE_LOADER",
    sourceRefs: [
      "src/engine/hermes_bootstrap.cc#env_flag_enabled:EX_SKIP_STARTUP_MODULE_LOADER:read",
    ],
    sourceMetadata: {
      evidenceType: "static-runtime-environment-control",
      authoredNames: ["EX_SKIP_STARTUP_MODULE_LOADER"],
    },
  };
  const recipe = {
    fixtureId: "fixture.startup.closed",
    planDigest: "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    classification: "closed",
    scenario: "closed",
    edgeIds: ["edge.closed"],
    implementationBranchIds: ["edge.closed.main"],
    enforcementBranchIds: ["edge.closed.main"],
    actionIds: [],
    terminalObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.closed.main",
    },
    route: {
      surfaceObservedKeys: ["startup:env:EX_SKIP_STARTUP_MODULE_LOADER"],
      alternatives: [
        {
          terminalObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
          proofPaths: ["startup:env:EX_SKIP_STARTUP_MODULE_LOADER"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "startup:env:EX_SKIP_STARTUP_MODULE_LOADER",
      command: ["ibex", "capsec-public-closed"],
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        surfaceKind: "startup",
        surfaceName: "env:EX_SKIP_STARTUP_MODULE_LOADER",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: {
          kind: "startup-environment",
          environmentName: "EX_SKIP_STARTUP_MODULE_LOADER",
        },
        expectedResult: "closed",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { closed: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedFilesystemCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = "builtin:export:node_fs:chmod";
  const sourceDescriptor = {
    kind: "closed-filesystem-unbound-mutation",
    surfaceObservedKey,
    targetTriple: target.triple,
    surfaceForm: "builtin-export",
    sourceKey: "node_fs",
    exportName: "chmod",
    moduleSpecifier: "node:fs",
    sourceRefs: ["src/builtins/fs.js#exports:chmod"],
    sourceMetadata: {
      sourceKey: "node_fs",
      exportName: "chmod",
      surfaceType: "export",
    },
  };
  recipe.fixtureId = "fixture.filesystem.chmod.closed";
  recipe.terminalObservedKey = surfaceObservedKey;
  recipe.route = {
    surfaceObservedKeys: [surfaceObservedKey],
    alternatives: [
      {
        terminalObservedKey: "native-op:__exactEnsureFs",
        proofPaths: [
          "export:chmod -> chmod -> _fsAsyncNative -> ensureExactFs -> __exactEnsureFs",
        ],
      },
    ],
    ambiguousCallees: ["unresolved-call:_exactFsMutationGuard"],
  };
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey,
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "builtin",
      surfaceName: "export:node_fs:chmod",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "filesystem-unbound-mutation",
        targetTriple: target.triple,
        surfaceForm: "builtin-export",
        sourceKey: "node_fs",
        exportName: "chmod",
        moduleSpecifier: "node:fs",
        invocationStyle: "callback",
        guardOperation: "chmod",
        argumentShape: "path-mode",
        expectedErrorCode: "EPERM",
        expectedErrorFragment: "operation not permitted",
      },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedProcessEventCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const methodName = "addListener";
  const branchId =
    "surface.native.op.global.process.addlistener.1oorvy1.posix";
  const sourceRefs = [
    "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:process",
    "packages/ibex-runtime-js/src/node/process.ts#Process.prototype.addListener",
    "src/engine/bootstrap/exact-global.js#process.addListener",
    "src/engine/bootstrap/ipc-listener.js#process.addListener",
    "src/engine/bootstrap/stream-enhance.js#process.addListener",
  ];
  const sourceDescriptor = {
    kind: "closed-process-event-method",
    surfaceObservedKey: `native-op:global:process.${methodName}`,
    globalName: "process",
    memberName: methodName,
    argumentShape: "event-listener",
    targetTriple: target.triple,
    implementationBranchIds: [branchId],
    enforcementBranchIds: [branchId],
    enforcementSourceRef:
      "src/engine/hermes_runtime.cc#armed-process-event-methods",
    sourceRefs,
    sourceMetadata: {
      exportName: `process.${methodName}`,
      globalName: "process",
      installationBranches: [
        {
          id: "default",
          sourceRefs: sourceRefs.slice(0, 4),
        },
        {
          id: "posix",
          sourceRefs: [sourceRefs[4]],
        },
      ],
      memberKinds: ["member-assignment", "prototype-method"],
      memberName: methodName,
      surfaceType: "global-api",
    },
  };
  recipe.fixtureId = "fixture.process.add-listener.closed";
  recipe.implementationBranchIds = [branchId];
  recipe.enforcementBranchIds = [branchId];
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: `global:process.${methodName}`,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "process-event-closure",
      methodName,
      argumentShape: "event-listener",
      eventName: "ibex-capsec-shared-event",
      expectedErrorCode: "ERR_ACCESS_DENIED",
      expectedPermission: "ProcessEvents",
      expectedError: `process.${methodName} is disabled for this event in an armed runtime`,
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeProcessLifecycleNoEffectCatalog() {
  const catalog = completeClosedProcessEventCatalog();
  const recipe = catalog.recipes[0];
  const invocation = recipe.publicSurfaceProbe.invocation;
  recipe.fixtureId =
    "fixture.process.add-listener.posix.logical.before-exit.no-effect";
  recipe.scenario = "no-effect";
  invocation.sourceDescriptor.kind =
    "closed-process-lifecycle-no-effect";
  invocation.sourceDescriptor.selectedLogicalBranch = {
    id: "before-exit",
    when: [
      {
        fact: "process.listener.event",
        equals: "before-exit",
      },
    ],
    disposition: "no-effect",
  };
  invocation.sourceDescriptorDigest = taggedDigest(
    invocation.sourceDescriptor,
  );
  invocation.operation = {
    kind: "process-event-lifecycle-no-effect",
    scenario: "no-effect",
    methodName: "addListener",
    argumentShape: "event-listener",
    eventName: "beforeExit",
    logicalBranchId: "before-exit",
    expectedReturnKind: "process",
  };
  invocation.expectedResult = "no-effect";
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeProcessUmaskCatalog() {
  const catalog = completeClosedProcessEventCatalog();
  const recipe = catalog.recipes[0];
  const invocation = recipe.publicSurfaceProbe.invocation;
  const branchId = "surface.native.op.global.process.umask.1axcurx.posix";
  const sourceRefs = [
    "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:process",
    "packages/ibex-runtime-js/src/node/process.ts#Process.prototype.umask",
    "src/engine/bootstrap/compat-polyfills.js#process.umask",
    "src/engine/bootstrap/stream-enhance.js#process.umask",
  ];
  recipe.fixtureId =
    "surface.native.op.global.process.umask.1axcurx.posix.closed";
  recipe.implementationBranchIds = [branchId];
  recipe.enforcementBranchIds = [branchId];
  recipe.terminalObservedKey = "native-op:global:process.umask";
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  invocation.surfaceName = "global:process.umask";
  invocation.sourceDescriptor = {
    kind: "closed-process-umask",
    surfaceObservedKey: recipe.terminalObservedKey,
    globalName: "process",
    memberName: "umask",
    targetTriple: target.triple,
    implementationBranchIds: [branchId],
    enforcementBranchIds: [branchId],
    enforcementSourceRef:
      "src/engine/hermes_runtime.cc#armed-process-event-methods",
    sourceRefs,
    sourceMetadata: {
      exportName: "process.umask",
      globalName: "process",
      installationBranches: [
        {
          id: "default",
          sourceRefs: sourceRefs.slice(0, 3),
        },
        {
          id: "posix",
          sourceRefs: sourceRefs.slice(3),
        },
      ],
      memberKinds: ["instance-property", "member-assignment"],
      memberName: "umask",
      surfaceType: "global-api",
      valueShape: "callable",
    },
  };
  invocation.sourceDescriptorDigest = taggedDigest(
    invocation.sourceDescriptor,
  );
  invocation.operation = {
    kind: "process-umask-closure",
    argumentCases: [
      { id: "read", arguments: [] },
      { id: "write", arguments: [0] },
    ],
    expectedErrorCode: "ERR_ACCESS_DENIED",
    expectedPermission: "ProcessUmask",
    expectedError: "process.umask is disabled in an armed runtime",
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeProcessSharedStateCatalog() {
  const catalog = completeClosedProcessEventCatalog();
  const recipe = catalog.recipes[0];
  const invocation = recipe.publicSurfaceProbe.invocation;
  const memberName = "title";
  const branchId =
    "surface.native.op.global.process.title.1h2aqxk.posix";
  const sourceRefs = [
    "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:process",
    "packages/ibex-runtime-js/src/node/process.ts#Process.prototype.title",
    "src/engine/hermes_runtime_process_setup.cc#jsi-global:process.title",
  ];
  recipe.fixtureId =
    "surface.native.op.global.process.title.1h2aqxk.posix.closed";
  recipe.implementationBranchIds = [branchId];
  recipe.enforcementBranchIds = [branchId];
  recipe.terminalObservedKey = `native-op:global:process.${memberName}`;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  invocation.surfaceName = `global:process.${memberName}`;
  invocation.sourceDescriptor = {
    kind: "closed-process-shared-state-member",
    surfaceObservedKey: recipe.terminalObservedKey,
    globalName: "process",
    memberName,
    memberForm: "property",
    targetTriple: target.triple,
    implementationBranchIds: [branchId],
    enforcementBranchIds: [branchId],
    enforcementSourceRef:
      "src/engine/hermes_runtime.cc#armed-process-shared-state-members",
    sourceRefs,
    sourceMetadata: {
      exportName: `process.${memberName}`,
      globalName: "process",
      installationBranches: [
        {
          id: "default",
          sourceRefs: sourceRefs.slice(0, 2),
        },
        {
          id: "posix",
          sourceRefs,
        },
      ],
      memberKinds: ["native-object-member", "prototype-accessor"],
      memberName,
      surfaceType: "global-api",
    },
  };
  invocation.sourceDescriptorDigest = taggedDigest(
    invocation.sourceDescriptor,
  );
  invocation.operation = {
    kind: "process-shared-state-closure",
    memberName,
    memberForm: "property",
    accessCases: [
      "read",
      "write",
      "prototype-read",
      "prototype-write",
      "replacement-read",
    ],
    expectedErrorCode: "ERR_ACCESS_DENIED",
    expectedPermission: "ProcessTitle",
    expectedError:
      "process.title is disabled in an armed runtime",
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeProcessReportMemberCatalog() {
  const catalog = completeClosedProcessEventCatalog();
  const recipe = catalog.recipes[0];
  const invocation = recipe.publicSurfaceProbe.invocation;
  const memberName = "getReport";
  const branchId =
    "surface.native.op.global.process.report.getReport.reviewed.posix";
  const sourceRefs = [
    "src/engine/bootstrap/process-compat-fix.js#process.report.getReport",
    "src/engine/bootstrap/stream-enhance.js#process.report.getReport",
  ];
  recipe.fixtureId =
    "surface.native.op.global.process.report.getReport.reviewed.posix.closed";
  recipe.implementationBranchIds = [branchId];
  recipe.enforcementBranchIds = [branchId];
  recipe.terminalObservedKey =
    `native-op:global:process.report.${memberName}`;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  invocation.surfaceName = `global:process.report.${memberName}`;
  invocation.sourceDescriptor = {
    kind: "closed-process-report-member",
    surfaceObservedKey: recipe.terminalObservedKey,
    globalName: "process",
    memberName,
    memberPath: ["report", memberName],
    memberForm: "callable",
    blockedAtMember: "report",
    targetTriple: target.triple,
    implementationBranchIds: [branchId],
    enforcementBranchIds: [branchId],
    enforcementSourceRef:
      "src/engine/hermes_runtime.cc#armed-process-shared-state-members",
    sourceRefs,
    sourceMetadata: {
      exportName: `process.report.${memberName}`,
      globalName: "process",
      installationBranches: [
        {
          id: "default",
          sourceRefs: sourceRefs.slice(0, 1),
        },
        {
          id: "posix",
          sourceRefs: sourceRefs.slice(1),
        },
      ],
      memberKinds: ["source-derived-member"],
      memberName: `report.${memberName}`,
      surfaceType: "global-api",
      valueShape: "callable",
    },
  };
  invocation.sourceDescriptorDigest = taggedDigest(
    invocation.sourceDescriptor,
  );
  invocation.operation = {
    kind: "process-report-member-closure",
    memberName,
    memberPath: ["report", memberName],
    memberForm: "callable",
    blockedAtMember: "report",
    accessCases: ["read", "call", "replacement-read"],
    expectedErrorCode: "ERR_ACCESS_DENIED",
    expectedPermission: "ProcessReport",
    expectedError: "process.report is disabled in an armed runtime",
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedCliCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-cli-control",
    surfaceObservedKey: "cli:option-name:ibex:inspect:--inspect",
    sourceRefs: [
      "runtime-surface.json#clapSurface.command:ibex:option:inspect",
    ],
    sourceMetadata: {
      evidenceType: "cli-option-name",
      name: "--inspect",
      routeKind: "primary",
    },
    controlDescriptor: {
      kind: "clap-option",
      commandPath: "ibex",
      argumentId: "inspect",
      optionSpellings: ["--inspect"],
    },
  };
  recipe.fixtureId = "fixture.cli.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey = recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "cli",
    surfaceName: "option-name:ibex:inspect:--inspect",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "cli-control",
      argumentVectors: [
        {
          spelling: "--inspect",
          args: ["--inspect", "{ibex-capsec-closed-project-code}"],
        },
      ],
      expectedRejectionFragments: [
        "closes compatibility, inspector",
        "runtime-fidelity overrides",
      ],
      projectCodePlaceholder: "{ibex-capsec-closed-project-code}",
      evaluationMarker:
        "globalThis.__IBEX_CAPSEC_CLOSED_CLI_EVALUATED__ = true",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedLoaderCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-loader-executable-kind",
    loaderKind: "native-addon",
    extension: ".node",
    sourceRefs: ["src/module_loader/mod.rs#resolve_with_oxc"],
    sourceMetadata: null,
  };
  recipe.fixtureId = "fixture.loader.native-addon.closed";
  recipe.terminalObservedKey = "loader:native-addon-module";
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey = recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "loader",
    surfaceName: "native-addon-module",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "loader-executable-file",
      loaderKind: "native-addon",
      extension: ".node",
      rejectionFragment: "Native addons are closed",
      publicErrorCode: "ERR_IBEX_MODULE_RESOLUTION",
      publicErrorMessage: "Module resolution failed",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedTerminalBuiltinCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-terminal-builtin",
    surfaceObservedKey: "builtin:export:node_vm:runInNewContext",
    sourceKey: "node_vm",
    exportName: "runInNewContext",
    moduleSpecifiers: ["node:vm", "vm"],
    sourceRefs: ["src/builtins/vm.js#exports:runInNewContext"],
    sourceMetadata: {
      surfaceType: "export",
      sourceKey: "node_vm",
      exportName: "runInNewContext",
      importReachability: "public",
      publicModuleSpecifiers: ["node:vm", "vm"],
    },
  };
  recipe.fixtureId = "fixture.builtin.vm.run-in-new-context.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "builtin",
    surfaceName: "export:node_vm:runInNewContext",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "terminal-builtin-import",
      terminalBuiltinRoot: "vm",
      moduleSpecifiers: ["node:vm", "vm"],
      expectedRejectionFragment: "Import denied:",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedSqliteExtensionCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const exportName = "Database.loadExtension";
  const moduleSpecifiers = ["bun:sqlite", "exact:sqlite"];
  const sourceDescriptor = {
    kind: "closed-sqlite-extension-load",
    surfaceObservedKey:
      "builtin:export:exact_sqlite:Database.loadExtension",
    sourceKey: "exact_sqlite",
    exportName,
    constructorExportName: "Database",
    moduleSpecifiers,
    sourceRefs: [
      "packages/ibex-runtime-js/src/sqlite/module.js#exports:Database.loadExtension",
    ],
    sourceMetadata: {
      surfaceType: "export",
      sourceKey: "exact_sqlite",
      exportName,
      valueShape: "callable",
      importReachability: "public",
      moduleSpecifiers,
      publicModuleSpecifiers: moduleSpecifiers,
      enforcementRouteEvidence: {
        terminals: ["__exactSqliteLoadExtension"],
      },
    },
  };
  recipe.fixtureId = "fixture.builtin.sqlite.load-extension.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives = [
    {
      terminalObservedKey: "native-op:__exactSqliteLoadExtension",
      proofPaths: [
        `${recipe.terminalObservedKey} -> native-op:__exactSqliteLoadExtension`,
      ],
    },
  ];
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "builtin",
    surfaceName: "export:exact_sqlite:Database.loadExtension",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "sqlite-extension-load",
      constructorExportName: "Database",
      methodName: "loadExtension",
      moduleSpecifiers,
      databasePath: ":memory:",
      extensionPath: "ibex-capsec-closed-extension",
      expectedRejectionFragment: "Extension loading not supported",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedSqliteCrSqliteCatalog() {
  const catalog = structuredClone(completeClosedSqliteExtensionCatalog());
  const recipe = catalog.recipes[0];
  const exportName = "Database.enableCrSqlite";
  const sourceDescriptor = recipe.publicSurfaceProbe.invocation.sourceDescriptor;
  Object.assign(sourceDescriptor, {
    kind: "closed-sqlite-crsqlite-enable",
    surfaceObservedKey:
      "builtin:export:exact_sqlite:Database.enableCrSqlite",
    exportName,
    sourceRefs: [
      "packages/ibex-runtime-js/src/sqlite/module.js#exports:Database.enableCrSqlite",
    ],
  });
  Object.assign(sourceDescriptor.sourceMetadata, {
    exportName,
    enforcementRouteEvidence: {
      terminals: [
        "__exactCrSqlitePath",
        "__exactSqliteLoadCrSqlite",
        "__exactSqliteLoadExtension",
      ],
    },
  });
  recipe.fixtureId = "fixture.builtin.sqlite.enable-crsqlite.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives = [
    "__exactCrSqlitePath",
    "__exactSqliteLoadCrSqlite",
    "__exactSqliteLoadExtension",
  ].map((terminal) => ({
    terminalObservedKey: `native-op:${terminal}`,
    proofPaths: [`${recipe.terminalObservedKey} -> native-op:${terminal}`],
  }));
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceName: "export:exact_sqlite:Database.enableCrSqlite",
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "sqlite-cr-sqlite-enable",
      constructorExportName: "Database",
      methodName: "enableCrSqlite",
      moduleSpecifiers: ["bun:sqlite", "exact:sqlite"],
      databasePath: ":memory:",
      expectedRejectionFragment:
        "cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support.",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedDebuggerAbiCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const functionName = "ex_hermes_debugger_eval";
  const defaultSourceRef =
    `src/engine/hermes_runtime_debugger.cc#${functionName}`;
  const windowsSourceRef =
    `src/engine/hermes_runtime_platform_windows.cc#${functionName}`;
  const alternatives = [
    ["default", defaultSourceRef],
    ["windows", windowsSourceRef],
  ].map(([targetVariant, sourceRef]) => ({
    id: targetVariant,
    kind: "alternative",
    sourceRefs: [sourceRef],
    stubDisposition: "not-structurally-proven",
    targetVariant,
  }));
  const outputContract = (sourceRef) => ({
    bufferLengthPairs: [],
    functionName,
    language: "c++",
    outputChannels: [
      {
        kind: "pointer",
        ownership: {
          kind: "caller-owned",
          releaseFunction: "ex_hermes_free_string",
        },
        role: "return",
        selector: "[[return]]",
      },
    ],
    parameters: [],
    return: {
      kind: "pointer",
      ownership: {
        kind: "caller-owned",
        releaseFunction: "ex_hermes_free_string",
      },
      role: "value",
      type: { canonical: "char *", tokens: ["char", "*"] },
    },
    schema: "ibex/host-abi-output-contract/1",
    sourceRef,
    status: "resolved",
    unresolved: [],
  });
  const outputContracts = [
    outputContract(defaultSourceRef),
    outputContract(windowsSourceRef),
  ];
  const sourceDescriptor = {
    kind: "closed-debugger-abi",
    surfaceObservedKey: `host-abi:${functionName}`,
    functionName,
    selectedSourceRef: defaultSourceRef,
    targetTriple: "aarch64-apple-darwin",
    sourceRefs: [defaultSourceRef, windowsSourceRef],
    sourceMetadata: {
      alternatives,
      branches: structuredClone(alternatives),
      definitions: [
        ["default", defaultSourceRef],
        ["windows", windowsSourceRef],
      ].map(([targetVariant, sourceRef], index) => ({
        language: "c++",
        outputContract: structuredClone(outputContracts[index]),
        sourceRef,
        targetVariant,
        unsafe: false,
        weak: false,
      })),
      outputContracts,
      provenanceLimitation:
        "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures.",
    },
  };
  recipe.fixtureId = "fixture.debugger.eval.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "host-abi",
    surfaceName: functionName,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "debugger-abi-disabled",
      functionName,
      expectedCallResult: "null-pointer",
      expectedError:
        `debugger ABI ${functionName} is unavailable in the no-debugger exact target`,
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedSharedRuntimeGlobalCatalog({
  globalName = "CacheStorage",
  memberName = "open",
  route = "legacy-bootstrap",
  routes = ["legacy-bootstrap"],
  sourceKey = "global_module_loader",
  sourceKeys = undefined,
  sourceRefs = ["src/engine/bootstrap/module-loader.js#CacheStorage.open"],
  surfaceName = "global:CacheStorage.open",
  targetTriple = "aarch64-apple-darwin",
  targetVariant = "default",
} = {}) {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const exportName =
    memberName === null ? globalName : `${globalName}.${memberName}`;
  const branch = {
    branchKind: "single",
    id: targetVariant,
    kind: "single",
    route,
    routes,
    sourceRefs,
    targetVariant,
  };
  const sourceDescriptor = {
    kind: "closed-shared-runtime-global-absence",
    surfaceObservedKey: `native-op:${surfaceName}`,
    globalName,
    ...(memberName === null ? {} : { memberName }),
    targetTriple,
    sourceRefs,
    sourceMetadata: {
      branches: [structuredClone(branch)],
      exportName,
      globalName,
      installationBranches: [structuredClone(branch)],
      memberName,
      moduleSpecifiers: [],
      sourceKey,
      ...(sourceKeys === undefined ? {} : { sourceKeys }),
      surfaceType: "global-api",
    },
  };
  recipe.fixtureId = `fixture.shared-runtime.${exportName}.closed`;
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "shared-runtime-global-absence",
      globalName,
      memberName,
      expectedError: `armed shared runtime does not expose ${exportName}`,
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedArmedNativeGlobalCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceRefs = [
    "src/engine/hermes_runtime.cc#__exactExit",
    "src/engine/hermes_runtime.cc#jsi-global:__exactExit",
  ];
  const sourceDescriptor = {
    kind: "closed-armed-native-global-absence",
    surfaceObservedKey: "native-op:__exactExit",
    globalName: "__exactExit",
    targetTriple: "aarch64-apple-darwin",
    sourceRefs,
    sourceMetadata: {
      exportName: "__exactExit",
      globalName: "__exactExit",
      installationBranches: [
        {
          route: "native-jsi-global",
          sourceRefs,
          targetVariant: "default",
        },
      ],
      memberKinds: ["native-root"],
      memberName: null,
      publicInvocation: {
        arity: 1,
        globalName: "__exactExit",
        kind: "native-global-function",
        sourceRef: sourceRefs[1],
      },
      sourceKey: "native_jsi_global",
      surfaceType: "global-api",
    },
  };
  recipe.fixtureId = "fixture.armed-native.exact-exit.closed";
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "__exactExit",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "armed-native-global-absence",
      globalName: "__exactExit",
      memberName: null,
      expectedError: "armed runtime does not expose __exactExit",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedArmedWorkletGlobalCatalog({
  evaluated = false,
  targetTriple = "aarch64-apple-darwin",
} = {}) {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const globalName = evaluated ? "worklet" : "measure";
  const memberName = evaluated ? "capture" : null;
  const exportName =
    memberName === null ? globalName : `${globalName}.${memberName}`;
  const surfaceName = `global:${exportName}`;
  const route = evaluated ? "evaluated-native-script" : "native-jsi-global";
  const sourceRef = evaluated
    ? "src/engine/hermes_runtime_worklet.cc#embedded:kPrelude:worklet.capture"
    : "src/engine/hermes_runtime_worklet.cc#jsi-global:measure";
  const sourceMetadata = {
    exportName,
    globalName,
    installationBranches: [
      {
        route,
        routes: [route],
        sourceRefs: [sourceRef],
        targetVariant: "worklet",
      },
    ],
    memberKinds: [evaluated ? "source-derived-member" : "native-root"],
    memberName,
    sourceKey: evaluated ? "evaluated_native_script" : "native_jsi_global",
    surfaceType: "global-api",
    ...(evaluated
      ? {
          evaluatedScript: "kPrelude",
          sourceUrls: ["worklet-prelude.js"],
        }
      : {
          publicInvocation: {
            arity: 1,
            globalName,
            kind: "native-global-function",
            sourceRef,
          },
        }),
  };
  const sourceDescriptor = {
    kind: "closed-armed-native-global-absence",
    surfaceObservedKey: `native-op:${surfaceName}`,
    globalName,
    ...(memberName === null ? {} : { memberName }),
    targetTriple,
    sourceRefs: [sourceRef],
    sourceMetadata,
  };
  recipe.fixtureId = `fixture.armed-worklet.${exportName}.closed`;
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey = recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "armed-native-global-absence",
      globalName,
      memberName,
      expectedError: `armed runtime does not expose ${exportName}`,
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeClosedExactCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "closed-exact-unendowed-operation",
    surfaceObservedKey: "native-op:global:exact.invokeHostAsync",
    globalName: "exact",
    memberName: "invokeHostAsync",
    sourceRefs: [
      "src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync",
    ],
    sourceMetadata: {
      surfaceType: "global-api",
      sourceKey: "native_jsi_global",
      globalName: "exact",
      memberName: "invokeHostAsync",
      memberKinds: ["native-object-member"],
      exportName: "exact.invokeHostAsync",
    },
  };
  recipe.fixtureId = "fixture.exact.invoke-host-async.closed";
  recipe.edgeIds = ["edge.exact-closed"];
  recipe.terminalObservedKey = sourceDescriptor.surfaceObservedKey;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey = recipe.terminalObservedKey;
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    surfaceKind: "native-op",
    surfaceName: "global:exact.invokeHostAsync",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "exact-unendowed-operation",
      contextKind: "app",
      operationManifestDigest:
        "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA",
      endowedOperationIds: [7, 11],
      selectedOperationId: 8,
      expectedError: "exact.invokeHostAsync operation is not endowed",
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeStartupCatalog() {
  const catalog = structuredClone(completeClosedCatalog());
  const recipe = catalog.recipes[0];
  const requiredFacts = [
    "lockdown-flag-pinned",
    "eval-tamed",
    "object-prototype-frozen",
  ];
  const sourceDescriptor = {
    kind: "startup-loaded-engine-postcondition",
    surfaceName: "lockdown-install",
    postcondition: "lockdown-installed",
    requiredFacts,
    sourceRefs: ["src/engine/hermes_runtime.cc#lockdownJS"],
    sourceMetadata: null,
    environment: null,
  };
  Object.assign(recipe, {
    fixtureId: "fixture.startup.lockdown",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.startup"],
    implementationBranchIds: ["edge.startup.main"],
    enforcementBranchIds: ["edge.startup.main"],
    terminalObservedKey: "startup:lockdown-install",
  });
  recipe.expectedObservation.branchId = "edge.startup.main";
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey = recipe.terminalObservedKey;
  recipe.route.alternatives[0].proofPaths = [recipe.terminalObservedKey];
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(recipe.publicSurfaceProbe.invocation, {
    invocationSchema: "ibex/capsec-startup-surface-invocation/1",
    kind: "startup-loaded-engine",
    surfaceKind: "startup",
    surfaceName: "lockdown-install",
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "loaded-engine-startup",
      postcondition: "lockdown-installed",
      requiredFacts,
      environment: null,
    },
    expectedResult: "return",
  });
  catalog.summary.byScenario = { "non-capability": 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function startupRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "return",
        surfaceKind: "startup",
        surfaceName: invocation.surfaceName,
        mechanism: invocation.operation.kind,
        postcondition: invocation.operation.postcondition,
        engineExecuted: true,
        projectCodeExecuted: true,
        observedFacts: Object.fromEntries(
          invocation.operation.requiredFacts.map((fact) => [fact, true]),
        ),
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function closedRuntimeObservation(recipe, projectCodeExecuted = false) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const errorMessage =
    invocation.operation.kind === "cli-control"
      ? invocation.operation.expectedRejectionFragments.join("; ")
      : invocation.operation.kind === "loader-executable-file"
        ? invocation.operation.publicErrorMessage
        : invocation.operation.kind === "terminal-builtin-import"
          ? invocation.operation.moduleSpecifiers
              .map(
                (specifier) =>
                  `${specifier}: ${invocation.operation.expectedRejectionFragment} '${specifier}'`,
              )
              .join("\n")
        : invocation.operation.kind === "sqlite-extension-load"
          ? invocation.operation.moduleSpecifiers
              .map(
                (specifier) =>
                  `${specifier}: ${invocation.operation.expectedRejectionFragment}`,
              )
              .join("\n")
        : invocation.operation.kind === "sqlite-cr-sqlite-enable"
          ? invocation.operation.moduleSpecifiers
              .map(
                (specifier) =>
                  `${specifier}: ${invocation.operation.expectedRejectionFragment}`,
              )
              .join("\n")
        : invocation.operation.kind === "debugger-abi-disabled"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "shared-runtime-global-absence"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "armed-native-global-absence"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "process-event-closure"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "exact-unendowed-operation"
          ? invocation.operation.expectedError
        : invocation.operation.kind === "filesystem-unbound-mutation"
          ? `EPERM: ${invocation.operation.expectedErrorFragment}, ${invocation.operation.guardOperation}`
          : "production capability startup rejects closed environment controls: EX_SKIP_STARTUP_MODULE_LOADER";
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "closed",
        surfaceKind: invocation.surfaceKind,
        surfaceName: invocation.surfaceName,
        mechanism: invocation.operation.kind,
        errorName:
          invocation.operation.kind === "filesystem-unbound-mutation" ||
          invocation.operation.kind === "process-event-closure"
            ? "Error"
            : "ClosedSurface",
        errorMessage,
        ...(invocation.operation.kind === "loader-executable-file"
          ? { errorCode: invocation.operation.publicErrorCode }
          : invocation.operation.kind === "filesystem-unbound-mutation"
            ? {
                errorCode: invocation.operation.expectedErrorCode,
                callbackCalled:
                  invocation.operation.invocationStyle ===
                  "callback-deferred",
                filesystemBeforeDigest:
                  "sha256-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                filesystemAfterDigest:
                  "sha256-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
              }
            : invocation.operation.kind === "process-event-closure"
              ? {
                  methodName: invocation.operation.methodName,
                  argumentShape: invocation.operation.argumentShape,
                  eventName: invocation.operation.eventName,
                  errorCode: invocation.operation.expectedErrorCode,
                  errorPermission: invocation.operation.expectedPermission,
                  prototypeErrorName: "Error",
                  prototypeErrorCode:
                    invocation.operation.expectedErrorCode,
                  prototypeErrorPermission:
                    invocation.operation.expectedPermission,
                  prototypeErrorMessage: invocation.operation.expectedError,
                  descriptorPinned: true,
                  prototypeDescriptorPinned: true,
                  backingStateHidden: true,
                }
            : {}),
        engineExecuted:
          invocation.operation.kind === "loader-executable-file" ||
          invocation.operation.kind === "terminal-builtin-import" ||
          invocation.operation.kind === "sqlite-extension-load" ||
          invocation.operation.kind === "sqlite-cr-sqlite-enable" ||
          invocation.operation.kind === "debugger-abi-disabled" ||
          invocation.operation.kind === "shared-runtime-global-absence" ||
          invocation.operation.kind === "armed-native-global-absence" ||
          invocation.operation.kind === "process-event-closure" ||
          invocation.operation.kind === "exact-unendowed-operation" ||
          invocation.operation.kind === "filesystem-unbound-mutation",
        projectCodeExecuted:
          invocation.operation.kind === "process-event-closure"
            ? true
            : projectCodeExecuted,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function processLifecycleNoEffectObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const operation = invocation.operation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "no-effect",
        surfaceKind: invocation.surfaceKind,
        surfaceName: invocation.surfaceName,
        mechanism: operation.kind,
        scenario: operation.scenario,
        methodName: operation.methodName,
        argumentShape: operation.argumentShape,
        eventName: operation.eventName,
        logicalBranchId: operation.logicalBranchId,
        directReturnKind: operation.expectedReturnKind,
        prototypeReturnKind: operation.expectedReturnKind,
        listenerCount: 0,
        listenersEmpty: true,
        rawListenersEmpty: true,
        listenerCalled: false,
        descriptorPinned: true,
        prototypeDescriptorPinned: true,
        backingStateHidden: true,
        engineExecuted: true,
        projectCodeExecuted: true,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function processUmaskObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const operation = invocation.operation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "closed",
        surfaceKind: invocation.surfaceKind,
        surfaceName: invocation.surfaceName,
        mechanism: operation.kind,
        argumentCases: operation.argumentCases.map(({ id }) => ({
          id,
          errorName: "Error",
          errorCode: operation.expectedErrorCode,
          errorPermission: operation.expectedPermission,
          errorMessage: operation.expectedError,
        })),
        errorName: "Error",
        errorMessage: operation.expectedError,
        descriptorPinned: true,
        backingStateHidden: true,
        replacementDenied: true,
        engineExecuted: true,
        projectCodeExecuted: true,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function processSharedStateObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const operation = invocation.operation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "closed",
        surfaceKind: invocation.surfaceKind,
        surfaceName: invocation.surfaceName,
        mechanism: operation.kind,
        memberName: operation.memberName,
        memberForm: operation.memberForm,
        accessCases: operation.accessCases.map((id) => ({
          id,
          errorName: "Error",
          errorCode: operation.expectedErrorCode,
          errorPermission: operation.expectedPermission,
          errorMessage: operation.expectedError,
        })),
        errorName: "Error",
        errorCode: operation.expectedErrorCode,
        errorPermission: operation.expectedPermission,
        errorMessage: operation.expectedError,
        descriptorPinned: true,
        prototypeDescriptorPinned: true,
        backingStateHidden: true,
        replacementDenied: true,
        engineExecuted: true,
        projectCodeExecuted: true,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function processReportMemberObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const operation = invocation.operation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "closed",
        surfaceKind: invocation.surfaceKind,
        surfaceName: invocation.surfaceName,
        mechanism: operation.kind,
        memberName: operation.memberName,
        memberPath: operation.memberPath,
        memberForm: operation.memberForm,
        blockedAtMember: operation.blockedAtMember,
        accessCases: operation.accessCases.map((id) => ({
          id,
          errorName: "Error",
          errorCode: operation.expectedErrorCode,
          errorPermission: operation.expectedPermission,
          errorMessage: operation.expectedError,
        })),
        errorName: "Error",
        errorCode: operation.expectedErrorCode,
        errorPermission: operation.expectedPermission,
        errorMessage: operation.expectedError,
        descriptorPinned: true,
        prototypeMemberAbsent: true,
        backingStateHidden: true,
        replacementDenied: true,
        engineExecuted: true,
        projectCodeExecuted: true,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function targetAbsenceCatalog() {
  const recipe = {
    fixtureId: "fixture.native.target.absent",
    planDigest: "sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
    classification: "effects",
    scenario: "absent",
    edgeIds: ["edge.public"],
    implementationBranchIds: [],
    enforcementBranchIds: [],
    actionIds: ["sys:read"],
    terminalObservedKey: "native-op:__exactPlatformOnly",
    expectedObservation: { kind: "target-absence", target },
    route: {
      surfaceObservedKeys: [],
      alternatives: [],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "target-absence-probe",
      surfaceObservedKey: "native-op:__exactPlatformOnly",
      command: [
        "ibex",
        "capsec-public-fixture",
        "fixture.native.target.absent",
      ],
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "native-global-function",
        globalName: "__exactPlatformOnly",
        sourceDescriptor: {
          arity: 0,
          globalName: "__exactPlatformOnly",
          kind: "native-global-function",
          sourceRef: "src/engine/platform.cc#jsi-global:__exactPlatformOnly",
        },
        arguments: [],
        setup: [],
        expectedResult: "absent",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.public"],
        expectedActionIds: ["sys:read"],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
    recipe.publicSurfaceProbe.invocation.sourceDescriptor,
  );
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { absent: 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeCallbackCatalog() {
  const catalog = structuredClone(completeCatalog());
  const recipe = catalog.recipes[0];
  const sourceDescriptor = {
    kind: "callback-security-invariant",
    proofScope: "source-bound-rationale-invariant",
    scenario: "generation-recheck",
    rationaleId: "callback-attribution-carrier",
    surfaceObservedKey: "native-op:__exactCallbackCarrier",
    edgeId: "edge.callback",
    branchId: "edge.callback.main",
    sourceRefs: ["src/engine/hermes_runtime.cc#callback-carrier"],
    coverageEdge: { id: "edge.callback" },
    implementationBranch: { branchId: "edge.callback.main" },
    liveSurface: {
      kind: "native-op",
      name: "__exactCallbackCarrier",
    },
    executionMechanism: "scheduled-public-environment-revocation-recheck",
    auxiliaryDecisionEdgeId: "edge.callback-terminal",
  };
  Object.assign(recipe, {
    fixtureId: "fixture.callback.generation-recheck",
    classification: "non-capability",
    scenario: "generation-recheck",
    edgeIds: ["edge.callback"],
    implementationBranchIds: ["edge.callback.main"],
    enforcementBranchIds: ["edge.callback.main"],
    actionIds: [],
    terminalObservedKey: "native-op:__exactCallbackCarrier",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.callback.main",
    },
    route: {
      surfaceObservedKeys: ["native-op:__exactCallbackCarrier"],
      alternatives: [],
      ambiguousCallees: [],
    },
  });
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey: recipe.terminalObservedKey,
    command: ["cargo", "test", "capsec_public_callback_invariant_batch"],
    invocation: {
      invocationSchema: "ibex/capsec-callback-invariant-invocation/1",
      kind: "callback-security-invariant",
      scenario: recipe.scenario,
      surfaceKind: "native-op",
      surfaceName: "__exactCallbackCarrier",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      expectedResult: "invariant-passed",
      expectedTypedDecisionCount: 3,
      expectedTypedStages: ["requested", "commit", "requested"],
      expectedTypedOutcomes: ["allow", "allow", "deny"],
      expectedTypedReasons: [
        "dynamic-session",
        "dynamic-session",
        "missing-authority",
      ],
      allowedCoverageEdgeIds: ["edge.callback-terminal"],
      expectedActionIds: ["env:read"],
    },
  });
  catalog.summary.byScenario = { "generation-recheck": 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completeExactCallbackCatalog() {
  const catalog = structuredClone(completeCallbackCatalog());
  const recipe = catalog.recipes[0];
  const surfaceObservedKey = "callback:exact-host-call-async-resolve";
  const sourceRefs = [
    "src/engine/hermes_runtime.cc#ex_hermes_resolve_exact_host_call",
  ];
  const sourceDescriptor = {
    kind: "callback-security-invariant",
    proofScope: "source-bound-exact-mechanism",
    scenario: "non-capability",
    rationaleId: "callback-attribution-carrier",
    surfaceObservedKey,
    edgeId: "edge.exact-callback",
    branchId: "edge.exact-callback.main",
    sourceRefs,
    coverageEdge: {
      id: "edge.exact-callback",
      classification: "non-capability",
    },
    implementationBranch: {
      branchId: "edge.exact-callback.main",
      sourceRefs,
    },
    liveSurface: {
      observedKey: surfaceObservedKey,
      kind: "callback",
      name: "exact-host-call-async-resolve",
      sourceRefs,
    },
    executionMechanism: "exact-host-call-round-trip",
    auxiliaryDecisionEdgeId: null,
  };
  Object.assign(recipe, {
    fixtureId: "fixture.exact-callback.non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.exact-callback"],
    implementationBranchIds: ["edge.exact-callback.main"],
    enforcementBranchIds: ["edge.exact-callback.main"],
    terminalObservedKey: surfaceObservedKey,
  });
  recipe.expectedObservation.branchId = "edge.exact-callback.main";
  recipe.route.surfaceObservedKeys = [surfaceObservedKey];
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey,
    invocation: {
      invocationSchema: "ibex/capsec-callback-invariant-invocation/1",
      kind: "callback-security-invariant",
      scenario: "non-capability",
      surfaceKind: "callback",
      surfaceName: "exact-host-call-async-resolve",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      expectedResult: "invariant-passed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      expectedTypedOutcomes: [],
      expectedTypedReasons: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  });
  catalog.summary.byScenario = { "non-capability": 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function exactCallbackRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      scenario: invocation.scenario,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "callback-security-invariant",
        scenario: "non-capability",
        outcome: "passed",
        checks: {
          executionMechanism: "exact-host-call-round-trip",
          setterInstalled: true,
          immutableCapability: true,
          genericBridgeAbsent: true,
          callbackExecuted: true,
          operationId: 7,
          payloadLength: 3,
          completion: "9,8",
          completionTargetsConsumed: 1,
          completionCallbacksQueued: 1,
          completionCallbacksDelivered: 1,
          singleUseCompletion: true,
        },
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function completeStartupEnvironmentCatalog(scenario = "allow") {
  const catalog = structuredClone(completeCatalog());
  const recipe = catalog.recipes[0];
  const selectedBranch = structuredClone(
    coverage.edges
      .find((edge) => edge.id === "edge.startup-env-node-debug")
      .logicalBranches.find((branch) => branch.id === "absent"),
  );
  const sourceDescriptor = {
    kind: "startup-environment-source",
    surfaceObservedKey: "startup:env:NODE_DEBUG",
    environmentName: "NODE_DEBUG",
    sourceRef: "src/builtins/http.js#process.env:NODE_DEBUG:read",
    liveSourceRefs: [
      "src/builtins/http.js#process.env:NODE_DEBUG:read",
      "src/builtins/util.js#process.env:NODE_DEBUG:read",
    ],
    carrierEdgeId: "edge.startup-env-node-debug",
    implementationBranchIds: ["edge.startup-env-node-debug.main"],
    enforcementBranchIds: ["enforcement.startup-env-node-debug"],
    selectedBranch,
    executionMechanism: "builtin-module-load",
    moduleSpecifier: "node:http",
    preloadModuleSpecifiers: ["node:events", "node:stream", "node:util"],
    observedEnvironmentNames: ["NODE_DEBUG"],
    observedEnvironmentAccesses: ["NODE_DEBUG"],
    principalMode: scenario === "deny" ? "package-denied" : "root-authorized",
    auxiliaryDecisionEdgeId: "edge.callback-terminal",
  };
  Object.assign(recipe, {
    fixtureId: `fixture.startup.env.node-debug.absent.${scenario}`,
    scenario,
    edgeIds: ["edge.startup-env-node-debug"],
    implementationBranchIds: ["edge.startup-env-node-debug.main"],
    enforcementBranchIds: ["enforcement.startup-env-node-debug"],
    actionIds: ["env:read"],
    terminalObservedKey: "startup:env:NODE_DEBUG",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "enforcement.startup-env-node-debug",
    },
    route: {
      surfaceObservedKeys: ["startup:env:NODE_DEBUG"],
      alternatives: [
        {
          terminalObservedKey: "startup:env:NODE_DEBUG",
          proofPaths: ["startup:env:NODE_DEBUG"],
        },
      ],
      ambiguousCallees: [],
    },
  });
  const denial = scenario === "deny";
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey: recipe.terminalObservedKey,
    command: ["cargo", "test", "capsec_public_startup_environment_batch"],
    invocation: {
      invocationSchema: "ibex/capsec-startup-environment-invocation/1",
      kind: "startup-environment-source",
      scenario,
      surfaceKind: "startup",
      surfaceName: "env:NODE_DEBUG",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "builtin-module-load",
        moduleSpecifier: "node:http",
        preloadModuleSpecifiers: ["node:events", "node:stream", "node:util"],
        observedEnvironmentNames: ["NODE_DEBUG"],
        observedEnvironmentAccesses: ["NODE_DEBUG"],
        environment: { name: "NODE_DEBUG", presence: "absent" },
        principalMode: sourceDescriptor.principalMode,
      },
      expectedResult: "return",
      expectedTypedDecisionCount: denial ? 1 : 2,
      expectedTypedStages: denial ? ["requested"] : ["requested", "commit"],
      expectedTypedOutcomes: denial ? ["deny"] : ["allow", "allow"],
      expectedTypedReasons: denial
        ? ["principal-denial"]
        : ["static-floor", "static-floor"],
      allowedCoverageEdgeIds: ["edge.callback-terminal"],
      expectedActionIds: ["env:read"],
      expectedResourceNames: ["NODE_DEBUG"],
    },
  });
  catalog.summary.byScenario = { [scenario]: 1 };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function completePairedStartupEnvironmentCatalog(scenario = "allow") {
  const catalog = completeStartupEnvironmentCatalog(scenario);
  const recipe = catalog.recipes[0];
  const invocation = recipe.publicSurfaceProbe.invocation;
  const sourceDescriptor = invocation.sourceDescriptor;
  const environmentName = "EXACT_PIPELINE_DEBUG";
  const observedEnvironmentNames = [
    "EXACT_PIPELINE_DEBUG",
    "EXACT_PIPELINE_STATE_DEBUG",
  ];
  const observedEnvironmentAccesses = [
    "EXACT_PIPELINE_DEBUG",
    "EXACT_PIPELINE_STATE_DEBUG",
  ];
  const preloadModuleSpecifiers = [
    "node:events",
    "node:string_decoder",
    "node:util",
  ];
  recipe.fixtureId = `fixture.startup.env.exact-pipeline-debug.absent.${scenario}`;
  recipe.terminalObservedKey = `startup:env:${environmentName}`;
  recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
  recipe.route.alternatives[0].terminalObservedKey =
    recipe.terminalObservedKey;
  recipe.route.alternatives[0].proofPaths = [recipe.terminalObservedKey];
  recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
  Object.assign(sourceDescriptor, {
    surfaceObservedKey: recipe.terminalObservedKey,
    environmentName,
    sourceRef:
      "src/builtins/stream.js#process.env:EXACT_PIPELINE_DEBUG:read",
    liveSourceRefs: [
      "src/builtins/stream.js#process.env:EXACT_PIPELINE_DEBUG:read",
    ],
    moduleSpecifier: "node:stream",
    preloadModuleSpecifiers,
    observedEnvironmentNames,
    observedEnvironmentAccesses,
  });
  sourceDescriptor.selectedBranch.when = [
    {
      fact: "environment.startup.exact_pipeline_debug",
      equals: "absent",
    },
  ];
  invocation.surfaceName = `env:${environmentName}`;
  invocation.sourceDescriptorDigest = taggedDigest(sourceDescriptor);
  Object.assign(invocation.operation, {
    moduleSpecifier: "node:stream",
    preloadModuleSpecifiers,
    observedEnvironmentNames,
    observedEnvironmentAccesses,
    environment: { name: environmentName, presence: "absent" },
  });
  const denial = scenario === "deny";
  const stages = denial ? ["requested"] : ["requested", "commit"];
  const outcomes = denial ? ["deny"] : ["allow", "allow"];
  const reasons = denial
    ? ["principal-denial"]
    : ["static-floor", "static-floor"];
  invocation.expectedTypedStages = observedEnvironmentAccesses.flatMap(
    () => stages,
  );
  invocation.expectedTypedOutcomes = observedEnvironmentAccesses.flatMap(
    () => outcomes,
  );
  invocation.expectedTypedReasons = observedEnvironmentAccesses.flatMap(
    () => reasons,
  );
  invocation.expectedTypedDecisionCount =
    invocation.expectedTypedStages.length;
  invocation.expectedResourceNames = observedEnvironmentNames;
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function startupEnvironmentRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const denial = invocation.scenario === "deny";
  const actor = denial
    ? {
        kind: "package",
        name: "image-lib",
        integrity: `sha256-${"A".repeat(43)}`,
        locator: "image-lib@2.4.1",
      }
    : { kind: "root", identity: "project-root" };
  const constrainedPrincipals = denial
    ? [{ kind: "root", identity: "project-root" }, actor]
    : [actor];
  const decisionsPerResource = denial ? 1 : 2;
  const decision = (stage, index) => ({
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `fixture-startup-environment-${stage}`,
      atomicityGroup: "edge.callback-terminal.decision",
      combination: "conjunction",
      context: {
        stage,
        actor,
        constrainedPrincipals,
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: "env:read",
          effectOwner: actor,
          resource: {
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "principal-overlay",
              name:
                invocation.operation.observedEnvironmentAccesses[
                  Math.floor(index / decisionsPerResource)
                ],
            },
            valueOrigin: "principal-overlay",
          },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: "edge.callback-terminal",
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: {
      outcome: invocation.expectedTypedOutcomes[index],
      evidence: [
        {
          effectIndex: 0,
          principal: actor,
          reason: invocation.expectedTypedReasons[index],
        },
      ],
    },
  });
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      scenario: invocation.scenario,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "return",
        surfaceKind: "startup",
        surfaceName: invocation.surfaceName,
        mechanism: invocation.operation.kind,
        moduleSpecifier: invocation.operation.moduleSpecifier,
        environmentName: invocation.operation.environment.name,
        observedEnvironmentNames:
          invocation.operation.observedEnvironmentNames,
        observedEnvironmentAccesses:
          invocation.operation.observedEnvironmentAccesses,
        environmentPresence: "absent",
        principalMode: invocation.operation.principalMode,
        engineExecuted: true,
        projectCodeExecuted: true,
        sourceOutcome: denial ? "denied-as-absent" : "source-observed",
        errorName: null,
        errorMessage: null,
      },
    },
    legacyObservationCount: 0,
    typedDecisions: invocation.expectedTypedStages.map(decision),
  };
}

function targetAbsenceObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      globalName: invocation.globalName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: { kind: "missing", globalName: invocation.globalName },
      executionProof: { kind: "exact-global-absence", bodyEntered: false },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function globalReadCatalog() {
  const recipe = {
    fixtureId: "fixture.global.read.non-capability",
    planDigest: "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
    classification: "non-capability",
    scenario: "non-capability",
    edgeIds: ["edge.read"],
    implementationBranchIds: ["edge.read.all"],
    enforcementBranchIds: ["edge.read.all"],
    actionIds: [],
    terminalObservedKey: "native-op:global:Exact.version",
    expectedObservation: {
      kind: "enforcement-branch",
      branchId: "edge.read.all",
    },
    route: {
      surfaceObservedKeys: ["native-op:global:Exact.version"],
      alternatives: [
        {
          terminalObservedKey: "native-op:global:Exact.version",
          proofPaths: ["native-op:global:Exact.version"],
        },
      ],
      ambiguousCallees: [],
    },
    adapterProbe: null,
    publicSurfaceProbe: {
      kind: "public-surface-invocation",
      surfaceObservedKey: "native-op:global:Exact.version",
      command: ["ibex", "capsec-public-fixture", "fixture.global.read"],
      invocation: {
        invocationSchema: "ibex/capsec-native-global-invocation/1",
        kind: "global-property-read",
        globalName: "Exact",
        sourceDescriptor: {
          kind: "global-property-read",
          sourceKey: "shared_runtime",
          exportName: "Exact.version",
          globalName: "Exact",
          memberKinds: ["object-property"],
          sourceRefs: [
            "packages/ibex-runtime-js/src/bootstrap.ts#Exact.version",
          ],
          valueShape: "data",
          access: {
            kind: "source-proven-property-path",
            path: ["Exact", "version"],
          },
        },
        arguments: [],
        requiredFloor: [],
        setup: [],
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.read"],
        expectedActionIds: [],
      },
    },
    status: "fully-executable",
    residualReasons: [],
  };
  recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
    recipe.publicSurfaceProbe.invocation.sourceDescriptor,
  );
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/1",
    profile: "ibex/capsec/1",
    target,
    recipes: [recipe],
    summary: {
      requiredFixtures: 1,
      fullyExecutableFixtures: 1,
      internallyVerifiedFixtures: 0,
      adapterExecutableFixtures: 0,
      unresolvedFixtures: 0,
      byScenario: { "non-capability": 1 },
      residualReasons: {},
    },
  };
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function globalReadObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      globalName: invocation.globalName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "return",
        globalName: invocation.globalName,
        valueType: "string",
        ownerDepths: [0, 0],
        cleanup: "none",
      },
      executionProof: { kind: "global-property-read", bodyEntered: true },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function privateCwdFacadeCatalog() {
  const catalog = globalReadCatalog();
  const recipe = catalog.recipes[0];
  const publicDisposition = rootGlobalDispositions.find(
    (row) =>
      row.observedKey === "native-op:global:process.cwd" &&
      row.branch.activation === "always",
  );
  const privateDisposition = rootGlobalDispositions.find(
    (row) =>
      row.observedKey === "native-op:__exactGetCwd" &&
      row.branch.activation === "always",
  );
  if (!publicDisposition || !privateDisposition) {
    throw new Error("private cwd facade dispositions are unavailable");
  }
  const sourceDescriptor = {
    kind: "native-global-function",
    globalName: "__exactGetCwd",
    arity: 0,
    sourceRef: "src/engine/hermes_runtime.cc#jsi-global:__exactGetCwd",
  };
  const publicAccess = {
    kind: "captured-private-global-function",
    observedKey: "native-op:global:process.cwd",
    installId: publicDisposition.installId,
    path: ["process", "cwd"],
    sourceRefs: structuredClone(publicDisposition.branch.sourceRefs),
    privateTerminal: {
      observedKey: "native-op:__exactGetCwd",
      installId: privateDisposition.installId,
      privateConsumer: "trusted-path-process-builtins",
      liveExpectation: "absent",
    },
    expectedDenyMessageFragment: "filesystem policy denied",
  };
  recipe.fixtureId = "fixture.native.private-cwd-facade.non-capability";
  recipe.terminalObservedKey = "native-op:__exactGetCwd";
  recipe.route.surfaceObservedKeys = ["native-op:__exactGetCwd"];
  recipe.route.alternatives = [
    {
      terminalObservedKey: "native-op:__exactGetCwd",
      proofPaths: ["native-op:global:process.cwd -> native-op:__exactGetCwd"],
    },
  ];
  Object.assign(recipe.publicSurfaceProbe, {
    surfaceObservedKey: "native-op:__exactGetCwd",
    invocation: {
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "private-native-facade-function",
      globalName: "__exactGetCwd",
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      publicAccess,
      publicAccessDigest: taggedDigest(publicAccess),
      arguments: [],
      requiredFloor: [],
      setup: [],
      expectedResult: "return",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  });
  catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
  return catalog;
}

function privateCwdFacadeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      globalName: invocation.globalName,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: { kind: "return", valueType: "string" },
      executionProof: { kind: "native-return", bodyEntered: true },
    },
    legacyObservationCount: 0,
    typedDecisions: [],
  };
}

function callbackRuntimeObservation(recipe) {
  const invocation = recipe.publicSurfaceProbe.invocation;
  const auxiliaryEdgeId = invocation.sourceDescriptor.auxiliaryDecisionEdgeId;
  const packagePrincipal = {
    kind: "package",
    name: "image-lib",
    integrity: `sha256-${"A".repeat(43)}`,
    locator: "image-lib@2.4.1",
  };
  const generationsBefore = { negative: 0, dynamic: 1, handle: 0 };
  const generationsAfter = { negative: 1, dynamic: 2, handle: 0 };
  const decision = (stage, outcome, reason, suffix, generations) => ({
    decisionSet: {
      decisionSetSchema: "ibex/capsec-decision-set/1",
      operationId: `fixture-callback-${suffix}`,
      atomicityGroup: `${auxiliaryEdgeId}.decision`,
      combination: "conjunction",
      context: {
        stage,
        actor: packagePrincipal,
        constrainedPrincipals: [packagePrincipal],
        presentedHandleIds: [],
      },
      effects: [
        {
          cap: "env:read",
          effectOwner: packagePrincipal,
          resource: {
            kind: "environment-occurrence",
            requested: {
              kind: "environment-name",
              target: "broker-base",
              name: "PATH",
            },
            valueOrigin: "broker-base",
          },
        },
      ],
    },
    gates: [
      {
        coverageEdgeId: auxiliaryEdgeId,
        targetCell: "complete",
        definitionAndEdgePredicatesSatisfied: true,
      },
    ],
    evidence: {
      outcome,
      generations,
      evidence: [{ principal: packagePrincipal, reason }],
    },
  });
  return {
    observationSchema: "ibex/capsec-runtime-public-observation/1",
    invocation: {
      invocationSchema: invocation.invocationSchema,
      kind: invocation.kind,
      surfaceObservedKey: recipe.publicSurfaceProbe.surfaceObservedKey,
      surfaceKind: invocation.surfaceKind,
      surfaceName: invocation.surfaceName,
      scenario: invocation.scenario,
      sourceDescriptorDigest: invocation.sourceDescriptorDigest,
      result: {
        kind: "callback-security-invariant",
        scenario: invocation.scenario,
        outcome: "passed",
        checks: {
          callbackExecuted: true,
          actualPrincipal: packagePrincipal,
          generationsBefore,
          generationsAfter,
          generationAdvanced: true,
          scheduledDecisionRechecked: true,
          runtimeNonce: "u64:17",
        },
      },
    },
    legacyObservationCount: 0,
    typedDecisions: [
      decision(
        "requested",
        "allow",
        "dynamic-session",
        "before-requested",
        generationsBefore,
      ),
      decision(
        "commit",
        "allow",
        "dynamic-session",
        "before-commit",
        generationsBefore,
      ),
      decision(
        "requested",
        "deny",
        "missing-authority",
        "after-requested",
        generationsAfter,
      ),
    ],
  };
}

describe("CapSec public-surface promotion evidence", () => {
  test("merges only exact, engine-bound public fixture batches", () => {
    const catalog = completeCatalog();
    const execution = buildPublicFixtureEvidence({
      recipe: catalog.recipes[0],
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: runtimeObservation(catalog.recipes[0]),
      coverage,
    });
    const batch = {
      publicBatchEvidenceSchema: "ibex/capsec-public-batch-evidence/1",
      recipeCatalogDigest: catalog.recipeCatalogDigest,
      loadedEngineIdentity: engine,
      executions: [execution],
    };
    expect(
      mergePublicBatchExecutions({
        batches: [
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toEqual([execution]);

    expect(() =>
      mergePublicBatchExecutions({
        batches: [
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
          { batch, expectedFixtureIds: [catalog.recipes[0].fixtureId] },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toThrow(/duplicate public execution/);
    expect(() =>
      mergePublicBatchExecutions({
        batches: [
          {
            batch: { ...batch, executions: [] },
            expectedFixtureIds: [catalog.recipes[0].fixtureId],
          },
        ],
        recipeCatalog: catalog,
        loadedEngineIdentity: engine,
      }),
    ).toThrow(/missing, duplicates, or adds/);
  });

  test("accepts one exact public invocation for every complete recipe", () => {
    const catalog = completeCatalog();
    const artifact = completeArtifact(catalog);
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog, {
        target,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        engine,
        coverage,
        expectedFixtureIds: ["fixture.public.allow"],
      }),
    ).not.toThrow();
  });

  test("accepts only exact authority-free global callable source completions", () => {
    const { recipe, observation } = globalCallableFixture();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const namedThrow = structuredClone(observation);
    Object.assign(namedThrow.invocation.result, {
      sourceCompletionKind: "throw",
      rawOutput: {
        kind: "throw",
        rawValueShape: "throw",
        value: null,
        errorCode: null,
        errorName: "TypeError",
      },
    });
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: namedThrow,
        coverage,
      }),
    ).not.toThrow();

    const anonymousThrow = structuredClone(namedThrow);
    delete anonymousThrow.invocation.result.rawOutput.errorName;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: anonymousThrow,
        coverage,
      }),
    ).toThrow(/did not prove the exact callable source completion/);

    const authorityBearing = structuredClone(recipe);
    authorityBearing.publicSurfaceProbe.invocation.route.authority = [
      {
        kind: "typed-effect",
        cap: "env:read",
        resourceKind: "environment-occurrence",
        requested: {
          kind: "environment-name",
          target: "broker-base",
          name: "WPT_SERVER_URL",
        },
      },
    ];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: authorityBearing,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/global callable runtime invocation descriptor drift/);

    const incompleteCleanup = structuredClone(observation);
    incompleteCleanup.invocation.result.cleanupPerformed = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: incompleteCleanup,
        coverage,
      }),
    ).toThrow(/did not prove the exact callable source completion/);

    const staleCompletion = structuredClone(observation);
    staleCompletion.invocation.completion.status = "pending";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: staleCompletion,
        coverage,
      }),
    ).toThrow(/global callable runtime invocation descriptor drift/);

    const substitutedDescriptor = structuredClone(observation);
    substitutedDescriptor.invocation.globalName = "AbortSignal";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: substitutedDescriptor,
        coverage,
      }),
    ).toThrow(/global callable runtime invocation descriptor drift/);
  });

  test("accepts only ambient fs:list traversal surplus for open-then-act builtins", () => {
    for (const exportName of [
      "appendFileSync",
      "mkdirSync",
      "readFileSync",
      "readlinkSync",
      "truncateSync",
    ]) {
      for (const scenario of ["allow", "deny"]) {
        const { recipe, observation } = openThenActFixture(
          scenario,
          exportName,
        );
        expect(() =>
          buildPublicFixtureEvidence({
            recipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: observation,
            coverage,
          }),
        ).not.toThrow();
      }
    }

    const wrongCapability = openThenActFixture();
    wrongCapability.observation.typedDecisions[0].decisionSet.effects[0].cap =
      "network:connect";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongCapability.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongCapability.observation,
        coverage,
      }),
    ).toThrow(/typed stages, actions, or gates drifted/);

    const wrongString = openThenActFixture("allow", "readlinkSync");
    wrongString.observation.invocation.result.stringValue =
      "substituted-target.txt";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongString.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongString.observation,
        coverage,
      }),
    ).toThrow(/string return did not match/);

    const mixedTraversal = openThenActFixture();
    mixedTraversal.observation.typedDecisions[1].decisionSet.effects.push(
      structuredClone(
        mixedTraversal.observation.typedDecisions[0].decisionSet.effects[0],
      ),
    );
    mixedTraversal.observation.typedDecisions[1].gates.push(
      structuredClone(mixedTraversal.observation.typedDecisions[1].gates[0]),
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: mixedTraversal.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: mixedTraversal.observation,
        coverage,
      }),
    ).toThrow(/mixed into an operation decision/);

    const wrongTraversal = openThenActFixture();
    wrongTraversal.observation.typedDecisions[0].decisionSet.effects[0].resource =
      {
        kind: "system-info-occurrence",
        requested: { kind: "system-info", name: "platform" },
      };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongTraversal.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongTraversal.observation,
        coverage,
      }),
    ).toThrow(/not an ambient open traversal/);
  });

  test("binds openSync success to an exact numeric result and descriptor cleanup", () => {
    const accepted = openSyncFixture();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: accepted.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: accepted.observation,
        coverage,
      }),
    ).not.toThrow();

    const substitutedCleanup = openSyncFixture();
    substitutedCleanup.observation.invocation.result.cleanup =
      "descriptor-left-open";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: substitutedCleanup.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: substitutedCleanup.observation,
        coverage,
      }),
    ).toThrow(/descriptor cleanup did not match/);

    const missingCleanup = openSyncFixture();
    delete missingCleanup.observation.invocation.result.cleanup;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: missingCleanup.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingCleanup.observation,
        coverage,
      }),
    ).toThrow(/cleanup result has unknown or missing fields/);

    const unauthoredCleanup = openSyncFixture();
    delete unauthoredCleanup.recipe.publicSurfaceProbe.invocation
      .expectedCleanup;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: unauthoredCleanup.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: unauthoredCleanup.observation,
        coverage,
      }),
    ).toThrow(/malformed builtin descriptor cleanup expectation/);
  });

  test("binds opendirSync success to an exact path and closed directory object", () => {
    const accepted = opendirSyncFixture();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: accepted.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: accepted.observation,
        coverage,
      }),
    ).not.toThrow();

    const substitutedPath = opendirSyncFixture();
    substitutedPath.observation.invocation.result.path =
      "/project/substituted-directory";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: substitutedPath.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: substitutedPath.observation,
        coverage,
      }),
    ).toThrow(/descriptor cleanup did not match/);

    const missingCleanup = opendirSyncFixture();
    delete missingCleanup.observation.invocation.result.cleanup;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: missingCleanup.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingCleanup.observation,
        coverage,
      }),
    ).toThrow(/cleanup result has unknown or missing fields/);

    const unauthoredCleanup = opendirSyncFixture();
    delete unauthoredCleanup.recipe.publicSurfaceProbe.invocation
      .expectedCleanup;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: unauthoredCleanup.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: unauthoredCleanup.observation,
        coverage,
      }),
    ).toThrow(/malformed builtin descriptor cleanup expectation/);
  });

  test("binds realpath helper decisions without replacing its allow terminal", () => {
    for (const scenario of ["allow", "deny"]) {
      const { recipe, observation } = realpathAuxiliaryFixture(scenario);
      const execution = buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      });
      expect(execution.evidence.terminalObservedKey).toBe(
        scenario === "deny"
          ? "builtin:export:node_fs:realpathSync"
          : "native-op:__exactRealpath",
      );
    }

    const wrongAuxiliaryAction = realpathAuxiliaryFixture();
    wrongAuxiliaryAction.observation.typedDecisions[0].decisionSet.effects[0].cap =
      "fs:list";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongAuxiliaryAction.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongAuxiliaryAction.observation,
        coverage,
      }),
    ).toThrow(/auxiliary decision observed an unbound action/);

    const wrongDenialTerminal = realpathAuxiliaryFixture("deny");
    const descriptor =
      wrongDenialTerminal.recipe.publicSurfaceProbe.invocation.sourceDescriptor;
    descriptor.denialTerminalEdgeId = "edge.realpath-cwd";
    wrongDenialTerminal.recipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(descriptor);
    wrongDenialTerminal.observation.invocation.sourceDescriptorDigest =
      taggedDigest(descriptor);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongDenialTerminal.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongDenialTerminal.observation,
        coverage,
      }),
    ).toThrow(/unsupported effect-builtin auxiliary carrier/);
  });

  test("binds existsSync denial to an exact false return", () => {
    for (const scenario of ["allow", "deny"]) {
      const { recipe, observation } = existsSyncBooleanFixture(scenario);
      const execution = buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      });
      expect(execution.evidence.terminalObservedKey).toBe(
        "native-op:__exactAccess",
      );
    }

    const falsePositive = existsSyncBooleanFixture("deny");
    falsePositive.observation.invocation.result.booleanValue = true;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: falsePositive.recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: falsePositive.observation,
        coverage,
      }),
    ).toThrow(/boolean return did not match its authored value/);
  });

  test("accepts only source-bound fresh-engine effect builtin imports", () => {
    for (const [scenario, moduleSpecifier] of [
      ["allow", "node:util"],
      ["deny", "node:util"],
      ["allow", "node:util/types"],
    ]) {
      const recipe = effectBuiltinModuleImportRecipe(
        scenario,
        moduleSpecifier,
      );
      expect(() =>
        buildPublicFixtureEvidence({
          recipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: effectBuiltinModuleImportObservation(recipe),
          coverage,
        }),
      ).not.toThrow();
    }

    const recipe = effectBuiltinModuleImportRecipe();
    const observed = effectBuiltinModuleImportObservation(recipe);
    const rebindDescriptor = (value, authoredRecipe) => {
      const invocation = authoredRecipe.publicSurfaceProbe.invocation;
      invocation.sourceDescriptorDigest = taggedDigest(
        invocation.sourceDescriptor,
      );
      value.invocation.sourceDescriptorDigest =
        invocation.sourceDescriptorDigest;
    };
    for (const [label, mutate, expected] of [
      [
        "runtime export field",
        (value) => {
          value.invocation.exportName = null;
        },
        /unknown or missing fields/,
      ],
      [
        "source family",
        (value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey =
            "node_fs";
          rebindDescriptor(value, authoredRecipe);
        },
        /module-import invocation descriptor drift/,
      ],
      [
        "live metadata",
        (value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.bundleExternal =
            false;
          rebindDescriptor(value, authoredRecipe);
        },
        /module-import invocation descriptor drift/,
      ],
      [
        "carrier edge",
        (value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.sourceDescriptor.carrierEdgeId =
            "edge.builtin-node-util-types";
          rebindDescriptor(value, authoredRecipe);
        },
        /module-import invocation descriptor drift/,
      ],
      [
        "auxiliary decision edge",
        (value, authoredRecipe) => {
          const invocation = authoredRecipe.publicSurfaceProbe.invocation;
          invocation.sourceDescriptor.auxiliaryDecisionEdgeId =
            "edge.terminal";
          invocation.allowedCoverageEdgeIds = ["edge.terminal"];
          value.typedDecisions.forEach((decision) => {
            decision.decisionSet.atomicityGroup = "edge.terminal.decision";
            decision.gates[0].coverageEdgeId = "edge.terminal";
          });
          rebindDescriptor(value, authoredRecipe);
        },
        /auxiliary decision is not coverage-bound/,
      ],
      [
        "route proof",
        (_value, authoredRecipe) => {
          authoredRecipe.route.alternatives[0].proofPaths = [
            "builtin:node:fs",
          ];
        },
        /module-import invocation descriptor drift/,
      ],
      [
        "authority resource",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.requiredAuthority[0].resource.name =
            "architecture";
        },
        /module-import invocation descriptor drift/,
      ],
      [
        "result module",
        (value) => {
          value.invocation.result.moduleSpecifier = "node:fs";
        },
        /returned the wrong module/,
      ],
      [
        "result type",
        (value) => {
          value.invocation.result.valueType = "function";
        },
        /returned the wrong module/,
      ],
      [
        "extra result field",
        (value) => {
          value.invocation.result.exportName = null;
        },
        /unknown or missing fields/,
      ],
      [
        "resource target",
        (value) => {
          value.typedDecisions[0].decisionSet.effects[0].resource.requested.target =
            "broker-base";
        },
        /exact NODE_DEBUG authority binding/,
      ],
      [
        "resource name",
        (value) => {
          value.typedDecisions[0].decisionSet.effects[0].resource.requested.name =
            "PATH";
        },
        /exact NODE_DEBUG authority binding/,
      ],
      [
        "resource origin",
        (value) => {
          value.typedDecisions[0].decisionSet.effects[0].resource.valueOrigin =
            "broker-base";
        },
        /exact NODE_DEBUG authority binding/,
      ],
      [
        "decision actor",
        (value) => {
          value.typedDecisions[0].decisionSet.context.actor = {
            kind: "root",
            identity: "another-root",
          };
        },
        /exact NODE_DEBUG authority binding/,
      ],
      [
        "decisive reason",
        (value) => {
          value.typedDecisions[0].evidence.evidence[0].reason =
            "dynamic-grant";
        },
        /exact NODE_DEBUG authority binding/,
      ],
      [
        "decisive source",
        (value) => {
          value.typedDecisions[0].evidence.evidence[0].sourceId =
            "principal.000000.grant.000000";
        },
        /exact NODE_DEBUG authority binding/,
      ],
      [
        "decision-set schema",
        (value) => {
          delete value.typedDecisions[0].decisionSet.decisionSetSchema;
        },
        /exact typed envelope/,
      ],
      [
        "decision combination",
        (value) => {
          value.typedDecisions[0].decisionSet.combination = "disjunction";
        },
        /exact typed envelope/,
      ],
      [
        "evidence operation",
        (value) => {
          value.typedDecisions[0].evidence.operationId = "another-operation";
        },
        /exact typed envelope/,
      ],
      [
        "coordinated operation rewrite",
        (value) => {
          value.typedDecisions[0].decisionSet.operationId =
            "another-operation";
          value.typedDecisions[0].evidence.operationId = "another-operation";
        },
        /exact typed envelope/,
      ],
      [
        "evidence identity",
        (value) => {
          value.typedDecisions[0].evidence.identity.vocabDigest = "sha256-bad";
        },
        /exact typed envelope/,
      ],
      [
        "valid but wrong evidence identity",
        (value) => {
          value.typedDecisions.forEach((decision) => {
            decision.evidence.identity.vocabDigest =
              `sha256-${"A".repeat(43)}`;
          });
        },
        /exact typed envelope/,
      ],
      [
        "coordinated registry identity rewrite",
        (value) => {
          value.invocation.decisionIdentity.registryDigest =
            `sha256-${"A".repeat(43)}`;
          value.typedDecisions.forEach((decision) => {
            decision.evidence.identity.registryDigest =
              `sha256-${"A".repeat(43)}`;
          });
        },
        /invocation descriptor drift/,
      ],
      [
        "evidence generations",
        (value) => {
          value.typedDecisions[0].evidence.generations.dynamic = 1;
        },
        /exact typed envelope/,
      ],
      [
        "evidence stage",
        (value) => {
          value.typedDecisions[0].evidence.stage = "delivery";
        },
        /exact typed envelope/,
      ],
      [
        "evidence actor",
        (value) => {
          value.typedDecisions[0].evidence.actor.identity = "another-root";
        },
        /exact typed envelope/,
      ],
      [
        "evidence owners",
        (value) => {
          value.typedDecisions[0].evidence.effectOwners = [];
        },
        /exact typed envelope/,
      ],
      [
        "evidence constrained principals",
        (value) => {
          value.typedDecisions[0].evidence.constrainedPrincipals = [];
        },
        /exact typed envelope/,
      ],
    ]) {
      const tampered = structuredClone(observed);
      const tamperedRecipe = structuredClone(recipe);
      mutate(tampered, tamperedRecipe);
      expect(
        () =>
          buildPublicFixtureEvidence({
            recipe: tamperedRecipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: tampered,
            coverage,
          }),
        label,
      ).toThrow(expected);
    }
  });

  test("accepts exactly the reviewed zero-decision imports without export conflation", () => {
    expect(NONCAP_MODULE_IMPORT_TEST_ALIASES).toHaveLength(34);
    for (const { moduleSpecifier } of NONCAP_MODULE_IMPORT_TEST_ALIASES) {
      const recipe = noncapModuleImportRecipe(moduleSpecifier);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: noncapModuleImportObservation(recipe),
          coverage,
        }),
      ).not.toThrow();
    }

    const rebindDescriptor = (value, recipe) => {
      const invocation = recipe.publicSurfaceProbe.invocation;
      invocation.sourceDescriptorDigest = taggedDigest(
        invocation.sourceDescriptor,
      );
      value.invocation.sourceDescriptorDigest =
        invocation.sourceDescriptorDigest;
    };
    for (const [mutate, expected] of [
      [
        (value) => {
          value.invocation.exportName = "getServers";
        },
        /unknown or missing fields/,
      ],
      [
        (value, recipe) => {
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey =
            "node_fs";
          rebindDescriptor(value, recipe);
        },
        /descriptor drift/,
      ],
      [
        (value, recipe) => {
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceRef =
            "src/builtins/dns.js#exports:getServers";
          rebindDescriptor(value, recipe);
        },
        /descriptor drift/,
      ],
      [
        (value, recipe) => {
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.moduleBuiltin =
            false;
          rebindDescriptor(value, recipe);
        },
        /descriptor drift/,
      ],
      [
        (value, recipe) => {
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.expectedRootType =
            "number";
          rebindDescriptor(value, recipe);
        },
        /descriptor drift/,
      ],
      [
        (value, recipe) => {
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.carrierEdgeId =
            "edge.dns-promises";
          rebindDescriptor(value, recipe);
        },
        /descriptor drift/,
      ],
      [
        (_value, recipe) => {
          recipe.route.alternatives[0].proofPaths = [
            "builtin:node:dns",
            "builtin:export:node_dns:getServers",
          ];
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.completion.status = "pending";
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          delete value.invocation.sourceExecution;
        },
        /unknown or missing fields/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.sourceId =
            "ibex-source-id-v1:forged";
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.moduleSpecifier = "dns";
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.observationId = "fixture.replayed";
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.runtimeNonce = 0;
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.runtimeNonce =
            "u64:18446744073709551616";
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.cacheMiss = false;
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.invocation.sourceExecution.bodyCompleted = false;
        },
        /descriptor drift/,
      ],
      [
        (value) => {
          value.typedDecisions.push({});
        },
        /malformed runtime public observation/,
      ],
      [
        (value) => {
          value.invocation.result.exportName = "getServers";
        },
        /unknown or missing fields/,
      ],
      [
        (value) => {
          value.invocation.result.valueType = "function";
        },
        /wrong module/,
      ],
    ]) {
      const recipe = noncapModuleImportRecipe();
      const observation = noncapModuleImportObservation(recipe);
      mutate(observation, recipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observation,
          coverage,
        }),
      ).toThrow(expected);
    }

    for (const [label, mutateCoverage, expected] of [
      [
        "unknown carrier",
        (_checked, recipe) => {
          recipe.edgeIds = ["edge.unknown-dns-carrier"];
          recipe.publicSurfaceProbe.invocation.sourceDescriptor.carrierEdgeId =
            "edge.unknown-dns-carrier";
        },
        /not coverage-bound/,
      ],
      [
        "wrong carrier classification",
        (checked, recipe) => {
          checked.edges.find((edge) => edge.id === recipe.edgeIds[0]).classification =
            "effects";
        },
        /not coverage-bound/,
      ],
      [
        "wrong carrier surface",
        (checked, recipe) => {
          checked.edges.find((edge) => edge.id === recipe.edgeIds[0]).surface.name =
            "node:path";
        },
        /not coverage-bound/,
      ],
      [
        "wrong carrier rationale",
        (checked, recipe) => {
          checked.edges.find((edge) => edge.id === recipe.edgeIds[0]).rationaleId =
            "pure-in-memory";
        },
        /not coverage-bound/,
      ],
    ]) {
      const recipe = noncapModuleImportRecipe();
      const observation = noncapModuleImportObservation(recipe);
      const checkedCoverage = structuredClone(coverage);
      mutateCoverage(checkedCoverage, recipe);
      rebindDescriptor(observation, recipe);
      expect(
        () =>
          buildPublicFixtureEvidence({
            recipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: observation,
            coverage: checkedCoverage,
          }),
        label,
      ).toThrow(expected);
    }

    const catalog = completeModuleImportCatalog();
    const executions = catalog.recipes.map((recipe, index) =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: noncapModuleImportObservation(
          recipe,
          `u64:${index + 1}`,
        ),
        coverage,
      }),
    );
    expect(() =>
      buildPublicSurfaceExecutionArtifact({
        recipeCatalog: catalog,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest:
          "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        target,
        engine,
        coverage,
        executions,
      }),
    ).not.toThrow();

    const replayedRuntimeExecutions = catalog.recipes.map((recipe) =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: noncapModuleImportObservation(recipe, "u64:7"),
        coverage,
      }),
    );
    expect(() =>
      buildPublicSurfaceExecutionArtifact({
        recipeCatalog: catalog,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest:
          "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        target,
        engine,
        coverage,
        executions: replayedRuntimeExecutions,
      }),
    ).toThrow(/reused a runtime nonce/);
  });

  test("accepts only the exact zero-decision builtin normal-return proof", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const observed = noncapBuiltinCallObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const [label, mutate, expected] of [
      [
        "result type",
        (value) => {
          value.invocation.result.valueType = "object";
        },
        /exact normal return/,
      ],
      [
        "dispatch",
        (value) => {
          value.invocation.result.dispatchKind = "construct";
        },
        /exact normal return/,
      ],
      [
        "body-entry marker",
        (value) => {
          value.invocation.result.bodyEntryProof = "caller-asserted";
        },
        /exact normal return/,
      ],
      [
        "extra result field",
        (value) => {
          value.invocation.result.synthetic = true;
        },
        /unknown or missing fields/,
      ],
      [
        "missing completion",
        (value) => {
          delete value.invocation.completion;
        },
        /unknown or missing fields/,
      ],
      [
        "unsettled completion",
        (value) => {
          value.invocation.completion.status = "pending";
        },
        /escaped its observation session/,
      ],
      [
        "caller-selected completion timeout",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.completion.timeoutMilliseconds = 5_000;
        },
        /escaped its observation session/,
      ],
      [
        "unknown setup",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.setup.kind =
            "caller-selected";
        },
        /malformed authored normal-return setup/,
      ],
      [
        "downgraded expectation",
        (_value, authoredRecipe) => {
          authoredRecipe.publicSurfaceProbe.invocation.expectedResult =
            "return";
        },
        /descriptor drift/,
      ],
      [
        "legacy decision",
        (value) => {
          value.legacyObservationCount = 1;
        },
        /malformed runtime public observation/,
      ],
      [
        "typed decision",
        (value) => {
          value.typedDecisions = [{}];
        },
        /malformed runtime public observation/,
      ],
    ]) {
      const tampered = structuredClone(observed);
      const tamperedRecipe = structuredClone(recipe);
      mutate(tampered, tamperedRecipe);
      expect(
        () =>
          buildPublicFixtureEvidence({
            recipe: tamperedRecipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: tampered,
            coverage,
          }),
        label,
      ).toThrow(expected);
    }

    const aliasRecipe = structuredClone(recipe);
    const aliasObservation = structuredClone(observed);
    aliasRecipe.publicSurfaceProbe.invocation.invocationSchema =
      "ibex/capsec-builtin-module-import-invocation/1";
    aliasRecipe.publicSurfaceProbe.invocation.kind = "builtin-module-import";
    aliasObservation.invocation.invocationSchema =
      aliasRecipe.publicSurfaceProbe.invocation.invocationSchema;
    aliasObservation.invocation.kind =
      aliasRecipe.publicSurfaceProbe.invocation.kind;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: aliasRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: aliasObservation,
        coverage,
      }),
    ).toThrow(/unknown or missing fields|module-import invocation descriptor drift/);
  });

  test("accepts only exact source-only compatibility calls", () => {
    for (const contract of [
      {
        sourceKey: "exact_crypto",
        exportName: "createPrivateKey",
        moduleSpecifier: "node:crypto",
        templateId: "exact-crypto-bounded-v1",
        exportIdioms: ["object-binding", "object-source"],
        moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
        sourceRef: "src/builtins/crypto.js#exports:createPrivateKey",
        arguments: [{ kind: "json", value: "ibex-key" }],
        resultType: "object",
      },
      {
        sourceKey: "node_readline",
        exportName: "CSI",
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
    ]) {
      const catalog = completeNoncapBuiltinCallCatalog();
      const recipe = catalog.recipes[0];
      const invocation = recipe.publicSurfaceProbe.invocation;
      invocation.moduleSpecifier = contract.moduleSpecifier;
      invocation.exportName = contract.exportName;
      invocation.templateId = contract.templateId;
      invocation.sourceDescriptor = {
        kind: "builtin-export",
        sourceKey: contract.sourceKey,
        exportName: contract.exportName,
        exportIdioms: contract.exportIdioms,
        moduleSpecifiers: contract.moduleSpecifiers,
        sourceRef: contract.sourceRef,
        valueShape: "callable",
        access: {
          kind: "export-property",
          path: [contract.exportName],
        },
      };
      invocation.sourceDescriptorDigest = taggedDigest(
        invocation.sourceDescriptor,
      );
      invocation.arguments = contract.arguments;
      invocation.setup = { kind: "root-call" };
      invocation.bodyEntryProof = {
        kind: "normal-return-from-source-call",
        resultType: contract.resultType,
      };
      const observed = noncapBuiltinCallObservation(recipe);

      expect(() =>
        buildPublicFixtureEvidence({
          recipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).not.toThrow();

      for (const mutate of [
        (value) => {
          value.publicSurfaceProbe.invocation.arguments[0].value =
            contract.sourceKey === "exact_crypto" ? "other-key" : ["32m"];
        },
        (value) => {
          value.publicSurfaceProbe.invocation.templateId =
            "generic-pure-v1";
        },
        (value) => {
          value.publicSurfaceProbe.invocation.bodyEntryProof.resultType =
            contract.resultType === "object" ? "string" : "object";
        },
      ]) {
        const tamperedRecipe = structuredClone(recipe);
        mutate(tamperedRecipe);
        expect(() =>
          buildPublicFixtureEvidence({
            recipe: tamperedRecipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: observed,
            coverage,
          }),
        ).toThrow(
          /malformed authored pure compatibility proof|wrong value type/,
        );
      }
    }

    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:readline";
    invocation.exportName = "emitKeypressEvents";
    invocation.templateId = "node-readline-pure-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_readline",
      exportName: "emitKeypressEvents",
      exportIdioms: ["module-exports-object"],
      moduleSpecifiers: [
        "node:readline",
        "node:readline/promises",
        "readline",
        "readline/promises",
      ],
      sourceRef:
        "src/builtins/readline.js#exports:emitKeypressEvents",
      valueShape: "callable",
      access: {
        kind: "export-property",
        path: ["emitKeypressEvents"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.arguments = [];
    invocation.setup = { kind: "root-call" };
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "undefined",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/malformed authored pure compatibility proof/);
  });

  test("accepts only harness-owned readline Interface lifecycle proofs", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:readline";
    invocation.exportName = "Interface.close";
    invocation.templateId = "node-readline-pure-v1";
    invocation.sourceDescriptor = {
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
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.arguments = [];
    invocation.setup = {
      kind: "readline-interface-owner",
      ownerExportName: "Interface",
      terminal: false,
    };
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "undefined",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.inputLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const pauseRecipe = structuredClone(recipe);
    const pauseInvocation = pauseRecipe.publicSurfaceProbe.invocation;
    pauseInvocation.exportName = "Interface.pause";
    pauseInvocation.sourceDescriptor.exportName = "Interface.pause";
    pauseInvocation.sourceDescriptor.sourceRef =
      "src/builtins/readline.js#exports:Interface.pause";
    pauseInvocation.sourceDescriptor.access.path = [
      "Interface",
      "prototype",
      "pause",
    ];
    pauseInvocation.sourceDescriptorDigest = taggedDigest(
      pauseInvocation.sourceDescriptor,
    );
    pauseInvocation.setup = {
      kind: "readline-interface-pause-owner",
      ownerExportName: "Interface",
      terminal: false,
      cleanupMethod: "close",
    };
    pauseInvocation.bodyEntryProof.resultType = "object";
    const pauseObserved = noncapBuiltinCallObservation(pauseRecipe);
    pauseObserved.invocation.result.dispatchKind = "prototype-call";
    pauseObserved.invocation.result.cleanupPerformed = true;
    pauseObserved.invocation.result.inputLifecycleVerified = true;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: pauseRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: pauseObserved,
        coverage,
      }),
    ).not.toThrow();

    const tamperedPauseRecipe = structuredClone(pauseRecipe);
    tamperedPauseRecipe.publicSurfaceProbe.invocation.setup.cleanupMethod =
      "destroy";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: tamperedPauseRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: pauseObserved,
        coverage,
      }),
    ).toThrow(/malformed authored readline Interface lifecycle proof/);

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.exportName = "Interface.pause";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.terminal = true;
      },
      (_value, runtime) => {
        runtime.invocation.result.cleanupPerformed = false;
      },
      (_value, runtime) => {
        runtime.invocation.result.inputLifecycleVerified = false;
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      const tamperedObservation = structuredClone(observed);
      mutate(tamperedRecipe, tamperedObservation);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: tamperedObservation,
          coverage,
        }),
      ).toThrow(
        /malformed authored (?:pure compatibility|readline Interface lifecycle) proof|did not prove its exact normal return|does not match recipe|descriptor drift/,
      );
    }
  });

  test("accepts only exact harness-owned KeyObject equality", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:crypto";
    invocation.exportName = "KeyObject.equals";
    invocation.templateId = "exact-crypto-bounded-v1";
    invocation.sourceDescriptor = {
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
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.arguments = [{ kind: "setup-value", name: "peer" }];
    invocation.setup = {
      kind: "key-object-pair-owner",
      ownerExportName: "KeyObject",
      keyType: "secret",
      bytes: [0x69, 0x62, 0x65, 0x78],
    };
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "boolean",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.moduleSpecifier = "node:crypto";
    observed.invocation.result.moduleSpecifier = "node:crypto";
    observed.invocation.result.exportName = "KeyObject.equals";
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.bytes[3] = 0x79;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.keyType = "public";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].name = "other";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.bodyEntryProof.resultType =
          "object";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored KeyObject.equals proof|wrong value type/,
      );
    }
  });

  test("accepts settled stream returns only for ended reviewed consumers", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:stream";
    invocation.exportName = "Readable.every";
    invocation.templateId = "node-stream-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_stream",
      exportName: "Readable.every",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:stream", "stream"],
      sourceRef: "src/builtins/stream.js#exports:Readable.every",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["Readable", "prototype", "every"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "stream-owner",
      ownerExportName: "Readable",
      endedInput: true,
    };
    invocation.arguments = [{ kind: "constant-function", value: true }];
    invocation.bodyEntryProof = {
      kind: "settled-return-from-source-call",
      resultType: "boolean",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.endedInput = false;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey =
          "node_path";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.exportName = "Readable.wrap";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored settled-return proof|descriptor drift|not source-descriptor bound/,
      );
    }
  });

  test("accepts only the fixed explicit DiffieHellman call contracts", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "crypto";
    invocation.exportName = "DiffieHellman.getPrime";
    invocation.templateId = "exact-crypto-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "exact_crypto",
      exportName: "DiffieHellman.getPrime",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["crypto", "exact:crypto", "node:crypto"],
      sourceRef: "src/builtins/crypto.js#exports:DiffieHellman.getPrime",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["DiffieHellman", "prototype", "getPrime"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "constructed-owner",
      ownerExportName: "DiffieHellman",
      constructorArguments: [
        { kind: "uint8-array", bytes: [23] },
        { kind: "json", value: 5 },
      ],
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.constructorArguments[0]
          .bytes = [29];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "uint8-array", bytes: [3] },
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.bodyEntryProof.resultType =
          "undefined";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored explicit DiffieHellman proof|wrong value type/,
      );
    }
  });

  test("accepts only reviewed base Stream module-value calls", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:stream";
    invocation.exportName = "default.destroy";
    invocation.templateId = "node-stream-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_stream",
      exportName: "default.destroy",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:stream", "stream"],
      sourceRef: "src/builtins/stream.js#exports:default.destroy",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["prototype", "destroy"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "stream-owner",
      ownerExportName: "default",
      endedInput: false,
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.access.path = [
          "default",
          "prototype",
          "destroy",
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Stream";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.endedInput = true;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "json", value: null },
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored base Stream module-value proof|descriptor drift|not source-descriptor bound/,
      );
    }
  });

  test("accepts only reviewed idle zlib destroy calls", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "Gzip.destroy";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Gzip.destroy",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:Gzip.destroy",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["Gzip", "prototype", "destroy"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "zlib-owner",
      ownerExportName: "Gzip",
      ensureNativeStream: false,
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.access.path = [
          "Gzip",
          "prototype",
          "_destroy",
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Gunzip";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ensureNativeStream = true;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "json", value: null },
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored idle zlib destroy proof|descriptor drift|not source-descriptor bound/,
      );
    }
  });

  test("accepts zlib end only after exact output and terminal cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "Inflate.end";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Inflate.end",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:Inflate.end",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["Inflate", "prototype", "end"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "zlib-end-owner",
      ownerExportName: "Inflate",
      outputContract: "exact-ibex-byte-view",
    };
    invocation.arguments = [
      {
        kind: "buffer",
        bytes: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
      },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibEndLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[0] = 121;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.outputContract =
          "nonempty-byte-view";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Gunzip";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib end lifecycle proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingLifecycleProof = structuredClone(observed);
    missingLifecycleProof.invocation.result.zlibEndLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycleProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts timers only with exact owned cleanup and callback suppression", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:timers";
    invocation.exportName = "active";
    invocation.templateId = "node-timers-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_timers",
      exportName: "active",
      exportIdioms: ["module-exports-object"],
      moduleSpecifiers: ["node:timers", "timers"],
      sourceRef: "src/builtins/timers.js#exports:active",
      valueShape: "callable",
      access: { kind: "export-property", path: ["active"] },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "timer-legacy-root",
      operation: "active",
    };
    invocation.arguments = [
      { kind: "setup-value", name: "timerRecord" },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "undefined",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.timerLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.operation = "enroll";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].name = "timerHandle";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.templateId =
          "node-timers-unbounded-v1";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(/malformed authored timer proof|descriptor drift/);
    }

    const missingLifecycle = structuredClone(observed);
    missingLifecycle.invocation.result.timerLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycle,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts direct zlib process-chunk only with exact output and cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "Inflate._processChunk";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Inflate._processChunk",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:Inflate._processChunk",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["Inflate", "prototype", "_processChunk"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "zlib-process-chunk-owner",
      ownerExportName: "Inflate",
      outputContract: "exact-ibex-byte-view",
    };
    invocation.arguments = [
      {
        kind: "buffer",
        bytes: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
      },
      { kind: "json", value: 4 },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibProcessChunkOutputVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[0] = 121;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[1].value = 3;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.outputContract =
          "nonempty-byte-view";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Gunzip";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib process-chunk proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingOutputProof = structuredClone(observed);
    missingOutputProof.invocation.result.zlibProcessChunkOutputVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingOutputProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts zlib write only after exact callback, output, and cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "Inflate.write";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Inflate.write",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:Inflate.write",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["Inflate", "prototype", "write"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "zlib-write-owner",
      ownerExportName: "Inflate",
      outputContract: "exact-ibex-byte-view",
      terminalMethod: "end",
    };
    invocation.arguments = [
      {
        kind: "buffer",
        bytes: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
      },
      { kind: "zlib-write-callback" },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "boolean",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibWriteLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[0] = 121;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[1].kind =
          "noop-function";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.terminalMethod = "destroy";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Gunzip";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib write lifecycle proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingLifecycleProof = structuredClone(observed);
    missingLifecycleProof.invocation.result.zlibWriteLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycleProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts zlib flush only after its exact callback, non-terminal state, and cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "ZstdCompress.flush";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "ZstdCompress.flush",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:ZstdCompress.flush",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["ZstdCompress", "prototype", "flush"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "zlib-flush-owner",
      ownerExportName: "ZstdCompress",
      callbackPosition: "first-argument",
      flushKind: "default-full-flush",
      cleanupMethod: "destroy",
    };
    invocation.arguments = [{ kind: "zlib-flush-callback" }];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibFlushLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].kind =
          "noop-function";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.flushKind = "finish";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.callbackPosition =
          "second-argument";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName =
          "ZstdDecompress";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib flush lifecycle proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingLifecycleProof = structuredClone(observed);
    missingLifecycleProof.invocation.result.zlibFlushLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycleProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts zlib params only after its exact selected state, callback, and cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "Deflate.params";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "Deflate.params",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:Deflate.params",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["Deflate", "prototype", "params"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "zlib-params-owner",
      ownerExportName: "Deflate",
      level: 1,
      strategy: 0,
      cleanupMethod: "destroy",
    };
    invocation.arguments = [
      { kind: "json", value: 1 },
      { kind: "json", value: 0 },
      { kind: "zlib-params-callback" },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibParamsLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].value = 2;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[2].kind =
          "noop-function";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.strategy = 1;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName =
          "DeflateRaw";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib params lifecycle proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingLifecycleProof = structuredClone(observed);
    missingLifecycleProof.invocation.result.zlibParamsLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycleProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts direct zlib transform only after exact input acceptance, callback, and cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "InflateRaw._transform";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "InflateRaw._transform",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:InflateRaw._transform",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["InflateRaw", "prototype", "_transform"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(invocation.sourceDescriptor);
    invocation.setup = {
      kind: "zlib-transform-owner",
      ownerExportName: "InflateRaw",
      inputLength: 6,
      cleanupMethod: "destroy",
    };
    invocation.arguments = [
      { kind: "buffer", bytes: [203, 76, 74, 173, 0, 0] },
      { kind: "json", value: "buffer" },
      { kind: "zlib-transform-callback" },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "undefined",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.valueType = "undefined";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibTransformLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[0] = 204;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[1].value = "utf8";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[2].kind =
          "noop-function";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.inputLength = 5;
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib transform lifecycle proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingLifecycleProof = structuredClone(observed);
    missingLifecycleProof.invocation.result.zlibTransformLifecycleVerified =
      false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycleProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts direct zlib flush only after exact prefill, callback outcome, and cleanup", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "InflateRaw._flush";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "InflateRaw._flush",
      exportIdioms: ["exported-constructor-inherited-prototype"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:InflateRaw._flush",
      valueShape: "callable",
      access: {
        kind: "inherited-prototype-property",
        path: ["InflateRaw", "prototype", "_flush"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(invocation.sourceDescriptor);
    invocation.setup = {
      kind: "zlib-direct-flush-owner",
      ownerExportName: "InflateRaw",
      prefillInput: [203, 76, 74, 173, 0, 0],
      expectedCallbackErrorCode: null,
      cleanupMethod: "destroy",
    };
    invocation.arguments = [{ kind: "zlib-direct-flush-callback" }];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "undefined",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.valueType = "undefined";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.zlibDirectFlushLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.prefillInput[0] = 204;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.expectedCallbackErrorCode =
          "ENOSYS";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].kind =
          "noop-function";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored direct zlib flush lifecycle proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingLifecycleProof = structuredClone(observed);
    missingLifecycleProof.invocation.result.zlibDirectFlushLifecycleVerified =
      false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingLifecycleProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts only reviewed isolated sync zlib encoders", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "deflateSync";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "deflateSync",
      exportIdioms: ["object-binding", "object-source"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:deflateSync",
      valueShape: "callable",
      access: {
        kind: "export-property",
        path: ["deflateSync"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = { kind: "root-call" };
    invocation.arguments = [
      { kind: "buffer", bytes: [105, 98, 101, 120] },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.zlibSyncEncoderOutputVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[3] = 121;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.kind = "construct-target";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.sourceRef =
          "src/builtins/zlib.js#exports:gzipSync";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored sync zlib encoder proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingOutputProof = structuredClone(observed);
    missingOutputProof.invocation.result.zlibSyncEncoderOutputVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingOutputProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts only reviewed isolated sync zlib decoders", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "inflateSync";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "inflateSync",
      exportIdioms: ["object-binding", "object-source"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:inflateSync",
      valueShape: "callable",
      access: {
        kind: "export-property",
        path: ["inflateSync"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = { kind: "root-call" };
    invocation.arguments = [
      {
        kind: "buffer",
        bytes: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
      },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.zlibSyncDecoderOutputVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[0] = 121;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.kind = "construct-target";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.sourceRef =
          "src/builtins/zlib.js#exports:unzipSync";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored sync zlib decoder proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingOutputProof = structuredClone(observed);
    missingOutputProof.invocation.result.zlibSyncDecoderOutputVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingOutputProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts only reviewed deferred zlib callback deliveries", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:zlib";
    invocation.exportName = "inflate";
    invocation.templateId = "node-zlib-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_zlib",
      exportName: "inflate",
      exportIdioms: ["object-binding", "object-source"],
      moduleSpecifiers: ["node:zlib", "zlib"],
      sourceRef: "src/builtins/zlib.js#exports:inflate",
      valueShape: "callable",
      access: {
        kind: "export-property",
        path: ["inflate"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = { kind: "root-call" };
    invocation.arguments = [
      {
        kind: "buffer",
        bytes: [120, 156, 203, 76, 74, 173, 0, 0, 4, 16, 1, 169],
      },
      {
        kind: "zlib-callback",
        resultContract: "exact-ibex-byte-view",
      },
    ];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "undefined",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.valueType = "undefined";
    observed.invocation.result.zlibCallbackOutputVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[0].bytes[0] = 121;
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments[1].resultContract =
          "nonempty-byte-view";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.sourceRef =
          "src/builtins/zlib.js#exports:deflate";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored zlib callback proof|descriptor drift|not source-descriptor bound/,
      );
    }

    const missingOutputProof = structuredClone(observed);
    missingOutputProof.invocation.result.zlibCallbackOutputVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingOutputProof,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts only reviewed bounded HTTP calls", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:http";
    invocation.exportName = "Server.close";
    invocation.templateId = "node-http-idle-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_http",
      exportName: "Server.close",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: [
        "_http_agent",
        "_http_common",
        "_http_incoming",
        "_http_outgoing",
        "_http_server",
        "http",
        "node:http",
      ],
      sourceRef: "src/builtins/http.js#exports:Server.close",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["Server", "prototype", "close"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "constructed-owner",
      ownerExportName: "Server",
      constructorArguments: [],
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const validatorRecipe = structuredClone(recipe);
    const validatorInvocation = validatorRecipe.publicSurfaceProbe.invocation;
    validatorInvocation.exportName = "validateHeaderValue";
    validatorInvocation.sourceDescriptor.exportName = "validateHeaderValue";
    validatorInvocation.sourceDescriptor.exportIdioms = [
      "module-exports-object",
    ];
    validatorInvocation.sourceDescriptor.sourceRef =
      "src/builtins/http.js#exports:validateHeaderValue";
    validatorInvocation.sourceDescriptor.access = {
      kind: "export-property",
      path: ["validateHeaderValue"],
    };
    validatorInvocation.sourceDescriptorDigest = taggedDigest(
      validatorInvocation.sourceDescriptor,
    );
    validatorInvocation.setup = { kind: "root-call" };
    validatorInvocation.arguments = [
      { kind: "json", value: "x-ibex" },
      { kind: "json", value: "ibex" },
    ];
    validatorInvocation.bodyEntryProof.resultType = "undefined";
    const validatorObserved = noncapBuiltinCallObservation(validatorRecipe);
    validatorObserved.invocation.moduleSpecifier = "node:http";
    validatorObserved.invocation.result.moduleSpecifier = "node:http";
    validatorObserved.invocation.result.exportName = "validateHeaderValue";
    validatorObserved.invocation.result.valueType = "undefined";
    validatorObserved.invocation.result.dispatchKind = "call";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: validatorRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: validatorObserved,
        coverage,
      }),
    ).not.toThrow();

    const tamperedValidatorRecipe = structuredClone(validatorRecipe);
    tamperedValidatorRecipe.publicSurfaceProbe.invocation.arguments[1].value =
      "other";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: tamperedValidatorRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: validatorObserved,
        coverage,
      }),
    ).toThrow(/malformed authored bounded HTTP proof/);

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Agent";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.constructorArguments = [
          { kind: "json", value: {} },
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "noop-function" },
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.bodyEntryProof.resultType =
          "undefined";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.templateId =
          "node-http2-pure-v1";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.access.path = [
          "Server",
          "prototype",
          "listen",
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored bounded HTTP proof|wrong value type|not source-descriptor bound/,
      );
    }
  });

  test("accepts fresh net terminal calls only after close delivery", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:net";
    invocation.exportName = "Socket.resetAndDestroy";
    invocation.templateId = "node-net-bounded-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_net",
      exportName: "Socket.resetAndDestroy",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["net", "node:net"],
      sourceRef: "src/builtins/net.js#exports:Socket.resetAndDestroy",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["Socket", "prototype", "resetAndDestroy"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "net-terminal-owner",
      ownerExportName: "Socket",
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.moduleSpecifier = "node:net";
    observed.invocation.result.moduleSpecifier = "node:net";
    observed.invocation.result.exportName = "Socket.resetAndDestroy";
    observed.invocation.result.dispatchKind = "prototype-call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.netLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Server";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.templateId =
          "node-http-idle-v1";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.access.path = [
          "Socket",
          "prototype",
          "destroy",
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored idle net terminal proof|not source-descriptor bound|descriptor drift/,
      );
    }

    const incompleteObservation = structuredClone(observed);
    incompleteObservation.invocation.result.netLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: incompleteObservation,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts only transport-free TLS socket lifecycle calls", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:tls";
    invocation.exportName = "TLSSocket.destroy";
    invocation.templateId = "node-tls-pure-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_tls",
      exportName: "TLSSocket.destroy",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["node:tls", "tls"],
      sourceRef: "src/builtins/tls.js#exports:TLSSocket.destroy",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["TLSSocket", "prototype", "destroy"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "constructed-owner",
      ownerExportName: "TLSSocket",
      constructorArguments: [],
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.moduleSpecifier = "node:tls";
    observed.invocation.result.moduleSpecifier = "node:tls";
    observed.invocation.result.exportName = "TLSSocket.destroy";
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Server";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.constructorArguments = [
          { kind: "json", value: {} },
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "json", value: null },
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.templateId =
          "node-net-bounded-v1";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.access.path = [
          "TLSSocket",
          "prototype",
          "connect",
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored idle TLS socket proof|not source-descriptor bound/,
      );
    }
  });

  test("accepts TLS Server construction only after exact retirement", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:tls";
    invocation.exportName = "createServer";
    invocation.templateId = "node-tls-pure-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_tls",
      exportName: "createServer",
      exportIdioms: ["module-exports-object"],
      moduleSpecifiers: ["node:tls", "tls"],
      sourceRef: "src/builtins/tls.js#exports:createServer",
      valueShape: "callable",
      access: {
        kind: "export-property",
        path: ["createServer"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = { kind: "tls-server-root-call" };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.moduleSpecifier = "node:tls";
    observed.invocation.result.moduleSpecifier = "node:tls";
    observed.invocation.result.exportName = "createServer";
    observed.invocation.result.dispatchKind = "call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.tlsServerLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.kind =
          "tls-server-construct-target";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.exportName = "connect";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "json", value: {} },
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored idle TLS Server proof|unreviewed authored TLS proof|not source-descriptor bound|descriptor drift/,
      );
    }

    const incompleteObservation = structuredClone(observed);
    incompleteObservation.invocation.result.tlsServerLifecycleVerified = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: incompleteObservation,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts HTTPS Server construction only after inner TLS retirement", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:https";
    invocation.exportName = "createServer";
    invocation.templateId = "node-https-idle-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_https",
      exportName: "createServer",
      exportIdioms: ["member-assignment"],
      moduleSpecifiers: ["https", "node:https"],
      sourceRef: "src/builtins/https.js#exports:createServer",
      valueShape: "callable",
      access: {
        kind: "export-property",
        path: ["createServer"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = { kind: "tls-server-root-call" };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.moduleSpecifier = "node:https";
    observed.invocation.result.moduleSpecifier = "node:https";
    observed.invocation.result.exportName = "createServer";
    observed.invocation.result.dispatchKind = "call";
    observed.invocation.result.cleanupPerformed = true;
    observed.invocation.result.tlsServerLifecycleVerified = true;

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.templateId = "node-tls-pure-v1";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.sourceRef =
          "src/builtins/tls.js#exports:createServer";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.exportName = "request";
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored idle TLS Server proof|unreviewed authored HTTPS proof|not source-descriptor bound|descriptor drift/,
      );
    }

    const incompleteObservation = structuredClone(observed);
    incompleteObservation.invocation.result.cleanupPerformed = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: incompleteObservation,
        coverage,
      }),
    ).toThrow(/did not prove its exact normal return/);
  });

  test("accepts only reviewed fresh UDP socket lifecycle calls", () => {
    const catalog = completeNoncapBuiltinCallCatalog();
    const recipe = catalog.recipes[0];
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.moduleSpecifier = "node:dgram";
    invocation.exportName = "Socket.close";
    invocation.templateId = "node-dgram-idle-v1";
    invocation.sourceDescriptor = {
      kind: "builtin-export",
      sourceKey: "node_dgram",
      exportName: "Socket.close",
      exportIdioms: ["exported-constructor-prototype"],
      moduleSpecifiers: ["dgram", "node:dgram"],
      sourceRef: "src/builtins/dgram.js#exports:Socket.close",
      valueShape: "callable",
      access: {
        kind: "prototype-property",
        path: ["Socket", "prototype", "close"],
      },
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.setup = {
      kind: "constructed-owner",
      ownerExportName: "Socket",
      constructorArguments: [{ kind: "json", value: "udp4" }],
    };
    invocation.arguments = [];
    invocation.bodyEntryProof = {
      kind: "normal-return-from-source-call",
      resultType: "object",
    };
    const observed = noncapBuiltinCallObservation(recipe);
    observed.invocation.moduleSpecifier = "node:dgram";
    observed.invocation.result.moduleSpecifier = "node:dgram";
    observed.invocation.result.exportName = "Socket.close";
    observed.invocation.result.dispatchKind = "prototype-call";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const dropRecipe = structuredClone(recipe);
    const dropInvocation = dropRecipe.publicSurfaceProbe.invocation;
    dropInvocation.exportName = "Socket.dropMembership";
    dropInvocation.sourceDescriptor.exportName = "Socket.dropMembership";
    dropInvocation.sourceDescriptor.sourceRef =
      "src/builtins/dgram.js#exports:Socket.dropMembership";
    dropInvocation.sourceDescriptor.access.path = [
      "Socket",
      "prototype",
      "dropMembership",
    ];
    dropInvocation.sourceDescriptorDigest = taggedDigest(
      dropInvocation.sourceDescriptor,
    );
    dropInvocation.arguments = [{ kind: "json", value: "224.0.0.1" }];
    dropInvocation.bodyEntryProof.resultType = "undefined";
    const dropObserved = noncapBuiltinCallObservation(dropRecipe);
    dropObserved.invocation.moduleSpecifier = "node:dgram";
    dropObserved.invocation.result.moduleSpecifier = "node:dgram";
    dropObserved.invocation.result.exportName = "Socket.dropMembership";
    dropObserved.invocation.result.dispatchKind = "prototype-call";
    dropObserved.invocation.result.valueType = "undefined";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe: dropRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dropObserved,
        coverage,
      }),
    ).not.toThrow();

    const unreviewedDrop = structuredClone(dropRecipe);
    unreviewedDrop.publicSurfaceProbe.invocation.arguments[0].value =
      "239.255.0.1";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: unreviewedDrop,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dropObserved,
        coverage,
      }),
    ).toThrow(/malformed authored idle UDP socket proof/);

    for (const mutate of [
      (value) => {
        value.publicSurfaceProbe.invocation.setup.ownerExportName = "Agent";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.setup.constructorArguments[0].value =
          "udp6";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.arguments = [
          { kind: "noop-function" },
        ];
      },
      (value) => {
        value.publicSurfaceProbe.invocation.bodyEntryProof.resultType =
          "undefined";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.templateId =
          "node-http-idle-v1";
      },
      (value) => {
        value.publicSurfaceProbe.invocation.sourceDescriptor.access.path = [
          "Socket",
          "prototype",
          "bind",
        ];
      },
    ]) {
      const tamperedRecipe = structuredClone(recipe);
      mutate(tamperedRecipe);
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: tamperedRecipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: observed,
          coverage,
        }),
      ).toThrow(
        /malformed authored idle UDP socket proof|wrong value type|not source-descriptor bound/,
      );
    }
  });

  test("accepts only reviewed dns/promises error reads that return strings", () => {
    const catalog = completeDnsPromiseErrorReadCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dnsPromiseErrorReadObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dnsPromiseErrorReadObservation(recipe, "object"),
        coverage,
      }),
    ).toThrow(/wrong export/);

    for (const mutate of [
      (descriptor) => {
        descriptor.expectedValueType = "number";
      },
      (descriptor) => {
        delete descriptor.expectedValueType;
      },
      (descriptor) => {
        descriptor.sourceRef =
          "src/builtins/dns.js#exports:NODATA";
      },
    ]) {
      const unreviewed = structuredClone(recipe);
      mutate(unreviewed.publicSurfaceProbe.invocation.sourceDescriptor);
      unreviewed.publicSurfaceProbe.invocation.sourceDescriptorDigest =
        taggedDigest(
          unreviewed.publicSurfaceProbe.invocation.sourceDescriptor,
        );
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: unreviewed,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: dnsPromiseErrorReadObservation(unreviewed),
          coverage,
        }),
      ).toThrow(/unreviewed runtime value-type expectation/);
    }
  });

  test("accepts only exact post-initialization value reads and runtime types", () => {
    for (const entry of [
      ...REVIEWED_POST_INITIALIZATION_VALUES,
      ...REVIEWED_PROTOTYPE_VALUES,
      ...REVIEWED_STREAM_INSTANCE_VALUES,
      ...REVIEWED_X509_INSTANCE_VALUES,
      ...REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUES,
      ...REVIEWED_DGRAM_SOCKET_INSTANCE_VALUES,
    ]) {
      const catalog = completePostInitializationValueReadCatalog(entry);
      const recipe = catalog.recipes[0];
      expect(() =>
        buildPublicFixtureEvidence({
          recipe,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: dnsPromiseErrorReadObservation(
            recipe,
            entry[3],
          ),
          coverage,
        }),
      ).not.toThrow();
    }

    const tlsContextCatalog = completePostInitializationValueReadCatalog(
      REVIEWED_TLS_SECURE_CONTEXT_INSTANCE_VALUES[0],
    );
    const tlsContextRecipe = tlsContextCatalog.recipes[0];
    const tamperedTlsContextRecipe = structuredClone(tlsContextRecipe);
    tamperedTlsContextRecipe.publicSurfaceProbe.invocation.setup.ownerExportName =
      "TLSSocket";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: tamperedTlsContextRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dnsPromiseErrorReadObservation(
          tlsContextRecipe,
          "object",
        ),
        coverage,
      }),
    ).toThrow(/setup did not match its reviewed receiver/);

    const dgramClosedCatalog = completePostInitializationValueReadCatalog(
      REVIEWED_DGRAM_SOCKET_INSTANCE_VALUES[0],
    );
    const dgramClosedRecipe = dgramClosedCatalog.recipes[0];
    const tamperedDgramClosedRecipe = structuredClone(dgramClosedRecipe);
    tamperedDgramClosedRecipe.publicSurfaceProbe.invocation.setup
      .constructorArguments[0].value = "udp6";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: tamperedDgramClosedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dnsPromiseErrorReadObservation(
          dgramClosedRecipe,
          "boolean",
        ),
        coverage,
      }),
    ).toThrow(/setup did not match its reviewed receiver/);

    const catalog = completePostInitializationValueReadCatalog(
      REVIEWED_POST_INITIALIZATION_VALUES[0],
    );
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: dnsPromiseErrorReadObservation(recipe, "string"),
        coverage,
      }),
    ).toThrow(/wrong export/);

    for (const mutate of [
      (descriptor) => {
        descriptor.expectedValueType = "string";
      },
      (descriptor) => {
        descriptor.sourceRef = "src/builtins/os.js#exports:SCHED_NONE";
      },
      (descriptor) => {
        descriptor.exportIdioms = ["module-exports-object"];
      },
    ]) {
      const unreviewed = structuredClone(recipe);
      mutate(unreviewed.publicSurfaceProbe.invocation.sourceDescriptor);
      unreviewed.publicSurfaceProbe.invocation.sourceDescriptorDigest =
        taggedDigest(
          unreviewed.publicSurfaceProbe.invocation.sourceDescriptor,
        );
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: unreviewed,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: dnsPromiseErrorReadObservation(
            unreviewed,
            unreviewed.publicSurfaceProbe.invocation.sourceDescriptor
              .expectedValueType,
          ),
          coverage,
        }),
      ).toThrow(/unreviewed runtime value-type expectation/);
    }
  });

  test("accepts captured builtin output only with source return, cleanup, and zero decisions", () => {
    const catalog = completeCapturedNoncapBuiltinCatalog();
    const recipe = catalog.recipes[0];
    const observed = capturedNoncapBuiltinObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    for (const [label, mutate, expected] of [
      [
        "descriptor substitution",
        (value) => {
          value.invocation.result.descriptorProof.accessKind =
            "prototype-property";
        },
        /did not prove the captured builtin source return/,
      ],
      [
        "cleanup substitution",
        (value) => {
          value.invocation.result.cleanupPerformed = false;
        },
        /did not prove the captured builtin source return/,
      ],
      [
        "throw substitution",
        (value) => {
          value.invocation.result.rawOutput = {
            kind: "throw",
            rawValueShape: "throw",
            value: null,
            errorCode: "ERR_METHOD_NOT_IMPLEMENTED",
          };
        },
        /did not prove the captured builtin source return/,
      ],
      [
        "caller-selected return shape",
        (value) => {
          value.invocation.result.rawOutput.rawValueShape =
            "caller-asserted";
        },
        /did not prove the captured builtin source return/,
      ],
      [
        "legacy decision",
        (value) => {
          value.legacyObservationCount = 1;
        },
        /malformed runtime public observation/,
      ],
      [
        "typed decision",
        (value) => {
          value.typedDecisions = [{}];
        },
        /malformed runtime public observation/,
      ],
      [
        "unsettled completion",
        (value) => {
          value.invocation.completion.status = "pending";
        },
        /descriptor drift/,
      ],
    ]) {
      const tampered = structuredClone(observed);
      mutate(tampered);
      expect(
        () =>
          buildPublicFixtureEvidence({
            recipe,
            engineBinaryDigest: engine.binaryDigest,
            runtimeObservation: tampered,
            coverage,
          }),
        label,
      ).toThrow(expected);
    }
  });

  test("accepts source-bound builtin target absence only after a public read", () => {
    const catalog = completeNoncapBuiltinAbsenceCatalog();
    const recipe = catalog.recipes[0];
    const observed = noncapBuiltinAbsenceObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const fabricated = structuredClone(observed);
    fabricated.invocation.result.available.push("EDQUOT");
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: fabricated,
        coverage,
      }),
    ).toThrow(/did not prove source-bound target absence/);

    const availableHere = structuredClone(recipe);
    availableHere.publicSurfaceProbe.invocation.sourceDescriptor.platformAvailability =
      ["darwin", "linux"];
    availableHere.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        availableHere.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const availableObservation = noncapBuiltinAbsenceObservation(availableHere);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: availableHere,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: availableObservation,
        coverage,
      }),
    ).toThrow(/did not prove source-bound target absence/);
  });

  test("accepts exact-target ABI absence only after a runtime symbol lookup", () => {
    const catalog = completeAbsenceCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe, true),
        coverage,
      }),
    ).toThrow(/did not prove absence/);
  });

  test("accepts native target absence only after exact runtime inspection", () => {
    const catalog = completeNativeAbsenceCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: absenceRuntimeObservation(recipe, true),
        coverage,
      }),
    ).toThrow(/did not prove absence/);
  });

  test("accepts structural startup only with exact loaded-engine postconditions", () => {
    const catalog = completeStartupCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: startupRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const failedFact = startupRuntimeObservation(recipe);
    failedFact.invocation.result.observedFacts["eval-tamed"] = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: failedFact,
        coverage,
      }),
    ).toThrow(/did not prove the startup postcondition/);

    const noProject = startupRuntimeObservation(recipe);
    noProject.invocation.result.projectCodeExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: noProject,
        coverage,
      }),
    ).toThrow(/did not prove the startup postcondition/);

    const drifted = structuredClone(recipe);
    drifted.publicSurfaceProbe.invocation.operation.postcondition =
      "runtime-created";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: drifted,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: startupRuntimeObservation(drifted),
        coverage,
      }),
    ).toThrow(/startup runtime invocation descriptor drift/);
  });

  test("accepts a closed surface only when project code did not execute", () => {
    const catalog = completeClosedCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe, true),
        coverage,
      }),
    ).toThrow(/did not fail closed/);
  });

  test("accepts filesystem closure only for exact EPERM and unchanged physical state", () => {
    const catalog = completeClosedFilesystemCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const mutated = closedRuntimeObservation(recipe);
    mutated.invocation.result.filesystemAfterDigest =
      "sha256-GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: mutated,
        coverage,
      }),
    ).toThrow(/unchanged physical state/);

    const wrongCode = closedRuntimeObservation(recipe);
    wrongCode.invocation.result.errorCode = "EACCES";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongCode,
        coverage,
      }),
    ).toThrow(/pre-lookup EPERM closure/);
  });

  test("accepts process-event closure only with pinned direct and prototype denial", () => {
    const catalog = completeClosedProcessEventCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const mutablePrototype = closedRuntimeObservation(recipe);
    mutablePrototype.invocation.result.prototypeDescriptorPinned = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: mutablePrototype,
        coverage,
      }),
    ).toThrow(/direct and prototype closure/);

    const inventedGate = structuredClone(recipe);
    inventedGate.publicSurfaceProbe.invocation.sourceDescriptor.enforcementSourceRef =
      "src/engine/hermes_runtime.cc#invented-process-gate";
    inventedGate.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inventedGate.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inventedGate,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(inventedGate),
        coverage,
      }),
    ).toThrow(/selected source branch and final armed gate/);
  });

  test("accepts process lifecycle receipts only with exact no-effect state", () => {
    const catalog = completeProcessLifecycleNoEffectCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: processLifecycleNoEffectObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const storedListener = processLifecycleNoEffectObservation(recipe);
    storedListener.invocation.result.listenerCount = 1;
    storedListener.invocation.result.listenersEmpty = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: storedListener,
        coverage,
      }),
    ).toThrow(/exact no-effect return and empty listener state/);

    const inventedBranch = structuredClone(recipe);
    inventedBranch.publicSurfaceProbe.invocation.sourceDescriptor
      .selectedLogicalBranch.when[0].equals = "exit";
    inventedBranch.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inventedBranch.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inventedBranch,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation:
          processLifecycleNoEffectObservation(inventedBranch),
        coverage,
      }),
    ).toThrow(/logical branch, source branch, and final armed gate/);
  });

  test("accepts process umask closure only with pinned read and write denial", () => {
    const catalog = completeProcessUmaskCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: processUmaskObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const mutable = processUmaskObservation(recipe);
    mutable.invocation.result.descriptorPinned = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: mutable,
        coverage,
      }),
    ).toThrow(/pinned read and write closure/);

    const missingWrite = processUmaskObservation(recipe);
    missingWrite.invocation.result.argumentCases.pop();
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingWrite,
        coverage,
      }),
    ).toThrow(/pinned read and write closure/);
  });

  test("accepts process shared-state closure only with pinned accessor denial", () => {
    const catalog = completeProcessSharedStateCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: processSharedStateObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const bypassedPrototype = processSharedStateObservation(recipe);
    bypassedPrototype.invocation.result.prototypeDescriptorPinned = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: bypassedPrototype,
        coverage,
      }),
    ).toThrow(/direct, prototype, and replacement closure/);

    const missingPrototypeWrite = processSharedStateObservation(recipe);
    missingPrototypeWrite.invocation.result.accessCases.splice(3, 1);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingPrototypeWrite,
        coverage,
      }),
    ).toThrow(/direct, prototype, and replacement closure/);
  });

  test("accepts nested process report closure only at the pinned parent", () => {
    const catalog = completeProcessReportMemberCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: processReportMemberObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const replacedParent = processReportMemberObservation(recipe);
    replacedParent.invocation.result.replacementDenied = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: replacedParent,
        coverage,
      }),
    ).toThrow(/exact nested access closure at the pinned parent/);

    const inventedNestedGate = structuredClone(recipe);
    inventedNestedGate.publicSurfaceProbe.invocation.sourceDescriptor
      .blockedAtMember = "getReport";
    inventedNestedGate.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inventedNestedGate.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inventedNestedGate,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation:
          processReportMemberObservation(inventedNestedGate),
        coverage,
      }),
    ).toThrow(/exact source row and parent armed gate/);
  });

  test("accepts CLI closure only with the authored production rejection", () => {
    const catalog = completeClosedCliCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();
    const wrong = closedRuntimeObservation(recipe);
    wrong.invocation.result.errorMessage = "a parser rejected unrelated syntax";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrong,
        coverage,
      }),
    ).toThrow(/wrong rejection/);
  });

  test("rejects normalized VFS failures as evidence for a legacy loader facet", () => {
    const catalog = completeClosedLoaderCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).toThrow(/cannot prove the legacy loader facet/);
  });

  test("accepts terminal builtin closure only when every public alias is denied", () => {
    const catalog = completeClosedTerminalBuiltinCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const directImportGate = structuredClone(recipe);
    directImportGate.route.alternatives = [];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: directImportGate,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(directImportGate),
        coverage,
      }),
    ).not.toThrow();

    const unboundDirectImportGate = structuredClone(directImportGate);
    unboundDirectImportGate.route.surfaceObservedKeys = [];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: unboundDirectImportGate,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(unboundDirectImportGate),
        coverage,
      }),
    ).toThrow(/outside the bound route/);

    const oneAlias = closedRuntimeObservation(recipe);
    oneAlias.invocation.result.errorMessage =
      "node:vm: Import denied: 'node:vm'";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: oneAlias,
        coverage,
      }),
    ).toThrow(/aliases did not fail closed/);

    const drifted = structuredClone(recipe);
    drifted.publicSurfaceProbe.invocation.sourceDescriptor.sourceKey =
      "node_wasi";
    drifted.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
      drifted.publicSurfaceProbe.invocation.sourceDescriptor,
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: drifted,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(drifted),
        coverage,
      }),
    ).toThrow(/authenticated import gate/);
  });

  test("accepts SQLite extension closure only through both public aliases", () => {
    const catalog = completeClosedSqliteExtensionCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const oneAlias = closedRuntimeObservation(recipe);
    oneAlias.invocation.result.errorMessage =
      "exact:sqlite: Extension loading not supported";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: oneAlias,
        coverage,
      }),
    ).toThrow(/every public alias/);

    const drifted = structuredClone(recipe);
    drifted.publicSurfaceProbe.invocation.operation.databasePath =
      "fixture.sqlite";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: drifted,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(drifted),
        coverage,
      }),
    ).toThrow(/public memory-database call/);

    const handLabeledRoute = structuredClone(recipe);
    handLabeledRoute.route.alternatives[0].terminalObservedKey =
      recipe.terminalObservedKey;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: handLabeledRoute,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(handLabeledRoute),
        coverage,
      }),
    ).toThrow(/public memory-database call/);
  });

  test("accepts cr-sqlite closure only through both public aliases", () => {
    const catalog = completeClosedSqliteCrSqliteCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const oneAlias = closedRuntimeObservation(recipe);
    oneAlias.invocation.result.errorMessage =
      "exact:sqlite: cr-sqlite extension not available. The Ibex runtime must be built with cr-sqlite support.";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: oneAlias,
        coverage,
      }),
    ).toThrow(/every public alias/);

    const drifted = structuredClone(recipe);
    drifted.publicSurfaceProbe.invocation.operation.methodName =
      "loadExtension";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: drifted,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(drifted),
        coverage,
      }),
    ).toThrow(/public memory-database call/);
  });

  test("accepts debugger ABI closure only for the physical no-debugger target result", () => {
    const catalog = completeClosedDebuggerAbiCatalog();
    const recipe = catalog.recipes[0];
    const execution = buildPublicFixtureEvidence({
      recipe,
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: closedRuntimeObservation(recipe),
      coverage,
    });
    expect(() =>
      buildPublicSurfaceExecutionArtifact({
        recipeCatalog: catalog,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest:
          "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        target,
        engine,
        coverage,
        executions: [execution],
      }),
    ).not.toThrow();

    const missingContracts = structuredClone(recipe);
    delete missingContracts.publicSurfaceProbe.invocation.sourceDescriptor
      .sourceMetadata.outputContracts;
    missingContracts.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        missingContracts.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: missingContracts,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(missingContracts),
        coverage,
      }),
    ).toThrow(/physical no-debugger target/);

    const mismatchedDefinitionContract = structuredClone(recipe);
    mismatchedDefinitionContract.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.definitions[0].outputContract.status =
      "unresolved";
    mismatchedDefinitionContract.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        mismatchedDefinitionContract.publicSurfaceProbe.invocation
          .sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: mismatchedDefinitionContract,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(
          mismatchedDefinitionContract,
        ),
        coverage,
      }),
    ).toThrow(/physical no-debugger target/);

    const windows = structuredClone(recipe);
    windows.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple =
      "x86_64-pc-windows-msvc";
    windows.publicSurfaceProbe.invocation.sourceDescriptor.selectedSourceRef =
      "src/engine/hermes_runtime_platform_windows.cc#ex_hermes_debugger_eval";
    windows.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
      windows.publicSurfaceProbe.invocation.sourceDescriptor,
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: windows,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(windows),
        coverage,
      }),
    ).not.toThrow();

    const wrongTargetSource = structuredClone(recipe);
    wrongTargetSource.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple =
      "x86_64-pc-windows-msvc";
    wrongTargetSource.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongTargetSource.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongTargetSource,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(wrongTargetSource),
        coverage,
      }),
    ).toThrow(/physical no-debugger target/);

    const wrongResult = structuredClone(recipe);
    wrongResult.publicSurfaceProbe.invocation.operation.expectedCallResult =
      "no-event";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongResult,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(wrongResult),
        coverage,
      }),
    ).toThrow(/physical no-debugger target/);

    const wrongError = closedRuntimeObservation(recipe);
    wrongError.invocation.result.errorMessage = "generic debugger error";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongError,
        coverage,
      }),
    ).toThrow(/no-debugger physical result/);
  });

  test("accepts shared-runtime global closure only for a reviewed installation path", () => {
    const catalog = completeClosedSharedRuntimeGlobalCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    for (const options of [
      {
        globalName: "Bun",
        memberName: "accessibility.get",
        route: "shared-runtime",
        routes: ["shared-runtime"],
        sourceKey: "shared_runtime",
        sourceRefs: [
          "packages/ibex-runtime-js/src/core/accessibility.ts#get.get",
        ],
        surfaceName: "global:Bun.accessibility.get",
        targetTriple: "x86_64-pc-windows-msvc",
        targetVariant: "all",
      },
      {
        globalName: "MessagePort",
        memberName: "postMessage",
        route: "shared-runtime",
        routes: ["shared-runtime"],
        sourceKey: "shared_runtime",
        sourceRefs: [
          "packages/ibex-runtime-js/src/messaging.ts#MessagePort.prototype.postMessage",
        ],
        surfaceName: "global:MessagePort.postMessage",
        targetVariant: "all",
      },
      {
        globalName: "localStorage",
        memberName: null,
        route: "composed:legacy-bootstrap+shared-runtime",
        routes: ["legacy-bootstrap", "shared-runtime"],
        sourceKey: "shared_runtime",
        sourceRefs: ["src/engine/bootstrap/web-storage.js#localStorage"],
        surfaceName: "global:localStorage",
        targetTriple: "x86_64-pc-windows-msvc",
      },
      ...[
        null,
        "clearModuleDebugSources",
        "formatBytes",
        "samples",
        "snapshot",
        "start",
        "state",
        "stop",
        "summary",
      ].map((memberName) => {
        const surfaceName =
          memberName === null
            ? "__exactMemoryDebug"
            : `__exactMemoryDebug.${memberName}`;
        return {
          globalName: "__exactMemoryDebug",
          memberName,
          route: "composed:legacy-bootstrap+shared-runtime",
          routes: ["legacy-bootstrap", "shared-runtime"],
          sourceKey: "shared_runtime",
          sourceRefs:
            memberName === null
              ? [
                  "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:__exactMemoryDebug",
                  "src/engine/bootstrap/exact-global.js#__exactMemoryDebug",
                  "src/engine/hermes_runtime.cc#__exactMemoryDebug",
                ]
              : [
                  `packages/ibex-runtime-js/src/bootstrap.ts#installGlobals.${memberName}`,
                  "packages/ibex-runtime-js/src/bootstrap.ts#installGlobals:globals:__exactMemoryDebug",
                  `src/engine/bootstrap/exact-global.js#__exactMemoryDebug.${memberName}`,
                ],
          surfaceName,
        };
      }),
      {
        globalName: "process",
        memberName: "__exactAsyncIpcListenerPatch",
        sourceKey: "global_ipc_listener",
        sourceRefs: [
          "src/engine/bootstrap/ipc-listener.js#process.__exactAsyncIpcListenerPatch",
        ],
        surfaceName: "global:process.__exactAsyncIpcListenerPatch",
      },
      {
        globalName: "process",
        memberName: "__exactLateIpcListenerPatch",
        sourceKey: "global_ipc_listener",
        sourceRefs: [
          "src/engine/bootstrap/ipc-listener.js#process.__exactLateIpcListenerPatch",
        ],
        surfaceName: "global:process.__exactLateIpcListenerPatch",
      },
      {
        globalName: "process",
        memberName: "__exactProcessIpcBootstrapInstalled",
        sourceKey: "global_compat_polyfills",
        sourceRefs: [
          "src/engine/bootstrap/compat-polyfills.js#process.__exactProcessIpcBootstrapInstalled",
        ],
        surfaceName: "global:process.__exactProcessIpcBootstrapInstalled",
      },
      {
        globalName: "process",
        memberName: "__exactStreamPinned",
        sourceKey: "global_module_loader",
        sourceRefs: [
          "src/engine/bootstrap/module-loader.js#process.__exactStreamPinned",
        ],
        surfaceName: "global:process.__exactStreamPinned",
      },
      {
        globalName: "process",
        memberName: "__exactStreamStabilityPatched",
        route: "composed:evaluated-native-script+legacy-bootstrap",
        routes: ["evaluated-native-script", "legacy-bootstrap"],
        sourceKey: "evaluated_native_script",
        sourceKeys: [
          "evaluated_native_script",
          "global_compat_polyfills",
        ],
        sourceRefs: [
          "src/engine/bootstrap/compat-polyfills.js#process.__exactStreamStabilityPatched",
          "src/engine/hermes_runtime_process_setup.cc#embedded:streamStabilityPatchJS:process.__exactStreamStabilityPatched",
        ],
        surfaceName: "global:process.__exactStreamStabilityPatched",
      },
      {
        globalName: "process",
        memberName: "_umask",
        route: "shared-runtime",
        routes: ["shared-runtime"],
        sourceKey: "shared_runtime",
        sourceRefs: [
          "packages/ibex-runtime-js/src/node/process.ts#Process.prototype._umask",
        ],
        surfaceName: "global:process._umask",
        targetVariant: "all",
      },
      {
        globalName: "process",
        memberName: "domain",
        sourceKey: "global_bootstrap_globals",
        sourceRefs: [
          "src/engine/bootstrap/bootstrap-globals.js#process.domain",
        ],
        surfaceName: "global:process.domain",
      },
    ]) {
      const reviewed = completeClosedSharedRuntimeGlobalCatalog(options)
        .recipes[0];
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: reviewed,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: closedRuntimeObservation(reviewed),
          coverage,
        }),
      ).not.toThrow();
    }

    const wrongRoute = structuredClone(recipe);
    wrongRoute.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.installationBranches[0].route =
      "shared-runtime";
    wrongRoute.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongRoute.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongRoute,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(wrongRoute),
        coverage,
      }),
    ).toThrow(/reviewed installation path/);

    const widenedComposition =
      completeClosedSharedRuntimeGlobalCatalog({
        globalName: "localStorage",
        memberName: null,
        route: "composed:legacy-bootstrap+shared-runtime",
        routes: ["shared-runtime", "legacy-bootstrap"],
        sourceKey: "shared_runtime",
        sourceRefs: ["src/engine/bootstrap/web-storage.js#localStorage"],
        surfaceName: "global:localStorage",
      }).recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: widenedComposition,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(widenedComposition),
        coverage,
      }),
    ).toThrow(/reviewed installation path/);

    const present = closedRuntimeObservation(recipe);
    present.invocation.result.engineExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: present,
        coverage,
      }),
    ).toThrow(/not physically absent/);
  });

  test("accepts armed native global closure only for a source-derived JSI path", () => {
    const catalog = completeClosedArmedNativeGlobalCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const windows = structuredClone(recipe);
    windows.publicSurfaceProbe.invocation.sourceDescriptor.targetTriple =
      "x86_64-pc-windows-msvc";
    windows.publicSurfaceProbe.invocation.sourceDescriptorDigest = taggedDigest(
      windows.publicSurfaceProbe.invocation.sourceDescriptor,
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: windows,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(windows),
        coverage,
      }),
    ).not.toThrow();

    for (const workletCatalog of [
      completeClosedArmedWorkletGlobalCatalog(),
      completeClosedArmedWorkletGlobalCatalog({
        evaluated: true,
        targetTriple: "x86_64-pc-windows-msvc",
      }),
    ]) {
      const worklet = workletCatalog.recipes[0];
      expect(() =>
        buildPublicFixtureEvidence({
          recipe: worklet,
          engineBinaryDigest: engine.binaryDigest,
          runtimeObservation: closedRuntimeObservation(worklet),
          coverage,
        }),
      ).not.toThrow();
    }

    const driftedWorklet = completeClosedArmedWorkletGlobalCatalog({
      evaluated: true,
    }).recipes[0];
    driftedWorklet.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.sourceUrls =
      ["invented-worklet.js"];
    driftedWorklet.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        driftedWorklet.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: driftedWorklet,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(driftedWorklet),
        coverage,
      }),
    ).toThrow(/source-derived JSI path/);

    const inventedSource = structuredClone(recipe);
    inventedSource.publicSurfaceProbe.invocation.sourceDescriptor.sourceMetadata.publicInvocation.sourceRef =
      "src/engine/hermes_runtime.cc#invented";
    inventedSource.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inventedSource.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inventedSource,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(inventedSource),
        coverage,
      }),
    ).toThrow(/source-derived JSI path/);

    const present = closedRuntimeObservation(recipe);
    present.invocation.result.engineExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: present,
        coverage,
      }),
    ).toThrow(/not physically absent/);
  });

  test("accepts Exact closure only for the authenticated unendowed operation", () => {
    const catalog = completeClosedExactCatalog();
    const recipe = catalog.recipes[0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(recipe),
        coverage,
      }),
    ).not.toThrow();

    const endowed = structuredClone(recipe);
    endowed.publicSurfaceProbe.invocation.operation.selectedOperationId = 7;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: endowed,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: closedRuntimeObservation(endowed),
        coverage,
      }),
    ).toThrow(/authenticated unendowed operation/);

    const wrongError = closedRuntimeObservation(recipe);
    wrongError.invocation.result.errorMessage = "generic IPC failure";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongError,
        coverage,
      }),
    ).toThrow(/did not fail closed before the embedder callback/);
  });

  test("accepts exact source-bound target absence and rejects invented entry proof", () => {
    const catalog = targetAbsenceCatalog();
    const recipe = catalog.recipes[0];
    const observation = targetAbsenceObservation(recipe);
    const execution = buildPublicFixtureEvidence({
      recipe,
      engineBinaryDigest: engine.binaryDigest,
      runtimeObservation: observation,
      coverage,
    });
    const artifact = buildPublicSurfaceExecutionArtifact({
      recipeCatalog: catalog,
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      target,
      engine,
      coverage,
      executions: [execution],
    });
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog, {
        target,
        sourceRevision: "a".repeat(40),
        sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        engine,
        coverage,
        expectedFixtureIds: [recipe.fixtureId],
      }),
    ).not.toThrow();

    const invented = targetAbsenceObservation(recipe);
    invented.invocation.executionProof = {
      kind: "native-return",
      bodyEntered: true,
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: invented,
        coverage,
      }),
    ).toThrow(/execution proof disagrees/);
  });

  test("accepts a source-bound global read and rejects function-return proof", () => {
    const catalog = globalReadCatalog();
    const recipe = catalog.recipes[0];
    const observation = globalReadObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    const inheritedRecipe = structuredClone(recipe);
    inheritedRecipe.publicSurfaceProbe.invocation.sourceDescriptor.memberKinds =
      ["inherited", "static"];
    inheritedRecipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        inheritedRecipe.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const inheritedObservation = globalReadObservation(inheritedRecipe);
    inheritedObservation.invocation.result.ownerDepths = [0, 1];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inheritedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: inheritedObservation,
        coverage,
      }),
    ).not.toThrow();
    inheritedObservation.invocation.result.valueType = "function";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inheritedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: inheritedObservation,
        coverage,
      }),
    ).toThrow(/exact property owner chain/);
    inheritedObservation.invocation.result.valueType = "string";
    inheritedObservation.invocation.result.ownerDepths = [0, 0];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: inheritedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: inheritedObservation,
        coverage,
      }),
    ).toThrow(/exact property owner chain/);

    observation.invocation.executionProof.kind = "native-return";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/execution proof disagrees/);
  });

  test("binds the private cwd facade to exact manifest provenance", () => {
    const catalog = privateCwdFacadeCatalog();
    const recipe = catalog.recipes[0];
    const observation = privateCwdFacadeObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const driftedPath = structuredClone(recipe);
    driftedPath.publicSurfaceProbe.invocation.publicAccess.path = [
      "process",
      "chdir",
    ];
    driftedPath.publicSurfaceProbe.invocation.publicAccessDigest = taggedDigest(
      driftedPath.publicSurfaceProbe.invocation.publicAccess,
    );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: driftedPath,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/private native facade provenance drift/);

    const driftedInstallId = structuredClone(recipe);
    driftedInstallId.publicSurfaceProbe.invocation.publicAccess.installId =
      "root-global.process.cwd.2583c1a2d2ca2d7b";
    driftedInstallId.publicSurfaceProbe.invocation.publicAccessDigest =
      taggedDigest(
        driftedInstallId.publicSurfaceProbe.invocation.publicAccess,
      );
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: driftedInstallId,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/private native facade provenance drift/);

    const staleDigest = structuredClone(recipe);
    staleDigest.publicSurfaceProbe.invocation.publicAccessDigest =
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: staleDigest,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/private native facade provenance drift/);
  });

  test("accepts armed environment enumeration only when its object is empty", () => {
    const recipe = completeCatalog().recipes[0];
    Object.assign(recipe, {
      fixtureId: "fixture.native.get-all-env.empty",
      classification: "effects",
      scenario: "branch-selection",
      actionIds: [],
      terminalObservedKey: "native-op:__exactGetAllEnv",
    });
    recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
    recipe.route.alternatives[0].terminalObservedKey =
      recipe.terminalObservedKey;
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    Object.assign(invocation, {
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName: "__exactGetAllEnv",
      sourceDescriptor: {
        kind: "native-global-function",
        globalName: "__exactGetAllEnv",
        arity: 0,
        sourceRef:
          "src/engine/hermes_runtime.cc#jsi-global:__exactGetAllEnv",
      },
      arguments: [],
      requiredFloor: [],
      setup: [],
      expectedResult: "return",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      expectedActionIds: [],
    });
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = runtimeObservation(recipe);
    Object.assign(observation.invocation, {
      kind: invocation.kind,
      globalName: invocation.globalName,
      result: {
        kind: "return",
        globalName: invocation.globalName,
        valueType: "object",
        cleanup: "none",
        valuePropertyCount: 0,
      },
      executionProof: {
        kind: "armed-empty-environment-enumeration",
        bodyEntered: true,
        propertyCount: 0,
      },
    });
    delete observation.invocation.moduleSpecifier;
    delete observation.invocation.exportName;
    observation.typedDecisions = [];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const nonempty = structuredClone(observation);
    nonempty.invocation.result.valuePropertyCount = 1;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: nonempty,
        coverage,
      }),
    ).toThrow(/authored cleanup/);

    const weakProof = structuredClone(observation);
    weakProof.invocation.executionProof.propertyCount = 1;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: weakProof,
        coverage,
      }),
    ).toThrow(/execution proof disagrees/);
  });

  test("accepts native async evidence only after authored quiescence", () => {
    const recipe = completeCatalog().recipes[0];
    recipe.terminalObservedKey = "native-op:__exactPublic";
    recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    invocation.invocationSchema = "ibex/capsec-native-global-invocation/1";
    invocation.kind = "native-global-function";
    invocation.globalName = "__exactPublic";
    invocation.sourceDescriptor = {
      kind: "native-global-function",
      globalName: "__exactPublic",
      arity: 0,
      sourceRef: "src/engine/hermes_runtime.cc#jsi-global:__exactPublic",
    };
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    invocation.arguments = [];
    invocation.requiredFloor = [];
    invocation.setup = [];
    invocation.expectedCleanup = "none";
    invocation.completion = {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 1_000,
    };
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = runtimeObservation(recipe);
    delete observation.invocation.moduleSpecifier;
    delete observation.invocation.exportName;
    observation.invocation.kind = invocation.kind;
    observation.invocation.globalName = invocation.globalName;
    observation.invocation.result.globalName = invocation.globalName;
    observation.invocation.result.cleanup = "none";
    observation.invocation.executionProof = {
      kind: "native-return",
      bodyEntered: true,
    };
    observation.invocation.completion = {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 1_000,
      status: "quiescent",
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const wrongCleanup = structuredClone(observation);
    wrongCleanup.invocation.result.cleanup = "closed-unrelated-resource";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongCleanup,
        coverage,
      }),
    ).toThrow(/did not prove its authored cleanup/);

    const pending = structuredClone(observation);
    pending.invocation.completion.status = "pending";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: pending,
        coverage,
      }),
    ).toThrow(/native work escaped its observation session/);

    const missing = structuredClone(observation);
    delete missing.invocation.completion;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missing,
        coverage,
      }),
    ).toThrow(/unknown or missing fields/);
  });

  test("accepts only the exact retained-object invalid-handle refusal", () => {
    const recipe = completeCatalog().recipes[0];
    Object.assign(recipe, {
      classification: "non-capability",
      scenario: "non-capability",
      actionIds: [],
      edgeIds: ["edge.terminal"],
      terminalObservedKey: "native-op:__exactSpawnSetReferenced",
    });
    recipe.route = {
      surfaceObservedKeys: [recipe.terminalObservedKey],
      alternatives: [
        {
          terminalObservedKey: recipe.terminalObservedKey,
          proofPaths: [recipe.terminalObservedKey],
        },
      ],
      ambiguousCallees: [],
    };
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    Object.assign(invocation, {
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName: "__exactSpawnSetReferenced",
      sourceDescriptor: {
        kind: "native-global-function",
        globalName: "__exactSpawnSetReferenced",
        arity: 2,
        sourceRef:
          "src/engine/hermes_runtime_process.cc#jsi-global:__exactSpawnSetReferenced",
      },
      arguments: [
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: false },
      ],
      requiredFloor: [],
      setup: [],
      expectedResult: "invalid-handle",
      expectedTypedStages: [],
      expectedTypedDecisionCount: 0,
      expectedActionIds: [],
      allowedCoverageEdgeIds: ["edge.terminal"],
    });
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: invocation.invocationSchema,
        kind: invocation.kind,
        surfaceObservedKey: recipe.terminalObservedKey,
        globalName: invocation.globalName,
        sourceDescriptorDigest: invocation.sourceDescriptorDigest,
        result: {
          kind: "throw",
          globalName: invocation.globalName,
          errorName: "Error",
          errorMessage: "__exactSpawnSetReferenced: invalid handle",
        },
        executionProof: {
          kind: "retained-object-refusal",
          bodyEntered: true,
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    observation.invocation.result.errorMessage = "unrelated invalid handle";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/exact retained-object refusal/);
  });

  test("accepts platform-cased generic permission-denial messages", () => {
    const recipe = completeCatalog().recipes[0];
    recipe.scenario = "deny";
    recipe.publicSurfaceProbe.invocation.expectedResult =
      "permission-denied";
    const observation = runtimeObservation(recipe);
    observation.invocation.result = {
      kind: "throw",
      errorName: "Error",
      errorMessage:
        "EACCES: permission denied, lstat '/project/capsec-stat-fixture.txt'",
    };
    observation.typedDecisions[0].evidence.outcome = "deny";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    observation.invocation.result.errorMessage = "unrelated filesystem error";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/public invocation did not deny/);
  });

  test("binds the native async dispatcher to its exact worker terminal", () => {
    const recipe = completeCatalog().recipes[0];
    recipe.terminalObservedKey = "native-op:__exactFsPathAsync";
    recipe.route.surfaceObservedKeys = [recipe.terminalObservedKey];
    recipe.route.alternatives = [
      {
        terminalObservedKey: recipe.terminalObservedKey,
        proofPaths: [recipe.terminalObservedKey],
      },
    ];
    recipe.publicSurfaceProbe.surfaceObservedKey = recipe.terminalObservedKey;
    const invocation = recipe.publicSurfaceProbe.invocation;
    Object.assign(invocation, {
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName: "__exactFsPathAsync",
      sourceDescriptor: {
        kind: "native-global-function",
        globalName: "__exactFsPathAsync",
        arity: 6,
        sourceRef:
          "src/engine/hermes_runtime_fs.cc#jsi-global:__exactFsPathAsync",
      },
      arguments: [
        { kind: "json-literal", value: "mkdir" },
        { kind: "json-literal", value: "target/owned-directory" },
        { kind: "json-literal", value: null },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
        { kind: "json-literal", value: 0 },
      ],
      requiredFloor: [],
      setup: [],
      expectedCleanup: "none",
      expectedDenyMessageFragment: "filesystem policy denied",
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      },
      allowedCoverageEdgeIds: ["edge.mkdir-worker"],
    });
    invocation.sourceDescriptorDigest = taggedDigest(
      invocation.sourceDescriptor,
    );
    delete invocation.moduleSpecifier;
    delete invocation.exportName;

    const observation = runtimeObservation(recipe);
    delete observation.invocation.moduleSpecifier;
    delete observation.invocation.exportName;
    Object.assign(observation.invocation, {
      kind: invocation.kind,
      globalName: invocation.globalName,
      result: {
        kind: "return",
        globalName: invocation.globalName,
        valueType: "undefined",
        cleanup: "none",
      },
      executionProof: { kind: "native-return", bodyEntered: true },
      completion: {
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
        status: "quiescent",
      },
    });
    observation.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.mkdir-worker.decision";
    observation.typedDecisions[0].gates[0].coverageEdgeId =
      "edge.mkdir-worker";

    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();

    const deniedRecipe = structuredClone(recipe);
    deniedRecipe.publicSurfaceProbe.invocation.expectedResult =
      "permission-denied";
    const denied = structuredClone(observation);
    denied.invocation.result = {
      kind: "throw",
      globalName: invocation.globalName,
      errorName: "Error",
      errorMessage: "filesystem policy denied",
    };
    denied.invocation.executionProof.kind = "typed-permission-denial";
    denied.typedDecisions[0].evidence.outcome = "deny";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: deniedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: denied,
        coverage,
      }),
    ).not.toThrow();

    const wrongWorker = structuredClone(observation);
    wrongWorker.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.terminal.decision";
    wrongWorker.typedDecisions[0].gates[0].coverageEdgeId = "edge.terminal";
    const wrongWorkerRecipe = structuredClone(recipe);
    wrongWorkerRecipe.publicSurfaceProbe.invocation.allowedCoverageEdgeIds = [
      "edge.mkdir-worker",
      "edge.terminal",
    ];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongWorkerRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongWorker,
        coverage,
      }),
    ).toThrow(/source-selected worker/);
  });

  test("keeps the native async worker-terminal account exact", () => {
    const descriptor = (operation, overrides = {}) => ({
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName: "__exactFsPathAsync",
      sourceDescriptor: {
        sourceRef:
          "src/engine/hermes_runtime_fs.cc#jsi-global:__exactFsPathAsync",
      },
      setup: [],
      arguments: [{ kind: "json-literal", value: operation }],
      ...overrides,
    });
    const expected = new Map([
      ["mkdir", "native-op:__exactMkdir"],
      ["readdir", "native-op:__exactReaddir"],
      ["realpath", "native-op:__exactRealpath"],
      ["statfs", "native-op:__exactStatfs"],
      ["truncate", "native-op:__exactTruncate"],
    ]);

    for (const [operation, terminal] of expected) {
      expect(nativeAsyncWorkerTerminal(descriptor(operation))).toBe(terminal);
    }
    for (const globalName of [
      "__exactFsFdAsync",
      "__exactFsFchmodSync",
      "__exactFsFstatSync",
      "__exactFsFtruncateSync",
      "__exactFsFutimesSync",
      "__exactFsRead",
      "__exactFsReadv",
      "__exactFsWrite",
    ]) {
      expect(
        nativeAsyncWorkerTerminal(
          descriptor("unrelated", {
            globalName,
            arguments: [],
            setup: [{ kind: "fs-read-file" }],
          }),
        ),
      ).toBe("native-op:__exactFsOpen");
    }
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("unrelated", {
          globalName: "__exactFsOpenAsync",
          arguments: [],
        }),
      ),
    ).toBe("native-op:__exactFsOpen");
    expect(
      nativeAsyncWorkerTerminals(
        descriptor("unrelated", {
          globalName: "__exactFsReadFileAsync",
          arguments: [],
          setup: [{ kind: "fs-read-file" }],
        }),
      ),
    ).toEqual([
      "native-op:__exactFsOpen",
      "native-op:__exactFsReadFileAsync",
    ]);
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("unrelated", {
          globalName: "__exactFsReadFileAsync",
          arguments: [],
          setup: [{ kind: "fs-read-file" }],
        }),
      ),
    ).toBeNull();
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("unrelated", {
          globalName: "__exactFsRead",
          arguments: [],
          setup: [{ kind: "fs-read-file" }],
          sourceDescriptor: {
            sourceRef:
              "src/engine/hermes_runtime_fs_windows.cc#jsi-global:__exactFsRead",
          },
        }),
      ),
    ).toBeNull();
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("unrelated", {
          globalName: "__exactFsRead",
          arguments: [],
        }),
      ),
    ).toBeNull();
    for (const globalName of [
      "__exactFsFdatasyncSync",
      "__exactFsFsyncSync",
      "__exactFsReadAsync",
      "__exactFsReadvAsync",
    ]) {
      expect(
        nativeAsyncWorkerTerminal(
          descriptor("unrelated", {
            globalName,
            arguments: [],
            setup: [{ kind: "fs-write-file" }],
          }),
        ),
      ).toBeNull();
    }
    expect(nativeAsyncWorkerTerminal(descriptor("mkdtemp"))).toBeNull();
    expect(nativeAsyncWorkerTerminal(descriptor("chmod"))).toBeNull();
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("unrelated", {
          globalName: "__exactFsOpen",
          arguments: [],
        }),
      ),
    ).toBeNull();
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("mkdir", { globalName: "__exactMkdir" }),
      ),
    ).toBeNull();
    expect(
      nativeAsyncWorkerTerminal(
        descriptor("mkdir", { arguments: [{ kind: "generated-value" }] }),
      ),
    ).toBeNull();
  });

  test("keeps native filesystem denial expectations on the reviewed globals", () => {
    const descriptor = (globalName, expectedDenyMessageFragment) => ({
      invocationSchema: "ibex/capsec-native-global-invocation/1",
      kind: "native-global-function",
      globalName,
      expectedDenyMessageFragment,
    });
    for (const globalName of [
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
    ]) {
      expect(() =>
        validateNativeFilesystemDenialRecipeDescriptor(
          descriptor(globalName, "filesystem policy denied"),
        ),
      ).not.toThrow();
    }
    expect(() =>
      validateNativeFilesystemDenialRecipeDescriptor(
        descriptor("__exactUnknownFsOperation", "filesystem policy denied"),
      ),
    ).toThrow(/unreviewed native denial expectation/);
    expect(() =>
      validateNativeFilesystemDenialRecipeDescriptor(
        descriptor("__exactLstat", "Permission denied"),
      ),
    ).toThrow(/unreviewed native denial expectation/);
  });

  test("accepts a source-bound zero-effect host ABI branch with cleanup", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const selectedBranch = {
      id: "memory",
      when: [{ fact: "sqlite.open.mode", equals: "memory" }],
    };
    const sourceDescriptor = {
      kind: "host-abi-function",
      functionName: "ex_host_sqlite_open",
      sourceRefs: ["src/host/abi.rs#ex_host_sqlite_open"],
      sourceMetadata: {
        definitions: [
          {
            language: "rust",
            sourceRef: "src/host/abi.rs#ex_host_sqlite_open",
            targetVariant: "default",
          },
        ],
      },
      selectedBranch,
    };
    Object.assign(recipe, {
      fixtureId: "fixture.host-sqlite.memory.no-effect",
      scenario: "no-effect",
      edgeIds: ["edge.host-sqlite"],
      actionIds: [],
      terminalObservedKey: "host-abi:ex_host_sqlite_open",
      route: {
        surfaceObservedKeys: ["host-abi:ex_host_sqlite_open"],
        alternatives: [
          {
            terminalObservedKey: "host-abi:ex_host_sqlite_open",
            proofPaths: ["host-abi:ex_host_sqlite_open"],
          },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey: recipe.terminalObservedKey,
      command: ["cargo", "test", "capsec_public_native_primary_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        functionName: "ex_host_sqlite_open",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "sqlite-memory", selectedBranch },
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.host-sqlite"],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        surfaceObservedKey: recipe.terminalObservedKey,
        functionName: "ex_host_sqlite_open",
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "return",
          functionName: "ex_host_sqlite_open",
          operation: "sqlite-memory",
          cleanup: "released-sqlite-memory-state",
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.cleanup = "none";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not prove bounded cleanup/);
  });

  test("accepts exact module-loader authority access with no CapSec decision", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const sourceDescriptor = {
      kind: "module-loader-function",
      surfaceName: "module-runner-cache-access",
      sourceRefs: ["src/module_loader/security.rs#authorize_then_access"],
    };
    Object.assign(recipe, {
      fixtureId: "fixture.module-loader.cache.non-capability",
      classification: "non-capability",
      scenario: "non-capability",
      edgeIds: ["edge.module-loader-cache"],
      actionIds: [],
      terminalObservedKey: "loader:module-runner-cache-access",
      route: {
        surfaceObservedKeys: ["loader:module-runner-cache-access"],
        alternatives: [
          {
            terminalObservedKey: "loader:module-runner-cache-access",
            proofPaths: ["loader:module-runner-cache-access"],
          },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey: recipe.terminalObservedKey,
      command: ["cargo", "test", "capsec_public_native_primary_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-module-loader-invocation/1",
        kind: "module-loader-authority",
        surfaceName: "module-runner-cache-access",
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "cache-read" },
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.module-loader-cache"],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-module-loader-invocation/1",
        kind: "module-loader-authority",
        surfaceObservedKey: recipe.terminalObservedKey,
        surfaceName: "module-runner-cache-access",
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "return",
          surfaceName: "module-runner-cache-access",
          operation: "cache-read",
          accessExecuted: true,
          cleanup: "none",
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.accessExecuted = false;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not prove its exact access/);
  });

  test("accepts only an exact loader-private source-point receipt", () => {
    const surfaceName = "function:javascript:checkImportGate";
    const surfaceObservedKey = `loader:${surfaceName}`;
    const edge = {
      id: "edge.loader-check-import-gate",
      classification: "non-capability",
      surface: { kind: "loader", name: surfaceName },
    };
    const surface = {
      kind: "loader",
      name: surfaceName,
      observedKey: surfaceObservedKey,
      sourceRefs: [
        "src/engine/bootstrap/module-loader.js#checkImportGate",
      ],
      metadata: { evidenceType: "loader-function" },
    };
    const invocation = authoredModuleLoaderCapturedInvocation({
      surface,
      coverageEdge: edge,
      target,
    });
    const recipe = completeCatalog().recipes[0];
    Object.assign(recipe, {
      fixtureId: "fixture.loader.check-import-gate.non-capability",
      classification: "non-capability",
      scenario: "non-capability",
      edgeIds: [edge.id],
      implementationBranchIds: [`${edge.id}.main`],
      enforcementBranchIds: [`${edge.id}.main`],
      actionIds: [],
      terminalObservedKey: surfaceObservedKey,
      expectedObservation: {
        kind: "enforcement-branch",
        branchId: `${edge.id}.main`,
      },
      route: {
        surfaceObservedKeys: [surfaceObservedKey],
        alternatives: [
          {
            terminalObservedKey: surfaceObservedKey,
            proofPaths: [surfaceObservedKey],
          },
        ],
        ambiguousCallees: [],
      },
      publicSurfaceProbe: {
        kind: "public-surface-invocation",
        surfaceObservedKey,
        command: ["cargo", "test", "capsec_public_loader_recipe_batch"],
        invocation,
      },
    });
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: invocation.invocationSchema,
        kind: invocation.kind,
        surfaceObservedKey,
        moduleSpecifier: invocation.moduleSpecifier,
        entrypoint: invocation.entrypoint,
        sourceDescriptorDigest: invocation.sourceDescriptorDigest,
        completion: {
          ...invocation.completion,
          status: "quiescent",
        },
        sourceExecution: {
          schema: "ibex/capsec-loader-source-point-execution/1",
          observationId: recipe.fixtureId,
          runtimeNonce: "u64:42",
          executionPoint: surfaceName,
          matchCount: 1,
          loaderPrivate: true,
        },
        result: {
          kind: "return",
          sourceOperationAttempted: true,
          entrypointProof: {
            presence: "present",
            descriptorKind: "data",
            valueType: "function",
          },
          rawOutput: {
            kind: "return",
            rawValueShape: "object",
            value: null,
            errorCode: null,
          },
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    const build = () =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage: { edges: [edge] },
      });

    expect(build).not.toThrow();
    observation.invocation.sourceExecution.executionPoint =
      "function:javascript:load";
    expect(build).toThrow(/captured module-loader invocation descriptor drift/);
    observation.invocation.sourceExecution.executionPoint = surfaceName;
    observation.invocation.sourceExecution.matchCount = 0;
    expect(build).toThrow(/captured module-loader invocation descriptor drift/);
    observation.invocation.sourceExecution.matchCount = 1;
    invocation.requiredAuthority = [{ cap: "fs:read" }];
    expect(build).toThrow(/captured module-loader invocation descriptor drift/);
  });

  test("accepts a source-bound module-runner ABI only when the graph enters it", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const functionName = "ex_hermes_module_compile_factory";
    const sourceDescriptor = {
      kind: "host-abi-function",
      functionName,
      sourceRefs: [`src/engine/hermes_module_runner.cc#${functionName}`],
      sourceMetadata: {
        definitions: [
          {
            language: "c++",
            sourceRef: `src/engine/hermes_module_runner.cc#${functionName}`,
            targetVariant: "default",
          },
        ],
      },
    };
    Object.assign(recipe, {
      fixtureId: "fixture.module-runner.compile.non-capability",
      classification: "non-capability",
      scenario: "non-capability",
      edgeIds: ["edge.module-runner-compile"],
      actionIds: [],
      terminalObservedKey: `host-abi:${functionName}`,
      route: {
        surfaceObservedKeys: [`host-abi:${functionName}`],
        alternatives: [
          {
            terminalObservedKey: `host-abi:${functionName}`,
            proofPaths: [`host-abi:${functionName}`],
          },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey: recipe.terminalObservedKey,
      command: ["cargo", "test", "capsec_public_native_primary_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        functionName,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "module-runner-source-graph" },
        expectedResult: "return",
        expectedTypedStages: [],
        expectedTypedDecisionCount: 0,
        allowedCoverageEdgeIds: ["edge.module-runner-compile"],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-host-abi-invocation/1",
        kind: "host-abi-function",
        surfaceObservedKey: recipe.terminalObservedKey,
        functionName,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "return",
          functionName,
          operation: "module-runner-source-graph",
          observedFunctionNames: [functionName],
          cleanup: "released-module-graph",
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.observedFunctionNames = [];
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not enter the exact host ABI/);
  });

  test("accepts armed module namespace closure only at the exact ABI", () => {
    const catalog = completeCatalog();
    const recipe = catalog.recipes[0];
    const functionName = "ex_hermes_module_record_namespace_json";
    const surfaceObservedKey = `host-abi:${functionName}`;
    const sourceDescriptor = {
      kind: "closed-module-runner-namespace",
      surfaceObservedKey,
      sourceRefs: [`src/engine/hermes_module_runner.cc#${functionName}`],
      sourceMetadata: {
        definitions: [
          {
            language: "c++",
            sourceRef: `src/engine/hermes_module_runner.cc#${functionName}`,
          },
        ],
      },
    };
    const expectedError =
      "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup";
    Object.assign(recipe, {
      fixtureId: "fixture.module-runner.namespace.closed",
      classification: "closed",
      scenario: "closed",
      edgeIds: ["edge.module-runner-namespace-closed"],
      actionIds: [],
      terminalObservedKey: surfaceObservedKey,
      route: {
        surfaceObservedKeys: [surfaceObservedKey],
        alternatives: [
          { terminalObservedKey: surfaceObservedKey, proofPaths: [surfaceObservedKey] },
        ],
        ambiguousCallees: [],
      },
    });
    recipe.publicSurfaceProbe = {
      kind: "public-surface-invocation",
      surfaceObservedKey,
      command: ["cargo", "test", "capsec_public_closed_recipe_batch"],
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        surfaceKind: "host-abi",
        surfaceName: functionName,
        sourceDescriptor,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        operation: { kind: "module-runner-namespace", expectedError },
        expectedResult: "closed",
        expectedTypedDecisionCount: 0,
        expectedTypedStages: [],
        allowedCoverageEdgeIds: [],
        expectedActionIds: [],
      },
    };
    const observation = {
      observationSchema: "ibex/capsec-runtime-public-observation/1",
      invocation: {
        invocationSchema: "ibex/capsec-closed-surface-invocation/1",
        kind: "closed-surface",
        surfaceObservedKey,
        surfaceKind: "host-abi",
        surfaceName: functionName,
        sourceDescriptorDigest: taggedDigest(sourceDescriptor),
        result: {
          kind: "closed",
          surfaceKind: "host-abi",
          surfaceName: functionName,
          mechanism: "module-runner-namespace",
          errorName: "ClosedSurface",
          errorMessage: expectedError,
          engineExecuted: true,
          projectCodeExecuted: false,
        },
      },
      legacyObservationCount: 0,
      typedDecisions: [],
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).not.toThrow();
    observation.invocation.result.errorMessage = "different rejection";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observation,
        coverage,
      }),
    ).toThrow(/did not fail closed/);
  });

  test("rejects rationale-only callback checks as public fixture evidence", () => {
    const catalog = completeCallbackCatalog();
    const recipe = catalog.recipes[0];
    const observed = callbackRuntimeObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/callback invariant runtime invocation descriptor drift/);
  });

  test("accepts Exact non-capability evidence only from its bound ABI lifecycle", () => {
    const catalog = completeExactCallbackCatalog();
    const recipe = catalog.recipes[0];
    const observed = exactCallbackRuntimeObservation(recipe);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).not.toThrow();

    const wrongScope = structuredClone(recipe);
    wrongScope.publicSurfaceProbe.invocation.sourceDescriptor.proofScope =
      "terminal-body-entry";
    wrongScope.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(wrongScope.publicSurfaceProbe.invocation.sourceDescriptor);
    const wrongScopeObservation = exactCallbackRuntimeObservation(wrongScope);
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongScope,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongScopeObservation,
        coverage,
      }),
    ).toThrow(/callback invariant runtime invocation descriptor drift/);

    const wrongMechanism = structuredClone(recipe);
    wrongMechanism.publicSurfaceProbe.invocation.sourceDescriptor.executionMechanism =
      "exact-endowment-install";
    wrongMechanism.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongMechanism.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const wrongMechanismObservation =
      exactCallbackRuntimeObservation(wrongMechanism);
    wrongMechanismObservation.invocation.result.checks.executionMechanism =
      "exact-endowment-install";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongMechanism,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongMechanismObservation,
        coverage,
      }),
    ).toThrow(/not source-bound/);

    const replayWon = structuredClone(observed);
    replayWon.invocation.result.checks.completion = "7";
    replayWon.invocation.result.checks.completionCallbacksDelivered = 2;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: replayWon,
        coverage,
      }),
    ).toThrow(/single-use Exact completion route/);
  });

  test("accepts startup environment carriers only with exact source, resource, and principal evidence", () => {
    for (const scenario of ["allow", "deny", "branch-selection"]) {
      const catalog = completeStartupEnvironmentCatalog(scenario);
      const recipe = catalog.recipes[0];
      const observed = startupEnvironmentRuntimeObservation(recipe);
      const execution = buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      });
      expect(execution.evidence.terminalObservedKey).toBe(
        "startup:env:NODE_DEBUG",
      );
    }

    const pairedCoverage = structuredClone(coverage);
    const pairedCarrier = pairedCoverage.edges.find(
      (edge) => edge.id === "edge.startup-env-node-debug",
    );
    pairedCarrier.surface.name = "env:EXACT_PIPELINE_DEBUG";
    pairedCarrier.logicalBranches.find(
      (branch) => branch.id === "absent",
    ).when = [
      {
        fact: "environment.startup.exact_pipeline_debug",
        equals: "absent",
      },
    ];
    for (const scenario of ["allow", "deny"]) {
      const pairedCatalog =
        completePairedStartupEnvironmentCatalog(scenario);
      const pairedRecipe = pairedCatalog.recipes[0];
      const pairedObserved =
        startupEnvironmentRuntimeObservation(pairedRecipe);
      const execution = buildPublicFixtureEvidence({
        recipe: pairedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: pairedObserved,
        coverage: pairedCoverage,
      });
      expect(
        execution.evidence.runtimeObservation.invocation.result
          .observedEnvironmentNames,
      ).toEqual([
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ]);
    }
    const pairedCatalog = completePairedStartupEnvironmentCatalog("allow");
    const pairedRecipe = pairedCatalog.recipes[0];
    const missingCompanion = startupEnvironmentRuntimeObservation(pairedRecipe);
    missingCompanion.typedDecisions[2].decisionSet.effects[0].resource.requested.name =
      "EXACT_PIPELINE_DEBUG";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: pairedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: missingCompanion,
        coverage: pairedCoverage,
      }),
    ).toThrow(/lost its exact resource or principal binding/);

    const catalog = completeStartupEnvironmentCatalog("allow");
    const recipe = catalog.recipes[0];
    const observed = startupEnvironmentRuntimeObservation(recipe);

    const incompleteSourceSet = structuredClone(recipe);
    incompleteSourceSet.publicSurfaceProbe.invocation.sourceDescriptor.liveSourceRefs.pop();
    incompleteSourceSet.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        incompleteSourceSet.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    expect(() =>
      validateStartupEnvironmentRecipeDescriptor(incompleteSourceSet),
    ).toThrow(/startup environment runtime invocation descriptor drift/);

    const wrongResource = structuredClone(observed);
    wrongResource.typedDecisions[0].decisionSet.effects[0].resource.requested.name =
      "NODE_OPTIONS";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongResource,
        coverage,
      }),
    ).toThrow(/lost its exact resource or principal binding/);

    const wrongActor = structuredClone(observed);
    wrongActor.typedDecisions[0].decisionSet.context.actor = {
      kind: "package",
      name: "image-lib",
      integrity: `sha256-${"B".repeat(43)}`,
      locator: "image-lib@2.4.1",
    };
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongActor,
        coverage,
      }),
    ).toThrow(/typed reason disagrees|exact resource or principal binding/);

    const wrongGate = structuredClone(observed);
    wrongGate.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.startup-env-node-debug.decision";
    wrongGate.typedDecisions[0].gates[0].coverageEdgeId =
      "edge.startup-env-node-debug";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongGate,
        coverage,
      }),
    ).toThrow(/unbound or incomplete typed gate/);

    const wrongResult = structuredClone(observed);
    wrongResult.invocation.result.environmentPresence = "present";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongResult,
        coverage,
      }),
    ).toThrow(/did not prove the startup environment source outcome/);

    const driftedRecipe = structuredClone(recipe);
    driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptor.selectedBranch.when =
      [
        {
          fact: "environment.startup.node_debug",
          equals: "present",
        },
      ];
    driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const driftedObservation = structuredClone(observed);
    driftedObservation.invocation.sourceDescriptorDigest =
      driftedRecipe.publicSurfaceProbe.invocation.sourceDescriptorDigest;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: driftedRecipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: driftedObservation,
        coverage,
      }),
    ).toThrow(/startup environment auxiliary decision is not coverage-bound/);

    const wrongAuxiliary = structuredClone(recipe);
    wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptor.auxiliaryDecisionEdgeId =
      "edge.terminal";
    wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptorDigest =
      taggedDigest(
        wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptor,
      );
    const wrongAuxiliaryObservation = structuredClone(observed);
    wrongAuxiliaryObservation.invocation.sourceDescriptorDigest =
      wrongAuxiliary.publicSurfaceProbe.invocation.sourceDescriptorDigest;
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: wrongAuxiliary,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: wrongAuxiliaryObservation,
        coverage,
      }),
    ).toThrow(/startup environment auxiliary decision is not coverage-bound/);
  });

  test("rejects hand-labeled callback terminals", () => {
    const catalog = completeExactCallbackCatalog();
    const recipe = catalog.recipes[0];
    const observed = exactCallbackRuntimeObservation(recipe);
    observed.invocation.surfaceObservedKey = "native-op:__exactHandLabel";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe,
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/not source-descriptor bound/);
  });

  test("rejects adapter-only evidence explicitly", () => {
    const catalog = completeCatalog();
    expect(() =>
      validatePublicSurfaceExecutionArtifact(
        {
          adapterEvidenceSchema: "ibex/capsec-adapter-probe-evidence/1",
          recipeCatalogDigest: catalog.recipeCatalogDigest,
        },
        { recipeCatalog: catalog },
      ),
    ).toThrow(/adapter-only evidence cannot advertise/);
  });

  test("rejects a nominally complete recipe without an authored public probe", () => {
    const catalog = completeCatalog();
    delete catalog.recipes[0].publicSurfaceProbe;
    catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
    expect(() => assertRecipeCatalogComplete(catalog)).toThrow(
      /lacks an exact authored public-surface probe/,
    );
  });

  test("rejects residual or missing public obligations", () => {
    const catalog = completeCatalog();
    catalog.recipes[0].status = "unresolved";
    catalog.recipes[0].residualReasons = [
      "public-surface-invocation-not-authored",
    ];
    delete catalog.recipes[0].publicSurfaceProbe;
    catalog.summary.fullyExecutableFixtures = 0;
    catalog.summary.unresolvedFixtures = 1;
    catalog.summary.residualReasons = {
      "public-surface-invocation-not-authored": 1,
    };
    catalog.recipeCatalogDigest = computeRecipeCatalogDigest(catalog);
    const artifact = buildPublicSurfaceExecutionArtifact({
      recipeCatalog: catalog,
      sourceRevision: "a".repeat(40),
      sourceTreeDigest: "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      target,
      engine,
      coverage,
      executions: [],
    });
    expect(() =>
      assertPublicSurfaceExecutionComplete(artifact, catalog),
    ).toThrow(/catalog is incomplete/);
  });

  test("rejects a terminal observation not bound by the recipe", () => {
    const catalog = completeCatalog();
    const artifact = completeArtifact(catalog);
    artifact.executions[0].evidence.terminalObservedKey =
      "native-op:__exactOther";
    expect(() =>
      validatePublicSurfaceExecutionArtifact(artifact, {
        recipeCatalog: catalog,
        coverage,
      }),
    ).toThrow(/digest-mismatched|stale or mismatched/);
  });

  test("rejects a manually supplied terminal label in runtime observations", () => {
    const catalog = completeCatalog();
    const observed = runtimeObservation(catalog.recipes[0]);
    observed.typedDecisions[0].terminalBranchId = "enforcement.public";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/unknown or missing fields/);
  });

  test("derives the terminal from the bound coverage edge, not the static claim", () => {
    const catalog = completeCatalog();
    const observed = runtimeObservation(catalog.recipes[0]);
    observed.typedDecisions[0].decisionSet.atomicityGroup =
      "edge.unselected.decision";
    observed.typedDecisions[0].gates[0].coverageEdgeId = "edge.unselected";
    expect(() =>
      buildPublicFixtureEvidence({
        recipe: catalog.recipes[0],
        engineBinaryDigest: engine.binaryDigest,
        runtimeObservation: observed,
        coverage,
      }),
    ).toThrow(/unknown coverage edge/);
  });
});
