/**
 * Source-bound output recipes for builtin callable/accessor rows that cannot
 * be proved by the generic descriptor sweep.
 *
 * This module authors operations only. It never reads the reviewed output
 * disposition or embeds an expected outcome. Every executable route names an
 * exact receiver, arguments, cleanup operation, and one-second quiescence
 * bound. Rows without a bounded receiver/lifecycle are retained as explicit
 * unexercisable routes instead of substituting a descriptor or deliberate
 * throw for `[[return]]` evidence.
 *
 * @ref LLP 0004#the-builtin-module-surface — aliases resolve to one exact
 * source-derived builtin export.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — a
 * callable output requires a normal source call and bounded cleanup.
 * @ref LLP 0023#6-path-bearing-observables — output values come from loaded
 * execution and are joined to reviewed dispositions only after capture.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { authoredNonCapabilityBuiltinOutputInvocation } from "./capsec-builtin-public-probe-templates.mjs";
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

export const BUILTIN_NONCAP_CLOSED_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-builtin-noncap-closed-output-invocation/1";
export const BUILTIN_NONCAP_CLOSED_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "authored-builtin-noncap-closed-output";
export const BUILTIN_NONCAP_CAPTURED_INVOCATION_SCHEMA =
  "ibex/capsec-builtin-noncap-captured-invocation/1";

const BUILTIN_NONCAP_CAPTURED_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand(
    "capsec_public_noncap_builtin_recipe_batch",
    true,
  ),
);

const COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});
const PROTOTYPE_IDIOMS = new Set([
  "exported-constructor-prototype",
  "exported-constructor-inherited-prototype",
]);
const KNOWN_CLASSIFICATIONS = new Set(["non-capability", "closed"]);
const KNOWN_PLATFORMS = new Set(["android", "darwin", "linux"]);
const CONFORMANCE_CAPTURED_SOURCE_OPERATIONS = new Map([
  ...[
    "exact_process",
    "node_buffer",
    "node_console",
    "node_events",
    "node_perf_hooks",
    "node_string_decoder",
    "node_timers",
    "node_timers_promises",
    "node_url",
    "node_util",
  ].map((sourceKey) => [
    sourceKey,
    new Set(["call", "construct", "get"]),
  ]),
  ["node_stream", new Set(["get"])],
]);
const DESCRIPTOR_ROOT_RETURN_ALIASES = new Set([
  "_stream_duplex",
  "_stream_passthrough",
  "_stream_readable",
  "_stream_transform",
  "_stream_writable",
  "assert",
  "assert/strict",
  "bun:sqlite",
  "events",
  "exact:sqlite",
  "node:assert",
  "node:assert/strict",
  "node:events",
  "node:stream",
  "node:string_decoder",
  "stream",
  "string_decoder",
  "ws",
]);
const DESCRIPTOR_OS_CALLS = new Set([
  "arch",
  "availableParallelism",
  "endianness",
  "freemem",
  "homedir",
  "hostname",
  "machine",
  "platform",
  "release",
  "tmpdir",
  "totalmem",
  "type",
  "uptime",
  "version",
]);
const DESCRIPTOR_STREAM_READABLE_MEMBERS = new Set([
  "readableAborted",
  "readableDidRead",
  "readableEncoding",
  "readableEnded",
  "readableFlowing",
  "readableHighWaterMark",
  "readableLength",
  "readableObjectMode",
]);
const DESCRIPTOR_STREAM_WRITABLE_MEMBERS = new Set([
  "writableAborted",
  "writableBuffer",
  "writableCorked",
  "writableEnded",
  "writableFinished",
  "writableHighWaterMark",
  "writableLength",
  "writableNeedDrain",
  "writableObjectMode",
]);
const DESCRIPTOR_STREAM_WEB_CONSTRUCTORS = new Set([
  "ByteLengthQueuingStrategy",
  "CountQueuingStrategy",
  "ReadableStream",
  "ReadableStreamBYOBReader",
  "ReadableStreamDefaultReader",
  "TransformStream",
  "WritableStream",
  "WritableStreamDefaultWriter",
]);

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const json = (value) => ({ kind: "json", value });
const noop = () => ({ kind: "noop-function" });
const buffer = (bytes = [73, 98, 101, 120]) => ({ kind: "buffer", bytes });
const uint8Array = (bytes = [73, 98, 101, 120]) => ({
  kind: "uint8-array",
  bytes,
});
const bigint = (value) => ({ kind: "bigint", value: String(value) });
const blob = (text = "ibex-output-shape") => ({ kind: "blob", text });
const resolvedPromise = (value = "ibex-output-shape") => ({
  kind: "resolved-promise",
  value,
});
const rejectedPromise = (message = "ibex-output-shape") => ({
  kind: "rejected-promise",
  message,
});
const eventEmitter = () => ({ kind: "event-emitter" });
const setupValue = (name) => ({ kind: "setup-value", name });
const constantFunction = (value) => ({ kind: "constant-function", value });
const reducerFunction = () => ({ kind: "reducer-function" });
const webReadableStream = (bytes = false, closed = false) => ({
  kind: "web-readable-stream",
  bytes,
  closed,
});
const webWritableStream = () => ({ kind: "web-writable-stream" });
const consoleWritableSink = () => ({ kind: "console-writable-sink" });
const streamInstance = (
  ownerExportName,
  { ended = false, endAfterOperation = false, deferredCleanup = false, content } = {},
) => ({
  kind: "stream-instance",
  ownerExportName,
  ended,
  endAfterOperation,
  deferredCleanup,
  ...(content === undefined ? {} : { content }),
});
const zlibInput = (ownerExportName) => ({
  kind: "zlib-input",
  ownerExportName,
});
const completionCallback = ({ cleanupReceiver = false } = {}) => ({
  kind: "completion-callback",
  errorFirst: true,
  cleanupReceiver,
});
const cryptoSecretKey = (bytes = [73, 98, 101, 120]) => ({
  kind: "crypto-secret-key",
  bytes,
});
const cryptoKeyPairMember = (role, type = "ec") => ({
  kind: "crypto-key-pair-member",
  role,
  type,
});
const cryptoRsaCiphertext = (bytes = [73, 98, 101, 120]) => ({
  kind: "crypto-rsa-ciphertext",
  bytes,
});
const cryptoHmacSignature = (
  data = [73, 98, 101, 120],
  key = "ibex-output-shape-key",
) => ({ kind: "crypto-hmac-signature", data, key });
const cryptoPeerPublicKey = () => ({ kind: "crypto-peer-public-key" });
const cryptoDiffieHellmanOptions = () => ({
  kind: "crypto-diffie-hellman-options",
});

const rootCall = (arguments_ = [], cleanup = { kind: "none" }) => ({
  operation: "call",
  receiver: { kind: "module-value" },
  arguments: arguments_,
  cleanup,
});
const construct = (arguments_ = [], cleanup = { kind: "none" }) => ({
  operation: "construct",
  arguments: arguments_,
  cleanup,
});
const receiverCall = (
  receiver,
  arguments_ = [],
  cleanup = { kind: "receiver-default" },
) => ({ operation: "call", receiver, arguments: arguments_, cleanup });
const receiverGet = (receiver, cleanup = { kind: "receiver-default" }) => ({
  operation: "get",
  receiver,
  arguments: [],
  cleanup,
});
const importRefusal = () => ({
  operation: "import-refusal",
  cleanup: { kind: "none" },
});
const blocked = (reasonCode, reason) => ({
  operation: "unexercisable",
  reasonCode,
  reason,
});
const capturePublicBuiltinOutcome = (route) => ({
  ...route,
  outcomeCapture: "public-builtin-family",
});

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

function canonicalModuleSpecifier(specifiers) {
  return canonicalSet(specifiers).sort((left, right) => {
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
  })[0];
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

function sourceDescriptor(surface, target) {
  const metadata = surface?.metadata;
  if (
    metadata?.surfaceType !== "export" ||
    typeof metadata.sourceKey !== "string" ||
    typeof metadata.exportName !== "string" ||
    !new Set(["callable", "accessor"]).has(metadata.valueShape) ||
    !Array.isArray(metadata.exportIdioms) ||
    metadata.exportIdioms.length === 0 ||
    canonicalJson(metadata.exportIdioms) !==
      canonicalJson(canonicalSet(metadata.exportIdioms)) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1
  ) {
    return null;
  }
  const expectedObservedKey = `builtin:export:${metadata.sourceKey}:${metadata.exportName}`;
  if (surface.observedKey !== expectedObservedKey) return null;
  const access = exportAccess(metadata.exportName, metadata.exportIdioms);
  if (!access) return null;

  const availability = metadata.platformAvailability;
  if (
    availability !== undefined &&
    (!Array.isArray(availability) ||
      availability.length === 0 ||
      !availability.every((platform) => KNOWN_PLATFORMS.has(platform)) ||
      canonicalJson(availability) !== canonicalJson(canonicalSet(availability)))
  ) {
    return null;
  }
  const targetPlatform = platformForTarget(target);
  const available =
    availability === undefined ||
    (targetPlatform !== null && availability.includes(targetPlatform));

  const publicSpecifiers = metadata.publicModuleSpecifiers;
  const specifiers = Array.isArray(publicSpecifiers)
    ? canonicalSet(publicSpecifiers)
    : [];
  const descriptor = {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: specifiers,
    sourceRef: surface.sourceRefs[0],
    valueShape: metadata.valueShape,
    importReachability: metadata.importReachability,
    access,
  };
  if (availability !== undefined) {
    descriptor.platformAvailability = [...availability];
  }
  return {
    descriptor,
    moduleSpecifier: canonicalModuleSpecifier(specifiers),
    available,
  };
}

function dynamicExportBase(exportName) {
  const marker = ".[[";
  const markerIndex = exportName.indexOf(marker);
  return markerIndex === -1 ? null : exportName.slice(0, markerIndex);
}

function isDescriptorResidualExport(sourceKey, exportName) {
  const dynamicBase = dynamicExportBase(exportName);
  if (sourceKey === "exact_process") {
    return new Set(["addListener", "off"]).has(exportName);
  }
  if (sourceKey === "node_buffer") {
    return new Set([
      "atob",
      "btoa",
      "Buffer.constructor",
      "INSPECT_MAX_BYTES",
      "SlowBuffer.constructor",
    ]).has(exportName);
  }
  if (sourceKey === "node_console") return exportName === "Console";
  if (sourceKey === "node_events") return exportName === "defaultMaxListeners";
  if (sourceKey === "node_fs") {
    return new Set([
      "ReadStream.destroy",
      "WriteStream.destroy",
      "WriteStream._emitClose",
    ]).has(exportName);
  }
  if (sourceKey === "node_http") {
    return new Set(["CloseEvent", "globalAgent", "MessageEvent"]).has(
      exportName,
    );
  }
  if (sourceKey === "node_https") return exportName === "globalAgent";
  if (sourceKey === "node_os") {
    return dynamicBase !== null && DESCRIPTOR_OS_CALLS.has(dynamicBase);
  }
  if (sourceKey === "node_stream") {
    const [owner, member, ...extra] = exportName.split(".");
    if (extra.length > 0 || !member) return false;
    if (
      new Set(["Duplex", "PassThrough", "Readable", "Transform"]).has(
        owner,
      )
    ) {
      return DESCRIPTOR_STREAM_READABLE_MEMBERS.has(member);
    }
    return owner === "Writable" && DESCRIPTOR_STREAM_WRITABLE_MEMBERS.has(member);
  }
  if (sourceKey === "node_stream_web") {
    return DESCRIPTOR_STREAM_WEB_CONSTRUCTORS.has(exportName);
  }
  if (sourceKey === "node_url") {
    return new Set(["domainToASCII", "domainToUnicode"]).has(
      dynamicBase ?? exportName,
    ) || new Set(["URL", "URLSearchParams"]).has(exportName);
  }
  if (sourceKey === "node_util") {
    return new Set(["TextDecoder", "TextEncoder"]).has(exportName);
  }
  return false;
}

function descriptorResidualSource(catalogKey, surface, target) {
  const metadata = surface?.metadata;
  if (
    catalogKey?.sourceKind !== "builtin" ||
    catalogKey.output !== "[[return]]" ||
    !Array.isArray(surface?.sourceRefs) ||
    surface.sourceRefs.length !== 1 ||
    typeof metadata?.sourceKey !== "string" ||
    metadata.importReachability !== "public"
  ) {
    return null;
  }
  const availability = metadata.platformAvailability;
  if (
    availability !== undefined &&
    (!Array.isArray(availability) ||
      availability.length === 0 ||
      !availability.every((platform) => KNOWN_PLATFORMS.has(platform)) ||
      canonicalJson(availability) !== canonicalJson(canonicalSet(availability)))
  ) {
    return null;
  }
  const targetPlatform = platformForTarget(target);
  const available =
    availability === undefined ||
    (targetPlatform !== null && availability.includes(targetPlatform));

  if (DESCRIPTOR_ROOT_RETURN_ALIASES.has(catalogKey.alias)) {
    if (
      surface.observedKey !== `builtin:${catalogKey.alias}` ||
      surface.name !== catalogKey.alias ||
      metadata.surfaceType === "export"
    ) {
      return null;
    }
    const descriptor = {
      kind: "builtin-root",
      sourceKey: metadata.sourceKey,
      exportName: "[[module]]",
      exportIdioms: ["module-value"],
      moduleSpecifiers: [catalogKey.alias],
      sourceRef: surface.sourceRefs[0],
      valueShape: metadata.valueShape ?? "unknown",
      importReachability: metadata.importReachability,
      access: { kind: "module-value", path: [] },
    };
    if (availability !== undefined) {
      descriptor.platformAvailability = [...availability];
    }
    return {
      descriptor,
      moduleSpecifier: catalogKey.alias,
      available,
      route: { operation: "import-return", cleanup: { kind: "none" } },
    };
  }

  if (
    metadata.surfaceType !== "export" ||
    typeof metadata.exportName !== "string" ||
    !Array.isArray(metadata.exportIdioms) ||
    metadata.exportIdioms.length === 0 ||
    surface.observedKey !==
      `builtin:export:${metadata.sourceKey}:${metadata.exportName}` ||
    !isDescriptorResidualExport(metadata.sourceKey, metadata.exportName)
  ) {
    return null;
  }
  const publicSpecifiers = metadata.publicModuleSpecifiers;
  const specifiers = Array.isArray(publicSpecifiers)
    ? canonicalSet(publicSpecifiers)
    : [];
  if (specifiers.length === 0) return null;
  const dynamicBase = dynamicExportBase(metadata.exportName);
  let access = dynamicBase
    ? { kind: "export-property", path: dynamicBase.split(".") }
    : exportAccess(metadata.exportName, metadata.exportIdioms);
  if (!access) return null;
  // These fs stream members are public through the constructor prototype
  // chain even though the source inventory normalizes them to the exported
  // constructor-prototype idiom. Bind the operation to the descriptor that is
  // actually present on the loaded source rather than inventing an own member.
  if (metadata.sourceKey === "node_fs") {
    access = { ...access, kind: "inherited-prototype-property" };
  }
  const descriptor = {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: specifiers,
    sourceRef: surface.sourceRefs[0],
    valueShape: metadata.valueShape ?? "unknown",
    importReachability: metadata.importReachability,
    access,
  };
  if (availability !== undefined) {
    descriptor.platformAvailability = [...availability];
  }
  return {
    descriptor,
    moduleSpecifier: canonicalModuleSpecifier(specifiers),
    available,
    route: descriptorResidualRoute(descriptor),
  };
}

export function hasBuiltinNoncapClosedDescriptorResidualRoute({
  catalogKey,
  surface,
  target,
}) {
  return descriptorResidualSource(catalogKey, surface, target) !== null;
}

function descriptorResidualRoute(descriptor) {
  const { sourceKey, exportName } = descriptor;
  const dynamicBase = dynamicExportBase(exportName);
  if (sourceKey === "exact_process") {
    return rootCall([json("ibex-output-shape"), noop()], {
      kind: "returned-process-listener-remove",
      eventName: "ibex-output-shape",
    });
  }
  if (sourceKey === "node_buffer") {
    if (exportName === "atob") return rootCall([json("SWJleA==")]);
    if (exportName === "btoa") return rootCall([json("Ibex")]);
    if (exportName === "INSPECT_MAX_BYTES") {
      return receiverGet({ kind: "module-value" }, { kind: "none" });
    }
    return construct([json(8)]);
  }
  if (sourceKey === "node_console") {
    return construct([consoleWritableSink()]);
  }
  if (sourceKey === "node_events") {
    return receiverGet({ kind: "module-value" }, { kind: "none" });
  }
  if (sourceKey === "node_fs") {
    const [ownerExportName] = exportName.split(".");
    return receiverCall(
      { kind: "fs-stream-owner", ownerExportName },
      [],
      { kind: "stream-owned-destroy" },
    );
  }
  if (sourceKey === "node_http") {
    if (exportName === "globalAgent") {
      return receiverGet({ kind: "module-value" }, { kind: "none" });
    }
    return construct([json("ibex-output-shape")]);
  }
  if (sourceKey === "node_https") {
    return receiverGet({ kind: "module-value" }, { kind: "none" });
  }
  if (sourceKey === "node_os") return rootCall([]);
  if (sourceKey === "node_stream") {
    const [ownerExportName] = exportName.split(".");
    return receiverGet(streamOwner(ownerExportName), {
      kind: "stream-owned-destroy",
    });
  }
  if (sourceKey === "node_stream_web") {
    if (
      new Set(["ByteLengthQueuingStrategy", "CountQueuingStrategy"]).has(
        exportName,
      )
    ) {
      return construct([json({ highWaterMark: 1 })]);
    }
    if (exportName === "ReadableStreamBYOBReader") {
      return construct([webReadableStream(true)], {
        kind: "constructed-web-stream-release",
      });
    }
    if (exportName === "ReadableStreamDefaultReader") {
      return construct([webReadableStream()], {
        kind: "constructed-web-stream-release",
      });
    }
    if (exportName === "WritableStreamDefaultWriter") {
      return construct([webWritableStream()], {
        kind: "constructed-web-stream-release",
      });
    }
    return construct([]);
  }
  if (sourceKey === "node_url") {
    const callable = dynamicBase ?? exportName;
    if (new Set(["domainToASCII", "domainToUnicode"]).has(callable)) {
      return rootCall([json("example.com")]);
    }
    return construct([
      json(exportName === "URL" ? "https://example.com/" : "a=1"),
    ]);
  }
  if (sourceKey === "node_util") return construct([]);
  return null;
}

function inheritedBoundedRoute(surface, target) {
  const invocation = authoredNonCapabilityBuiltinOutputInvocation({
    surface,
    target,
  });
  if (!invocation) return null;
  if (invocation.kind === "builtin-export-read") {
    return {
      operation: "get",
      receiver: { kind: "module-value" },
      arguments: [],
      cleanup: { kind: "none" },
      inheritedTemplateId: "generic-public-builtin-read-v1",
    };
  }
  if (invocation.kind !== "builtin-export-call") return null;
  const operation =
    invocation.setup.kind === "construct-target" ? "construct" : "call";
  return {
    operation,
    ...(operation === "call" ? { receiver: invocation.setup } : {}),
    arguments: structuredClone(invocation.arguments),
    cleanup:
      operation === "construct"
        ? { kind: "none" }
        : invocation.setup.kind === "zlib-owner"
          ? { kind: "zlib-native-stream" }
          : invocation.setup.kind === "stream-owner"
            ? { kind: "stream-destroy" }
            : { kind: "receiver-default" },
    inheritedTemplateId: invocation.templateId,
  };
}

const sqliteDatabase = (ownerExportName) => ({
  kind: "sqlite-database",
  ownerExportName,
});
const sqliteStatement = () => ({ kind: "sqlite-statement" });
const bufferOwner = (ownerExportName) => ({
  kind: "buffer-owner",
  ownerExportName,
  bytes: [73, 98, 101, 120, 0, 1, 2, 3],
});
const dirent = () => ({ kind: "fs-dirent" });
const stats = () => ({ kind: "fs-stats" });
const fsFileHandle = () => ({ kind: "fs-file-handle" });
const fsDir = (sourceCloses = false) => ({ kind: "fs-dir", sourceCloses });
const stringDecoder = () => ({ kind: "string-decoder" });
const performanceMark = () => ({ kind: "performance-mark" });
const performanceMeasure = () => ({ kind: "performance-measure" });
const secretKey = () => ({ kind: "crypto-secret-key" });
const cryptoCertificate = () => ({ kind: "crypto-certificate" });
const cryptoX509Certificate = () => ({ kind: "crypto-x509-certificate" });
const cryptoCipher = (
  ownerExportName,
  {
    algorithm = "aes-128-ctr",
    preload = false,
    finalized = false,
    deferredCleanup = false,
  } = {},
) => ({
  kind: "crypto-cipher",
  ownerExportName,
  algorithm,
  preload,
  finalized,
  deferredCleanup,
});
const cryptoDiffieHellman = ({ generated = false, peer = false } = {}) => ({
  kind: "crypto-diffie-hellman",
  generated,
  peer,
});
const cryptoDiffieHellmanGroup = ({ generated = false, peer = false } = {}) => ({
  kind: "crypto-diffie-hellman-group",
  generated,
  peer,
});
const cryptoEcdh = ({ generated = false, peer = false } = {}) => ({
  kind: "crypto-ecdh",
  generated,
  peer,
});
const cryptoHashStream = (ownerExportName, deferredCleanup = false) => ({
  kind: "crypto-hash-stream",
  ownerExportName,
  deferredCleanup,
});
const streamOwner = (
  ownerExportName,
  {
    ended = false,
    deferredCleanup = false,
    swallowError = false,
  } = {},
) => ({
  kind: "stream-owner",
  ownerExportName,
  ended,
  deferredCleanup,
  swallowError,
});
const zlibOwner = (ownerExportName, deferredCleanup = false) => ({
  kind: "zlib-output-owner",
  ownerExportName,
  deferredCleanup,
});
const asyncLocalStorage = () => ({ kind: "async-local-storage" });
const asyncResource = () => ({ kind: "async-resource" });
const diagnosticsChannel = (withListener = false) => ({
  kind: "diagnostics-channel",
  withListener,
});
const diagnosticsTracingChannel = (withHandlers = false) => ({
  kind: "diagnostics-tracing-channel",
  withHandlers,
});
const diagnosticsChannelMap = () => ({ kind: "diagnostics-channel-map" });
const diagnosticsHandlers = () => ({ kind: "diagnostics-handlers" });
const domainOwner = (withMember = false) => ({
  kind: "domain-owner",
  withMember,
});
const timer = (timerKind = "timeout") => ({ kind: "timer-handle", timerKind });

function eventsRoute(exportName, valueShape) {
  if (exportName === "captureRejections" && valueShape === "accessor") {
    return receiverGet({ kind: "module-value" }, { kind: "none" });
  }
  if (exportName === "default" || exportName === "EventEmitterAsyncResource") {
    return exportName === "default"
      ? construct([])
      : construct([json("ibex-output-shape")]);
  }
  if (exportName === "setMaxListeners") {
    return rootCall([json(11), eventEmitter()]);
  }
  if (
    new Set(["default.setMaxListeners", "EventEmitter.setMaxListeners"]).has(
      exportName,
    )
  ) {
    return receiverCall({ kind: "event-emitter" }, [json(11)]);
  }
  const prefix = "EventEmitterAsyncResource.";
  if (!exportName.startsWith(prefix)) return null;
  const member = exportName.slice(prefix.length);
  if (member === "constructor") {
    return construct([json("ibex-output-shape")]);
  }
  const receiver = { kind: "event-emitter-async-resource" };
  if (
    new Set([
      "addListener",
      "on",
      "once",
      "prependListener",
      "prependOnceListener",
    ]).has(member)
  ) {
    return receiverCall(receiver, [json("ibex-output-shape"), noop()]);
  }
  if (new Set(["off", "removeListener"]).has(member)) {
    return receiverCall(receiver, [
      json("ibex-output-shape"),
      setupValue("listener"),
    ]);
  }
  if (member === "emit") {
    return receiverCall(receiver, [json("ibex-output-shape")]);
  }
  if (new Set(["listenerCount", "listeners", "rawListeners"]).has(member)) {
    return receiverCall(receiver, [json("ibex-output-shape")]);
  }
  if (member === "setMaxListeners") return receiverCall(receiver, [json(11)]);
  if (
    new Set(["eventNames", "getMaxListeners", "removeAllListeners"]).has(member)
  ) {
    return receiverCall(receiver);
  }
  return null;
}

function sqliteRoute(exportName, valueShape) {
  const [owner, member] = exportName.split(".");
  if (new Set(["Database", "default"]).has(owner) && member) {
    const receiver = sqliteDatabase(owner);
    if (valueShape === "accessor") return receiverGet(receiver);
    if (member === "_checkClosed") return receiverCall(receiver);
    if (member === "constructor") return construct([json(":memory:")]);
    if (new Set(["enableCrSqlite", "loadExtension"]).has(member)) {
      return capturePublicBuiltinOutcome(
        receiverCall(
          receiver,
          member === "loadExtension" ? [json("ibex-missing-extension")] : [],
          { kind: "sqlite-database-only" },
        ),
      );
    }
    return null;
  }
  if (owner === "Statement" && member) {
    const receiver = sqliteStatement();
    if (valueShape === "accessor") {
      if (member === "declaredTypes") {
        return receiverGet({
          kind: "sqlite-statement",
          executeBeforeGet: true,
        });
      }
      return receiverGet(receiver);
    }
    if (member === "_checkFinalized" || member === "toString") {
      return receiverCall(receiver);
    }
    if (member === "_normalizeParams") {
      return receiverCall(receiver, [json([])]);
    }
    if (member === "as") {
      return receiverCall(receiver, [{ kind: "empty-class" }]);
    }
    if (member === "finalize") {
      return receiverCall(receiver, [], { kind: "sqlite-database-only" });
    }
    return blocked(
      "sqlite-statement-route-not-bounded",
      `${exportName} needs a statement lifecycle not owned by this one-shot recipe`,
    );
  }
  if (exportName === "SQLiteError") {
    return construct([json("ibex"), json(1), json("SQLITE_ERROR"), json(0)]);
  }
  if (exportName === "SQLiteError.constructor") {
    return construct([json("ibex"), json(1), json("SQLITE_ERROR"), json(0)]);
  }
  if (exportName === "deserialize") {
    return capturePublicBuiltinOutcome(rootCall([uint8Array([])]));
  }
  return null;
}

function fsRoute(exportName, valueShape) {
  if (exportName === "Stats") {
    return construct([json({}), json(false)]);
  }
  if (exportName === "Dirent") {
    return construct([json("entry.txt"), json(1)]);
  }
  if (exportName.startsWith("Dirent.") && valueShape === "callable") {
    return receiverCall(dirent());
  }
  if (exportName === "_toUnixTimestamp") {
    return rootCall([json(0)]);
  }
  if (exportName === "WriteStream.autoClose") {
    return receiverGet(
      { kind: "fs-stream-owner", ownerExportName: "WriteStream" },
      { kind: "stream-owned-destroy" },
    );
  }
  if (new Set(["close", "closeSync"]).has(exportName)) {
    return capturePublicBuiltinOutcome(
      rootCall(
        exportName === "close"
          ? [json(-1), completionCallback()]
          : [json(-1)],
        exportName === "close"
          ? { kind: "async-callback-quiescence" }
          : { kind: "none" },
      ),
    );
  }
  if (exportName === "unwatchFile") {
    return rootCall([json("/project/output-shape-unused")]);
  }
  if (exportName === "Dir") {
    return capturePublicBuiltinOutcome(
      construct([json("/project")], { kind: "constructed-dir-close" }),
    );
  }
  if (exportName === "FSWatcher") {
    return capturePublicBuiltinOutcome(
      construct([], { kind: "constructed-fs-watcher-close" }),
    );
  }
  if (exportName === "Dir.close") {
    return capturePublicBuiltinOutcome(
      receiverCall(
        fsDir(true),
        [completionCallback()],
        { kind: "async-callback-quiescence" },
      ),
    );
  }
  if (exportName === "Dir.closeSync") {
    return capturePublicBuiltinOutcome(
      receiverCall(fsDir(true), [], { kind: "none" }),
    );
  }
  return null;
}

function performanceRoute(exportName, valueShape) {
  if (exportName === "PerformanceMark.detail" && valueShape === "accessor") {
    return receiverGet(performanceMark());
  }
  if (exportName === "PerformanceMeasure.detail" && valueShape === "accessor") {
    return receiverGet(performanceMeasure());
  }
  if (exportName === "PerformanceEntry.toJSON") {
    return receiverCall(performanceMark());
  }
  if (exportName === "PerformanceMeasure.toJSON") {
    return receiverCall(performanceMeasure());
  }
  if (exportName === "eventLoopUtilization") return rootCall([]);
  if (exportName === "timerify") return rootCall([noop()]);
  if (exportName === "PerformanceObserver.observe") {
    return receiverCall(
      { kind: "performance-observer" },
      [json({ entryTypes: ["mark"] })],
      { kind: "performance-observer-disconnect" },
    );
  }
  // PerformanceEntry, PerformanceMeasure, and PerformanceResourceTiming are
  // illegal public constructors in the bound runtime. Their inherited
  // constructors and ResourceTiming.toJSON likewise cannot furnish a normal
  // public source return, so they stay residual rather than using a deliberate
  // throw or an incompatible plain-object receiver as output evidence.
  if (new Set(["createHistogram", "monitorEventLoopDelay"]).has(exportName)) {
    return rootCall([], { kind: "returned-performance-monitor-disable" });
  }
  return null;
}

function timerRoute(exportName) {
  if (
    new Set(["clearImmediate", "clearInterval", "clearTimeout"]).has(exportName)
  ) {
    return rootCall([json(null)]);
  }
  if (exportName === "setImmediate") {
    return rootCall([noop()], { kind: "returned-timer-handle" });
  }
  if (exportName === "setTimeout") {
    return rootCall([noop(), json(60_000)], { kind: "returned-timer-handle" });
  }
  if (exportName === "setInterval") {
    return rootCall([noop(), json(60_000)], { kind: "returned-timer-handle" });
  }
  if (exportName === "Timeout") {
    return capturePublicBuiltinOutcome(construct([]));
  }
  if (exportName === "Immediate") {
    return capturePublicBuiltinOutcome(construct([]));
  }
  const [owner, member] = exportName.split(".");
  if (owner === "Timeout" && member) {
    if (member === "_scheduleNative") {
      return receiverCall(
        { kind: "unscheduled-timeout" },
        [],
        { kind: "timer-record-close" },
      );
    }
    return receiverCall(timer("timeout"));
  }
  if (owner === "Immediate" && member) {
    return receiverCall(timer("immediate"));
  }
  if (
    new Set(["_unrefActive", "active", "enroll", "unenroll"]).has(exportName)
  ) {
    return rootCall(
      [
        { kind: "legacy-timer-record" },
        ...(exportName === "enroll" ? [json(60_000)] : []),
      ],
      { kind: "legacy-timer-record-cancel" },
    );
  }
  return null;
}

function v8Route(exportName) {
  // serialize/deserialize are present on the public surface but the bound
  // runtime returns ERR_METHOD_NOT_IMPLEMENTED. They cannot provide normal
  // source-return evidence and remain residual.
  if (
    new Set([
      "getHeapCodeStatistics",
      "getHeapSpaceStatistics",
      "getHeapStatistics",
    ]).has(exportName)
  ) {
    return rootCall([]);
  }
  if (exportName === "getHeapSnapshot") {
    return rootCall([], { kind: "returned-stream-destroy" });
  }
  if (exportName === "setFlagsFromString") return rootCall([json("")]);
  if (exportName === "writeHeapSnapshot") {
    return rootCall([json("/project/ibex-output-shape.heapsnapshot")]);
  }
  return null;
}

function stringDecoderRoute(exportName) {
  const [owner, member] = exportName.split(".");
  if (owner !== "default" || !member) return null;
  const receiver = stringDecoder();
  if (member === "write") return receiverCall(receiver, [buffer()]);
  if (member === "end") return receiverCall(receiver, [buffer()]);
  if (member === "text") return receiverCall(receiver, [buffer(), json(0)]);
  if (member === "fillLast") return receiverCall(receiver, [buffer()]);
  if (member === "toString") return receiverCall(receiver);
  return null;
}

function cryptoRoute(exportName, valueShape) {
  if (valueShape === "accessor") {
    if (exportName.startsWith("KeyObject.")) return receiverGet(secretKey());
    if (exportName.startsWith("X509Certificate.")) {
      return receiverGet(cryptoX509Certificate());
    }
    return null;
  }

  const cipherOwners = new Set(["Cipher", "Cipheriv"]);
  const decipherOwners = new Set(["Decipher", "Decipheriv"]);
  const cipherConstructorArguments = [
    json("aes-128-ctr"),
    buffer(new Array(16).fill(7)),
    buffer(new Array(16).fill(9)),
  ];
  if (
    new Set(["Cipher", "Cipheriv", "Decipher", "Decipheriv"]).has(
      exportName,
    )
  ) {
    return construct(cipherConstructorArguments, {
      kind: "constructed-stream-destroy",
    });
  }
  if (
    new Set([
      "createCipher",
      "createCipheriv",
      "createDecipher",
      "createDecipheriv",
    ]).has(exportName)
  ) {
    return rootCall(cipherConstructorArguments, {
      kind: "returned-stream-destroy",
    });
  }
  const cipherSegments = exportName.split(".");
  if (
    cipherSegments.length === 2 &&
    (cipherOwners.has(cipherSegments[0]) ||
      decipherOwners.has(cipherSegments[0]))
  ) {
    const [ownerExportName, member] = cipherSegments;
    if (member === "constructor") {
      return construct(cipherConstructorArguments, {
        kind: "constructed-stream-destroy",
      });
    }
    const isDecipher = decipherOwners.has(ownerExportName);
    const algorithm = new Set(["getAuthTag", "setAAD", "setAuthTag"]).has(
      member,
    )
      ? "aes-128-gcm"
      : "aes-128-ctr";
    const receiver = cryptoCipher(ownerExportName, {
      algorithm,
      preload:
        isDecipher &&
        new Set(["final", "_flush", "_flushStreamResult", "end"]).has(
          member,
        ),
      finalized: !isDecipher && member === "getAuthTag",
      deferredCleanup: member === "end",
    });
    const cleanup = { kind: "crypto-stream-destroy" };
    if (member === "end") {
      return receiverCall(
        receiver,
        [buffer(), completionCallback({ cleanupReceiver: true })],
        { kind: "crypto-stream-end-callback-destroy" },
      );
    }
    if (member === "final" || member === "_flushStreamResult") {
      return receiverCall(receiver, [], cleanup);
    }
    if (member === "_flush" || member === "_final") {
      return receiverCall(receiver, [completionCallback()], cleanup);
    }
    if (member === "_transform") {
      return receiverCall(
        receiver,
        [buffer(), json("utf8"), completionCallback()],
        cleanup,
      );
    }
    if (member === "getAuthTag") return receiverCall(receiver, [], cleanup);
    if (member === "setAAD") {
      return receiverCall(receiver, [buffer([97, 97, 100])], cleanup);
    }
    if (member === "setAuthTag") {
      return receiverCall(receiver, [buffer(new Array(16).fill(3))], cleanup);
    }
    if (member === "setAutoPadding") {
      return receiverCall(receiver, [json(true)], cleanup);
    }
    if (member === "update") {
      return receiverCall(receiver, [buffer()], cleanup);
    }
  }

  if (exportName === "Certificate") return construct([]);
  if (exportName.startsWith("Certificate.")) {
    return receiverCall(cryptoCertificate(), [buffer()]);
  }
  if (exportName === "X509Certificate") {
    return construct([json("ibex-output-shape-certificate")]);
  }
  if (exportName.startsWith("X509Certificate.")) {
    const member = exportName.slice("X509Certificate.".length);
    const arguments_ = new Set(["checkEmail", "checkHost", "checkIP"]).has(
      member,
    )
      ? [json(member === "checkIP" ? "127.0.0.1" : "localhost")]
      : member === "checkIssued"
        ? [cryptoX509Certificate()]
        : member === "checkPrivateKey"
          ? [cryptoKeyPairMember("private", "rsa")]
          : member === "verify"
            ? [cryptoKeyPairMember("public", "rsa")]
            : [];
    return receiverCall(cryptoX509Certificate(), arguments_);
  }
  if (exportName === "KeyObject.equals") {
    return receiverCall(secretKey(), [cryptoSecretKey()]);
  }
  if (exportName === "createPrivateKey") {
    return rootCall([cryptoKeyPairMember("private")]);
  }
  if (exportName === "createPublicKey") {
    return rootCall([cryptoKeyPairMember("public")]);
  }
  if (exportName === "generateKeyPairSync") {
    return rootCall([
      json("ec"),
      json({
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      }),
    ]);
  }
  if (exportName === "generateKeyPair") {
    return rootCall(
      [
        json("ec"),
        json({
          namedCurve: "prime256v1",
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        }),
        completionCallback(),
      ],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "generateKey") {
    return rootCall(
      [json("aes"), json({ length: 128 }), completionCallback()],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "generatePrime") {
    return rootCall(
      [json(16), json({ bigint: true }), completionCallback()],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "checkPrime") {
    return rootCall(
      [bigint(17), json({}), completionCallback()],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "randomFill") {
    return rootCall([uint8Array([0, 0, 0, 0]), completionCallback()], {
      kind: "async-callback-quiescence",
    });
  }
  if (exportName === "hkdf") {
    return rootCall(
      [
        json("sha256"),
        json("ibex-key"),
        json("ibex-salt"),
        json("ibex-info"),
        json(16),
        completionCallback(),
      ],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "pbkdf2") {
    return rootCall(
      [
        json("ibex-password"),
        json("ibex-salt"),
        json(2),
        json(16),
        json("sha256"),
        completionCallback(),
      ],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "scrypt") {
    return rootCall(
      [
        json("ibex-password"),
        json("ibex-salt"),
        json(16),
        json({ N: 16, r: 1, p: 1, maxmem: 1024 * 1024 }),
        completionCallback(),
      ],
      { kind: "async-callback-quiescence" },
    );
  }
  if (exportName === "getRandomValues") {
    return capturePublicBuiltinOutcome(
      rootCall([uint8Array([0, 0, 0, 0])]),
    );
  }
  if (exportName === "randomUUID") {
    return capturePublicBuiltinOutcome(rootCall([]));
  }
  if (exportName === "secureHeapUsed") {
    return rootCall([]);
  }
  if (exportName === "setEngine") return rootCall([json("ibex")]);
  if (exportName === "setFips") {
    return receiverCall(
      { kind: "crypto-module-fips" },
      [json(false)],
      { kind: "crypto-fips-restore" },
    );
  }
  if (exportName === "sign") {
    return rootCall([
      json("sha256"),
      buffer(),
      json("ibex-output-shape-key"),
    ]);
  }
  if (exportName === "verify") {
    return rootCall([
      json("sha256"),
      buffer(),
      json("ibex-output-shape-key"),
      cryptoHmacSignature(),
    ]);
  }
  if (exportName === "Sign.sign") {
    return receiverCall(
      { kind: "crypto-sign-verify", ownerExportName: "Sign" },
      [json("ibex-output-shape-key")],
      { kind: "crypto-stream-destroy" },
    );
  }
  if (exportName === "Verify.verify") {
    return receiverCall(
      { kind: "crypto-sign-verify", ownerExportName: "Verify" },
      [json("ibex-output-shape-key"), cryptoHmacSignature()],
      { kind: "crypto-stream-destroy" },
    );
  }
  if (new Set(["Hash.end", "Hash._flush", "Hmac.end", "Hmac._flush"]).has(exportName)) {
    const [ownerExportName, member] = exportName.split(".");
    const isEnd = member === "end";
    const arguments_ = isEnd
      ? [buffer(), completionCallback({ cleanupReceiver: true })]
      : [completionCallback()];
    return receiverCall(
      cryptoHashStream(ownerExportName, isEnd),
      arguments_,
      {
        kind: isEnd
          ? "crypto-stream-end-callback-destroy"
          : "crypto-stream-destroy",
      },
    );
  }
  if (exportName === "publicEncrypt") {
    return capturePublicBuiltinOutcome(
      rootCall([cryptoKeyPairMember("public", "rsa"), buffer()]),
    );
  }
  if (exportName === "privateDecrypt") {
    return capturePublicBuiltinOutcome(
      rootCall([
        cryptoKeyPairMember("private", "rsa"),
        cryptoRsaCiphertext(),
      ]),
    );
  }

  const dhArguments = [buffer([23]), json(5)];
  if (exportName === "DiffieHellman") return construct(dhArguments);
  if (exportName === "DiffieHellman.constructor") {
    return construct(dhArguments);
  }
  if (exportName === "createDiffieHellman") return rootCall(dhArguments);
  if (exportName.startsWith("DiffieHellman.")) {
    const member = exportName.slice("DiffieHellman.".length);
    const generated = new Set([
      "computeSecret",
      "getPrivateKey",
      "getPublicKey",
    ]).has(member);
    const receiver = cryptoDiffieHellman({
      generated,
      peer: member === "computeSecret",
    });
    if (member === "computeSecret") {
      return receiverCall(receiver, [cryptoPeerPublicKey()]);
    }
    if (member === "generateKeys") return receiverCall(receiver);
    if (member === "setPrivateKey") {
      return receiverCall(receiver, [buffer([6])]);
    }
    if (member === "setPublicKey") {
      return receiverCall(receiver, [buffer([8])]);
    }
    if (
      new Set([
        "getGenerator",
        "getPrime",
        "getPrivateKey",
        "getPublicKey",
      ]).has(member)
    ) {
      return receiverCall(receiver);
    }
  }
  if (exportName.startsWith("DiffieHellmanGroup.")) {
    const member = exportName.slice("DiffieHellmanGroup.".length);
    if (new Set(["computeSecret", "generateKeys"]).has(member)) {
      const receiver = cryptoDiffieHellmanGroup({
        generated: member === "computeSecret",
        peer: member === "computeSecret",
      });
      return receiverCall(
        receiver,
        member === "computeSecret" ? [cryptoPeerPublicKey()] : [],
      );
    }
  }
  if (exportName.startsWith("ECDH.")) {
    const member = exportName.slice("ECDH.".length);
    if (member === "computeSecret") {
      return capturePublicBuiltinOutcome(
        receiverCall(
          cryptoEcdh({ generated: true, peer: true }),
          [cryptoPeerPublicKey()],
        ),
      );
    }
    if (new Set(["computeSecret", "generateKeys"]).has(member)) {
      const receiver = cryptoEcdh({
        generated: member === "computeSecret",
        peer: member === "computeSecret",
      });
      return receiverCall(
        receiver,
        member === "computeSecret" ? [cryptoPeerPublicKey()] : [],
      );
    }
  }
  if (exportName === "diffieHellman") {
    return capturePublicBuiltinOutcome(
      rootCall([cryptoDiffieHellmanOptions()]),
    );
  }

  if (
    new Set([
      "argon2",
      "encapsulate",
      "decapsulate",
      "privateEncrypt",
      "publicDecrypt",
    ]).has(exportName)
  ) {
    const arguments_ =
      exportName === "encapsulate"
        ? [json("ibex-key")]
        : exportName === "decapsulate"
          ? [json("ibex-key"), buffer()]
          : new Set(["privateEncrypt", "publicDecrypt"]).has(exportName)
            ? [
                cryptoKeyPairMember(
                  exportName === "privateEncrypt" ? "private" : "public",
                  "rsa",
                ),
                buffer(),
              ]
            : [];
    return capturePublicBuiltinOutcome(
      rootCall(arguments_),
    );
  }
  return null;
}

function streamRoute(exportName) {
  if (exportName === "setDefaultHighWaterMark") {
    return receiverCall(
      { kind: "stream-module-watermark" },
      [json(false), json(32_768)],
      { kind: "stream-watermark-restore" },
    );
  }
  if (exportName === "compose") {
    return rootCall([streamInstance("PassThrough")], {
      kind: "returned-stream-destroy",
    });
  }
  if (exportName === "pipeline") {
    return rootCall(
      [
        streamInstance("Readable", { ended: true, deferredCleanup: true }),
        streamInstance("Writable", { deferredCleanup: true }),
        completionCallback({ cleanupReceiver: true }),
      ],
      { kind: "stream-pipeline-callback-destroy" },
    );
  }

  const [ownerExportName, member] = exportName.split(".");
  if (!member) return null;
  if (member === "constructor" && ownerExportName === "default") {
    return construct([], { kind: "constructed-stream-destroy" });
  }
  if (ownerExportName === "default") {
    const receiver = streamOwner("default");
    if (member === "_close") {
      return receiverCall(receiver, [json(true)], {
        kind: "stream-owned-destroy",
      });
    }
    if (new Set(["_emitClose", "_undestroy", "destroy", "unpipe"]).has(member)) {
      return receiverCall(receiver, [], { kind: "stream-owned-destroy" });
    }
    if (member === "pipe") {
      return receiverCall(receiver, [streamInstance("Writable")], {
        kind: "stream-owned-destroy",
      });
    }
  }

  if (
    new Set(["Duplex", "PassThrough", "Readable", "Transform"]).has(
      ownerExportName,
    ) &&
    member === "addListener"
  ) {
    return receiverCall(
      streamOwner(ownerExportName),
      [json("ibex-output-shape"), noop()],
      { kind: "stream-owned-destroy" },
    );
  }
  if (exportName === "Duplex._undestroy") {
    return receiverCall(streamOwner("Duplex"), [], {
      kind: "stream-owned-destroy",
    });
  }
  if (
    new Set(["Duplex", "PassThrough", "Readable", "Transform"]).has(
      ownerExportName,
    ) &&
    member === "compose"
  ) {
    return receiverCall(
      streamOwner(ownerExportName, { ended: true }),
      [streamInstance("PassThrough")],
      { kind: "returned-and-owned-stream-destroy" },
    );
  }
  if (
    new Set(["Duplex", "PassThrough", "Readable", "Transform"]).has(
      ownerExportName,
    ) &&
    new Set(["every", "find", "forEach", "reduce", "some", "toArray"]).has(
      member,
    )
  ) {
    const arguments_ =
      member === "toArray"
        ? []
        : member === "reduce"
          ? [reducerFunction(), json("seed")]
          : [constantFunction(true)];
    return {
      ...receiverCall(
        streamOwner(ownerExportName, {
          ended: true,
          deferredCleanup: true,
        }),
        arguments_,
        { kind: "returned-promise-stream-drain" },
      ),
      awaitResult: true,
    };
  }
  if (
    new Set(["Duplex", "PassThrough", "Readable", "Transform"]).has(
      ownerExportName,
    ) &&
    member === "wrap"
  ) {
    return receiverCall(
      streamOwner(ownerExportName),
      [streamInstance("Readable")],
      { kind: "stream-owned-destroy" },
    );
  }
  if (exportName === "Writable.pipe") {
    return receiverCall(
      streamOwner("Writable", { swallowError: true }),
      [],
      { kind: "stream-owned-destroy" },
    );
  }
  if (new Set(["Transform._transform", "Writable._write"]).has(exportName)) {
    const [ownerExportName] = exportName.split(".");
    return capturePublicBuiltinOutcome(
      receiverCall(
        streamOwner(ownerExportName),
        [buffer(), json("utf8"), noop()],
        { kind: "stream-owned-destroy" },
      ),
    );
  }
  return null;
}

function zlibRoute(exportName) {
  if (
    new Set(["zstdCompress", "zstdDecompress"]).has(exportName)
  ) {
    return capturePublicBuiltinOutcome(
      rootCall([buffer(), completionCallback()], {
        kind: "async-callback-quiescence",
      }),
    );
  }
  if (new Set(["zstdCompressSync", "zstdDecompressSync"]).has(exportName)) {
    return capturePublicBuiltinOutcome(rootCall([buffer()]));
  }
  const [ownerExportName, member] = exportName.split(".");
  const owners = new Set([
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
  if (!owners.has(ownerExportName) || !member) return null;
  if (member === "destroy") {
    return receiverCall(zlibOwner(ownerExportName), [], {
      kind: "zlib-owned-close",
    });
  }
  if (member === "end") {
    if (ownerExportName.startsWith("Zstd")) {
      return capturePublicBuiltinOutcome(
        receiverCall(
          zlibOwner(ownerExportName, true),
          [buffer(), completionCallback({ cleanupReceiver: true })],
          { kind: "zlib-end-callback-close" },
        ),
      );
    }
    return receiverCall(
      zlibOwner(ownerExportName, true),
      [zlibInput(ownerExportName), completionCallback({ cleanupReceiver: true })],
      { kind: "zlib-end-callback-close" },
    );
  }
  if (new Set(["_processChunk", "_writeNative"]).has(member)) {
    return capturePublicBuiltinOutcome(
      receiverCall(
        zlibOwner(ownerExportName),
        member === "_processChunk"
          ? [buffer(), json(0)]
          : [buffer(), json(0), json(true)],
        { kind: "zlib-owned-close" },
      ),
    );
  }
  return null;
}

function asyncHooksRoute(exportName) {
  if (exportName === "AsyncLocalStorage") {
    return construct([], { kind: "constructed-async-local-storage-disable" });
  }
  if (exportName.startsWith("AsyncLocalStorage.")) {
    const member = exportName.slice("AsyncLocalStorage.".length);
    const receiver = asyncLocalStorage();
    if (new Set(["disable", "enable", "getStore", "snapshot"]).has(member)) {
      return receiverCall(receiver);
    }
    if (member === "enterWith") return receiverCall(receiver, [json("ibex")]);
    if (member === "exit") return receiverCall(receiver, [noop()]);
    if (member === "run") {
      return receiverCall(receiver, [json("ibex"), noop()]);
    }
  }
  if (exportName === "AsyncResource") {
    return construct([json("ibex-output-shape")], {
      kind: "constructed-async-resource-destroy",
    });
  }
  if (exportName.startsWith("AsyncResource.")) {
    const member = exportName.slice("AsyncResource.".length);
    const receiver = asyncResource();
    if (
      new Set([
        "asyncId",
        "emitAfter",
        "emitBefore",
        "emitDestroy",
        "triggerAsyncId",
      ]).has(member)
    ) {
      return receiverCall(receiver);
    }
    if (member === "bind") return receiverCall(receiver, [noop()]);
    if (member === "runInAsyncScope") {
      return receiverCall(receiver, [noop(), json(null)]);
    }
  }
  if (exportName === "createHook") {
    return rootCall([json({})], { kind: "returned-async-hook-disable" });
  }
  if (exportName === "__emitInit") {
    return rootCall([
      json(1),
      json("ibex-output-shape"),
      json(0),
      json({}),
    ]);
  }
  if (
    new Set([
      "__getHooksEnabled",
      "executionAsyncId",
      "triggerAsyncId",
    ]).has(exportName)
  ) {
    return rootCall([]);
  }
  if (exportName === "__nextAsyncId") {
    return blocked(
      "async-id-allocator-has-no-rollback",
      "__nextAsyncId irreversibly advances module-global allocator state and has no fixture-local rollback",
    );
  }
  return null;
}

function diagnosticsRoute(exportName, valueShape) {
  if (exportName === "Channel") {
    return construct([json("ibex-output-shape")], {
      kind: "constructed-diagnostics-channel-clear",
    });
  }
  if (exportName.startsWith("Channel.")) {
    const member = exportName.slice("Channel.".length);
    const receiver = diagnosticsChannel(member === "unsubscribe");
    if (valueShape === "accessor") return receiverGet(receiver);
    if (member === "publish") return receiverCall(receiver, [json({})]);
    if (member === "subscribe") return receiverCall(receiver, [noop()]);
    if (member === "unsubscribe") {
      return receiverCall(receiver, [setupValue("diagnosticsListener")]);
    }
  }
  if (exportName === "TracingChannel") {
    return construct([diagnosticsChannelMap()], {
      kind: "constructed-diagnostics-tracing-clear",
    });
  }
  if (exportName.startsWith("TracingChannel.")) {
    const member = exportName.slice("TracingChannel.".length);
    const receiver = diagnosticsTracingChannel(member === "unsubscribe");
    if (member === "subscribe") {
      return receiverCall(receiver, [diagnosticsHandlers()]);
    }
    if (member === "unsubscribe") {
      return receiverCall(receiver, [setupValue("diagnosticsHandlers")]);
    }
    if (member === "traceSync") {
      return receiverCall(receiver, [noop(), json({})]);
    }
  }
  if (exportName === "hasSubscribers") {
    return rootCall([json("ibex-output-shape-absent")]);
  }
  if (exportName === "tracingChannel") {
    return rootCall([diagnosticsChannelMap()], {
      kind: "returned-diagnostics-tracing-clear",
    });
  }
  if (exportName === "channel") {
    return rootCall([json("ibex-output-shape")], {
      kind: "returned-diagnostics-channel-clear",
    });
  }
  return null;
}

function domainRoute(exportName) {
  if (exportName === "Domain") {
    return construct([], { kind: "constructed-domain-dispose" });
  }
  if (exportName === "Domain.constructor") {
    return construct([], { kind: "constructed-domain-dispose" });
  }
  if (exportName.startsWith("Domain.")) {
    const member = exportName.slice("Domain.".length);
    const receiver = domainOwner(member === "remove");
    if (new Set(["dispose", "enter", "exit"]).has(member)) {
      return receiverCall(receiver);
    }
    if (new Set(["bind", "intercept", "run"]).has(member)) {
      return receiverCall(receiver, [noop()]);
    }
    if (new Set(["add", "remove"]).has(member)) {
      return receiverCall(receiver, [setupValue("domainMember")]);
    }
  }
  if (new Set(["create", "createDomain"]).has(exportName)) {
    return rootCall([], { kind: "returned-domain-dispose" });
  }
  return null;
}

function httpRoute(exportName) {
  if (exportName === "HTTPParser") return construct([]);
  if (exportName === "_checkInvalidHeaderChar") {
    return rootCall([json("ibex-output-shape")]);
  }
  if (exportName === "_checkIsHttpToken") {
    return rootCall([json("x-ibex-output-shape")]);
  }
  if (exportName === "validateHeaderName") {
    return rootCall([json("x-ibex-output-shape")]);
  }
  if (exportName === "validateHeaderValue") {
    return rootCall([
      json("x-ibex-output-shape"),
      json("ibex-output-shape"),
    ]);
  }
  return null;
}

function http2Route(exportName) {
  if (exportName === "getDefaultSettings") return rootCall([]);
  if (exportName === "getPackedSettings") {
    return rootCall([json({ enablePush: true, maxConcurrentStreams: 8 })]);
  }
  if (exportName === "getUnpackedSettings") {
    // SETTINGS_ENABLE_PUSH (id 2) with a valid value of one.
    return rootCall([uint8Array([0, 2, 0, 0, 0, 1])]);
  }
  return null;
}

function tlsRoute(exportName) {
  if (exportName === "SecureContext") return construct([json({})]);
  if (exportName === "createSecureContext") return rootCall([json({})]);
  if (exportName === "checkServerIdentity") {
    return rootCall([
      json("localhost"),
      json({
        subject: { CN: "localhost" },
        subjectaltname: "DNS:localhost",
      }),
    ]);
  }
  if (exportName === "convertALPNProtocols") {
    return rootCall([json(["h2", "http/1.1"])]);
  }
  if (exportName === "getCACertificates" || exportName === "getCiphers") {
    return rootCall([]);
  }
  if (exportName === "translatePeerCertificate") {
    return rootCall([
      json({
        subject: { CN: "localhost" },
        issuer: { CN: "ibex-output-shape" },
        subjectaltname: "DNS:localhost",
      }),
    ]);
  }
  return null;
}

function customRoute(descriptor) {
  const { sourceKey, exportName, valueShape } = descriptor;
  if (sourceKey === "exact_process") {
    if (exportName === "hrtime") return rootCall([]);
    if (exportName === "hasUncaughtExceptionCaptureCallback")
      return rootCall([]);
    if (exportName === "binding") return rootCall([json("util")]);
    if (exportName === "emitWarning") {
      return capturePublicBuiltinOutcome(
        rootCall([json("ibex-output-shape-warning")]),
      );
    }
    if (exportName === "kill") {
      return capturePublicBuiltinOutcome(
        rootCall([json(0), json("IBEX_INVALID_SIGNAL")]),
      );
    }
    if (exportName === "setSourceMapsEnabled") {
      return capturePublicBuiltinOutcome(rootCall([json(false)]));
    }
    if (exportName === "setUncaughtExceptionCaptureCallback") {
      return capturePublicBuiltinOutcome(rootCall([json(null)]));
    }
    if (exportName === "umask") return rootCall([]);
  }
  if (sourceKey === "exact_sqlite") {
    return sqliteRoute(exportName, valueShape);
  }
  if (sourceKey === "node_buffer" && valueShape === "accessor") {
    const [owner] = exportName.split(".");
    if (new Set(["Buffer", "SlowBuffer"]).has(owner)) {
      return receiverGet(bufferOwner(owner));
    }
  }
  if (sourceKey === "node_events") {
    if (exportName === "init") {
      return receiverCall({ kind: "event-emitter" });
    }
    return eventsRoute(exportName, valueShape);
  }
  if (sourceKey === "node_fs") return fsRoute(exportName, valueShape);
  if (sourceKey === "node_fs_promises") {
    if (exportName === "FileHandle") {
      return construct(
        [json(null), json("/project/ibex-output-shape"), json("r")],
        { kind: "constructed-file-handle-close" },
      );
    }
    if (exportName === "FileHandle.fd") return receiverGet(fsFileHandle());
    if (exportName === "FileHandle.close") {
      return receiverCall(fsFileHandle(), [], {
        kind: "file-handle-close",
      });
    }
    if (exportName === "FileHandle.emit") {
      return receiverCall(fsFileHandle(), [json("ibex-output-shape")]);
    }
    if (exportName === "FileHandle.on") {
      return receiverCall(fsFileHandle(), [json("close"), noop()], {
        kind: "file-handle-close",
      });
    }
  }
  if (sourceKey === "node_http") return httpRoute(exportName);
  if (sourceKey === "node_http2") return http2Route(exportName);
  if (sourceKey === "node_tls") return tlsRoute(exportName);
  if (sourceKey === "node_perf_hooks") {
    return performanceRoute(exportName, valueShape);
  }
  if (sourceKey === "node_string_decoder") {
    return stringDecoderRoute(exportName);
  }
  if (sourceKey === "node_stream") return streamRoute(exportName);
  if (sourceKey === "node_zlib") return zlibRoute(exportName);
  if (sourceKey === "node_async_hooks") return importRefusal();
  if (sourceKey === "node_diagnostics_channel") {
    return diagnosticsRoute(exportName, valueShape);
  }
  if (sourceKey === "node_domain") return domainRoute(exportName);
  if (sourceKey === "node_timers") return timerRoute(exportName);
  if (sourceKey === "node_timers_promises") {
    if (exportName === "setTimeout") return rootCall([json(0), json("ibex")]);
    if (exportName === "setImmediate") return rootCall([json("ibex")]);
    if (exportName === "setInterval") {
      return capturePublicBuiltinOutcome(
        rootCall([json(60_000), json("ibex")], {
          kind: "returned-async-iterator-return",
        }),
      );
    }
  }
  if (sourceKey === "node_url") {
    if (exportName === "createObjectURL") {
      return rootCall([blob()], { kind: "returned-object-url" });
    }
    if (exportName === "revokeObjectURL") {
      return rootCall([json("blob:ibex-output-shape:absent")]);
    }
  }
  if (sourceKey === "node_v8") return v8Route(exportName);
  if (sourceKey === "exact_crypto") return cryptoRoute(exportName, valueShape);
  if (sourceKey === "node_stream_consumers") {
    const content = exportName === "json" ? '{"fixture":true}' : "ibex";
    return capturePublicBuiltinOutcome({
      ...rootCall(
        [
          streamInstance("Readable", {
            ended: true,
            deferredCleanup: true,
            content,
          }),
        ],
        { kind: "returned-promise-stream-drain" },
      ),
      awaitResult: true,
      dependencyModuleSpecifiers: ["node:stream"],
    });
  }
  if (sourceKey === "node_stream_promises") {
    const route =
      exportName === "finished"
        ? rootCall(
            [
              streamInstance("Readable", {
                endAfterOperation: true,
                deferredCleanup: true,
              }),
            ],
            { kind: "returned-promise-stream-drain" },
          )
        : rootCall(
            [
              streamInstance("Readable", {
                ended: true,
                deferredCleanup: true,
              }),
              streamInstance("Writable", { deferredCleanup: true }),
            ],
            { kind: "returned-promise-stream-drain" },
          );
    return capturePublicBuiltinOutcome({
      ...route,
      awaitResult: true,
      dependencyModuleSpecifiers: ["node:stream"],
    });
  }
  if (sourceKey === "node_stream_web") {
    if (exportName === "isReadableStream") {
      return rootCall([webReadableStream(false, true)]);
    }
    if (exportName === "isWritableStream") {
      return rootCall([webWritableStream()]);
    }
    if (exportName === "fromWeb") {
      return capturePublicBuiltinOutcome(
        rootCall([webReadableStream(false, true)], {
          kind: "returned-stream-destroy",
        }),
      );
    }
    if (exportName === "toWeb") {
      return capturePublicBuiltinOutcome({
        ...rootCall(
          [
            streamInstance("Readable", {
              ended: true,
              deferredCleanup: true,
            }),
          ],
          { kind: "returned-web-stream-cancel" },
        ),
        dependencyModuleSpecifiers: ["node:stream"],
      });
    }
  }
  if (sourceKey === "node_assert") {
    if (exportName === "fail") {
      return capturePublicBuiltinOutcome(
        rootCall([json("ibex-output-shape")]),
      );
    }
    if (exportName === "rejects") {
      return capturePublicBuiltinOutcome(rootCall([rejectedPromise()]));
    }
    if (exportName === "doesNotReject") {
      return capturePublicBuiltinOutcome(rootCall([resolvedPromise()]));
    }
  }
  return null;
}

function familyResidual(descriptor) {
  const { sourceKey, exportName } = descriptor;
  if (descriptor.importReachability === "bootstrap-internal") {
    return blocked(
      "bootstrap-shadowed-manifest-export",
      `${sourceKey}:${exportName} resolves to a bootstrap-owned object instead of the inventoried manifest source`,
    );
  }
  if (descriptor.moduleSpecifiers.length === 0) {
    return blocked(
      "builtin-export-not-publicly-importable",
      `${sourceKey}:${exportName} has no source-proven public module specifier`,
    );
  }
  if (
    new Set([
      "node_child_process",
      "node_cluster",
      "node_dgram",
      "node_dns",
      "node_http",
      "node_http2",
      "node_https",
      "node_net",
      "node_readline",
      "node_tls",
      "ws",
    ]).has(sourceKey)
  ) {
    return blocked(
      "receiver-needs-external-or-network-lifecycle",
      `${sourceKey}:${exportName} needs a socket, subprocess, server, terminal, or peer lifecycle not owned by an in-memory output recipe`,
    );
  }
  if (
    new Set([
      "node_async_hooks",
      "node_diagnostics_channel",
      "node_domain",
      "node_events",
    ]).has(sourceKey)
  ) {
    return blocked(
      "shared-hook-or-listener-lifecycle-not-isolated",
      `${sourceKey}:${exportName} mutates shared hook/listener state without a source-proven fixture-local rollback`,
    );
  }
  if (
    new Set([
      "node_inspector",
      "node_module",
      "node_os",
      "node_trace_events",
      "node_vm",
      "node_wasi",
      "node_worker_threads",
    ]).has(sourceKey)
  ) {
    return blocked(
      "runtime-inspection-or-escape-surface-has-no-safe-receiver",
      `${sourceKey}:${exportName} has no bounded production receiver that can normally return without reopening runtime inspection or escape state`,
    );
  }
  if (sourceKey === "node_stream") {
    return blocked(
      "stream-route-retains-or-defers-work",
      `${exportName} needs awaited stream completion or owns a pipeline/listener beyond the synchronous return`,
    );
  }
  if (
    new Set(["node_stream_consumers", "node_stream_promises"]).has(sourceKey)
  ) {
    return blocked(
      "promise-return-needs-awaited-output-capture",
      `${sourceKey}:${exportName} returns deferred work whose settlement is not the catalog's synchronous [[return]] value`,
    );
  }
  if (sourceKey === "node_stream_web") {
    return blocked(
      "web-stream-adapter-needs-owned-cross-runtime-stream",
      `${exportName} needs paired Node/Web stream ownership and cancellation cleanup`,
    );
  }
  if (sourceKey === "node_zlib") {
    return blocked(
      "codec-route-retains-native-or-deferred-stream-state",
      `${exportName} needs native codec state or deferred stream completion not owned by a one-shot recipe`,
    );
  }
  if (sourceKey === "exact_crypto") {
    return blocked(
      "crypto-route-needs-authentic-key-cipher-or-callback-fixture",
      `${exportName} needs a matched key/certificate/cipher lifecycle or awaited callback not supplied by a bounded source-owned fixture`,
    );
  }
  if (sourceKey === "node_assert") {
    return blocked(
      "assertion-route-does-not-normally-return-or-is-deferred",
      `${exportName} either intentionally throws or settles through an asynchronous assertion promise`,
    );
  }
  return blocked(
    "no-bounded-source-owned-receiver",
    `${sourceKey}:${exportName} has no deterministic receiver, arguments, and cleanup recipe`,
  );
}

/**
 * Author one exact builtin output operation. `catalogKey` and `coverageEdge`
 * select the source row, but neither reviewed output policy nor expectation is
 * accepted by this API.
 */
export function authoredBuiltinNoncapClosedOutputInvocation({
  catalogKey,
  coverageEdge,
  surface,
  target,
}) {
  if (
    catalogKey?.sourceKind !== "builtin" ||
    catalogKey.output !== "[[return]]" ||
    !KNOWN_CLASSIFICATIONS.has(coverageEdge?.classification) ||
    coverageEdge?.id !== catalogKey.surfaceId ||
    coverageEdge?.surface?.kind !== "builtin" ||
    coverageEdge.surface.name !== surface?.name
  ) {
    return null;
  }
  const source =
    sourceDescriptor(surface, target) ??
    descriptorResidualSource(catalogKey, surface, target);
  if (!source) return null;
  const { descriptor, moduleSpecifier, available } = source;
  let route;
  if (!available) {
    route = blocked(
      "builtin-export-not-available-on-target",
      `${descriptor.sourceKey}:${descriptor.exportName} is not authored for the selected target`,
    );
  } else if (descriptor.importReachability !== "public") {
    route = familyResidual(descriptor);
  } else if (source.route) {
    route = structuredClone(source.route);
  } else {
    route =
      customRoute(descriptor) ??
      inheritedBoundedRoute(surface, target) ??
      familyResidual(descriptor);
  }
  if (!route) return null;
  if (
    descriptor.importReachability === "public" &&
    new Set(["call", "construct", "get"]).has(route.operation)
  ) {
    route = capturePublicBuiltinOutcome(route);
  }
  return {
    invocationSchema: BUILTIN_NONCAP_CLOSED_OUTPUT_INVOCATION_SCHEMA,
    kind: "builtin-noncap-closed-output",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    surfaceObservedKey: surface.observedKey,
    moduleSpecifier: moduleSpecifier ?? null,
    sourceDescriptor: descriptor,
    sourceDescriptorDigest: taggedDigest(descriptor),
    route,
    completion: { ...COMPLETION },
  };
}

/**
 * Reuse a bounded public-output operation as zero-decision conformance
 * evidence only when the exact non-capability recipe selects that same source
 * edge. The loaded executor still has to prove a normal inner source return,
 * owned cleanup, quiescence, and zero typed or legacy decisions.
 */
export function authoredNonCapabilityBuiltinCapturedProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByEdge,
  target,
}) {
  if (
    plan?.classification !== "non-capability" ||
    scenario !== "non-capability" ||
    plan.actionIds?.length !== 0 ||
    route?.surfaceObservedKeys?.length !== 1 ||
    route.alternatives?.length !== 1 ||
    route.ambiguousCallees?.length !== 0 ||
    plan.edgeIds?.length !== 1
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (
    !surfaceObservedKey.startsWith("builtin:export:") ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    !Array.isArray(route.alternatives[0].proofPaths) ||
    route.alternatives[0].proofPaths.length === 0
  ) {
    return null;
  }
  const surface = liveByObservedKey.get(surfaceObservedKey);
  const coverageEdge = coverageByEdge.get(plan.edgeIds[0]);
  const capturedOutputInvocation =
    authoredBuiltinNoncapClosedOutputInvocation({
      catalogKey: {
        sourceKind: "builtin",
        surfaceId: plan.edgeIds[0],
        output: "[[return]]",
      },
      coverageEdge,
      surface,
      target,
    });
  if (
    capturedOutputInvocation?.coverageClassification !== "non-capability" ||
    capturedOutputInvocation.coverageEdgeId !== plan.edgeIds[0] ||
    capturedOutputInvocation.surfaceObservedKey !== surfaceObservedKey ||
    capturedOutputInvocation.route?.operation === "unexercisable" ||
    !new Set(["call", "construct", "get"]).has(
      capturedOutputInvocation.route?.operation,
    ) ||
    capturedOutputInvocation.route?.outcomeCapture !==
      "public-builtin-family"
  ) {
    return null;
  }
  const descriptor = capturedOutputInvocation.sourceDescriptor;
  if (
    !CONFORMANCE_CAPTURED_SOURCE_OPERATIONS.get(descriptor.sourceKey)?.has(
      capturedOutputInvocation.route.operation,
    )
  ) {
    return null;
  }
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...BUILTIN_NONCAP_CAPTURED_BATCH_COMMAND],
    invocation: {
      invocationSchema: BUILTIN_NONCAP_CAPTURED_INVOCATION_SCHEMA,
      kind: "builtin-noncap-captured-call",
      moduleSpecifier: capturedOutputInvocation.moduleSpecifier,
      exportName: descriptor.exportName,
      sourceDescriptor: structuredClone(descriptor),
      sourceDescriptorDigest:
        capturedOutputInvocation.sourceDescriptorDigest,
      arguments: [],
      setup: { kind: "captured-output-route" },
      completion: structuredClone(capturedOutputInvocation.completion),
      capturedOutputInvocation: structuredClone(capturedOutputInvocation),
      requiredAuthority: [],
      expectedResult: "captured-source-return",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

/** Build the exact output-sweep hook consumed by reconciliation. */
export function authoredBuiltinNoncapClosedOutputProbe(input) {
  const invocation = authoredBuiltinNoncapClosedOutputInvocation(input);
  if (!invocation) return null;
  const sourceDescriptor = {
    kind: BUILTIN_NONCAP_CLOSED_OUTPUT_SOURCE_DESCRIPTOR_KIND,
    surfaceObservedKey: invocation.surfaceObservedKey,
    invocation,
  };
  const sourceDescriptorDigest = taggedDigest(sourceDescriptor);
  const fixtureDigest = crypto
    .createHash("sha256")
    .update("ibex:capsec:builtin-noncap-closed-output:1", "utf8")
    .update(Buffer.from([0]))
    .update(
      canonicalJson([
        input.catalogKey,
        invocation.sourceDescriptorDigest,
        invocation.route,
      ]),
      "utf8",
    )
    .digest("base64url")
    .slice(0, 22);
  return {
    kind: "loaded-engine-return-record",
    fixtureId: `output-shape-builtin-${fixtureDigest}`,
    sourceDescriptor,
    sourceDescriptorDigest,
    recordPath: ["[[return]]"],
  };
}

export function builtinNoncapClosedOutputRouteManifest(invocations) {
  const counts = Object.create(null);
  const residualReasons = Object.create(null);
  for (const invocation of invocations) {
    const operation = invocation.route.operation;
    counts[operation] = (counts[operation] ?? 0) + 1;
    if (operation === "unexercisable") {
      const reasonCode = invocation.route.reasonCode;
      residualReasons[reasonCode] = (residualReasons[reasonCode] ?? 0) + 1;
    }
  }
  return {
    total: invocations.length,
    operations: Object.fromEntries(
      Object.entries(counts).sort(([left], [right]) =>
        compareText(left, right),
      ),
    ),
    residualReasons: Object.fromEntries(
      Object.entries(residualReasons).sort(([left], [right]) =>
        compareText(left, right),
      ),
    ),
  };
}
