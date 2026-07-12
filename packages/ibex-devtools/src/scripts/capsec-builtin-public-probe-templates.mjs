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
  "capsec-conformance-observer",
  "capsec_public_noncap_builtin_recipe_batch",
  "--",
  "--test-threads=1",
  "--nocapture",
]);

const READ_INVOCATION_SCHEMA = "ibex/capsec-builtin-export-invocation/1";
const CALL_INVOCATION_SCHEMA = "ibex/capsec-builtin-call-invocation/1";

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

// These tables are deliberately keyed by the scanner's sourceKey and exact
// exportName. They are an allowlist derived from the corresponding builtin
// source, not a generic "call every function" mechanism.
const ROOT_CALL_SPECS = Object.freeze({
  node_path: Object.freeze({
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
    escape: rootCall([jsonArgument("ibex probe")], "string"),
    parse: rootCall([jsonArgument("a=1&a=2&b=ibex")], "object"),
    stringify: rootCall(
      [jsonArgument({ a: ["1", "2"], b: "ibex" })],
      "string",
    ),
    unescape: rootCall([jsonArgument("ibex%20probe")], "string"),
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

function bufferPrototypeSpec(exportName) {
  const [ownerExportName, methodName] = exportName.split(".");
  if (
    !new Set(["Buffer", "SlowBuffer"]).has(ownerExportName) ||
    !methodName ||
    exportName.split(".").length !== 2
  ) {
    return null;
  }
  const method = ownValue(BUFFER_METHOD_SPECS, methodName);
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

const CALL_TEMPLATE_IDS = Object.freeze({
  node_assert: "node-assert-bounded-v1",
  node_buffer: "node-buffer-bounded-v1",
  node_events: "node-events-bounded-v1",
  node_path: "node-path-pure-v1",
  node_punycode: "node-punycode-pure-v1",
  node_querystring: "node-querystring-pure-v1",
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

function sourceDescriptor(surface, target, allowedValueShapes) {
  const metadata = surface?.metadata;
  const availability = platformAvailability(metadata);
  const targetPlatform = platformForTarget(target);
  if (
    metadata?.surfaceType !== "export" ||
    typeof metadata.sourceKey !== "string" ||
    metadata.sourceKey.length === 0 ||
    metadata.sourceKey === "node_os" ||
    !allowedValueShapes.has(metadata.valueShape) ||
    typeof metadata.exportName !== "string" ||
    metadata.exportName.length === 0 ||
    !Array.isArray(metadata.exportIdioms) ||
    metadata.exportIdioms.length === 0 ||
    canonicalJson(metadata.exportIdioms) !==
      canonicalJson(canonicalSet(metadata.exportIdioms)) ||
    !Array.isArray(metadata.moduleSpecifiers) ||
    metadata.moduleSpecifiers.length === 0 ||
    !metadata.moduleSpecifiers.every(
      (specifier) => typeof specifier === "string" && specifier.length > 0,
    ) ||
    canonicalJson(metadata.moduleSpecifiers) !==
      canonicalJson(canonicalSet(metadata.moduleSpecifiers)) ||
    availability === false ||
    (availability &&
      (!targetPlatform || !availability.includes(targetPlatform))) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1
  ) {
    return null;
  }
  const expectedObservedKey = `builtin:export:${metadata.sourceKey}:${metadata.exportName}`;
  if (surface.observedKey !== expectedObservedKey) return null;
  const access = exportAccess(metadata.exportName, metadata.exportIdioms);
  const moduleSpecifier = canonicalModuleSpecifier(metadata.moduleSpecifiers);
  if (!access || !moduleSpecifier) {
    return null;
  }
  const descriptor = {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: [...metadata.moduleSpecifiers],
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
  if (!surfaceObservedKey.startsWith("builtin:export:")) return null;
  const alternative = route.alternatives[0];
  if (
    alternative.terminalObservedKey !== surfaceObservedKey ||
    !Array.isArray(alternative.proofPaths) ||
    alternative.proofPaths.length === 0
  ) {
    return null;
  }
  const surface = liveByObservedKey.get(surfaceObservedKey);
  const readDescriptor = sourceDescriptor(
    surface,
    target,
    new Set(["accessor", "data"]),
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
        requiredAuthority: [],
        expectedResult: "return",
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
