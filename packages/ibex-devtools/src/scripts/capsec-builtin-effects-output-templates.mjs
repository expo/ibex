/**
 * Independently authored, source-bound recipes for effect-classified builtin
 * output rows.  This module deliberately accepts no disposition policy and
 * carries no expected output.  Dynamic fixture identities (private loopback
 * ports and private project paths) are resolved by the authenticated executor
 * and retained in its raw artifact.
 *
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — each operation is bounded
 * to its exact root principal and typed authority family.
 * @ref LLP 0023#6-path-bearing-observables — the evidence value must come
 * from the exact loaded export named by the source inventory.
 * @ref LLP 0024#9-asynchronous-failures — every recipe has a
 * bounded cleanup and event-loop quiescence contract.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

export const BUILTIN_EFFECTS_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-builtin-effects-output-invocation/1";
export const BUILTIN_EFFECTS_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "authored-builtin-effects-output";

export const BUILTIN_EFFECTS_REGISTRAR_FAMILY_COUNTS = Object.freeze({
  node_http: 152,
  node_fs: 109,
  node_net: 68,
  node_tls: 50,
  node_readline: 48,
  exact_sqlite: 35,
  node_dns: 30,
  ws: 28,
  node_http2: 18,
  node_fs_promises: 16,
  node_tty: 14,
  node_child_process: 8,
  exact_process: 7,
  node_dgram: 6,
  node_https: 5,
  node_os: 4,
  node_util: 2,
  exact_clipboard: 2,
  node_path: 1,
  node_cluster: 1,
  exact_http: 1,
});

export const BUILTIN_EFFECTS_DESCRIPTOR_RESIDUAL_FAMILY_COUNTS = Object.freeze({});

const COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});
const KNOWN_PLATFORMS = new Set(["android", "darwin", "linux"]);
const PROTOTYPE_IDIOMS = new Set([
  "exported-constructor-prototype",
  "exported-constructor-inherited-prototype",
]);
const FAMILY_NAMES = new Set(
  Object.keys(BUILTIN_EFFECTS_REGISTRAR_FAMILY_COUNTS),
);
const ALREADY_LIVE_PROBED_CALLABLES = new Set([
  "exact_process:cwd",
  "node_fs:realpath",
  "node_fs:realpathSync",
  "node_path:relative",
  "node_path:resolve",
]);
const DESCRIPTOR_RESIDUAL_EXPORTS = new Set([
  "node_fs:ReadStream._read",
  "node_fs:WriteStream._write",
  "node_fs_promises:access",
  "node_fs_promises:appendFile",
  "node_fs_promises:chmod",
  "node_fs_promises:chown",
  "node_fs_promises:copyFile",
  "node_fs_promises:fdatasync",
  "node_fs_promises:fsync",
  "node_fs_promises:lchown",
  "node_fs_promises:link",
  "node_fs_promises:lstat",
  "node_fs_promises:lutimes",
  "node_fs_promises:mkdir",
  "node_fs_promises:mkdtemp",
  "node_fs_promises:opendir",
  "node_fs_promises:readdir",
  "node_fs_promises:readv",
  "node_fs_promises:rename",
  "node_fs_promises:rm",
  "node_fs_promises:rmdir",
  "node_fs_promises:stat",
  "node_fs_promises:statfs",
  "node_fs_promises:symlink",
  "node_fs_promises:unlink",
  "node_fs_promises:utimes",
  "node_fs_promises:writev",
  "node_http:WebSocket",
  "node_os:arch",
  "node_os:availableParallelism",
  "node_os:endianness",
  "node_os:freemem",
  "node_os:hostname",
  "node_os:machine",
  "node_os:platform",
  "node_os:release",
  "node_os:totalmem",
  "node_os:type",
  "node_os:uptime",
  "node_os:version",
]);
const SUPPLEMENTAL_ENVIRONMENT_READS = new Map([
  ...[
    "node_http:ClientRequest.flushHeaders",
    "node_http:ClientRequest.setTimeout",
    "node_http:ServerIncomingMessage.addListener",
    "node_http:ServerIncomingMessage.destroy",
    "node_http:ServerIncomingMessage.on",
    "node_http:ServerIncomingMessage.pause",
    "node_http:ServerIncomingMessage.setTimeout",
    "node_https:Agent.createConnection",
    "node_tls:connect",
    "ws:Server",
    "ws:WebSocketServer",
  ].map((identity) => [identity, ["EXACT_DEBUG_EMIT_LISTENER"]]),
  ["node_tty:WriteStream", ["COLUMNS", "LINES"]],
  ["node_tty:WriteStream.constructor", ["COLUMNS", "LINES"]],
  ["node_tty:WriteStream._refreshSize", ["COLUMNS", "LINES"]],
  ["node_tty:WriteStream.getColorDepth", ["NO_COLOR"]],
  ["node_tty:WriteStream.hasColors", ["NO_COLOR"]],
]);
const CONSTRUCTOR_EXPORTS = new Set([
  "Agent",
  "ClientRequest",
  "Database",
  "Dir",
  "Http2ServerRequest",
  "Http2ServerResponse",
  "IncomingMessage",
  "Interface",
  "OutgoingMessage",
  "ReadStream",
  "Server",
  "ServerIncomingMessage",
  "ServerResponse",
  "Statement",
  "WebSocket",
  "WebSocketServer",
  "WriteStream",
  "default",
]);
const NODE_FS_LIVE_FD_EXPORTS = new Set([
  "fdatasync",
  "fdatasyncSync",
  "fstat",
  "fstatSync",
  "fsync",
  "fsyncSync",
  "ftruncate",
  "ftruncateSync",
  "read",
  "readSync",
  "readv",
  "readvSync",
  "write",
  "writeSync",
  "writev",
  "writevSync",
]);
const NODE_FS_PROMISE_LIVE_FD_EXPORTS = new Set([
  "fdatasync",
  "fsync",
  "readv",
  "writev",
]);
const NODE_FS_PROMISE_LIVE_HANDLE_EXPORTS = new Set([
  "FileHandle.read",
  "FileHandle.readFile",
  "FileHandle.readv",
  "FileHandle.stat",
  "FileHandle.truncate",
  "FileHandle.write",
  "FileHandle.writeFile",
  "FileHandle.writev",
]);

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalSet = (values) => [...new Set(values)].sort(compareText);
const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

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

function canonicalModuleSpecifier(specifiers, sourceKey) {
  return canonicalSet(specifiers).sort((left, right) => {
    const rank = (value) =>
      sourceKey.startsWith("exact_") && value.startsWith("exact:")
        ? 0
        : sourceKey === "node_fs_promises" && value === "bun:fs/promises"
          ? 1
          : value.startsWith("node:")
            ? 2
            : value.startsWith("exact:")
              ? 3
              : value.startsWith("bun:")
                ? 4
                : value.startsWith("internal/")
                  ? 5
                  : 6;
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

export function isBuiltinEffectsOutputTargetSurface(surface) {
  const metadata = surface?.metadata;
  if (
    metadata?.surfaceType !== "export" ||
    !FAMILY_NAMES.has(metadata.sourceKey) ||
    typeof metadata.exportName !== "string"
  ) {
    return false;
  }
  const identity = `${metadata.sourceKey}:${metadata.exportName}`;
  if (metadata.valueShape === "unknown") {
    return DESCRIPTOR_RESIDUAL_EXPORTS.has(identity);
  }
  return (
    new Set(["callable", "accessor"]).has(metadata.valueShape) &&
    !ALREADY_LIVE_PROBED_CALLABLES.has(identity)
  );
}

function sourceDescriptor(surface, target) {
  const metadata = surface?.metadata;
  if (
    !isBuiltinEffectsOutputTargetSurface(surface) ||
    metadata?.surfaceType !== "export" ||
    typeof metadata.sourceKey !== "string" ||
    !FAMILY_NAMES.has(metadata.sourceKey) ||
    typeof metadata.exportName !== "string" ||
    !new Set(["callable", "accessor", "unknown"]).has(metadata.valueShape) ||
    !Array.isArray(metadata.exportIdioms) ||
    metadata.exportIdioms.length === 0 ||
    canonicalJson(metadata.exportIdioms) !==
      canonicalJson(canonicalSet(metadata.exportIdioms)) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length !== 1 ||
    surface.observedKey !==
      `builtin:export:${metadata.sourceKey}:${metadata.exportName}`
  ) {
    return null;
  }
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
  const publicSpecifiers = Array.isArray(metadata.publicModuleSpecifiers)
    ? canonicalSet(metadata.publicModuleSpecifiers)
    : [];
  const targetPlatform = platformForTarget(target);
  const descriptor = {
    kind: "builtin-export",
    sourceKey: metadata.sourceKey,
    exportName: metadata.exportName,
    exportIdioms: [...metadata.exportIdioms],
    moduleSpecifiers: publicSpecifiers,
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
    moduleSpecifier: canonicalModuleSpecifier(
      publicSpecifiers,
      metadata.sourceKey,
    ),
    available:
      availability === undefined ||
      (targetPlatform !== null && availability.includes(targetPlatform)),
  };
}

const json = (value) => ({ kind: "json", value });
const noop = () => ({ kind: "noop-function" });
const inert = () => ({ kind: "inert-object" });
const fixtureFd = () => ({ kind: "fixture-fd" });
const completionCallback = () => ({ kind: "completion-callback" });
const uint8Array = (size = 32) => ({ kind: "uint8-array", size });
const uint8ArrayList = () => ({ kind: "uint8-array-list", sizes: [16, 16] });

function usesLiveFdFixture(descriptor) {
  return (
    (descriptor.sourceKey === "node_fs" &&
      NODE_FS_LIVE_FD_EXPORTS.has(descriptor.exportName)) ||
    (descriptor.sourceKey === "node_fs_promises" &&
      NODE_FS_PROMISE_LIVE_FD_EXPORTS.has(descriptor.exportName))
  );
}

function usesLiveFileHandleFixture(descriptor) {
  return (
    descriptor.sourceKey === "node_fs_promises" &&
    NODE_FS_PROMISE_LIVE_HANDLE_EXPORTS.has(descriptor.exportName)
  );
}

function filesystemArgumentsFor(descriptor, coverageEdge) {
  if (
    !new Set(["node_fs", "node_fs_promises"]).has(descriptor.sourceKey)
  ) {
    return undefined;
  }
  const root = `/project/fixtures/${coverageEdge.id}`;
  const primary = json(`${root}/input.txt`);
  const secondary = json(`${root}/output.txt`);
  const directory = json(`${root}/directory`);
  const emptyDirectory = json(`${root}/empty-directory`);
  const newDirectory = json(`${root}/new-directory`);
  const tempPrefix = json(`${root}/temporary-`);
  const callback = descriptor.sourceKey === "node_fs" ? [noop()] : [];
  const withCallback = (arguments_) => [...arguments_, ...callback];
  const name = descriptor.exportName;

  if (usesLiveFdFixture(descriptor)) {
    const asyncCallback =
      descriptor.sourceKey === "node_fs" && !name.endsWith("Sync")
        ? [completionCallback()]
        : [];
    if (new Set(["fdatasync", "fdatasyncSync", "fsync", "fsyncSync"]).has(name)) {
      return [fixtureFd(), ...asyncCallback];
    }
    if (new Set(["fstat", "fstatSync"]).has(name)) {
      return [fixtureFd(), ...asyncCallback];
    }
    if (new Set(["ftruncate", "ftruncateSync"]).has(name)) {
      return [fixtureFd(), json(0), ...asyncCallback];
    }
    if (new Set(["read", "readSync"]).has(name)) {
      return [fixtureFd(), uint8Array(), json(0), json(32), json(0), ...asyncCallback];
    }
    if (new Set(["readv", "readvSync"]).has(name)) {
      return [fixtureFd(), uint8ArrayList(), json(0), ...asyncCallback];
    }
    if (new Set(["write", "writeSync"]).has(name)) {
      return [fixtureFd(), json("ibex-output-shape"), ...asyncCallback];
    }
    if (new Set(["writev", "writevSync"]).has(name)) {
      return [fixtureFd(), uint8ArrayList(), json(0), ...asyncCallback];
    }
  }

  if (usesLiveFileHandleFixture(descriptor)) {
    if (name === "FileHandle.read") return [uint8Array()];
    if (name === "FileHandle.readv") return [uint8ArrayList(), json(0)];
    if (name === "FileHandle.truncate") return [json(0)];
    if (name === "FileHandle.write") return [uint8Array()];
    if (name === "FileHandle.writeFile") return [json("ibex-output-shape")];
    if (name === "FileHandle.writev") return [uint8ArrayList(), json(0)];
    return [];
  }

  if (new Set(["Dir", "Dir.constructor"]).has(name)) return [directory];
  if (
    new Set([
      "ReadStream",
      "ReadStream.constructor",
      "createReadStream",
    ]).has(name)
  ) {
    return [primary];
  }
  if (
    new Set([
      "WriteStream",
      "WriteStream.constructor",
      "createWriteStream",
    ]).has(name)
  ) {
    return [secondary];
  }

  const sync = name.endsWith("Sync") || name === "readFileSync";
  const finish = (arguments_) =>
    descriptor.sourceKey === "node_fs" && !sync
      ? withCallback(arguments_)
      : arguments_;
  if (
    new Set([
      "access",
      "accessSync",
      "lstat",
      "lstatSync",
      "readFile",
      "readFileSync",
      "stat",
      "statSync",
      "statfs",
      "statfsSync",
    ]).has(name)
  ) {
    return finish([primary]);
  }
  if (new Set(["appendFile", "appendFileSync", "writeFile", "writeFileSync"]).has(name)) {
    return finish([primary, json("ibex-output-shape")]);
  }
  if (new Set(["chmod", "chmodSync", "lchmod", "lchmodSync"]).has(name)) {
    return finish([primary, json(0o600)]);
  }
  if (new Set(["chown", "chownSync", "lchown", "lchownSync"]).has(name)) {
    // `0` is deliberately an ordinary, validated uid/gid rather than the
    // `-1/-1` no-op pair. Callback/Promise routes still return normally if
    // the private fixture's host rejects the eventual ownership change.
    return finish([primary, json(0), json(0)]);
  }
  if (
    new Set([
      "copyFile",
      "copyFileSync",
      "cp",
      "cpSync",
      "link",
      "linkSync",
      "rename",
      "renameSync",
    ]).has(name)
  ) {
    return finish([primary, secondary]);
  }
  if (new Set(["lutimes", "lutimesSync", "utimes", "utimesSync"]).has(name)) {
    return finish([primary, json(0), json(0)]);
  }
  if (new Set(["mkdir", "mkdirSync"]).has(name)) {
    return finish([newDirectory]);
  }
  if (
    new Set([
      "mkdtemp",
      "mkdtempDisposable",
      "mkdtempDisposableSync",
      "mkdtempSync",
    ]).has(name)
  ) {
    return finish([tempPrefix]);
  }
  if (new Set(["open", "openSync"]).has(name)) {
    return finish([primary, json("r")]);
  }
  if (new Set(["opendir", "opendirSync", "readdir", "readdirSync"]).has(name)) {
    return finish([directory]);
  }
  if (new Set(["rm", "rmSync", "unlink", "unlinkSync"]).has(name)) {
    return finish([primary]);
  }
  if (new Set(["rmdir", "rmdirSync"]).has(name)) {
    return finish([emptyDirectory]);
  }
  if (new Set(["symlink", "symlinkSync"]).has(name)) {
    return finish([primary, secondary]);
  }
  if (new Set(["truncate", "truncateSync"]).has(name)) {
    return finish([primary, json(0)]);
  }
  if (name === "exists") return [primary, noop()];
  if (name === "existsSync") return [primary];
  if (name === "watchFile") return [primary, noop()];
  return undefined;
}

function argumentsFor(descriptor, coverageEdge) {
  const filesystemArguments = filesystemArgumentsFor(
    descriptor,
    coverageEdge,
  );
  if (filesystemArguments !== undefined) return filesystemArguments;
  const { sourceKey, exportName } = descriptor;
  const member = exportName.split(".").at(-1);
  if (
    new Set([
      "addListener",
      "off",
      "on",
      "once",
      "prependListener",
      "prependOnceListener",
      "removeListener",
    ]).has(member)
  ) {
    return [json("ibex-output-shape"), noop()];
  }
  if (member === "emit") return [json("ibex-output-shape")];
  if (member === "setMaxListeners") return [json(1)];
  if (member === "setTimeout") return [json(0), noop()];
  if (member === "setEncoding") return [json("utf8")];
  if (new Set(["push", "unshift"]).has(member)) return [json(null)];
  if (member === "pipe") return [inert()];
  if (new Set(["write", "send", "sendto", "_writeRaw"]).has(member)) {
    return [json("ibex-output-shape")];
  }
  if (member === "setHeader" || member === "appendHeader") {
    return [json("x-ibex-output-shape"), json("1")];
  }
  if (new Set(["getHeader", "hasHeader", "removeHeader"]).has(member)) {
    return [json("x-ibex-output-shape")];
  }
  if (member === "setHeaders" || member === "addTrailers") return [json({})];
  if (member === "question") return [json("ibex?"), noop()];
  if (member === "setPrompt") return [json("ibex> ")];
  if (member === "_insertString" || member === "_normalWrite") {
    return [json("ibex")];
  }
  if (member === "_moveCursor" || member === "_moveCursorTo") {
    return [json(0)];
  }
  if (new Set(["clearLine", "cursorTo", "moveCursor"]).has(member)) {
    return [inert(), json(0), json(0), noop()];
  }
  if (member === "clearScreenDown") return [inert(), noop()];
  if (member === "debuglog") return [json("IBEX_OUTPUT_SHAPE")];
  if (member === "toNamespacedPath") return [json("fixture.txt")];
  if (member === "writeText") return [];
  if (sourceKey === "ws" && member === "close") return [json(1)];
  if (member === "chdir") return [];
  if (member === "execve") return [];
  if (
    new Set([
      "exec",
      "execFile",
      "execFileSync",
      "execSync",
      "fork",
      "spawn",
      "spawnSync",
    ]).has(member)
  ) {
    return [];
  }
  return [];
}

function receiverFor(descriptor) {
  if (usesLiveFileHandleFixture(descriptor)) {
    return { kind: "fixture-value" };
  }
  const path = descriptor.access.path;
  if (descriptor.access.kind === "module-value" || path.length < 3) {
    return { kind: "module-value" };
  }
  return {
    kind: "prototype-shell",
    ownerPath: path.slice(0, path.indexOf("prototype")),
  };
}

function operationFor(descriptor) {
  if (descriptor.valueShape === "accessor") return "get";
  const segments = descriptor.exportName.split(".");
  if (
    segments.at(-1) === "constructor" ||
    (segments.length === 1 && CONSTRUCTOR_EXPORTS.has(segments[0]))
  ) {
    return "construct";
  }
  return "call";
}

function authorityBounds(descriptor, coverageEdge) {
  const bounds = canonicalSet(
    (coverageEdge.effects ?? []).map((effect) => effect.cap),
  ).map((cap) => ({ kind: "capability-family", cap }));
  const identity = `${descriptor.sourceKey}:${descriptor.exportName}`;
  for (const name of SUPPLEMENTAL_ENVIRONMENT_READS.get(identity) ?? []) {
    bounds.push({
      kind: "typed-effect",
      cap: "env:read",
      resourceKind: "environment-occurrence",
      requested: {
        kind: "environment-name",
        target: "broker-base",
        name,
      },
    });
  }
  return bounds;
}

function actionStagesForEdge(edge) {
  const byAction = new Map();
  for (const effect of edge?.effects ?? []) {
    if (
      typeof effect?.cap !== "string" ||
      !Array.isArray(effect.stages) ||
      effect.stages.length === 0
    ) {
      continue;
    }
    const stages = byAction.get(effect.cap) ?? new Set();
    for (const stage of effect.stages) stages.add(stage);
    byAction.set(effect.cap, stages);
  }
  return [...byAction]
    .sort(([left], [right]) => compareText(left, right))
    .map(([actionId, stages]) => ({
      actionId,
      stages: [...stages].sort(compareText),
    }));
}

function internalObserverActionStagesForEdge(edge) {
  if (
    edge?.surface?.kind !== "native-op" ||
    !edge.surface.name.startsWith("__exact")
  ) {
    return [];
  }
  const actions = new Set((edge.effects ?? []).map((effect) => effect.cap));
  const retainedPathRequestedList = new Set([
    "__exactFsReadFileAsync",
    "__exactFsWriteFileAsync",
  ]).has(edge.surface.name);
  return [
    ...(actions.has("fs:list") || retainedPathRequestedList
      ? [
          {
            actionId: "fs:list",
            stages: retainedPathRequestedList
              ? ["discovery", "repeat", "requested"]
              : ["repeat"],
          },
        ]
      : []),
    ...(actions.has("fs:read")
      ? [{ actionId: "fs:read", stages: ["discovery"] }]
      : []),
    ...(actions.has("fs:write")
      ? [{ actionId: "fs:write", stages: ["discovery"] }]
      : []),
  ];
}

function nativeFilesystemSourceBinding(edge) {
  if (
    edge?.surface?.kind !== "native-op" ||
    !edge.surface.name.startsWith("__exact") ||
    !(edge.effects ?? []).some((effect) =>
      new Set(["fs:list", "fs:read", "fs:write"]).has(effect.cap),
    )
  ) {
    return null;
  }
  const source = {
    kind: "source-authored-native-filesystem-terminal",
    nativeTerminal: edge.surface.name,
    nativeSourceRef: `src/engine/hermes_runtime_fs.cc#${edge.surface.name}`,
    hostAuthorizationRef:
      "src/host/abi.rs#ex_host_authorize_typed_fs_stack",
  };
  return { ...source, bindingDigest: taggedDigest(source) };
}

function sourceAuthoredFilesystemTerminalNames(descriptor) {
  if (!new Set(["node_fs", "node_fs_promises"]).has(descriptor.sourceKey)) {
    return [];
  }
  const name = descriptor.exportName;
  const callbackOrPromise =
    descriptor.sourceKey === "node_fs_promises" || !name.endsWith("Sync");
  if (callbackOrPromise) {
    if (
      new Set([
        "fdatasync",
        "fsync",
        "ftruncate",
        "FileHandle.truncate",
      ]).has(name)
    ) {
      return ["__exactFsFdAsync"];
    }
    if (new Set(["fstat", "FileHandle.stat"]).has(name)) {
      return ["__exactFsStatAsync"];
    }
    if (new Set(["read", "FileHandle.read"]).has(name)) {
      return ["__exactFsReadAsync"];
    }
    if (new Set(["readv", "FileHandle.readv"]).has(name)) {
      return ["__exactFsReadvAsync"];
    }
    if (new Set(["write", "FileHandle.write"]).has(name)) {
      return ["__exactFsWriteAsync"];
    }
    if (new Set(["writev", "FileHandle.writev"]).has(name)) {
      return ["__exactFsWritevAsync"];
    }
    if (name === "FileHandle.readFile") return ["__exactFsReadFileAsync"];
    if (name === "FileHandle.writeFile") return ["__exactFsWriteFileAsync"];
  }
  if (new Set(["access", "exists"]).has(name)) return ["__exactAccess"];
  if (callbackOrPromise && new Set(["appendFile", "writeFile"]).has(name)) {
    return ["__exactFsWriteFileAsync"];
  }
  if (callbackOrPromise && new Set(["lstat", "stat"]).has(name)) {
    return ["__exactFsStatAsync"];
  }
  if (name === "mkdir") return ["__exactMkdir"];
  if (name === "open") return ["__exactFsOpen"];
  if (name === "readdir") return ["__exactReaddir"];
  if (name === "readFile") return ["__exactFsReadFileAsync"];
  if (name === "statfs") return ["__exactStatfs"];
  if (name === "truncate") return ["__exactTruncate"];
  return [];
}

function requiredLiveFixtureTerminalNames(descriptor) {
  if (!usesLiveFdFixture(descriptor) && !usesLiveFileHandleFixture(descriptor)) {
    return [];
  }
  const name = descriptor.exportName;
  if (descriptor.sourceKey === "node_fs" && name.endsWith("Sync")) {
    const syncTerminals = new Map([
      ["fdatasyncSync", "__exactFsFdatasyncSync"],
      ["fstatSync", "__exactFsFstatSync"],
      ["fsyncSync", "__exactFsFsyncSync"],
      ["ftruncateSync", "__exactFsFtruncateSync"],
      ["readSync", "__exactFsRead"],
      ["readvSync", "__exactFsReadv"],
      ["writeSync", "__exactFsWrite"],
      ["writevSync", "__exactFsWritev"],
    ]);
    return syncTerminals.has(name) ? [syncTerminals.get(name)] : [];
  }
  return sourceAuthoredFilesystemTerminalNames(descriptor).filter(
    (terminal) => terminal !== "__exactFsOpen",
  );
}

function filesystemLiveFixtureSetup(descriptor, coverageEdge, coverage) {
  const fixtureKind = usesLiveFileHandleFixture(descriptor)
    ? "file-handle"
    : usesLiveFdFixture(descriptor)
      ? "fd"
      : null;
  if (fixtureKind === null) return null;
  const terminal = coverageEdgeBySurfaceName(
    coverage,
    "native-op",
    "__exactFsOpen",
  );
  if (!terminal || terminal.classification !== "effects") return null;
  const writes = new Set([
    "fdatasync",
    "fdatasyncSync",
    "fsync",
    "fsyncSync",
    "ftruncate",
    "ftruncateSync",
    "write",
    "writeSync",
    "writev",
    "writevSync",
    "FileHandle.truncate",
    "FileHandle.write",
    "FileHandle.writeFile",
    "FileHandle.writev",
  ]).has(descriptor.exportName);
  const source = {
    kind: "source-authored-filesystem-live-fixture",
    fixtureKind,
    fixtureKey: coverageEdge.id,
    moduleSpecifier:
      fixtureKind === "file-handle" ? "bun:fs/promises" : "node:fs",
    operation: fixtureKind === "file-handle" ? "open-promise" : "open-sync",
    path: `/project/fixtures/${coverageEdge.id}/input.txt`,
    flags: writes ? "r+" : "r",
    decisionEvidence: {
      kind: "coverage-bound-fixture-setup-effects",
      carrierEdgeId: coverageEdge.id,
      typedRoutes: [
        {
          coverageEdgeId: terminal.id,
          actionStages: actionStagesForEdge(terminal),
          internalObserverActionStages:
            internalObserverActionStagesForEdge(terminal),
          sourceBinding: nativeFilesystemSourceBinding(terminal),
        },
      ],
      requiredDecisionEdgeIds: [terminal.id],
      selectedNoEffectBranch: null,
    },
    cleanup: { kind: "close-filesystem-live-fixture" },
  };
  return { ...source, setupDigest: taggedDigest(source) };
}

function coverageEdgeBySurfaceName(coverage, kind, name) {
  const matches = (coverage?.edges ?? []).filter(
    (edge) => edge?.surface?.kind === kind && edge.surface.name === name,
  );
  return matches.length === 1 ? matches[0] : null;
}

function selectedNoEffectBranch(descriptor, coverageEdge, route) {
  const candidates = (coverageEdge.logicalBranches ?? []).filter(
    (branch) =>
      Array.isArray(branch?.effects) &&
      branch.effects.length === 0 &&
      Array.isArray(branch.when) &&
      branch.when.length === 1,
  );
  const selected = candidates.find((branch) => {
    const condition = branch.when[0];
    if (
      condition?.equals === "metadata" &&
      (route.receiver.kind === "prototype-shell" ||
        route.operation === "construct")
    ) {
      return true;
    }
    if (
      condition?.fact === "stdio.readline.operation" &&
      condition.equals === "memory" &&
      route.receiver.kind === "prototype-shell"
    ) {
      return true;
    }
    return (
      condition?.fact === "sqlite.open.mode" &&
      condition.equals === "memory" &&
      new Set(["Database", "default", "open"]).has(descriptor.exportName) &&
      new Set(["call", "construct"]).has(route.operation) &&
      route.arguments.length === 0
    );
  });
  if (!selected) return null;
  return {
    carrierEdgeId: coverageEdge.id,
    branchId: selected.id,
    conditions: structuredClone(selected.when),
    branchDigest: taggedDigest(selected),
  };
}

function decisionEvidenceFor(descriptor, surface, coverageEdge, coverage, route) {
  const edges = new Map([[coverageEdge.id, coverageEdge]]);
  const routeEvidence = surface.metadata?.enforcementRouteEvidence;
  if (routeEvidence?.kind === "static-builtin-call-graph") {
    for (const terminal of routeEvidence.terminals ?? []) {
      const edge = coverageEdgeBySurfaceName(coverage, "native-op", terminal);
      if (edge?.classification === "effects") edges.set(edge.id, edge);
    }
  }
  if (descriptor.sourceKey === "exact_process") {
    const edge = coverageEdgeBySurfaceName(
      coverage,
      "native-op",
      `global:process.${descriptor.exportName}`,
    );
    if (edge?.classification === "effects") edges.set(edge.id, edge);
  }
  if (SUPPLEMENTAL_ENVIRONMENT_READS.has(
    `${descriptor.sourceKey}:${descriptor.exportName}`,
  )) {
    const edge = coverageEdgeBySurfaceName(
      coverage,
      "native-op",
      "__exactGetEnv",
    );
    if (edge?.classification === "effects") edges.set(edge.id, edge);
  }
  for (const terminal of sourceAuthoredFilesystemTerminalNames(descriptor)) {
    const edge = coverageEdgeBySurfaceName(coverage, "native-op", terminal);
    if (edge?.classification === "effects") edges.set(edge.id, edge);
  }
  if (route.setup !== null) {
    const retainedOpen = coverageEdgeBySurfaceName(
      coverage,
      "native-op",
      "__exactFsOpen",
    );
    if (retainedOpen?.classification === "effects") {
      edges.set(retainedOpen.id, retainedOpen);
    }
  }
  const requiredDecisionEdgeIds = requiredLiveFixtureTerminalNames(descriptor)
    .map((terminal) =>
      coverageEdgeBySurfaceName(coverage, "native-op", terminal),
    )
    .filter((edge) => edge?.classification === "effects")
    .map((edge) => edge.id)
    .sort(compareText);
  const typedRoutes = [...edges.values()]
    .map((edge) => ({
      coverageEdgeId: edge.id,
      actionStages: actionStagesForEdge(edge),
      internalObserverActionStages: internalObserverActionStagesForEdge(edge),
      sourceBinding: nativeFilesystemSourceBinding(edge),
    }))
    .filter((edge) => edge.actionStages.length > 0)
    .sort((left, right) =>
      compareText(left.coverageEdgeId, right.coverageEdgeId),
    );
  return {
    kind: "coverage-bound-typed-effects",
    carrierEdgeId: coverageEdge.id,
    typedRoutes,
    requiredDecisionEdgeIds,
    selectedNoEffectBranch: selectedNoEffectBranch(
      descriptor,
      coverageEdge,
      route,
    ),
  };
}

function routeFor(descriptor, coverageEdge, coverage) {
  return {
    operation: operationFor(descriptor),
    receiver: receiverFor(descriptor),
    arguments: argumentsFor(descriptor, coverageEdge),
    cleanup: { kind: "fixture-owned-resource-release" },
    authorityBounds: authorityBounds(descriptor, coverageEdge),
    setup: filesystemLiveFixtureSetup(descriptor, coverageEdge, coverage),
    fixture: {
      kind: "isolated-family-fixture",
      family: descriptor.sourceKey,
      network: "private-loopback-only",
      filesystem: "private-project-tree-only",
      process: "controlled-helper-only",
    },
  };
}

function cohortFor(descriptor) {
  return descriptor.valueShape === "unknown"
    ? "descriptor-residual"
    : "registrar";
}

/**
 * Author one exact effect-classified builtin operation.  The API intentionally
 * has no parameter through which reviewed output policy can enter the plan.
 */
export function authoredBuiltinEffectsOutputInvocation({
  catalogKey,
  coverage,
  coverageEdge,
  surface,
  target,
}) {
  if (
    catalogKey?.sourceKind !== "builtin" ||
    catalogKey.output !== "[[return]]" ||
    coverageEdge?.classification !== "effects" ||
    coverageEdge.id !== catalogKey.surfaceId ||
    coverageEdge.surface?.kind !== "builtin" ||
    coverageEdge.surface.name !== surface?.name ||
    !Array.isArray(coverageEdge.effects) ||
    coverageEdge.effects.length === 0
  ) {
    return null;
  }
  if (!Array.isArray(coverage?.edges)) return null;
  const source = sourceDescriptor(surface, target);
  if (!source) return null;
  const { descriptor, moduleSpecifier, available } = source;
  if (
    !available ||
    descriptor.importReachability !== "public" ||
    typeof moduleSpecifier !== "string"
  ) {
    return null;
  }
  const route = routeFor(descriptor, coverageEdge, coverage);
  return {
    invocationSchema: BUILTIN_EFFECTS_OUTPUT_INVOCATION_SCHEMA,
    kind: "builtin-effects-output",
    cohort: cohortFor(descriptor),
    coverageEdgeId: coverageEdge.id,
    coverageClassification: "effects",
    surfaceObservedKey: surface.observedKey,
    moduleSpecifier,
    sourceDescriptor: descriptor,
    sourceDescriptorDigest: taggedDigest(descriptor),
    route,
    decisionEvidence: decisionEvidenceFor(
      descriptor,
      surface,
      coverageEdge,
      coverage,
      route,
    ),
    positiveControl: {
      kind: "public-family-positive-control",
      family: descriptor.sourceKey,
    },
    completion: { ...COMPLETION },
  };
}

/** Build the exact probe hook consumed by the consolidated sweep. */
export function authoredBuiltinEffectsOutputProbe(input) {
  const invocation = authoredBuiltinEffectsOutputInvocation(input);
  if (!invocation) return null;
  const sourceDescriptor = {
    kind: BUILTIN_EFFECTS_OUTPUT_SOURCE_DESCRIPTOR_KIND,
    surfaceObservedKey: invocation.surfaceObservedKey,
    invocation,
  };
  const sourceDescriptorDigest = taggedDigest(sourceDescriptor);
  const fixtureDigest = crypto
    .createHash("sha256")
    .update("ibex:capsec:builtin-effects-output:1", "utf8")
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
    fixtureId: `output-shape-builtin-effects-${fixtureDigest}`,
    sourceDescriptor,
    sourceDescriptorDigest,
    recordPath: ["[[return]]"],
  };
}

export function builtinEffectsOutputRouteManifest(invocations) {
  const familyCounts = Object.create(null);
  const cohortCounts = Object.create(null);
  const operationCounts = Object.create(null);
  for (const invocation of invocations) {
    const family = invocation.sourceDescriptor.sourceKey;
    familyCounts[family] = (familyCounts[family] ?? 0) + 1;
    cohortCounts[invocation.cohort] = (cohortCounts[invocation.cohort] ?? 0) + 1;
    const operation = invocation.route.operation;
    operationCounts[operation] = (operationCounts[operation] ?? 0) + 1;
  }
  const sorted = (value) =>
    Object.fromEntries(
      Object.entries(value).sort(([left], [right]) => compareText(left, right)),
    );
  return {
    total: invocations.length,
    cohorts: sorted(cohortCounts),
    families: sorted(familyCounts),
    operations: sorted(operationCounts),
  };
}
