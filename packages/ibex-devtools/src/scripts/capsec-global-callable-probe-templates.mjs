/**
 * Source-bound, expectation-free invocations for callable global API rows.
 *
 * A recipe is executable only when this file names a deterministic in-memory
 * receiver and arguments for the exact source-inventory member. Missing,
 * capability-requiring, closed, externally effectful, and lifecycle-unsafe
 * routes remain explicit `unexercisable` operations. The executor must retain
 * the actual outer return; a descriptor or a thrown call is not return
 * evidence.
 *
 * @ref LLP 0023#6-path-bearing-observables — output-disposition values are
 * produced from live execution of the exact loaded surface, not registrar
 * presence or reviewed policy inputs.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const INVOCATION_SCHEMA = "ibex/capsec-global-callable-invocation/1";
const COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const json = (value) => Object.freeze({ kind: "json", value });
const bigint = (value) => Object.freeze({ kind: "bigint", value: String(value) });
const noop = () => Object.freeze({ kind: "noop-function" });
const constant = (value) => Object.freeze({ kind: "constant-function", value });
const uint8Array = (...bytes) => Object.freeze({ kind: "uint8-array", bytes });
const buffer = (...bytes) => Object.freeze({ kind: "buffer", bytes });
const arrayBuffer = (byteLength) =>
  Object.freeze({ kind: "array-buffer", byteLength });
const typedArray = (globalName, values) =>
  Object.freeze({ kind: "typed-array", globalName, values });
const event = (type = "ibex-capsec") => Object.freeze({ kind: "event", type });
const eventTarget = () => Object.freeze({ kind: "event-target" });
const abortSignal = () => Object.freeze({ kind: "abort-signal" });
const blob = (text = "ibex", type = "text/plain") =>
  Object.freeze({ kind: "blob", text, type });
const promise = (value = "ibex") => Object.freeze({ kind: "resolved-promise", value });
const resolvedPromiseRecord = () => Object.freeze({ kind: "resolved-promise-record" });
const iterator = (...values) => Object.freeze({ kind: "iterator", values });
const readableStream = (text = "ibex") =>
  Object.freeze({ kind: "readable-stream", text });
const writableStream = () => Object.freeze({ kind: "writable-stream" });
const transformStream = () => Object.freeze({ kind: "transform-stream" });
const throwingNumberCoercion = () =>
  Object.freeze({ kind: "throwing-number-coercion" });

const existing = (globalName) =>
  Object.freeze({ kind: "existing-global", globalName });
const construct = (globalName, ...arguments_) =>
  Object.freeze({ kind: "construct-global", globalName, arguments: arguments_ });
const factory = (factoryId, options = {}) =>
  Object.freeze({ kind: "factory", factoryId, options });

const call = (receiver, arguments_ = [], options = {}) => ({
  operation: "call",
  receiver,
  arguments: arguments_,
  ...options,
});
const callMember = (arguments_ = [], options = {}) =>
  call(Object.freeze({ kind: "source-member-owner" }), arguments_, options);
const constructMember = (arguments_ = [], options = {}) => ({
  operation: "construct",
  receiver: Object.freeze({ kind: "source-member-owner" }),
  arguments: arguments_,
  ...options,
});
const get = (receiver) => ({
  operation: "get",
  receiver,
  arguments: [],
});
const getMember = () => get(Object.freeze({ kind: "source-member-owner" }));
const typedEffectAuthority = (cap, resourceKind, requested) =>
  Object.freeze({ kind: "typed-effect", cap, resourceKind, requested });
const authority = (...entries) => ({ authority: Object.freeze(entries) });

const ENV_EXACT_COMPAT_TEST_AUTHORITY = typedEffectAuthority(
  "env:read",
  "environment-occurrence",
  Object.freeze({
    kind: "environment-name",
    target: "broker-base",
    name: "EXACT_COMPAT_TEST",
  }),
);
const ENV_WPT_SERVER_URL_AUTHORITY = typedEffectAuthority(
  "env:read",
  "environment-occurrence",
  Object.freeze({
    kind: "environment-name",
    target: "broker-base",
    name: "WPT_SERVER_URL",
  }),
);
const PROJECT_ROOT_LIST_AUTHORITY = typedEffectAuthority(
  "fs:list",
  "path-occurrence",
  Object.freeze({ root: "project", components: Object.freeze([]) }),
);
const MEMORY_SYSTEM_INFO_AUTHORITY = typedEffectAuthority(
  "sys:read",
  "system-info-occurrence",
  Object.freeze({ kind: "system-info", name: "memory" }),
);

const unsupported = (reasonCode, reason) => ({
  operation: "unexercisable",
  reasonCode,
  reason,
});

const BUFFER_BYTES = Object.freeze([0, 1, 2, 3, 4, 5, 6, 7]);
const bufferReceiver = () => factory("buffer", { bytes: [...BUFFER_BYTES] });

const BUFFER_METHOD_ARGUMENTS = Object.freeze({
  compare: [buffer(...BUFFER_BYTES)],
  copy: [buffer(0, 0, 0, 0, 0, 0, 0, 0), json(0), json(0), json(8)],
  equals: [buffer(...BUFFER_BYTES)],
  fill: [json(1), json(0), json(8)],
  includes: [json(1)],
  indexOf: [json(1)],
  lastIndexOf: [json(1)],
  readBigInt64BE: [json(0)],
  readBigInt64LE: [json(0)],
  readBigUInt64BE: [json(0)],
  readBigUInt64LE: [json(0)],
  readDoubleBE: [json(0)],
  readDoubleLE: [json(0)],
  readFloatBE: [json(0)],
  readFloatLE: [json(0)],
  readInt16BE: [json(0)],
  readInt16LE: [json(0)],
  readInt32BE: [json(0)],
  readInt32LE: [json(0)],
  readInt8: [json(0)],
  readIntBE: [json(0), json(6)],
  readIntLE: [json(0), json(6)],
  readUInt16BE: [json(0)],
  readUInt16LE: [json(0)],
  readUInt32BE: [json(0)],
  readUInt32LE: [json(0)],
  readUInt8: [json(0)],
  readUIntBE: [json(0), json(6)],
  readUIntLE: [json(0), json(6)],
  slice: [json(0), json(4)],
  subarray: [json(0), json(4)],
  write: [json("a"), json(0), json(1), json("utf8")],
  writeBigInt64BE: [bigint(-1), json(0)],
  writeBigInt64LE: [bigint(-1), json(0)],
  writeBigUInt64BE: [bigint(1), json(0)],
  writeBigUInt64LE: [bigint(1), json(0)],
  writeDoubleBE: [json(1.5), json(0)],
  writeDoubleLE: [json(1.5), json(0)],
  writeFloatBE: [json(1.5), json(0)],
  writeFloatLE: [json(1.5), json(0)],
  writeInt16BE: [json(-1), json(0)],
  writeInt16LE: [json(-1), json(0)],
  writeInt32BE: [json(-1), json(0)],
  writeInt32LE: [json(-1), json(0)],
  writeInt8: [json(-1), json(0)],
  writeIntBE: [json(-1), json(0), json(6)],
  writeIntLE: [json(-1), json(0), json(6)],
  writeUInt16BE: [json(1), json(0)],
  writeUInt16LE: [json(1), json(0)],
  writeUInt32BE: [json(1), json(0)],
  writeUInt32LE: [json(1), json(0)],
  writeUInt8: [json(1), json(0)],
  writeUIntBE: [json(1), json(0), json(6)],
  writeUIntLE: [json(1), json(0), json(6)],
});

const BUFFER_ALIASES = Object.freeze({
  readBigUint64BE: "readBigUInt64BE",
  readBigUint64LE: "readBigUInt64LE",
  readUint16BE: "readUInt16BE",
  readUint16LE: "readUInt16LE",
  readUint32BE: "readUInt32BE",
  readUint32LE: "readUInt32LE",
  readUint8: "readUInt8",
  readUintBE: "readUIntBE",
  readUintLE: "readUIntLE",
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

const BUFFER_NO_ARGUMENT_METHODS = new Set([
  "entries",
  "keys",
  "swap16",
  "swap32",
  "swap64",
  "[[Symbol.for:nodejs.util.inspect.custom]]",
  "[[Symbol.iterator]]",
  "toJSON",
  "values",
]);

function bufferRecipe(memberName) {
  if (memberName === null) return constructMember([json(8)]);
  const staticArguments = {
    alloc: [json(8)],
    allocUnsafe: [json(8)],
    allocUnsafeSlow: [json(8)],
    byteLength: [json("ibex")],
    compare: [buffer(0), buffer(1)],
    concat: [Object.freeze({ kind: "buffer-array", values: [[0], [1]] })],
    from: [json("ibex")],
    isBuffer: [buffer(0)],
    isEncoding: [json("utf8")],
  };
  if (Object.hasOwn(staticArguments, memberName)) {
    return callMember(staticArguments[memberName]);
  }
  const canonical = Object.hasOwn(BUFFER_ALIASES, memberName)
    ? BUFFER_ALIASES[memberName]
    : memberName;
  if (canonical === "toString") {
    return call(bufferReceiver(), [json("utf8"), json(0), json(8)]);
  }
  if (BUFFER_NO_ARGUMENT_METHODS.has(memberName)) {
    return call(bufferReceiver());
  }
  if (Object.hasOwn(BUFFER_METHOD_ARGUMENTS, canonical)) {
    return call(bufferReceiver(), BUFFER_METHOD_ARGUMENTS[canonical]);
  }
  return null;
}

const EVENT_RECEIVER_CLASSES = new Set([
  "CloseEvent",
  "CustomEvent",
  "ErrorEvent",
  "Event",
  "FocusEvent",
  "KeyboardEvent",
  "MessageEvent",
  "MediaQueryListEvent",
  "ProgressEvent",
  "PromiseRejectionEvent",
]);

const EVENT_METHOD_ARGUMENTS = Object.freeze({
  composedPath: [],
  _isBeingDispatched: [],
  _isImmediatePropagationStopped: [],
  _isPropagationStopped: [],
  preventDefault: [],
  _resetFlags: [],
  _setCurrentTarget: [eventTarget()],
  _setDispatchFlag: [json(true)],
  _setEventPhase: [json(2)],
  _setInPassiveListener: [json(false)],
  _setTarget: [eventTarget()],
  stopImmediatePropagation: [],
  stopPropagation: [],
  initMessageEvent: [
    json("message"),
    json(false),
    json(false),
    json("ibex"),
    json("https://example.invalid"),
    json("event-1"),
    json(null),
  ],
});

function eventReceiver(globalName) {
  const options = { type: "ibex-capsec" };
  if (globalName === "PromiseRejectionEvent") options.promise = "resolved";
  return factory("event-instance", { globalName, ...options });
}

function eventRecipe(globalName, memberName) {
  if (!EVENT_RECEIVER_CLASSES.has(globalName)) return null;
  if (!Object.hasOwn(EVENT_METHOD_ARGUMENTS, memberName)) return null;
  return call(eventReceiver(globalName), EVENT_METHOD_ARGUMENTS[memberName]);
}

const TYPED_ARRAYS = new Set([
  "BigInt64Array",
  "BigUint64Array",
  "Float16Array",
  "Float32Array",
  "Float64Array",
  "Int16Array",
  "Int32Array",
  "Int8Array",
  "Uint16Array",
  "Uint32Array",
  "Uint8Array",
  "Uint8ClampedArray",
]);

function typedArrayRecipe(globalName, memberName) {
  if (!TYPED_ARRAYS.has(globalName)) return null;
  if (memberName === null) return constructMember([json(4)]);
  if (memberName === "prototype.subarray") {
    return call(factory("typed-array", { globalName, length: 4 }), [json(0), json(2)]);
  }
  return null;
}

const ITERATOR_ARGUMENTS = Object.freeze({
  "prototype.drop": [json(1)],
  "prototype.every": [constant(true)],
  "prototype.filter": [constant(true)],
  "prototype.find": [constant(true)],
  "prototype.flatMap": [constant([1])],
  "prototype.forEach": [noop()],
  "prototype.map": [constant(1)],
  "prototype.reduce": [constant(1), json(0)],
  "prototype.some": [constant(true)],
  "prototype.[[Symbol.iterator]]": [],
  "prototype.take": [json(1)],
  "prototype.toArray": [],
});

function iteratorRecipe(memberName) {
  if (memberName === "from") return callMember([iterator(1, 2)]);
  if (!Object.hasOwn(ITERATOR_ARGUMENTS, memberName)) return null;
  return call(factory("iterator-helper", { values: [1, 2] }), ITERATOR_ARGUMENTS[memberName]);
}

const COLLECTION_ARGUMENTS = Object.freeze({
  append: [json("x-ibex"), json("1")],
  delete: [json("x-ibex")],
  entries: [],
  forEach: [noop()],
  get: [json("x-ibex")],
  getAll: [json("x-ibex")],
  getSetCookie: [],
  has: [json("x-ibex")],
  keys: [],
  set: [json("x-ibex"), json("1")],
  "[[Symbol.iterator]]": [],
  "[[Symbol.for:nodejs.util.inspect.custom]]": [],
  toJSON: [],
  toTupleArray: [],
  values: [],
});

function headersRecipe(memberName) {
  if (memberName === null) return constructMember([json({ "x-ibex": "1" })]);
  if (memberName === "fromTupleArray") {
    return callMember([json([["x-ibex", "1"]])]);
  }
  if (!Object.hasOwn(COLLECTION_ARGUMENTS, memberName)) return null;
  return call(
    factory("headers", { entries: [["x-ibex", "1"]] }),
    COLLECTION_ARGUMENTS[memberName],
  );
}

function formDataRecipe(memberName) {
  const argumentsByMethod = {
    append: [json("field"), json("value")],
    delete: [json("field")],
    _encode: [],
    entries: [],
    forEach: [noop()],
    get: [json("field")],
    getAll: [json("field")],
    _getEntries: [],
    has: [json("field")],
    keys: [],
    set: [json("field"), json("value")],
    "[[Symbol.iterator]]": [],
    values: [],
  };
  if (!Object.hasOwn(argumentsByMethod, memberName)) return null;
  return call(factory("form-data", { entries: [["field", "value"]] }), argumentsByMethod[memberName]);
}

function urlSearchParamsRecipe(memberName) {
  if (memberName === null) return constructMember([json("a=1")]);
  if (memberName === "_resetFromSearch" || memberName === "toJSON") {
    return get(factory("url-search-params", { value: "a=1" }));
  }
  const argumentsByMethod = {
    append: [json("b"), json("2")],
    delete: [json("a")],
    entries: [],
    forEach: [noop()],
    get: [json("a")],
    getAll: [json("a")],
    has: [json("a")],
    keys: [],
    set: [json("a"), json("2")],
    _setURL: [json(null)],
    sort: [],
    "[[Symbol.iterator]]": [],
    toString: [],
    values: [],
  };
  if (!Object.hasOwn(argumentsByMethod, memberName)) return null;
  return call(factory("url-search-params", { value: "a=1" }), argumentsByMethod[memberName]);
}

function blobRecipe(globalName, memberName) {
  if (!new Set(["Blob", "File"]).has(globalName)) return null;
  const receiver = (format = "text") => factory("blob-like", { globalName, format });
  const noArguments = new Set(["arrayBuffer", "bytes", "_getBytes", "stream", "text"]);
  if (noArguments.has(memberName)) return call(receiver());
  if (memberName === "json") return call(receiver("json"));
  if (memberName === "formData") return call(receiver("form"));
  if (memberName === "slice") return call(receiver(), [json(0), json(2), json("text/plain")]);
  return null;
}

function urlRecipe(memberName) {
  if (memberName === null) {
    return constructMember([json("https://example.invalid/path?x=1")]);
  }
  const staticArguments = {
    canParse: [json("https://example.invalid")],
    createObjectURL: [blob("ibex")],
    parse: [json("https://example.invalid")],
    revokeObjectURL: [json("blob:ibex-capsec-nonexistent")],
  };
  if (Object.hasOwn(staticArguments, memberName)) {
    return callMember(staticArguments[memberName],
      memberName === "createObjectURL" ? { cleanup: { kind: "revoke-returned-object-url" } } : {});
  }
  if (new Set(["toJSON", "toString"]).has(memberName)) {
    return call(factory("url", { value: "https://example.invalid/path?x=1" }));
  }
  if (memberName === "_updateSearch") {
    return call(factory("url", { value: "https://example.invalid/path" }), [json("?x=1")]);
  }
  return null;
}

function requestResponseRecipe(globalName, memberName) {
  if (!new Set(["Request", "Response"]).has(globalName)) return null;
  const requestAuthority = globalName === "Request"
    ? authority(ENV_WPT_SERVER_URL_AUTHORITY)
    : {};
  const responseCompatibilityAuthority = authority(ENV_EXACT_COMPAT_TEST_AUTHORITY);
  if (memberName === null) {
    return globalName === "Request"
      ? constructMember(
          [factory("body-message", { globalName: "Request", format: "text" })],
          requestAuthority,
        )
      : constructMember([json("ibex")]);
  }
  if (globalName === "Response" && memberName === "json") {
    return callMember([json({ ibex: true })], responseCompatibilityAuthority);
  }
  const receiver = (format = "text") => factory("body-message", { globalName, format });
  if (new Set(["arrayBuffer", "blob", "bytes", "text"]).has(memberName)) {
    return call(receiver(), [], requestAuthority);
  }
  if (memberName === "json") return call(receiver("json"), [], requestAuthority);
  if (memberName === "formData") return call(receiver("form"), [], requestAuthority);
  if (memberName === "clone") {
    return call(
      receiver(),
      [],
      globalName === "Request" ? requestAuthority : {},
    );
  }
  if (globalName === "Request") {
    if (new Set(["getBodyAsUint8Array", "getBodyStream", "hasExplicitKeepalive", "isBodyStream", "markBodyAsUsedForFetch"]).has(memberName)) {
      return call(receiver(), [], requestAuthority);
    }
  } else {
    if (memberName === "error") return callMember();
    if (memberName === "redirect") {
      return callMember(
        [json("https://example.com/next"), json(302)],
        responseCompatibilityAuthority,
      );
    }
  }
  return null;
}

function textCodecRecipe(globalName, memberName) {
  if (globalName === "TextDecoder" && memberName === "decode") {
    return call(construct("TextDecoder", json("utf-8")), [uint8Array(73, 98, 101, 120)]);
  }
  if (globalName === "TextEncoder" && memberName === "encode") {
    return call(construct("TextEncoder"), [json("ibex")]);
  }
  if (globalName === "TextEncoder" && memberName === "encodeInto") {
    return call(construct("TextEncoder"), [json("ibex"), uint8Array(0, 0, 0, 0, 0, 0, 0, 0)]);
  }
  return null;
}

function atomicsRecipe(memberName) {
  const receiver = existing("Atomics");
  const view = Object.freeze({ kind: "shared-int32-array", values: [0, 0] });
  const args = {
    add: [view, json(0), json(1)],
    and: [view, json(0), json(1)],
    compareExchange: [view, json(0), json(0), json(1)],
    exchange: [view, json(0), json(1)],
    isLockFree: [json(4)],
    load: [view, json(0)],
    notify: [view, json(0), json(1)],
    or: [view, json(0), json(1)],
    store: [view, json(0), json(1)],
    sub: [view, json(0), json(1)],
    wait: [view, json(0), json(0), json(0)],
    xor: [view, json(0), json(1)],
  };
  return Object.hasOwn(args, memberName) ? call(receiver, args[memberName]) : null;
}

function abortRecipe(globalName, memberName) {
  if (globalName === "AbortController" && memberName === "abort") {
    return call(construct("AbortController"), [json("ibex")]);
  }
  if (globalName !== "AbortSignal") return null;
  const signal = factory("abort-signal");
  if (memberName === "_abort") return call(signal, [json("ibex")]);
  if (memberName === "abort") return callMember([json("ibex")]);
  if (memberName === "any") return callMember([Object.freeze({ kind: "abort-signal-array" })]);
  if (memberName === "timeout") return callMember([json(0)]);
  if (memberName === "throwIfAborted") return call(signal);
  if (memberName === "addEventListener") return call(signal, [json("abort"), noop()]);
  if (memberName === "removeEventListener") return call(signal, [json("abort"), noop()]);
  if (memberName === "dispatchEvent") return call(signal, [event("abort")]);
  return null;
}

function eventTargetRecipe(globalName, memberName) {
  if (globalName === "EventTarget") {
    if (memberName === "addEventListener") return call(construct("EventTarget"), [json("ibex"), noop()]);
    if (memberName === "removeEventListener") return call(construct("EventTarget"), [json("ibex"), noop()]);
    if (memberName === "dispatchEvent") return call(construct("EventTarget"), [event()]);
  }
  if (globalName === "FileReader") {
    const receiver = construct("FileReader");
    if (memberName === "abort") return call(receiver);
    if (memberName === "addEventListener") return call(receiver, [json("load"), noop()]);
    if (memberName === "removeEventListener") return call(receiver, [json("load"), noop()]);
    if (memberName === "dispatchEvent") return call(receiver, [event("load")]);
    if (new Set(["readAsArrayBuffer", "readAsBinaryString", "readAsDataURL", "readAsText"]).has(memberName)) {
      return call(receiver, [blob("ibex")]);
    }
  }
  if (globalName === "MediaQueryList") {
    const receiver = factory("media-query-list", { query: "(min-width: 0px)" });
    if (new Set(["addEventListener", "addListener"]).has(memberName)) return call(receiver, [memberName === "addListener" ? noop() : json("change"), ...(memberName === "addListener" ? [] : [noop()])]);
    if (new Set(["removeEventListener", "removeListener"]).has(memberName)) return call(receiver, [memberName === "removeListener" ? noop() : json("change"), ...(memberName === "removeListener" ? [] : [noop()])]);
    if (memberName === "dispatchEvent") return call(receiver, [event("change")]);
    if (memberName === "_syncFromAppearance") return call(receiver);
  }
  return null;
}

function processRecipe(memberName) {
  const receiver = existing("process");
  if (memberName === "memoryUsage") {
    return call(receiver, [], authority(MEMORY_SYSTEM_INFO_AUTHORITY));
  }
  const noArguments = new Set([
    "cpuUsage",
    "cwd",
    "eventNames",
    "getActiveResourcesInfo",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getMaxListeners",
    "getuid",
    "hasUncaughtExceptionCaptureCallback",
    "memoryUsage",
    "resourceUsage",
    "umask",
    "uptime",
    "_getActiveHandles",
    "_getActiveRequests",
  ]);
  if (noArguments.has(memberName)) return call(receiver);
  if (memberName === "chdir") {
    return call(
      receiver,
      [json(".")],
      authority(PROJECT_ROOT_LIST_AUTHORITY),
    );
  }
  if (memberName === "emit") return call(receiver, [json("ibex-capsec-process")]);
  if (new Set(["listenerCount", "listeners", "rawListeners"]).has(memberName)) {
    return call(receiver, [json("ibex-capsec-process")]);
  }
  if (new Set(["off", "removeListener"]).has(memberName)) {
    return call(receiver, [json("ibex-capsec-process"), noop()]);
  }
  if (memberName === "removeAllListeners") {
    return call(receiver, [json("ibex-capsec-process")]);
  }
  if (memberName === "execve") return call(receiver, [json(""), json(null)]);
  if (memberName === "exit") return call(receiver, [throwingNumberCoercion()]);
  if (memberName === "abort") return call(receiver);
  if (memberName === "binding") return call(receiver, [json("ibex-capsec-invalid")]);
  if (memberName === "emitWarning") return call(receiver, [json(null)]);
  if (memberName === "kill") {
    return call(receiver, [throwingNumberCoercion(), json(0)]);
  }
  if (memberName === "_kill") {
    return call(receiver, [throwingNumberCoercion(), json(0)]);
  }
  if (new Set(["setegid", "seteuid", "setgid", "setuid"]).has(memberName)) {
    return call(receiver, [throwingNumberCoercion()]);
  }
  if (memberName === "setMaxListeners") {
    return call(factory("isolated-prototype", { globalName: "process" }), [json(1)]);
  }
  if (memberName === "setUncaughtExceptionCaptureCallback") {
    return call(receiver, [json(1)]);
  }
  if (new Set(["addListener", "on", "once", "prependListener", "prependOnceListener"]).has(memberName)) {
    return call(receiver, [json("ibex-capsec-process"), noop()], {
      cleanup: {
        kind: "remove-receiver-listener",
        type: "ibex-capsec-process",
        listenerArgument: 1,
      },
    });
  }
  return null;
}

function messagingRecipe(globalName, memberName) {
  if (globalName === "MessagePort") {
    const receiver = factory("message-port");
    const cleanup = { cleanup: { kind: "close-message-port-pair" } };
    if (memberName === "addEventListener") {
      return call(receiver, [json("message"), noop()], {
        cleanup: { kind: "close-message-port-pair" },
      });
    }
    if (memberName === "removeEventListener") {
      return call(receiver, [json("message"), noop()], cleanup);
    }
    if (memberName === "dispatchEvent") return call(receiver, [event("message")], cleanup);
    if (memberName === "postMessage") return call(receiver, [json({ ibex: true })], cleanup);
    if (memberName === "start" || memberName === "close") return call(receiver, [], cleanup);
  }
  if (globalName === "BroadcastChannel") {
    const receiver = factory("broadcast-channel", { name: "ibex-capsec-output" });
    const cleanup = { cleanup: { kind: "close-receiver" } };
    if (memberName === "addEventListener") {
      return call(receiver, [json("message"), noop()], cleanup);
    }
    if (memberName === "removeEventListener") {
      return call(receiver, [json("message"), noop()], cleanup);
    }
    if (memberName === "dispatchEvent") return call(receiver, [event("message")], cleanup);
    if (memberName === "postMessage") return call(receiver, [json({ ibex: true })], cleanup);
    if (memberName === "close") return call(receiver, [], cleanup);
    if (memberName === "_deliverMessage") {
      return callMember([json("ibex-capsec-output"), json({ ibex: true })]);
    }
    if (memberName === "_getChannelCount") {
      return callMember([json("ibex-capsec-output")]);
    }
    if (memberName === "_getChannelNames") return callMember();
  }
  return null;
}

function idbKeyRangeRecipe(memberName) {
  if (new Set(["bound", "lowerBound", "only", "upperBound"]).has(memberName)) {
    const args = memberName === "bound" ? [json(1), json(2)] : [json(1)];
    return callMember(args);
  }
  if (memberName === "includes") return call(factory("idb-key-range"), [json(1)]);
  return null;
}

function promiseRecipe(globalName, memberName) {
  if (globalName === "__OriginalPromise") return getMember();
  if (memberName === null) {
    return constructMember([Object.freeze({ kind: "promise-executor", value: "ibex" })]);
  }
  if (memberName === "reject") {
    return callMember([json("ibex-capsec-rejection")], { suppressRejection: true });
  }
  const receiver = factory("resolved-promise", { value: "ibex" });
  if (memberName === "prototype.catch") return call(receiver, [noop()]);
  if (memberName === "prototype.finally") return call(receiver, [noop()]);
  if (memberName === "prototype.then") return call(receiver, [constant("observed")]);
  return null;
}

function intlRecipe(memberName) {
  const locale = json("en-US");
  const locales = json(["en-US"]);
  const duration = json({ hours: 1, minutes: 2, seconds: 3 });
  const receivers = {
    "Collator.compare": construct("Intl.Collator", locale),
    "Collator.resolvedOptions": construct("Intl.Collator", locale),
    "DateTimeFormat.prototype.formatRange": construct("Intl.DateTimeFormat", locale, json({ timeZone: "UTC" })),
    "DateTimeFormat.prototype.formatRangeToParts": construct("Intl.DateTimeFormat", locale, json({ timeZone: "UTC" })),
    "DateTimeFormat.prototype.formatToParts": construct("Intl.DateTimeFormat", locale, json({ timeZone: "UTC" })),
    "DisplayNames.of": construct("Intl.DisplayNames", locale, json({ type: "language" })),
    "DisplayNames.resolvedOptions": construct("Intl.DisplayNames", locale, json({ type: "language" })),
    "DurationFormat._buildDigitalParts": construct("Intl.DurationFormat", locale, json({ style: "digital" })),
    "DurationFormat._buildParts": construct("Intl.DurationFormat", locale, json({ style: "short" })),
    "DurationFormat._buildTextParts": construct("Intl.DurationFormat", locale, json({ style: "short" })),
    "DurationFormat.format": construct("Intl.DurationFormat", locale, json({ style: "short" })),
    "DurationFormat.formatToParts": construct("Intl.DurationFormat", locale, json({ style: "short" })),
    "DurationFormat.resolvedOptions": construct("Intl.DurationFormat", locale, json({ style: "short" })),
    "ListFormat.format": construct("Intl.ListFormat", locale),
    "ListFormat.formatToParts": construct("Intl.ListFormat", locale),
    "ListFormat.resolvedOptions": construct("Intl.ListFormat", locale),
    "Locale.maximize": construct("Intl.Locale", locale),
    "Locale.minimize": construct("Intl.Locale", locale),
    "Locale.toJSON": construct("Intl.Locale", locale),
    "Locale.toString": construct("Intl.Locale", locale),
    "NumberFormat.prototype.formatRange": construct("Intl.NumberFormat", locale),
    "NumberFormat.prototype.formatRangeToParts": construct("Intl.NumberFormat", locale),
    "NumberFormat.prototype.formatToParts": construct("Intl.NumberFormat", locale),
    "PluralRules.resolvedOptions": construct("Intl.PluralRules", locale),
    "PluralRules.select": construct("Intl.PluralRules", locale),
    "PluralRules.selectRange": construct("Intl.PluralRules", locale),
    "RelativeTimeFormat.format": construct("Intl.RelativeTimeFormat", locale),
    "RelativeTimeFormat.formatToParts": construct("Intl.RelativeTimeFormat", locale),
    "RelativeTimeFormat.resolvedOptions": construct("Intl.RelativeTimeFormat", locale),
    "Segmenter.resolvedOptions": construct("Intl.Segmenter", locale),
    "Segmenter.segment": construct("Intl.Segmenter", locale),
  };
  const argumentsByMember = {
    "Collator.compare": [json("a"), json("b")],
    "Collator.resolvedOptions": [],
    "DateTimeFormat.prototype.formatRange": [json(0), json(1_000)],
    "DateTimeFormat.prototype.formatRangeToParts": [json(0), json(1_000)],
    "DateTimeFormat.prototype.formatToParts": [json(0)],
    "DisplayNames.of": [json("en")],
    "DisplayNames.resolvedOptions": [],
    "DurationFormat._buildDigitalParts": [duration],
    "DurationFormat._buildParts": [duration],
    "DurationFormat._buildTextParts": [duration],
    "DurationFormat.format": [duration],
    "DurationFormat.formatToParts": [duration],
    "DurationFormat.resolvedOptions": [],
    "ListFormat.format": [json(["a", "b"])],
    "ListFormat.formatToParts": [json(["a", "b"])],
    "ListFormat.resolvedOptions": [],
    "Locale.maximize": [],
    "Locale.minimize": [],
    "Locale.toJSON": [],
    "Locale.toString": [],
    "NumberFormat.prototype.formatRange": [json(1), json(2)],
    "NumberFormat.prototype.formatRangeToParts": [json(1), json(2)],
    "NumberFormat.prototype.formatToParts": [json(1)],
    "PluralRules.resolvedOptions": [],
    "PluralRules.select": [json(1)],
    "PluralRules.selectRange": [json(1), json(2)],
    "RelativeTimeFormat.format": [json(-1), json("day")],
    "RelativeTimeFormat.formatToParts": [json(-1), json("day")],
    "RelativeTimeFormat.resolvedOptions": [],
    "Segmenter.resolvedOptions": [],
    "Segmenter.segment": [json("ibex")],
  };
  if (Object.hasOwn(receivers, memberName)) {
    return call(receivers[memberName], argumentsByMember[memberName]);
  }
  const constructors = {
    Collator: [locale],
    DisplayNames: [locale, json({ type: "language" })],
    DurationFormat: [locale, json({ style: "short" })],
    ListFormat: [locale],
    Locale: [locale],
    PluralRules: [locale],
    RelativeTimeFormat: [locale],
    Segmenter: [locale],
  };
  if (Object.hasOwn(constructors, memberName)) {
    return constructMember(constructors[memberName]);
  }
  if (memberName === "getCanonicalLocales") return callMember([locales]);
  if (memberName?.endsWith(".supportedLocalesOf")) return callMember([locales]);
  return null;
}

function performanceRecipe(memberName) {
  const args = {
    clearMarks: [json("ibex-capsec-mark")],
    clearMeasures: [json("ibex-capsec-measure")],
    clearResourceTimings: [],
    getEntries: [],
    getEntriesByName: [json("ibex-capsec-mark")],
    getEntriesByType: [json("mark")],
    mark: [json("ibex-capsec-mark")],
    measure: [json("ibex-capsec-measure"), json({ start: 0, end: 1 })],
    now: [],
    setResourceTimingBufferSize: [json(1)],
    toJSON: [],
  };
  if (!Object.hasOwn(args, memberName)) return null;
  const cleanup = memberName === "mark"
    ? { kind: "clear-performance-mark", name: "ibex-capsec-mark" }
    : memberName === "measure"
      ? { kind: "clear-performance-measure", name: "ibex-capsec-measure" }
      : undefined;
  return call(existing("performance"), args[memberName], cleanup ? { cleanup } : {});
}

function performanceEntryRecipe(globalName, memberName) {
  if (memberName !== "toJSON") return null;
  if (globalName === "PerformanceEntry" || globalName === "PerformanceMark") {
    return call(factory("performance-mark", { name: "ibex-capsec-entry" }), [], {
      cleanup: { kind: "clear-performance-mark", name: "ibex-capsec-entry" },
    });
  }
  if (globalName === "PerformanceMeasure") {
    return call(factory("performance-measure", { name: "ibex-capsec-entry" }), [], {
      cleanup: { kind: "clear-performance-measure", name: "ibex-capsec-entry" },
    });
  }
  return null;
}

function performanceObserverRecipe(memberName) {
  const receiver = factory("performance-observer");
  if (memberName === "disconnect" || memberName === "takeRecords") return call(receiver);
  if (memberName === "_notify") return call(receiver, [json(null)]);
  if (memberName === "observe") {
    return call(receiver, [json({ entryTypes: ["mark"] })], {
      cleanup: { kind: "disconnect-receiver" },
    });
  }
  return null;
}

function exactRecipe(globalName, memberName) {
  if (!new Set(["Exact", "Bun"]).has(globalName)) return null;
  if (memberName === "CryptoHasher") return constructMember([json("sha256")]);
  if (memberName === "CryptoHasher.update") {
    return call(factory("exact-crypto-hasher", { globalName }), [json("ibex")]);
  }
  if (memberName === "CryptoHasher.digest") {
    return call(factory("exact-crypto-hasher", { globalName, update: "ibex" }), [json("hex")]);
  }
  if (memberName === "deepMatch") return callMember([json({ a: 1 }), json({ a: 1 })]);
  if (memberName === "peek") return callMember([promise("ibex")]);
  if (memberName === "peek.status") return callMember([promise("ibex")]);
  if (memberName === "semver.order") return callMember([json("1.0.0"), json("2.0.0")]);
  if (memberName === "semver.satisfies") return callMember([json("1.0.0"), json("^1.0.0")]);
  if (memberName === "sleep") return callMember([json(0)]);
  if (memberName === "sleepSync") return callMember([json(0)]);
  if (memberName === "which") return callMember([json("")]);
  if (memberName === "unsafe.arrayBufferToString") return callMember([uint8Array(73, 98, 101, 120)]);
  if (memberName === "unsafe.gcAggressionLevel") return callMember();
  if (memberName === "accessibility.announce") return callMember([json("")]);
  if (memberName === "accessibility.get") return callMember([json("prefersReducedMotion")]);
  if (memberName === "accessibility.addEventListener") {
    return callMember([json("change"), noop()], { cleanup: { kind: "invoke-returned-function" } });
  }
  if (memberName === "locale.addListener") {
    return callMember([json("change"), noop()], { cleanup: { kind: "invoke-returned-function" } });
  }
  if (memberName === "password.hash") {
    return callMember([json("ibex")], { suppressRejection: true });
  }
  if (memberName === "password.verify") {
    return callMember([json("ibex"), json("$ibex$invalid")], { suppressRejection: true });
  }
  if (memberName === "password.hashSync") return callMember([json("ibex")]);
  if (memberName === "password.verifySync") return callMember([json("ibex"), json("$ibex$invalid")]);
  if (memberName === "setModuleCapabilities") {
    // The production runtime strips this legacy bootstrap mutator after
    // initialization. Observe that exact loaded absence instead of calling a
    // source-only implementation that is no longer public.
    return getMember();
  }
  if (memberName === "unsafe.segfault") return callMember();
  return null;
}

function exactMemoryDebugRecipe(memberName) {
  const passiveArguments = {
    formatBytes: [json(1024)],
    samples: [],
    state: [],
    stop: [],
  };
  if (Object.hasOwn(passiveArguments, memberName)) {
    return callMember(passiveArguments[memberName]);
  }
  const options = json({
    includeExpensive: false,
    includeGCStats: false,
  });
  if (memberName === "snapshot" || memberName === "summary") {
    return callMember([options], authority(MEMORY_SYSTEM_INFO_AUTHORITY));
  }
  if (memberName === "start") {
    return callMember(
      [
        json({
          intervalMs: 60_000,
          maxSamples: 10,
          logEvery: 0,
          logOnGrowthBytes: Number.MAX_SAFE_INTEGER,
          includeExpensive: false,
          includeGCStats: false,
        }),
      ],
      {
        ...authority(MEMORY_SYSTEM_INFO_AUTHORITY),
        cleanup: { kind: "stop-memory-debug" },
      },
    );
  }
  if (memberName === "clearModuleDebugSources") {
    return callMember([], {
      cleanup: { kind: "restore-memory-debug-sources" },
    });
  }
  return null;
}

function exactBundleRecipe(globalName, memberName) {
  if (globalName === "ExactBundle") {
    if (new Set(["areGlobalsInstalled", "detectEngine", "detectPlatform", "getRuntimeVersion"]).has(memberName)) {
      return callMember();
    }
    if (memberName === "installGlobals") {
      return callMember();
    }
  }
  if (globalName === "exact" && new Set(["runtime.detectEngine", "runtime.detectPlatform", "runtime.isInstalled"]).has(memberName)) {
    return callMember();
  }
  return null;
}

function cryptoRecipe(globalName, memberName) {
  if (globalName === "Crypto" && memberName === null) return constructMember();
  if (globalName === "SubtleCrypto" && memberName === null) return constructMember();
  if (new Set(["Crypto", "crypto"]).has(globalName)) {
    if (memberName === "getRandomValues") return call(existing("crypto"), [uint8Array(0, 0, 0, 0)]);
    if (memberName === "randomUUID") return call(existing("crypto"));
  }
  if (new Set(["SubtleCrypto", "crypto"]).has(globalName) && (memberName === "digest" || memberName === "subtle.digest")) {
    return call(existing("crypto.subtle"), [json("SHA-256"), uint8Array(73, 98, 101, 120)]);
  }
  const subtleMember = globalName === "crypto" && memberName?.startsWith("subtle.")
    ? memberName.slice("subtle.".length)
    : globalName === "SubtleCrypto"
      ? memberName
      : null;
  const invalidAlgorithm = json({ name: "IBEX-CAPSEC-INVALID" });
  const subtleArguments = {
    decrypt: [invalidAlgorithm, json(null), uint8Array(0)],
    deriveBits: [invalidAlgorithm, json(null), json(8)],
    deriveKey: [invalidAlgorithm, json(null), invalidAlgorithm, json(false), json([])],
    encrypt: [invalidAlgorithm, json(null), uint8Array(0)],
    exportKey: [json("raw"), json(null)],
    generateKey: [invalidAlgorithm, json(false), json([])],
    importKey: [json("raw"), uint8Array(0), invalidAlgorithm, json(false), json([])],
    sign: [invalidAlgorithm, json(null), uint8Array(0)],
    unwrapKey: [
      json("raw"),
      uint8Array(0),
      json(null),
      invalidAlgorithm,
      invalidAlgorithm,
      json(false),
      json([]),
    ],
    verify: [invalidAlgorithm, json(null), uint8Array(0), uint8Array(0)],
    wrapKey: [json("raw"), json(null), json(null), invalidAlgorithm],
  };
  if (subtleMember && Object.hasOwn(subtleArguments, subtleMember)) {
    return call(existing("crypto.subtle"), subtleArguments[subtleMember], {
      suppressRejection: true,
    });
  }
  return null;
}

function streamRecipe(globalName, memberName) {
  if (globalName === "ReadableStream") {
    if (memberName === "from") return callMember([iterator("ibex")]);
    const receiver = (format = "text") => factory("readable-stream", { format });
    if (new Set(["arrayBuffer", "blob", "bytes", "text"]).has(memberName)) return call(receiver());
    if (memberName === "json") return call(receiver("json"));
    if (memberName === "cancel") return call(receiver("empty"), [json("ibex")]);
    if (memberName === "getReader") return call(receiver("empty"));
    if (memberName === "pipeThrough") return call(receiver(), [transformStream()]);
    if (memberName === "pipeTo") return call(receiver(), [writableStream()]);
    if (memberName === "_closeStream") return call(receiver("empty"));
    if (memberName === "_errorStream") return call(receiver("empty"), [json("ibex")]);
    if (new Set(["[[Symbol.asyncIterator]]", "tee", "values"]).has(memberName)) return call(receiver());
  }
  if (globalName === "TransformStream" && memberName === "_updateBackpressure") {
    return call(construct("TransformStream"), [json(false)]);
  }
  if (globalName === "ReadableStreamDefaultReader") {
    const receiver = factory("readable-default-reader", { closed: true });
    if (memberName === "cancel") return call(receiver, [json("ibex")]);
    if (memberName === "read" || memberName === "releaseLock" || memberName === "_initializeClosedPromise") return call(receiver);
    const pendingReceiver = factory("readable-default-reader", { closed: false });
    if (memberName === "_closedReject") return call(pendingReceiver, [json("ibex")]);
    if (memberName === "_closedResolve") return call(pendingReceiver);
  }
  if (globalName === "ReadableStreamBYOBReader") {
    const receiver = factory("readable-byob-reader", { closed: true });
    if (memberName === "cancel") return call(receiver, [json("ibex")]);
    if (memberName === "read") return call(receiver, [uint8Array(0, 0, 0, 0)]);
    if (memberName === "releaseLock" || memberName === "_initializeClosedPromise") return call(receiver);
    const pendingReceiver = factory("readable-byob-reader", { closed: false });
    if (memberName === "_closedReject") return call(pendingReceiver, [json("ibex")]);
    if (memberName === "_closedResolve") return call(pendingReceiver);
  }
  if (globalName === "ReadableStreamDefaultController") {
    const receiver = factory("readable-default-controller");
    if (memberName === "close") return call(receiver);
    if (memberName === "enqueue") return call(receiver, [json("ibex")]);
    if (memberName === "error") return call(receiver, [json("ibex")]);
    const internalArguments = {
      _cancelAlgorithm: [json("ibex")],
      _canCloseOrEnqueue: [],
      _dequeue: [],
      _error: [json("ibex")],
      _pullAlgorithm: [],
      _pullIfNeeded: [],
      _shouldPull: [],
      _strategySizeAlgorithm: [json("ibex")],
    };
    if (Object.hasOwn(internalArguments, memberName)) {
      return call(receiver, internalArguments[memberName], {
        suppressRejection: true,
      });
    }
  }
  if (globalName === "ReadableByteStreamController") {
    const receiver = factory("readable-byte-controller");
    if (memberName === "close") return call(receiver);
    if (memberName === "enqueue") return call(receiver, [uint8Array(1)]);
    if (memberName === "error") return call(receiver, [json("ibex")]);
    const internalArguments = {
      _cancelAlgorithm: [json("ibex")],
      _pullAlgorithm: [],
    };
    if (Object.hasOwn(internalArguments, memberName)) {
      return call(receiver, internalArguments[memberName], {
        suppressRejection: true,
      });
    }
  }
  if (globalName === "WritableStream") {
    const receiver = factory("writable-stream");
    if (memberName === "abort") return call(receiver, [json("ibex")]);
    if (memberName === "close" || memberName === "getWriter") return call(receiver);
    const internalArguments = {
      _abortAlgorithm: [json("ibex")],
      _abortStream: [json("ibex")],
      _advanceQueueIfNeeded: [],
      _closeAlgorithm: [],
      _closeStream: [],
      _dealWithRejection: [json("ibex")],
      _errorIfNeeded: [json("ibex")],
      _errorStream: [json("ibex")],
      _finishClose: [],
      _finishErroring: [],
      _hasOperationInFlight: [],
      _notifyWriterError: [json("ibex")],
      _rejectClosedPromiseIfNeeded: [],
      _startErroring: [json("ibex")],
      _strategySizeAlgorithm: [json("ibex")],
      _updateBackpressure: [],
      _writeAlgorithm: [json("ibex"), json(null)],
      _writeChunk: [json("ibex")],
    };
    if (Object.hasOwn(internalArguments, memberName)) {
      return call(receiver, internalArguments[memberName], {
        suppressRejection: true,
      });
    }
  }
  if (globalName === "WritableStreamDefaultWriter") {
    const receiver = factory("writable-writer");
    if (memberName === "abort") return call(receiver, [json("ibex")]);
    if (memberName === "write") return call(receiver, [json("ibex")]);
    if (memberName === "close" || memberName === "releaseLock") return call(receiver);
    if (memberName === "_setClosedPromiseRecord" || memberName === "_setReadyPromiseRecord") {
      return call(receiver, [resolvedPromiseRecord()]);
    }
    if (memberName === "_closedReject" || memberName === "_readyReject" ||
        memberName === "_ensureClosedPromiseRejected" ||
        memberName === "_ensureReadyPromiseRejected") {
      return call(receiver, [json("ibex")]);
    }
    if (memberName === "_closedResolve" || memberName === "_readyResolve") {
      return call(receiver);
    }
  }
  if (globalName === "WritableStreamDefaultController" && memberName === "error") {
    return call(factory("writable-controller"), [json("ibex")]);
  }
  if (globalName === "TransformStreamDefaultController") {
    const receiver = factory("transform-controller");
    if (memberName === "enqueue") return call(receiver, [json("ibex")]);
    if (memberName === "_flushAlgorithm") {
      return call(receiver, [], { suppressRejection: true });
    }
    if (memberName === "_transformAlgorithm") {
      return call(receiver, [json("ibex")], { suppressRejection: true });
    }
  }
  if (globalName === "TransformStream" && memberName === "_backpressureResolve") {
    return call(factory("transform-stream-backpressure"));
  }
  return null;
}

function miscRecipe(globalName, memberName) {
  if (globalName === "ArrayBuffer" && memberName === null) return constructMember([json(8)]);
  if (globalName === "SharedArrayBuffer" && memberName === null) return constructMember([json(8)]);
  if (globalName === "SharedArrayBuffer" && memberName === "slice") return call(construct("SharedArrayBuffer", json(8)), [json(0), json(4)]);
  if (globalName === "DataView" && memberName === null) return constructMember([arrayBuffer(8)]);
  if (globalName === "DOMException" && memberName === "toString") return call(construct("DOMException", json("ibex"), json("Error")));
  if (globalName === "URLPattern") {
    const receiver = construct("URLPattern", json("https://example.invalid/:path"));
    if (memberName === "exec" || memberName === "test") return call(receiver, [json("https://example.invalid/ibex")]);
  }
  if (globalName === "ClipboardItem" && memberName === "getType") {
    return call(factory("clipboard-item"), [json("text/plain")]);
  }
  if (globalName === "indexedDB" && memberName === "cmp") return call(existing("indexedDB"), [json(1), json(2)]);
  if (globalName === "process" && memberName === "hrtime") return call(existing("process"));
  if (globalName === "process" && memberName === "nextTick") return call(existing("process"), [noop()]);
  if (globalName === "addEventListener" && memberName === null) {
    return call(existing("globalThis"), [json("ibex-capsec-global"), noop()], {
      cleanup: { kind: "remove-global-event-listener", type: "ibex-capsec-global", listenerArgument: 1 },
    });
  }
  if (globalName === "removeEventListener" && memberName === null) {
    return call(existing("globalThis"), [json("ibex-capsec-global"), noop()]);
  }
  if (globalName === "clearImmediate" && memberName === null) {
    return call(existing("globalThis"), [json(0)]);
  }
  if (globalName === "setImmediate" && memberName === null) return call(existing("globalThis"), [noop()]);
  if (globalName === "structuredClone" && memberName === null) return call(existing("globalThis"), [json({ ibex: true })]);
  if (globalName === "__exactIsReadableStream" && memberName === null) return call(existing("globalThis"), [readableStream()]);
  if (globalName === "__exactWindowNotifyResize" && memberName === null) {
    return call(existing("globalThis"));
  }
  if (globalName === "__exactAndroidDispatchPlatformEvent" && memberName === null) {
    return call(existing("globalThis"), [json({ type: "ibex-capsec" }), json(null)]);
  }
  if (globalName === "__exactAccessibilityChanged" && memberName === null) {
    return call(existing("globalThis"), [existing("__exactAccessibilitySnapshot")]);
  }
  if (globalName === "__exactLocaleChanged" && memberName === null) {
    return call(existing("globalThis"), [existing("__exactLocaleSnapshot")]);
  }
  if (globalName === "__exactWindowNotifyMediaChange" && memberName === null) {
    return call(existing("globalThis"), [existing("__exactAccessibilitySnapshot")]);
  }
  if (globalName === "__exactEnsureFilesystemModule" && memberName === null) {
    return call(existing("globalThis"));
  }
  if (globalName === "Response" &&
      new Set(["fromNative", "fromNativeStreaming"]).has(memberName)) {
    return callMember([json(null)]);
  }
  return null;
}

const ISOLATED_PROTOTYPE_GLOBALS = new Set([
  "EventSource",
  "IDBCursor",
  "IDBCursorWithValue",
  "IDBDatabase",
  "IDBIndex",
  "IDBObjectStore",
  "IDBOpenDBRequest",
  "IDBRequest",
  "IDBTransaction",
  "MessagePort",
  "ReadableByteStreamController",
  "ReadableStream",
  "ReadableStreamBYOBReader",
  "ReadableStreamBYOBRequest",
  "ReadableStreamDefaultController",
  "ReadableStreamDefaultReader",
  "TransformStream",
  "TransformStreamDefaultController",
  "WebSocket",
  "WebSocketStream",
  "caches",
  "indexedDB",
]);

function isolatedPrototypeRecipe(globalName, memberName) {
  if (new Set(["localStorage", "sessionStorage"]).has(globalName) && memberName !== null) {
    return call(
      factory("storage-prototype"),
      [],
      { suppressRejection: true },
    );
  }
  if (memberName === null || !ISOLATED_PROTOTYPE_GLOBALS.has(globalName)) return null;
  return call(
    factory("isolated-prototype", { globalName }),
    [],
    { suppressRejection: true },
  );
}

function boundedFormerlyUnsafeRecipe(globalName, memberName) {
  if (globalName === "CryptoKey" && memberName === null) {
    return constructMember([
      json("secret"),
      json(false),
      json({ name: "HMAC", hash: { name: "SHA-256" }, length: 8 }),
      json([]),
      uint8Array(0),
    ]);
  }
  if (globalName === "VideoFrame" && memberName !== null) {
    return call(
      construct(
        "VideoFrame",
        uint8Array(0),
        json({ format: "RGBA", timestamp: 0, codedWidth: 1, codedHeight: 1 }),
      ),
    );
  }
  if (globalName === "WebSocketError" && memberName === "toString") {
    return call(construct("WebSocketError", json("ibex-capsec")));
  }
  return isolatedPrototypeRecipe(globalName, memberName);
}

function recipeFor(metadata) {
  const { globalName, memberName = null } = metadata;

  return (
    bufferRecipe(globalName === "Buffer" ? memberName : "__not-buffer") ??
    eventRecipe(globalName, memberName) ??
    typedArrayRecipe(globalName, memberName) ??
    (globalName === "Iterator" ? iteratorRecipe(memberName) : null) ??
    (globalName === "Headers" ? headersRecipe(memberName) : null) ??
    (globalName === "FormData" ? formDataRecipe(memberName) : null) ??
    (globalName === "URLSearchParams" ? urlSearchParamsRecipe(memberName) : null) ??
    blobRecipe(globalName, memberName) ??
    (globalName === "URL" ? urlRecipe(memberName) : null) ??
    requestResponseRecipe(globalName, memberName) ??
    textCodecRecipe(globalName, memberName) ??
    (globalName === "Atomics" ? atomicsRecipe(memberName) : null) ??
    abortRecipe(globalName, memberName) ??
    eventTargetRecipe(globalName, memberName) ??
    (globalName === "process" ? processRecipe(memberName) : null) ??
    messagingRecipe(globalName, memberName) ??
    (globalName === "IDBKeyRange" ? idbKeyRangeRecipe(memberName) : null) ??
    (new Set(["Promise", "__OriginalPromise"]).has(globalName)
      ? promiseRecipe(globalName, memberName)
      : null) ??
    (globalName === "Intl" ? intlRecipe(memberName) : null) ??
    (globalName === "performance" ? performanceRecipe(memberName) : null) ??
    performanceEntryRecipe(globalName, memberName) ??
    (globalName === "PerformanceObserver" ? performanceObserverRecipe(memberName) : null) ??
    (globalName === "__exactMemoryDebug" ? exactMemoryDebugRecipe(memberName) : null) ??
    exactRecipe(globalName, memberName) ??
    exactBundleRecipe(globalName, memberName) ??
    cryptoRecipe(globalName, memberName) ??
    streamRecipe(globalName, memberName) ??
    miscRecipe(globalName, memberName) ??
    boundedFormerlyUnsafeRecipe(globalName, memberName)
  );
}

function classificationRecipe(coverageEdge, metadata) {
  const recipe = recipeFor(metadata);
  if (recipe) return recipe;
  if (coverageEdge.classification === "effects") {
    return unsupported(
      "capability-requiring-call",
      `coverage edge ${coverageEdge.id} is effect-classified; the output sweep grants no authority`,
    );
  }
  if (coverageEdge.classification === "closed") {
    return unsupported(
      "closed-call",
      `coverage edge ${coverageEdge.id} is closed on the selected target`,
    );
  }
  if (coverageEdge.classification !== "non-capability") {
    return unsupported(
      "unsupported-coverage-classification",
      `coverage edge ${coverageEdge.id} has unsupported classification ${JSON.stringify(coverageEdge.classification)}`,
    );
  }
  const { globalName, memberName = null } = metadata;
  return unsupported(
    "no-deterministic-in-memory-invocation",
    `${globalName}${memberName === null ? "" : `.${memberName}`} has no authored deterministic in-memory call recipe`,
  );
}

export function authoredGlobalCallableOutputInvocation({
  surface,
  coverageEdge,
}) {
  const metadata = surface?.metadata;
  if (
    !coverageEdge ||
    surface?.kind !== "native-op" ||
    surface.observedKey !== `native-op:${surface.name}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.valueShape !== "callable" ||
    typeof metadata.globalName !== "string" ||
    metadata.globalName.length === 0 ||
    (metadata.memberName !== null &&
      metadata.memberName !== undefined &&
      (typeof metadata.memberName !== "string" || metadata.memberName.length === 0)) ||
    !Array.isArray(metadata.memberKinds) ||
    !metadata.memberKinds.every(
      (kind) => typeof kind === "string" && kind.length > 0,
    ) ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length === 0 ||
    !surface.sourceRefs.every(
      (sourceRef) => typeof sourceRef === "string" && sourceRef.length > 0,
    )
  ) {
    return null;
  }

  const sourceDescriptor = {
    kind: "global-api-callable",
    globalName: metadata.globalName,
    memberName: metadata.memberName ?? null,
    memberKinds: [...metadata.memberKinds],
    sourceRefs: [...surface.sourceRefs],
  };
  return {
    invocationSchema: INVOCATION_SCHEMA,
    kind: "global-callable-invocation",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    route: classificationRecipe(coverageEdge, metadata),
    completion: { ...COMPLETION },
  };
}

export const globalCallableFactoryRecipeIds = Object.freeze([
  "abort-signal",
  "blob-like",
  "body-message",
  "broadcast-channel",
  "buffer",
  "clipboard-item",
  "event-instance",
  "exact-crypto-hasher",
  "form-data",
  "headers",
  "idb-key-range",
  "isolated-prototype",
  "iterator-helper",
  "media-query-list",
  "message-port",
  "performance-mark",
  "performance-measure",
  "performance-observer",
  "readable-byob-reader",
  "readable-byte-controller",
  "readable-default-controller",
  "readable-default-reader",
  "readable-stream",
  "resolved-promise",
  "storage-prototype",
  "transform-controller",
  "transform-stream-backpressure",
  "typed-array",
  "url",
  "url-search-params",
  "writable-controller",
  "writable-stream",
  "writable-writer",
]);
