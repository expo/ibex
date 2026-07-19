/**
 * Source-bound, expectation-free recipes for reading global accessors.
 *
 * The output sweep may execute only an actual JavaScript Get. Receiver setup
 * is restricted to deterministic in-memory objects. Effect-classified Gets
 * retain exact typed authority when required; receiver-unsafe members remain
 * explicit unexercisable routes. Closed rows use the loaded descriptor/read
 * route so target absence is observed without inventing a receiver.
 *
 * @ref LLP 0023#6-path-bearing-observables — output evidence must retain the
 * loaded operation's raw return/throw outcome without consulting disposition
 * policy.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const INVOCATION_SCHEMA = "ibex/capsec-global-accessor-get-invocation/1";
const COMPLETION = Object.freeze({
  kind: "event-loop-quiescence",
  timeoutMilliseconds: 1_000,
});

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const construct = (...arguments_) =>
  Object.freeze({ kind: "construct-global", arguments: arguments_ });
const factory = (factoryId) => Object.freeze({ kind: "factory", factoryId });
const existing = (receiverGlobalName) =>
  Object.freeze({ kind: "existing-global", receiverGlobalName });
const globalPrototype = () => Object.freeze({ kind: "global-prototype" });
const typedEffectAuthority = (cap, resourceKind, requested) =>
  Object.freeze({ kind: "typed-effect", cap, resourceKind, requested });

const ENV_WPT_SERVER_URL_AUTHORITY = Object.freeze([
  typedEffectAuthority(
    "env:read",
    "environment-occurrence",
    Object.freeze({
      kind: "environment-name",
      target: "broker-base",
      name: "WPT_SERVER_URL",
    }),
  ),
]);

const LIFECYCLE_EXIT_CODE_GET_AUTHORITY = Object.freeze([
  typedEffectAuthority(
    "lifecycle:exit",
    "lifecycle-occurrence",
    Object.freeze({
      kind: "session-lifecycle",
      operation: "exit-code-get",
    }),
  ),
]);

// Every constructor below is deterministic and in-memory. JSON-only argument
// shapes keep the plan data-only and prevent it from smuggling source text.
const CONSTRUCTED_RECEIVERS = Object.freeze({
  AbortController: construct(),
  Blob: construct(["ibex"], { type: "text/plain" }),
  ByteLengthQueuingStrategy: construct({ highWaterMark: 1 }),
  CloseEvent: construct("close"),
  CompressionStream: construct("gzip"),
  CountQueuingStrategy: construct({ highWaterMark: 1 }),
  CustomEvent: construct("ibex"),
  DecompressionStream: construct("gzip"),
  ErrorEvent: construct("error"),
  Event: construct("ibex"),
  File: construct(["ibex"], "fixture.txt", {
    lastModified: 0,
    type: "text/plain",
  }),
  FileReader: construct(),
  Float16Array: construct(0),
  FocusEvent: construct("focus"),
  FormData: construct(),
  Headers: construct(),
  IDBOpenDBRequest: construct(),
  IDBRequest: construct(),
  KeyboardEvent: construct("keydown"),
  MediaQueryListEvent: construct("change", {
    matches: true,
    media: "(min-width: 0px)",
  }),
  MessageEvent: construct("message"),
  ProgressEvent: construct("progress"),
  ReadableStream: construct(),
  Request: construct("https://example.invalid/ibex"),
  Response: construct("ibex"),
  SharedArrayBuffer: construct(0),
  TextDecoderStream: construct(),
  TextEncoderStream: construct(),
  TransformStream: construct(),
  URL: construct("https://user:pass@example.invalid:8443/path?query#hash"),
  URLPattern: construct("https://example.invalid/:path"),
  URLSearchParams: construct("a=1"),
  WritableStream: construct(),
});

// These globals are already the correctly branded receiver. In particular,
// Crypto.prototype.subtle must be read with the installed `crypto` object.
const EXISTING_RECEIVERS = Object.freeze({
  Crypto: existing("crypto"),
  caches: existing("caches"),
  crypto: existing("crypto"),
  localStorage: existing("localStorage"),
  performance: existing("performance"),
  process: existing("process"),
  sessionStorage: existing("sessionStorage"),
});

const FACTORY_RECEIVERS = Object.freeze({
  AbortSignal: factory("abort-signal"),
  Buffer: factory("buffer"),
  ClipboardItem: factory("clipboard-item"),
  EventSource: factory("inert-event-source"),
  MediaQueryList: factory("media-query-list"),
  "Intl.Locale": factory("intl-locale"),
  PromiseRejectionEvent: factory("promise-rejection-event"),
  ReadableStreamBYOBRequest: factory("readable-byob-request"),
  ReadableByteStreamController: factory("readable-byte-controller"),
  ReadableStreamBYOBReader: factory("readable-byob-reader"),
  ReadableStreamDefaultController: factory("readable-default-controller"),
  ReadableStreamDefaultReader: factory("readable-default-reader"),
  TransformStreamDefaultController: factory("transform-controller"),
  WritableStreamDefaultController: factory("writable-controller"),
  WritableStreamDefaultWriter: factory("writable-writer"),
  WebSocketStream: factory("aborted-websocket-stream"),
});

const UNSAFE_RECEIVERS = Object.freeze({
  CryptoKey: [
    "async-key-material-receiver-required",
    "CryptoKey has no deterministic synchronous public constructor",
  ],
  EventSource: [
    "external-network-receiver-required",
    "EventSource construction would initiate an external network operation",
  ],
  ReadableStreamBYOBRequest: [
    "async-byob-receiver-required",
    "ReadableStreamBYOBRequest exists only during an asynchronous BYOB pull",
  ],
  VideoFrame: [
    "native-resource-receiver-required",
    "VideoFrame construction would retain a native resource requiring lifecycle evidence",
  ],
  WebSocket: [
    "external-network-receiver-required",
    "WebSocket construction would initiate an external network operation",
  ],
  WebSocketError: [
    "no-deterministic-public-receiver",
    "WebSocketError has no source-proven deterministic public receiver recipe",
  ],
  WebSocketStream: [
    "external-network-receiver-required",
    "WebSocketStream construction would initiate an external network operation",
  ],
});

function unexercisable(reasonCode, reason) {
  return { kind: "unexercisable", reasonCode, reason };
}

function receiverFor(metadata, coverageEdge) {
  if (
    !new Set(["non-capability", "effects", "closed"]).has(
      coverageEdge.classification,
    )
  ) {
    return unexercisable(
      "unsupported-coverage-classification",
      `coverage edge ${coverageEdge.id} has unsupported classification ${JSON.stringify(coverageEdge.classification)}`,
    );
  }

  if (metadata.memberName === null) {
    return { kind: "global-root" };
  }
  const prototypeMember = metadata.memberKinds.some((kind) =>
    kind.includes("prototype-accessor"),
  );
  const intlLocaleMember =
    metadata.globalName === "Intl" &&
    typeof metadata.memberName === "string" &&
    metadata.memberName.startsWith("Locale.");
  if (!prototypeMember && !intlLocaleMember) {
    return existing(metadata.globalName);
  }
  const nestedReceiverKey =
    intlLocaleMember ? "Intl.Locale" : metadata.globalName;
  const receiver =
    EXISTING_RECEIVERS[metadata.globalName] ??
    CONSTRUCTED_RECEIVERS[nestedReceiverKey] ??
    FACTORY_RECEIVERS[nestedReceiverKey];
  if (receiver) return structuredClone(receiver);
  const unsafe = UNSAFE_RECEIVERS[metadata.globalName];
  if (
    unsafe &&
    metadata.memberName === "[[Symbol.toStringTag]]"
  ) {
    return globalPrototype();
  }
  if (unsafe) return unexercisable(unsafe[0], unsafe[1]);
  return unexercisable(
    "no-deterministic-public-receiver",
    `${metadata.globalName}.${metadata.memberName} has no source-proven deterministic public receiver recipe`,
  );
}

function authorityFor(metadata, receiver) {
  // Constructing the runtime's branded Request receiver consults this exact
  // compatibility environment occurrence before the accessor Get. Retaining
  // that setup decision is part of the live observation; it must not be
  // hidden by constructing a lookalike receiver.
  if (
    metadata.globalName === "Request" &&
    receiver.kind === "construct-global"
  ) {
    return [...ENV_WPT_SERVER_URL_AUTHORITY];
  }
  if (
    metadata.globalName === "process" &&
    metadata.memberName === "exitCode" &&
    receiver.kind === "existing-global"
  ) {
    return [...LIFECYCLE_EXIT_CODE_GET_AUTHORITY];
  }
  return [];
}

export function authoredGlobalAccessorOutputInvocation({
  surface,
  coverageEdge,
}) {
  const metadata = surface?.metadata;
  if (
    !coverageEdge ||
    surface?.kind !== "native-op" ||
    surface.observedKey !== `native-op:${surface.name}` ||
    metadata?.surfaceType !== "global-api" ||
    metadata.valueShape !== "accessor" ||
    typeof metadata.globalName !== "string" ||
    metadata.globalName.length === 0 ||
    (metadata.memberName !== null &&
      metadata.memberName !== undefined &&
      (typeof metadata.memberName !== "string" ||
        metadata.memberName.length === 0)) ||
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
    kind: "global-api-accessor",
    globalName: metadata.globalName,
    memberName: metadata.memberName ?? null,
    memberKinds: [...metadata.memberKinds],
    sourceRefs: [...surface.sourceRefs],
  };
  const receiver = receiverFor(metadata, coverageEdge);
  const authority = authorityFor(metadata, receiver);
  return {
    invocationSchema: INVOCATION_SCHEMA,
    kind: "global-accessor-get",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    receiver,
    ...(authority.length > 0 ? { authority } : {}),
    completion: { ...COMPLETION },
  };
}

export const globalAccessorReceiverRecipeIds = Object.freeze([
  ...new Set(
    Object.values(FACTORY_RECEIVERS).map((receiver) => receiver.factoryId),
  ),
].sort());
