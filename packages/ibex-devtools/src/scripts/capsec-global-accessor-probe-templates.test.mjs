import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  authoredGlobalAccessorOutputInvocation,
  globalAccessorReceiverRecipeIds,
} from "./capsec-global-accessor-probe-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const harnessSource = fs.readFileSync(
  path.join(
    repoRoot,
    "src/bin/ibex/engine/capsec_global_accessor_get.js",
  ),
  "utf8",
);
const execute = new Function(
  "config",
  `return (${harnessSource.trim()})(config);`,
);

function surface(globalName, memberName, memberKinds = ["prototype-accessor"]) {
  const name = `global:${globalName}${memberName === null ? "" : `.${memberName}`}`;
  return {
    kind: "native-op",
    name,
    observedKey: `native-op:${name}`,
    sourceRefs: [`src/test.js#${globalName}`],
    metadata: {
      surfaceType: "global-api",
      valueShape: "accessor",
      globalName,
      memberName,
      memberKinds,
    },
  };
}

function invocation(globalName, memberName, options = {}) {
  return authoredGlobalAccessorOutputInvocation({
    surface: surface(globalName, memberName, options.memberKinds),
    coverageEdge: {
      id: options.id ?? "surface.native.global.test.0000001",
      classification: options.classification ?? "non-capability",
    },
  });
}

describe("source-bound global accessor Get recipes", () => {
  test("retains an actual primitive Get from a constructed receiver", () => {
    const recipe = invocation("URL", "href");
    expect(recipe.receiver).toEqual({
      kind: "construct-global",
      arguments: [
        "https://user:pass@example.invalid:8443/path?query#hash",
      ],
    });
    const result = execute(recipe);
    expect(result).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      descriptorProof: {
        presence: "inherited",
        descriptorKind: "accessor",
      },
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value:
          "https://user:pass@example.invalid:8443/path?query#hash",
        errorCode: null,
      },
    });
  });

  test("performs a root lazy-global Get rather than accepting its descriptor", () => {
    const recipe = invocation("AbortController", null, {
      memberKinds: ["define-property"],
    });
    expect(recipe.receiver).toEqual({ kind: "global-root" });
    expect(execute(recipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "function",
        value: null,
      },
    });
  });

  test("authors effect receivers but keeps unsafe receivers non-executable", () => {
    expect(
      invocation("Exact", "locale.tag", {
        classification: "effects",
        memberKinds: ["object-accessor"],
      }).receiver,
    ).toEqual({ kind: "existing-global", receiverGlobalName: "Exact" });
    expect(invocation("WebSocket", "[[Symbol.toStringTag]]").receiver)
      .toEqual({ kind: "global-prototype" });
    expect(invocation("EventSource", "readyState").receiver).toEqual({
      kind: "factory",
      factoryId: "inert-event-source",
    });
  });

  test("authors deterministic nested, event, stream, and BYOB receivers", () => {
    expect(
      invocation("Intl", "Locale.baseName", {
        classification: "effects",
      }).receiver,
    ).toEqual({ kind: "factory", factoryId: "intl-locale" });
    expect(invocation("MediaQueryListEvent", "currentTarget").receiver)
      .toEqual({
        kind: "construct-global",
        arguments: [
          "change",
          { matches: true, media: "(min-width: 0px)" },
        ],
      });
    expect(invocation("ReadableStreamBYOBRequest", "view").receiver)
      .toEqual({ kind: "factory", factoryId: "readable-byob-request" });
    expect(invocation("IDBRequest", "readyState").receiver).toEqual({
      kind: "construct-global",
      arguments: [],
    });
    expect(invocation("WebSocketStream", "url").receiver).toEqual({
      kind: "factory",
      factoryId: "aborted-websocket-stream",
    });
  });

  test("retains Request receiver setup's exact typed environment effect", () => {
    expect(invocation("Request", "url")).toMatchObject({
      receiver: {
        kind: "construct-global",
        arguments: ["https://example.invalid/ibex"],
      },
      authority: [
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
      ],
    });
    expect(invocation("URL", "href").authority).toBeUndefined();
  });

  test("authors the exact lifecycle authority observed by process.exitCode Get", () => {
    expect(invocation("process", "exitCode")).toMatchObject({
      receiver: {
        kind: "existing-global",
        receiverGlobalName: "process",
      },
      authority: [
        {
          kind: "typed-effect",
          cap: "lifecycle:exit",
          resourceKind: "lifecycle-occurrence",
          requested: {
            kind: "session-lifecycle",
            operation: "exit-code-get",
          },
        },
      ],
    });
  });

  test("retains the actual thrown error name from a source accessor Get", () => {
    class PendingRequest {
      get result() {
        const error = new Error("pending");
        error.name = "InvalidStateError";
        throw error;
      }
    }
    const original = globalThis.PendingRequest;
    globalThis.PendingRequest = PendingRequest;
    try {
      const config = invocation("PendingRequest", "result");
      config.receiver = { kind: "construct-global", arguments: [] };
      expect(execute(config)).toMatchObject({
        kind: "throw",
        sourceOperationAttempted: true,
        rawOutput: {
          kind: "throw",
          rawValueShape: "throw",
          value: null,
          errorCode: null,
          errorName: "InvalidStateError",
        },
      });
    } finally {
      if (original === undefined) delete globalThis.PendingRequest;
      else globalThis.PendingRequest = original;
    }
  });

  test("reads nested Intl.Locale accessors from a real locale instance", () => {
    const result = execute(
      invocation("Intl", "Locale.baseName", {
        classification: "effects",
      }),
    );
    expect(result).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value: "en-US",
        errorCode: null,
      },
    });
  });

  test("publishes a closed set of data-only receiver factories", () => {
    expect(globalAccessorReceiverRecipeIds).toEqual([
      "abort-signal",
      "aborted-websocket-stream",
      "buffer",
      "clipboard-item",
      "inert-event-source",
      "intl-locale",
      "media-query-list",
      "promise-rejection-event",
      "readable-byob-reader",
      "readable-byob-request",
      "readable-byte-controller",
      "readable-default-controller",
      "readable-default-reader",
      "transform-controller",
      "writable-controller",
      "writable-writer",
    ]);
  });
});
