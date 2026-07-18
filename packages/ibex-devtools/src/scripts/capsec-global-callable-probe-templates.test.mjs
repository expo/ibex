import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  authoredGlobalCallableOutputInvocation,
  globalCallableFactoryRecipeIds,
} from "./capsec-global-callable-probe-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const harnessSource = fs.readFileSync(
  path.join(
    repoRoot,
    "src/bin/ibex/engine/capsec_global_callable_invocation.js",
  ),
  "utf8",
);
const execute = new Function(
  "config",
  `return (${harnessSource.trim()})(config);`,
);

function surface(globalName, memberName, memberKinds = ["prototype-method"]) {
  const name = `global:${globalName}${memberName === null ? "" : `.${memberName}`}`;
  return {
    kind: "native-op",
    name,
    observedKey: `native-op:${name}`,
    sourceRefs: [`src/test.js#${globalName}`],
    metadata: {
      surfaceType: "global-api",
      valueShape: "callable",
      globalName,
      memberName,
      memberKinds,
    },
  };
}

function invocation(globalName, memberName, options = {}) {
  return authoredGlobalCallableOutputInvocation({
    surface: surface(globalName, memberName, options.memberKinds),
    coverageEdge: {
      id: options.id ?? "surface.native.global.test.0000001",
      classification: options.classification ?? "non-capability",
    },
  });
}

describe("source-bound global callable recipes", () => {
  test("calls the exact loaded Buffer prototype method and retains its return", () => {
    const recipe = invocation("Buffer", "readUInt8");
    expect(recipe.route).toMatchObject({
      operation: "call",
      receiver: { kind: "factory", factoryId: "buffer" },
      arguments: [{ kind: "json", value: 0 }],
    });
    expect(execute(recipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      descriptorProof: {
        presence: "inherited",
        descriptorKind: "data",
        valueType: "function",
      },
      cleanupPerformed: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "number",
        value: 0,
        errorCode: null,
      },
    });
  });

  test("constructs a root callable rather than accepting function presence", () => {
    const recipe = invocation("ArrayBuffer", null, {
      memberKinds: ["assignment"],
    });
    expect(recipe.route).toMatchObject({
      operation: "construct",
      arguments: [{ kind: "json", value: 8 }],
    });
    expect(execute(recipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "object",
      },
    });
  });

  test("materializes descriptor-shaped constructor arguments for source-bound receivers", () => {
    const recipe = invocation("DOMException", "toString");
    expect(recipe.route.receiver).toEqual({
      kind: "construct-global",
      globalName: "DOMException",
      arguments: [
        { kind: "json", value: "ibex" },
        { kind: "json", value: "Error" },
      ],
    });
    expect(execute(recipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value: "Error: ibex",
      },
    });
  });

  test("rejects malformed receiver argument schemas before invoking the source", () => {
    const recipe = invocation("DOMException", "toString");
    const extraKey = {
      ...recipe,
      route: {
        ...recipe.route,
        receiver: {
          ...recipe.route.receiver,
          arguments: [
            { kind: "json", value: "ibex", unexpected: true },
            { kind: "json", value: "Error" },
          ],
        },
      },
    };
    const rawArgument = {
      ...recipe,
      route: {
        ...recipe.route,
        receiver: {
          ...recipe.route.receiver,
          arguments: ["ibex", { kind: "json", value: "Error" }],
        },
      },
    };
    for (const malformed of [extraKey, rawArgument]) {
      expect(execute(malformed)).toMatchObject({
        kind: "throw",
        sourceOperationAttempted: false,
        rawOutput: {
          kind: "throw",
          errorCode: null,
          errorName: "TypeError",
        },
      });
    }
  });

  test("calls a deterministic collection receiver with source-bound arguments", () => {
    const recipe = invocation("Headers", "get");
    expect(execute(recipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value: "1",
      },
    });
    for (const memberName of [
      "forEach",
      "[[Symbol.for:nodejs.util.inspect.custom]]",
      "toJSON",
    ]) {
      expect(invocation("Headers", memberName).route.authority).toBeUndefined();
    }
    expect(invocation("Response", "clone").route.authority).toBeUndefined();
  });

  test("constructs body-message receivers before invoking their source method", () => {
    const constructorRecipe = invocation("Request");
    expect(constructorRecipe.route).toMatchObject({
      operation: "construct",
      receiver: { kind: "source-member-owner" },
      arguments: [{
        kind: "factory",
        factoryId: "body-message",
        options: { globalName: "Request", format: "text" },
      }],
      authority: [{
        kind: "typed-effect",
        cap: "env:read",
        resourceKind: "environment-occurrence",
        requested: {
          kind: "environment-name",
          target: "broker-base",
          name: "WPT_SERVER_URL",
        },
      }],
    });
    expect(execute(constructorRecipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "object",
      },
    });

    const recipe = invocation("Request", "clone");
    expect(recipe.route.receiver).toMatchObject({
      kind: "factory",
      factoryId: "body-message",
      options: { globalName: "Request", format: "text" },
    });
    expect(execute(recipe)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "object",
      },
    });
  });

  test("isolates external receivers while allowing bounded effect fixtures", () => {
    expect(
      invocation("WebSocket", "close").route,
    ).toMatchObject({
      operation: "call",
      receiver: {
        kind: "factory",
        factoryId: "isolated-prototype",
        options: { globalName: "WebSocket" },
      },
    });
    expect(
      invocation("Headers", "get", { classification: "effects" }).route,
    ).toMatchObject({
      operation: "call",
      receiver: { kind: "factory", factoryId: "headers" },
    });
  });

  test("authors bounded effects and closed calls when a live fixture exists", () => {
    const locale = invocation("Intl", "Locale.toString", {
      classification: "effects",
    });
    expect(locale.route).toMatchObject({
      operation: "call",
      receiver: {
        kind: "construct-global",
        globalName: "Intl.Locale",
      },
    });
    expect(execute(locale)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: { kind: "return", value: "en-US" },
    });

    const processEvents = invocation("process", "eventNames", {
      classification: "closed",
    });
    expect(processEvents.route.operation).toBe("call");
    expect(execute(processEvents)).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: { kind: "return", rawValueShape: "array" },
    });

    expect(
      invocation("process", "exit", { classification: "effects" }).route,
    ).toMatchObject({
      operation: "call",
      receiver: { kind: "existing-global", globalName: "process" },
      arguments: [{ kind: "throwing-number-coercion" }],
    });
  });

  test("authors every isolated WritableStream internal against a complete inert sink", () => {
    const methodArguments = {
      _abortAlgorithm: 1,
      _abortStream: 1,
      _advanceQueueIfNeeded: 0,
      _closeAlgorithm: 0,
      _closeStream: 0,
      _dealWithRejection: 1,
      _errorIfNeeded: 1,
      _errorStream: 1,
      _finishClose: 0,
      _finishErroring: 0,
      _hasOperationInFlight: 0,
      _notifyWriterError: 1,
      _rejectClosedPromiseIfNeeded: 0,
      _startErroring: 1,
      _strategySizeAlgorithm: 1,
      _updateBackpressure: 0,
      _writeAlgorithm: 2,
      _writeChunk: 1,
    };
    for (const [memberName, argumentCount] of Object.entries(methodArguments)) {
      expect(invocation("WritableStream", memberName).route).toMatchObject({
        operation: "call",
        receiver: { kind: "factory", factoryId: "writable-stream" },
        arguments: { length: argumentCount },
        suppressRejection: true,
      });
    }
  });

  test("keeps closed diagnostics bounded and grants only their exact memory read", () => {
    expect(invocation("__exactMemoryDebug", "formatBytes", {
      classification: "closed",
    }).route).toMatchObject({
      operation: "call",
      arguments: [{ kind: "json", value: 1024 }],
    });
    for (const memberName of ["snapshot", "summary", "start"]) {
      expect(invocation("__exactMemoryDebug", memberName, {
        classification: "closed",
      }).route).toMatchObject({
        operation: "call",
        authority: [{
          kind: "typed-effect",
          cap: "sys:read",
          resourceKind: "system-info-occurrence",
          requested: { kind: "system-info", name: "memory" },
        }],
      });
    }
    expect(invocation("__exactMemoryDebug", "start", {
      classification: "closed",
    }).route.cleanup).toEqual({ kind: "stop-memory-debug" });
    expect(invocation("__exactMemoryDebug", "clearModuleDebugSources", {
      classification: "closed",
    }).route).toMatchObject({
      operation: "call",
      cleanup: { kind: "restore-memory-debug-sources" },
    });
  });

  test("restores debug sources after observing the exact clear operation", () => {
    const debugObjectDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "__exactMemoryDebug",
    );
    const debugSourcesDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "__exactDebugModuleSources",
    );
    const debugSourceDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "__exactDebugModuleSource",
    );
    try {
      globalThis.__exactDebugModuleSources = ["alpha", "beta"];
      globalThis.__exactDebugModuleSource = "beta";
      globalThis.__exactMemoryDebug = {
        clearModuleDebugSources() {
          globalThis.__exactDebugModuleSources.length = 0;
          globalThis.__exactDebugModuleSource = undefined;
          return { count: 0 };
        },
      };
      const result = execute(invocation(
        "__exactMemoryDebug",
        "clearModuleDebugSources",
        { classification: "closed" },
      ));
      expect(result).toMatchObject({
        kind: "return",
        sourceOperationAttempted: true,
        cleanupPerformed: true,
        rawOutput: { kind: "return", rawValueShape: "object" },
      });
      expect(globalThis.__exactDebugModuleSources).toEqual(["alpha", "beta"]);
      expect(globalThis.__exactDebugModuleSource).toBe("beta");
    } finally {
      for (const [name, descriptor] of [
        ["__exactMemoryDebug", debugObjectDescriptor],
        ["__exactDebugModuleSources", debugSourcesDescriptor],
        ["__exactDebugModuleSource", debugSourceDescriptor],
      ]) {
        if (descriptor) Object.defineProperty(globalThis, name, descriptor);
        else delete globalThis[name];
      }
    }
  });

  test("authors writer promise internals with handled receiver promises", () => {
    for (const memberName of [
      "_closedReject",
      "_closedResolve",
      "_ensureClosedPromiseRejected",
      "_ensureReadyPromiseRejected",
      "_readyReject",
      "_readyResolve",
    ]) {
      expect(invocation("WritableStreamDefaultWriter", memberName).route).toMatchObject({
        operation: "call",
        receiver: { kind: "factory", factoryId: "writable-writer" },
      });
    }
    for (const memberName of ["_setClosedPromiseRecord", "_setReadyPromiseRecord"]) {
      expect(invocation("WritableStreamDefaultWriter", memberName).route).toMatchObject({
        operation: "call",
        arguments: [{ kind: "resolved-promise-record" }],
      });
    }
  });

  test("authors callable stream instance fields against initialized receivers", () => {
    for (const [globalName, factoryId, methods] of [
      [
        "ReadableStreamDefaultController",
        "readable-default-controller",
        [
          "_cancelAlgorithm",
          "_canCloseOrEnqueue",
          "_dequeue",
          "_error",
          "_pullAlgorithm",
          "_pullIfNeeded",
          "_shouldPull",
          "_strategySizeAlgorithm",
        ],
      ],
      [
        "ReadableByteStreamController",
        "readable-byte-controller",
        ["_cancelAlgorithm", "_pullAlgorithm"],
      ],
      [
        "TransformStreamDefaultController",
        "transform-controller",
        ["_flushAlgorithm", "_transformAlgorithm"],
      ],
    ]) {
      for (const memberName of methods) {
        expect(invocation(globalName, memberName).route).toMatchObject({
          operation: "call",
          receiver: { kind: "factory", factoryId },
        });
      }
    }
    for (const globalName of [
      "ReadableStreamDefaultReader",
      "ReadableStreamBYOBReader",
    ]) {
      for (const memberName of ["_closedReject", "_closedResolve"]) {
        expect(invocation(globalName, memberName).route).toMatchObject({
          operation: "call",
          receiver: {
            kind: "factory",
            options: { closed: false },
          },
        });
      }
    }
    expect(invocation("TransformStream", "_backpressureResolve").route)
      .toMatchObject({
        operation: "call",
        receiver: {
          kind: "factory",
          factoryId: "transform-stream-backpressure",
        },
      });
  });

  test("resolves source-inventory structured-clone symbol bindings", () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, "MessagePort");
    class FixtureMessagePort {
      [Symbol.for("exact.structuredClone.transfer")]() {
        return "transferred";
      }
    }
    try {
      Object.defineProperty(globalThis, "MessagePort", {
        configurable: true,
        value: FixtureMessagePort,
      });
      const recipe = invocation(
        "MessagePort",
        "[[symbol-binding:structuredCloneTransferSymbol]]",
        { classification: "closed" },
      );
      expect(execute(recipe)).toMatchObject({
        kind: "return",
        sourceOperationAttempted: true,
        descriptorProof: { presence: "inherited", valueType: "function" },
        rawOutput: { kind: "return", value: "transferred" },
      });
    } finally {
      if (original) Object.defineProperty(globalThis, "MessagePort", original);
      else delete globalThis.MessagePort;
    }
  });

  test("uses a live Get for production-omitted compatibility callables", () => {
    const originalPromise = Object.getOwnPropertyDescriptor(
      globalThis,
      "__OriginalPromise",
    );
    try {
      delete globalThis.__OriginalPromise;
      for (const memberName of [
        "prototype.catch",
        "prototype.finally",
        "prototype.then",
        "reject",
      ]) {
        const recipe = invocation("__OriginalPromise", memberName, {
          classification: "closed",
        });
        expect(recipe.route).toEqual({
          operation: "get",
          receiver: { kind: "source-member-owner" },
          arguments: [],
        });
        expect(execute(recipe)).toMatchObject({
          kind: "absent",
          sourceOperationAttempted: true,
          rawOutput: { kind: "absent", rawValueShape: "absent" },
        });
      }
    } finally {
      if (originalPromise) {
        Object.defineProperty(
          globalThis,
          "__OriginalPromise",
          originalPromise,
        );
      } else {
        delete globalThis.__OriginalPromise;
      }
    }
    for (const memberName of ["_resetFromSearch", "toJSON"]) {
      expect(invocation("URLSearchParams", memberName).route).toMatchObject({
        operation: "get",
        receiver: { kind: "factory", factoryId: "url-search-params" },
      });
    }
  });

  test("authors source-proven closed no-ops and stable refusals", () => {
    for (const globalName of ["Exact", "Bun"]) {
      expect(invocation(globalName, "accessibility.announce", {
        classification: "closed",
      }).route).toMatchObject({ operation: "call", arguments: [{ value: "" }] });
      expect(invocation(globalName, "accessibility.get", {
        classification: "closed",
      }).route).toMatchObject({
        operation: "call",
        arguments: [{ value: "prefersReducedMotion" }],
      });
      expect(invocation(globalName, "unsafe.gcAggressionLevel", {
        classification: "closed",
      }).route.operation).toBe("call");
      expect(invocation(globalName, "unsafe.segfault", {
        classification: "closed",
      }).route).toMatchObject({ operation: "call", arguments: [] });
      expect(invocation(globalName, "setModuleCapabilities").route).toEqual({
        operation: "get",
        receiver: { kind: "source-member-owner" },
        arguments: [],
      });
    }
    expect(invocation("clearImmediate", null, {
      classification: "closed",
      memberKinds: ["assignment"],
    }).route).toMatchObject({ operation: "call", arguments: [{ value: 0 }] });
    expect(invocation("__exactAndroidDispatchPlatformEvent", null, {
      classification: "closed",
      memberKinds: ["assignment"],
    }).route.operation).toBe("call");
  });

  test("executes receiver-only APIs against isolated public prototypes", () => {
    const byob = invocation("ReadableStreamBYOBRequest", "respond");
    expect(byob.route).toMatchObject({
      operation: "call",
      receiver: {
        kind: "factory",
        factoryId: "isolated-prototype",
        options: { globalName: "ReadableStreamBYOBRequest" },
      },
      suppressRejection: true,
    });
    expect(execute(byob)).toMatchObject({
      kind: "throw",
      sourceOperationAttempted: true,
      descriptorProof: { presence: "inherited", valueType: "function" },
      rawOutput: { kind: "throw" },
    });

    for (const [globalName, memberName, classification] of [
      ["WebSocket", "_handleOpen", "non-capability"],
      ["IDBDatabase", "close", "closed"],
      ["IDBObjectStore", "get", "closed"],
      ["caches", "keys", "closed"],
    ]) {
      expect(invocation(globalName, memberName, { classification }).route).toMatchObject({
        operation: "call",
        receiver: { kind: "factory", factoryId: "isolated-prototype" },
      });
    }
  });

  test("publishes a closed data-only factory vocabulary", () => {
    expect(globalCallableFactoryRecipeIds).toContain("buffer");
    expect(globalCallableFactoryRecipeIds).toContain("body-message");
    expect(globalCallableFactoryRecipeIds).toContain("isolated-prototype");
    expect(globalCallableFactoryRecipeIds).toContain("storage-prototype");
    expect(globalCallableFactoryRecipeIds).toContain("transform-stream-backpressure");
    expect(globalCallableFactoryRecipeIds).toContain("broadcast-channel");
    expect(globalCallableFactoryRecipeIds).toContain("message-port");
    expect(globalCallableFactoryRecipeIds).toContain("event-instance");
    expect(globalCallableFactoryRecipeIds).toContain("readable-stream");
    expect(globalCallableFactoryRecipeIds).not.toContain("network");
  });

  test("partitions the exact current non-capability callable family", async () => {
    const inventory = await discoverRepositorySurfaces(repoRoot);
    const coverage = JSON.parse(
      fs.readFileSync(
        path.join(repoRoot, "capsec/registry/coverage-edges.json"),
        "utf8",
      ),
    );
    const coverageBySurface = new Map(
      coverage.edges.map((edge) => [
        `${edge.surface.kind}:${edge.surface.name}`,
        edge,
      ]),
    );
    const recipes = inventory.surfaces.flatMap((candidate) => {
      const edge = coverageBySurface.get(
        `${candidate.kind}:${candidate.name}`,
      );
      if (!edge || edge.classification !== "non-capability") return [];
      const recipe = authoredGlobalCallableOutputInvocation({
        surface: candidate,
        coverageEdge: edge,
      });
      return recipe ? [recipe] : [];
    });
    const counts = Object.fromEntries(
      Object.entries(Object.groupBy(recipes, (recipe) => recipe.route.operation))
        .map(([kind, rows]) => [kind, rows.length]),
    );
    // Timer cancellation is exercised through its owner-authenticated native
    // route; the generic callable partition keeps both global aliases explicit
    // but unexercisable so it cannot double-claim that evidence.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // the frozen 882-row baseline preceded the deliberate closure of two
    // accessibility callbacks, thirty IndexedDB callables, and two worklet
    // helpers. Those rows remain covered by the closed-surface batches rather
    // than borrowing non-capability execution evidence.
    expect(recipes).toHaveLength(848);
    expect(counts).toEqual({
      call: 601,
      construct: 9,
      get: 4,
      unexercisable: 234,
    });
  }, 30_000);
});
