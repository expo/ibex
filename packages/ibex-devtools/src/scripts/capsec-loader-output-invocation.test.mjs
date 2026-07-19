import { afterEach, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { authoredModuleLoaderOutputInvocation } from "./capsec-loader-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const harnessSource = fs.readFileSync(
  path.join(
    repoRoot,
    "src/bin/ibex/engine/capsec_loader_output_invocation.js",
  ),
  "utf8",
);
const execute = new Function(
  "config",
  `return (${harnessSource.trim()})(config);`,
);

const savedDescriptors = new Map();

function replaceGlobal(name, value) {
  if (!savedDescriptors.has(name)) {
    savedDescriptors.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  }
  Object.defineProperty(globalThis, name, {
    configurable: true,
    writable: true,
    value,
  });
}

afterEach(() => {
  for (const [name, descriptor] of savedDescriptors) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
  savedDescriptors.clear();
});

function invocation(name) {
  const metadata = {
    "entry:global-require": {
      evidenceType: "loader-entry-route",
      globalName: "globalThis.require",
    },
    "entry:exact-require": {
      evidenceType: "loader-entry-route",
      globalName: "globalThis.__exactRequire",
    },
    "entry:global-import": {
      evidenceType: "loader-entry-route",
      globalName: "globalThis.import",
    },
    "entry:import-module": {
      evidenceType: "loader-entry-route",
      globalName: "globalThis.importModule",
    },
    "entry:require-resolve": {
      evidenceType: "loader-entry-route",
      globalName: "globalThis.require.resolve",
    },
  }[name];
  return authoredModuleLoaderOutputInvocation({
    surface: {
      kind: "loader",
      name,
      observedKey: `loader:${name}`,
      sourceRefs: [`src/engine/bootstrap/module-loader.js#${name}`],
      metadata,
    },
    coverageEdge: {
      id: `surface.loader.${name.replace(/[^a-z]+/g, ".")}.test`,
      classification: "non-capability",
    },
  });
}

async function currentExecutableInvocations() {
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
  return inventory.surfaces.flatMap((surface) => {
    if (
      surface.kind !== "loader" ||
      !surface.sourceRefs.some((sourceRef) =>
        sourceRef.startsWith("src/engine/bootstrap/module-loader.js"),
      )
    ) {
      return [];
    }
    const candidate = authoredModuleLoaderOutputInvocation({
      surface,
      coverageEdge: coverageBySurface.get(`loader:${surface.name}`),
    });
    return candidate?.route.operation === "invoke-public-loader"
      ? [candidate]
      : [];
  });
}

describe("loaded module-loader output invocation harness", () => {
  test("retains the exact synchronous public require completion", async () => {
    replaceGlobal("require", function (specifier) {
      return `loaded:${specifier}`;
    });
    const result = await execute(invocation("entry:global-require"));
    expect(result).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      entrypointProof: {
        presence: "own",
        descriptorKind: "data",
        valueType: "function",
      },
      rawOutput: {
        kind: "return",
        rawValueShape: "string",
        value: "loaded:node:path",
        errorCode: null,
      },
    });
  });

  test("preserves only an actual throw code and actual error name", async () => {
    const coded = new Error("denied");
    coded.name = "ImportPolicyError";
    coded.code = "ERR_IBEX_IMPORT_DENIED";
    replaceGlobal("__exactRequire", function () {
      throw coded;
    });
    expect(await execute(invocation("entry:exact-require"))).toMatchObject({
      kind: "throw",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "throw",
        rawValueShape: "throw",
        value: null,
        errorCode: "ERR_IBEX_IMPORT_DENIED",
        errorName: "ImportPolicyError",
      },
    });

    const requireFunction = function () {};
    requireFunction.resolve = function () {
      throw new TypeError("bad specifier");
    };
    replaceGlobal("require", requireFunction);
    expect(await execute(invocation("entry:require-resolve"))).toMatchObject({
      kind: "throw",
      rawOutput: {
        kind: "throw",
        errorCode: null,
        errorName: "TypeError",
      },
    });
  });

  test("records loaded absence without fabricating a call", async () => {
    replaceGlobal("import", undefined);
    const result = await execute(invocation("entry:global-import"));
    expect(result).toMatchObject({
      kind: "unexercisable",
      sourceOperationAttempted: true,
      entrypointProof: {
        presence: "own",
        descriptorKind: "data",
        valueType: "undefined",
      },
    });
    expect(result).toMatchObject({
      kind: "unexercisable",
      reasonCode: "loaded-entrypoint-is-not-callable",
      rawOutput: null,
    });

    delete globalThis.import;
    const absentResult = await execute(invocation("entry:global-import"));
    expect(absentResult).toMatchObject({
      kind: "absent",
      sourceOperationAttempted: true,
      entrypointProof: { presence: "absent" },
      rawOutput: {
        kind: "absent",
        rawValueShape: "absent",
        errorCode: null,
      },
    });
  });

  test("settles async imports across a bounded quiescence turn", async () => {
    replaceGlobal("importModule", async function (specifier) {
      await Promise.resolve();
      return { default: specifier };
    });
    expect(await execute(invocation("entry:import-module"))).toMatchObject({
      kind: "return",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "return",
        rawValueShape: "object",
        value: null,
        errorCode: null,
      },
    });
  });

  test("retains async rejection identity and never synthesizes a code", async () => {
    replaceGlobal("importModule", function () {
      return Promise.reject(new RangeError("bad import"));
    });
    expect(await execute(invocation("entry:import-module"))).toMatchObject({
      kind: "throw",
      sourceOperationAttempted: true,
      rawOutput: {
        kind: "throw",
        errorCode: null,
        errorName: "RangeError",
      },
    });
  });

  test("reports a bounded async timeout without inventing source output", async () => {
    replaceGlobal("importModule", function () {
      return new Promise(function () {});
    });
    const config = invocation("entry:import-module");
    config.completion = {
      kind: "event-loop-quiescence",
      timeoutMilliseconds: 5,
    };
    expect(await execute(config)).toMatchObject({
      kind: "unexercisable",
      reasonCode: "event-loop-quiescence-timeout",
      sourceOperationAttempted: true,
      rawOutput: null,
    });
  });

  test("clears its captured timeout even when the loader rewrites timer globals", async () => {
    const realSetTimeout = globalThis.setTimeout;
    const realClearTimeout = globalThis.clearTimeout;
    const active = new Set();
    replaceGlobal("setTimeout", function (callback, milliseconds) {
      let timer;
      timer = realSetTimeout(function () {
        active.delete(timer);
        callback();
      }, milliseconds);
      active.add(timer);
      return timer;
    });
    replaceGlobal("clearTimeout", function (timer) {
      active.delete(timer);
      return realClearTimeout(timer);
    });
    replaceGlobal("importModule", function () {
      globalThis.setTimeout = function () {
        throw new Error("rewritten timeout must not be used");
      };
      globalThis.clearTimeout = function () {
        throw new Error("rewritten clearTimeout must not be used");
      };
      return Promise.resolve("loaded");
    });
    expect(await execute(invocation("entry:import-module"))).toMatchObject({
      kind: "return",
      rawOutput: { kind: "return", value: "loaded" },
    });
    expect(active.size).toBe(0);
  });

  test("refuses private entrypoints and malformed route expansion", async () => {
    const privateRoute = invocation("entry:global-require");
    privateRoute.route.entrypoint = "loadInternal";
    expect(await execute(privateRoute)).toMatchObject({
      kind: "unexercisable",
      reasonCode: "private-or-unknown-entrypoint",
      sourceOperationAttempted: false,
    });

    const expanded = invocation("entry:global-require");
    expanded.route.targetFunction = "load";
    expect(await execute(expanded)).toMatchObject({
      kind: "unexercisable",
      reasonCode: "invalid-invocation-shape",
      sourceOperationAttempted: false,
    });
  });

  test("accepts every exact current executable recipe without private expansion", async () => {
    const fakeRequire = function (specifier) {
      return specifier;
    };
    fakeRequire.resolve = function (specifier) {
      return specifier;
    };
    replaceGlobal("require", fakeRequire);
    replaceGlobal("__exactRequire", fakeRequire);
    replaceGlobal("import", function (specifier) {
      return Promise.resolve(specifier);
    });
    replaceGlobal("importModule", function (specifier) {
      return Promise.resolve(specifier);
    });

    const invocations = await currentExecutableInvocations();
    expect(invocations).toHaveLength(119);
    for (const config of invocations) {
      expect(await execute(config)).toMatchObject({
        kind: "return",
        sourceOperationAttempted: true,
        rawOutput: {
          kind: "return",
          rawValueShape: "string",
          value: config.route.specifier,
          errorCode: null,
        },
      });
    }
  }, 30_000);
});
