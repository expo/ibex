// @ref LLP 0023#6-path-bearing-observables — native freeze output evidence
// proves the exact source completion by identity in the loaded engine.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  NATIVE_FREEZE_OUTPUT_INVOCATION_SCHEMA,
  authoredNativeFreezeOutputInvocation,
  validateNativeFreezeOutputInvocation,
} from "./capsec-native-freeze-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

const DEFINITIONS = Object.freeze({
  __exactDeepFreeze: Object.freeze({
    symbol: "exactDeepFreeze",
    path: "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
    semantics: "deep",
  }),
  __exactNativeFreeze: Object.freeze({
    symbol: "exactNativeFreeze",
    path: "patches/hermes/0005-native-compartment-refinements.patch",
    semantics: "shallow",
  }),
});

function fixture(name, mode) {
  const definition = DEFINITIONS[name];
  const surfaceId = `surface.native.op.${name.slice(2).toLowerCase()}.test`;
  const implementationSourceRefs = [
    `${definition.path}#region:CallResult<HermesValue> ${definition.symbol}(void *, Runtime &runtime)..return args.getArg(0);#tokens:return args.getArg(0);`,
    `${definition.path}#region:runtime, createASCIIRef("${name}")..${definition.symbol},#tokens:runtime, createASCIIRef("${name}")+${definition.symbol},`,
  ].sort();
  const catalogRow = {
    key: {
      surfaceId,
      output: "[[return]]",
      alias: name,
      mode,
      sourceKind: "native-op",
      returnVariant: "same-as-argument-0",
      contextId: "runtime.bootstrap-native-call-loaded",
    },
    discovery: {
      kind: "source-asserted-structured-output",
      sourceRefs: implementationSourceRefs,
    },
    requiredValueProof: "live-value-observation",
  };
  const surface = {
    kind: "native-op",
    name,
    observedKey: `native-op:${name}`,
    sourceRefs: [`${definition.path}#inventory:${name}`],
  };
  const coverageEdge = {
    id: surfaceId,
    classification: "non-capability",
    surface: { kind: "native-op", name },
    rationaleId: `${surfaceId}.rationale`,
    rationale: "native freeze is a non-authority runtime refinement",
  };
  return { catalogRow, surface, coverageEdge, definition };
}

function invocation(name, mode) {
  const value = fixture(name, mode);
  return {
    ...value,
    invocation: authoredNativeFreezeOutputInvocation(value),
  };
}

const harnessSource = fs.readFileSync(
  path.join(
    repoRoot,
    "src/bin/ibex/engine/capsec_native_freeze_output_invocation.js",
  ),
  "utf8",
);
const executeInvocation = new Function(
  "config",
  `return (${harnessSource.trim()})(config);`,
);

const savedGlobals = new Map();

beforeAll(() => {
  for (const name of Object.keys(DEFINITIONS)) {
    savedGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  }
  Object.defineProperty(globalThis, "__exactDeepFreeze", {
    configurable: true,
    writable: true,
    value(value) {
      if (value !== null && typeof value === "object") {
        Object.freeze(value.child);
        Object.freeze(value);
      }
      return value;
    },
  });
  Object.defineProperty(globalThis, "__exactNativeFreeze", {
    configurable: true,
    writable: true,
    value(value) {
      if (value !== null && typeof value === "object") Object.freeze(value);
      return value;
    },
  });
});

afterAll(() => {
  for (const [name, descriptor] of savedGlobals) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
});

describe("native freeze output invocation", () => {
  test("authors primitive and object identity routes bound to each exact patch", () => {
    for (const name of Object.keys(DEFINITIONS)) {
      for (const mode of ["primitive-sentinel", "object-sentinel"]) {
        const value = invocation(name, mode);
        expect(value.invocation).toMatchObject({
          invocationSchema: NATIVE_FREEZE_OUTPUT_INVOCATION_SCHEMA,
          kind: "native-freeze-output",
          coverageEdgeId: value.coverageEdge.id,
          coverageClassification: "non-capability",
          surfaceObservedKey: `native-op:${name}`,
          sourceDescriptor: {
            kind: "native-freeze-global",
            globalName: name,
            implementationSymbol: value.definition.symbol,
            implementationPath: value.definition.path,
            freezeSemantics: value.definition.semantics,
          },
          operation: {
            kind: "native-freeze-argument-identity",
            sentinelId:
              mode === "primitive-sentinel"
                ? "primitive-number-1729"
                : "null-prototype-two-node-graph-v1",
            identityCheck: "strict-equality",
            freezeCheck:
              mode === "primitive-sentinel"
                ? "not-applicable"
                : value.definition.semantics,
          },
          completion: { kind: "synchronous-loaded-hermes" },
        });
        expect(JSON.stringify(value.invocation)).not.toContain(
          "normalizedValue",
        );
        expect(JSON.stringify(value.invocation)).not.toContain(
          "expectedResult",
        );
        expect(
          value.invocation.sourceDescriptor.implementationSourceRefs.every(
            (sourceRef) => sourceRef.startsWith(`${value.definition.path}#region:`),
          ),
        ).toBe(true);
        expect(() =>
          validateNativeFreezeOutputInvocation(value.invocation, {
            catalogKey: value.catalogRow.key,
            surfaceObservedKey: value.surface.observedKey,
          }),
        ).not.toThrow();
      }
    }
  });

  test("the executor proves strict identity and the requested freezing semantics", () => {
    for (const name of Object.keys(DEFINITIONS)) {
      for (const mode of ["primitive-sentinel", "object-sentinel"]) {
        expect(executeInvocation(invocation(name, mode).invocation)).toEqual({
          kind: "return",
          sourceOperationAttempted: true,
          identityProven: true,
          freezingSemanticsProven: true,
          rawOutput: {
            kind: "return",
            rawValueShape: "argument-identity",
            value: "same-as-argument-0",
            errorCode: null,
          },
        });
      }
    }
  });

  test("rejects identity, semantic, and patch-binding drift", () => {
    const deep = invocation("__exactDeepFreeze", "object-sentinel");
    const originalDeep = globalThis.__exactDeepFreeze;
    try {
      globalThis.__exactDeepFreeze = (value) => ({ ...value });
      expect(executeInvocation(deep.invocation)).toMatchObject({
        kind: "throw",
        sourceOperationAttempted: true,
        identityProven: false,
        freezingSemanticsProven: false,
        rawOutput: {
          errorCode: "ERR_IBEX_NATIVE_FREEZE_IDENTITY_PROBE",
        },
      });
      globalThis.__exactDeepFreeze = (value) => {
        Object.freeze(value);
        return value;
      };
      expect(executeInvocation(deep.invocation)).toMatchObject({
        kind: "throw",
        identityProven: true,
        freezingSemanticsProven: false,
      });
    } finally {
      globalThis.__exactDeepFreeze = originalDeep;
    }

    const wrongPatch = structuredClone(deep);
    wrongPatch.catalogRow.discovery.sourceRefs[0] =
      "patches/hermes/wrong.patch#region:wrong..wrong#tokens:wrong";
    wrongPatch.catalogRow.discovery.sourceRefs.sort();
    expect(() => authoredNativeFreezeOutputInvocation(wrongPatch)).toThrow(
      /exact freeze patch/,
    );

    const wrongSentinel = structuredClone(deep.invocation);
    wrongSentinel.operation.sentinelId = "primitive-number-0";
    expect(() =>
      validateNativeFreezeOutputInvocation(wrongSentinel, {
        catalogKey: deep.catalogRow.key,
        surfaceObservedKey: deep.surface.observedKey,
      }),
    ).toThrow(/invalid native freeze invocation/);
  });
});
