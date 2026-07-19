/**
 * Expectation-free loaded-Hermes invocations for the two native freeze
 * primitives. Each route binds the exact patch assertions carried by its
 * catalog row, then selects either a primitive or a null-prototype object
 * sentinel. The executor owns the strict-identity and freeze checks; this
 * author never supplies a reviewed output value to echo.
 *
 * @ref LLP 0023#6-path-bearing-observables — a native return is output
 * evidence only after the loaded engine observes the exact source completion.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

export const NATIVE_FREEZE_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-native-freeze-output-invocation/1";
export const NATIVE_FREEZE_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "authored-native-freeze-invocation";

const COMPLETION = Object.freeze({ kind: "synchronous-loaded-hermes" });
const RETURN_VARIANT = "same-as-argument-0";
const CONTEXT_ID = "runtime.bootstrap-native-call-loaded";

const SURFACES = Object.freeze({
  __exactDeepFreeze: Object.freeze({
    implementationSymbol: "exactDeepFreeze",
    implementationPath:
      "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
    freezeSemantics: "deep",
  }),
  __exactNativeFreeze: Object.freeze({
    implementationSymbol: "exactNativeFreeze",
    implementationPath:
      "patches/hermes/0005-native-compartment-refinements.patch",
    freezeSemantics: "shallow",
  }),
});

const MODES = Object.freeze({
  "object-sentinel": Object.freeze({
    sentinelId: "null-prototype-two-node-graph-v1",
    identityCheck: "strict-equality",
  }),
  "primitive-sentinel": Object.freeze({
    sentinelId: "primitive-number-1729",
    identityCheck: "strict-equality",
  }),
});

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}: expected object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error(
      `${label}: expected exact keys [${wanted.join(", ")}], got [${actual.join(", ")}]`,
    );
  }
}

function canonicalStrings(values, label) {
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.some((value) => typeof value !== "string" || value.length === 0) ||
    canonicalJson(values) !== canonicalJson([...new Set(values)].sort())
  ) {
    throw new Error(`${label}: expected canonical non-empty strings`);
  }
  return values;
}

function surfaceDefinition(surfaceName) {
  const definition = SURFACES[surfaceName];
  if (!definition) {
    throw new Error(`unknown native freeze output surface ${surfaceName}`);
  }
  return definition;
}

function validateCatalogBinding(catalogRow, surface, coverageEdge) {
  exactKeys(
    catalogRow,
    ["key", "discovery", "requiredValueProof"],
    "native freeze catalog row",
  );
  exactKeys(
    catalogRow.key,
    [
      "surfaceId",
      "output",
      "alias",
      "mode",
      "sourceKind",
      "returnVariant",
      "contextId",
    ],
    "native freeze catalog key",
  );
  exactKeys(
    catalogRow.discovery,
    ["kind", "sourceRefs"],
    "native freeze catalog discovery",
  );
  exactKeys(
    coverageEdge,
    ["id", "classification", "surface", "rationaleId", "rationale"],
    "native freeze coverage edge",
  );
  exactKeys(
    coverageEdge.surface,
    ["kind", "name"],
    "native freeze coverage surface",
  );

  const key = catalogRow.key;
  const definition = surfaceDefinition(surface?.name);
  const mode = MODES[key.mode];
  if (
    !mode ||
    surface.kind !== "native-op" ||
    surface.observedKey !== `native-op:${surface.name}` ||
    !Array.isArray(surface.sourceRefs) ||
    surface.sourceRefs.length === 0 ||
    coverageEdge.id !== key.surfaceId ||
    coverageEdge.classification !== "non-capability" ||
    coverageEdge.surface.kind !== surface.kind ||
    coverageEdge.surface.name !== surface.name ||
    key.output !== "[[return]]" ||
    key.alias !== surface.name ||
    key.sourceKind !== "native-op" ||
    key.returnVariant !== RETURN_VARIANT ||
    key.contextId !== CONTEXT_ID ||
    catalogRow.discovery.kind !== "source-asserted-structured-output" ||
    catalogRow.requiredValueProof !== "live-value-observation"
  ) {
    throw new Error(`${surface?.observedKey}: invalid native freeze catalog binding`);
  }

  const implementationSourceRefs = canonicalStrings(
    catalogRow.discovery.sourceRefs,
    "native freeze implementation source refs",
  );
  if (
    !implementationSourceRefs.every((sourceRef) =>
      sourceRef.startsWith(`${definition.implementationPath}#region:`),
    ) ||
    !implementationSourceRefs.some(
      (sourceRef) =>
        sourceRef.includes(
          `CallResult<HermesValue> ${definition.implementationSymbol}`,
        ) && sourceRef.includes("return args.getArg(0);"),
    ) ||
    !implementationSourceRefs.some((sourceRef) =>
      sourceRef.includes(`createASCIIRef("${surface.name}")`),
    )
  ) {
    throw new Error(
      `${surface.observedKey}: catalog is not bound to the exact freeze patch`,
    );
  }
  return { definition, key, mode, implementationSourceRefs };
}

export function validateNativeFreezeOutputInvocation(
  invocation,
  { catalogKey, surfaceObservedKey },
) {
  exactKeys(
    invocation,
    [
      "invocationSchema",
      "kind",
      "coverageEdgeId",
      "coverageClassification",
      "surfaceObservedKey",
      "sourceDescriptor",
      "sourceDescriptorDigest",
      "operation",
      "completion",
    ],
    "native freeze invocation",
  );
  exactKeys(
    invocation.sourceDescriptor,
    [
      "kind",
      "globalName",
      "implementationSymbol",
      "implementationPath",
      "freezeSemantics",
      "inventorySourceRefs",
      "implementationSourceRefs",
    ],
    "native freeze invocation source descriptor",
  );
  exactKeys(
    invocation.operation,
    ["kind", "sentinelId", "identityCheck", "freezeCheck"],
    "native freeze invocation operation",
  );
  exactKeys(
    invocation.completion,
    ["kind"],
    "native freeze invocation completion",
  );

  const descriptor = invocation.sourceDescriptor;
  const definition = surfaceDefinition(descriptor.globalName);
  const mode = MODES[catalogKey?.mode];
  canonicalStrings(
    descriptor.inventorySourceRefs,
    "native freeze inventory source refs",
  );
  const implementationSourceRefs = canonicalStrings(
    descriptor.implementationSourceRefs,
    "native freeze implementation source refs",
  );
  const expectedFreezeCheck =
    catalogKey.mode === "primitive-sentinel"
      ? "not-applicable"
      : definition.freezeSemantics;
  if (
    !mode ||
    invocation.invocationSchema !== NATIVE_FREEZE_OUTPUT_INVOCATION_SCHEMA ||
    invocation.kind !== "native-freeze-output" ||
    invocation.coverageEdgeId !== catalogKey.surfaceId ||
    invocation.coverageClassification !== "non-capability" ||
    invocation.surfaceObservedKey !== surfaceObservedKey ||
    surfaceObservedKey !== `native-op:${catalogKey.alias}` ||
    descriptor.kind !== "native-freeze-global" ||
    descriptor.globalName !== catalogKey.alias ||
    descriptor.implementationSymbol !== definition.implementationSymbol ||
    descriptor.implementationPath !== definition.implementationPath ||
    descriptor.freezeSemantics !== definition.freezeSemantics ||
    !implementationSourceRefs.every((sourceRef) =>
      sourceRef.startsWith(`${definition.implementationPath}#region:`),
    ) ||
    !implementationSourceRefs.some(
      (sourceRef) =>
        sourceRef.includes(
          `CallResult<HermesValue> ${definition.implementationSymbol}`,
        ) && sourceRef.includes("return args.getArg(0);"),
    ) ||
    !implementationSourceRefs.some((sourceRef) =>
      sourceRef.includes(`createASCIIRef("${descriptor.globalName}")`),
    ) ||
    invocation.sourceDescriptorDigest !== taggedDigest(descriptor) ||
    invocation.operation.kind !== "native-freeze-argument-identity" ||
    invocation.operation.sentinelId !== mode.sentinelId ||
    invocation.operation.identityCheck !== mode.identityCheck ||
    invocation.operation.freezeCheck !== expectedFreezeCheck ||
    invocation.completion.kind !== COMPLETION.kind
  ) {
    throw new Error(`${surfaceObservedKey}: invalid native freeze invocation`);
  }
  return invocation;
}

export function authoredNativeFreezeOutputInvocation({
  catalogRow,
  surface,
  coverageEdge,
}) {
  const { definition, key, mode, implementationSourceRefs } =
    validateCatalogBinding(catalogRow, surface, coverageEdge);
  const sourceDescriptor = {
    kind: "native-freeze-global",
    globalName: surface.name,
    implementationSymbol: definition.implementationSymbol,
    implementationPath: definition.implementationPath,
    freezeSemantics: definition.freezeSemantics,
    inventorySourceRefs: [...surface.sourceRefs].sort(),
    implementationSourceRefs: [...implementationSourceRefs],
  };
  const invocation = {
    invocationSchema: NATIVE_FREEZE_OUTPUT_INVOCATION_SCHEMA,
    kind: "native-freeze-output",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    surfaceObservedKey: surface.observedKey,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: "native-freeze-argument-identity",
      sentinelId: mode.sentinelId,
      identityCheck: mode.identityCheck,
      freezeCheck:
        key.mode === "primitive-sentinel"
          ? "not-applicable"
          : definition.freezeSemantics,
    },
    completion: structuredClone(COMPLETION),
  };
  return validateNativeFreezeOutputInvocation(invocation, {
    catalogKey: key,
    surfaceObservedKey: surface.observedKey,
  });
}
