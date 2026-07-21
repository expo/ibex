/**
 * Expectation-free invocation descriptions for fixed native-to-JavaScript
 * delivery outputs that already have a bounded native execution fixture.
 *
 * The iOS module/renderer callbacks are intentionally not authored here: their
 * source proves catalog membership, but this repository has no bounded live
 * adapter for those two C entry points yet. Returning null keeps that gap
 * explicit instead of turning source registration into value evidence.
 *
 * @ref LLP 0023#6-path-bearing-observables — callback arguments are delivered
 * values; an ignored JavaScript callback return is not an output channel.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

export const FIXED_NATIVE_DELIVERY_OUTPUT_INVOCATION_SCHEMA =
  "ibex/capsec-fixed-native-delivery-output-invocation/1";
export const FIXED_NATIVE_DELIVERY_OUTPUT_SOURCE_DESCRIPTOR_KIND =
  "source-bound-fixed-native-delivery";

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const keySignature = ({ output, mode, returnVariant }) =>
  `${output}\0${mode}\0${returnVariant}`;

const channel = (output, mode, returnVariant) =>
  keySignature({ output, mode, returnVariant });

const DEFINITIONS = Object.freeze({
  __exactMotionRatedPublish: Object.freeze({
    classification: "closed",
    nativeDriver: "ex_hermes_dispatch_motion_rated_publish",
    operationKind: "bounded-motion-rated-publish-delivery",
    fixtureId: "motion-rated-publish-fixed-sample-v1",
    implementationPath: "src/engine/hermes_runtime_worklet.cc",
    liveFixturePath: "src/engine/mod.rs",
    channels: new Set([
      channel(
        "callback:motion-rated-publish/0",
        "fixed-sample",
        "u64-decimal-string",
      ),
      channel("callback:motion-rated-publish/1", "fixed-sample", "array"),
      channel(
        "callback:motion-rated-publish/1[]",
        "fixed-sample",
        "finite-number",
      ),
      channel(
        "callback:motion-rated-publish/2",
        "fixed-sample",
        "metadata-object",
      ),
      ...["dirtyGeneration", "sampleTimeNs"].map((field) =>
        channel(
          `callback:motion-rated-publish/2.${field}`,
          "fixed-sample",
          "u64-decimal-string",
        ),
      ),
      ...["heartbeat", "programmatic"].map((field) =>
        channel(
          `callback:motion-rated-publish/2.${field}`,
          "fixed-sample",
          "boolean",
        ),
      ),
    ]),
  }),
  __exactRunOnJS: Object.freeze({
    classification: "closed",
    nativeDriver: "ex_hermes_dispatch_worklet_calls",
    operationKind: "bounded-worklet-run-on-js-delivery",
    fixtureId: "worklet-run-on-js-bounded-batch-v1",
    implementationPath: "src/engine/hermes_runtime_worklet.cc",
    liveFixturePath: "src/engine/mod.rs",
    channels: new Set([
      channel("callback:run-on-js/0", "bounded-batch", "number"),
      channel("callback:run-on-js/1", "bounded-batch", "metadata-object"),
      ...["sourceIdentity", "sourceSequence", "generation"].map((field) =>
        channel(
          `callback:run-on-js/1.${field}`,
          "bounded-batch",
          "u64-decimal-string",
        ),
      ),
      channel(
        "callback:run-on-js/arguments[]",
        "bounded-batch",
        "finite-number",
      ),
    ]),
  }),
  __exactScheduleOnAppRuntime: Object.freeze({
    classification: "closed",
    nativeDriver: "ex_hermes_dispatch_worklet_json_batch",
    operationKind: "bounded-worklet-json-batch-delivery",
    fixtureId: "schedule-on-app-runtime-json-batch-v1",
    implementationPath: "src/engine/hermes_runtime_worklet.cc",
    liveFixturePath: "src/engine/mod.rs",
    channels: new Set([
      channel("callback:schedule-on-app-runtime/0", "json-batch", "array"),
      channel(
        "callback:schedule-on-app-runtime/0[].name",
        "json-batch",
        "string",
      ),
      channel(
        "callback:schedule-on-app-runtime/0[].args",
        "json-batch",
        "json-value",
      ),
      channel(
        "callback:schedule-on-app-runtime/1",
        "json-batch",
        "number",
      ),
    ]),
  }),
  __ibexCapsecContextObserver_: Object.freeze({
    classification: "non-capability",
    nativeDriver: "ibex_test_install_capsec_context_observer",
    operationKind: "bounded-ephemeral-context-observer-call",
    fixtureId: "capsec-context-observer-one-shot-v1",
    implementationPath: "src/engine/hermes_runtime.cc",
    liveFixturePath:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs",
    channels: new Set([
      channel("[[return]]", "ephemeral-one-shot", "context-record"),
      channel(
        "field:principalId",
        "ephemeral-one-shot",
        "u64-tagged-string",
      ),
      channel(
        "field:runtimeNonce",
        "ephemeral-one-shot",
        "u64-tagged-string",
      ),
    ]),
  }),
});

const SOURCE_ONLY_SURFACES = new Set([
  "__exactDispatchEvent",
  "__exactDispatchStableEvent",
  "__exactModuleEvent",
]);

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

function validateBinding(catalogRow, surface, coverageEdge) {
  exactKeys(
    catalogRow,
    ["key", "discovery", "requiredValueProof"],
    "fixed native delivery catalog row",
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
    "fixed native delivery catalog key",
  );
  exactKeys(
    catalogRow.discovery,
    ["kind", "sourceRefs"],
    "fixed native delivery discovery",
  );

  const definition = DEFINITIONS[surface?.name];
  if (!definition) {
    if (SOURCE_ONLY_SURFACES.has(surface?.name)) return null;
    throw new Error(`unsupported fixed native delivery ${surface?.name}`);
  }
  const key = catalogRow.key;
  if (
    surface.kind !== "native-op" ||
    surface.observedKey !== `native-op:${surface.name}` ||
    coverageEdge.id !== key.surfaceId ||
    coverageEdge.classification !== definition.classification ||
    coverageEdge.surface?.kind !== surface.kind ||
    coverageEdge.surface?.name !== surface.name ||
    key.sourceKind !== "native-op" ||
    (surface.name === "__ibexCapsecContextObserver_"
      ? key.contextId !== "javascript.package-call-loaded"
      : key.contextId !== "javascript.package-callback-loaded") ||
    catalogRow.discovery.kind !== "source-asserted-structured-output" ||
    catalogRow.requiredValueProof !== "live-value-observation" ||
    !definition.channels.has(keySignature(key))
  ) {
    throw new Error(`${surface.observedKey}: invalid fixed delivery binding`);
  }

  const implementationSourceRefs = canonicalStrings(
    catalogRow.discovery.sourceRefs,
    "fixed native delivery source refs",
  );
  const implementationSourceRef = implementationSourceRefs.find(
    (sourceRef) =>
      sourceRef.startsWith(`${definition.implementationPath}#`) &&
      sourceRef.includes(definition.nativeDriver),
  );
  const liveFixtureSourceRef = implementationSourceRefs.find((sourceRef) =>
    sourceRef.startsWith(`${definition.liveFixturePath}#`),
  );
  if (!implementationSourceRef || !liveFixtureSourceRef) {
    throw new Error(
      `${surface.observedKey}: bounded native delivery lacks implementation or live fixture binding`,
    );
  }
  canonicalStrings(surface.sourceRefs, "fixed native delivery inventory refs");
  return {
    definition,
    implementationSourceRefs,
    implementationSourceRef,
    liveFixtureSourceRef,
  };
}

export function validateFixedNativeDeliveryOutputInvocation(
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
      "selection",
      "completion",
    ],
    "fixed native delivery invocation",
  );
  exactKeys(
    invocation.sourceDescriptor,
    [
      "kind",
      "globalName",
      "nativeDriver",
      "inventorySourceRefs",
      "implementationSourceRefs",
      "implementationSourceRef",
      "liveFixtureSourceRef",
    ],
    "fixed native delivery source descriptor",
  );
  exactKeys(
    invocation.operation,
    ["kind", "fixtureId"],
    "fixed native delivery operation",
  );
  exactKeys(
    invocation.selection,
    ["output", "alias", "mode", "returnVariant"],
    "fixed native delivery selection",
  );
  exactKeys(
    invocation.completion,
    ["kind"],
    "fixed native delivery completion",
  );

  const descriptor = invocation.sourceDescriptor;
  const definition = DEFINITIONS[descriptor.globalName];
  canonicalStrings(
    descriptor.inventorySourceRefs,
    "fixed native delivery inventory refs",
  );
  const implementationSourceRefs = canonicalStrings(
    descriptor.implementationSourceRefs,
    "fixed native delivery implementation refs",
  );
  if (
    !definition ||
    invocation.invocationSchema !==
      FIXED_NATIVE_DELIVERY_OUTPUT_INVOCATION_SCHEMA ||
    invocation.kind !== "fixed-native-delivery-output" ||
    invocation.coverageEdgeId !== catalogKey.surfaceId ||
    invocation.coverageClassification !== definition.classification ||
    invocation.surfaceObservedKey !== surfaceObservedKey ||
    surfaceObservedKey !== `native-op:${descriptor.globalName}` ||
    descriptor.kind !== FIXED_NATIVE_DELIVERY_OUTPUT_SOURCE_DESCRIPTOR_KIND ||
    descriptor.globalName !== catalogKey.alias.split(".")[0] ||
    descriptor.nativeDriver !== definition.nativeDriver ||
    descriptor.implementationSourceRef !==
      implementationSourceRefs.find(
        (sourceRef) =>
          sourceRef.startsWith(`${definition.implementationPath}#`) &&
          sourceRef.includes(definition.nativeDriver),
      ) ||
    descriptor.liveFixtureSourceRef !==
      implementationSourceRefs.find((sourceRef) =>
        sourceRef.startsWith(`${definition.liveFixturePath}#`),
      ) ||
    invocation.sourceDescriptorDigest !== taggedDigest(descriptor) ||
    invocation.operation.kind !== definition.operationKind ||
    invocation.operation.fixtureId !== definition.fixtureId ||
    canonicalJson(invocation.selection) !==
      canonicalJson({
        output: catalogKey.output,
        alias: catalogKey.alias,
        mode: catalogKey.mode,
        returnVariant: catalogKey.returnVariant,
      }) ||
    !definition.channels.has(keySignature(catalogKey)) ||
    invocation.completion.kind !== "synchronous-native-driver"
  ) {
    throw new Error(`${surfaceObservedKey}: invalid fixed delivery invocation`);
  }
  return invocation;
}

export function authoredFixedNativeDeliveryOutputInvocation({
  catalogRow,
  surface,
  coverageEdge,
}) {
  const binding = validateBinding(catalogRow, surface, coverageEdge);
  if (binding === null) return null;
  const {
    definition,
    implementationSourceRefs,
    implementationSourceRef,
    liveFixtureSourceRef,
  } = binding;
  const sourceDescriptor = {
    kind: FIXED_NATIVE_DELIVERY_OUTPUT_SOURCE_DESCRIPTOR_KIND,
    globalName: surface.name,
    nativeDriver: definition.nativeDriver,
    inventorySourceRefs: [...surface.sourceRefs],
    implementationSourceRefs: [...implementationSourceRefs],
    implementationSourceRef,
    liveFixtureSourceRef,
  };
  const invocation = {
    invocationSchema: FIXED_NATIVE_DELIVERY_OUTPUT_INVOCATION_SCHEMA,
    kind: "fixed-native-delivery-output",
    coverageEdgeId: coverageEdge.id,
    coverageClassification: coverageEdge.classification,
    surfaceObservedKey: surface.observedKey,
    sourceDescriptor,
    sourceDescriptorDigest: taggedDigest(sourceDescriptor),
    operation: {
      kind: definition.operationKind,
      fixtureId: definition.fixtureId,
    },
    selection: {
      output: catalogRow.key.output,
      alias: catalogRow.key.alias,
      mode: catalogRow.key.mode,
      returnVariant: catalogRow.key.returnVariant,
    },
    completion: { kind: "synchronous-native-driver" },
  };
  return validateFixedNativeDeliveryOutputInvocation(invocation, {
    catalogKey: catalogRow.key,
    surfaceObservedKey: surface.observedKey,
  });
}
