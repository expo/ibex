/**
 * Author exact-target absence probes from source-discovered ABI definitions.
 * An absent surface cannot be invoked; the runtime batch instead proves that
 * the bound target is incompatible with every defining target variant and
 * checks that the platform bridge symbol is absent from the loaded process.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * unsupported-target claims require executed evidence on the exact target.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const TARGET_ABSENCE_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_target_absence_batch",
  "--",
  "--test-threads=1",
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

function canonicalStrings(values) {
  return [...new Set(values)].sort(compareText);
}

function absenceProbeMode(surfaceName, metadata) {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(surfaceName)) {
    return { kind: "dynamic-symbol", symbolName: surfaceName };
  }
  if (
    metadata?.bridgeRole === "java-to-native-callback" &&
    typeof metadata.cppBinding.functionName === "string"
  ) {
    return {
      kind: "dynamic-symbol",
      symbolName: metadata.cppBinding.functionName,
    };
  }
  if (surfaceName.startsWith("java:")) {
    return { kind: "platform-bridge", symbolName: "ex_android_initialize" };
  }
  return null;
}

export function authoredTargetAbsenceProbe({
  plan,
  scenario,
  target,
  coverageByEdge,
  liveByObservedKey,
}) {
  if (
    scenario !== "absent" ||
    plan.expectedObservation?.kind !== "target-absence" ||
    plan.edgeIds.length !== 1 ||
    target?.triple !== "aarch64-apple-darwin"
  ) {
    return null;
  }
  const edge = coverageByEdge.get(plan.edgeIds[0]);
  if (
    !edge ||
    edge.id !== plan.expectedObservation.edgeId ||
    edge.surface?.kind !== "host-abi"
  ) {
    return null;
  }
  const surfaceObservedKey = `host-abi:${edge.surface.name}`;
  if (surfaceObservedKey !== plan.terminalObservedKey) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const metadata = live?.metadata;
  const definitions = metadata?.definitions;
  const targetVariants = canonicalStrings(
    Array.isArray(definitions)
      ? definitions.map((definition) => definition?.targetVariant)
      : [metadata?.targetVariant],
  );
  if (
    live?.kind !== "host-abi" ||
    live.name !== edge.surface.name ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    targetVariants.length === 0 ||
    targetVariants.some((variant) => !["android", "ios"].includes(variant)) ||
    (Array.isArray(definitions) &&
      definitions.some(
        (definition) =>
          typeof definition.sourceRef !== "string" ||
          !live.sourceRefs.includes(definition.sourceRef),
      ))
  ) {
    return null;
  }
  const probeMode = absenceProbeMode(edge.surface.name, metadata);
  if (!probeMode) return null;
  const sourceDescriptor = {
    kind: "target-absent-host-abi",
    surfaceKind: edge.surface.kind,
    surfaceName: edge.surface.name,
    sourceRefs: canonicalStrings(live.sourceRefs),
    targetVariants,
    sourceMetadata: structuredClone(metadata),
    probeMode,
  };
  return {
    kind: "target-absence-probe",
    surfaceObservedKey,
    command: [...TARGET_ABSENCE_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-target-absence-invocation/1",
      kind: "target-absence",
      surfaceKind: edge.surface.kind,
      surfaceName: edge.surface.name,
      targetTriple: target.triple,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      expectedResult: "absent",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

export const targetAbsenceBatchCommand = TARGET_ABSENCE_BATCH_COMMAND;
