/**
 * Source-bound public probes for deny-only surfaces. Closed surfaces do not
 * enter the typed authority evaluator: the production boundary must reject
 * them before project code and report zero typed and legacy decisions.
 *
 * @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces —
 * deny-only startup controls must fail at the authenticated entry boundary.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const CLOSED_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_closed_recipe_batch",
  "--",
  "--test-threads=1",
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

function startupEnvironmentProbe({
  plan,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const prefix = "startup:env:";
  if (!surfaceObservedKey.startsWith(prefix)) return null;
  const environmentName = surfaceObservedKey.slice(prefix.length);
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  if (
    !environmentName ||
    live?.kind !== "startup" ||
    live.name !== `env:${environmentName}` ||
    live.metadata?.evidenceType !== "static-runtime-environment-control" ||
    canonicalJson(live.metadata.authoredNames) !==
      canonicalJson([environmentName]) ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length === 0 ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "closed" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "closed-startup-environment",
    environmentName,
    sourceRefs: structuredClone(live.sourceRefs),
    sourceMetadata: structuredClone(live.metadata),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...CLOSED_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-closed-surface-invocation/1",
      kind: "closed-surface",
      surfaceKind: "startup",
      surfaceName: `env:${environmentName}`,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: { kind: "startup-environment", environmentName },
      expectedResult: "closed",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

export function authoredClosedPublicProbe(options) {
  const { plan, scenario } = options;
  if (
    plan.classification !== "closed" ||
    scenario !== "closed" ||
    plan.expectedObservation?.kind !== "enforcement-branch" ||
    plan.edgeIds.length !== 1 ||
    plan.actionIds.length !== 0
  ) {
    return null;
  }
  return startupEnvironmentProbe(options);
}

export const closedBatchCommand = CLOSED_BATCH_COMMAND;
