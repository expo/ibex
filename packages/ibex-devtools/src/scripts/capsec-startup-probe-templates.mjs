/**
 * Author exact loaded-engine probes for the curated production startup stages.
 * Scanner-only call routes, script-URL facets, lazy installers, and platform
 * definitions deliberately remain residual: a post-bootstrap property is not
 * evidence that every source mention executed.
 *
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * startup promotion requires execution by the attested engine and a
 * source-bound postcondition, not an inventory label.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const STARTUP_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_startup_batch",
  "--",
  "--test-threads=1",
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const STARTUP_STAGES = new Map(
  [
    {
      surfaceName: "runtime-create",
      postcondition: "runtime-created",
      sourceRef: "src/engine/hermes_runtime.cc#ex_hermes_create_armed",
      requiredFacts: ["engine-can-evaluate"],
    },
    {
      surfaceName: "globals-install",
      postcondition: "globals-installed",
      sourceRef: "src/engine/hermes_runtime.cc#installGlobals",
      requiredFacts: ["console-installed", "timers-installed"],
    },
    {
      surfaceName: "module-loader-install",
      postcondition: "module-loader-installed",
      sourceRef: "src/engine/hermes_bootstrap.cc#installModuleLoader",
      requiredFacts: ["module-loader-installed"],
    },
    {
      surfaceName: "shared-runtime-install",
      postcondition: "shared-runtime-installed",
      sourceRef: "src/engine/hermes_bootstrap.cc#installSharedRuntimeBundle",
      requiredFacts: ["shared-runtime-loaded"],
    },
    {
      surfaceName: "capability-hardening-seal",
      postcondition: "capability-hatches-sealed",
      sourceRef: "src/engine/hermes_runtime.cc#kCapabilityHardeningJS",
      requiredFacts: ["capability-hatches-absent"],
    },
    {
      surfaceName: "eager-native-seal",
      postcondition: "lazy-installers-sealed",
      sourceRef: "src/engine/hermes_runtime.cc#kEagerInstallSealJS",
      requiredFacts: ["lazy-installers-absent"],
    },
    {
      surfaceName: "lockdown-install",
      postcondition: "lockdown-installed",
      sourceRef: "src/engine/hermes_runtime.cc#lockdownJS",
      requiredFacts: [
        "lockdown-flag-pinned",
        "eval-tamed",
        "object-prototype-frozen",
      ],
    },
    {
      surfaceName: "freeze-seal",
      postcondition: "freeze-hatches-sealed",
      sourceRef: "src/engine/hermes_runtime.cc#kFreezeSealJS",
      requiredFacts: ["freeze-hatches-absent"],
    },
    {
      surfaceName: "compartment-registry-install",
      postcondition: "compartment-registry-installed",
      sourceRef: "src/engine/hermes_runtime.cc#kCompartmentRegistryJS",
      requiredFacts: ["compartment-registry-pinned"],
    },
    {
      surfaceName: "web-streams-install",
      postcondition: "web-streams-installed",
      sourceRef: "src/engine/hermes_bootstrap.cc#installWebStreamsPolyfill",
      requiredFacts: ["web-stream-constructors-installed"],
      environment: {
        name: "EX_WEB_STREAMS_POLYFILL",
        value: "1",
      },
    },
  ].map((stage) => [stage.surfaceName, Object.freeze(stage)]),
);

export function authoredStartupPublicProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    plan.classification !== "non-capability" ||
    scenario !== "non-capability" ||
    plan.expectedObservation?.kind !== "enforcement-branch" ||
    plan.edgeIds.length !== 1 ||
    plan.actionIds.length !== 0 ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  if (!surfaceObservedKey.startsWith("startup:")) return null;
  const live = liveByObservedKey.get(surfaceObservedKey);
  const edge = coverageByObservedKey.get(surfaceObservedKey);
  const stage = STARTUP_STAGES.get(live?.name);
  if (
    live?.kind !== "startup" ||
    stage === undefined ||
    !Array.isArray(live.sourceRefs) ||
    canonicalJson(live.sourceRefs) !== canonicalJson([stage.sourceRef]) ||
    (live.metadata ?? null) !== null ||
    edge?.id !== plan.edgeIds[0] ||
    edge.classification !== "non-capability" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey
  ) {
    return null;
  }
  const sourceDescriptor = {
    kind: "startup-loaded-engine-postcondition",
    surfaceName: stage.surfaceName,
    postcondition: stage.postcondition,
    requiredFacts: [...stage.requiredFacts],
    sourceRefs: [...live.sourceRefs],
    sourceMetadata: null,
    environment: structuredClone(stage.environment ?? null),
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...STARTUP_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-startup-surface-invocation/1",
      kind: "startup-loaded-engine",
      surfaceKind: "startup",
      surfaceName: stage.surfaceName,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: "loaded-engine-startup",
        postcondition: stage.postcondition,
        requiredFacts: [...stage.requiredFacts],
        environment: structuredClone(stage.environment ?? null),
      },
      expectedResult: "return",
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}

export const startupBatchCommand = STARTUP_BATCH_COMMAND;
export const startupStages = STARTUP_STAGES;
