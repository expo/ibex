/**
 * Source-bound loaded-engine probes for startup-environment inventory edges
 * whose production JavaScript source performs a typed process.env read.
 *
 * The startup edge is a source carrier: the production read is authorized by
 * the separately reviewed __exactGetEnv edge. Keep both identities explicit
 * so runtime evidence cannot relabel a generic environment read as an
 * arbitrary scanner occurrence.
 *
 * @ref LLP 0021#typed-resources-and-initial-vocabulary — environment
 * authority is bound to one exact name, never wildcard enumeration.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * promotion requires an exact loaded-engine source execution and independently
 * observed typed decisions.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

const STARTUP_ENVIRONMENT_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand("capsec_public_startup_environment_batch"),
);

const ENVIRONMENT_AUXILIARY_OBSERVED_KEY = "native-op:__exactGetEnv";
const STARTUP_ENVIRONMENT_SCENARIOS = new Set([
  "allow",
  "deny",
  "malformed",
  "missing-attribution",
  "wrong-principal",
  "branch-selection",
]);

const STARTUP_ENVIRONMENT_SOURCES = new Map([
  [
    "startup:env:NODE_DEBUG",
    Object.freeze({
      environmentName: "NODE_DEBUG",
      sourceRef: "src/builtins/http.js#process.env:NODE_DEBUG:read",
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:http",
      preloadModuleSpecifiers: ["node:events", "node:stream", "node:util"],
      observedEnvironmentNames: ["NODE_DEBUG"],
      selectedBranchId: "absent",
      supportedScenarios: STARTUP_ENVIRONMENT_SCENARIOS,
    }),
  ],
  [
    "startup:env:EXACT_DEBUG_EMIT_LISTENER",
    Object.freeze({
      environmentName: "EXACT_DEBUG_EMIT_LISTENER",
      sourceRef:
        "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
      mechanism: "event-emitter-emit",
      moduleSpecifier: "node:events",
      preloadModuleSpecifiers: [],
      observedEnvironmentNames: ["EXACT_DEBUG_EMIT_LISTENER"],
      selectedBranchId: "absent",
      supportedScenarios: STARTUP_ENVIRONMENT_SCENARIOS,
    }),
  ],
  [
    "startup:env:TZ",
    Object.freeze({
      environmentName: "TZ",
      sourceRef:
        "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
      mechanism: "date-to-string",
      moduleSpecifier: null,
      preloadModuleSpecifiers: [],
      observedEnvironmentNames: ["TZ"],
      selectedBranchId: "absent",
      supportedScenarios: STARTUP_ENVIRONMENT_SCENARIOS,
    }),
  ],
  [
    "startup:env:EXACT_PIPELINE_DEBUG",
    Object.freeze({
      environmentName: "EXACT_PIPELINE_DEBUG",
      sourceRef:
        "src/builtins/stream.js#process.env:EXACT_PIPELINE_DEBUG:read",
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:stream",
      preloadModuleSpecifiers: [
        "node:events",
        "node:string_decoder",
        "node:util",
      ],
      observedEnvironmentNames: [
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ],
      selectedBranchId: "absent",
      supportedScenarios: STARTUP_ENVIRONMENT_SCENARIOS,
    }),
  ],
  [
    "startup:env:EXACT_PIPELINE_STATE_DEBUG",
    Object.freeze({
      environmentName: "EXACT_PIPELINE_STATE_DEBUG",
      sourceRef:
        "src/builtins/stream.js#process.env:EXACT_PIPELINE_STATE_DEBUG:read",
      mechanism: "builtin-module-load",
      moduleSpecifier: "node:stream",
      preloadModuleSpecifiers: [
        "node:events",
        "node:string_decoder",
        "node:util",
      ],
      observedEnvironmentNames: [
        "EXACT_PIPELINE_DEBUG",
        "EXACT_PIPELINE_STATE_DEBUG",
      ],
      selectedBranchId: "absent",
      supportedScenarios: STARTUP_ENVIRONMENT_SCENARIOS,
    }),
  ],
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const clone = (value) => structuredClone(value);
const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const actionIdsForEffects = (effects) =>
  [...new Set((effects ?? []).map((effect) => effect.cap))].sort(compareText);

export function authoredStartupEnvironmentProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    plan.classification !== "effects" ||
    plan.expectedObservation?.kind !== "enforcement-branch" ||
    route.surfaceObservedKeys.length !== 1 ||
    route.alternatives.length !== 1 ||
    route.ambiguousCallees.length !== 0
  ) {
    return null;
  }
  const surfaceObservedKey = route.surfaceObservedKeys[0];
  const template = STARTUP_ENVIRONMENT_SOURCES.get(surfaceObservedKey);
  if (!template?.supportedScenarios.has(scenario)) return null;

  const live = liveByObservedKey.get(surfaceObservedKey);
  const carrierEdge = coverageByObservedKey.get(surfaceObservedKey);
  const auxiliaryEdge = coverageByObservedKey.get(
    ENVIRONMENT_AUXILIARY_OBSERVED_KEY,
  );
  const selectedBranch = carrierEdge?.logicalBranches?.find(
    (branch) => branch.id === template.selectedBranchId,
  );
  if (
    live?.kind !== "startup" ||
    live.name !== `env:${template.environmentName}` ||
    !Array.isArray(live.sourceRefs) ||
    !live.sourceRefs.includes(template.sourceRef) ||
    carrierEdge?.id !== plan.edgeIds[0] ||
    carrierEdge.classification !== "effects" ||
    carrierEdge.effectMode !== "conditional" ||
    !selectedBranch ||
    canonicalJson(actionIdsForEffects(selectedBranch.effects)) !==
      canonicalJson(plan.actionIds) ||
    selectedBranch.when?.length !== 1 ||
    selectedBranch.when[0]?.fact !==
      `environment.startup.${template.environmentName.toLowerCase()}` ||
    selectedBranch.when[0]?.equals !== "absent" ||
    route.alternatives[0].terminalObservedKey !== surfaceObservedKey ||
    auxiliaryEdge?.classification !== "effects" ||
    auxiliaryEdge.effects?.length !== 1 ||
    auxiliaryEdge.effects[0]?.cap !== "env:read" ||
    !["requested", "commit"].every((stage) =>
      auxiliaryEdge.effects[0].stages?.includes(stage),
    )
  ) {
    return null;
  }

  const publicDenial = scenario === "deny";
  const principalMode = publicDenial ? "package-denied" : "root-authorized";
  const observedEnvironmentNames = [...template.observedEnvironmentNames].sort(
    compareText,
  );
  const expectedStagesPerResource = publicDenial
    ? ["requested"]
    : ["requested", "commit"];
  const expectedOutcomesPerResource = publicDenial
    ? ["deny"]
    : ["allow", "allow"];
  const expectedReasonsPerResource = publicDenial
    ? ["principal-denial"]
    : ["static-floor", "static-floor"];
  const sourceDescriptor = {
    kind: "startup-environment-source",
    surfaceObservedKey,
    environmentName: template.environmentName,
    sourceRef: template.sourceRef,
    liveSourceRefs: clone(live.sourceRefs),
    carrierEdgeId: carrierEdge.id,
    implementationBranchIds: clone(plan.implementationBranchIds),
    enforcementBranchIds: clone(plan.enforcementBranchIds),
    selectedBranch: clone(selectedBranch),
    executionMechanism: template.mechanism,
    moduleSpecifier: template.moduleSpecifier,
    preloadModuleSpecifiers: clone(template.preloadModuleSpecifiers),
    observedEnvironmentNames,
    principalMode,
    auxiliaryDecisionEdgeId: auxiliaryEdge.id,
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: [...STARTUP_ENVIRONMENT_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-startup-environment-invocation/1",
      kind: "startup-environment-source",
      scenario,
      surfaceKind: "startup",
      surfaceName: `env:${template.environmentName}`,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: template.mechanism,
        moduleSpecifier: template.moduleSpecifier,
        preloadModuleSpecifiers: clone(template.preloadModuleSpecifiers),
        observedEnvironmentNames,
        environment: {
          name: template.environmentName,
          presence: "absent",
        },
        principalMode,
      },
      // Armed process.env has an empty base and exact per-principal overlays.
      // The hardened proxy converts a denied overlay read to undefined. The
      // source therefore takes its safe absent branch while the observer
      // independently records the requested-stage denial.
      // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
      expectedResult: "return",
      expectedTypedDecisionCount:
        observedEnvironmentNames.length * expectedStagesPerResource.length,
      expectedTypedStages: observedEnvironmentNames.flatMap(
        () => expectedStagesPerResource,
      ),
      expectedTypedOutcomes: observedEnvironmentNames.flatMap(
        () => expectedOutcomesPerResource,
      ),
      expectedTypedReasons: observedEnvironmentNames.flatMap(
        () => expectedReasonsPerResource,
      ),
      allowedCoverageEdgeIds: [auxiliaryEdge.id],
      expectedActionIds: ["env:read"],
      expectedResourceNames: observedEnvironmentNames,
    },
  };
}

export const startupEnvironmentBatchCommand =
  STARTUP_ENVIRONMENT_BATCH_COMMAND;
