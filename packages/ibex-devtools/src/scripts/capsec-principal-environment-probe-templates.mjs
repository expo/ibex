/**
 * Source-bound public probes for the dynamic process.env property overlay.
 *
 * The public carrier is the reviewed Proxy trap in the shared runtime. The
 * independently observed typed decision belongs to the captured native bridge;
 * keeping both identities in the descriptor prevents the carrier from claiming
 * an arbitrary environment decision.
 *
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — every
 * process.env property operation remains bound to the current principal's
 * exact-name overlay.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * promotion requires an exact loaded-engine source execution and independently
 * observed typed decisions.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

const PRINCIPAL_ENVIRONMENT_BATCH_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand("capsec_public_startup_environment_batch"),
);

const SURFACE_OBSERVED_KEY =
  "native-op:global:process.env.[[dynamic-table:principal-environment-overlay-properties]]";
const SOURCE_CONTRACT_SCHEMA =
  "ibex/principal-environment-overlay-source-contract/1";
const DYNAMIC_MEMBER =
  "[[dynamic-table:principal-environment-overlay-properties]]";
const ENVIRONMENT_NAME = "IBEX_CAPSEC_PUBLIC_ENV_PROPERTY";
const SUPPORTED_SCENARIOS = new Set(["allow", "deny", "branch-selection"]);
const AUXILIARY_OBSERVED_KEYS = new Map([
  ["env:read", "native-op:__exactGetEnv"],
  ["env:write", "native-op:__exactSetEnv"],
]);
const EXPECTED_TRAP = new Map([
  ["env:read", { name: "get", bridge: "__exactGetEnv" }],
  ["env:write", { name: "set", bridge: "__exactSetEnv" }],
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

function reviewedSourceContract(live, actionId) {
  const contract =
    live?.metadata?.principalEnvironmentOverlaySourceContract ?? null;
  const expectedTrap = EXPECTED_TRAP.get(actionId);
  const trap = contract?.proxyTraps?.find(
    (candidate) => candidate.name === expectedTrap?.name,
  );
  if (
    live?.kind !== "native-op" ||
    live.name !== SURFACE_OBSERVED_KEY.slice("native-op:".length) ||
    live.observedKey !== SURFACE_OBSERVED_KEY ||
    !Array.isArray(live.sourceRefs) ||
    live.sourceRefs.length !== 6 ||
    contract?.schema !== SOURCE_CONTRACT_SCHEMA ||
    contract.surfaceName !== live.name ||
    contract.dynamicMember !== DYNAMIC_MEMBER ||
    contract.globalPath !== "process.env" ||
    contract.binding?.factory !== "createEnvProxy" ||
    contract.binding?.member !== "Process.prototype.env" ||
    contract.factory?.name !== "createEnvProxy" ||
    canonicalJson(contract.nativeBridges) !==
      canonicalJson(["__exactGetAllEnv", "__exactGetEnv", "__exactSetEnv"]) ||
    canonicalJson(contract.sourceRefs) !== canonicalJson(live.sourceRefs) ||
    contract.proxyTraps?.length !== 4 ||
    trap?.sourceRef !==
      `packages/ibex-runtime-js/src/node/process.ts#createEnvProxy:Proxy.${expectedTrap?.name}` ||
    !trap.nativeBridges?.includes(expectedTrap?.bridge) ||
    !live.metadata?.semanticRoles?.includes(
      "principal-environment-overlay",
    ) ||
    !live.metadata?.semanticRoles?.includes("runtime-property-overlay")
  ) {
    return null;
  }
  return { contract, trap };
}

export function authoredPrincipalEnvironmentProbe({
  plan,
  scenario,
  route,
  liveByObservedKey,
  coverageByObservedKey,
}) {
  if (
    plan.classification !== "effects" ||
    !SUPPORTED_SCENARIOS.has(scenario) ||
    route.surfaceObservedKeys.length !== 1 ||
    route.surfaceObservedKeys[0] !== SURFACE_OBSERVED_KEY ||
    route.alternatives.length !== 1 ||
    route.alternatives[0].terminalObservedKey !== SURFACE_OBSERVED_KEY ||
    canonicalJson(route.alternatives[0].proofPaths) !==
      canonicalJson([SURFACE_OBSERVED_KEY]) ||
    route.ambiguousCallees.length !== 0 ||
    plan.actionIds.length !== 1
  ) {
    return null;
  }

  const actionId = plan.actionIds[0];
  const operationKind =
    actionId === "env:read"
      ? "read"
      : actionId === "env:write"
        ? "write"
        : null;
  const reviewed = reviewedSourceContract(
    liveByObservedKey.get(SURFACE_OBSERVED_KEY),
    actionId,
  );
  const carrierEdge = coverageByObservedKey.get(SURFACE_OBSERVED_KEY);
  const selectedBranch = carrierEdge?.logicalBranches?.find(
    (branch) => branch.id === operationKind,
  );
  const auxiliaryObservedKey = AUXILIARY_OBSERVED_KEYS.get(actionId);
  const auxiliaryEdge = coverageByObservedKey.get(auxiliaryObservedKey);
  if (
    !operationKind ||
    !reviewed ||
    carrierEdge?.id !== plan.edgeIds[0] ||
    carrierEdge.classification !== "effects" ||
    carrierEdge.effectMode !== "conditional" ||
    canonicalJson(actionIdsForEffects(selectedBranch?.effects)) !==
      canonicalJson([actionId]) ||
    canonicalJson(selectedBranch?.when) !==
      canonicalJson([
        {
          fact: "environment.property.operation",
          equals: operationKind,
        },
      ]) ||
    auxiliaryEdge?.classification !== "effects" ||
    canonicalJson(actionIdsForEffects(auxiliaryEdge.effects)) !==
      canonicalJson([actionId]) ||
    !["requested", "commit"].every((stage) =>
      auxiliaryEdge.effects?.[0]?.stages?.includes(stage),
    )
  ) {
    return null;
  }

  const publicDenial = scenario === "deny";
  const principalMode = publicDenial
    ? "package-denied"
    : "root-authorized";
  const sourceDescriptor = {
    kind: "principal-environment-property",
    surfaceObservedKey: SURFACE_OBSERVED_KEY,
    carrierEdgeId: carrierEdge.id,
    implementationBranchIds: clone(plan.implementationBranchIds),
    enforcementBranchIds: clone(plan.enforcementBranchIds),
    selectedBranch: clone(selectedBranch),
    sourceContract: clone(reviewed.contract),
    selectedProxyTrap: clone(reviewed.trap),
    auxiliaryObservedKey,
    auxiliaryDecisionEdgeId: auxiliaryEdge.id,
    principalMode,
  };
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey: SURFACE_OBSERVED_KEY,
    command: [...PRINCIPAL_ENVIRONMENT_BATCH_COMMAND],
    invocation: {
      invocationSchema: "ibex/capsec-principal-environment-invocation/1",
      kind: "principal-environment-property",
      scenario,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      operation: {
        kind: operationKind,
        environmentName: ENVIRONMENT_NAME,
        value: operationKind === "write" ? "ibex-capsec-value" : null,
        principalMode,
      },
      expectedResult:
        publicDenial && operationKind === "write"
          ? "permission-denied"
          : "return",
      expectedTypedDecisionCount: publicDenial ? 1 : 2,
      expectedTypedStages: publicDenial
        ? ["requested"]
        : ["requested", "commit"],
      expectedTypedOutcomes: publicDenial ? ["deny"] : ["allow", "allow"],
      expectedTypedReasons: publicDenial
        ? ["principal-denial"]
        : ["static-floor", "static-floor"],
      allowedCoverageEdgeIds: [auxiliaryEdge.id],
      expectedActionIds: [actionId],
      expectedResourceNames: [ENVIRONMENT_NAME],
    },
  };
}

export const principalEnvironmentBatchCommand =
  PRINCIPAL_ENVIRONMENT_BATCH_COMMAND;
