/**
 * Source-bound public executions for the callback-attribution and authority
 * control-plane invariants. These surfaces are not effects themselves, but
 * their security classification is meaningful only when an exact armed engine
 * proves the associated attribution/authority invariant at runtime.
 *
 * @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence —
 * callback principals, snapshot identities, and mutable authority generations
 * must remain bound across asynchronous delivery.
 */

import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";

const CALLBACK_BATCH_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_public_callback_invariant_batch",
  "--",
  "--test-threads=1",
]);

const CALLBACK_SCENARIOS = new Map([
  [
    "attribution-missing-deny",
    {
      mechanism: "scheduled-public-attribution-guard",
      auxiliaryObservedKey: "native-op:__exactGetEnv",
      action: "env:read",
      stages: ["requested", "commit"],
      outcomes: ["allow", "allow"],
      reasons: ["ambient-root", "ambient-root"],
    },
  ],
  [
    "generation-recheck",
    {
      mechanism: "scheduled-public-environment-revocation-recheck",
      auxiliaryObservedKey: "native-op:__exactGetEnv",
      action: "env:read",
      stages: ["requested", "commit", "requested"],
      outcomes: ["allow", "allow", "deny"],
      reasons: ["dynamic-session", "dynamic-session", "missing-authority"],
    },
  ],
  [
    "principal-restore",
    {
      mechanism: "scheduled-package-principal-scope",
      auxiliaryObservedKey: "native-op:__exactGetEnv",
      action: "env:read",
      stages: ["requested", "commit", "requested", "commit"],
      outcomes: ["allow", "allow", "allow", "allow"],
      reasons: ["static-floor", "static-floor", "ambient-root", "ambient-root"],
    },
  ],
  [
    "snapshot-mismatch-deny",
    {
      mechanism: "cross-snapshot-public-handle-reattenuation",
      auxiliaryObservedKey: null,
      action: null,
      stages: [],
      outcomes: [],
      reasons: [],
    },
  ],
]);

const CONTROL_SCENARIOS = new Map([
  [
    "cannot-widen-authority",
    {
      mechanism: "typed-grant-ceiling-refusal",
      outcomes: [],
      reasons: [],
    },
  ],
  [
    "post-lockdown-invariant",
    {
      mechanism: "lockdown-tamper-and-grant-refusal",
      outcomes: [],
      reasons: [],
    },
  ],
]);

const EXACT_EMBEDDER_NON_CAPABILITY_MECHANISMS = new Map([
  [
    "callback:exact-host-call-async-resolve",
    {
      mechanism: "exact-host-call-round-trip",
      rationaleId: "callback-attribution-carrier",
    },
  ],
  [
    "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback",
    {
      mechanism: "exact-host-call-round-trip",
      rationaleId: "callback-attribution-carrier",
    },
  ],
  [
    "host-abi:ex_hermes_resolve_exact_host_call",
    {
      mechanism: "exact-host-call-round-trip",
      rationaleId: "callback-attribution-carrier",
    },
  ],
  [
    "host-abi:ex_hermes_set_exact_host_call_async",
    {
      mechanism: "exact-endowment-install",
      rationaleId: "authority-control-plane",
    },
  ],
  [
    "host-abi:ex_host_authorize_exact_endowment",
    {
      mechanism: "exact-endowment-authorize",
      rationaleId: "authority-control-plane",
    },
  ],
  [
    "host-abi:ex_host_prepare_armed_embedder_artifacts",
    {
      mechanism: "exact-artifact-prepare-round-trip",
      rationaleId: "authority-control-plane",
    },
  ],
]);

const taggedDigest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

const clone = (value) => structuredClone(value);

function observedKeyForEdge(edge) {
  return `${edge.surface.kind}:${edge.surface.name}`;
}

export function authoredCallbackInvariantProbe({
  plan,
  scenario,
  rows,
  route,
  liveByObservedKey,
  coverageByEdge,
  coverageByObservedKey,
}) {
  const callback = CALLBACK_SCENARIOS.get(scenario);
  const control = CONTROL_SCENARIOS.get(scenario);
  if (plan.classification !== "non-capability") return null;
  if (
    plan.actionIds.length !== 0 ||
    plan.edgeIds.length !== 1 ||
    plan.implementationBranchIds.length !== 1 ||
    rows.length !== 1
  ) {
    return null;
  }

  const edge = coverageByEdge.get(plan.edgeIds[0]);
  const row = rows[0];
  if (
    !edge ||
    edge.classification !== "non-capability" ||
    row.edgeId !== edge.id ||
    row.branchId !== plan.implementationBranchIds[0] ||
    row.enforcementBranchId !== plan.enforcementBranchIds[0]
  ) {
    return null;
  }
  const surfaceObservedKey = observedKeyForEdge(edge);
  const exactEmbedder =
    scenario === "non-capability"
      ? EXACT_EMBEDDER_NON_CAPABILITY_MECHANISMS.get(surfaceObservedKey)
      : null;
  const template = callback ?? control ?? exactEmbedder;
  if (!template) return null;
  const expectedRationale =
    exactEmbedder?.rationaleId ??
    (callback ? "callback-attribution-carrier" : "authority-control-plane");
  if (edge.rationaleId !== expectedRationale) return null;

  const live = liveByObservedKey.get(surfaceObservedKey);
  if (
    !live ||
    live.kind !== edge.surface.kind ||
    live.name !== edge.surface.name ||
    plan.terminalObservedKey !== surfaceObservedKey ||
    !route.surfaceObservedKeys.includes(surfaceObservedKey) ||
    !row.sourceRefs.some((sourceRef) => live.sourceRefs.includes(sourceRef))
  ) {
    return null;
  }

  const auxiliaryEdge = callback?.auxiliaryObservedKey
    ? coverageByObservedKey.get(callback.auxiliaryObservedKey)
    : null;
  if (
    callback?.auxiliaryObservedKey &&
    (!auxiliaryEdge ||
      auxiliaryEdge.classification !== "effects" ||
      auxiliaryEdge.effects?.length !== 1 ||
      auxiliaryEdge.effects[0].cap !== callback.action ||
      !callback.stages.every((stage) =>
        auxiliaryEdge.effects[0].stages.includes(stage),
      ))
  ) {
    return null;
  }

  const sourceDescriptor = {
    kind: "callback-security-invariant",
    scenario,
    rationaleId: edge.rationaleId,
    surfaceObservedKey,
    edgeId: edge.id,
    branchId: row.branchId,
    sourceRefs: clone(row.sourceRefs),
    coverageEdge: clone(edge),
    implementationBranch: clone(row),
    liveSurface: clone(live),
    executionMechanism: template.mechanism,
    auxiliaryDecisionEdgeId: auxiliaryEdge?.id ?? null,
  };
  const expectedOutcomes = template.outcomes ?? [];
  const expectedReasons = template.reasons ?? [];
  const expectedTypedDecisionCount = expectedOutcomes.length;
  if (
    callback &&
    (callback.stages.length !== expectedTypedDecisionCount ||
      expectedReasons.length !== expectedTypedDecisionCount)
  ) {
    throw new Error(`callback template ${scenario} has inconsistent decision arrays`);
  }
  return {
    kind: "public-surface-invocation",
    surfaceObservedKey,
    command: clone(CALLBACK_BATCH_COMMAND),
    invocation: {
      invocationSchema: "ibex/capsec-callback-invariant-invocation/1",
      kind: "callback-security-invariant",
      scenario,
      surfaceKind: edge.surface.kind,
      surfaceName: edge.surface.name,
      sourceDescriptor,
      sourceDescriptorDigest: taggedDigest(sourceDescriptor),
      expectedResult: "invariant-passed",
      expectedTypedDecisionCount,
      expectedTypedStages: clone(callback?.stages ?? []),
      expectedTypedOutcomes: clone(expectedOutcomes),
      expectedTypedReasons: clone(expectedReasons),
      allowedCoverageEdgeIds: auxiliaryEdge ? [auxiliaryEdge.id] : [],
      expectedActionIds: auxiliaryEdge ? [callback.action] : [],
    },
  };
}
