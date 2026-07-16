/**
 * Source-bound public executions for exact callback/control-plane mechanisms.
 * Generic rationale-wide invariant checks are deliberately not authored as
 * per-surface probes: async attribution is secured channel-by-channel, so a
 * passing check on one mechanism cannot prove that an arbitrary static carrier
 * entered its body or used that mechanism.
 *
 * @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence —
 * callback principals, snapshot identities, and mutable authority generations
 * must remain bound across asynchronous delivery.
 * @ref LLP 0016#weak-points-and-biggest-risks — async attribution is secured
 * channel-by-channel, so conformance must not generalize across carriers.
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
}) {
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
  // The callback/control scenarios remain useful diagnostic smoke tests, but
  // only these six exact embedder mechanisms have source-bound body/lifecycle
  // evidence that may close a recipe. Leave every rationale-only row residual.
  if (!exactEmbedder) return null;
  const template = exactEmbedder;
  if (!template) return null;
  const expectedRationale = exactEmbedder.rationaleId;
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

  const sourceDescriptor = {
    kind: "callback-security-invariant",
    proofScope: "source-bound-exact-mechanism",
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
    auxiliaryDecisionEdgeId: null,
  };
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
      expectedTypedDecisionCount: 0,
      expectedTypedStages: [],
      expectedTypedOutcomes: [],
      expectedTypedReasons: [],
      allowedCoverageEdgeIds: [],
      expectedActionIds: [],
    },
  };
}
