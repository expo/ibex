/**
 * Internal CapSec invariant proof vocabulary.
 *
 * These scenarios describe runtime-owned transitions rather than public
 * JavaScript calls. A recipe may classify one as internally verified, but the
 * conformance report must still consume executed proof before crediting it.
 *
 * @ref LLP 0036#the-design-question-and-its-resolved-direction
 * @ref LLP 0036#correctness-owed-the-deliberately-deferred-verification
 */
import crypto from "node:crypto";
import { canonicalJson } from "./capsec-contract.mjs";
import { capsecSecureCargoTestCommand } from "./capsec-secure-test-command.mjs";

export const INTERNAL_INVARIANT_EXECUTOR =
  "ibex-internal-invariant-proof-harness-v1";

export const INTERNAL_INVARIANT_COMMAND = Object.freeze(
  capsecSecureCargoTestCommand(
    "capsec_internal_invariant_evidence_batch",
    true,
  ),
);

export const INTERNALLY_VERIFIED_SCENARIOS = Object.freeze([
  "attribution-missing-deny",
  "cannot-widen-authority",
  "generation-recheck",
  "post-lockdown-invariant",
  "principal-restore",
  "snapshot-mismatch-deny",
]);

export const internallyVerifiedScenario = (scenario) =>
  INTERNALLY_VERIFIED_SCENARIOS.includes(scenario);

const PROOF_MECHANISMS = Object.freeze({
  "attribution-missing-deny": Object.freeze({
    mechanism: "scheduled-public-attribution-guard",
    sourceRef:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_attribution_missing",
  }),
  "cannot-widen-authority": Object.freeze({
    mechanism: "typed-grant-ceiling-refusal",
    sourceRef:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_cannot_widen",
  }),
  "generation-recheck": Object.freeze({
    mechanism: "scheduled-public-environment-revocation-recheck",
    sourceRef:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_generation_recheck",
  }),
  "post-lockdown-invariant": Object.freeze({
    mechanism: "lockdown-tamper-and-grant-refusal",
    sourceRef:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_post_lockdown",
  }),
  "principal-restore": Object.freeze({
    mechanism: "scheduled-package-principal-scope",
    sourceRef:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_principal_restore",
  }),
  "snapshot-mismatch-deny": Object.freeze({
    mechanism: "cross-snapshot-public-handle-reattenuation",
    sourceRef:
      "src/bin/ibex/engine/capsec_public_callback_invariant_batch.rs#execute_snapshot_mismatch",
  }),
});

const digest = (value) =>
  `sha256-${crypto
    .createHash("sha256")
    .update(canonicalJson(value), "utf8")
    .digest("base64url")}`;

export function computeInternalInvariantProofPlanDigest(plan) {
  const { proofPlanDigest: _digest, ...payload } = plan;
  return digest(payload);
}

export function internalInvariantProofPlan(scenario) {
  const proof = PROOF_MECHANISMS[scenario];
  if (!proof || !internallyVerifiedScenario(scenario)) return null;
  const plan = {
    proofPlanSchema: "ibex/capsec-internal-invariant-proof-plan/1",
    scenario,
    mechanism: proof.mechanism,
    sourceRef: proof.sourceRef,
    executor: INTERNAL_INVARIANT_EXECUTOR,
    command: [...INTERNAL_INVARIANT_COMMAND],
    proofPlanDigest:
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  plan.proofPlanDigest = computeInternalInvariantProofPlanDigest(plan);
  return plan;
}
