/**
 * Target-runner contract for inherited intrinsic alias evidence.
 *
 * This layer deliberately separates a valid observation from all-profile
 * closure.  Each target receives one content-addressed probe plan, the Rust
 * batch executes it in the actually loaded Ibex Hermes runtime, and this
 * module authenticates the returned image identity and observation.  Missing
 * target records remain named blockers; they are never replaced with a host
 * realm or a copied observation.
 *
 * A mapped-byte identity is not, by itself, proof of a source-build pin or a
 * Maven/NuGet coordinate. Until those installation paths emit independently
 * checkable provenance receipts, even a complete execution set stays
 * ineligible for structural accounts and names that residual explicitly.
 *
 * @ref LLP 0013#mechanism-1-lockdown — alias identity and the complete
 * inherited member graph are part of the shared-intrinsic boundary.
 * @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
 * target evidence must come from the exact loaded engine and target.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./capsec-contract.mjs";
import {
  auditLoadedInheritedIntrinsicAliasExecution,
  inheritedIntrinsicAliasProbe,
} from "./capsec-inherited-intrinsic-alias-accounts.mjs";

export const INHERITED_INTRINSIC_ALIAS_EXECUTION_PLAN_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-execution-plan/1";
export const INHERITED_INTRINSIC_ALIAS_BATCH_EVIDENCE_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-loaded-execution/1";
export const INHERITED_INTRINSIC_ALIAS_EXECUTION_LEDGER_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-execution-ledger/1";
export const INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_SCHEMA =
  "ibex/capsec-inherited-intrinsic-alias-target-record/1";
export const INHERITED_INTRINSIC_ALIAS_MISSING_EXECUTION_CODE =
  "missing-authenticated-loaded-profile-execution";
export const INHERITED_INTRINSIC_ALIAS_PROFILE_PROVENANCE_CODE =
  "loaded-engine-reviewed-profile-provenance-unverified";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const EXECUTOR_CONTRACT_PATH =
  "src/bin/ibex/engine/capsec_inherited_intrinsic_alias_batch.test.rs";
const EXECUTION_COMMAND = Object.freeze([
  "cargo",
  "test",
  "--bin",
  "ibex",
  "--features",
  "capsec-conformance-observer",
  "capsec_inherited_intrinsic_alias_loaded_execution",
  "--",
  "--test-threads=1",
  "--nocapture",
]);
const EXECUTION_ENVIRONMENT_KEYS = Object.freeze([
  "IBEX_CAPSEC_INTRINSIC_ALIAS_EVIDENCE_OUTPUT",
  "IBEX_CAPSEC_INTRINSIC_ALIAS_PLAN",
]);

const PLAN_DIGEST_DOMAIN =
  "ibex.capsec.inherited-intrinsic-alias.execution-plan.v1";
const LEDGER_DIGEST_DOMAIN =
  "ibex.capsec.inherited-intrinsic-alias.execution-ledger.v1";

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256Hex(value) {
  return `sha256-${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function taggedDigest(domain, value) {
  return sha256Hex(`${domain}\0${canonicalJson(value)}`);
}

export const INHERITED_INTRINSIC_ALIAS_EXECUTOR_CONTRACT_DIGEST = sha256Hex(
  fs.readFileSync(path.join(repoRoot, EXECUTOR_CONTRACT_PATH)),
);

function exactFields(value, fields) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort(compareText)) ===
      canonicalJson([...fields].sort(compareText))
  );
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function clone(value) {
  return structuredClone(value);
}

function profileFor(sourceAudit, profileId) {
  const profile = sourceAudit?.profiles?.find(
    (candidate) => candidate?.id === profileId,
  );
  if (!profile) throw new Error(`unknown inherited intrinsic profile ${profileId}`);
  return profile;
}

function canonicalTargetFromProbe(probe) {
  return {
    triple: probe.binding.targetTriple,
    features: [...probe.binding.structuralFeatures],
  };
}

export function inheritedIntrinsicAliasExecutionPlan({
  sourceAudit,
  profileId,
  target,
}) {
  const probe = inheritedIntrinsicAliasProbe({ sourceAudit, profileId, target });
  const profile = profileFor(sourceAudit, profileId);
  const unsignedPlan = {
    schema: INHERITED_INTRINSIC_ALIAS_EXECUTION_PLAN_SCHEMA,
    profileId: profile.id,
    targetVariant: profile.targetVariant,
    target: canonicalTargetFromProbe(probe),
    executorContractDigest:
      INHERITED_INTRINSIC_ALIAS_EXECUTOR_CONTRACT_DIGEST,
    reviewedProfileIdentity: clone(profile.identity),
    sourceReviewDigest: sourceAudit.sourceReviewDigest,
    profileReviewDigest: sourceAudit.profileReviewDigest,
    probe: {
      schema: probe.schema,
      source: probe.source,
      sourceDigest: probe.sourceDigest,
    },
  };
  return deepFreeze({
    ...unsignedPlan,
    planDigest: taggedDigest(PLAN_DIGEST_DOMAIN, unsignedPlan),
  });
}

function rawExecutionFromEvidence(sourceAudit, evidence) {
  if (
    !exactFields(evidence, [
      "loadedEngineIdentity",
      "observation",
      "executorContractDigest",
      "planDigest",
      "probeSourceDigest",
      "profileId",
      "schema",
      "target",
      "targetVariant",
    ]) ||
    evidence.schema !== INHERITED_INTRINSIC_ALIAS_BATCH_EVIDENCE_SCHEMA ||
    typeof evidence.profileId !== "string"
  ) {
    throw new Error("loaded intrinsic batch evidence has malformed exact fields");
  }
  const plan = inheritedIntrinsicAliasExecutionPlan({
    sourceAudit,
    profileId: evidence.profileId,
    target: evidence.target,
  });
  if (
    evidence.planDigest !== plan.planDigest ||
    evidence.executorContractDigest !== plan.executorContractDigest ||
    evidence.targetVariant !== plan.targetVariant ||
    canonicalJson(evidence.target) !== canonicalJson(plan.target) ||
    evidence.probeSourceDigest !== plan.probe.sourceDigest
  ) {
    throw new Error("loaded intrinsic batch evidence is not bound to its plan");
  }
  const identity = evidence.loadedEngineIdentity;
  return {
    profileId: evidence.profileId,
    targetVariant: evidence.targetVariant,
    target: clone(evidence.target),
    probeSourceDigest: evidence.probeSourceDigest,
    observation: clone(evidence.observation),
    engine: {
      canonicalArtifactPath: identity?.engineArtifactPath,
      binaryDigest: identity?.binaryDigest,
      expectedObject: clone(identity?.object),
      identity: clone(identity),
    },
  };
}

export function auditInheritedIntrinsicAliasBatchEvidence({
  sourceAudit,
  evidence,
}) {
  const rawExecution = rawExecutionFromEvidence(sourceAudit, evidence);
  const execution = auditLoadedInheritedIntrinsicAliasExecution({
    sourceAudit,
    execution: rawExecution,
  });
  return deepFreeze({
    evidence: clone(evidence),
    execution,
    rawExecution,
  });
}

function validateCommandStream(stream, label) {
  if (
    !exactFields(stream, ["bytes", "digest", "tail", "truncated"]) ||
    !Number.isSafeInteger(stream.bytes) ||
    stream.bytes < 0 ||
    !/^sha256-[A-Za-z0-9_-]{43}$/u.test(stream.digest ?? "") ||
    typeof stream.tail !== "string" ||
    typeof stream.truncated !== "boolean"
  ) {
    throw new Error(`${label}: malformed bounded command output evidence`);
  }
}

function validateExecutionCommand(record) {
  if (
    !exactFields(record, [
      "commandEvidence",
      "evidenceEnvironment",
      "schema",
    ]) ||
    record.schema !== "ibex/capsec-inherited-intrinsic-alias-command/1" ||
    canonicalJson(record.evidenceEnvironment) !==
      canonicalJson(EXECUTION_ENVIRONMENT_KEYS)
  ) {
    throw new Error("inherited intrinsic execution command record is malformed");
  }
  const command = record.commandEvidence;
  if (
    !exactFields(command, [
      "command",
      "exitCode",
      "id",
      "signal",
      "stderr",
      "stdout",
    ]) ||
    command.id !== "loaded-intrinsic-alias-execution" ||
    canonicalJson(command.command) !== canonicalJson(EXECUTION_COMMAND) ||
    command.exitCode !== 0 ||
    command.signal !== null
  ) {
    throw new Error("inherited intrinsic execution command did not pass exactly");
  }
  validateCommandStream(command.stdout, "intrinsic execution stdout");
  validateCommandStream(command.stderr, "intrinsic execution stderr");
}

export function auditInheritedIntrinsicAliasTargetRecord({
  sourceAudit,
  targetRecord,
}) {
  if (
    !exactFields(targetRecord, [
      "evidence",
      "evidenceDigest",
      "executionCommand",
      "schema",
      "sourceRevision",
      "sourceTree",
    ]) ||
    targetRecord.schema !== INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_SCHEMA ||
    !/^[a-f0-9]{40,64}$/u.test(targetRecord.sourceRevision ?? "") ||
    !/^[a-f0-9]{40,64}$/u.test(targetRecord.sourceTree ?? "") ||
    targetRecord.evidenceDigest !==
      sha256Hex(canonicalJson(targetRecord.evidence))
  ) {
    throw new Error("inherited intrinsic target record is detached or malformed");
  }
  validateExecutionCommand(targetRecord.executionCommand);
  const accepted = auditInheritedIntrinsicAliasBatchEvidence({
    sourceAudit,
    evidence: targetRecord.evidence,
  });
  return deepFreeze({
    ...accepted,
    sourceRevision: targetRecord.sourceRevision,
    sourceTree: targetRecord.sourceTree,
    targetRecord: clone(targetRecord),
  });
}

function validateSourceAudit(sourceAudit) {
  // Probe authoring runs the account module's full reviewed-source validator.
  // The representative target is used only to validate the immutable review;
  // it never appears in the returned ledger as an execution.
  inheritedIntrinsicAliasProbe({
    sourceAudit,
    profileId: "source-patched",
    target: { triple: "aarch64-apple-darwin", features: [] },
  });
}

export function auditInheritedIntrinsicAliasExecutionLedger({
  sourceAudit,
  targetRecords,
}) {
  validateSourceAudit(sourceAudit);
  if (!Array.isArray(targetRecords)) {
    throw new Error("inherited intrinsic target records are absent");
  }
  const reviewedProfiles = [...sourceAudit.profiles].sort((left, right) =>
    compareText(left.id, right.id),
  );
  const accepted = targetRecords
    .map((targetRecord) =>
      auditInheritedIntrinsicAliasTargetRecord({ sourceAudit, targetRecord }),
    )
    .sort((left, right) =>
      compareText(left.execution.profileId, right.execution.profileId),
    );
  const acceptedProfileIds = accepted.map(
    ({ execution }) => execution.profileId,
  );
  if (new Set(acceptedProfileIds).size !== acceptedProfileIds.length) {
    throw new Error("duplicate inherited intrinsic loaded-profile evidence");
  }
  const sourceBindings = new Set(
    accepted.map((entry) => `${entry.sourceRevision}:${entry.sourceTree}`),
  );
  if (sourceBindings.size > 1) {
    throw new Error("inherited intrinsic target records span source revisions");
  }
  const missingProfiles = reviewedProfiles.filter(
    (profile) => !acceptedProfileIds.includes(profile.id),
  );
  const provenanceBlockers = accepted.map(({ execution }) => {
    const profile = reviewedProfiles.find(
      (candidate) => candidate.id === execution.profileId,
    );
    return {
      code: INHERITED_INTRINSIC_ALIAS_PROFILE_PROVENANCE_CODE,
      profileId: execution.profileId,
      targetVariant: execution.targetVariant,
      loadedBinaryDigest: execution.loadedEngineIdentity.binaryDigest,
      reviewedProfileIdentity: clone(profile.identity),
    };
  });
  const result = {
    schema: INHERITED_INTRINSIC_ALIAS_EXECUTION_LEDGER_SCHEMA,
    status: "incomplete",
    runtimeExecutionRequired: true,
    runtimeExecutionsComplete: missingProfiles.length === 0,
    reviewedProfileProvenanceComplete: false,
    eligibleForStructuralAccounts: false,
    sourceReviewDigest: sourceAudit.sourceReviewDigest,
    profileReviewDigest: sourceAudit.profileReviewDigest,
    acceptedProfileIds,
    missingProfileIds: missingProfiles.map((profile) => profile.id),
    blockers: [
      ...missingProfiles.map((profile) => ({
        code: INHERITED_INTRINSIC_ALIAS_MISSING_EXECUTION_CODE,
        profileId: profile.id,
        targetVariant: profile.targetVariant,
        reviewedProfileIdentity: clone(profile.identity),
      })),
      ...provenanceBlockers,
    ],
    sourceRevision: accepted[0]?.sourceRevision ?? null,
    sourceTree: accepted[0]?.sourceTree ?? null,
    targetRecords: accepted.map(({ targetRecord }) => targetRecord),
    evidence: accepted.map(({ evidence }) => evidence),
    executions: accepted.map(({ execution }) => execution),
    accountSet: null,
  };
  return deepFreeze({
    ...result,
    ledgerDigest: taggedDigest(LEDGER_DIGEST_DOMAIN, result),
  });
}
