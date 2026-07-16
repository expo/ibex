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
 * A current-file digest tied by device/inode to the Hermes factory mapping is
 * not a hash of the executable pages already mapped, nor proof of a
 * source-build authority. The receipt chain mechanically binds reviewed
 * package checksums (plus the NuGet repository signature) to link-selected
 * files and verifies that the Hermes file's current object is the factory
 * mapping's object. It still does not authenticate already mapped code pages,
 * separately loaded JSI, local source builds, or imported target JSON.
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
export const INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_ATTESTATION_CODE =
  "imported-target-record-authenticity-unverified";
export const INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE =
  "source-patched-cache-build-authority-unattested";
export const INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE =
  "loaded-engine-linked-dependency-provenance-unverified";
export const INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE =
  "linux-source-profile-receipt-unavailable";
export const INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE =
  "windows-loaded-engine-mapped-image-provenance-unverified";
export const HERMES_PROFILE_PROVENANCE_RECEIPT_SCHEMA =
  "ibex/hermes-profile-provenance-receipt/2";

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
  "IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE",
  "IBEX_CAPSEC_INTRINSIC_ALIAS_EVIDENCE_OUTPUT",
  "IBEX_CAPSEC_INTRINSIC_ALIAS_PLAN",
].sort(compareText));

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

function sha256Base64UrlAsHex(value, label) {
  if (!/^sha256-[A-Za-z0-9_-]{43}$/u.test(value ?? "")) {
    throw new Error(`${label}: malformed loaded binary digest`);
  }
  const raw = Buffer.from(value.slice(7), "base64url");
  if (raw.length !== 32) {
    throw new Error(`${label}: loaded binary digest is not SHA-256`);
  }
  return `sha256-${raw.toString("hex")}`;
}

function validatePackageRepository(value, label) {
  let repository;
  try {
    repository = new URL(value);
  } catch {
    throw new Error(`${label}: malformed package repository`);
  }
  if (
    repository.protocol !== "https:" ||
    repository.username ||
    repository.password ||
    repository.search ||
    repository.hash
  ) {
    throw new Error(`${label}: package repository must be an uncredentialed HTTPS URL`);
  }
}

function auditLoadedProfileProvenance({ sourceAudit, evidence }) {
  const receipt = evidence.loadedEngineProfileProvenance;
  const profile = profileFor(sourceAudit, evidence.profileId);
  if (receipt === null) {
    return {
      mechanicallyBound: false,
      blocker: {
        code: INHERITED_INTRINSIC_ALIAS_PROFILE_PROVENANCE_CODE,
        profileId: profile.id,
        targetVariant: profile.targetVariant,
        loadedBinaryDigest: evidence.loadedEngineIdentity?.binaryDigest,
        reviewedProfileIdentity: clone(profile.identity),
      },
    };
  }
  const receiptFields =
    profile.id === "windows-nuget"
      ? [
          "artifact",
          "linkArtifact",
          "origin",
          "profileId",
          "schema",
          "targetVariant",
        ]
      : ["artifact", "origin", "profileId", "schema", "targetVariant"];
  if (
    !exactFields(receipt, receiptFields) ||
    receipt.schema !== HERMES_PROFILE_PROVENANCE_RECEIPT_SCHEMA ||
    receipt.profileId !== profile.id ||
    receipt.targetVariant !== profile.targetVariant
  ) {
    throw new Error(`${profile.id}: malformed exact Hermes profile receipt`);
  }
  const artifact = receipt.artifact;
  const identity = evidence.loadedEngineIdentity;
  const universalArtifactAllowed =
    profile.id === "source-patched" &&
    typeof evidence.target?.triple === "string" &&
    evidence.target.triple.endsWith("-apple-darwin");
  const artifactArchitectureMatches =
    (artifact?.targetArchitecture === identity?.targetArchitecture &&
      artifact?.targetArchitecture !== "universal") ||
    (universalArtifactAllowed && artifact?.targetArchitecture === "universal");
  if (
    !exactFields(artifact, [
      "binaryDigest",
      "fileName",
      "targetArchitecture",
    ]) ||
    artifact.binaryDigest !==
      sha256Base64UrlAsHex(identity?.binaryDigest, profile.id) ||
    artifact.fileName !== path.basename(identity?.engineArtifactPath ?? "") ||
    !artifactArchitectureMatches
  ) {
    throw new Error(
      `${profile.id}: Hermes profile receipt does not bind the loaded artifact bytes`,
    );
  }
  const origin = receipt.origin;
  if (
    canonicalJson(origin?.reviewedProfileIdentity) !==
    canonicalJson(profile.identity)
  ) {
    throw new Error(
      `${profile.id}: Hermes receipt identity differs from the reviewed profile`,
    );
  }
  if (profile.id === "source-patched") {
    if (
      !exactFields(origin, [
        "cacheKey",
        "kind",
        "reviewedProfileIdentity",
      ]) ||
      origin.kind !== "source-patched-cache"
    ) {
      throw new Error("source-patched: malformed source-build receipt origin");
    }
    const patchPrefix = profile.identity.patchStackDigest.slice(7, 19);
    const commitPrefix = profile.identity.sourceCommit.slice(0, 12);
    const patchApplicationPrefix =
      profile.identity.patchApplicationAuthorityDigest.slice(7, 19);
    const patchIdentityPrefix =
      profile.identity.patchIdentityAuthorityDigest.slice(7, 19);
    const appleBuildPrefix =
      profile.identity.sourceBuildAuthorityDigests[
        "scripts/build-hermes.sh"
      ].slice(7, 19);
    const linuxBuildPrefix =
      profile.identity.sourceBuildAuthorityDigests[
        "scripts/build-hermes-linux.sh"
      ].slice(7, 19);
    const authorityKey =
      `p${patchPrefix}-ba${appleBuildPrefix}-bl${linuxBuildPrefix}` +
      `-a${patchApplicationPrefix}-i${patchIdentityPrefix}`;
    const reviewedCacheKeys =
      artifact.fileName === "libhermesvm.so"
        ? [
            `${commitPrefix}-${authorityKey}-olinux`,
          ]
        : [
            `${commitPrefix}-${authorityKey}-oapple`,
            `${commitPrefix}-debug-${authorityKey}-oapple`,
          ];
    if (!reviewedCacheKeys.includes(origin.cacheKey)) {
      throw new Error(
        "source-patched: receipt cache key does not bind the reviewed pin, patch stack, both build authorities, patch-application authority, and patch-identity authority",
      );
    }
  } else if (profile.id === "android-maven") {
    if (
      !exactFields(origin, [
        "kind",
        "linkedDependency",
        "packageCoordinate",
        "packageDigest",
        "packageRepository",
        "reviewedProfileIdentity",
      ]) ||
      origin.kind !== "maven-aar" ||
      origin.packageDigest !== profile.identity.packageDigest
    ) {
      throw new Error("android-maven: malformed reviewed package provenance origin");
    }
    validatePackageRepository(origin.packageRepository, profile.id);
    const expected = `${profile.identity.artifact}:${profile.identity.version}:${profile.identity.variant}`;
    if (
      origin.packageCoordinate !== expected ||
      origin.packageRepository !== "https://repo1.maven.org/maven2"
    ) {
      throw new Error("android-maven: receipt coordinate drifted from review");
    }
    const linkedIdentity = profile.identity.linkedDependency;
    const linked = origin.linkedDependency;
    if (
      !exactFields(linked, [
        "artifact",
        "packageCoordinate",
        "packageDigest",
        "packageRepository",
      ]) ||
      !exactFields(linked.artifact, [
        "binaryDigest",
        "fileName",
        "targetArchitecture",
      ]) ||
      !/^sha256-[a-f0-9]{64}$/u.test(linked.artifact.binaryDigest ?? "") ||
      linked.artifact.fileName !== "libjsi.so" ||
      linked.artifact.targetArchitecture === "universal" ||
      linked.artifact.targetArchitecture !== identity?.targetArchitecture ||
      linked.packageCoordinate !==
        `${linkedIdentity.artifact}:${linkedIdentity.version}:${linkedIdentity.variant}` ||
      linked.packageDigest !== linkedIdentity.packageDigest ||
      linked.packageRepository !== origin.packageRepository
    ) {
      throw new Error(
        "android-maven: receipt does not bind the reviewed linked JSI package and selected artifact",
      );
    }
  } else {
    const linkArtifact = receipt.linkArtifact;
    if (
      !exactFields(linkArtifact, [
        "binaryDigest",
        "fileName",
        "targetArchitecture",
      ]) ||
      !/^sha256-[a-f0-9]{64}$/u.test(linkArtifact.binaryDigest ?? "") ||
      linkArtifact.fileName !== "hermes.lib" ||
      linkArtifact.targetArchitecture === "universal" ||
      linkArtifact.targetArchitecture !== identity?.targetArchitecture
    ) {
      throw new Error(
        "windows-nuget: receipt does not bind the exact reviewed Hermes import library",
      );
    }
    if (
      !exactFields(origin, [
        "kind",
        "packageCoordinate",
        "packageDigest",
        "packageRepository",
        "packageSignature",
        "reviewedProfileIdentity",
      ]) ||
      origin.kind !== "nuget-package" ||
      origin.packageDigest !== profile.identity.packageDigest ||
      !exactFields(origin.packageSignature, [
        "kind",
        "serviceIndex",
        "verification",
      ]) ||
      origin.packageSignature.kind !== "nuget-repository-signature" ||
      origin.packageSignature.serviceIndex !==
        profile.identity.repositorySignature.serviceIndex ||
      origin.packageSignature.verification !== "dotnet-nuget-verify-all"
    ) {
      throw new Error("windows-nuget: malformed reviewed package provenance origin");
    }
    validatePackageRepository(origin.packageRepository, profile.id);
    const expected = `${profile.identity.artifact}:${profile.identity.version}`;
    if (
      origin.packageCoordinate !== expected ||
      origin.packageRepository !==
        profile.identity.repositorySignature.serviceIndex
    ) {
      throw new Error("windows-nuget: receipt coordinate drifted from review");
    }
  }
  return { mechanicallyBound: true, blocker: null, receipt: clone(receipt) };
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
      "loadedEngineProfileProvenance",
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
  const profileProvenance = auditLoadedProfileProvenance({
    sourceAudit,
    evidence,
  });
  return deepFreeze({
    evidence: clone(evidence),
    execution,
    profileProvenance,
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

function knownProvenanceDesignBlockers(sourceAudit) {
  const sourceProfile = profileFor(sourceAudit, "source-patched");
  const androidProfile = profileFor(sourceAudit, "android-maven");
  const windowsProfile = profileFor(sourceAudit, "windows-nuget");
  return [
    {
      code: INHERITED_INTRINSIC_ALIAS_SOURCE_CACHE_AUTHORITY_CODE,
      profileId: sourceProfile.id,
      targetVariant: sourceProfile.targetVariant,
      originKind: "source-patched-cache",
      reviewedProfileIdentity: clone(sourceProfile.identity),
      reason:
        "published source bundles now require GitHub build-provenance verification, but local and force-built source receipts still have no independent build attestation proving that the reviewed source, patches, and build command produced those bytes, and the receipt does not distinguish those paths",
    },
    {
      code: INHERITED_INTRINSIC_ALIAS_LINKED_DEPENDENCY_CODE,
      profileId: androidProfile.id,
      targetVariant: androidProfile.targetVariant,
      artifact: "com.facebook.react:react-android/libjsi.so",
      reason:
        "the Android installer and build receipt bind the reviewed React Android AAR and link-selected libjsi.so bytes, but runtime evidence does not yet authenticate the separately loaded JSI image",
    },
    {
      code: INHERITED_INTRINSIC_ALIAS_LINUX_PROFILE_RECEIPT_CODE,
      profileId: sourceProfile.id,
      targetVariant: sourceProfile.targetVariant,
      platform: "linux",
      reason:
        "the Linux source build emits a reviewed receipt for dynamic libhermesvm.so, but a statically linked Hermes archive cannot be authenticated as a standalone mapped object by the current receipt contract",
    },
    {
      code: INHERITED_INTRINSIC_ALIAS_WINDOWS_LOADED_IMAGE_CODE,
      profileId: windowsProfile.id,
      targetVariant: windowsProfile.targetVariant,
      packageCoordinate: `${windowsProfile.identity.artifact}:${windowsProfile.identity.version}`,
      reason:
        "the Windows installer enforces the reviewed NuGet SHA-512 and repository signature, but the runtime mapped-object verifier remains unavailable on Windows",
    },
  ];
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
  const provenanceBlockers = accepted
    .filter(({ profileProvenance }) => !profileProvenance.mechanicallyBound)
    .map(({ profileProvenance }) => profileProvenance.blocker);
  const targetRecordAttestationBlockers = accepted.map(({ execution }) => ({
    code: INHERITED_INTRINSIC_ALIAS_TARGET_RECORD_ATTESTATION_CODE,
    profileId: execution.profileId,
    targetVariant: execution.targetVariant,
    reason:
      "exported JSON and command digests are recomputable assertions without a trusted target signature or CI attestation",
  }));
  const provenanceDesignBlockers = knownProvenanceDesignBlockers(sourceAudit);
  const executionRecordsComplete = missingProfiles.length === 0;
  const result = {
    schema: INHERITED_INTRINSIC_ALIAS_EXECUTION_LEDGER_SCHEMA,
    status: "incomplete",
    runtimeExecutionRequired: true,
    runtimeExecutionRecordsComplete: executionRecordsComplete,
    runtimeExecutionsComplete: false,
    // A receipt can mechanically bind Hermes bytes while the platform's full
    // linked dependency/provenance chain remains open. Keep the closure field
    // false until every design blocker below has an independent trust anchor.
    linkedProfileBindingsComplete: false,
    reviewedProfileProvenanceComplete: false,
    targetRecordAuthenticityComplete: false,
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
      ...targetRecordAttestationBlockers,
      ...provenanceDesignBlockers,
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
