/** Validate and ingest release-mode LLP 0033 global corpus evidence. */

import fs from "node:fs";

import { canonicalJson, parseJsonStrict } from "./capsec-contract.mjs";
import {
  assertExactKeys,
  validateEngine,
  validateRevisionAndAuthorities,
} from "./restricted-exact-reachable-evidence.mjs";
import { restrictedGlobalCorpusPlan } from "./run-restricted-exact-global-corpora.mjs";
import { validateRestrictedObserverEquivalenceEvidence } from "./run-restricted-exact-observer-equivalence.mjs";
import {
  loadRestrictedReportAuthorities,
  taggedDigest,
} from "./restricted-exact-target-report.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-profile-global-corpora-evidence/1";
const RESULT_MARKER = "ibex-restricted-global-corpora:passed";

function bindingsFor(artifact, patchIdentity) {
  return {
    sourceRevision: artifact.sourceRevision,
    sourceTreeDigest: artifact.sourceTreeDigest,
    target: artifact.target,
    engine: {
      artifactPath: artifact.engine.engineArtifactPath,
      kind: artifact.engine.kind,
      binaryDigest: artifact.engine.binaryDigest,
      patchIdentity,
      targetArchitecture: artifact.engine.targetArchitecture,
      structuralFeatures: artifact.engine.structuralFeatures,
    },
    ...artifact.authorityDigests,
  };
}

export function ingestRestrictedGlobalCorporaEvidence(
  rawBytes,
  bindingEvidenceBytes,
  authorities = undefined,
) {
  const reportAuthorities = authorities ?? loadRestrictedReportAuthorities();
  const artifact = parseJsonStrict(rawBytes, "restricted global corpus evidence");
  const bindingEvidence = parseJsonStrict(
    bindingEvidenceBytes,
    "restricted global corpus binding evidence",
  );
  const hasObserverEquivalence = Object.hasOwn(artifact, "observerEquivalence");
  const artifactKeys = [
    "evidenceSchema",
    "profile",
    "runId",
    "sourceRevision",
    "sourceTreeDigest",
    "target",
    "engine",
    "hermesProfileProvenance",
    "authorityDigests",
    "bindingEvidenceRawContentDigest",
    "commandEnvironment",
    "exitCode",
    "resultMarker",
    "corpora",
    "executions",
  ];
  if (hasObserverEquivalence) artifactKeys.splice(11, 0, "observerEquivalence");
  assertExactKeys(
    artifact,
    artifactKeys,
    "restricted global corpus evidence",
  );
  if (
    artifact.evidenceSchema !== EVIDENCE_SCHEMA
    || artifact.profile !== "ibex/exact-embedder-contract/1"
    || artifact.exitCode !== 0
    || artifact.resultMarker !== RESULT_MARKER
  ) {
    throw new Error("restricted global corpus evidence is not a passing v1 artifact");
  }
  if (taggedDigest(bindingEvidenceBytes) !== artifact.bindingEvidenceRawContentDigest) {
    throw new Error("global corpus binding evidence digest mismatch");
  }
  validateRevisionAndAuthorities(artifact, reportAuthorities);
  if (!hasObserverEquivalence) {
    throw new Error("restricted global corpus evidence omits observer equivalence");
  }
  const patchIdentity = validateEngine(artifact);
  const observerEquivalenceRaw = Buffer.from(
    `${JSON.stringify(artifact.observerEquivalence, null, 2)}\n`,
    "utf8",
  );
  validateRestrictedObserverEquivalenceEvidence(
    observerEquivalenceRaw,
    bindingEvidenceBytes,
    reportAuthorities,
  );
  const bindings = bindingsFor(artifact, patchIdentity);
  const bindingPatchIdentity = validateEngine(bindingEvidence);
  if (
    canonicalJson(bindings) !== canonicalJson(bindingsFor(bindingEvidence, bindingPatchIdentity))
  ) {
    throw new Error("global corpus and per-edge evidence bindings differ");
  }

  const plannedCorpusIds = restrictedGlobalCorpusPlan.map((row) => row.id);
  if (
    canonicalJson(plannedCorpusIds)
      !== canonicalJson(reportAuthorities.fixturePlan.globalCorpora.map((row) => row.id))
    || canonicalJson(artifact.corpora.map((row) => row.id))
      !== canonicalJson(plannedCorpusIds)
  ) {
    throw new Error("global corpus set differs from the preregistered plan");
  }
  const executionById = new Map(
    artifact.executions.map((execution) => [execution.executionId, execution]),
  );
  if (executionById.size !== artifact.executions.length) {
    throw new Error("global corpus execution IDs contain duplicates");
  }
  const expectedExecutionIds = [];
  for (const planned of restrictedGlobalCorpusPlan) {
    const corpus = artifact.corpora.find((row) => row.id === planned.id);
    if (planned.id === "observer-equivalence") {
      const executionId = "restricted-corpus.observer-equivalence.release-build-transcript-equality";
      const execution = executionById.get(executionId);
      const expectedCommand = [
        "bun",
        "packages/ibex-devtools/src/scripts/run-restricted-exact-observer-equivalence.mjs",
        "--binding-evidence",
        "<reachable-evidence>",
        "--output",
        "<observer-equivalence-evidence>",
      ];
      if (
        corpus.status !== "passed"
        || canonicalJson(corpus.executionIds) !== canonicalJson([executionId])
        || !execution
        || execution.fixtureId !== planned.id
        || execution.outcome !== "passed"
        || execution.exitCode !== 0
        || execution.resultMarker
          !== "ibex-restricted-global-corpus:passed:observer-equivalence:release-build-transcript-equality"
        || canonicalJson(execution.command) !== canonicalJson(expectedCommand)
        || execution.outputDigest !== taggedDigest(observerEquivalenceRaw)
      ) {
        throw new Error("global corpus observer-equivalence execution drift");
      }
      expectedExecutionIds.push(executionId);
      continue;
    }
    const expectedIds = planned.tests.map(
      (testName) => `restricted-corpus.${planned.id}.${testName}`,
    );
    if (
      corpus.status !== "passed"
      || canonicalJson(corpus.executionIds) !== canonicalJson(expectedIds)
    ) {
      throw new Error(`global corpus ${planned.id} execution set drift`);
    }
    for (const [index, executionId] of expectedIds.entries()) {
      const testName = planned.tests[index];
      const execution = executionById.get(executionId);
      const expectedCommand = [
        "cargo",
        "test",
        "-p",
        "ibex-runtime",
        "--lib",
        "--release",
        "--features",
        "capsec-conformance-observer",
        `host::embedder_artifacts::tests::${testName}`,
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
      ];
      if (
        !execution
        || execution.fixtureId !== planned.id
        || execution.outcome !== "passed"
        || execution.exitCode !== 0
        || execution.resultMarker
          !== `ibex-restricted-global-corpus:passed:${planned.id}:${testName}`
        || canonicalJson(execution.command) !== canonicalJson(expectedCommand)
        || !/^sha256-[A-Za-z0-9_-]{43}$/u.test(execution.outputDigest)
      ) {
        throw new Error(`global corpus execution drift for ${executionId}`);
      }
      expectedExecutionIds.push(executionId);
    }
  }
  if (
    canonicalJson([...executionById.keys()].sort())
      !== canonicalJson(expectedExecutionIds.sort())
  ) {
    throw new Error("global corpus evidence includes an unplanned execution");
  }

  const artifactDigest = taggedDigest(Buffer.from(canonicalJson(artifact), "utf8"));
  return {
    artifact,
    bindings,
    globalCorpora: artifact.corpora.map((corpus) => ({
      ...corpus,
      executionIds: [...corpus.executionIds].sort(),
    })),
    executions: artifact.executions.map((execution) => ({
      executionId: execution.executionId,
      fixtureId: execution.fixtureId,
      outcome: execution.outcome,
      command: execution.command,
      exitCode: execution.exitCode,
      resultMarker: execution.resultMarker,
      artifactDigest,
      engineBinaryDigest: artifact.engine.binaryDigest,
      observations: [],
    })),
  };
}

export function readRestrictedGlobalCorporaEvidence(
  filePath,
  bindingEvidencePath,
  authorities = undefined,
) {
  return ingestRestrictedGlobalCorporaEvidence(
    fs.readFileSync(filePath),
    fs.readFileSync(bindingEvidencePath),
    authorities,
  );
}
