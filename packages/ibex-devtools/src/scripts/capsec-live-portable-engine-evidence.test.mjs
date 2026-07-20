import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  buildPortableEvidencePlan,
  buildPortablePublicBatchEvidencePlan,
  parsePortableEngineIdentityMarker,
  validateLivePortableProcess,
} from "./capsec-live-portable-engine-evidence.mjs";
import {
  commandAttemptDigest,
  mappedEngineExecutionEvidenceDigest,
  portableFixtureEvidenceDigest,
  rawContentDigest,
} from "./capsec-portable-engine-evidence-contract.mjs";
import { computeDomainDigest, parseJsonStrict } from "./capsec-contract.mjs";

const repoRoot = path.resolve(import.meta.dir, "../../../..");
const portableVectors = parseJsonStrict(
  fs.readFileSync(
    path.join(
      repoRoot,
      "schemas/vectors/portable-engine-provenance-v1.valid.json",
    ),
  ),
  "portable engine vectors",
);
const roots = [];
const digest = (character) => rawContentDigest(Buffer.from(character, "utf8"));
const exactBytes = (value) =>
  Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");

afterEach(() => {
  for (const root of roots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("public-batch plans bind source-selected executor and supervisor route", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-portable-plan-"));
  roots.push(root);
  const bindings = {
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: digest("A"),
    target: {
      triple: "aarch64-apple-darwin",
      features: ["hermes-frame-attribution"],
    },
    engine: portableVectors.documents.portableIdentity,
    vocabularyDigest: digest("B"),
    registryDigest: digest("C"),
    implementationManifestDigest: digest("D"),
    fixtureCatalogDigest: digest("E"),
    targetCellsRawContentDigest: digest("F"),
    recipeCatalogDigest: digest("G"),
    recipeCatalogRawContentDigest: digest("H"),
    publicSurfaceExecutionDigest: digest("I"),
    publicSurfaceExecutionRawContentDigest: digest("J"),
    outputDispositionEvidenceRawContentDigest: digest("K"),
  };
  const state = buildPortablePublicBatchEvidencePlan({
    bindings,
    evidenceDirectory: root,
    fixtureIds: ["fixture.alpha", "fixture.beta"],
    executor: "ibex-native-public-surface-harness",
    commandId: "portable-public-fixtures-001-deadbeef",
  });
  expect(state.plan.executor).toBe("ibex-native-public-surface-harness");
  expect(state.plan.phaseId).toBe("fixture-evidence");
  expect(state.plan.commandId).toBe(
    "portable-public-fixtures-001-deadbeef",
  );
  expect(state.fixtureOutputs.map((row) => row.fixtureId)).toEqual([
    "fixture.alpha",
    "fixture.beta",
  ]);

  expect(() =>
    buildPortablePublicBatchEvidencePlan({
      bindings,
      evidenceDirectory: root,
      fixtureIds: ["fixture.beta", "fixture.alpha"],
      executor: "ibex-native-public-surface-harness",
      commandId: "portable-public-fixtures-001-deadbeef",
    }),
  ).toThrow(/sorted and unique/u);
  expect(() =>
    buildPortablePublicBatchEvidencePlan({
      bindings,
      evidenceDirectory: root,
      fixtureIds: ["fixture.alpha"],
      executor: "Borrowed Executor",
      commandId: "portable-public-fixtures-001-deadbeef",
    }),
  ).toThrow(/invalid portable public-batch executor/u);
});

function liveFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ibex-portable-live-"));
  roots.push(root);
  const engine = structuredClone(
    portableVectors.documents.portableIdentity,
  );
  const target = {
    triple: engine.target.triple,
    features: [
      "hermes-frame-attribution",
      "native-compartments",
      "native-lockdown",
    ],
  };
  const bindings = {
    sourceRevision: "a".repeat(40),
    sourceTreeDigest: digest("A"),
    target,
    engine,
    vocabularyDigest: digest("B"),
    registryDigest: digest("C"),
    implementationManifestDigest: digest("D"),
    fixtureCatalogDigest: digest("E"),
    targetCellsRawContentDigest: digest("F"),
    recipeCatalogDigest: digest("G"),
    recipeCatalogRawContentDigest: digest("H"),
    publicSurfaceExecutionDigest: digest("I"),
    publicSurfaceExecutionRawContentDigest: digest("J"),
    outputDispositionEvidenceRawContentDigest: digest("K"),
  };
  const fixtureIds = ["fixture.portable-alpha", "fixture.portable-beta"];
  const plan = buildPortableEvidencePlan({
    bindings,
    evidenceDirectory: root,
    fixtureIds,
  });
  const fixtureRecords = plan.fixtureOutputs.map((output) => {
    const fixture = {
      fixtureEvidenceSchema: "ibex/capsec-portable-fixture-evidence/1",
      profile: "ibex/capsec/1",
      sourceRevision: bindings.sourceRevision,
      sourceTreeDigest: bindings.sourceTreeDigest,
      target,
      engine,
      fixtureId: output.fixtureId,
      outcome: "passed",
      executor: "ibex-exact-fixture-evidence-pilot",
      bindingDigest: plan.plan.bindingDigest,
      artifactDigest: digest("A"),
    };
    fixture.artifactDigest = portableFixtureEvidenceDigest(fixture);
    const bytes = exactBytes(fixture);
    fs.writeFileSync(output.path, bytes, { flag: "wx", mode: 0o600 });
    return { fixture, bytes, output, rawDigest: rawContentDigest(bytes) };
  });
  const mappedEngine = structuredClone(
    portableVectors.documents.mappedInstance,
  );
  mappedEngine.portable = structuredClone(engine);
  mappedEngine.before.digest = engine.runtimeComponentDigest;
  mappedEngine.after.digest = engine.runtimeComponentDigest;
  mappedEngine.processArchitecture = target.triple.split("-")[0];
  mappedEngine.observationDigest = computeDomainDigest(
    "ibex.mapped-engine-instance-identity.v1",
    mappedEngine,
    ["observationDigest"],
  );
  const evidence = {
    mappedEngineExecutionEvidenceSchema:
      "ibex/capsec-mapped-engine-execution-evidence/1",
    profile: "ibex/capsec/1",
    authorityClass: "same-runner-authoritative",
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    target,
    phaseId: "fixture-evidence",
    commandId: "exact-fixture-evidence-portable-pilot",
    commandIdentityDigest: digest("L"),
    fixtureIds,
    outputDigests: fixtureRecords.map((record) => record.rawDigest).sort(),
    engine,
    mappedEngine,
    evidenceDigest: digest("A"),
  };
  evidence.evidenceDigest = mappedEngineExecutionEvidenceDigest(evidence);
  const mappedBytes = exactBytes(evidence);
  fs.writeFileSync(plan.mappedEvidencePath, mappedBytes, {
    flag: "wx",
    mode: 0o600,
  });
  const attempt = {
    schema: "ibex/capsec-command-attempt/1",
    attemptId: "attempt-000001",
    commandId: evidence.commandId,
    commandIdentity: evidence.commandIdentityDigest,
    phase: evidence.phaseId,
    displayedInvocation: ["cargo", "test"],
    startedAt: "2026-07-20T00:00:00.000Z",
    finishedAt: "2026-07-20T00:00:01.000Z",
    elapsedMs: 1000,
    deadlineMs: 30000,
    gracePeriodMs: 5000,
    classification: "success",
    exitCode: 0,
    signal: null,
    cleanup: { actions: [], cleanupProven: true, escapedDescendants: [] },
    stdout: { bytes: 0, digest: digest("M"), tail: "", truncated: false },
    stderr: { bytes: 0, digest: digest("M"), tail: "", truncated: false },
    outputs: [
      ...fixtureRecords.map((record) => ({
        path: record.output.path,
        bytes: record.bytes.byteLength,
        digest: record.rawDigest,
      })),
      {
        path: plan.mappedEvidencePath,
        bytes: mappedBytes.byteLength,
        digest: rawContentDigest(mappedBytes),
      },
    ],
    attemptDigest: digest("A"),
  };
  attempt.attemptDigest = commandAttemptDigest(attempt);
  return { attempt, bindings, evidence, fixtureRecords, plan };
}

test("only the exact null marker preserves the legacy v1 path", () => {
  expect(parsePortableEngineIdentityMarker(Buffer.from("null\n"))).toBeNull();
  expect(() => parsePortableEngineIdentityMarker(Buffer.from(" null\n"))).toThrow(
    /exactly null followed by LF/u,
  );
  const portable = portableVectors.documents.portableIdentity;
  expect(parsePortableEngineIdentityMarker(exactBytes(portable))).toEqual(
    portable,
  );
});

test("live validation produces a locality-free v2 report slice", () => {
  const fixture = liveFixture();
  const result = validateLivePortableProcess({
    attempt: fixture.attempt,
    bindings: fixture.bindings,
    fixtureOutputs: fixture.plan.fixtureOutputs,
    mappedEvidencePath: fixture.plan.mappedEvidencePath,
  });
  expect(result.reportSlice.executions).toHaveLength(2);
  expect(
    result.reportSlice.bindings.mappedEngineExecutionEvidence[0].evidenceDigest,
  ).toBe(fixture.evidence.evidenceDigest);
  expect(JSON.stringify(result.reportSlice)).not.toContain(
    fixture.evidence.mappedEngine.canonicalLocalRuntimePath,
  );
  expect(result.process.outputArtifactBytes).toHaveLength(2);
});

test("live validation refuses missing and substituted declared outputs", () => {
  const missing = liveFixture();
  fs.rmSync(missing.fixtureRecords[0].output.path);
  expect(() =>
    validateLivePortableProcess({
      attempt: missing.attempt,
      bindings: missing.bindings,
      fixtureOutputs: missing.plan.fixtureOutputs,
      mappedEvidencePath: missing.plan.mappedEvidencePath,
    }),
  ).toThrow();

  const substituted = liveFixture();
  const firstPath = substituted.fixtureRecords[0].output.path;
  const changed = JSON.parse(fs.readFileSync(firstPath, "utf8"));
  changed.executor = "substituted-executor";
  fs.writeFileSync(firstPath, exactBytes(changed));
  expect(() =>
    validateLivePortableProcess({
      attempt: substituted.attempt,
      bindings: substituted.bindings,
      fixtureOutputs: substituted.plan.fixtureOutputs,
      mappedEvidencePath: substituted.plan.mappedEvidencePath,
    }),
  ).toThrow(/finalized supervisor output/u);
});

test("live validation refuses a mapped record from another command attempt", () => {
  const fixture = liveFixture();
  fixture.attempt.commandIdentity = digest("Z");
  fixture.attempt.attemptDigest = commandAttemptDigest(fixture.attempt);
  expect(() =>
    validateLivePortableProcess({
      attempt: fixture.attempt,
      bindings: fixture.bindings,
      fixtureOutputs: fixture.plan.fixtureOutputs,
      mappedEvidencePath: fixture.plan.mappedEvidencePath,
    }),
  ).toThrow(/another command or process attempt/u);
});
