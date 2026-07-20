// Live same-runner bridge from engine-using commands to the frozen additive
// Phase-2 report contract. This module does not advertise or accept a target.
//
// @ref LLP 0035#reports-and-advertisements — mapped evidence binds the
// pre-command identity and every other declared output; the finalized attempt
// then binds the mapped evidence without a digest cycle.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";
import {
  commandAttemptDigest,
  mappedEngineExecutionEvidenceDigest,
  portableExecutionBindingDigest,
  portableFixtureEvidenceDigest,
  rawContentDigest,
} from "./capsec-portable-engine-evidence-contract.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDirectory, "../../../..");
const schemaFiles = [
  "schemas/portable-engine-common-v1.schema.json",
  "schemas/portable-engine-artifact-identity-v1.schema.json",
  "schemas/mapped-engine-instance-identity-v1.schema.json",
  "schemas/capsec-portable-engine-evidence-common-v1.schema.json",
  "schemas/capsec-command-attempt-v1.schema.json",
  "schemas/capsec-portable-fixture-evidence-v1.schema.json",
  "schemas/capsec-mapped-engine-execution-evidence-v1.schema.json",
];
const schemaIds = Object.freeze({
  attempt: "https://ibex.dev/schemas/capsec-command-attempt-v1.schema.json",
  evidence:
    "https://ibex.dev/schemas/capsec-mapped-engine-execution-evidence-v1.schema.json",
  fixture:
    "https://ibex.dev/schemas/capsec-portable-fixture-evidence-v1.schema.json",
  portable:
    "https://ibex.dev/schemas/portable-engine-artifact-identity-v1.schema.json",
});
const stableId = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u;
let compiledValidators;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function validators() {
  if (compiledValidators) return compiledValidators;
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const relativePath of schemaFiles) {
    ajv.addSchema(
      parseJsonStrict(
        fs.readFileSync(path.join(repoRoot, relativePath)),
        relativePath,
      ),
    );
  }
  compiledValidators = Object.fromEntries(
    Object.entries(schemaIds).map(([name, id]) => [name, ajv.getSchema(id)]),
  );
  invariant(
    Object.values(compiledValidators).every(Boolean),
    "portable live evidence schemas did not compile",
  );
  return compiledValidators;
}

function validateSchema(name, value, label) {
  const validate = validators()[name];
  invariant(
    validate(value),
    `${label} schema invalid: ${validate.errors
      ?.map((error) => error.message)
      .join(", ")}`,
  );
  return value;
}

function parseValidated(bytes, name, label) {
  invariant(Buffer.isBuffer(bytes), `${label} must be exact bytes`);
  return validateSchema(name, parseJsonStrict(bytes, label), label);
}

function assertCanonicalSet(values, label) {
  invariant(Array.isArray(values), `${label} must be an array`);
  const sorted = [...new Set(values)].sort(compareUtf8);
  invariant(same(values, sorted), `${label} must be UTF-8 sorted and unique`);
}

const ownedByCurrentUser = (metadata) =>
  typeof process.getuid !== "function" || metadata.uid === process.getuid();

function readOwnedBytes(filePath, label) {
  const before = fs.lstatSync(filePath);
  invariant(
    !before.isSymbolicLink() &&
      before.isFile() &&
      before.nlink === 1 &&
      ownedByCurrentUser(before),
    `${label} must be an owned regular file`,
  );
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = fs.fstatSync(descriptor);
    invariant(
      opened.isFile() &&
        opened.nlink === 1 &&
        opened.dev === before.dev &&
        opened.ino === before.ino &&
        ownedByCurrentUser(opened),
      `${label} changed while opening`,
    );
    const bytes = fs.readFileSync(descriptor);
    const finalized = fs.fstatSync(descriptor);
    const after = fs.lstatSync(filePath);
    invariant(
      finalized.isFile() &&
        finalized.nlink === 1 &&
        finalized.dev === opened.dev &&
        finalized.ino === opened.ino &&
        finalized.size === opened.size &&
        finalized.mtimeMs === opened.mtimeMs &&
        finalized.ctimeMs === opened.ctimeMs &&
      !after.isSymbolicLink() &&
        after.isFile() &&
        after.nlink === 1 &&
        ownedByCurrentUser(after) &&
        after.dev === opened.dev &&
        after.ino === opened.ino &&
        after.size === opened.size &&
        after.mtimeMs === opened.mtimeMs &&
        after.ctimeMs === opened.ctimeMs,
      `${label} changed while reading`,
    );
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function exactJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

/** Parse the exact build marker. Only `null\n` selects legacy v1 behavior. */
export function parsePortableEngineIdentityMarker(bytes) {
  invariant(Buffer.isBuffer(bytes), "portable engine identity marker must be bytes");
  if (bytes.equals(Buffer.from("null\n", "utf8"))) return null;
  invariant(
    !/^\s*null\s*$/u.test(bytes.toString("utf8")),
    "legacy portable identity marker must be exactly null followed by LF",
  );
  return parseValidated(bytes, "portable", "portable engine identity marker");
}

export function buildPortableEvidencePlan({
  bindings,
  evidenceDirectory,
  fixtureIds,
}) {
  assertCanonicalSet(fixtureIds, "portable evidence fixtureIds");
  for (const fixtureId of fixtureIds) {
    invariant(stableId.test(fixtureId), `invalid portable fixture ID ${fixtureId}`);
  }
  const fixtureOutputs = fixtureIds.map((fixtureId, index) => {
    const suffix = crypto
      .createHash("sha256")
      .update(fixtureId)
      .digest("hex")
      .slice(0, 16);
    return {
      fixtureId,
      path: path.join(
        evidenceDirectory,
        `portable-fixture-${String(index + 1).padStart(4, "0")}-${suffix}.json`,
      ),
    };
  });
  const bindingDigest = portableExecutionBindingDigest(bindings);
  return {
    plan: {
      portableEvidencePlanSchema: "ibex/capsec-portable-evidence-plan/1",
      profile: "ibex/capsec/1",
      bindings,
      bindingDigest,
      fixtureOutputs,
    },
    fixtureOutputs,
    mappedEvidencePath: path.join(
      evidenceDirectory,
      "mapped-engine-execution-evidence.json",
    ),
  };
}

function validateMappedIdentity(mapped, engine, target) {
  invariant(same(mapped.portable, engine), "mapped identity carries another portable engine");
  invariant(
    same(mapped.before.object, mapped.localObject) &&
      same(mapped.after.object, mapped.localObject),
    "mapped before/after observations name another local object",
  );
  invariant(
    mapped.before.digest === engine.runtimeComponentDigest &&
      mapped.after.digest === engine.runtimeComponentDigest &&
      mapped.before.size === mapped.after.size,
    "mapped observations differ from the portable runtime bytes",
  );
  invariant(
    mapped.processArchitecture === target.triple.split("-")[0],
    "mapped process architecture differs from the exact target",
  );
  invariant(
    mapped.observationDigest ===
      computeDomainDigest("ibex.mapped-engine-instance-identity.v1", mapped, [
        "observationDigest",
      ]),
    "mapped observation digest is stale",
  );
  const proof = mapped.mappingProof;
  const platform = proof.platformObservation;
  if (target.triple.endsWith("-apple-darwin")) {
    invariant(
      proof.class === "macos-proc-pid-region-path-info" &&
        platform.platform === "macos" &&
        same(platform.mappedObject, mapped.localObject),
      "mapped identity has the wrong macOS mapping proof",
    );
  } else if (target.triple.endsWith("-pc-windows-msvc")) {
    invariant(
      proof.class === "windows-locked-module-closure" &&
        platform.platform === "windows" &&
        same(platform.runtimeModule.object, mapped.localObject),
      "mapped identity has the wrong Windows mapping proof",
    );
  } else {
    invariant(
      proof.class === "linux-proc-self-maps" &&
        platform.platform === "linux" &&
        same(platform.mappedObject, mapped.localObject),
      "mapped identity has the wrong Linux mapping proof",
    );
  }
}

/**
 * Validate one live engine-using process after its supervisor attempt has
 * finalized. The returned report slice contains no host-local mapped values.
 */
export function validateLivePortableProcess({
  attempt,
  bindings,
  fixtureOutputs,
  mappedEvidencePath,
}) {
  validateSchema("attempt", attempt, "supervisor command attempt");
  invariant(
    attempt.attemptDigest === commandAttemptDigest(attempt),
    "supervisor command attempt digest is stale",
  );
  invariant(
    attempt.classification === "success" &&
      attempt.exitCode === 0 &&
      attempt.cleanup.cleanupProven,
    "portable process requires one successful clean attempt",
  );
  const mappedEvidenceBytes = readOwnedBytes(
    mappedEvidencePath,
    "mapped-engine execution evidence",
  );
  const evidence = parseValidated(
    mappedEvidenceBytes,
    "evidence",
    "mapped-engine execution evidence",
  );
  invariant(
    evidence.evidenceDigest === mappedEngineExecutionEvidenceDigest(evidence),
    "mapped-engine execution evidence digest is stale",
  );
  invariant(
    attempt.commandId === evidence.commandId &&
      attempt.phase === evidence.phaseId &&
      attempt.commandIdentity === evidence.commandIdentityDigest,
    "mapped evidence names another command or process attempt",
  );
  invariant(
    evidence.sourceRevision === bindings.sourceRevision &&
      evidence.sourceTreeDigest === bindings.sourceTreeDigest &&
      same(evidence.target, bindings.target) &&
      same(evidence.engine, bindings.engine),
    "mapped evidence differs from the portable execution bindings",
  );
  validateMappedIdentity(evidence.mappedEngine, bindings.engine, bindings.target);

  const mappedRawDigest = rawContentDigest(mappedEvidenceBytes);
  const expectedPaths = new Set([
    mappedEvidencePath,
    ...fixtureOutputs.map((output) => output.path),
  ]);
  invariant(
    attempt.outputs.length === expectedPaths.size &&
      attempt.outputs.every((output) => expectedPaths.has(output.path)),
    "supervisor output membership differs from the portable evidence plan",
  );
  const rowByPath = new Map(attempt.outputs.map((output) => [output.path, output]));
  invariant(
    rowByPath.size === attempt.outputs.length,
    "supervisor attempt repeats an output path",
  );
  invariant(
    new Set(attempt.outputs.map((output) => output.digest)).size ===
      attempt.outputs.length,
    "supervisor attempt has ambiguous equal-digest outputs",
  );
  const mappedRow = rowByPath.get(mappedEvidencePath);
  invariant(
    mappedRow?.digest === mappedRawDigest &&
      mappedRow.bytes === mappedEvidenceBytes.byteLength,
    "mapped evidence bytes differ from the finalized supervisor output",
  );

  const outputArtifactBytes = [];
  const executions = [];
  const fixtureIds = [];
  const outputDigests = [];
  const expectedBindingDigest = portableExecutionBindingDigest(bindings);
  for (const output of fixtureOutputs) {
    const bytes = readOwnedBytes(output.path, `${output.fixtureId} fixture evidence`);
    const fixture = parseValidated(
      bytes,
      "fixture",
      `${output.fixtureId} fixture evidence`,
    );
    const rawDigest = rawContentDigest(bytes);
    const row = rowByPath.get(output.path);
    invariant(
      row?.digest === rawDigest && row.bytes === bytes.byteLength,
      `${output.fixtureId}: fixture bytes differ from the finalized supervisor output`,
    );
    invariant(
      fixture.artifactDigest === portableFixtureEvidenceDigest(fixture),
      `${output.fixtureId}: portable fixture artifact digest is stale`,
    );
    invariant(
      fixture.fixtureId === output.fixtureId &&
        fixture.sourceRevision === bindings.sourceRevision &&
        fixture.sourceTreeDigest === bindings.sourceTreeDigest &&
        same(fixture.target, bindings.target) &&
        same(fixture.engine, bindings.engine) &&
        fixture.bindingDigest === expectedBindingDigest,
      `${output.fixtureId}: fixture differs from its portable execution binding`,
    );
    fixtureIds.push(fixture.fixtureId);
    outputDigests.push(rawDigest);
    outputArtifactBytes.push(bytes);
    executions.push({
      fixtureId: fixture.fixtureId,
      outcome: fixture.outcome,
      executor: fixture.executor,
      artifactDigest: fixture.artifactDigest,
      rawContentDigest: rawDigest,
      bindingDigest: fixture.bindingDigest,
      mappedEngineExecutionEvidenceDigest: evidence.evidenceDigest,
    });
  }
  fixtureIds.sort(compareUtf8);
  outputDigests.sort(compareUtf8);
  executions.sort((left, right) => compareUtf8(left.fixtureId, right.fixtureId));
  invariant(
    same(evidence.fixtureIds, fixtureIds),
    "mapped evidence fixture membership differs from declared output bytes",
  );
  invariant(
    same(evidence.outputDigests, outputDigests),
    "mapped evidence output digests differ from declared output bytes",
  );

  const commandAttemptBytes = exactJsonBytes(attempt);
  const reference = {
    evidenceDigest: evidence.evidenceDigest,
    rawContentDigest: mappedRawDigest,
    attemptDigest: attempt.attemptDigest,
    attemptRawContentDigest: rawContentDigest(commandAttemptBytes),
  };
  return {
    evidence,
    process: {
      mappedEvidenceBytes,
      commandAttemptBytes,
      outputArtifactBytes,
    },
    reportSlice: {
      portableReportSliceSchema: "ibex/capsec-portable-report-slice/1",
      profile: "ibex/capsec/1",
      bindings: {
        ...bindings,
        mappedEngineExecutionEvidence: [reference],
      },
      executions,
    },
  };
}

export function portableReportSliceBytes(reportSlice) {
  return exactJsonBytes(reportSlice);
}
