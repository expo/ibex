/**
 * Build the LLP 0033 restricted runtime with and without its conformance
 * observer, execute the same production-only transcript fixture, and require
 * canonical output equality.
 *
 * @ref LLP 0033#third-review-disposition-and-executable-route-v2
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  parseJsonStrict,
  repoRoot,
} from "./capsec-contract.mjs";
import {
  assertExactKeys,
  validateEngine,
  validateRevisionAndAuthorities,
} from "./restricted-exact-reachable-evidence.mjs";
import {
  loadRestrictedReportAuthorities,
  taggedDigest,
} from "./restricted-exact-target-report.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-exact-observer-equivalence-evidence/1";
const TRANSCRIPT_SCHEMA = "ibex/restricted-exact-observer-equivalence-transcript/1";
const RESULT_MARKER = "ibex-restricted-observer-equivalence:passed";
const TEST_NAME = "host::embedder_artifacts::tests::restricted_exact_observer_build_equivalence_transcript";
const COMPARISON_FIELDS = Object.freeze([
  "descriptorSnapshot",
  "checkpointBytes",
  "eventAndPollResults",
  "callbackTranscript",
  "poisonState",
  "teardownResult",
]);

function digestFile(filePath) {
  return taggedDigest(fs.readFileSync(filePath));
}

function bindingProjection(artifact, patchIdentity) {
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

function expectedBuildCommand(observerEnabled) {
  const command = [
    "cargo", "test", "-p", "ibex-runtime", "--lib", "--release",
  ];
  if (observerEnabled) {
    command.push("--features", "capsec-conformance-observer");
  }
  command.push("--no-run", "--message-format=json");
  return command;
}

function expectedExecuteCommand() {
  return [
    "<compiled-rust-test-binary>",
    TEST_NAME,
    "--exact",
    "--nocapture",
    "--test-threads=1",
  ];
}

function validateTranscript(transcript, label) {
  assertExactKeys(
    transcript,
    ["schema", ...COMPARISON_FIELDS],
    `${label} restricted observer-equivalence transcript`,
  );
  if (transcript.schema !== TRANSCRIPT_SCHEMA) {
    throw new Error(`${label} restricted observer-equivalence transcript schema drift`);
  }
  for (const field of ["descriptorSnapshot", "checkpointBytes"]) {
    if (
      !Array.isArray(transcript[field])
      || transcript[field].length === 0
      || transcript[field].some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
    ) {
      throw new Error(`${label} restricted observer-equivalence ${field} is malformed`);
    }
  }
  for (const field of COMPARISON_FIELDS.slice(2)) {
    if (
      transcript[field] === null
      || typeof transcript[field] !== "object"
      || Array.isArray(transcript[field])
      || Object.keys(transcript[field]).length === 0
    ) {
      throw new Error(`${label} restricted observer-equivalence ${field} is malformed`);
    }
  }
}

export function validateRestrictedObserverTranscriptPair({ builds, comparison }) {
  if (!Array.isArray(builds) || builds.length !== 2) {
    throw new Error("restricted observer-equivalence must contain exactly two builds");
  }
  const expected = [
    ["observer-disabled", false, []],
    ["observer-enabled", true, ["capsec-conformance-observer"]],
  ];
  for (const [index, [label, observerEnabled, featureSet]] of expected.entries()) {
    const build = builds[index];
    assertExactKeys(
      build,
      [
        "label",
        "observerEnabled",
        "featureSet",
        "buildCommand",
        "executeCommand",
        "testBinaryDigest",
        "transcriptRawBase64",
        "transcriptRawContentDigest",
        "transcriptCanonicalDigest",
        "transcript",
        "exitCode",
        "resultMarker",
      ],
      `${label} restricted observer-equivalence build`,
    );
    if (
      build.label !== label
      || build.observerEnabled !== observerEnabled
      || canonicalJson(build.featureSet) !== canonicalJson(featureSet)
      || canonicalJson(build.buildCommand) !== canonicalJson(expectedBuildCommand(observerEnabled))
      || canonicalJson(build.executeCommand) !== canonicalJson(expectedExecuteCommand())
      || !/^sha256-[A-Za-z0-9_-]{43}$/u.test(build.testBinaryDigest)
      || typeof build.transcriptRawBase64 !== "string"
      || Buffer.from(build.transcriptRawBase64, "base64").toString("base64")
        !== build.transcriptRawBase64
      || build.transcriptRawContentDigest
        !== taggedDigest(Buffer.from(build.transcriptRawBase64, "base64"))
      || canonicalJson(parseJsonStrict(
        Buffer.from(build.transcriptRawBase64, "base64"),
        `${label} embedded raw transcript`,
      )) !== canonicalJson(build.transcript)
      || build.transcriptCanonicalDigest
        !== taggedDigest(Buffer.from(canonicalJson(build.transcript), "utf8"))
      || build.exitCode !== 0
      || build.resultMarker !== `ibex-restricted-observer-equivalence:passed:${label}`
    ) {
      throw new Error(`${label} restricted observer-equivalence build drift`);
    }
    validateTranscript(build.transcript, label);
  }
  const disabled = builds[0];
  const enabled = builds[1];
  assertExactKeys(
    comparison,
    ["fields", "rawBytesEqual", "canonicalEqual", "canonicalTranscriptDigest"],
    "restricted observer-equivalence comparison",
  );
  if (
    canonicalJson(comparison.fields) !== canonicalJson(COMPARISON_FIELDS)
    || comparison.rawBytesEqual !== true
    || comparison.canonicalEqual !== true
    || disabled.transcriptRawContentDigest !== enabled.transcriptRawContentDigest
    || disabled.transcriptCanonicalDigest !== enabled.transcriptCanonicalDigest
    || disabled.transcriptCanonicalDigest !== comparison.canonicalTranscriptDigest
    || canonicalJson(disabled.transcript) !== canonicalJson(enabled.transcript)
  ) {
    throw new Error("restricted observer-enabled and disabled transcripts differ");
  }
}

export function validateRestrictedObserverEquivalenceEvidence(
  rawBytes,
  bindingEvidenceBytes,
  authorities = undefined,
) {
  const reportAuthorities = authorities ?? loadRestrictedReportAuthorities();
  const artifact = parseJsonStrict(rawBytes, "restricted observer-equivalence evidence");
  const binding = parseJsonStrict(
    bindingEvidenceBytes,
    "restricted observer-equivalence binding evidence",
  );
  assertExactKeys(
    artifact,
    [
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
      "builds",
      "comparison",
      "exitCode",
      "resultMarker",
    ],
    "restricted observer-equivalence evidence",
  );
  if (
    artifact.evidenceSchema !== EVIDENCE_SCHEMA
    || artifact.profile !== "ibex/exact-embedder-contract/1"
    || artifact.exitCode !== 0
    || artifact.resultMarker !== RESULT_MARKER
  ) {
    throw new Error("restricted observer-equivalence evidence is not a passing v1 artifact");
  }
  if (taggedDigest(bindingEvidenceBytes) !== artifact.bindingEvidenceRawContentDigest) {
    throw new Error("restricted observer-equivalence binding digest mismatch");
  }
  validateRevisionAndAuthorities(artifact, reportAuthorities);
  const patchIdentity = validateEngine(artifact);
  const bindingPatchIdentity = validateEngine(binding);
  if (
    canonicalJson(bindingProjection(artifact, patchIdentity))
      !== canonicalJson(bindingProjection(binding, bindingPatchIdentity))
  ) {
    throw new Error("restricted observer-equivalence and per-edge bindings differ");
  }
  validateRestrictedObserverTranscriptPair(artifact);
  return artifact;
}

function parseArgs(argv) {
  const value = (flag) => {
    const index = argv.indexOf(flag);
    if (index < 0 || index + 1 >= argv.length) throw new Error(`missing ${flag}`);
    return argv[index + 1];
  };
  return {
    bindingEvidencePath: path.resolve(repoRoot, value("--binding-evidence")),
    outputPath: path.resolve(repoRoot, value("--output")),
    scratchRoot: argv.includes("--scratch-root")
      ? path.resolve(repoRoot, value("--scratch-root"))
      : path.join(repoRoot, "target/restricted-exact-observer-equivalence"),
  };
}

function runBuild({ label, observerEnabled, scratchRoot, environment }) {
  const targetDirectory = path.join(scratchRoot, label);
  fs.mkdirSync(targetDirectory, { recursive: true });
  const transcriptPath = path.join(targetDirectory, "transcript.json");
  fs.rmSync(transcriptPath, { force: true });
  const buildCommand = expectedBuildCommand(observerEnabled);
  const build = spawnSync(buildCommand[0], buildCommand.slice(1), {
    cwd: repoRoot,
    env: { ...environment, CARGO_TARGET_DIR: targetDirectory },
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
    timeout: 30 * 60 * 1000,
  });
  if (build.error || build.status !== 0) {
    process.stderr.write(build.stdout ?? "");
    process.stderr.write(build.stderr ?? "");
    throw new Error(`${label} restricted observer-equivalence release build failed`);
  }
  const artifacts = (build.stdout ?? "")
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line))
    .filter((message) => (
      message.reason === "compiler-artifact"
      && message.target?.name === "ibex_runtime"
      && message.profile?.test === true
      && typeof message.executable === "string"
    ));
  if (artifacts.length !== 1) {
    throw new Error(`${label} restricted observer-equivalence test binary was ambiguous`);
  }
  const executable = artifacts[0].executable;
  const executeCommand = expectedExecuteCommand();
  const run = spawnSync(executable, executeCommand.slice(1), {
    cwd: repoRoot,
    env: {
      ...environment,
      CARGO_TARGET_DIR: targetDirectory,
      IBEX_RESTRICTED_OBSERVER_EQUIVALENCE_OUTPUT: transcriptPath,
    },
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
    timeout: 180_000,
  });
  const combined = Buffer.concat([run.stdout ?? Buffer.alloc(0), run.stderr ?? Buffer.alloc(0)]);
  const rendered = combined.toString("utf8");
  if (
    run.error
    || run.status !== 0
    || !rendered.includes("test result: ok")
    || !rendered.includes("1 passed")
    || !fs.existsSync(transcriptPath)
  ) {
    process.stderr.write(combined);
    throw new Error(`${label} restricted observer-equivalence transcript fixture failed`);
  }
  const rawTranscript = fs.readFileSync(transcriptPath);
  const transcript = parseJsonStrict(rawTranscript, transcriptPath);
  validateTranscript(transcript, label);
  return {
    label,
    observerEnabled,
    featureSet: observerEnabled ? ["capsec-conformance-observer"] : [],
    buildCommand,
    executeCommand,
    testBinaryDigest: digestFile(executable),
    transcriptRawBase64: rawTranscript.toString("base64"),
    transcriptRawContentDigest: taggedDigest(rawTranscript),
    transcriptCanonicalDigest: taggedDigest(Buffer.from(canonicalJson(transcript), "utf8")),
    transcript,
    exitCode: run.status,
    resultMarker: `ibex-restricted-observer-equivalence:passed:${label}`,
  };
}

function main() {
  const { bindingEvidencePath, outputPath, scratchRoot } = parseArgs(process.argv.slice(2));
  const sourceRevision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8",
  }).trim();
  const dirty = execFileSync(
    "git",
    ["status", "--porcelain", "--untracked-files=no"],
    { cwd: repoRoot },
  );
  if (dirty.length !== 0) {
    throw new Error("restricted observer-equivalence run requires a clean tracked source tree");
  }
  const bindingRaw = fs.readFileSync(bindingEvidencePath);
  const binding = parseJsonStrict(bindingRaw, bindingEvidencePath);
  if (binding.sourceRevision !== sourceRevision) {
    throw new Error("restricted observer-equivalence binding used a different source revision");
  }
  if (digestFile(binding.engine.engineArtifactPath) !== binding.engine.binaryDigest) {
    throw new Error("restricted observer-equivalence loaded engine differs from binding evidence");
  }
  if (
    digestFile(binding.hermesProfileProvenance.path)
      !== binding.hermesProfileProvenance.rawContentDigest
  ) {
    throw new Error("restricted observer-equivalence Hermes provenance receipt changed");
  }

  const environment = { ...process.env };
  delete environment.IBEX_RESTRICTED_OBSERVER_EQUIVALENCE_OUTPUT;
  delete environment.IBEX_RESTRICTED_REACHABLE_EVIDENCE_OUTPUT;
  delete environment.IBEX_RESTRICTED_CONTROL_EVIDENCE_OUTPUT;
  delete environment.IBEX_RESTRICTED_ABSENCE_EVIDENCE_OUTPUT;
  const builds = [
    runBuild({ label: "observer-disabled", observerEnabled: false, scratchRoot, environment }),
    runBuild({ label: "observer-enabled", observerEnabled: true, scratchRoot, environment }),
  ];
  const rawBytesEqual = builds[0].transcriptRawContentDigest
    === builds[1].transcriptRawContentDigest;
  const canonicalEqual = canonicalJson(builds[0].transcript)
    === canonicalJson(builds[1].transcript);
  if (!rawBytesEqual || !canonicalEqual) {
    throw new Error("restricted observer-enabled and disabled transcripts differ");
  }

  const artifact = {
    evidenceSchema: EVIDENCE_SCHEMA,
    profile: binding.profile,
    runId: `restricted-observer-equivalence-${crypto.randomBytes(16).toString("hex")}`,
    sourceRevision,
    sourceTreeDigest: binding.sourceTreeDigest,
    target: binding.target,
    engine: binding.engine,
    hermesProfileProvenance: binding.hermesProfileProvenance,
    authorityDigests: binding.authorityDigests,
    bindingEvidenceRawContentDigest: taggedDigest(bindingRaw),
    commandEnvironment: {
      runner: process.execPath,
      platform: process.platform,
      architecture: process.arch,
      rustc: execFileSync("rustc", ["-Vv"], { encoding: "utf8" }).trim(),
      cargo: execFileSync("cargo", ["-V"], { encoding: "utf8" }).trim(),
    },
    builds,
    comparison: {
      fields: COMPARISON_FIELDS,
      rawBytesEqual,
      canonicalEqual,
      canonicalTranscriptDigest: builds[0].transcriptCanonicalDigest,
    },
    exitCode: 0,
    resultMarker: RESULT_MARKER,
  };
  const serialized = Buffer.from(`${JSON.stringify(JSON.parse(canonicalJson(artifact)), null, 2)}\n`);
  validateRestrictedObserverEquivalenceEvidence(serialized, bindingRaw);
  const fd = fs.openSync(outputPath, "wx", 0o644);
  try {
    fs.writeFileSync(fd, serialized);
  } finally {
    fs.closeSync(fd);
  }
  console.log(JSON.stringify({
    outputPath,
    sourceRevision,
    target: binding.target,
    transcriptDigest: builds[0].transcriptCanonicalDigest,
    equivalent: true,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
