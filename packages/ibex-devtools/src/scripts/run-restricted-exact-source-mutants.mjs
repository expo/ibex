/** Execute the five source-level LLP 0033 restricted-profile mutants. */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { canonicalJson, parseJsonStrict, repoRoot } from "./capsec-contract.mjs";
import {
  assertExactKeys,
  validateEngine,
  validateRevisionAndAuthorities,
} from "./restricted-exact-reachable-evidence.mjs";
import {
  loadRestrictedReportAuthorities,
  taggedDigest,
} from "./restricted-exact-target-report.mjs";

const EVIDENCE_SCHEMA = "ibex/restricted-exact-source-mutants-evidence/1";
const RESULT_MARKER = "ibex-restricted-source-mutants:passed";
const TEST_NAME = "host::embedder_artifacts::tests::restricted_exact_source_mutant_detection_fixture";
const RUNTIME_SOURCE = "src/engine/hermes_runtime.cc";

const restrictedInstallerNeedle = `  installTimerGlobals(handle, false);

  auto exactObject = rt.global().getPropertyAsObject(rt, "exact");`;

export const restrictedExactSourceMutants = Object.freeze([
  Object.freeze({
    id: "select-full-installer",
    sourcePath: RUNTIME_SOURCE,
    before: `      installRestrictedExactGlobals(handle);
    } else {`,
    after: `      installGlobals(handle);
    } else {`,
    expectedFailureMarker: "restricted source-mutant detector: bootstrap posture",
  }),
  Object.freeze({
    id: "install-module-loader",
    sourcePath: RUNTIME_SOURCE,
    before: restrictedInstallerNeedle,
    after: `  installTimerGlobals(handle, false);
  (void)installModuleLoader(handle);

  auto exactObject = rt.global().getPropertyAsObject(rt, "exact");`,
    expectedFailureMarker: "restricted source-mutant detector: bootstrap posture",
  }),
  Object.freeze({
    id: "install-forbidden-global",
    sourcePath: RUNTIME_SOURCE,
    before: restrictedInstallerNeedle,
    after: `  installTimerGlobals(handle, false);
  rt.global().setProperty(rt, "process", facebook::jsi::Value(1));

  auto exactObject = rt.global().getPropertyAsObject(rt, "exact");`,
    expectedFailureMarker: "restricted source-mutant detector: bootstrap posture",
  }),
  Object.freeze({
    id: "retain-callback-after-global-deletion",
    sourcePath: RUNTIME_SOURCE,
    before: restrictedInstallerNeedle,
    after: `  installTimerGlobals(handle, false);
  auto retainedCallback = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__hostCall"),
      0,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) { return facebook::jsi::Value::undefined(); });
  rt.global().setProperty(rt, "__hostCall", std::move(retainedCallback));
  auto retainedValue = rt.global().getProperty(rt, "__hostCall");
  handle->structured_unhandled_rejection_handler =
      std::make_unique<facebook::jsi::Function>(
          retainedValue.asObject(rt).asFunction(rt));
  auto deleted = rt.global()
                     .getPropertyAsObject(rt, "Reflect")
                     .getPropertyAsFunction(rt, "deleteProperty")
                     .call(
                         rt,
                         rt.global(),
                         facebook::jsi::String::createFromAscii(
                             rt, "__hostCall"));
  if (!deleted.isBool() || !deleted.getBool()) {
    throw std::runtime_error("source mutant could not delete retained callback global");
  }

  auto exactObject = rt.global().getPropertyAsObject(rt, "exact");`,
    expectedFailureMarker: "restricted source-mutant detector: bootstrap posture",
  }),
  Object.freeze({
    id: "lazy-global-after-poll",
    sourcePath: RUNTIME_SOURCE,
    before: `  const int result = pollRuntime(runtime, now_ms, false);
  if (result >= 0 && runtime->restricted_exact) {`,
    after: `  const int result = pollRuntime(runtime, now_ms, false);
  if (result >= 0 && runtime->restricted_exact) {
    runtime->runtime->global().setProperty(
        *runtime->runtime, "process", facebook::jsi::Value(1));
  }
  if (result >= 0 && runtime->restricted_exact) {`,
    expectedFailureMarker: "restricted source-mutant detector: temporal posture",
  }),
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

function expectedBuildCommand() {
  return [
    "cargo", "test", "-p", "ibex-runtime", "--lib", "--release",
    "--features", "capsec-conformance-observer", "--no-run", "--message-format=json",
  ];
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

function applyExactMutation(source, mutant) {
  const first = source.indexOf(mutant.before);
  if (first < 0 || source.indexOf(mutant.before, first + 1) >= 0) {
    throw new Error(`source mutant ${mutant.id} anchor is missing or ambiguous`);
  }
  return `${source.slice(0, first)}${mutant.after}${source.slice(first + mutant.before.length)}`;
}

export function validateRestrictedSourceMutantExecutions(executions) {
  if (!Array.isArray(executions) || executions.length !== restrictedExactSourceMutants.length) {
    throw new Error("restricted source-mutant execution count drift");
  }
  for (const [index, mutant] of restrictedExactSourceMutants.entries()) {
    const execution = executions[index];
    assertExactKeys(
      execution,
      [
        "mutantId", "sourcePath", "beforeBase64", "afterBase64",
        "originalSourceRawContentDigest", "mutatedSourceRawContentDigest",
        "diffBase64", "diffRawContentDigest", "buildCommand", "executeCommand",
        "testBinaryDigest", "buildExitCode", "testExitCode",
        "expectedFailureMarker", "outputBase64", "outputRawContentDigest",
        "resultMarker",
      ],
      `restricted source mutant ${mutant.id}`,
    );
    const sourcePath = path.join(repoRoot, mutant.sourcePath);
    const source = fs.readFileSync(sourcePath, "utf8");
    const mutated = applyExactMutation(source, mutant);
    const output = Buffer.from(execution.outputBase64, "base64");
    const diff = Buffer.from(execution.diffBase64, "base64");
    if (
      execution.mutantId !== mutant.id
      || execution.sourcePath !== mutant.sourcePath
      || execution.beforeBase64 !== Buffer.from(mutant.before).toString("base64")
      || execution.afterBase64 !== Buffer.from(mutant.after).toString("base64")
      || execution.originalSourceRawContentDigest !== taggedDigest(Buffer.from(source))
      || execution.mutatedSourceRawContentDigest !== taggedDigest(Buffer.from(mutated))
      || execution.diffRawContentDigest !== taggedDigest(diff)
      || diff.length === 0
      || canonicalJson(execution.buildCommand) !== canonicalJson(expectedBuildCommand())
      || canonicalJson(execution.executeCommand) !== canonicalJson(expectedExecuteCommand())
      || !/^sha256-[A-Za-z0-9_-]{43}$/u.test(execution.testBinaryDigest)
      || execution.buildExitCode !== 0
      || !Number.isInteger(execution.testExitCode)
      || execution.testExitCode === 0
      || execution.expectedFailureMarker !== mutant.expectedFailureMarker
      || execution.outputRawContentDigest !== taggedDigest(output)
      || !output.toString("utf8").includes(mutant.expectedFailureMarker)
      || execution.resultMarker !== `ibex-restricted-source-mutant:detected:${mutant.id}`
    ) {
      throw new Error(`restricted source mutant ${mutant.id} evidence drift`);
    }
  }
}

export function validateRestrictedSourceMutantsEvidence(
  rawBytes,
  bindingEvidenceBytes,
  authorities = undefined,
) {
  const reportAuthorities = authorities ?? loadRestrictedReportAuthorities();
  const artifact = parseJsonStrict(rawBytes, "restricted source-mutants evidence");
  const binding = parseJsonStrict(bindingEvidenceBytes, "restricted source-mutants binding evidence");
  assertExactKeys(
    artifact,
    [
      "evidenceSchema", "profile", "runId", "sourceRevision", "sourceTreeDigest",
      "target", "engine", "hermesProfileProvenance", "authorityDigests",
      "bindingEvidenceRawContentDigest", "commandEnvironment", "executions",
      "exitCode", "resultMarker",
    ],
    "restricted source-mutants evidence",
  );
  if (
    artifact.evidenceSchema !== EVIDENCE_SCHEMA
    || artifact.profile !== "ibex/exact-embedder-contract/1"
    || artifact.exitCode !== 0
    || artifact.resultMarker !== RESULT_MARKER
  ) {
    throw new Error("restricted source-mutants evidence is not a passing v1 artifact");
  }
  if (taggedDigest(bindingEvidenceBytes) !== artifact.bindingEvidenceRawContentDigest) {
    throw new Error("restricted source-mutants binding digest mismatch");
  }
  validateRevisionAndAuthorities(artifact, reportAuthorities);
  const patchIdentity = validateEngine(artifact);
  const bindingPatchIdentity = validateEngine(binding);
  if (
    canonicalJson(bindingProjection(artifact, patchIdentity))
      !== canonicalJson(bindingProjection(binding, bindingPatchIdentity))
  ) {
    throw new Error("restricted source-mutants and per-edge bindings differ");
  }
  validateRestrictedSourceMutantExecutions(artifact.executions);
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
      ? path.resolve(value("--scratch-root"))
      : fs.mkdtempSync(path.join(os.tmpdir(), "ibex-restricted-source-mutants-")),
  };
}

function linkNativeBuildInputs(worktree, targetTriple) {
  const links = targetTriple.includes("apple")
    ? [["ios/Frameworks", "ios/Frameworks"], ["tools/hermes", "tools/hermes"]]
    : [["linux", "linux"], ["tools/hermes", "tools/hermes"]];
  for (const [sourceRelative, targetRelative] of links) {
    const source = path.join(repoRoot, sourceRelative);
    const target = path.join(worktree, targetRelative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.symlinkSync(source, target, "dir");
  }
}

function runMutant({ mutant, sourceRevision, target, scratchRoot, environment }) {
  const worktree = path.join(scratchRoot, mutant.id);
  execFileSync("git", ["worktree", "add", "--detach", worktree, sourceRevision], {
    cwd: repoRoot,
    stdio: "pipe",
  });
  try {
    linkNativeBuildInputs(worktree, target.triple);
    const sourcePath = path.join(worktree, mutant.sourcePath);
    const original = fs.readFileSync(sourcePath, "utf8");
    const mutated = applyExactMutation(original, mutant);
    fs.writeFileSync(sourcePath, mutated);
    const diff = execFileSync(
      "git",
      ["diff", "--no-ext-diff", "--", mutant.sourcePath],
      { cwd: worktree, maxBuffer: 16 * 1024 * 1024 },
    );
    if (diff.length === 0) throw new Error(`source mutant ${mutant.id} produced no diff`);

    const buildCommand = expectedBuildCommand();
    const cargoTarget = path.join(scratchRoot, "cargo-target");
    const build = spawnSync(buildCommand[0], buildCommand.slice(1), {
      cwd: worktree,
      env: { ...environment, CARGO_TARGET_DIR: cargoTarget },
      encoding: "utf8",
      maxBuffer: 128 * 1024 * 1024,
      timeout: 30 * 60 * 1000,
    });
    if (build.error || build.status !== 0) {
      process.stderr.write(build.stdout ?? "");
      process.stderr.write(build.stderr ?? "");
      throw new Error(`source mutant ${mutant.id} failed to compile`);
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
      throw new Error(`source mutant ${mutant.id} test binary was ambiguous`);
    }
    const executable = artifacts[0].executable;
    const executeCommand = expectedExecuteCommand();
    const run = spawnSync(executable, executeCommand.slice(1), {
      cwd: worktree,
      env: { ...environment, CARGO_TARGET_DIR: cargoTarget },
      encoding: null,
      maxBuffer: 64 * 1024 * 1024,
      timeout: 180_000,
    });
    const output = Buffer.concat([run.stdout ?? Buffer.alloc(0), run.stderr ?? Buffer.alloc(0)]);
    if (run.error || run.status === 0 || !output.toString("utf8").includes(mutant.expectedFailureMarker)) {
      process.stderr.write(output);
      throw new Error(`source mutant ${mutant.id} was not detected at its expected boundary`);
    }
    return {
      mutantId: mutant.id,
      sourcePath: mutant.sourcePath,
      beforeBase64: Buffer.from(mutant.before).toString("base64"),
      afterBase64: Buffer.from(mutant.after).toString("base64"),
      originalSourceRawContentDigest: taggedDigest(Buffer.from(original)),
      mutatedSourceRawContentDigest: taggedDigest(Buffer.from(mutated)),
      diffBase64: diff.toString("base64"),
      diffRawContentDigest: taggedDigest(diff),
      buildCommand,
      executeCommand,
      testBinaryDigest: digestFile(executable),
      buildExitCode: build.status,
      testExitCode: run.status,
      expectedFailureMarker: mutant.expectedFailureMarker,
      outputBase64: output.toString("base64"),
      outputRawContentDigest: taggedDigest(output),
      resultMarker: `ibex-restricted-source-mutant:detected:${mutant.id}`,
    };
  } finally {
    execFileSync("git", ["worktree", "remove", "--force", worktree], {
      cwd: repoRoot,
      stdio: "pipe",
    });
  }
}

function main() {
  const { bindingEvidencePath, outputPath, scratchRoot } = parseArgs(process.argv.slice(2));
  const sourceRevision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8",
  }).trim();
  const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=no"], {
    cwd: repoRoot,
  });
  if (dirty.length !== 0) {
    throw new Error("restricted source-mutant run requires a clean tracked source tree");
  }
  const bindingRaw = fs.readFileSync(bindingEvidencePath);
  const binding = parseJsonStrict(bindingRaw, bindingEvidencePath);
  if (binding.sourceRevision !== sourceRevision) {
    throw new Error("restricted source-mutant binding used a different source revision");
  }
  if (digestFile(binding.engine.engineArtifactPath) !== binding.engine.binaryDigest) {
    throw new Error("restricted source-mutant loaded engine differs from binding evidence");
  }
  if (digestFile(binding.hermesProfileProvenance.path)
      !== binding.hermesProfileProvenance.rawContentDigest) {
    throw new Error("restricted source-mutant Hermes provenance receipt changed");
  }
  const environment = { ...process.env };
  for (const name of [
    "IBEX_RESTRICTED_OBSERVER_EQUIVALENCE_OUTPUT",
    "IBEX_RESTRICTED_REACHABLE_EVIDENCE_OUTPUT",
    "IBEX_RESTRICTED_CONTROL_EVIDENCE_OUTPUT",
    "IBEX_RESTRICTED_ABSENCE_EVIDENCE_OUTPUT",
  ]) delete environment[name];
  const executions = restrictedExactSourceMutants.map((mutant) => runMutant({
    mutant,
    sourceRevision,
    target: binding.target,
    scratchRoot,
    environment,
  }));
  const artifact = {
    evidenceSchema: EVIDENCE_SCHEMA,
    profile: binding.profile,
    runId: `restricted-source-mutants-${crypto.randomBytes(16).toString("hex")}`,
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
    executions,
    exitCode: 0,
    resultMarker: RESULT_MARKER,
  };
  const serialized = Buffer.from(`${JSON.stringify(JSON.parse(canonicalJson(artifact)), null, 2)}\n`);
  validateRestrictedSourceMutantsEvidence(serialized, bindingRaw);
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
    mutantsDetected: executions.length,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
