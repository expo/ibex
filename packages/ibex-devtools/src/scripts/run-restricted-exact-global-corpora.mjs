/** Execute the preregistered LLP 0033 global corpora on one bound engine. */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { canonicalJson, parseJsonStrict, repoRoot } from "./capsec-contract.mjs";
import { taggedDigest } from "./restricted-exact-target-report.mjs";

export const restrictedGlobalCorpusPlan = Object.freeze([
  Object.freeze({
    id: "artifact-tamper",
    tests: Object.freeze([
      "restricted_exact_builder_binds_one_immutable_candidate_bundle",
      "restricted_exact_builder_rejects_format_and_engine_confusion",
    ]),
  }),
  Object.freeze({
    id: "hostile-lifecycle",
    tests: Object.freeze([
      "restricted_exact_startup_checkpoint_failures_poison_the_runtime",
      "restricted_exact_event_checkpoint_failures_poison_the_runtime",
    ]),
  }),
  Object.freeze({
    id: "loader-and-bridge-absence",
    tests: Object.freeze([
      "restricted_exact_runtime_has_authenticated_single_use_ingress",
      "restricted_exact_absence_edges_close_source_and_live_routes",
    ]),
  }),
  Object.freeze({
    id: "profile-confusion",
    tests: Object.freeze([
      "restricted_exact_builder_binds_one_immutable_candidate_bundle",
      "restricted_exact_builder_rejects_format_and_engine_confusion",
      "restricted_exact_runtime_has_authenticated_single_use_ingress",
    ]),
  }),
  Object.freeze({
    id: "teardown",
    tests: Object.freeze([
      "restricted_exact_control_plane_edges_enforce_lifecycle_refusals",
      "restricted_exact_startup_checkpoint_failures_poison_the_runtime",
      "restricted_exact_event_checkpoint_failures_poison_the_runtime",
    ]),
  }),
]);

function digestFile(filePath) {
  return `sha256-${crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("base64url")}`;
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
  };
}

function main() {
  const { bindingEvidencePath, outputPath } = parseArgs(process.argv.slice(2));
  const sourceRevision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8",
  }).trim();
  const dirty = execFileSync(
    "git",
    ["status", "--porcelain", "--untracked-files=no"],
    { cwd: repoRoot },
  );
  if (dirty.length !== 0) throw new Error("global corpus run requires a clean tracked source tree");
  const bindingRaw = fs.readFileSync(bindingEvidencePath);
  const binding = parseJsonStrict(bindingRaw, bindingEvidencePath);
  if (binding.sourceRevision !== sourceRevision) {
    throw new Error("global corpus binding evidence used a different source revision");
  }
  if (digestFile(binding.engine.engineArtifactPath) !== binding.engine.binaryDigest) {
    throw new Error("global corpus loaded engine differs from binding evidence");
  }
  if (
    digestFile(binding.hermesProfileProvenance.path)
      !== binding.hermesProfileProvenance.rawContentDigest
  ) {
    throw new Error("global corpus Hermes provenance receipt changed");
  }

  const executions = [];
  const corpora = [];
  const runEnvironment = { ...process.env };
  delete runEnvironment.IBEX_RESTRICTED_REACHABLE_EVIDENCE_OUTPUT;
  delete runEnvironment.IBEX_RESTRICTED_CONTROL_EVIDENCE_OUTPUT;
  delete runEnvironment.IBEX_RESTRICTED_ABSENCE_EVIDENCE_OUTPUT;
  for (const corpus of restrictedGlobalCorpusPlan) {
    const executionIds = [];
    for (const testName of corpus.tests) {
      const executionId = `restricted-corpus.${corpus.id}.${testName}`;
      const command = [
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
      const run = spawnSync(command[0], command.slice(1), {
        cwd: repoRoot,
        env: runEnvironment,
        encoding: null,
        maxBuffer: 64 * 1024 * 1024,
        timeout: 180_000,
      });
      const stdout = run.stdout ?? Buffer.alloc(0);
      const stderr = run.stderr ?? Buffer.alloc(0);
      const combined = Buffer.concat([stdout, stderr]);
      const rendered = combined.toString("utf8");
      if (
        run.error
        || run.status !== 0
        || !rendered.includes("test result: ok")
        || !rendered.includes("1 passed")
      ) {
        process.stderr.write(combined);
        throw new Error(`restricted corpus ${corpus.id}/${testName} failed`);
      }
      executionIds.push(executionId);
      executions.push({
        executionId,
        fixtureId: corpus.id,
        outcome: "passed",
        command,
        exitCode: run.status,
        resultMarker: `ibex-restricted-global-corpus:passed:${corpus.id}:${testName}`,
        outputDigest: taggedDigest(combined),
      });
    }
    corpora.push({ id: corpus.id, status: "passed", executionIds });
  }

  const runId = `restricted-global-corpora-${crypto.randomBytes(16).toString("hex")}`;
  const artifact = {
    evidenceSchema: "ibex/restricted-profile-global-corpora-evidence/1",
    profile: binding.profile,
    runId,
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
    },
    exitCode: 0,
    resultMarker: "ibex-restricted-global-corpora:passed",
    corpora,
    executions,
  };
  const fd = fs.openSync(outputPath, "wx", 0o644);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(JSON.parse(canonicalJson(artifact)), null, 2)}\n`);
  } finally {
    fs.closeSync(fd);
  }
  console.log(JSON.stringify({
    outputPath,
    sourceRevision,
    target: binding.target,
    corpora: corpora.length,
    executions: executions.length,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
