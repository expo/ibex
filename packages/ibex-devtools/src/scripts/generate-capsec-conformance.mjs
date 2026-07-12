#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import { fileURLToPath } from "node:url";
import {
  buildConformanceReport,
  validateConformanceReportSemantics,
} from "./capsec-conformance.mjs";
import { readJsonStrict } from "./capsec-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
};
const outputPath = path.resolve(
  repoRoot,
  option("--output") ?? "target/capsec-conformance-report.json",
);
const enginePath = path.resolve(
  repoRoot,
  option("--engine") ?? "tools/hermes/hermes",
);
const executionsPath = option("--executions");

const taggedDigest = (bytes) =>
  `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
const git = (...gitArgs) => execFileSync("git", gitArgs, { cwd: repoRoot });
if (!fs.existsSync(enginePath))
  throw new Error(`patched Hermes binary not found: ${enginePath}`);

const manifest = readJsonStrict(path.join(capsecRoot, "contract-files.json"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const relativePath of manifest.schemas) {
  ajv.addSchema(readJsonStrict(path.join(capsecRoot, relativePath)));
}

const coverage = readJsonStrict(
  path.join(capsecRoot, "registry/coverage-edges.json"),
);
const implementation = readJsonStrict(
  path.join(capsecRoot, "generated/implementation-manifest.json"),
);
const rules = readJsonStrict(
  path.join(capsecRoot, "registry/policy-rules.json"),
);
const registryBundle = readJsonStrict(
  path.join(capsecRoot, "examples/registry-digest-bundle.canonical.json"),
);
const digestVectors = readJsonStrict(
  path.join(capsecRoot, "examples/digest-vectors.canonical.json"),
);
const target = rules.initialProfile.candidateTargets[0];
if (!target) throw new Error("no candidate target is declared");
const vocabularyDigest = registryBundle.members.find(
  (member) => member.logicalName === "vocab-digest",
)?.document?.digest;
const registryDigest = digestVectors.vectors.find(
  (vector) => vector.id === "registry",
)?.expectedDigest;
if (!vocabularyDigest || !registryDigest)
  throw new Error("semantic digest identities are unavailable");

const executions = executionsPath
  ? readJsonStrict(path.resolve(repoRoot, executionsPath)).executions
  : [];
if (!Array.isArray(executions))
  throw new Error("execution artifact must contain an executions array");

const report = buildConformanceReport({
  coverage,
  implementation,
  target,
  executions,
  bindings: {
    sourceRevision: git("rev-parse", "HEAD").toString("utf8").trim(),
    sourceTreeDigest: taggedDigest(git("rev-parse", "HEAD^{tree}")),
    engine: {
      kind: "patched-hermes",
      binaryDigest: taggedDigest(fs.readFileSync(enginePath)),
    },
    vocabularyDigest,
    registryDigest,
  },
  digestContract: rules.digestContract,
});
const validate = ajv.getSchema(
  "https://ibex.dev/capsec/schema/conformance-report.schema.json",
);
if (!validate?.(report))
  throw new Error(
    `invalid conformance report: ${ajv.errorsText(validate?.errors)}`,
  );
validateConformanceReportSemantics(report, {
  coverage,
  implementation,
  target,
  digestContract: rules.digestContract,
});
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(
  JSON.stringify({
    output: path.relative(repoRoot, outputPath),
    status: report.status,
    ...report.summary,
  }),
);
if (args.includes("--require-conformant") && report.status !== "conformant")
  process.exitCode = 1;
