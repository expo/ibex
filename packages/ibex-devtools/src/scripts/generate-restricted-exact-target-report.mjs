/** Build a deterministic incomplete/conformant target report from raw evidence. */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, repoRoot } from "./capsec-contract.mjs";
import { readRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";
import {
  buildRestrictedTargetReport,
  loadRestrictedReportAuthorities,
} from "./restricted-exact-target-report.mjs";

export function buildRestrictedTargetReportFromReachableEvidence(evidencePath) {
  const authorities = loadRestrictedReportAuthorities();
  const reachable = readRestrictedReachableEvidence(evidencePath, authorities);
  return buildRestrictedTargetReport({
    ...authorities,
    bindings: reachable.bindings,
    executions: reachable.executions,
    globalCorpora: authorities.fixturePlan.globalCorpora.map((row) => ({
      id: row.id,
      status: "missing",
      executionIds: [],
    })),
    independentReview: {
      status: "pending",
      artifactDigest: null,
      unresolvedCritical: 0,
      unresolvedHigh: 0,
    },
  });
}

function render(value) {
  return `${JSON.stringify(JSON.parse(canonicalJson(value)), null, 2)}\n`;
}

function main() {
  const args = process.argv.slice(2);
  const write = args.includes("--write");
  const check = args.includes("--check") || !write;
  if (write && args.includes("--check")) throw new Error("choose --write or --check");
  const positional = args.filter((arg) => !arg.startsWith("--"));
  if (positional.length !== 2) {
    throw new Error("usage: generate-restricted-exact-target-report <evidence> <report> [--write|--check]");
  }
  const evidencePath = path.resolve(repoRoot, positional[0]);
  const outputPath = path.resolve(repoRoot, positional[1]);
  const conformanceRoot = `${path.resolve(repoRoot, "capsec/conformance")}${path.sep}`;
  if (!evidencePath.startsWith(conformanceRoot) || !outputPath.startsWith(conformanceRoot)) {
    throw new Error("restricted evidence and report must remain under capsec/conformance");
  }
  const reportText = render(buildRestrictedTargetReportFromReachableEvidence(evidencePath));
  if (write) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, reportText, { flag: "w", mode: 0o644 });
  } else if (check && fs.readFileSync(outputPath, "utf8") !== reportText) {
    throw new Error(`${path.relative(repoRoot, outputPath)} is stale`);
  }
  const report = JSON.parse(reportText);
  console.log(JSON.stringify({
    mode: write ? "write" : "check",
    target: report.bindings.target,
    status: report.status,
    summary: report.summary,
    reportDigest: report.reportDigest,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
