/** Build a deterministic incomplete/conformant target report from raw evidence. */

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { canonicalJson, parseJsonStrict, repoRoot } from "./capsec-contract.mjs";
import { readRestrictedAbsenceEvidence } from "./restricted-exact-absence-evidence.mjs";
import { readRestrictedControlEvidence } from "./restricted-exact-control-evidence.mjs";
import { readRestrictedGlobalCorporaEvidence } from "./restricted-exact-global-corpora-evidence.mjs";
import { readRestrictedReachableEvidence } from "./restricted-exact-reachable-evidence.mjs";
import {
  buildRestrictedTargetReport,
  loadRestrictedReportAuthorities,
  restrictedReportPathForTarget,
  taggedDigest,
} from "./restricted-exact-target-report.mjs";

function readSettledReview(reviewPath, evidencePaths, target, expectedVerdict) {
  const rawReview = fs.readFileSync(reviewPath);
  const review = parseJsonStrict(rawReview, reviewPath);
  if (
    review.kind !== "ibex-llp-0033-independent-security-review"
    || review.independent !== true
    || review.verdict !== expectedVerdict
    || (expectedVerdict === "clear"
      ? review.unresolvedCritical !== 0 || review.unresolvedHigh !== 0
      : review.unresolvedCritical < 1 && review.unresolvedHigh < 1)
  ) {
    throw new Error(`restricted ${expectedVerdict}-review artifact has an invalid disposition`);
  }
  const reviewedReportPath = restrictedReportPathForTarget(target);
  const reviewedReportRaw = execFileSync(
    "git",
    ["show", `${review.reviewedCommit}:${reviewedReportPath}`],
    { cwd: repoRoot, maxBuffer: 64 * 1024 * 1024 },
  );
  const reviewedReport = parseJsonStrict(reviewedReportRaw, reviewedReportPath);
  if (
    taggedDigest(reviewedReportRaw) !== review.reviewedReportRawContentDigest
    || reviewedReport.reportDigest !== review.reviewedReportDigest
  ) {
    throw new Error(`restricted ${expectedVerdict} review does not bind its reviewed report`);
  }
  for (const evidencePath of evidencePaths) {
    const expected = review.reviewedEvidenceRawContentDigests[path.basename(evidencePath)];
    if (!expected || taggedDigest(fs.readFileSync(evidencePath)) !== expected) {
      throw new Error(
        `restricted ${expectedVerdict} review does not bind ${path.basename(evidencePath)}`,
      );
    }
  }
  return {
    review,
    artifactDigest: taggedDigest(rawReview),
  };
}

export function buildRestrictedTargetReportFromEvidence(
  reachablePath,
  controlPath,
  absencePath,
  corpusPath,
) {
  const authorities = loadRestrictedReportAuthorities();
  const reachable = readRestrictedReachableEvidence(reachablePath, authorities);
  const control = readRestrictedControlEvidence(controlPath, authorities);
  const absence = readRestrictedAbsenceEvidence(absencePath, authorities);
  const corpora = readRestrictedGlobalCorporaEvidence(
    corpusPath,
    reachablePath,
    authorities,
  );
  if (
    canonicalJson(reachable.bindings) !== canonicalJson(control.bindings)
    || canonicalJson(reachable.bindings) !== canonicalJson(absence.bindings)
    || canonicalJson(reachable.bindings) !== canonicalJson(corpora.bindings)
  ) {
    throw new Error("restricted target evidence bindings differ");
  }
  return buildRestrictedTargetReport({
    ...authorities,
    bindings: reachable.bindings,
    executions: [
      ...reachable.executions,
      ...control.executions,
      ...absence.executions,
      ...corpora.executions,
    ].sort(
      (left, right) => left.executionId.localeCompare(right.executionId),
    ),
    globalCorpora: corpora.globalCorpora,
    independentReview: {
      status: "pending",
      artifactDigest: null,
      unresolvedCritical: 0,
      unresolvedHigh: 0,
    },
  });
}

export function buildRestrictedTargetReportAfterFailedReview(
  reachablePath,
  controlPath,
  absencePath,
  corpusPath,
  reviewPath,
) {
  const authorities = loadRestrictedReportAuthorities();
  const reachable = readRestrictedReachableEvidence(reachablePath, authorities);
  const control = readRestrictedControlEvidence(controlPath, authorities);
  if (canonicalJson(reachable.bindings) !== canonicalJson(control.bindings)) {
    throw new Error("restricted retained evidence bindings differ");
  }
  const failed = readSettledReview(
    reviewPath,
    [reachablePath, controlPath, absencePath, corpusPath],
    reachable.bindings.target,
    "fail",
  );
  return buildRestrictedTargetReport({
    ...authorities,
    bindings: reachable.bindings,
    executions: [
      ...reachable.executions,
      ...control.executions,
    ].sort((left, right) => left.executionId.localeCompare(right.executionId)),
    globalCorpora: authorities.fixturePlan.globalCorpora.map((corpus) => ({
      id: corpus.id,
      status: "missing",
      executionIds: [],
    })),
    independentReview: {
      status: "failed",
      artifactDigest: failed.artifactDigest,
      unresolvedCritical: failed.review.unresolvedCritical,
      unresolvedHigh: failed.review.unresolvedHigh,
    },
  });
}

export function buildRestrictedTargetReportAfterClearReview(
  reachablePath,
  controlPath,
  absencePath,
  corpusPath,
  reviewPath,
) {
  const pending = buildRestrictedTargetReportFromEvidence(
    reachablePath,
    controlPath,
    absencePath,
    corpusPath,
  );
  const authorities = loadRestrictedReportAuthorities();
  const clear = readSettledReview(
    reviewPath,
    [reachablePath, controlPath, absencePath, corpusPath],
    pending.bindings.target,
    "clear",
  );
  return buildRestrictedTargetReport({
    ...authorities,
    bindings: pending.bindings,
    executions: pending.executions,
    globalCorpora: pending.globalCorpora,
    independentReview: {
      status: "clear",
      artifactDigest: clear.artifactDigest,
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
  const failedReviewArgument = args.find((arg) => arg.startsWith("--failed-review="));
  const clearReviewArgument = args.find((arg) => arg.startsWith("--clear-review="));
  if (failedReviewArgument && clearReviewArgument) {
    throw new Error("choose one settled restricted review disposition");
  }
  if (write && args.includes("--check")) throw new Error("choose --write or --check");
  const positional = args.filter((arg) => !arg.startsWith("--"));
  if (positional.length !== 5) {
    throw new Error(
      "usage: generate-restricted-exact-target-report <reachable-evidence> <control-evidence> <absence-evidence> <global-corpora-evidence> <report> [--write|--check] [--clear-review=<path>|--failed-review=<path>]",
    );
  }
  const reachablePath = path.resolve(repoRoot, positional[0]);
  const controlPath = path.resolve(repoRoot, positional[1]);
  const absencePath = path.resolve(repoRoot, positional[2]);
  const corpusPath = path.resolve(repoRoot, positional[3]);
  const outputPath = path.resolve(repoRoot, positional[4]);
  const failedReviewPath = failedReviewArgument
    ? path.resolve(repoRoot, failedReviewArgument.slice("--failed-review=".length))
    : null;
  const clearReviewPath = clearReviewArgument
    ? path.resolve(repoRoot, clearReviewArgument.slice("--clear-review=".length))
    : null;
  const conformanceRoot = `${path.resolve(repoRoot, "capsec/conformance")}${path.sep}`;
  if (
    !reachablePath.startsWith(conformanceRoot)
    || !controlPath.startsWith(conformanceRoot)
    || !absencePath.startsWith(conformanceRoot)
    || !corpusPath.startsWith(conformanceRoot)
    || !outputPath.startsWith(conformanceRoot)
  ) {
    throw new Error("restricted evidence and report must remain under capsec/conformance");
  }
  const reportText = render(clearReviewPath
    ? buildRestrictedTargetReportAfterClearReview(
      reachablePath,
      controlPath,
      absencePath,
      corpusPath,
      clearReviewPath,
    )
    : failedReviewPath
      ? buildRestrictedTargetReportAfterFailedReview(
        reachablePath,
        controlPath,
        absencePath,
        corpusPath,
        failedReviewPath,
      )
      : buildRestrictedTargetReportFromEvidence(
        reachablePath,
        controlPath,
        absencePath,
        corpusPath,
      ));
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
