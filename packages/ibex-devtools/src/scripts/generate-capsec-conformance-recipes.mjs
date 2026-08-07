#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
  computeRecipeCatalogDigest,
} from "./capsec-conformance-recipes.mjs";
import {
  fixtureCatalogForTarget,
  selectCandidateTarget,
} from "./capsec-conformance.mjs";
import { readJsonStrict } from "./capsec-contract.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const args = process.argv.slice(2);
const knownOptions = new Set([
  "--declared-allow-list",
  "--output",
  "--require-complete",
  "--target",
]);
let outputPath = path.join(repoRoot, "target/capsec-executable-recipes.json");
let requireComplete = false;
let requestedTargetTriple;
let declaredAllowListPath;
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (!knownOptions.has(argument)) {
    throw new Error(`unknown recipe generator option ${JSON.stringify(argument)}`);
  }
  if (argument === "--require-complete") {
    requireComplete = true;
    continue;
  }
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${argument} requires a value`);
  }
  if (argument === "--output") {
    outputPath = path.resolve(repoRoot, value);
  } else if (argument === "--declared-allow-list") {
    declaredAllowListPath = path.resolve(repoRoot, value);
  } else {
    requestedTargetTriple = value;
  }
  index += 1;
}

const coverage = readJsonStrict(
  path.join(capsecRoot, "registry/coverage-edges.json"),
);
const implementation = readJsonStrict(
  path.join(capsecRoot, "generated/implementation-manifest.json"),
);
const rules = readJsonStrict(path.join(capsecRoot, "registry/policy-rules.json"));
const capabilityDefinitions = readJsonStrict(
  path.join(capsecRoot, "registry/capability-definitions.json"),
);
const occurrenceExamples = readJsonStrict(
  path.join(capsecRoot, "examples/effect-occurrences.canonical.json"),
);
const selectorExamples = readJsonStrict(
  path.join(capsecRoot, "examples/authority-selectors.canonical.json"),
);
const target = selectCandidateTarget(rules, requestedTargetTriple);
const catalog = fixtureCatalogForTarget({ coverage, implementation, target });
const inventory = await discoverRepositorySurfaces(repoRoot);
const recipes = buildConformanceRecipeCatalog({
  catalog,
  coverage,
  implementation,
  inventory,
  occurrenceExamples,
  selectorExamples,
  capabilityDefinitions,
  target,
});
// @ref LLP 0049#3-construction-rules — rule 3's advance-declaration mechanics:
// when the allow-list is declared BEFORE candidate generation, its content
// digest (sha256 over the file's raw bytes, base64url, matching the catalog
// digest spelling) is embedded in the candidate catalog itself, and the
// recipeCatalogDigest is recomputed over the embedded field so the declaration
// cannot be stripped without changing the catalog identity. The diff gate
// (scripts/llp0045-route-evidence-diff.mjs) recomputes and compares it, which
// makes an allow-list authored AFTER the diff mechanically unable to pass.
// Without the flag nothing changes: no field is embedded and the catalog is
// byte-identical to what this generator produced before the flag existed.
if (declaredAllowListPath) {
  recipes.declaredAllowListDigest = `sha256-${crypto
    .createHash("sha256")
    .update(fs.readFileSync(declaredAllowListPath))
    .digest("base64url")}`;
  recipes.recipeCatalogDigest = computeRecipeCatalogDigest(recipes);
}
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(recipes, null, 2)}\n`, {
  flag: "wx",
});
console.log(
  JSON.stringify({
    output: path.relative(repoRoot, outputPath),
    recipeCatalogDigest: recipes.recipeCatalogDigest,
    ...(recipes.declaredAllowListDigest
      ? { declaredAllowListDigest: recipes.declaredAllowListDigest }
      : {}),
    ...recipes.summary,
  }),
);
if (requireComplete) assertRecipeCatalogComplete(recipes);
