#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
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
const knownOptions = new Set(["--output", "--require-complete", "--target"]);
let outputPath = path.join(repoRoot, "target/capsec-executable-recipes.json");
let requireComplete = false;
let requestedTargetTriple;
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
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(recipes, null, 2)}\n`, {
  flag: "wx",
});
console.log(
  JSON.stringify({
    output: path.relative(repoRoot, outputPath),
    recipeCatalogDigest: recipes.recipeCatalogDigest,
    ...recipes.summary,
  }),
);
if (requireComplete) assertRecipeCatalogComplete(recipes);
