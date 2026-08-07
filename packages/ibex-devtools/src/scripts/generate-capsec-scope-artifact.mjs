#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  fixtureCatalogForTarget,
  selectCandidateTarget,
} from "./capsec-conformance.mjs";
import { readJsonStrict } from "./capsec-contract.mjs";
import {
  generateScopeArtifacts,
  validateIntensionalDefinition,
} from "./capsec-scope-artifact.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { canonicalJson } from "../../../../scripts/portable-engine-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

export const SCOPE_OUTPUT_FILES = {
  scope: "capsec-scope.json",
  expansionDiff: "capsec-scope-expansion-diff.json",
  cellMapping: "capsec-scope-cell-mapping.json",
};

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function parseSet(raw, label) {
  const values = [...new Set(raw.split(",").map((value) => value.trim()))]
    .filter(Boolean)
    .sort();
  invariant(values.length > 0, `${label} must name at least one value`);
  return values;
}

function parseArgs(argv) {
  const options = {
    families: ["env", "fs", "process"],
    outputDir: path.join(repoRoot, "target/capsec-scope"),
  };
  const valued = new Set([
    "--families",
    "--surface-kinds",
    "--target",
    "--output-dir",
    "--predecessor",
    "--inventory-history",
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--write") options.mode = "write";
    else if (argument === "--check") options.mode = "check";
    else if (valued.has(argument)) {
      const value = argv[index + 1];
      invariant(value && !value.startsWith("--"), `${argument} requires a value`);
      index += 1;
      if (argument === "--families") options.families = parseSet(value, argument);
      else if (argument === "--surface-kinds") {
        options.surfaceKinds = parseSet(value, argument);
      } else if (argument === "--target") options.targetTriple = value;
      else if (argument === "--output-dir") {
        options.outputDir = path.resolve(repoRoot, value);
      } else if (argument === "--predecessor") {
        options.predecessorPath = path.resolve(repoRoot, value);
      } else {
        options.inventoryHistoryPath = path.resolve(repoRoot, value);
      }
    } else {
      throw new Error(`unknown scope generator option ${JSON.stringify(argument)}`);
    }
  }
  invariant(options.mode, "scope generator requires exactly one of --write or --check");
  invariant(
    argv.filter((argument) => argument === "--write" || argument === "--check").length === 1,
    "scope generator requires exactly one of --write or --check",
  );
  return options;
}

export function writeOrCheckScopeArtifacts({ artifacts, outputDir, mode }) {
  invariant(mode === "write" || mode === "check", "scope output mode is invalid");
  const results = [];
  for (const [key, filename] of Object.entries(SCOPE_OUTPUT_FILES)) {
    const outputPath = path.join(outputDir, filename);
    const expected = Buffer.from(canonicalJson(artifacts[key]), "utf8");
    if (mode === "write") {
      fs.mkdirSync(outputDir, { recursive: true });
      fs.writeFileSync(outputPath, expected);
    } else {
      invariant(fs.existsSync(outputPath), `${filename}: generated scope artifact is missing`);
      invariant(
        fs.readFileSync(outputPath).equals(expected),
        `${filename}: generated scope artifact drift`,
      );
    }
    results.push({ path: outputPath, bytes: expected.length });
  }
  return results;
}

export async function generateFromRepository(options) {
  const capsecRoot = path.join(repoRoot, "capsec");
  const coverage = readJsonStrict(path.join(capsecRoot, "registry/coverage-edges.json"));
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const rules = readJsonStrict(path.join(capsecRoot, "registry/policy-rules.json"));
  const target = selectCandidateTarget(rules, options.targetTriple);
  const catalog = fixtureCatalogForTarget({ coverage, implementation, target });
  const surfaceInventory = await discoverRepositorySurfaces(repoRoot);
  const surfaceKinds =
    options.surfaceKinds ??
    [...new Set(coverage.edges.map((edge) => edge.surface.kind))].sort();
  const intensionalDefinition = {
    capabilityFamilies: options.families,
    surfaceKinds,
  };
  validateIntensionalDefinition(intensionalDefinition);
  const predecessorScope = options.predecessorPath
    ? readJsonStrict(options.predecessorPath)
    : null;
  const inventoryHistory = options.inventoryHistoryPath
    ? readJsonStrict(options.inventoryHistoryPath)
    : null;
  return generateScopeArtifacts({
    target,
    intensionalDefinition,
    catalog,
    coverage,
    implementation,
    surfaceInventory,
    predecessorScope,
    inventoryHistory,
  });
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const artifacts = await generateFromRepository(options);
  const outputs = writeOrCheckScopeArtifacts({
    artifacts,
    outputDir: options.outputDir,
    mode: options.mode,
  });
  process.stdout.write(
    `${JSON.stringify({
      mode: options.mode,
      scopeDigest: artifacts.scope.scopeDigest,
      cells: artifacts.scope.expandedCellIds.length,
      closureEdges: artifacts.scope.closureEdges.length,
      outputs: outputs.map((output) => ({
        path: path.relative(repoRoot, output.path),
        bytes: output.bytes,
      })),
    })}\n`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
