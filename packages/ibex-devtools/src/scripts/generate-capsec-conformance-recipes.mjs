#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertRecipeCatalogComplete,
  bindRecipeCatalogScopeArtifact,
  buildConformanceRecipeCatalog,
  computeRecipeCatalogDigest,
} from "./capsec-conformance-recipes.mjs";
import {
  fixtureCatalogForTarget,
  selectCandidateTarget,
} from "./capsec-conformance.mjs";
import { readJsonStrict } from "./capsec-contract.mjs";
import {
  buildScopeArtifact,
  buildScopeCellMapping,
  deriveScopeExpansion,
} from "./capsec-scope-artifact.mjs";
import {
  generateFromRepository as generateScopeFromRepository,
  SCOPE_OUTPUT_FILES,
  writeOrCheckScopeArtifacts,
} from "./generate-capsec-scope-artifact.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { canonicalJson } from "../../../../scripts/portable-engine-contract.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const capsecRoot = path.join(repoRoot, "capsec");
const knownOptions = new Set([
  "--declared-allow-list",
  "--output",
  "--require-complete",
  "--scope-families",
  "--scope-input-dir",
  "--scope-output-dir",
  "--target",
]);

export function parseRecipeGeneratorArgs(args) {
  const options = {
    outputPath: path.join(repoRoot, "target/capsec-executable-recipes.json"),
    requireComplete: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!knownOptions.has(argument)) {
      throw new Error(
        `unknown recipe generator option ${JSON.stringify(argument)}`,
      );
    }
    if (argument === "--require-complete") {
      options.requireComplete = true;
      continue;
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`${argument} requires a value`);
    }
    if (argument === "--output") {
      options.outputPath = path.resolve(repoRoot, value);
    } else if (argument === "--declared-allow-list") {
      options.declaredAllowListPath = path.resolve(repoRoot, value);
    } else if (argument === "--scope-input-dir") {
      options.scopeInputDirectory = path.resolve(repoRoot, value);
    } else if (argument === "--scope-families") {
      options.scopeFamilies = [
        ...new Set(value.split(",").map((part) => part.trim())),
      ]
        .filter(Boolean)
        .sort();
      if (options.scopeFamilies.length === 0) {
        throw new Error("--scope-families must name at least one family");
      }
    } else if (argument === "--scope-output-dir") {
      options.scopeOutputDirectory = path.resolve(repoRoot, value);
    } else {
      options.requestedTargetTriple = value;
    }
    index += 1;
  }
  if (options.scopeInputDirectory && !options.scopeOutputDirectory) {
    throw new Error("--scope-input-dir requires --scope-output-dir");
  }
  if (options.scopeInputDirectory && options.scopeFamilies) {
    throw new Error(
      "--scope-input-dir cannot be combined with --scope-families",
    );
  }
  return options;
}

function readScopeArtifacts(inputDirectory) {
  return Object.fromEntries(
    Object.entries(SCOPE_OUTPUT_FILES).map(([name, filename]) => [
      name,
      readJsonStrict(path.join(inputDirectory, filename)),
    ]),
  );
}

function validateAcceptedScopeArtifacts({ artifacts, expansion, target }) {
  const rebuiltMapping = buildScopeCellMapping({
    target,
    expansionDiff: artifacts.expansionDiff,
    inventoryHistory: {
      additions: artifacts.cellMapping.additions,
      retirements: artifacts.cellMapping.retirements,
      mappings: artifacts.cellMapping.mappings,
    },
  });
  const rebuiltScope = buildScopeArtifact({
    target,
    intensionalDefinition: artifacts.scope.intensionalDefinition,
    expandedCellIds: expansion.expandedCellIds,
    closureEdges: expansion.closureEdges,
    predecessor: artifacts.scope.predecessor,
    expansionDiff: artifacts.expansionDiff,
    cellMapping: artifacts.cellMapping,
  });
  if (
    canonicalJson(rebuiltMapping) !== canonicalJson(artifacts.cellMapping) ||
    canonicalJson(rebuiltScope) !== canonicalJson(artifacts.scope)
  ) {
    throw new Error(
      "accepted CapSec scope artifact or companions differ from current source-derived scope",
    );
  }
}

/**
 * Generate a scope bundle or accept an existing exact bundle, re-derive its
 * expansion from the current full inventory, and emit all three members in
 * the same supervised command that emits the bound recipe catalog.
 *
 * @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — M1/M2 require
 * scope identity to be created by the S1 generator and bound into the full,
 * honest recipe catalog before any evidence subprocess consumes it.
 */
async function resolveScope({
  options,
  target,
  catalog,
  coverage,
  implementation,
  surfaceInventory,
}) {
  if (!options.scopeOutputDirectory) return null;
  const artifacts = options.scopeInputDirectory
    ? readScopeArtifacts(options.scopeInputDirectory)
    : await generateScopeFromRepository({
        families: options.scopeFamilies ?? ["env", "fs", "process"],
        targetTriple: target.triple,
      });
  const expansion = deriveScopeExpansion({
    intensionalDefinition: artifacts.scope.intensionalDefinition,
    catalog,
    coverage,
    implementation,
    surfaceInventory,
  });
  validateAcceptedScopeArtifacts({ artifacts, expansion, target });
  writeOrCheckScopeArtifacts({
    artifacts,
    outputDir: options.scopeOutputDirectory,
    mode: "write",
  });
  return { artifacts, expansion };
}

export async function main(args = process.argv.slice(2)) {
  const options = parseRecipeGeneratorArgs(args);
  const coverage = readJsonStrict(
    path.join(capsecRoot, "registry/coverage-edges.json"),
  );
  const implementation = readJsonStrict(
    path.join(capsecRoot, "generated/implementation-manifest.json"),
  );
  const rules = readJsonStrict(
    path.join(capsecRoot, "registry/policy-rules.json"),
  );
  const capabilityDefinitions = readJsonStrict(
    path.join(capsecRoot, "registry/capability-definitions.json"),
  );
  const occurrenceExamples = readJsonStrict(
    path.join(capsecRoot, "examples/effect-occurrences.canonical.json"),
  );
  const selectorExamples = readJsonStrict(
    path.join(capsecRoot, "examples/authority-selectors.canonical.json"),
  );
  const target = selectCandidateTarget(
    rules,
    options.requestedTargetTriple,
  );
  const catalog = fixtureCatalogForTarget({ coverage, implementation, target });
  const inventory = await discoverRepositorySurfaces(repoRoot);
  let recipes = buildConformanceRecipeCatalog({
    catalog,
    coverage,
    implementation,
    inventory,
    occurrenceExamples,
    selectorExamples,
    capabilityDefinitions,
    target,
  });
  const scope = await resolveScope({
    options,
    target,
    catalog,
    coverage,
    implementation,
    surfaceInventory: inventory,
  });
  if (scope) {
    recipes = await bindRecipeCatalogScopeArtifact(recipes, {
      scopeArtifact: scope.artifacts.scope,
      scopeInventory: scope.expansion.inventory,
    });
  }
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
  if (options.declaredAllowListPath) {
    recipes.declaredAllowListDigest = `sha256-${crypto
      .createHash("sha256")
      .update(fs.readFileSync(options.declaredAllowListPath))
      .digest("base64url")}`;
    recipes.recipeCatalogDigest = computeRecipeCatalogDigest(recipes);
  }
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  fs.writeFileSync(
    options.outputPath,
    `${JSON.stringify(recipes, null, 2)}\n`,
    { flag: "wx" },
  );
  console.log(
    JSON.stringify({
      output: path.relative(repoRoot, options.outputPath),
      recipeCatalogDigest: recipes.recipeCatalogDigest,
      ...(recipes.declaredAllowListDigest
        ? { declaredAllowListDigest: recipes.declaredAllowListDigest }
        : {}),
      ...recipes.summary,
    }),
  );
  if (options.requireComplete) {
    assertRecipeCatalogComplete(
      recipes,
      scope
        ? {
            scopeDigest: scope.artifacts.scope.scopeDigest,
            expandedEdgeIds: scope.artifacts.scope.expandedCellIds,
          }
        : {},
    );
  }
  return { recipes, scope };
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  await main();
}
