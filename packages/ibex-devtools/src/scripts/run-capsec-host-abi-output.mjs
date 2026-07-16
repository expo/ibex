#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readJsonStrict } from "./capsec-contract.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { authoredTargetAbsenceOutputBindings } from "./capsec-target-absence-output-templates.mjs";
import { buildHostAbiOutputProbePartition } from "./capsec-host-abi-output-templates.mjs";
import { validateCurrentSourceRecipeCatalog } from "./capsec-conformance-recipes.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const args = process.argv.slice(2);
let output = path.join(repoRoot, "target/capsec-host-abi-output-plan.json");
let recipeCatalogPath = null;
for (let index = 0; index < args.length; index += 1) {
  if (
    !new Set(["--output", "--recipe-catalog"]).has(args[index]) ||
    !args[index + 1]
  ) {
    throw new Error(
      `unknown or incomplete option ${JSON.stringify(args[index])}`,
    );
  }
  if (args[index] === "--output") {
    output = path.resolve(repoRoot, args[index + 1]);
  } else {
    recipeCatalogPath = path.resolve(repoRoot, args[index + 1]);
  }
  index += 1;
}

const catalog = readJsonStrict(
  path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
);
const coverage = readJsonStrict(
  path.join(repoRoot, "capsec/registry/coverage-edges.json"),
);
const inventory = await discoverRepositorySurfaces(repoRoot);
const surfaces = inventory.surfaces;
const target = readJsonStrict(
  path.join(repoRoot, "capsec/registry/policy-rules.json"),
).initialProfile.candidateTargets[0];
let targetAbsenceBindings = [];
if (recipeCatalogPath) {
  const recipeCatalog = readJsonStrict(recipeCatalogPath);
  validateCurrentSourceRecipeCatalog(recipeCatalog, {
    coverage,
    implementation: readJsonStrict(
      path.join(repoRoot, "capsec/generated/implementation-manifest.json"),
    ),
    inventory,
    occurrenceExamples: readJsonStrict(
      path.join(
        repoRoot,
        "capsec/examples/effect-occurrences.canonical.json",
      ),
    ),
    selectorExamples: readJsonStrict(
      path.join(
        repoRoot,
        "capsec/examples/authority-selectors.canonical.json",
      ),
    ),
    capabilityDefinitions: readJsonStrict(
      path.join(repoRoot, "capsec/registry/capability-definitions.json"),
    ),
    target,
  });
  targetAbsenceBindings = authoredTargetAbsenceOutputBindings({
    catalog,
    recipeCatalog,
    coverage,
    target,
  }).filter((binding) => binding.key.sourceKind === "host-abi");
}
const plan = buildHostAbiOutputProbePartition({
  catalog,
  coverage,
  surfaces,
  targetAbsenceBindings,
});
const { rows, residuals } = plan;
const outputPlan = {
  hostAbiOutputPlanSchema: "ibex/capsec-host-abi-output-plan/1",
  hostAbiOutputPartitionSchema: plan.hostAbiOutputPartitionSchema,
  targetAbsenceBindings: plan.targetAbsenceBindings,
  rows,
  residuals,
};
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${JSON.stringify(outputPlan, null, 2)}\n`, {
  flag: "wx",
});
const residualReasons = Object.fromEntries(
  [...Map.groupBy(residuals, (row) => row.reason)]
    .map(([reason, grouped]) => [reason, grouped.length])
    .sort(([left], [right]) => left.localeCompare(right, "en-US")),
);
process.stdout.write(
  `${JSON.stringify({
    output: path.relative(repoRoot, output),
    catalogRows:
      rows.length + residuals.length + plan.targetAbsenceBindings.length,
    targetAbsenceRows: plan.targetAbsenceBindings.length,
    remainingRows: rows.length + residuals.length,
    executableRows: rows.length,
    residualRows: residuals.length,
    residualReasons,
  })}\n`,
);
