#!/usr/bin/env node

// Focused, expectation-free plan builder for the builtin callable/accessor
// output tranche. The loaded Rust batch consumes this exact plan.
// @ref LLP 0023#6-path-bearing-observables

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { outputShapeProbeKindForCatalogRow } from "./capsec-output-shape-sweep.mjs";
import {
  authoredBuiltinNoncapClosedOutputProbe,
  hasBuiltinNoncapClosedDescriptorResidualRoute,
} from "./capsec-builtin-noncap-closed-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const args = process.argv.slice(2).filter((argument) => argument !== "--");
if (args.length !== 2 || args[0] !== "--output") {
  throw new Error(
    "usage: run-capsec-builtin-noncap-closed-output.mjs --output <fresh-plan.json>",
  );
}
const outputPath = path.resolve(repoRoot, args[1]);
const catalog = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
    "utf8",
  ),
);
const coverage = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "capsec/registry/coverage-edges.json"),
    "utf8",
  ),
);
const rules = JSON.parse(
  fs.readFileSync(
    path.join(repoRoot, "capsec/registry/policy-rules.json"),
    "utf8",
  ),
);
const target = rules.initialProfile.candidateTargets[0];
const inventory = await discoverRepositorySurfaces(repoRoot);
const surfaces = new Map(
  inventory.surfaces.map((surface) => [
    `${surface.kind}:${surface.name}`,
    surface,
  ]),
);
const edges = new Map(coverage.edges.map((edge) => [edge.id, edge]));

const rows = catalog.rows.flatMap((catalogRow) => {
  const coverageEdge = edges.get(catalogRow.key.surfaceId);
  const surface = coverageEdge
    ? surfaces.get(`${coverageEdge.surface.kind}:${coverageEdge.surface.name}`)
    : null;
  const genericKind = outputShapeProbeKindForCatalogRow(catalogRow, surface, {
    coverageEdge,
    target,
  });
  if (
    catalogRow.key.sourceKind !== "builtin" ||
    !new Set(["non-capability", "closed"]).has(coverageEdge?.classification) ||
    !new Set(["compiled-registrar", "loaded-engine-descriptor"]).has(
      genericKind,
    )
  ) {
    return [];
  }
  if (
    genericKind === "loaded-engine-descriptor" &&
    !hasBuiltinNoncapClosedDescriptorResidualRoute({
      catalogKey: catalogRow.key,
      surface,
      target,
    })
  ) {
    return [];
  }
  const probe = authoredBuiltinNoncapClosedOutputProbe({
    catalogKey: catalogRow.key,
    coverageEdge,
    surface,
    target,
  });
  if (!probe) {
    if (genericKind === "loaded-engine-descriptor") return [];
    throw new Error(`missing builtin output probe for ${surface.observedKey}`);
  }
  return [{ key: catalogRow.key, probe }];
});
if (rows.length !== 716) {
  throw new Error(
    `expected exact 716-row builtin output tranche, got ${rows.length}`,
  );
}
if (
  rows.filter(
    (row) =>
      row.probe.sourceDescriptor.invocation.route.operation !== "unexercisable",
  ).length !== 533
) {
  throw new Error("builtin output executable route count drifted from 533");
}

fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
const descriptor = fs.openSync(
  outputPath,
  fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
  0o600,
);
try {
  fs.writeFileSync(
    descriptor,
    `${JSON.stringify(
      {
        planSchema: "ibex/capsec-builtin-noncap-closed-output-plan/1",
        target,
        rows,
      },
      null,
      2,
    )}\n`,
  );
  fs.fsyncSync(descriptor);
} finally {
  fs.closeSync(descriptor);
}
console.log(JSON.stringify({ outputPath, rows: rows.length, executable: 533 }));
