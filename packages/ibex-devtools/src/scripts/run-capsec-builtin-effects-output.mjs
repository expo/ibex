#!/usr/bin/env node

// Focused, expectation-free plan builder for the exact builtin effects
// tranche.  It reads source inventory and effects coverage, but never the
// reviewed output-disposition dataset.
// @ref LLP 0023#6-path-bearing-observables

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./capsec-contract.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  authoredBuiltinEffectsOutputProbe,
  isBuiltinEffectsOutputTargetSurface,
} from "./capsec-builtin-effects-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const args = process.argv.slice(2).filter((argument) => argument !== "--");
if (args.length !== 2 || args[0] !== "--output") {
  throw new Error(
    "usage: run-capsec-builtin-effects-output.mjs --output <fresh-plan.json>",
  );
}
const outputPath = path.resolve(repoRoot, args[1]);
const readJson = (relative) =>
  JSON.parse(fs.readFileSync(path.join(repoRoot, relative), "utf8"));
const catalog = readJson("capsec/generated/output-shape-catalog.json");
if (catalog.outputShapeCatalogSchema !== "ibex/capsec-output-shape-catalog/2") {
  throw new Error(
    "builtin effects output requires the v2 output-shape catalog",
  );
}
const coverage = readJson("capsec/registry/coverage-edges.json");
const rules = readJson("capsec/registry/policy-rules.json");
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
  if (
    catalogRow.key.sourceKind !== "builtin" ||
    catalogRow.key.output !== "[[return]]" ||
    coverageEdge?.classification !== "effects" ||
    !isBuiltinEffectsOutputTargetSurface(surface)
  ) {
    return [];
  }
  const probe = authoredBuiltinEffectsOutputProbe({
    catalogKey: catalogRow.key,
    coverage,
    coverageEdge,
    surface,
    target,
  });
  if (!probe) {
    throw new Error(`missing builtin effects probe for ${surface.observedKey}`);
  }
  return [{ key: catalogRow.key, probe }];
});
const registrar = rows.filter(
  (row) => row.probe.sourceDescriptor.invocation.cohort === "registrar",
);
const descriptorResidual = rows.filter(
  (row) =>
    row.probe.sourceDescriptor.invocation.cohort === "descriptor-residual",
);
if (registrar.length !== 605 || descriptorResidual.length !== 0) {
  throw new Error(
    `expected exact v2 605+0 builtin effects tranche, got ${registrar.length}+${descriptorResidual.length}`,
  );
}

const payload = {
  planSchema: "ibex/capsec-builtin-effects-output-plan/2",
  catalogKeyDigest: catalog.catalogKeyDigest,
  target,
  counts: {
    registrar: registrar.length,
    descriptorResidual: descriptorResidual.length,
  },
  rows,
};
const planDigest = `sha256-${crypto
  .createHash("sha256")
  .update("ibex:capsec:builtin-effects-output-plan:2", "utf8")
  .update(Buffer.from([0]))
  .update(canonicalJson(payload), "utf8")
  .digest("base64url")}`;
const plan = { ...payload, planDigest };

fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
const descriptor = fs.openSync(
  outputPath,
  fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
  0o600,
);
try {
  fs.writeFileSync(descriptor, `${JSON.stringify(plan, null, 2)}\n`);
  fs.fsyncSync(descriptor);
} finally {
  fs.closeSync(descriptor);
}
console.log(
  JSON.stringify({
    outputPath,
    planDigest,
    registrar: registrar.length,
    descriptorResidual: descriptorResidual.length,
  }),
);
