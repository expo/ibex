/**
 * Generate the LLP 0021 WP1 implementation inventory and language bindings.
 *
 * The semantic datasets under capsec/registry are the authority. Source
 * discovery proves that every live observed surface joins exactly one
 * semantic edge; generated bindings never become a second matcher.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — one
 * closed source inventory, exact target cells, reproducible bindings, and a
 * non-writing CI drift gate.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  capsecRoot,
  parseJsonStrict,
  readJsonStrict,
  repoRoot,
} from "./capsec-contract.mjs";
import {
  assertReviewedSurfaceInventory,
  buildCoverageModel,
} from "./capsec-coverage-model.mjs";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import { applicableImplementationBranchIds } from "./capsec-target-branches.mjs";
import {
  assertReportMayAdvertise,
  fixtureCatalogForTarget,
  fixtureExecutionPlans,
  validateConformanceReportSemantics,
} from "./capsec-conformance.mjs";
import {
  assertRecipeCatalogComplete,
  buildConformanceRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import {
  assertPublicSurfaceExecutionComplete,
  validatePublicFixtureRuntimeObservation,
} from "./capsec-public-surface-evidence.mjs";
import {
  buildOutputDispositionDataset,
  buildOutputShapeCatalog,
  renderOutputDispositionMarkdown,
  validateTrackedOutputDispositionEvidenceSentinel,
} from "./capsec-output-dispositions.mjs";
import { validatePromotableOutputDispositionEvidence } from "./capsec-output-shape-sweep.mjs";
import { validateIngressObligationDataset } from "./capsec-ingress-obligations.mjs";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";
import {
  buildWebGpuPrivateOperationRegistry,
} from "./capsec-webgpu-operation-registry.mjs";

const __filename = fileURLToPath(import.meta.url);

export const generatedRegistryPaths = Object.freeze({
  coverage: path.join(capsecRoot, "registry", "coverage-edges.json"),
  targetCells: path.join(capsecRoot, "registry", "target-cells.json"),
  targetAdvertisements: path.join(
    capsecRoot,
    "generated",
    "target-advertisements.json",
  ),
  implementationManifest: path.join(
    capsecRoot,
    "generated",
    "implementation-manifest.json",
  ),
  webgpuOperations: path.join(
    capsecRoot,
    "generated",
    "webgpu-private-operation-registry.json",
  ),
  idsSchema: path.join(
    capsecRoot,
    "generated",
    "capsec-registry-ids.schema.json",
  ),
  surfaceDocs: path.join(capsecRoot, "generated", "surface-inventory.md"),
  targetDocs: path.join(capsecRoot, "generated", "target-matrix.md"),
  outputShapeCatalog: path.join(
    capsecRoot,
    "generated",
    "output-shape-catalog.json",
  ),
  outputDispositions: path.join(
    capsecRoot,
    "generated",
    "output-dispositions.json",
  ),
  outputDispositionDocs: path.join(
    capsecRoot,
    "generated",
    "output-dispositions.md",
  ),
  rust: path.join(repoRoot, "src", "capsec_registry_generated.rs"),
  cxx: path.join(repoRoot, "src", "engine", "capsec_registry_generated.h"),
  javascript: path.join(
    repoRoot,
    "src",
    "builtins",
    "helpers",
    "capsec-registry.generated.cjs",
  ),
  typescript: path.join(
    repoRoot,
    "packages",
    "ibex-runtime-js",
    "src",
    "security",
    "capsec-registry.generated.ts",
  ),
});

// This catalog is deliberately closed and independent of the order in which
// renderCapsecRegistry constructs its Map. The implementation manifest cannot
// digest itself; the aggregate registry digest binds that excluded artifact.
export const generatedRegistryOutputCatalog = Object.freeze([
  Object.freeze({
    path: "capsec/generated/capsec-registry-ids.schema.json",
    kind: "json-schema",
    digestBound: true,
  }),
  Object.freeze({
    path: "capsec/generated/implementation-manifest.json",
    kind: "implementation-manifest",
    digestBound: false,
  }),
  Object.freeze({
    path: "capsec/generated/webgpu-private-operation-registry.json",
    kind: "webgpu-private-operation-registry",
    digestBound: false,
  }),
  Object.freeze({
    path: "capsec/generated/output-dispositions.json",
    kind: "output-disposition-dataset",
    digestBound: true,
  }),
  Object.freeze({
    path: "capsec/generated/output-dispositions.md",
    kind: "markdown",
    digestBound: true,
  }),
  Object.freeze({
    path: "capsec/generated/output-shape-catalog.json",
    kind: "output-shape-catalog",
    digestBound: true,
  }),
  Object.freeze({
    path: "capsec/generated/surface-inventory.md",
    kind: "markdown",
    digestBound: true,
  }),
  Object.freeze({
    path: "capsec/generated/target-matrix.md",
    kind: "markdown",
    digestBound: false,
  }),
  Object.freeze({
    path: "capsec/generated/target-advertisements.json",
    kind: "target-advertisements",
    digestBound: false,
  }),
  Object.freeze({
    path: "capsec/registry/coverage-edges.json",
    kind: "registry",
    digestBound: true,
  }),
  Object.freeze({
    path: "capsec/registry/target-cells.json",
    kind: "registry",
    digestBound: false,
  }),
  Object.freeze({
    path: "packages/ibex-runtime-js/src/security/capsec-registry.generated.ts",
    kind: "typescript",
    digestBound: true,
  }),
  Object.freeze({
    path: "src/builtins/helpers/capsec-registry.generated.cjs",
    kind: "javascript",
    digestBound: true,
  }),
  Object.freeze({
    path: "src/capsec_registry_generated.rs",
    kind: "rust",
    digestBound: true,
  }),
  Object.freeze({
    path: "src/engine/capsec_registry_generated.h",
    kind: "cxx",
    digestBound: true,
  }),
]);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function prettyJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function rawContentDigest(content) {
  return `sha256-${crypto.createHash("sha256").update(content, "utf8").digest("base64url")}`;
}

const ownedByCurrentUser = (metadata) =>
  typeof process.getuid !== "function" || metadata.uid === process.getuid();

function relativeOutputPath(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function compareStringArrays(left, right) {
  return (
    canonicalJson([...left].sort(compareText)) ===
    canonicalJson([...right].sort(compareText))
  );
}

function assertExactCatalogPaths(actualPaths, expectedRows, label) {
  const actual = actualPaths.map(relativeOutputPath);
  const expected = expectedRows.map((row) => row.path);
  if (!compareStringArrays(actual, expected)) {
    const actualSet = new Set(actual);
    const expectedSet = new Set(expected);
    throw new Error(
      `${label}: generated output catalog mismatch; unexpected=[${actual.filter((entry) => !expectedSet.has(entry)).join(", ")}] missing=[${expected.filter((entry) => !actualSet.has(entry)).join(", ")}]`,
    );
  }
}

assertExactCatalogPaths(
  Object.values(generatedRegistryPaths),
  generatedRegistryOutputCatalog,
  "declared generated registry paths",
);

function quoteRust(value) {
  return JSON.stringify(value);
}

function quoteCxx(value) {
  return JSON.stringify(value)
    .replaceAll("\\u2028", "\\u2028")
    .replaceAll("\\u2029", "\\u2029");
}

function edgeActionIds(edge) {
  if (edge.classification === "effects") {
    return edge.effects.map((effect) => effect.cap);
  }
  return edge.classification === "closed" ? [edge.cap] : [];
}

function renderRustBinding(binding) {
  const actions = binding.actionIds
    .map((id) => `    ${quoteRust(id)},`)
    .join("\n");
  const edges = binding.edgeIds.map((id) => `    ${quoteRust(id)},`).join("\n");
  const branches = binding.implementationBranchIds
    .map((id) => `    ${quoteRust(id)},`)
    .join("\n");
  const enforcementBranches = binding.enforcementBranchIds
    .map((id) => `    ${quoteRust(id)},`)
    .join("\n");
  const targets = binding.targetKeys
    .map((id) => `    ${quoteRust(id)},`)
    .join("\n");
  const closedEnvironmentNames = binding.closedEnvironmentNames
    .map((name) => `    ${quoteRust(name)},`)
    .join("\n");
  return `// @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs
// Do not edit by hand.
// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory

pub const CAPSEC_PROFILE: &str = ${quoteRust(binding.profile)};
pub const CAPSEC_SEMANTIC_CORE: &str = ${quoteRust(binding.semanticCore)};
pub const CAPSEC_CAPABILITY_DEFINITIONS_JSON: &str =
    include_str!("../capsec/registry/capability-definitions.json");
pub const CAPSEC_COVERAGE_EDGES_JSON: &str = include_str!("../capsec/registry/coverage-edges.json");
pub const CAPSEC_TARGET_CELLS_JSON: &str = include_str!("../capsec/registry/target-cells.json");
pub const CAPSEC_TARGET_ADVERTISEMENTS_JSON: &str =
    include_str!("../capsec/generated/target-advertisements.json");
pub const CAPSEC_WEBGPU_PRIVATE_OPERATION_REGISTRY_JSON: &str =
    include_str!("../capsec/generated/webgpu-private-operation-registry.json");
pub const CAPSEC_POLICY_RULES_JSON: &str = include_str!("../capsec/registry/policy-rules.json");

#[rustfmt::skip]
pub const CAPSEC_ACTION_IDS: &[&str] = &[
${actions}
];

#[rustfmt::skip]
pub const CAPSEC_COVERAGE_EDGE_IDS: &[&str] = &[
${edges}
];

#[rustfmt::skip]
pub const CAPSEC_IMPLEMENTATION_BRANCH_IDS: &[&str] = &[
${branches}
];

#[rustfmt::skip]
pub const CAPSEC_ENFORCEMENT_BRANCH_IDS: &[&str] = &[
${enforcementBranches}
];

#[rustfmt::skip]
pub const CAPSEC_TARGET_KEYS: &[&str] = &[
${targets}
];

#[rustfmt::skip]
pub const CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES: &[&str] = &[
${closedEnvironmentNames}
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_registry_ids_are_nonempty_and_sorted() {
        assert!(!CAPSEC_ACTION_IDS.is_empty());
        assert!(!CAPSEC_COVERAGE_EDGE_IDS.is_empty());
        assert!(!CAPSEC_IMPLEMENTATION_BRANCH_IDS.is_empty());
        assert!(!CAPSEC_ENFORCEMENT_BRANCH_IDS.is_empty());
        assert!(!CAPSEC_TARGET_KEYS.is_empty());
        assert!(!CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES.is_empty());
        assert!(CAPSEC_ACTION_IDS.windows(2).all(|rows| rows[0] < rows[1]));
        assert!(CAPSEC_COVERAGE_EDGE_IDS
            .windows(2)
            .all(|rows| rows[0] < rows[1]));
        assert!(CAPSEC_IMPLEMENTATION_BRANCH_IDS
            .windows(2)
            .all(|rows| rows[0] < rows[1]));
        assert!(CAPSEC_ENFORCEMENT_BRANCH_IDS
            .windows(2)
            .all(|rows| rows[0] < rows[1]));
        assert!(CAPSEC_TARGET_KEYS.windows(2).all(|rows| rows[0] < rows[1]));
        assert!(CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
            .windows(2)
            .all(|rows| rows[0] < rows[1]));
    }
}
`;
}

function renderCxxBinding(binding) {
  const actions = binding.actionIds
    .map((id) => `    ${quoteCxx(id)},`)
    .join("\n");
  const edges = binding.edgeIds.map((id) => `    ${quoteCxx(id)},`).join("\n");
  const branches = binding.implementationBranchIds
    .map((id) => `    ${quoteCxx(id)},`)
    .join("\n");
  const enforcementBranches = binding.enforcementBranchIds
    .map((id) => `    ${quoteCxx(id)},`)
    .join("\n");
  const targets = binding.targetKeys
    .map((id) => `    ${quoteCxx(id)},`)
    .join("\n");
  return `// @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs
// Do not edit by hand.
// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory
#pragma once

#include <cstddef>

namespace ibex::capsec_generated {

inline constexpr const char* kProfile = ${quoteCxx(binding.profile)};
inline constexpr const char* kSemanticCore = ${quoteCxx(binding.semanticCore)};
inline constexpr const char* kActionIds[] = {
${actions}
};
inline constexpr const char* kCoverageEdgeIds[] = {
${edges}
};
inline constexpr const char* kImplementationBranchIds[] = {
${branches}
};
inline constexpr const char* kEnforcementBranchIds[] = {
${enforcementBranches}
};
inline constexpr const char* kTargetKeys[] = {
${targets}
};
inline constexpr std::size_t kActionCount = sizeof(kActionIds) / sizeof(kActionIds[0]);
inline constexpr std::size_t kCoverageEdgeCount =
    sizeof(kCoverageEdgeIds) / sizeof(kCoverageEdgeIds[0]);
inline constexpr std::size_t kImplementationBranchCount =
    sizeof(kImplementationBranchIds) / sizeof(kImplementationBranchIds[0]);
inline constexpr std::size_t kEnforcementBranchCount =
    sizeof(kEnforcementBranchIds) / sizeof(kEnforcementBranchIds[0]);
inline constexpr std::size_t kTargetCellCount = sizeof(kTargetKeys) / sizeof(kTargetKeys[0]);

}  // namespace ibex::capsec_generated
`;
}

function renderTypeScriptBinding(binding) {
  return `// @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs
// Do not edit by hand.
// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory

export const CAPSEC_REGISTRY = Object.freeze({
  bindingSchema: ${JSON.stringify(binding.bindingSchema)},
  profile: ${JSON.stringify(binding.profile)},
  semanticCore: ${JSON.stringify(binding.semanticCore)},
  actionIds: Object.freeze(${JSON.stringify(binding.actionIds, null, 2)} as const),
  edgeIds: Object.freeze(${JSON.stringify(binding.edgeIds, null, 2)} as const),
  implementationBranchIds: Object.freeze(${JSON.stringify(binding.implementationBranchIds, null, 2)} as const),
  enforcementBranchIds: Object.freeze(${JSON.stringify(binding.enforcementBranchIds, null, 2)} as const),
  targetKeys: Object.freeze(${JSON.stringify(binding.targetKeys, null, 2)} as const),
} as const);

export type CapsecActionId = (typeof CAPSEC_REGISTRY.actionIds)[number];
export type CapsecCoverageEdgeId = (typeof CAPSEC_REGISTRY.edgeIds)[number];
export type CapsecImplementationBranchId = (typeof CAPSEC_REGISTRY.implementationBranchIds)[number];
export type CapsecEnforcementBranchId = (typeof CAPSEC_REGISTRY.enforcementBranchIds)[number];
export type CapsecTargetKey = (typeof CAPSEC_REGISTRY.targetKeys)[number];
`;
}

function renderJavaScriptBinding(binding) {
  return `'use strict';
// @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs
// Do not edit by hand.
// @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory

const CAPSEC_REGISTRY = ${JSON.stringify(binding, null, 2)};
Object.freeze(CAPSEC_REGISTRY.actionIds);
Object.freeze(CAPSEC_REGISTRY.edgeIds);
Object.freeze(CAPSEC_REGISTRY.implementationBranchIds);
Object.freeze(CAPSEC_REGISTRY.enforcementBranchIds);
Object.freeze(CAPSEC_REGISTRY.targetKeys);
Object.freeze(CAPSEC_REGISTRY);

module.exports = Object.freeze({ CAPSEC_REGISTRY });
`;
}

function renderIdsSchema(binding) {
  return prettyJson({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "https://ibex.dev/capsec/generated/capsec-registry-ids.schema.json",
    title: "Generated Ibex capsec registry identifiers",
    $comment:
      "@generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs",
    $defs: {
      actionId: { enum: binding.actionIds },
      coverageEdgeId: { enum: binding.edgeIds },
      implementationBranchId: { enum: binding.implementationBranchIds },
      enforcementBranchId: { enum: binding.enforcementBranchIds },
      targetKey: { enum: binding.targetKeys },
    },
  });
}

function markdownCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

function renderSurfaceDocs(coverage, implementationRows) {
  const implementationByEdge = new Map();
  for (const row of implementationRows) {
    const rows = implementationByEdge.get(row.edgeId) ?? [];
    rows.push(row);
    implementationByEdge.set(row.edgeId, rows);
  }
  const lines = [
    "<!-- @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs -->",
    "<!-- @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — generated review output -->",
    "# Generated capability surface inventory",
    "",
    "This table is review output. The JSON registries and observed source-surface manifest are authoritative.",
    "",
    "| Edge | Surface | Classification | Effect mode | Actions | Owner | Surface branch → enforcement branch | Observed source references |",
    "|---|---|---|---|---|---|---|---|",
  ];
  for (const edge of coverage.edges) {
    const implementations = implementationByEdge.get(edge.id) ?? [];
    const sourceRefs = [
      ...new Set(implementations.flatMap((row) => row.sourceRefs)),
    ].sort(compareText);
    const owners = [
      ...new Set(implementations.map((row) => row.implementationOwner)),
    ].sort(compareText);
    const branches = implementations
      .map(
        (row) =>
          `${row.branchId} → ${row.enforcementBranchId} [${row.targetVariant}${row.backend ? `/${row.backend}` : ""}]`,
      )
      .sort(compareText);
    lines.push(
      `| ${markdownCell(edge.id)} | ${markdownCell(`${edge.surface.kind}:${edge.surface.name}`)} | ${markdownCell(edge.classification)} | ${markdownCell(edge.effectMode ?? "—")} | ${markdownCell(edgeActionIds(edge).join(", ") || "—")} | ${markdownCell(owners.join(", ") || "—")} | ${markdownCell(branches.join(", ") || "—")} | ${markdownCell(sourceRefs.join(", ") || "—")} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

function renderTargetDocs(targetCells, coverage, targetAdvertisements) {
  const conditionalEdges = coverage.edges.filter(
    (edge) => edge.effectMode === "conditional-unrefined",
  ).length;
  const byTarget = new Map();
  for (const cell of targetCells.cells) {
    const targetKey = canonicalJson([cell.target.triple, cell.target.features]);
    const counts = byTarget.get(targetKey) ?? {
      target: cell.target,
      enforced: 0,
      closed: 0,
      nonCapability: 0,
      absent: 0,
      unsupported: 0,
      implementationBranches: 0,
      branchlessCells: 0,
    };
    const key =
      cell.disposition === "non-capability"
        ? "nonCapability"
        : cell.disposition;
    counts[key] += 1;
    counts.implementationBranches += cell.implementationBranchIds.length;
    if (cell.implementationBranchIds.length === 0) counts.branchlessCells += 1;
    byTarget.set(targetKey, counts);
  }
  const lines = [
    "<!-- @generated by packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs -->",
    "<!-- @ref LLP 0021#default-and-target-claim — exact-target claims derive only from content-addressed conformance reports -->",
    "# Generated capsec target matrix",
    "",
    `The registry contains ${coverage.edges.length} semantic coverage edges, including ${conditionalEdges} conditional-unrefined edges. ${targetAdvertisements.advertisements.length} exact target(s) are advertised from verified conformance reports.`,
    "",
    "| Exact target | Structural features | Selected implementation branches | Branchless cells | Enforced | Closed | Non-capability | Absent | Unsupported |",
    "|---|---|---:|---:|---:|---:|---:|---:|---:|",
  ];
  for (const counts of [...byTarget.values()].sort((left, right) =>
    compareText(canonicalJson(left.target), canonicalJson(right.target)),
  )) {
    lines.push(
      `| ${counts.target.triple} | ${counts.target.features.join(", ")} | ${counts.implementationBranches} | ${counts.branchlessCells} | ${counts.enforced} | ${counts.closed} | ${counts.nonCapability} | ${counts.absent} | ${counts.unsupported} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

export function buildTargetCells(
  coverage,
  candidateTargets,
  implementationRows,
  promotions = [],
) {
  const implementationsByEdge = new Map();
  for (const row of implementationRows) {
    const rows = implementationsByEdge.get(row.edgeId) ?? [];
    rows.push(row);
    implementationsByEdge.set(row.edgeId, rows);
  }
  const promotionByTarget = new Map(
    promotions.map((promotion) => [
      canonicalJson(promotion.report.bindings.target),
      promotion,
    ]),
  );
  const cells = [];
  for (const edge of coverage.edges) {
    const implementations = implementationsByEdge.get(edge.id) ?? [];
    if (implementations.length === 0) {
      throw new Error(`${edge.id}: target cell has no implementation branches`);
    }
    for (const target of candidateTargets) {
      const implementationBranchIds = applicableImplementationBranchIds(
        implementations,
        target,
      );
      const promotion = promotionByTarget.get(canonicalJson(target));
      if (!promotion) {
        cells.push({
          edgeId: edge.id,
          target: structuredClone(target),
          disposition: "unsupported",
          implementationBranchIds,
          fixtures: [],
          rationale:
            "No content-addressed conformant report advertises this exact target cell.",
        });
        continue;
      }
      const matching = promotion.report.cells.filter(
        (cell) => cell.edgeId === edge.id,
      );
      if (matching.length !== 1 || matching[0].status !== "conformant") {
        throw new Error(
          `${edge.id}: advertised report lacks one conformant exact target cell`,
        );
      }
      const reportCell = matching[0];
      if (
        canonicalJson(reportCell.implementationBranchIds) !==
        canonicalJson(implementationBranchIds)
      ) {
        throw new Error(
          `${edge.id}: advertised report branch selection differs from source inventory`,
        );
      }
      if (edge.effectMode === "conditional-unrefined") {
        throw new Error(
          `${edge.id}: conditional-unrefined edge cannot be advertised`,
        );
      }
      const disposition =
        implementationBranchIds.length === 0
          ? "absent"
          : edge.classification === "effects"
            ? "enforced"
            : edge.classification === "closed"
              ? "closed"
              : edge.classification === "non-capability"
                ? "non-capability"
                : null;
      if (!disposition) {
        throw new Error(
          `${edge.id}: report cannot promote classification ${edge.classification}`,
        );
      }
      cells.push({
        edgeId: edge.id,
        target: structuredClone(target),
        disposition,
        implementationBranchIds,
        fixtures: [...reportCell.requiredFixtures],
        rationale: `Promoted only by conformance report ${promotion.report.conformanceDigest} with raw content ${promotion.attestation.reportRawContentDigest}.`,
      });
    }
  }
  cells.sort((left, right) =>
    compareText(
      canonicalJson([left.edgeId, left.target.triple, left.target.features]),
      canonicalJson([right.edgeId, right.target.triple, right.target.features]),
    ),
  );
  return {
    targetCellSchema: "ibex/capsec-target-cells/1",
    profile: "ibex/capsec/1",
    cells,
  };
}

function buildSchemaValidator() {
  const manifest = readJsonStrict(path.join(capsecRoot, "contract-files.json"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const relativePath of manifest.schemas) {
    ajv.addSchema(readJsonStrict(path.join(capsecRoot, relativePath)));
  }
  return ajv;
}

function validateSchemaDocument(ajv, schemaId, value, label) {
  const validate = ajv.getSchema(schemaId);
  if (!validate) throw new Error(`${label}: schema is not loaded: ${schemaId}`);
  if (!validate(value)) {
    const details = (validate.errors ?? [])
      .map((error) => `${error.instancePath || "/"} ${error.message}`)
      .join("; ");
    throw new Error(`${label}: ${details}`);
  }
}

function expectedDigest(digestVectors, id) {
  const matches = digestVectors.vectors.filter((vector) => vector.id === id);
  if (matches.length !== 1)
    throw new Error(`missing exact ${id} digest vector`);
  return matches[0].expectedDigest;
}

export function readImmutablePromotionArtifact(
  directory,
  digest,
  label,
  root = capsecRoot,
) {
  const artifactPath = path.join(
    root,
    "conformance",
    directory,
    `${digest}.json`,
  );
  let pathMetadata;
  try {
    pathMetadata = fs.lstatSync(artifactPath);
  } catch {
    throw new Error(`${label} content-addressed artifact is missing`);
  }
  if (
    !pathMetadata.isFile() ||
    pathMetadata.isSymbolicLink() ||
    pathMetadata.nlink !== 1 ||
    !ownedByCurrentUser(pathMetadata)
  ) {
    throw new Error(
      `${label} is not an immutable regular file owned solely by the current user`,
    );
  }
  let descriptor;
  let bytes;
  try {
    descriptor = fs.openSync(
      artifactPath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const openedMetadata = fs.fstatSync(descriptor);
    if (
      !openedMetadata.isFile() ||
      openedMetadata.nlink !== 1 ||
      !ownedByCurrentUser(openedMetadata) ||
      openedMetadata.dev !== pathMetadata.dev ||
      openedMetadata.ino !== pathMetadata.ino
    ) {
      throw new Error(`${label} changed while it was being opened`);
    }
    bytes = fs.readFileSync(descriptor);
    const currentMetadata = fs.lstatSync(artifactPath);
    if (
      !currentMetadata.isFile() ||
      currentMetadata.isSymbolicLink() ||
      currentMetadata.nlink !== 1 ||
      !ownedByCurrentUser(currentMetadata) ||
      currentMetadata.dev !== openedMetadata.dev ||
      currentMetadata.ino !== openedMetadata.ino
    ) {
      throw new Error(`${label} changed while it was being read`);
    }
  } catch (error) {
    if (error?.message?.startsWith(label)) throw error;
    throw new Error(`${label} could not be opened without following links`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  if (rawContentDigest(bytes) !== digest) {
    throw new Error(`${label} raw content digest differs`);
  }
  return parseJsonStrict(bytes, label);
}

function verifyReportSourceRevision(attestation, allowedReportPaths) {
  const git = (...args) =>
    execFileSync("git", args, { cwd: repoRoot, encoding: "utf8" });
  try {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", attestation.sourceRevision, "HEAD"],
      { cwd: repoRoot, stdio: "ignore" },
    );
  } catch {
    throw new Error(
      "attested conformance source is not an ancestor of this checkout",
    );
  }
  const sourceTreeDigest = rawContentDigest(
    git("rev-parse", `${attestation.sourceRevision}^{tree}`),
  );
  if (sourceTreeDigest !== attestation.sourceTreeDigest) {
    throw new Error(
      "attested source revision does not have the reported tree digest",
    );
  }
  const allowed = new Set([
    "capsec/conformance/target-attestations.json",
    "capsec/generated/target-advertisements.json",
    "capsec/generated/target-matrix.md",
    "capsec/registry/target-cells.json",
    ...allowedReportPaths,
  ]);
  const committedChanges = git(
    "diff",
    "--name-only",
    `${attestation.sourceRevision}..HEAD`,
  )
    .trim()
    .split("\n")
    .filter(Boolean);
  const workingChanges = git("status", "--porcelain", "--untracked-files=all")
    .split("\n")
    .filter(Boolean)
    .map((line) => line.slice(3).split(" -> ").at(-1));
  const unbound = [...new Set([...committedChanges, ...workingChanges])].filter(
    (changedPath) => !allowed.has(changedPath),
  );
  if (unbound.length > 0) {
    throw new Error(
      `conformance source changed outside publication artifacts: ${unbound.join(", ")}`,
    );
  }
}

/**
 * Resolve the tiny authored attestation catalog to immutable report bytes and
 * re-derive every claim. No status, cell, or target list is copied from the
 * catalog: an advertisement exists only if the addressed report validates
 * against the current source-derived implementation inventory.
 */
export function loadTargetPromotions({
  coverage,
  implementation,
  inventory,
  outputShapeCatalog,
  outputDispositionRows,
  rules,
}) {
  const attestationPath = path.join(
    capsecRoot,
    "conformance",
    "target-attestations.json",
  );
  const attestations = readJsonStrict(attestationPath);
  const ajv = buildSchemaValidator();
  const validateAttestations = ajv.getSchema(
    "https://ibex.dev/capsec/schema/target-attestations.schema.json",
  );
  if (!validateAttestations?.(attestations)) {
    throw new Error(
      `invalid target attestations: ${ajv.errorsText(validateAttestations?.errors)}`,
    );
  }
  const validateReport = ajv.getSchema(
    "https://ibex.dev/capsec/schema/conformance-report.schema.json",
  );
  const validateOutputDispositionEvidence = ajv.getSchema(
    "https://ibex.dev/capsec/schema/output-disposition-evidence.schema.json",
  );
  const digestVectors = readJsonStrict(
    path.join(capsecRoot, "examples", "digest-vectors.canonical.json"),
  );
  const registryBundle = readJsonStrict(
    path.join(capsecRoot, "examples", "registry-digest-bundle.canonical.json"),
  );
  const vocabularyDigest = registryBundle.members.find(
    (member) => member.logicalName === "vocab-digest",
  )?.document?.digest;
  const registryDigest = expectedDigest(digestVectors, "registry");
  if (!vocabularyDigest) throw new Error("vocabulary digest is unavailable");

  const candidateTargets = new Set(
    rules.initialProfile.candidateTargets.map(canonicalJson),
  );
  const seenTargets = new Set();
  const seenReports = new Set();
  const seenRecipeCatalogs = new Set();
  const seenPublicExecutions = new Set();
  const seenOutputDispositionEvidence = new Set();
  const promotions = [];
  const allowedReportPaths = attestations.attestations.flatMap(
    (attestation) => [
      `capsec/conformance/reports/${attestation.reportRawContentDigest}.json`,
      `capsec/conformance/recipe-catalogs/${attestation.recipeCatalogRawContentDigest}.json`,
      `capsec/conformance/public-surface-executions/${attestation.publicSurfaceExecutionRawContentDigest}.json`,
      `capsec/conformance/output-disposition-evidence/${attestation.outputDispositionEvidenceRawContentDigest}.json`,
    ],
  );
  for (const attestation of attestations.attestations) {
    const targetKey = canonicalJson(attestation.target);
    if (!candidateTargets.has(targetKey)) {
      throw new Error("target attestation names a non-candidate target");
    }
    if (seenTargets.has(targetKey)) {
      throw new Error("target attestations contain a duplicate exact target");
    }
    if (seenReports.has(attestation.reportRawContentDigest)) {
      throw new Error(
        "target attestations reuse one report for multiple targets",
      );
    }
    if (seenRecipeCatalogs.has(attestation.recipeCatalogRawContentDigest)) {
      throw new Error(
        "target attestations reuse one recipe catalog for multiple targets",
      );
    }
    if (
      seenPublicExecutions.has(
        attestation.publicSurfaceExecutionRawContentDigest,
      )
    ) {
      throw new Error(
        "target attestations reuse one public execution artifact for multiple targets",
      );
    }
    if (
      seenOutputDispositionEvidence.has(
        attestation.outputDispositionEvidenceRawContentDigest,
      )
    ) {
      throw new Error(
        "target attestations reuse one output-disposition evidence artifact for multiple targets",
      );
    }
    seenTargets.add(targetKey);
    seenReports.add(attestation.reportRawContentDigest);
    seenRecipeCatalogs.add(attestation.recipeCatalogRawContentDigest);
    seenPublicExecutions.add(
      attestation.publicSurfaceExecutionRawContentDigest,
    );
    seenOutputDispositionEvidence.add(
      attestation.outputDispositionEvidenceRawContentDigest,
    );
    verifyReportSourceRevision(attestation, allowedReportPaths);

    const report = readImmutablePromotionArtifact(
      "reports",
      attestation.reportRawContentDigest,
      "attested conformance report",
    );
    if (!validateReport?.(report)) {
      throw new Error(
        `invalid attested conformance report: ${ajv.errorsText(validateReport?.errors)}`,
      );
    }
    const outputDispositionEvidence = readImmutablePromotionArtifact(
      "output-disposition-evidence",
      attestation.outputDispositionEvidenceRawContentDigest,
      "attested output-disposition evidence",
    );
    if (!validateOutputDispositionEvidence?.(outputDispositionEvidence)) {
      throw new Error(
        `invalid attested output-disposition evidence: ${ajv.errorsText(validateOutputDispositionEvidence?.errors)}`,
      );
    }
    const outputDispositionEvidenceState =
      validatePromotableOutputDispositionEvidence({
        catalog: outputShapeCatalog,
        dispositionRows: outputDispositionRows,
        evidence: outputDispositionEvidence,
        conformanceRunner: report.bindings.conformanceRunner,
      });
    assertOutputDispositionEvidenceMatchesReport(
      outputDispositionEvidenceState,
      report,
      attestation.outputDispositionEvidenceRawContentDigest,
    );
    const recipeCatalog = readImmutablePromotionArtifact(
      "recipe-catalogs",
      attestation.recipeCatalogRawContentDigest,
      "attested executable recipe catalog",
    );
    const expectedFixtureIds = fixtureExecutionPlans(
      fixtureCatalogForTarget({
        coverage,
        implementation,
        target: attestation.target,
      }),
    ).map((plan) => plan.fixtureId);
    const derivedRecipeCatalog = buildConformanceRecipeCatalog({
      catalog: fixtureCatalogForTarget({
        coverage,
        implementation,
        target: attestation.target,
      }),
      coverage,
      implementation,
      inventory,
      occurrenceExamples: readJsonStrict(
        path.join(capsecRoot, "examples", "effect-occurrences.canonical.json"),
      ),
      selectorExamples: readJsonStrict(
        path.join(capsecRoot, "examples", "authority-selectors.canonical.json"),
      ),
      capabilityDefinitions: readJsonStrict(
        path.join(capsecRoot, "registry", "capability-definitions.json"),
      ),
      target: attestation.target,
    });
    if (canonicalJson(recipeCatalog) !== canonicalJson(derivedRecipeCatalog)) {
      throw new Error(
        "attested recipe catalog differs from the source-derived public recipe plan",
      );
    }
    assertRecipeCatalogComplete(recipeCatalog, {
      target: attestation.target,
      expectedFixtureIds,
    });
    const publicSurfaceExecutions = readImmutablePromotionArtifact(
      "public-surface-executions",
      attestation.publicSurfaceExecutionRawContentDigest,
      "attested public-surface execution evidence",
    );
    assertPublicSurfaceExecutionComplete(
      publicSurfaceExecutions,
      recipeCatalog,
      {
        target: attestation.target,
        sourceRevision: attestation.sourceRevision,
        sourceTreeDigest: attestation.sourceTreeDigest,
        engine: report.bindings.engine,
        expectedFixtureIds,
      },
    );
    if (
      report.conformanceDigest !== attestation.conformanceDigest ||
      report.bindings.sourceRevision !== attestation.sourceRevision ||
      report.bindings.sourceTreeDigest !== attestation.sourceTreeDigest ||
      report.bindings.engine?.binaryDigest !== attestation.engineBinaryDigest ||
      canonicalJson(report.bindings.target) !== targetKey ||
      report.bindings.vocabularyDigest !== vocabularyDigest ||
      report.bindings.registryDigest !== registryDigest ||
      report.bindings.recipeCatalogDigest !== attestation.recipeCatalogDigest ||
      recipeCatalog.recipeCatalogDigest !== attestation.recipeCatalogDigest ||
      report.bindings.publicSurfaceExecutionDigest !==
        attestation.publicSurfaceExecutionDigest ||
      publicSurfaceExecutions.publicSurfaceExecutionDigest !==
        attestation.publicSurfaceExecutionDigest ||
      report.bindings.outputDispositionEvidenceRawContentDigest !==
        attestation.outputDispositionEvidenceRawContentDigest
    ) {
      throw new Error(
        "target attestation differs from the report or current semantic identities",
      );
    }
    validateConformanceReportSemantics(report, {
      coverage,
      implementation,
      target: attestation.target,
      digestContract: rules.digestContract,
      recipeCatalog,
      validateRuntimeObservation: validatePublicFixtureRuntimeObservation,
    });
    assertReportMayAdvertise(report);
    promotions.push({ attestation, report, outputDispositionEvidence });
  }
  promotions.sort((left, right) =>
    compareText(
      canonicalJson(left.attestation.target),
      canonicalJson(right.attestation.target),
    ),
  );
  return promotions;
}

export function assertOutputDispositionEvidenceMatchesReport(
  evidenceState,
  report,
  rawContentDigest,
) {
  const bindings = report?.bindings;
  if (
    evidenceState?.status !== "verified" ||
    bindings?.outputDispositionEvidenceRawContentDigest !== rawContentDigest ||
    evidenceState?.sourceRevision !== bindings?.sourceRevision ||
    evidenceState?.sourceTreeDigest !== bindings?.sourceTreeDigest ||
    canonicalJson(evidenceState?.conformanceRunner) !==
      canonicalJson(bindings?.conformanceRunner) ||
    canonicalJson(evidenceState?.target) !== canonicalJson(bindings?.target) ||
    canonicalJson(evidenceState?.engine) !== canonicalJson(bindings?.engine)
  ) {
    throw new Error(
      "target promotion is closed because the output-disposition evidence raw digest or exact source, runner, target, and loaded-engine binding differs from the report",
    );
  }
}

function buildTargetAdvertisements(promotions, targetCellsText) {
  return {
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/1",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: rawContentDigest(targetCellsText),
    advertisements: promotions.map(({ attestation, report }) => ({
      target: structuredClone(report.bindings.target),
      conformanceDigest: report.conformanceDigest,
      reportRawContentDigest: attestation.reportRawContentDigest,
      sourceRevision: report.bindings.sourceRevision,
      sourceTreeDigest: report.bindings.sourceTreeDigest,
      engine: structuredClone(report.bindings.engine),
      vocabularyDigest: report.bindings.vocabularyDigest,
      registryDigest: report.bindings.registryDigest,
      implementationManifestDigest:
        report.bindings.implementationManifestDigest,
      fixtureCatalogDigest: report.bindings.fixtureCatalogDigest,
      recipeCatalogDigest: report.bindings.recipeCatalogDigest,
      recipeCatalogRawContentDigest: attestation.recipeCatalogRawContentDigest,
      publicSurfaceExecutionDigest:
        report.bindings.publicSurfaceExecutionDigest,
      publicSurfaceExecutionRawContentDigest:
        attestation.publicSurfaceExecutionRawContentDigest,
      outputDispositionEvidenceRawContentDigest:
        attestation.outputDispositionEvidenceRawContentDigest,
    })),
  };
}

function buildBinding(
  definitions,
  coverage,
  targetCells,
  rules,
  implementationRows,
) {
  const actionIds = definitions.definitions
    .map((definition) => definition.id)
    .sort(compareText);
  const edgeIds = coverage.edges.map((edge) => edge.id).sort(compareText);
  const implementationBranchIds = implementationRows
    .map((row) => row.branchId)
    .sort(compareText);
  assertUnique(implementationBranchIds, "implementation branch ids");
  const enforcementBranchIds = [
    ...new Set(implementationRows.map((row) => row.enforcementBranchId)),
  ].sort(compareText);
  const targetKeys = targetCells.cells
    .map((cell) =>
      canonicalJson([cell.edgeId, cell.target.triple, cell.target.features]),
    )
    .sort(compareText);
  const closedEnvironmentNames = coverage.edges
    .filter((edge) => edge.classification === "closed")
    .map((edge) => edge.surface.name)
    .filter((name) => name.startsWith("env:") && !name.includes("<dynamic>"))
    .map((name) => name.slice("env:".length))
    .sort(compareText);
  assertUnique(closedEnvironmentNames, "closed startup environment names");
  return {
    bindingSchema: "ibex/capsec-generated-bindings/1",
    profile: "ibex/capsec/1",
    semanticCore: rules.semanticCore,
    actionIds,
    edgeIds,
    implementationBranchIds,
    enforcementBranchIds,
    targetKeys,
    closedEnvironmentNames,
  };
}

function renderOutputEntries(rendered) {
  const catalog = generatedRegistryOutputCatalog.filter(
    (row) => row.digestBound,
  );
  return catalog
    .map(({ path: outputPath, kind }) => {
      const content = rendered.get(path.join(repoRoot, outputPath));
      if (typeof content !== "string") {
        throw new Error(`digest-bound output ${outputPath} was not rendered`);
      }
      return {
        kind,
        path: outputPath,
        rawContentDigest: rawContentDigest(content),
      };
    })
    .sort((left, right) => compareText(left.path, right.path));
}

function assertUnique(values, label) {
  if (new Set(values).size !== values.length)
    throw new Error(`${label}: duplicate value`);
}

export async function renderCapsecRegistry() {
  const definitions = readJsonStrict(
    path.join(capsecRoot, "registry", "capability-definitions.json"),
  );
  const rules = readJsonStrict(
    path.join(capsecRoot, "registry", "policy-rules.json"),
  );
  const inventory = await discoverRepositorySurfaces(repoRoot);
  const flattened = inventory.surfaces ?? inventory;
  if (!Array.isArray(flattened) || flattened.length === 0) {
    throw new Error("surface discovery returned no surfaces");
  }
  assertReviewedSurfaceInventory(flattened);
  const model = buildCoverageModel(flattened, { definitions, rules });
  const coverage = model.coverage ?? {
    coverageSchema: "ibex/capsec-coverage/1",
    profile: "ibex/capsec/1",
    edges: model.edges,
  };
  coverage.edges.sort((left, right) => compareText(left.id, right.id));
  assertUnique(
    coverage.edges.map((edge) => edge.id),
    "coverage edge ids",
  );

  const implementationRows = [...model.implementationRows].sort((left, right) =>
    compareText(
      `${left.edgeId}\u0000${left.branchId}`,
      `${right.edgeId}\u0000${right.branchId}`,
    ),
  );
  assertUnique(
    implementationRows.map((row) => `${row.edgeId}\u0000${row.branchId}`),
    "implementation edge/branch ids",
  );

  const outputDispositionPolicy = readJsonStrict(
    path.join(capsecRoot, "registry", "output-disposition-policy.json"),
  );
  const outputDispositionEvidence = readJsonStrict(
    path.join(capsecRoot, "registry", "output-disposition-evidence.json"),
  );
  const ingressObligations = readJsonStrict(
    path.join(capsecRoot, "registry", "ingress-obligations.json"),
  );
  const schemaValidator = buildSchemaValidator();
  validateSchemaDocument(
    schemaValidator,
    "https://ibex.dev/capsec/schema/ingress-obligations.schema.json",
    ingressObligations,
    "authenticated ingress obligations",
  );
  const ingressObligationCounts = validateIngressObligationDataset({
    coverage,
    dataset: ingressObligations,
    repoRoot,
  });
  validateSchemaDocument(
    schemaValidator,
    "https://ibex.dev/capsec/schema/output-disposition-policy.schema.json",
    outputDispositionPolicy,
    "output disposition policy",
  );
  validateSchemaDocument(
    schemaValidator,
    "https://ibex.dev/capsec/schema/output-disposition-evidence.schema.json",
    outputDispositionEvidence,
    "output disposition evidence",
  );
  validateTrackedOutputDispositionEvidenceSentinel(outputDispositionEvidence);
  const outputShapeCatalog = buildOutputShapeCatalog({
    coverage,
    implementationRows,
    surfaces: flattened,
    repoRoot,
    liveEvidence: outputDispositionEvidence,
  });
  const outputDispositionDataset = buildOutputDispositionDataset({
    catalog: outputShapeCatalog,
    policy: outputDispositionPolicy,
    evidence: outputDispositionEvidence,
  });
  validateSchemaDocument(
    schemaValidator,
    "https://ibex.dev/capsec/schema/output-shape-catalog.schema.json",
    outputShapeCatalog,
    "generated output shape catalog",
  );
  validateSchemaDocument(
    schemaValidator,
    "https://ibex.dev/capsec/schema/output-dispositions.schema.json",
    outputDispositionDataset,
    "generated output disposition dataset",
  );
  const implementedEdgeIds = [
    ...new Set(implementationRows.map((row) => row.edgeId)),
  ].sort(compareText);
  if (
    canonicalJson(coverage.edges.map((edge) => edge.id)) !==
    canonicalJson(implementedEdgeIds)
  ) {
    throw new Error(
      "coverage edges and implementation rows do not join one-to-one",
    );
  }

  const candidateTargets = structuredClone(
    rules.initialProfile.candidateTargets,
  );
  let targetCells = buildTargetCells(
    coverage,
    candidateTargets,
    implementationRows,
  );
  const binding = buildBinding(
    definitions,
    coverage,
    targetCells,
    rules,
    implementationRows,
  );

  const rendered = new Map();
  rendered.set(generatedRegistryPaths.coverage, prettyJson(coverage));
  rendered.set(generatedRegistryPaths.targetCells, prettyJson(targetCells));
  rendered.set(
    generatedRegistryPaths.outputShapeCatalog,
    prettyJson(outputShapeCatalog),
  );
  rendered.set(
    generatedRegistryPaths.outputDispositions,
    prettyJson(outputDispositionDataset),
  );
  rendered.set(
    generatedRegistryPaths.outputDispositionDocs,
    renderOutputDispositionMarkdown(outputDispositionDataset),
  );
  let targetAdvertisements = buildTargetAdvertisements(
    [],
    rendered.get(generatedRegistryPaths.targetCells),
  );
  rendered.set(
    generatedRegistryPaths.targetAdvertisements,
    prettyJson(targetAdvertisements),
  );
  rendered.set(generatedRegistryPaths.rust, renderRustBinding(binding));
  rendered.set(generatedRegistryPaths.cxx, renderCxxBinding(binding));
  rendered.set(
    generatedRegistryPaths.javascript,
    renderJavaScriptBinding(binding),
  );
  rendered.set(
    generatedRegistryPaths.typescript,
    renderTypeScriptBinding(binding),
  );
  rendered.set(generatedRegistryPaths.idsSchema, renderIdsSchema(binding));
  rendered.set(
    generatedRegistryPaths.surfaceDocs,
    renderSurfaceDocs(coverage, implementationRows),
  );
  rendered.set(
    generatedRegistryPaths.targetDocs,
    renderTargetDocs(targetCells, coverage, targetAdvertisements),
  );

  const implementationManifest = {
    implementationManifestSchema: "ibex/capsec-implementation/1",
    profile: "ibex/capsec/1",
    status: "inventory-only-until-conformance",
    provenance: {
      sourceRefs: "definitions-stubs-or-security-relevant-references",
      targetBranches: "source-derived-not-conformance-evidence",
      targetSelection: "exact-branch-ids-from-target-applicability",
      fixtureDispatch: "enforcement-branch-ids-from-exact-source-and-semantics",
      promotionRule: "executed-fixtures-required",
    },
    sourceDatasets: [
      "registry/capability-definitions.json",
      "registry/coverage-edges.json",
      "registry/ingress-obligations.json",
      "registry/output-disposition-evidence.json",
      "registry/output-disposition-policy.json",
      "registry/policy-rules.json",
    ],
    candidateTargets,
    surfaces: implementationRows,
    definitionCoverage: [...model.definitionCoverage].sort((left, right) =>
      compareText(left.definitionId, right.definitionId),
    ),
    outputs: renderOutputEntries(rendered),
    counts: {
      observedReferences: implementationRows.reduce(
        (sum, row) => sum + row.sourceRefs.length,
        0,
      ),
      logicalSurfaces: new Set(implementationRows.map((row) => row.observedKey))
        .size,
      enforcementBranches: new Set(
        implementationRows.map((row) => row.enforcementBranchId),
      ).size,
      coverageEdges: coverage.edges.length,
      targetCells: targetCells.cells.length,
    },
  };

  // The source-derived implementation manifest is intentionally complete
  // before report verification. Target cells, advertisements, and their docs
  // are excluded from its output digest family, so promoting a report cannot
  // mutate the implementationManifestDigest that the report itself binds.
  const promotions = loadTargetPromotions({
    coverage,
    implementation: implementationManifest,
    inventory,
    outputShapeCatalog,
    outputDispositionRows: outputDispositionDataset.rows,
    rules,
  });
  targetCells = buildTargetCells(
    coverage,
    candidateTargets,
    implementationRows,
    promotions,
  );
  const targetCellsText = prettyJson(targetCells);
  targetAdvertisements = buildTargetAdvertisements(promotions, targetCellsText);
  rendered.set(generatedRegistryPaths.targetCells, targetCellsText);
  rendered.set(
    generatedRegistryPaths.targetAdvertisements,
    prettyJson(targetAdvertisements),
  );
  rendered.set(
    generatedRegistryPaths.targetDocs,
    renderTargetDocs(targetCells, coverage, targetAdvertisements),
  );
  rendered.set(
    generatedRegistryPaths.webgpuOperations,
    prettyJson(
      buildWebGpuPrivateOperationRegistry({
        authenticated: inventory.authenticatedWebGpuProductionPlan,
        coverage,
        implementationRows,
        targetCells,
        targetAdvertisements,
      }),
    ),
  );
  rendered.set(
    generatedRegistryPaths.implementationManifest,
    prettyJson(implementationManifest),
  );
  assertExactCatalogPaths(
    [...rendered.keys()],
    generatedRegistryOutputCatalog,
    "complete rendered output family",
  );
  return {
    rendered,
    coverage,
    targetCells,
    implementationManifest,
    targetAdvertisements,
    promotions,
    binding,
    inventory,
    outputShapeCatalog,
    outputDispositionDataset,
    ingressObligations,
    ingressObligationCounts,
  };
}

export async function runCapsecRegistryGenerator({ write = false } = {}) {
  const result = await renderCapsecRegistry();
  const stale = [];
  if (write) {
    writeGeneratedFilesTransactionally(
      repoRoot,
      [...result.rendered].map(([filePath, content]) => ({
        path: filePath,
        content,
        label: `generated capsec registry output ${relativeOutputPath(filePath)}`,
      })),
    );
  } else {
    for (const [filePath, content] of result.rendered) {
      const relative = relativeOutputPath(filePath);
      if (!fs.existsSync(filePath)) {
        stale.push(relative);
        continue;
      }
      assertConfinedGeneratedFile(
        repoRoot,
        filePath,
        `generated capsec registry output ${relative}`,
      );
      if (fs.readFileSync(filePath, "utf8") !== content) {
        stale.push(relative);
      }
    }
  }
  if (stale.length) {
    throw new Error(
      `generated capsec registry is stale:\n${stale.map((entry) => `  - ${entry}`).join("\n")}\nRun: bun run generate:capsec-registry`,
    );
  }
  return {
    coverageEdges: result.coverage.edges.length,
    targetCells: result.targetCells.cells.length,
    enforcementBranches:
      result.implementationManifest.counts.enforcementBranches,
    observedReferences: result.implementationManifest.counts.observedReferences,
    outputs: result.rendered.size,
    ingressObligations: result.ingressObligationCounts.obligations,
    outputDispositionEvidence: result.outputDispositionDataset.evidence.status,
  };
}

if (path.resolve(process.argv[1] ?? "") === __filename) {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  if (write === check) {
    console.error("usage: generate-capsec-registry.mjs (--write | --check)");
    process.exit(2);
  }
  try {
    const counts = await runCapsecRegistryGenerator({ write });
    console.log(
      `${write ? "Generated" : "Validated"} capsec registry: ${counts.coverageEdges} coverage edges, ${counts.enforcementBranches} enforcement branches, ${counts.targetCells} target cells, ${counts.observedReferences} observed source references, ${counts.ingressObligations} authenticated-ingress obligations, ${counts.outputs} outputs; output-disposition evidence ${counts.outputDispositionEvidence}.`,
    );
  } catch (error) {
    const diagnostic =
      error instanceof Error ? (error.stack ?? error.message) : String(error);
    console.error(`error: ${diagnostic}`);
    process.exit(1);
  }
}
