// Deterministic Phase-2 promotion preparation and assembly. This module emits
// detached candidate bytes; it never edits the checked acceptance catalogs.
//
// @ref LLP 0035#reports-and-advertisements — portable publication is derived
// from reviewed source inputs, then joined to exact per-process output bytes by
// the single frozen promotion validator.
// @ref LLP 0032#authority-boundary — preparation is not authority; only a
// complete aggregate containing every finalized attempt may validate.

import { createHash } from "node:crypto";
import {
  assertRecipeCatalogComplete,
  validateRecipeCatalog,
} from "./capsec-conformance-recipes.mjs";
import { fixtureCatalogForTarget } from "./capsec-conformance.mjs";
import { assertPublicSurfaceExecutionComplete } from "./capsec-public-surface-evidence.mjs";
import { publicSurfaceExecutorForRecipe } from "./capsec-public-executors.mjs";
import { canonicalOutputDispositionKey } from "./capsec-output-dispositions.mjs";
import { validatePromotableOutputDispositionEvidence } from "./capsec-output-shape-sweep.mjs";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";
import {
  portableConformanceDigest,
  portableOutputDispositionObservationDigest,
  portablePublicSurfaceExecutionDigest,
  portablePublicSurfaceExecutionEvidenceDigest,
  portableRecipeCatalogDigest,
  portableRecipePlanDigest,
  rawContentDigest,
  validatePortablePromotionV2,
} from "./capsec-portable-engine-evidence-contract.mjs";

const PROFILE = "ibex/capsec/1";
const SOURCE_SCHEMA = "ibex/capsec-portable-promotion-source/2";
const BUNDLE_SCHEMA = "ibex/capsec-portable-promotion-bundle/1";
const BUNDLE_DOMAIN = "ibex:capsec:portable-promotion-bundle:1";
const DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const REVISION_PATTERN = /^[a-f0-9]{40}$/u;
const FAMILY_BY_TRIPLE = Object.freeze([
  ["macos", /^(?:aarch64|x86_64)-apple-darwin$/u],
  ["windows", /^(?:aarch64|x86_64)-pc-windows-msvc$/u],
  ["linux", /^(?:aarch64|x86_64)-unknown-linux-(?:gnu|musl)$/u],
]);

const compareUtf8 = (left, right) =>
  Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
const clone = (value) => structuredClone(value);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactKeys(value, keys, label) {
  invariant(
    value && typeof value === "object" && !Array.isArray(value),
    `${label} must be an object`,
  );
  invariant(
    same(Object.keys(value).sort(compareUtf8), [...keys].sort(compareUtf8)),
    `${label} has unknown or missing fields`,
  );
}

function bytes(value, label) {
  invariant(
    Buffer.isBuffer(value) || value instanceof Uint8Array,
    `${label} must be exact bytes`,
  );
  return Buffer.from(value);
}

function exactJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function parseBytes(value, label) {
  return parseJsonStrict(bytes(value, label), label);
}

function canonicalDigest(value) {
  return rawContentDigest(Buffer.from(canonicalJson(value), "utf8"));
}

function canonicalScalarSet(values, label) {
  invariant(Array.isArray(values), `${label} must be an array`);
  const sorted = [...new Set(values)].sort(compareUtf8);
  invariant(same(values, sorted), `${label} must be UTF-8 sorted and unique`);
  return sorted;
}

function targetFamily(triple) {
  const matches = FAMILY_BY_TRIPLE.filter(([_family, pattern]) =>
    pattern.test(triple),
  );
  invariant(matches.length === 1, `unsupported portable target ${triple}`);
  return matches[0][0];
}

function parseReviewedSource(reviewedSourceBytes) {
  const source = parseBytes(reviewedSourceBytes, "reviewed promotion source");
  exactKeys(
    source,
    [
      "portablePromotionSourceSchema",
      "profile",
      "sourceRevision",
      "sourceTreeDigest",
      "family",
      "target",
      "engine",
      "vocabularyDigest",
      "registryDigest",
      "executorPolicy",
    ],
    "reviewed promotion source",
  );
  invariant(
    source.portablePromotionSourceSchema === SOURCE_SCHEMA &&
      source.profile === PROFILE &&
      REVISION_PATTERN.test(source.sourceRevision) &&
      DIGEST_PATTERN.test(source.sourceTreeDigest) &&
      DIGEST_PATTERN.test(source.vocabularyDigest) &&
      DIGEST_PATTERN.test(source.registryDigest) &&
      source.family === targetFamily(source.target?.triple) &&
      source.executorPolicy === "recipe-public-command",
    "reviewed promotion source is malformed",
  );
  canonicalScalarSet(source.target?.features, "reviewed target features");
  invariant(
    source.engine?.schema === "ibex/portable-engine-artifact-identity/1" &&
      source.engine.artifactId &&
      source.engine.target?.triple === source.target.triple,
    "reviewed promotion source lacks the exact portable engine identity",
  );
  return source;
}

function exactTargetCells(targetCells, target) {
  invariant(
    targetCells?.targetCellSchema === "ibex/capsec-target-cells/1" &&
      targetCells.profile === PROFILE &&
      Array.isArray(targetCells.cells),
    "promotion target cells are malformed",
  );
  const targetKey = canonicalJson(target);
  const rows = targetCells.cells.filter(
    (row) => canonicalJson(row.target) === targetKey,
  );
  invariant(rows.length > 0, "promotion target has no exact target cells");
  const edgeIds = rows.map((row) => row.edgeId);
  canonicalScalarSet(edgeIds, "promotion target-cell edge IDs");
  invariant(
    rows.every(
      (row) =>
        row.disposition !== "unsupported" &&
        Array.isArray(row.fixtures) &&
        Array.isArray(row.implementationBranchIds),
    ),
    "promotion target cells remain unsupported or malformed",
  );
  for (const row of rows) {
    canonicalScalarSet(row.fixtures, `${row.edgeId} fixture IDs`);
    canonicalScalarSet(
      row.implementationBranchIds,
      `${row.edgeId} implementation branch IDs`,
    );
  }
  return rows;
}

/**
 * Build the non-authoritative candidate target-cell bytes directly from the
 * reviewed coverage and implementation closure. This deliberately does not
 * consume a report: the later physical executions and sole v2 validator are
 * what justify carrying these bytes into a promotion bundle.
 */
export function derivePortablePromotionTargetCells({
  coverage,
  implementation,
  target,
}) {
  invariant(
    Array.isArray(coverage?.edges) &&
      Array.isArray(implementation?.surfaces),
    "candidate target cells require reviewed coverage and implementation bytes",
  );
  const fixtureCatalog = fixtureCatalogForTarget({
    coverage,
    implementation,
    target,
  });
  const coverageByEdge = new Map(
    coverage.edges.map((edge) => [edge.id, edge]),
  );
  invariant(
    coverageByEdge.size === coverage.edges.length &&
      fixtureCatalog.length === coverage.edges.length,
    "candidate target-cell source closure is incomplete or duplicated",
  );
  const cells = fixtureCatalog.map((catalogRow) => {
    const edge = coverageByEdge.get(catalogRow.edgeId);
    invariant(edge, `${catalogRow.edgeId}: candidate cell has no coverage edge`);
    invariant(
      edge.effectMode !== "conditional-unrefined",
      `${edge.id}: conditional-unrefined edge cannot enter candidate target cells`,
    );
    const disposition =
      catalogRow.implementationBranchIds.length === 0
        ? "absent"
        : edge.classification === "effects"
          ? "enforced"
          : edge.classification === "closed"
            ? "closed"
            : edge.classification === "non-capability"
              ? "non-capability"
              : null;
    invariant(
      disposition !== null,
      `${edge.id}: candidate cell has unpromotable classification ${edge.classification}`,
    );
    canonicalScalarSet(
      catalogRow.implementationBranchIds,
      `${edge.id} candidate implementation branches`,
    );
    canonicalScalarSet(
      catalogRow.requiredFixtures,
      `${edge.id} candidate fixture IDs`,
    );
    invariant(
      catalogRow.requiredFixtures.length > 0,
      `${edge.id}: candidate target cell has no required physical fixture`,
    );
    return {
      edgeId: edge.id,
      target: clone(target),
      disposition,
      implementationBranchIds: clone(catalogRow.implementationBranchIds),
      fixtures: clone(catalogRow.requiredFixtures),
      rationale:
        "Source-derived physical-promotion candidate; authority requires complete v2 execution evidence.",
    };
  });
  cells.sort((left, right) => compareUtf8(left.edgeId, right.edgeId));
  return {
    targetCellSchema: "ibex/capsec-target-cells/1",
    profile: PROFILE,
    cells,
  };
}

function validateSourceClosure({
  coverage,
  fixtureCatalog,
  implementation,
  targetCells,
  targetRows,
  source,
}) {
  invariant(
    Array.isArray(coverage?.edges) &&
      Array.isArray(implementation?.surfaces) &&
      Array.isArray(fixtureCatalog),
    "reviewed coverage, implementation, or fixture catalog is malformed",
  );
  const derivedFixtureCatalog = fixtureCatalogForTarget({
    coverage,
    implementation,
    target: source.target,
  });
  invariant(
    same(fixtureCatalog, derivedFixtureCatalog),
    "fixture catalog differs from reviewed coverage and implementation bytes",
  );
  const coverageByEdge = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  invariant(
    coverageByEdge.size === coverage.edges.length &&
      same(
        targetRows.map((row) => row.edgeId),
        coverage.edges.map((edge) => edge.id).sort(compareUtf8),
      ),
    "promotion target cells do not cover the exact reviewed edge inventory",
  );
  const catalogByEdge = new Map(fixtureCatalog.map((row) => [row.edgeId, row]));
  for (const row of targetRows) {
    const edge = coverageByEdge.get(row.edgeId);
    const catalogRow = catalogByEdge.get(row.edgeId);
    const expectedDisposition =
      catalogRow.implementationBranchIds.length === 0
        ? "absent"
        : edge.effectMode === "conditional-unrefined"
          ? null
          : edge.classification === "effects"
            ? "enforced"
            : edge.classification === "closed"
              ? "closed"
              : edge.classification === "non-capability"
                ? "non-capability"
                : null;
    invariant(
      expectedDisposition &&
        catalogRow.requiredFixtures.length > 0 &&
        row.disposition === expectedDisposition &&
        same(row.implementationBranchIds, catalogRow.implementationBranchIds) &&
        same(row.fixtures, catalogRow.requiredFixtures),
      `${row.edgeId}: target cell differs from independently derived source closure`,
    );
  }
  invariant(
    targetCells.cells.filter(
      (row) => canonicalJson(row.target) === canonicalJson(source.target),
    ).length === coverage.edges.length,
    "promotion target-cell catalog has incomplete exact-target membership",
  );
}

function requiredFixtureIds(targetRows) {
  return [...new Set(targetRows.flatMap((row) => row.fixtures))].sort(
    compareUtf8,
  );
}

export function derivePortableRecipeCatalogV2({
  richRecipeCatalog,
  target,
  expectedFixtureIds,
}) {
  validateRecipeCatalog(richRecipeCatalog, {
    target,
    expectedFixtureIds,
  });
  assertRecipeCatalogComplete(richRecipeCatalog, {
    target,
    expectedFixtureIds,
  });
  const recipes = richRecipeCatalog.recipes.map((richRecipe) => {
    const recipe = {
      fixtureId: richRecipe.fixtureId,
      status: "fully-executable",
      executor: publicSurfaceExecutorForRecipe(richRecipe),
      planDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    recipe.planDigest = portableRecipePlanDigest(recipe);
    return recipe;
  });
  const catalog = {
    recipeCatalogSchema: "ibex/capsec-executable-recipes/2",
    profile: PROFILE,
    target: clone(target),
    recipes,
    summary: {
      requiredFixtures: recipes.length,
      fullyExecutableFixtures: recipes.length,
      unresolvedFixtures: 0,
    },
    recipeCatalogDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  catalog.recipeCatalogDigest = portableRecipeCatalogDigest(catalog);
  return catalog;
}

export function derivePortablePublicSurfaceExecutionV2({
  richPublicSurfaceExecution,
  source,
  richRecipeCatalog,
  recipeCatalog,
  recipeCatalogBytes,
  expectedFixtureIds,
}) {
  invariant(
    richPublicSurfaceExecution?.publicSurfaceExecutionSchema ===
      "ibex/capsec-public-surface-executions/1" &&
      richPublicSurfaceExecution.profile === PROFILE &&
      richPublicSurfaceExecution.sourceRevision === source.sourceRevision &&
      richPublicSurfaceExecution.sourceTreeDigest === source.sourceTreeDigest &&
      same(richPublicSurfaceExecution.target, source.target) &&
      richPublicSurfaceExecution.engine?.binaryDigest ===
        source.engine.runtimeComponentDigest &&
      Array.isArray(richPublicSurfaceExecution.executions),
    "rich public-surface evidence differs from the reviewed portable source",
  );
  const rows = richPublicSurfaceExecution.executions;
  invariant(
    same(
      rows.map((row) => row.fixtureId),
      expectedFixtureIds,
    ) && rows.every((row) => row.outcome === "passed"),
    "rich public-surface evidence is missing, duplicate, failed, or noncanonical",
  );
  const recipeByFixture = new Map(
    recipeCatalog.recipes.map((recipe) => [recipe.fixtureId, recipe]),
  );
  const richRecipeByFixture = new Map(
    richRecipeCatalog.recipes.map((recipe) => [recipe.fixtureId, recipe]),
  );
  const executions = rows.map((row) => {
    const recipe = recipeByFixture.get(row.fixtureId);
    const richRecipe = richRecipeByFixture.get(row.fixtureId);
    invariant(
      recipe &&
        richRecipe &&
        row.executor === recipe.executor &&
        recipe.executor === publicSurfaceExecutorForRecipe(richRecipe),
      `${row.fixtureId}: public evidence executor differs from its source-authored command`,
    );
    const execution = {
      fixtureId: row.fixtureId,
      outcome: "passed",
      executor: recipe.executor,
      evidenceDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    execution.evidenceDigest =
      portablePublicSurfaceExecutionEvidenceDigest(execution);
    return execution;
  });
  const artifact = {
    publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/2",
    profile: PROFILE,
    sourceRevision: source.sourceRevision,
    sourceTreeDigest: source.sourceTreeDigest,
    target: clone(source.target),
    engine: clone(source.engine),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    recipeCatalogRawContentDigest: rawContentDigest(recipeCatalogBytes),
    summary: {
      requiredFixtures: executions.length,
      executableFixtures: executions.length,
      residualFixtures: 0,
      executedFixtures: executions.length,
      passedFixtures: executions.length,
      failedFixtures: 0,
      missingFixtures: 0,
    },
    executions,
    publicSurfaceExecutionDigest:
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  artifact.publicSurfaceExecutionDigest =
    portablePublicSurfaceExecutionDigest(artifact);
  return artifact;
}

function portableOutputKey(key) {
  const canonicalKey = canonicalOutputDispositionKey(key);
  return `output.${createHash("sha256").update(canonicalKey).digest("hex")}`;
}

export function derivePortableOutputDispositionEvidenceV4({
  richOutputDispositionEvidence,
  source,
}) {
  invariant(
    richOutputDispositionEvidence?.outputDispositionEvidenceSchema ===
      "ibex/capsec-output-disposition-evidence/3" &&
      richOutputDispositionEvidence.profile === PROFILE &&
      richOutputDispositionEvidence.status === "verified" &&
      richOutputDispositionEvidence.sourceRevision === source.sourceRevision &&
      richOutputDispositionEvidence.sourceTreeDigest ===
        source.sourceTreeDigest &&
      same(richOutputDispositionEvidence.target, source.target) &&
      richOutputDispositionEvidence.engine?.binaryDigest ===
        source.engine.runtimeComponentDigest &&
      Array.isArray(richOutputDispositionEvidence.observations) &&
      richOutputDispositionEvidence.observations.length > 0,
    "rich output-disposition proof differs from the reviewed portable source",
  );
  const observations = richOutputDispositionEvidence.observations
    .map((richObservation) => {
      const observation = {
        key: portableOutputKey(richObservation.key),
        disposition: richObservation.disposition,
        proofKind: richObservation.proofKind,
        observationDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      };
      observation.observationDigest =
        portableOutputDispositionObservationDigest(observation);
      return observation;
    })
    .sort((left, right) => compareUtf8(left.key, right.key));
  canonicalScalarSet(
    observations.map((observation) => observation.key),
    "portable output-disposition observation keys",
  );
  return {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/4",
    profile: PROFILE,
    status: "verified",
    sourceRevision: source.sourceRevision,
    sourceTreeDigest: source.sourceTreeDigest,
    target: clone(source.target),
    engine: clone(source.engine),
    summary: { observations: observations.length },
    observations,
  };
}

/**
 * Rejoin already-derived exact Phase-2 bytes to independently reviewed source
 * inputs. This is preparation only; no target is accepted or advertised here.
 */
export function preparePortablePromotionFromDerivedArtifactsV2({
  reviewedSourceBytes,
  coverageBytes,
  implementationManifestBytes,
  fixtureCatalogBytes,
  targetCellsBytes,
  recipeCatalogBytes,
  publicSurfaceExecutionBytes,
  outputDispositionEvidenceBytes,
}) {
  const source = parseReviewedSource(reviewedSourceBytes);
  const coverage = parseBytes(coverageBytes, "reviewed coverage bytes");
  const implementation = parseBytes(
    implementationManifestBytes,
    "reviewed implementation manifest bytes",
  );
  const fixtureCatalog = parseBytes(
    fixtureCatalogBytes,
    "derived fixture catalog bytes",
  );
  const targetCells = parseBytes(
    targetCellsBytes,
    "promotion target-cell bytes",
  );
  const recipeCatalog = parseBytes(recipeCatalogBytes, "portable recipe bytes");
  const publicSurfaceExecution = parseBytes(
    publicSurfaceExecutionBytes,
    "portable public-surface bytes",
  );
  const outputDispositionEvidence = parseBytes(
    outputDispositionEvidenceBytes,
    "portable output-disposition bytes",
  );
  const targetRows = exactTargetCells(targetCells, source.target);
  validateSourceClosure({
    coverage,
    fixtureCatalog,
    implementation,
    targetCells,
    targetRows,
    source,
  });
  const fixtures = requiredFixtureIds(targetRows);
  invariant(
    recipeCatalog.recipeCatalogSchema === "ibex/capsec-executable-recipes/2" &&
      recipeCatalog.recipeCatalogDigest ===
        portableRecipeCatalogDigest(recipeCatalog) &&
      same(recipeCatalog.target, source.target) &&
      same(
        recipeCatalog.recipes.map((row) => row.fixtureId),
        fixtures,
      ) &&
      recipeCatalog.recipes.every(
        (row) =>
          row.status === "fully-executable" &&
          typeof row.executor === "string" &&
          row.executor.length > 0 &&
          row.planDigest === portableRecipePlanDigest(row),
      ),
    "portable recipe bytes differ from reviewed complete fixture membership",
  );
  const portableRecipeByFixture = new Map(
    recipeCatalog.recipes.map((row) => [row.fixtureId, row]),
  );
  invariant(
    publicSurfaceExecution.publicSurfaceExecutionSchema ===
      "ibex/capsec-public-surface-executions/2" &&
      publicSurfaceExecution.sourceRevision === source.sourceRevision &&
      publicSurfaceExecution.sourceTreeDigest === source.sourceTreeDigest &&
      same(publicSurfaceExecution.target, source.target) &&
      same(publicSurfaceExecution.engine, source.engine) &&
      publicSurfaceExecution.recipeCatalogDigest ===
        recipeCatalog.recipeCatalogDigest &&
      publicSurfaceExecution.recipeCatalogRawContentDigest ===
        rawContentDigest(recipeCatalogBytes) &&
      publicSurfaceExecution.publicSurfaceExecutionDigest ===
        portablePublicSurfaceExecutionDigest(publicSurfaceExecution) &&
      same(
        publicSurfaceExecution.executions.map((row) => row.fixtureId),
        fixtures,
      ) &&
      publicSurfaceExecution.executions.every(
        (row) => {
          const recipe = portableRecipeByFixture.get(row.fixtureId);
          return (
            recipe &&
            row.outcome === "passed" &&
            row.executor === recipe.executor &&
            row.evidenceDigest ===
              portablePublicSurfaceExecutionEvidenceDigest(row)
          );
        },
      ),
    "portable public-surface bytes differ from reviewed source or recipes",
  );
  invariant(
    outputDispositionEvidence.outputDispositionEvidenceSchema ===
      "ibex/capsec-output-disposition-evidence/4" &&
      outputDispositionEvidence.status === "verified" &&
      outputDispositionEvidence.sourceRevision === source.sourceRevision &&
      outputDispositionEvidence.sourceTreeDigest === source.sourceTreeDigest &&
      same(outputDispositionEvidence.target, source.target) &&
      same(outputDispositionEvidence.engine, source.engine) &&
      outputDispositionEvidence.summary?.observations ===
        outputDispositionEvidence.observations?.length &&
      outputDispositionEvidence.observations?.every(
        (row) =>
          row.observationDigest ===
          portableOutputDispositionObservationDigest(row),
      ),
    "portable output-disposition bytes differ from reviewed source or proof",
  );

  const authorityEntry = {
    family: source.family,
    target: clone(source.target),
    engine: clone(source.engine),
    vocabularyDigest: source.vocabularyDigest,
    registryDigest: source.registryDigest,
    implementationManifestDigest: canonicalDigest(implementation),
    fixtureCatalogDigest: canonicalDigest(fixtureCatalog),
    targetCellsRawContentDigest: rawContentDigest(targetCellsBytes),
    recipeCatalogDigest: recipeCatalog.recipeCatalogDigest,
    recipeCatalogRawContentDigest: rawContentDigest(recipeCatalogBytes),
    publicSurfaceExecutionDigest:
      publicSurfaceExecution.publicSurfaceExecutionDigest,
    publicSurfaceExecutionRawContentDigest: rawContentDigest(
      publicSurfaceExecutionBytes,
    ),
    outputDispositionEvidenceRawContentDigest: rawContentDigest(
      outputDispositionEvidenceBytes,
    ),
  };
  const authority = {
    portablePromotionAuthoritySchema:
      "ibex/capsec-portable-promotion-authority/1",
    profile: PROFILE,
    sourceRevision: source.sourceRevision,
    sourceTreeDigest: source.sourceTreeDigest,
    targets: [authorityEntry],
  };
  return {
    authority,
    authorityBytes: exactJsonBytes(authority),
    authorityEntry,
    coverage,
    fixtureCatalog,
    fixtures,
    implementation,
    outputDispositionEvidence,
    outputDispositionEvidenceBytes: bytes(
      outputDispositionEvidenceBytes,
      "portable output-disposition bytes",
    ),
    publicSurfaceExecution,
    publicSurfaceExecutionBytes: bytes(
      publicSurfaceExecutionBytes,
      "portable public-surface bytes",
    ),
    recipeCatalog,
    recipeCatalogBytes: bytes(recipeCatalogBytes, "portable recipe bytes"),
    reviewedSourceBytes: bytes(reviewedSourceBytes, "reviewed source bytes"),
    source,
    targetCells,
    targetCellsBytes: bytes(targetCellsBytes, "promotion target-cell bytes"),
    targetRows,
  };
}

/**
 * Production preparation from the current rich v1 evidence. The rich output
 * proof is replayed before its small, locality-free v4 projection is emitted.
 */
export function preparePortablePromotionV2({
  reviewedSourceBytes,
  coverageBytes,
  implementationManifestBytes,
  targetCellsBytes = null,
  richRecipeCatalogBytes,
  richPublicSurfaceExecutionBytes,
  richOutputDispositionEvidenceBytes,
  outputShapeCatalogBytes,
  outputDispositionRowsBytes,
}) {
  const source = parseReviewedSource(reviewedSourceBytes);
  const coverage = parseBytes(coverageBytes, "reviewed coverage bytes");
  const implementation = parseBytes(
    implementationManifestBytes,
    "reviewed implementation manifest bytes",
  );
  const targetCells = derivePortablePromotionTargetCells({
    coverage,
    implementation,
    target: source.target,
  });
  const derivedTargetCellsBytes = exactJsonBytes(targetCells);
  if (targetCellsBytes !== null && targetCellsBytes !== undefined) {
    invariant(
      bytes(targetCellsBytes, "supplied promotion target-cell bytes").equals(
        derivedTargetCellsBytes,
      ),
      "supplied promotion target cells differ from independent source closure",
    );
  }
  const targetRows = exactTargetCells(targetCells, source.target);
  const fixtureCatalog = fixtureCatalogForTarget({
    coverage,
    implementation,
    target: source.target,
  });
  validateSourceClosure({
    coverage,
    fixtureCatalog,
    implementation,
    targetCells,
    targetRows,
    source,
  });
  const fixtures = requiredFixtureIds(targetRows);
  const richRecipeCatalog = parseBytes(
    richRecipeCatalogBytes,
    "rich executable recipe bytes",
  );
  const richPublicSurfaceExecution = parseBytes(
    richPublicSurfaceExecutionBytes,
    "rich public-surface bytes",
  );
  assertPublicSurfaceExecutionComplete(
    richPublicSurfaceExecution,
    richRecipeCatalog,
    {
      target: source.target,
      sourceRevision: source.sourceRevision,
      sourceTreeDigest: source.sourceTreeDigest,
      expectedFixtureIds: fixtures,
      coverage,
    },
  );
  invariant(
    richPublicSurfaceExecution.engine?.binaryDigest ===
      source.engine.runtimeComponentDigest,
    "rich public evidence executed another engine binary",
  );
  const richOutputDispositionEvidence = parseBytes(
    richOutputDispositionEvidenceBytes,
    "rich output-disposition proof bytes",
  );
  const outputShapeCatalog = parseBytes(
    outputShapeCatalogBytes,
    "reviewed output-shape catalog bytes",
  );
  const outputDispositionRowsDocument = parseBytes(
    outputDispositionRowsBytes,
    "reviewed output-disposition rows bytes",
  );
  invariant(
    Array.isArray(outputDispositionRowsDocument?.rows),
    "reviewed output-disposition rows document is malformed",
  );
  validatePromotableOutputDispositionEvidence({
    catalog: outputShapeCatalog,
    dispositionRows: outputDispositionRowsDocument.rows,
    evidence: richOutputDispositionEvidence,
  });

  const recipeCatalog = derivePortableRecipeCatalogV2({
    richRecipeCatalog,
    target: source.target,
    expectedFixtureIds: fixtures,
  });
  const recipeCatalogBytes = exactJsonBytes(recipeCatalog);
  const publicSurfaceExecution = derivePortablePublicSurfaceExecutionV2({
    richPublicSurfaceExecution,
    source,
    richRecipeCatalog,
    recipeCatalog,
    recipeCatalogBytes,
    expectedFixtureIds: fixtures,
  });
  const publicSurfaceExecutionBytes = exactJsonBytes(publicSurfaceExecution);
  const outputDispositionEvidence = derivePortableOutputDispositionEvidenceV4({
    richOutputDispositionEvidence,
    source,
  });
  const outputDispositionEvidenceBytes = exactJsonBytes(
    outputDispositionEvidence,
  );
  return preparePortablePromotionFromDerivedArtifactsV2({
    reviewedSourceBytes,
    coverageBytes,
    implementationManifestBytes,
    fixtureCatalogBytes: exactJsonBytes(fixtureCatalog),
    targetCellsBytes: derivedTargetCellsBytes,
    recipeCatalogBytes,
    publicSurfaceExecutionBytes,
    outputDispositionEvidenceBytes,
  });
}

function reportCells(preparation) {
  const fixtureCatalogByEdge = new Map(
    preparation.fixtureCatalog.map((row) => [row.edgeId, row]),
  );
  return preparation.targetRows.map((targetCell) => {
    const sourceCell = fixtureCatalogByEdge.get(targetCell.edgeId);
    return {
      edgeId: targetCell.edgeId,
      implementationBranchIds: clone(targetCell.implementationBranchIds),
      enforcementBranchIds: clone(sourceCell.enforcementBranchIds),
      status: "conformant",
      requiredFixtures: clone(targetCell.fixtures),
      passedFixtures: clone(targetCell.fixtures),
      missingFixtures: [],
      failedFixtures: [],
    };
  });
}

function processProjection(processes, preparation) {
  invariant(
    Array.isArray(processes) && processes.length > 0,
    "portable promotion requires at least one detached process",
  );
  const projected = processes.map((process, processIndex) => {
    exactKeys(
      process,
      ["mappedEvidenceBytes", "commandAttemptBytes", "outputArtifactBytes"],
      `portable process ${processIndex}`,
    );
    const mappedEvidenceBytes = bytes(
      process.mappedEvidenceBytes,
      `portable process ${processIndex} mapped evidence`,
    );
    const commandAttemptBytes = bytes(
      process.commandAttemptBytes,
      `portable process ${processIndex} command attempt`,
    );
    invariant(
      Array.isArray(process.outputArtifactBytes) &&
        process.outputArtifactBytes.length > 0,
      `portable process ${processIndex} has no fixture outputs`,
    );
    const evidence = parseBytes(
      mappedEvidenceBytes,
      `portable process ${processIndex} mapped evidence`,
    );
    const attempt = parseBytes(
      commandAttemptBytes,
      `portable process ${processIndex} command attempt`,
    );
    const outputs = process.outputArtifactBytes
      .map((outputBytes, outputIndex) => {
        const rawBytes = bytes(
          outputBytes,
          `portable process ${processIndex} output ${outputIndex}`,
        );
        return {
          artifact: parseBytes(
            rawBytes,
            `portable process ${processIndex} output ${outputIndex}`,
          ),
          bytes: rawBytes,
        };
      })
      .sort((left, right) =>
        compareUtf8(left.artifact.fixtureId, right.artifact.fixtureId),
      );
    return {
      attempt,
      commandAttemptBytes,
      evidence,
      mappedEvidenceBytes,
      outputs,
      process: {
        mappedEvidenceBytes,
        commandAttemptBytes,
        outputArtifactBytes: outputs.map((output) => output.bytes),
      },
    };
  });
  projected.sort((left, right) =>
    compareUtf8(left.evidence.evidenceDigest, right.evidence.evidenceDigest),
  );
  const seenEvidence = new Set();
  const seenFixtures = new Set();
  const references = [];
  const executions = [];
  for (const process of projected) {
    invariant(
      typeof process.evidence.evidenceDigest === "string" &&
        !seenEvidence.has(process.evidence.evidenceDigest),
      "portable process evidence is missing or duplicated",
    );
    seenEvidence.add(process.evidence.evidenceDigest);
    references.push({
      evidenceDigest: process.evidence.evidenceDigest,
      rawContentDigest: rawContentDigest(process.mappedEvidenceBytes),
      attemptDigest: process.attempt.attemptDigest,
      attemptRawContentDigest: rawContentDigest(process.commandAttemptBytes),
    });
    for (const output of process.outputs) {
      const artifact = output.artifact;
      invariant(
        typeof artifact.fixtureId === "string" &&
          !seenFixtures.has(artifact.fixtureId),
        "portable fixture output is missing or duplicated",
      );
      seenFixtures.add(artifact.fixtureId);
      executions.push({
        fixtureId: artifact.fixtureId,
        outcome: artifact.outcome,
        executor: artifact.executor,
        artifactDigest: artifact.artifactDigest,
        rawContentDigest: rawContentDigest(output.bytes),
        bindingDigest: artifact.bindingDigest,
        mappedEngineExecutionEvidenceDigest: process.evidence.evidenceDigest,
      });
    }
  }
  references.sort((left, right) =>
    compareUtf8(left.evidenceDigest, right.evidenceDigest),
  );
  executions.sort((left, right) =>
    compareUtf8(left.fixtureId, right.fixtureId),
  );
  invariant(
    same(
      executions.map((execution) => execution.fixtureId),
      preparation.fixtures,
    ),
    "portable process outputs do not cover exact required fixture membership",
  );
  return { executions, processes: projected, references };
}

function candidateFiles(input) {
  const files = [
    ["portable-promotion-authority", input.authorityBytes],
    ["portable-conformance-report", input.reportBytes],
    ["target-attestations", input.attestationCatalogBytes],
    ["target-advertisements", input.advertisementCatalogBytes],
    ["target-cells", input.targetCellsBytes],
    ["recipes", input.recipeCatalogBytes],
    ["public-surface", input.publicSurfaceExecutionBytes],
    ["output-dispositions", input.outputDispositionEvidenceBytes],
  ];
  input.processes.forEach((process, processIndex) => {
    const prefix = `process-${String(processIndex + 1).padStart(4, "0")}`;
    files.push([`${prefix}.mapped-evidence`, process.mappedEvidenceBytes]);
    files.push([`${prefix}.command-attempt`, process.commandAttemptBytes]);
    process.outputArtifactBytes.forEach((outputBytes, outputIndex) => {
      files.push([
        `${prefix}.fixture-${String(outputIndex + 1).padStart(6, "0")}`,
        outputBytes,
      ]);
    });
  });
  return files.map(([logicalName, fileBytes]) => ({
    logicalName,
    bytes: Buffer.from(fileBytes),
    byteLength: fileBytes.byteLength,
    rawContentDigest: rawContentDigest(fileBytes),
  }));
}

/** Assemble and validate the exact future-P candidate without publishing it. */
export function buildPortablePromotionBundleV2({ preparation, processes }) {
  invariant(
    preparation?.authorityEntry && preparation?.source,
    "portable promotion preparation is required",
  );
  const processState = processProjection(processes, preparation);
  const bindings = {
    sourceRevision: preparation.source.sourceRevision,
    sourceTreeDigest: preparation.source.sourceTreeDigest,
    engine: clone(preparation.source.engine),
    target: clone(preparation.source.target),
    vocabularyDigest: preparation.authorityEntry.vocabularyDigest,
    registryDigest: preparation.authorityEntry.registryDigest,
    implementationManifestDigest:
      preparation.authorityEntry.implementationManifestDigest,
    fixtureCatalogDigest: preparation.authorityEntry.fixtureCatalogDigest,
    targetCellsRawContentDigest:
      preparation.authorityEntry.targetCellsRawContentDigest,
    recipeCatalogDigest: preparation.authorityEntry.recipeCatalogDigest,
    recipeCatalogRawContentDigest:
      preparation.authorityEntry.recipeCatalogRawContentDigest,
    publicSurfaceExecutionDigest:
      preparation.authorityEntry.publicSurfaceExecutionDigest,
    publicSurfaceExecutionRawContentDigest:
      preparation.authorityEntry.publicSurfaceExecutionRawContentDigest,
    outputDispositionEvidenceRawContentDigest:
      preparation.authorityEntry.outputDispositionEvidenceRawContentDigest,
    mappedEngineExecutionEvidence: processState.references,
  };
  const cells = reportCells(preparation);
  const report = {
    conformanceSchema: "ibex/capsec-conformance/2",
    profile: PROFILE,
    status: "conformant",
    bindings,
    summary: {
      cells: cells.length,
      conformantCells: cells.length,
      incompleteCells: 0,
      requiredFixtures: preparation.fixtures.length,
      passedFixtures: preparation.fixtures.length,
      missingFixtures: 0,
      failedFixtures: 0,
    },
    executions: processState.executions,
    cells,
    conformanceDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  report.conformanceDigest = portableConformanceDigest(report);
  const reportBytes = exactJsonBytes(report);
  const reportRawContentDigest = rawContentDigest(reportBytes);
  const attestations = {
    targetAttestationSchema: "ibex/capsec-target-attestations/2",
    profile: PROFILE,
    attestations: [
      {
        target: clone(preparation.source.target),
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest,
        sourceRevision: preparation.source.sourceRevision,
        sourceTreeDigest: preparation.source.sourceTreeDigest,
        portableArtifactId: preparation.source.engine.artifactId,
        mappedEngineExecutionEvidence: clone(processState.references),
        recipeCatalogDigest: preparation.authorityEntry.recipeCatalogDigest,
        recipeCatalogRawContentDigest:
          preparation.authorityEntry.recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          preparation.authorityEntry.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          preparation.authorityEntry.publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          preparation.authorityEntry.outputDispositionEvidenceRawContentDigest,
      },
    ],
  };
  const advertisements = {
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/2",
    profile: PROFILE,
    targetCellsRawContentDigest:
      preparation.authorityEntry.targetCellsRawContentDigest,
    advertisements: [
      {
        target: clone(preparation.source.target),
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest,
        sourceRevision: preparation.source.sourceRevision,
        sourceTreeDigest: preparation.source.sourceTreeDigest,
        engine: clone(preparation.source.engine),
        mappedEngineExecutionEvidence: clone(processState.references),
        vocabularyDigest: preparation.authorityEntry.vocabularyDigest,
        registryDigest: preparation.authorityEntry.registryDigest,
        implementationManifestDigest:
          preparation.authorityEntry.implementationManifestDigest,
        fixtureCatalogDigest: preparation.authorityEntry.fixtureCatalogDigest,
        recipeCatalogDigest: preparation.authorityEntry.recipeCatalogDigest,
        recipeCatalogRawContentDigest:
          preparation.authorityEntry.recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest:
          preparation.authorityEntry.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          preparation.authorityEntry.publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          preparation.authorityEntry.outputDispositionEvidenceRawContentDigest,
      },
    ],
  };
  const input = {
    authorityBytes: preparation.authorityBytes,
    reportBytes,
    attestationCatalogBytes: exactJsonBytes(attestations),
    advertisementCatalogBytes: exactJsonBytes(advertisements),
    targetCellsBytes: preparation.targetCellsBytes,
    recipeCatalogBytes: preparation.recipeCatalogBytes,
    publicSurfaceExecutionBytes: preparation.publicSurfaceExecutionBytes,
    outputDispositionEvidenceBytes: preparation.outputDispositionEvidenceBytes,
    processes: processState.processes.map((process) => process.process),
  };

  // This is deliberately the only authority-bearing validation call.
  const validated = validatePortablePromotionV2(input);
  const files = candidateFiles(input);
  const manifest = {
    portablePromotionBundleSchema: BUNDLE_SCHEMA,
    profile: PROFILE,
    sourceRevision: preparation.source.sourceRevision,
    sourceTreeDigest: preparation.source.sourceTreeDigest,
    target: clone(preparation.source.target),
    files: files.map(({ bytes: _bytes, ...file }) => file),
    bundleDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  manifest.bundleDigest = computeDomainDigest(BUNDLE_DOMAIN, manifest, [
    "bundleDigest",
  ]);
  return {
    advertisements,
    attestations,
    files,
    input,
    manifest,
    manifestBytes: exactJsonBytes(manifest),
    report,
    validated,
  };
}
