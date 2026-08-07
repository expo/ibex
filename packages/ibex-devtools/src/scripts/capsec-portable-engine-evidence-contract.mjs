// Additive Phase-2 contract validation. This module freezes a future
// promotion boundary; the live v1 conformance runner does not import it.
//
// @ref LLP 0035#runtime-identity-split — portable publication identity and
// per-process mapped identity are different authority layers.
// @ref LLP 0035#reports-and-advertisements — promotion rejoins detached local
// evidence to portable reports and independently derived source authority.
// @ref LLP 0032#authority-boundary — a structurally valid document is not
// promotion authority without complete command and output evidence.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
  conformanceRunnerBindingDigest,
  validateConformanceRunnerBinding,
} from "./capsec-conformance-runner-binding.mjs";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";
import { INTERNAL_INVARIANT_EXECUTOR } from "./capsec-internal-invariant-evidence.mjs";

const MAPPED_ENGINE_EXECUTION_EVIDENCE_SCHEMA =
  "ibex/capsec-mapped-engine-execution-evidence/1";
const MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN =
  "ibex:capsec:mapped-engine-execution-evidence:1";
const PORTABLE_FIXTURE_EVIDENCE_SCHEMA =
  "ibex/capsec-portable-fixture-evidence/1";
const PORTABLE_FIXTURE_EVIDENCE_DOMAIN =
  "ibex:capsec:portable-fixture-evidence:1";
const PORTABLE_EXECUTION_BINDING_DOMAIN =
  "ibex:capsec:portable-execution-binding:1";
const PORTABLE_RECIPE_PLAN_DOMAIN = "ibex:capsec:executable-recipe-plan:1";
const PORTABLE_RECIPE_CATALOG_DOMAIN = "ibex:capsec:executable-recipes:2";
const PORTABLE_PUBLIC_SURFACE_EXECUTION_DOMAIN =
  "ibex:capsec:public-surface-executions:2";
const PORTABLE_PUBLIC_SURFACE_EXECUTION_EVIDENCE_DOMAIN =
  "ibex:capsec:public-surface-execution-evidence:1";
const PORTABLE_OUTPUT_DISPOSITION_OBSERVATION_DOMAIN =
  "ibex:capsec:output-disposition-observation:1";
const PORTABLE_CONFORMANCE_SCHEMA = "ibex/capsec-conformance/2";
const PORTABLE_CONFORMANCE_DOMAIN = "ibex:capsec:conformance:2";
const PORTABLE_TARGET_ATTESTATIONS_SCHEMA = "ibex/capsec-target-attestations/3";
// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — publication v3 names scoped certification and binds
// scopeDigest without changing tuple-keyed catalog selection.
const PORTABLE_TARGET_ADVERTISEMENTS_SCHEMA =
  "ibex/capsec-target-advertisements/3";
const PORTABLE_PROMOTION_AUTHORITY_SCHEMA =
  "ibex/capsec-portable-promotion-authority/1";
const CAPSEC_SCOPE_SCHEMA = "ibex/capsec-scope/1";
const CAPSEC_SCOPE_DOMAIN = "ibex:capsec:scope:1";
const CAPSEC_SCOPE_EXPANSION_DIFF_SCHEMA = "ibex/capsec-scope-expansion-diff/1";
const CAPSEC_SCOPE_EXPANSION_DIFF_DOMAIN = "ibex:capsec:scope-expansion-diff:1";
const CAPSEC_SCOPE_CELL_MAPPING_SCHEMA = "ibex/capsec-scope-cell-mapping/1";
const CAPSEC_SCOPE_CELL_MAPPING_DOMAIN = "ibex:capsec:scope-cell-mapping:1";
const COMMAND_ATTEMPT_DOMAIN = "ibex/capsec-command-attempt/1";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../../..");
const schemaPaths = [
  "capsec/schema/common.schema.json",
  "capsec/schema/target-cell.schema.json",
  "schemas/portable-engine-common-v1.schema.json",
  "schemas/portable-engine-artifact-identity-v1.schema.json",
  "schemas/mapped-engine-instance-identity-v1.schema.json",
  "schemas/capsec-portable-engine-evidence-common-v1.schema.json",
  "schemas/capsec-command-attempt-v1.schema.json",
  "schemas/capsec-executable-recipes-v2.schema.json",
  "schemas/capsec-public-surface-executions-v2.schema.json",
  "schemas/capsec-output-disposition-evidence-v4.schema.json",
  "schemas/capsec-portable-fixture-evidence-v1.schema.json",
  "schemas/capsec-mapped-engine-execution-evidence-v1.schema.json",
  "schemas/capsec-conformance-report-v2.schema.json",
  "schemas/capsec-target-attestations-v2.schema.json",
  "schemas/capsec-target-advertisements-v3.schema.json",
  "schemas/capsec-portable-promotion-authority-v1.schema.json",
];

const schemaIds = Object.freeze({
  advertisements:
    "https://ibex.dev/schemas/capsec-target-advertisements-v3.schema.json",
  attestations:
    "https://ibex.dev/schemas/capsec-target-attestations-v2.schema.json",
  authority:
    "https://ibex.dev/schemas/capsec-portable-promotion-authority-v1.schema.json",
  attempt: "https://ibex.dev/schemas/capsec-command-attempt-v1.schema.json",
  evidence:
    "https://ibex.dev/schemas/capsec-mapped-engine-execution-evidence-v1.schema.json",
  fixture:
    "https://ibex.dev/schemas/capsec-portable-fixture-evidence-v1.schema.json",
  report: "https://ibex.dev/schemas/capsec-conformance-report-v2.schema.json",
  recipe: "https://ibex.dev/schemas/capsec-executable-recipes-v2.schema.json",
  publicSurface:
    "https://ibex.dev/schemas/capsec-public-surface-executions-v2.schema.json",
  outputDisposition:
    "https://ibex.dev/schemas/capsec-output-disposition-evidence-v4.schema.json",
  targetCells: "https://ibex.dev/capsec/schema/target-cell.schema.json",
});

const CAPSEC_STABLE_ID = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u;
const FAMILY_TRIPLE_PATTERNS = Object.freeze({
  linux: /^(?:aarch64|x86_64)-unknown-linux-(?:gnu|musl)$/u,
  macos: /^(?:aarch64|x86_64)-apple-darwin$/u,
  windows: /^(?:aarch64|x86_64)-pc-windows-msvc$/u,
});

const FORBIDDEN_PUBLICATION_KEYS = new Set(
  [
    "after",
    "before",
    "binaryDigest",
    "canonicalLocalRuntimePath",
    "engineArtifactPath",
    "engineBinaryDigest",
    "localObject",
    "mappedEngine",
    "mappedObject",
    "mappingProof",
    "object",
    "observationDigest",
    "processArchitecture",
    "regionEnd",
    "regionStart",
    "targetArchitecture",
  ].map((key) => key.toLowerCase()),
);

let compiledValidators;

const compareUtf8 = (left, right) =>
  Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));

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
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...keys].sort(compareUtf8);
  invariant(same(actual, expected), `${label} has unknown or missing fields`);
}

function assertBytes(value, label) {
  invariant(
    Buffer.isBuffer(value) || value instanceof Uint8Array,
    `${label} must contain exact raw bytes`,
  );
}

function assertCanonicalScalarSet(values, label) {
  invariant(Array.isArray(values), `${label} must be an array`);
  const canonical = [...new Set(values)].sort(compareUtf8);
  invariant(
    same(values, canonical),
    `${label} must be a canonically ordered unique set`,
  );
}

function assertCapsecStableId(value, label) {
  invariant(
    typeof value === "string" && CAPSEC_STABLE_ID.test(value),
    `${label} is not a CapSec stable ID`,
  );
}

function assertScopeDigest(value, label) {
  invariant(
    typeof value === "string" && /^sha256-[A-Za-z0-9_-]{43}$/u.test(value),
    `${label} is not a scope digest`,
  );
}

// The amendment evolves authority v1 in place and revs attestations to v3,
// while the slice ownership table assigns neither companion schema file to
// this slice. Keep validation closed during that cross-slice handoff by
// validating an exact one-field scoped extension over the settled schemas.
// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — v3 attestations bind the admitted scope.
// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — independent promotion authority binds the same scope.
function parseScopedSchemaExtension(bytes, name, label) {
  assertBytes(bytes, label);
  const value = parseJsonStrict(bytes, label);
  const projection = structuredClone(value);
  const entries =
    name === "authority" ? projection.targets : projection.attestations;
  invariant(Array.isArray(entries), `${label} scoped entries are malformed`);
  for (const [index, entry] of entries.entries()) {
    assertScopeDigest(entry?.scopeDigest, `${label}[${index}].scopeDigest`);
    delete entry.scopeDigest;
  }
  if (name === "attestations") {
    invariant(
      projection.targetAttestationSchema ===
        PORTABLE_TARGET_ATTESTATIONS_SCHEMA,
      `${label} catalog has the wrong schema`,
    );
    projection.targetAttestationSchema = "ibex/capsec-target-attestations/2";
  }
  const { ajv, validate } = validators()[name];
  invariant(
    validate(projection),
    `${label} schema invalid: ${ajv.errorsText(validate.errors)}`,
  );
  return value;
}

function parseScopedReport(bytes, label) {
  assertBytes(bytes, label);
  const value = parseJsonStrict(bytes, label);
  assertScopeDigest(
    value?.bindings?.scopeDigest,
    `${label}.bindings.scopeDigest`,
  );
  const projection = structuredClone(value);
  delete projection.bindings.scopeDigest;
  delete projection.summary.uncertifiedCells;
  for (const cell of projection.cells ?? []) {
    if (cell.status === "uncertified") cell.status = "incomplete";
  }
  const { ajv, validate } = validators().report;
  invariant(
    validate(projection),
    `${label} schema invalid: ${ajv.errorsText(validate.errors)}`,
  );
  return value;
}

function validators() {
  if (compiledValidators) return compiledValidators;
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateSchema: true,
  });
  for (const relativePath of schemaPaths) {
    const absolutePath = path.join(repoRoot, relativePath);
    ajv.addSchema(parseJsonStrict(fs.readFileSync(absolutePath), relativePath));
  }
  compiledValidators = Object.fromEntries(
    Object.entries(schemaIds).map(([name, id]) => {
      const validate = ajv.getSchema(id);
      invariant(validate, `portable promotion schema did not compile: ${id}`);
      return [name, { ajv, validate }];
    }),
  );
  return compiledValidators;
}

function parseValidated(bytes, name, label) {
  assertBytes(bytes, label);
  const value = parseJsonStrict(bytes, label);
  const { ajv, validate } = validators()[name];
  invariant(
    validate(value),
    `${label} schema invalid: ${ajv.errorsText(validate.errors)}`,
  );
  return value;
}

export function rawContentDigest(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("base64url")}`;
}

/**
 * Validate the exact scope-member identity joins carried by a promotion
 * bundle. Scope expansion authority remains with admission; this gate checks
 * only closed shape, self-digests, companion binding, tuple, and membership.
 *
 * @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — the bundle binds one scope and both companions.
 * @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — graph validation is limited to membership/digest joins.
 */
export function validatePortableScopeBundle({
  scopeArtifactBytes,
  scopeExpansionDiffBytes,
  scopeCellMappingBytes,
  expectedTarget = null,
}) {
  const scope = parseJsonStrict(scopeArtifactBytes, "CapSec scope artifact");
  const diff = parseJsonStrict(
    scopeExpansionDiffBytes,
    "CapSec scope expansion diff",
  );
  const mapping = parseJsonStrict(
    scopeCellMappingBytes,
    "CapSec scope cell mapping",
  );
  exactKeys(
    scope,
    [
      "scopeSchema",
      "profile",
      "target",
      "intensionalDefinition",
      "expandedCellIds",
      "closureEdges",
      "predecessor",
      "scopeExpansionDiffDigest",
      "scopeCellMappingDigest",
      "scopeDigest",
    ],
    "CapSec scope artifact",
  );
  exactKeys(
    diff,
    [
      "scopeExpansionDiffSchema",
      "profile",
      "target",
      "predecessor",
      "previousExpandedCellIds",
      "currentExpandedCellIds",
      "addedCellIds",
      "retiredCellIds",
      "scopeExpansionDiffDigest",
    ],
    "CapSec scope expansion diff",
  );
  exactKeys(
    mapping,
    [
      "scopeCellMappingSchema",
      "profile",
      "target",
      "predecessor",
      "additions",
      "retirements",
      "mappings",
      "scopeCellMappingDigest",
    ],
    "CapSec scope cell mapping",
  );
  assertCanonicalScalarSet(scope.target?.features, "scope target.features");
  assertCanonicalScalarSet(scope.expandedCellIds, "scope expandedCellIds");
  assertCanonicalScalarSet(
    diff.previousExpandedCellIds,
    "scope diff previousExpandedCellIds",
  );
  assertCanonicalScalarSet(
    diff.currentExpandedCellIds,
    "scope diff currentExpandedCellIds",
  );
  assertCanonicalScalarSet(diff.addedCellIds, "scope diff addedCellIds");
  assertCanonicalScalarSet(diff.retiredCellIds, "scope diff retiredCellIds");
  assertCanonicalScalarSet(mapping.additions, "scope mapping additions");
  assertCanonicalScalarSet(mapping.retirements, "scope mapping retirements");
  for (const [value, label] of [
    [scope.scopeDigest, "scope.scopeDigest"],
    [scope.scopeExpansionDiffDigest, "scope.scopeExpansionDiffDigest"],
    [scope.scopeCellMappingDigest, "scope.scopeCellMappingDigest"],
    [diff.scopeExpansionDiffDigest, "diff.scopeExpansionDiffDigest"],
    [mapping.scopeCellMappingDigest, "mapping.scopeCellMappingDigest"],
  ]) {
    assertScopeDigest(value, label);
  }
  invariant(
    scope.scopeSchema === CAPSEC_SCOPE_SCHEMA &&
      diff.scopeExpansionDiffSchema === CAPSEC_SCOPE_EXPANSION_DIFF_SCHEMA &&
      mapping.scopeCellMappingSchema === CAPSEC_SCOPE_CELL_MAPPING_SCHEMA &&
      scope.profile === "ibex/capsec/1" &&
      diff.profile === scope.profile &&
      mapping.profile === scope.profile &&
      scope.expandedCellIds.length > 0 &&
      Array.isArray(scope.closureEdges) &&
      Array.isArray(mapping.mappings) &&
      same(diff.target, scope.target) &&
      same(mapping.target, scope.target) &&
      same(diff.predecessor, scope.predecessor) &&
      same(mapping.predecessor, scope.predecessor) &&
      same(diff.currentExpandedCellIds, scope.expandedCellIds) &&
      same(mapping.additions, diff.addedCellIds) &&
      same(mapping.retirements, diff.retiredCellIds) &&
      (expectedTarget === null || same(scope.target, expectedTarget)),
    "CapSec scope members differ in schema, profile, tuple, predecessor, or expansion",
  );
  invariant(
    diff.scopeExpansionDiffDigest ===
      computeDomainDigest(CAPSEC_SCOPE_EXPANSION_DIFF_DOMAIN, diff, [
        "scopeExpansionDiffDigest",
      ]) &&
      mapping.scopeCellMappingDigest ===
        computeDomainDigest(CAPSEC_SCOPE_CELL_MAPPING_DOMAIN, mapping, [
          "scopeCellMappingDigest",
        ]) &&
      scope.scopeExpansionDiffDigest === diff.scopeExpansionDiffDigest &&
      scope.scopeCellMappingDigest === mapping.scopeCellMappingDigest &&
      scope.scopeDigest ===
        computeDomainDigest(CAPSEC_SCOPE_DOMAIN, scope, ["scopeDigest"]),
    "CapSec scope or companion digest mismatch",
  );
  return { scope, diff, mapping };
}

export function mappedEngineExecutionEvidenceDigest(evidence) {
  return computeDomainDigest(
    MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN,
    evidence,
    ["evidenceDigest"],
  );
}

export function portableFixtureEvidenceDigest(evidence) {
  return computeDomainDigest(PORTABLE_FIXTURE_EVIDENCE_DOMAIN, evidence, [
    "artifactDigest",
  ]);
}

export function portableExecutionBindingDigest(bindings) {
  return computeDomainDigest(PORTABLE_EXECUTION_BINDING_DOMAIN, {
    sourceRevision: bindings.sourceRevision,
    sourceTreeDigest: bindings.sourceTreeDigest,
    conformanceRunner: bindings.conformanceRunner,
    target: bindings.target,
    engine: bindings.engine,
    vocabularyDigest: bindings.vocabularyDigest,
    registryDigest: bindings.registryDigest,
    implementationManifestDigest: bindings.implementationManifestDigest,
    fixtureCatalogDigest: bindings.fixtureCatalogDigest,
    targetCellsRawContentDigest: bindings.targetCellsRawContentDigest,
    recipeCatalogDigest: bindings.recipeCatalogDigest,
    recipeCatalogRawContentDigest: bindings.recipeCatalogRawContentDigest,
    publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
    publicSurfaceExecutionRawContentDigest:
      bindings.publicSurfaceExecutionRawContentDigest,
    outputDispositionEvidenceRawContentDigest:
      bindings.outputDispositionEvidenceRawContentDigest,
  });
}

// M28 transitivity rule: execution-plan bindings remain closed and carry no
// direct scopeDigest. Their existing recipeCatalogDigest instead commits the
// independently recomputed scope digest through this scoped digest envelope.
// @ref LLP 0021#amendment-scoped-advertisement-2026-08-06 — M28 permits transitive scope carriage only when reachability is machine-checked.
export function portableRecipeCatalogDigest(catalog, scopeDigest) {
  assertScopeDigest(scopeDigest, "portable recipe catalog scopeDigest");
  const catalogWithoutSelfDigest = structuredClone(catalog);
  delete catalogWithoutSelfDigest.recipeCatalogDigest;
  return computeDomainDigest(PORTABLE_RECIPE_CATALOG_DOMAIN, {
    scopeDigest,
    recipeCatalog: catalogWithoutSelfDigest,
  });
}

export function assertPortableExecutionBindingScopeReachable({
  bindingDigest,
  bindings,
  recipeCatalog,
  scopeArtifact,
}) {
  const recomputedScopeDigest = computeDomainDigest(
    CAPSEC_SCOPE_DOMAIN,
    scopeArtifact,
    ["scopeDigest"],
  );
  invariant(
    scopeArtifact?.scopeSchema === CAPSEC_SCOPE_SCHEMA &&
      scopeArtifact.scopeDigest === recomputedScopeDigest &&
      recipeCatalog?.recipeCatalogDigest ===
        portableRecipeCatalogDigest(recipeCatalog, recomputedScopeDigest) &&
      bindings?.recipeCatalogDigest === recipeCatalog.recipeCatalogDigest &&
      bindingDigest === portableExecutionBindingDigest(bindings),
    "scope artifact is not digest-reachable from the portable execution binding",
  );
  return true;
}

export function portableRecipePlanDigest(recipe) {
  return computeDomainDigest(PORTABLE_RECIPE_PLAN_DOMAIN, {
    fixtureId: recipe.fixtureId,
    status: recipe.status,
    executor: recipe.executor,
  });
}

export function portablePublicSurfaceExecutionDigest(artifact) {
  return computeDomainDigest(
    PORTABLE_PUBLIC_SURFACE_EXECUTION_DOMAIN,
    artifact,
    ["publicSurfaceExecutionDigest"],
  );
}

export function portablePublicSurfaceExecutionEvidenceDigest(execution) {
  return computeDomainDigest(
    PORTABLE_PUBLIC_SURFACE_EXECUTION_EVIDENCE_DOMAIN,
    {
      fixtureId: execution.fixtureId,
      outcome: execution.outcome,
      executor: execution.executor,
    },
  );
}

export function portableOutputDispositionObservationDigest(observation) {
  return computeDomainDigest(
    PORTABLE_OUTPUT_DISPOSITION_OBSERVATION_DOMAIN,
    observation,
    ["observationDigest"],
  );
}

export function portableConformanceDigest(report) {
  return computeDomainDigest(PORTABLE_CONFORMANCE_DOMAIN, report, [
    "conformanceDigest",
  ]);
}

export function commandAttemptDigest(attempt) {
  return computeDomainDigest(COMMAND_ATTEMPT_DOMAIN, attempt, [
    "attemptDigest",
  ]);
}

function decodedStringVariants(value) {
  const variants = [value];
  let current = value;
  for (let index = 0; index < 3; index += 1) {
    const byteDecoded = current.replace(/%([0-9a-f]{2})/giu, (_match, hex) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
    if (byteDecoded !== current && !variants.includes(byteDecoded)) {
      variants.push(byteDecoded);
    }
    try {
      const decoded = decodeURIComponent(current);
      const next = decoded === current ? byteDecoded : decoded;
      if (next === current) break;
      if (!variants.includes(next)) variants.push(next);
      current = next;
    } catch {
      if (byteDecoded === current) break;
      current = byteDecoded;
    }
  }
  return variants;
}

function looksHostLocal(value) {
  return decodedStringVariants(value).some((candidate) => {
    const text = candidate.trim();
    return (
      /(?:^|[\s"'(=])file:\/\//iu.test(text) ||
      /(?:^|[\s"'(=])\/(?!\/)[^\s]/u.test(text) ||
      /(?:^|[\s"'(=])[A-Za-z]:[\\/]/u.test(text) ||
      /(?:^|[\s"'(=])\\\\[^\\]/u.test(text) ||
      /(?:^|[\s"'(=])0x[0-9a-f]+(?:$|[\s"'),;])/iu.test(text) ||
      /(?:^|[\s"'(=])(?:dev|file|ino|inode|volume):/iu.test(text)
    );
  });
}

function assertNoPublishedLocality(value, label = "$") {
  if (typeof value === "string") {
    invariant(
      !looksHostLocal(value),
      `${label} contains a host-local path, URI, address, or object identity`,
    );
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertNoPublishedLocality(item, `${label}[${index}]`),
    );
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      invariant(
        !FORBIDDEN_PUBLICATION_KEYS.has(key.toLowerCase()),
        `${label}.${key} is a mapped/local engine field`,
      );
      assertNoPublishedLocality(child, `${label}.${key}`);
    }
  }
}

function targetFamily(triple) {
  const matching = Object.entries(FAMILY_TRIPLE_PATTERNS).filter(
    ([, pattern]) => pattern.test(triple),
  );
  invariant(
    matching.length === 1,
    `unsupported or ambiguous target family: ${triple}`,
  );
  return matching[0][0];
}

function assertCanonicalEvidenceReferences(references, label) {
  invariant(
    Array.isArray(references) && references.length > 0,
    `${label} is empty`,
  );
  const canonical = [...references].sort((left, right) =>
    compareUtf8(
      canonicalJson([
        left.evidenceDigest,
        left.rawContentDigest,
        left.attemptDigest,
        left.attemptRawContentDigest,
      ]),
      canonicalJson([
        right.evidenceDigest,
        right.rawContentDigest,
        right.attemptDigest,
        right.attemptRawContentDigest,
      ]),
    ),
  );
  invariant(same(references, canonical), `${label} is not canonically ordered`);
  invariant(
    new Set(references.map((reference) => reference.evidenceDigest)).size ===
      references.length,
    `${label} repeats an evidence digest`,
  );
  invariant(
    new Set(references.map((reference) => reference.rawContentDigest)).size ===
      references.length,
    `${label} repeats a raw-content digest`,
  );
  invariant(
    new Set(references.map((reference) => reference.attemptDigest)).size ===
      references.length,
    `${label} repeats an attempt digest`,
  );
  invariant(
    new Set(references.map((reference) => reference.attemptRawContentDigest))
      .size === references.length,
    `${label} repeats an attempt raw-content digest`,
  );
}

function validateAuthority(authority) {
  invariant(
    authority.portablePromotionAuthoritySchema ===
      PORTABLE_PROMOTION_AUTHORITY_SCHEMA,
    "portable promotion authority has the wrong schema",
  );
  assertNoPublishedLocality(authority, "authority");
  const targetKeys = [];
  for (const [index, entry] of authority.targets.entries()) {
    const label = `authority.targets[${index}]`;
    validateConformanceRunnerBinding(entry.conformanceRunner, {
      sourceRevision: authority.sourceRevision,
      sourceTreeDigest: authority.sourceTreeDigest,
    });
    assertCanonicalScalarSet(entry.target.features, `${label}.target.features`);
    assertCanonicalScalarSet(
      entry.engine.target.structuralFeatures,
      `${label}.engine.target.structuralFeatures`,
    );
    invariant(
      targetFamily(entry.target.triple) === entry.family,
      `${label} has the wrong exact target-family dispatch`,
    );
    invariant(
      entry.engine.target.triple === entry.target.triple,
      `${label} portable engine target differs from its CapSec target`,
    );
    invariant(
      entry.conformanceRunner.artifactId === entry.engine.artifactId,
      `${label} conformance runner names another portable engine artifact`,
    );
    targetKeys.push(canonicalJson(entry.target));
  }
  assertCanonicalScalarSet(targetKeys, "authority target keys");
  return authority;
}

function authorityForReport(authority, report) {
  const targetKey = canonicalJson(report.bindings.target);
  const matches = authority.targets.filter(
    (entry) => canonicalJson(entry.target) === targetKey,
  );
  invariant(
    matches.length === 1,
    "report has no unique independently derived target authority",
  );
  const [entry] = matches;
  const bindings = report.bindings;
  invariant(
    authority.sourceRevision === bindings.sourceRevision &&
      authority.sourceTreeDigest === bindings.sourceTreeDigest &&
      same(entry.engine, bindings.engine) &&
      same(entry.conformanceRunner, bindings.conformanceRunner) &&
      entry.vocabularyDigest === bindings.vocabularyDigest &&
      entry.registryDigest === bindings.registryDigest &&
      entry.implementationManifestDigest ===
        bindings.implementationManifestDigest &&
      entry.fixtureCatalogDigest === bindings.fixtureCatalogDigest &&
      entry.scopeDigest === bindings.scopeDigest &&
      entry.targetCellsRawContentDigest ===
        bindings.targetCellsRawContentDigest &&
      entry.recipeCatalogDigest === bindings.recipeCatalogDigest &&
      entry.recipeCatalogRawContentDigest ===
        bindings.recipeCatalogRawContentDigest &&
      entry.publicSurfaceExecutionDigest ===
        bindings.publicSurfaceExecutionDigest &&
      entry.publicSurfaceExecutionRawContentDigest ===
        bindings.publicSurfaceExecutionRawContentDigest &&
      entry.outputDispositionEvidenceRawContentDigest ===
        bindings.outputDispositionEvidenceRawContentDigest,
    "report differs from independently derived source, target, engine, or artifact authority",
  );
  return entry;
}

function validateMappedEvidence(evidence, authorityEntry, authority) {
  invariant(
    evidence.mappedEngineExecutionEvidenceSchema ===
      MAPPED_ENGINE_EXECUTION_EVIDENCE_SCHEMA,
    "mapped-engine execution evidence has the wrong schema",
  );
  invariant(
    evidence.authorityClass === "same-runner-authoritative",
    "mapped-engine execution evidence is not same-runner authoritative",
  );
  assertCapsecStableId(evidence.phaseId, "mapped evidence phaseId");
  assertCapsecStableId(evidence.commandId, "mapped evidence commandId");
  assertCanonicalScalarSet(
    evidence.target.features,
    "mapped evidence target.features",
  );
  assertCanonicalScalarSet(
    evidence.engine.target.structuralFeatures,
    "mapped evidence engine.target.structuralFeatures",
  );
  assertCanonicalScalarSet(evidence.fixtureIds, "mapped evidence fixtureIds");
  assertCanonicalScalarSet(
    evidence.outputDigests,
    "mapped evidence outputDigests",
  );
  invariant(
    evidence.sourceRevision === authority.sourceRevision &&
      evidence.sourceTreeDigest === authority.sourceTreeDigest &&
      same(evidence.target, authorityEntry.target) &&
      same(evidence.engine, authorityEntry.engine),
    "mapped evidence differs from independently derived portable authority",
  );
  const family = targetFamily(evidence.target.triple);
  invariant(
    family === authorityEntry.family,
    "mapped evidence has the wrong exact target-family dispatch",
  );

  const mapped = evidence.mappedEngine;
  invariant(
    same(mapped.portable, evidence.engine),
    "mapped engine does not carry the complete portable engine identity",
  );
  invariant(
    same(mapped.before.object, mapped.localObject) &&
      same(mapped.after.object, mapped.localObject),
    "mapped before/after observations do not identify the retained local object",
  );
  invariant(
    mapped.before.digest === evidence.engine.runtimeComponentDigest &&
      mapped.after.digest === evidence.engine.runtimeComponentDigest,
    "mapped before/after bytes do not match the portable runtime component",
  );
  invariant(
    mapped.before.size === mapped.after.size,
    "mapped runtime size changed during the evidence interval",
  );
  invariant(
    mapped.processArchitecture === evidence.target.triple.split("-")[0],
    "mapped process architecture does not match the target",
  );
  invariant(
    mapped.observationDigest ===
      computeDomainDigest("ibex.mapped-engine-instance-identity.v1", mapped, [
        "observationDigest",
      ]),
    "mapped-engine instance observation digest mismatch",
  );

  const proof = mapped.mappingProof;
  const observation = proof.platformObservation;
  if (family === "macos") {
    invariant(
      proof.class === "macos-proc-pid-region-path-info" &&
        observation.platform === "macos" &&
        same(observation.mappedObject, mapped.localObject),
      "macOS evidence does not contain the admitted mapped-region object proof",
    );
  } else if (family === "windows") {
    invariant(
      proof.class === "windows-locked-module-closure" &&
        observation.platform === "windows" &&
        same(observation.runtimeModule.object, mapped.localObject),
      "Windows evidence does not contain the admitted locked-module proof",
    );
  } else {
    invariant(
      proof.class === "linux-proc-self-maps" &&
        observation.platform === "linux" &&
        same(observation.mappedObject, mapped.localObject),
      "Linux evidence does not contain the admitted mapped-region object proof",
    );
  }
  invariant(
    evidence.evidenceDigest === mappedEngineExecutionEvidenceDigest(evidence),
    "mapped-engine execution evidence digest mismatch",
  );
}

function validateAttempt(attempt, evidence, authorityEntry) {
  invariant(
    attempt.attemptDigest === commandAttemptDigest(attempt),
    "supervisor command-attempt digest mismatch",
  );
  invariant(
    attempt.classification === "success" &&
      attempt.exitCode === 0 &&
      attempt.cleanup.cleanupProven === true,
    "mapped evidence requires one successful, clean supervisor attempt",
  );
  invariant(
    attempt.commandId === evidence.commandId &&
      attempt.phase === evidence.phaseId &&
      attempt.commandIdentity === evidence.commandIdentityDigest,
    "mapped evidence command binding differs from the current supervisor attempt",
  );
  const runnerInputs = attempt.declaredInputs.filter(
    (input) => input.name === "conformanceRunner",
  );
  invariant(
    runnerInputs.length === 1 &&
      runnerInputs[0].digest ===
        conformanceRunnerBindingDigest(authorityEntry.conformanceRunner),
    "selected-runner process lacks the exact conformance-runner declared-input identity",
  );
  const paths = attempt.outputs.map((output) => output.path);
  const digests = attempt.outputs.map((output) => output.digest);
  invariant(
    new Set(paths).size === paths.length,
    "supervisor attempt repeats an output path",
  );
  invariant(
    new Set(digests).size === digests.length,
    "supervisor attempt has ambiguous equal-digest output rows",
  );
}

function validateFixtureArtifact(
  fixture,
  evidence,
  reportExecution,
  reportBindings,
  authorityEntry,
) {
  invariant(
    fixture.fixtureEvidenceSchema === PORTABLE_FIXTURE_EVIDENCE_SCHEMA &&
      fixture.artifactDigest === portableFixtureEvidenceDigest(fixture),
    `${reportExecution.fixtureId}: detached fixture artifact digest mismatch`,
  );
  invariant(
    fixture.sourceRevision === evidence.sourceRevision &&
      fixture.sourceTreeDigest === evidence.sourceTreeDigest &&
      same(fixture.target, evidence.target) &&
      same(fixture.engine, evidence.engine) &&
      targetFamily(fixture.target.triple) === authorityEntry.family,
    `${reportExecution.fixtureId}: fixture artifact differs from portable process bindings`,
  );
  const expectedBindingDigest = portableExecutionBindingDigest(reportBindings);
  invariant(
    fixture.fixtureId === reportExecution.fixtureId &&
      fixture.outcome === reportExecution.outcome &&
      fixture.executor === reportExecution.executor &&
      fixture.bindingDigest === reportExecution.bindingDigest &&
      fixture.bindingDigest === expectedBindingDigest &&
      fixture.artifactDigest === reportExecution.artifactDigest,
    `${reportExecution.fixtureId}: report execution differs from its detached fixture artifact`,
  );
}

function validateProcessRecord({
  process,
  reference,
  report,
  authorityEntry,
  authority,
}) {
  exactKeys(
    process,
    ["mappedEvidenceBytes", "commandAttemptBytes", "outputArtifactBytes"],
    "detached process record",
  );
  invariant(
    Array.isArray(process.outputArtifactBytes),
    "detached process outputs must be an array",
  );
  const evidence = parseValidated(
    process.mappedEvidenceBytes,
    "evidence",
    "detached mapped-engine evidence",
  );
  invariant(
    evidence.evidenceDigest === reference.evidenceDigest &&
      rawContentDigest(process.mappedEvidenceBytes) ===
        reference.rawContentDigest,
    "detached mapped-engine evidence does not match the report reference",
  );
  validateMappedEvidence(evidence, authorityEntry, authority);

  const attempt = parseValidated(
    process.commandAttemptBytes,
    "attempt",
    `${evidence.commandId} supervisor attempt`,
  );
  validateAttempt(attempt, evidence, authorityEntry);
  invariant(
    attempt.attemptDigest === reference.attemptDigest &&
      rawContentDigest(process.commandAttemptBytes) ===
        reference.attemptRawContentDigest,
    "finalized supervisor attempt does not match the report reference",
  );
  const mappedOutputRows = attempt.outputs.filter(
    (output) =>
      output.digest === reference.rawContentDigest &&
      output.bytes === process.mappedEvidenceBytes.byteLength,
  );
  invariant(
    mappedOutputRows.length === 1,
    "supervisor attempt must contain exactly one mapped-evidence output row",
  );
  const mappedOutputPath = mappedOutputRows[0].path;
  const otherOutputs = attempt.outputs.filter(
    (output) => output.path !== mappedOutputPath,
  );
  const expectedOutputDigests = otherOutputs
    .map((output) => output.digest)
    .sort(compareUtf8);
  invariant(
    same(evidence.outputDigests, expectedOutputDigests),
    "mapped evidence outputDigests differ from the exact supervisor output rows",
  );
  invariant(
    process.outputArtifactBytes.length === otherOutputs.length,
    "detached output artifact membership differs from the supervisor attempt",
  );

  const outputByDigest = new Map();
  for (const [index, bytes] of process.outputArtifactBytes.entries()) {
    assertBytes(bytes, `detached output artifact ${index}`);
    const digest = rawContentDigest(bytes);
    const outputRows = otherOutputs.filter(
      (output) => output.digest === digest && output.bytes === bytes.byteLength,
    );
    invariant(
      outputRows.length === 1,
      "detached output bytes do not match one exact supervisor output row",
    );
    invariant(
      !outputByDigest.has(digest),
      "detached output artifacts repeat a raw digest",
    );
    outputByDigest.set(digest, bytes);
  }

  const reportExecutions = report.executions.filter(
    (execution) =>
      execution.mappedEngineExecutionEvidenceDigest === evidence.evidenceDigest,
  );
  invariant(
    reportExecutions.length === otherOutputs.length,
    "mapped process output rows do not correspond one-for-one with report executions",
  );
  const fixtureIds = [];
  for (const execution of reportExecutions) {
    const bytes = outputByDigest.get(execution.rawContentDigest);
    invariant(
      bytes,
      `${execution.fixtureId}: report raw digest is not a supervisor output`,
    );
    const fixture = parseValidated(
      bytes,
      "fixture",
      `${execution.fixtureId} detached fixture artifact`,
    );
    validateFixtureArtifact(
      fixture,
      evidence,
      execution,
      report.bindings,
      authorityEntry,
    );
    fixtureIds.push(fixture.fixtureId);
  }
  fixtureIds.sort(compareUtf8);
  invariant(
    same(evidence.fixtureIds, fixtureIds),
    "mapped evidence fixtureIds differ from the exact supervisor outputs",
  );
  return { attempt, evidence };
}

function validateCompleteReport(report, mappedEvidenceReferences, scope) {
  invariant(
    report.status === "conformant",
    "only a conformant report may promote a target",
  );
  invariant(report.cells.length > 0, "conformant report has no target cells");
  const executionsByFixture = new Map();
  for (const execution of report.executions) {
    invariant(
      !executionsByFixture.has(execution.fixtureId),
      "report repeats a fixture execution",
    );
    invariant(
      execution.outcome === "passed",
      `${execution.fixtureId}: non-passing execution cannot promote`,
    );
    invariant(
      mappedEvidenceReferences.has(
        execution.mappedEngineExecutionEvidenceDigest,
      ),
      `${execution.fixtureId}: report execution references unbound mapped-engine evidence`,
    );
    executionsByFixture.set(execution.fixtureId, execution);
  }
  invariant(
    same(
      report.executions.map((execution) => execution.fixtureId),
      [...executionsByFixture.keys()].sort(compareUtf8),
    ),
    "report executions are not in canonical fixture order",
  );
  const required = new Set();
  const edgeIds = new Set();
  const inScope = new Set(scope.expandedCellIds);
  let passedRows = 0;
  for (const cell of report.cells) {
    invariant(!edgeIds.has(cell.edgeId), "report repeats an exact target cell");
    edgeIds.add(cell.edgeId);
    assertCanonicalScalarSet(
      cell.implementationBranchIds,
      `${cell.edgeId}.implementationBranchIds`,
    );
    assertCanonicalScalarSet(
      cell.enforcementBranchIds,
      `${cell.edgeId}.enforcementBranchIds`,
    );
    assertCanonicalScalarSet(
      cell.requiredFixtures,
      `${cell.edgeId}.requiredFixtures`,
    );
    assertCanonicalScalarSet(
      cell.passedFixtures,
      `${cell.edgeId}.passedFixtures`,
    );
    assertCanonicalScalarSet(
      cell.missingFixtures,
      `${cell.edgeId}.missingFixtures`,
    );
    assertCanonicalScalarSet(
      cell.failedFixtures,
      `${cell.edgeId}.failedFixtures`,
    );
    invariant(
      cell.missingFixtures.length === 0 && cell.failedFixtures.length === 0,
      `${cell.edgeId}: failed or missing fixture cannot promote`,
    );
    if (inScope.has(cell.edgeId)) {
      invariant(
        cell.status === "conformant" &&
          same(cell.passedFixtures, cell.requiredFixtures),
        `${cell.edgeId}: in-scope cell is not conformant`,
      );
      for (const fixtureId of cell.requiredFixtures) {
        required.add(fixtureId);
        invariant(
          executionsByFixture.has(fixtureId),
          `${cell.edgeId}: required in-scope fixture has no execution`,
        );
      }
      passedRows += cell.passedFixtures.length;
    } else {
      invariant(
        cell.status === "uncertified" && cell.passedFixtures.length === 0,
        `${cell.edgeId}: out-of-scope cell contributes authoritative evidence`,
      );
    }
  }
  invariant(
    inScope.size > 0 &&
      inScope.size <= edgeIds.size &&
      [...inScope].every((edgeId) => edgeIds.has(edgeId)),
    "scope expansion differs from report cell membership",
  );
  const executionIds = [...executionsByFixture.keys()].sort(compareUtf8);
  const requiredIds = [...required].sort(compareUtf8);
  invariant(
    same(executionIds, requiredIds),
    "report executions differ from exact required fixture membership",
  );
  invariant(
    report.summary.cells === report.cells.length &&
      report.summary.conformantCells === inScope.size &&
      report.summary.incompleteCells === 0 &&
      report.summary.uncertifiedCells === report.cells.length - inScope.size &&
      report.summary.requiredFixtures === required.size &&
      report.summary.passedFixtures === required.size &&
      report.summary.missingFixtures === 0 &&
      report.summary.failedFixtures === 0 &&
      passedRows >= required.size,
    "conformance summary does not prove complete passing membership",
  );
  invariant(
    report.conformanceDigest === portableConformanceDigest(report),
    "portable conformance report digest mismatch",
  );
}

function validateTargetCells(
  targetCells,
  targetCellsBytes,
  report,
  authorityEntry,
  advertisements,
  scope,
) {
  invariant(
    rawContentDigest(targetCellsBytes) ===
      authorityEntry.targetCellsRawContentDigest &&
      report.bindings.targetCellsRawContentDigest ===
        authorityEntry.targetCellsRawContentDigest &&
      advertisements.targetCellsRawContentDigest ===
        authorityEntry.targetCellsRawContentDigest,
    "target-cell raw bytes differ from independent authority or advertisement",
  );
  const targetKey = canonicalJson(authorityEntry.target);
  const rows = targetCells.cells.filter(
    (cell) => canonicalJson(cell.target) === targetKey,
  );
  invariant(
    rows.length === report.cells.length,
    "target-cell catalog membership differs from the report",
  );
  invariant(
    same(
      rows.map((row) => row.edgeId),
      report.cells.map((cell) => cell.edgeId),
    ),
    "target-cell catalog order or exact edge membership differs from the report",
  );
  const rowByEdge = new Map();
  for (const row of rows) {
    invariant(
      !rowByEdge.has(row.edgeId),
      "target-cell catalog repeats an exact target edge",
    );
    rowByEdge.set(row.edgeId, row);
  }
  const inScope = new Set(scope.expandedCellIds);
  invariant(
    scope.expandedCellIds.every((edgeId) => rowByEdge.has(edgeId)),
    "scope expansion names a non-inventory target cell",
  );
  for (const cell of report.cells) {
    const row = rowByEdge.get(cell.edgeId);
    invariant(
      row &&
        (inScope.has(cell.edgeId)
          ? row.disposition !== "unsupported"
          : row.disposition === "unsupported") &&
        same(row.implementationBranchIds, cell.implementationBranchIds) &&
        same(
          row.fixtures,
          inScope.has(cell.edgeId) ? cell.requiredFixtures : [],
        ),
      `${cell.edgeId}: report cell differs from the exact target-cell catalog`,
    );
  }
}

function validateRecipeCatalog(bytes, report, authorityEntry, scope) {
  const recipeCatalog = parseValidated(
    bytes,
    "recipe",
    "independent recipe catalog",
  );
  const rawDigest = rawContentDigest(bytes);
  invariant(
    recipeCatalog.recipeCatalogSchema === "ibex/capsec-executable-recipes/2" &&
      recipeCatalog.profile === "ibex/capsec/1" &&
      same(recipeCatalog.target, authorityEntry.target) &&
      targetFamily(recipeCatalog.target.triple) === authorityEntry.family &&
      recipeCatalog.recipeCatalogDigest ===
        portableRecipeCatalogDigest(recipeCatalog, scope.scopeDigest),
    "recipe catalog semantic identity is invalid",
  );
  const fixtureIds = recipeCatalog.recipes.map((recipe) => recipe.fixtureId);
  fixtureIds.forEach((fixtureId, index) =>
    assertCapsecStableId(
      fixtureId,
      `recipeCatalog.recipes[${index}].fixtureId`,
    ),
  );
  assertCanonicalScalarSet(fixtureIds, "recipe catalog fixture IDs");
  const required = [
    ...new Set(
      report.cells
        .filter((cell) => scope.expandedCellIds.includes(cell.edgeId))
        .flatMap((cell) => cell.requiredFixtures),
    ),
  ].sort(compareUtf8);
  invariant(
    same(fixtureIds, required),
    "recipe catalog differs from exact required fixture membership",
  );
  const reportExecutions = new Map(
    report.executions.map((execution) => [execution.fixtureId, execution]),
  );
  const fullyExecutable = recipeCatalog.recipes.filter(
    (recipe) => recipe.status === "fully-executable",
  );
  const internallyVerified = recipeCatalog.recipes.filter(
    (recipe) => recipe.status === "internally-verified",
  );
  invariant(
    recipeCatalog.recipes.every((recipe) => {
      const statusAndExecutor =
        recipe.status === "fully-executable" ||
        (recipe.status === "internally-verified" &&
          recipe.executor === INTERNAL_INVARIANT_EXECUTOR);
      return (
        statusAndExecutor &&
        recipe.planDigest === portableRecipePlanDigest(recipe) &&
        recipe.executor === reportExecutions.get(recipe.fixtureId)?.executor
      );
    }) &&
      recipeCatalog.summary.requiredFixtures === required.length &&
      recipeCatalog.summary.fullyExecutableFixtures ===
        fullyExecutable.length &&
      recipeCatalog.summary.internallyVerifiedFixtures ===
        internallyVerified.length &&
      recipeCatalog.summary.unresolvedFixtures === 0,
    "recipe catalog does not bind every required fixture to a reviewed executor",
  );
  invariant(
    recipeCatalog.recipeCatalogDigest === authorityEntry.recipeCatalogDigest &&
      recipeCatalog.recipeCatalogDigest ===
        report.bindings.recipeCatalogDigest &&
      rawDigest === authorityEntry.recipeCatalogRawContentDigest &&
      rawDigest === report.bindings.recipeCatalogRawContentDigest,
    "recipe catalog raw or semantic identity differs from independent authority",
  );
  return recipeCatalog;
}

function validatePublicSurfaceExecution(bytes, report, authorityEntry) {
  const artifact = parseValidated(
    bytes,
    "publicSurface",
    "independent public-surface execution",
  );
  const rawDigest = rawContentDigest(bytes);
  invariant(
    artifact.publicSurfaceExecutionSchema ===
      "ibex/capsec-public-surface-executions/2" &&
      artifact.profile === "ibex/capsec/1" &&
      artifact.sourceRevision === report.bindings.sourceRevision &&
      artifact.sourceTreeDigest === report.bindings.sourceTreeDigest &&
      same(artifact.target, authorityEntry.target) &&
      targetFamily(artifact.target.triple) === authorityEntry.family &&
      same(artifact.engine, authorityEntry.engine) &&
      artifact.recipeCatalogDigest === authorityEntry.recipeCatalogDigest &&
      artifact.recipeCatalogDigest === report.bindings.recipeCatalogDigest &&
      artifact.recipeCatalogRawContentDigest ===
        authorityEntry.recipeCatalogRawContentDigest &&
      artifact.recipeCatalogRawContentDigest ===
        report.bindings.recipeCatalogRawContentDigest &&
      artifact.publicSurfaceExecutionDigest ===
        portablePublicSurfaceExecutionDigest(artifact),
    "public-surface execution semantic identity is invalid",
  );
  const fixtureIds = artifact.executions.map(
    (execution) => execution.fixtureId,
  );
  fixtureIds.forEach((fixtureId, index) =>
    assertCapsecStableId(
      fixtureId,
      `publicSurfaceExecution.executions[${index}].fixtureId`,
    ),
  );
  assertCanonicalScalarSet(fixtureIds, "public-surface execution fixture IDs");
  const required = [
    ...new Set(report.executions.map((execution) => execution.fixtureId)),
  ].sort(compareUtf8);
  const reportExecutions = new Map(
    report.executions.map((execution) => [execution.fixtureId, execution]),
  );
  const publicRequired = report.executions
    .filter((execution) => execution.executor !== INTERNAL_INVARIANT_EXECUTOR)
    .map((execution) => execution.fixtureId)
    .sort(compareUtf8);
  const internalRequiredCount = required.length - publicRequired.length;
  invariant(
    same(fixtureIds, publicRequired) &&
      artifact.executions.every((execution) => {
        const reportExecution = reportExecutions.get(execution.fixtureId);
        return (
          reportExecution &&
          execution.outcome === "passed" &&
          execution.outcome === reportExecution.outcome &&
          execution.executor === reportExecution.executor &&
          execution.evidenceDigest ===
            portablePublicSurfaceExecutionEvidenceDigest(execution)
        );
      }) &&
      artifact.summary.requiredFixtures === required.length &&
      artifact.summary.executableFixtures === publicRequired.length &&
      artifact.summary.internallyVerifiedFixtures === internalRequiredCount &&
      artifact.summary.residualFixtures === 0 &&
      artifact.summary.executedFixtures === publicRequired.length &&
      artifact.summary.passedFixtures === publicRequired.length &&
      artifact.summary.failedFixtures === 0 &&
      artifact.summary.missingFixtures === internalRequiredCount,
    "public-surface execution does not prove every public fixture passed",
  );
  invariant(
    artifact.publicSurfaceExecutionDigest ===
      authorityEntry.publicSurfaceExecutionDigest &&
      artifact.publicSurfaceExecutionDigest ===
        report.bindings.publicSurfaceExecutionDigest &&
      rawDigest === authorityEntry.publicSurfaceExecutionRawContentDigest &&
      rawDigest === report.bindings.publicSurfaceExecutionRawContentDigest,
    "public-surface raw or semantic identity differs from independent authority",
  );
  return artifact;
}

function validateOutputDispositionEvidence(bytes, report, authorityEntry) {
  const artifact = parseValidated(
    bytes,
    "outputDisposition",
    "independent output-disposition evidence",
  );
  const rawDigest = rawContentDigest(bytes);
  invariant(
    artifact.outputDispositionEvidenceSchema ===
      "ibex/capsec-output-disposition-evidence/4" &&
      artifact.profile === "ibex/capsec/1" &&
      artifact.status === "verified" &&
      artifact.sourceRevision === report.bindings.sourceRevision &&
      artifact.sourceTreeDigest === report.bindings.sourceTreeDigest &&
      same(artifact.conformanceRunner, authorityEntry.conformanceRunner) &&
      same(artifact.conformanceRunner, report.bindings.conformanceRunner) &&
      same(artifact.target, authorityEntry.target) &&
      targetFamily(artifact.target.triple) === authorityEntry.family &&
      same(artifact.engine, authorityEntry.engine),
    "output-disposition portable bindings are invalid",
  );
  const observationKeys = artifact.observations.map(
    (observation) => observation.key,
  );
  assertCanonicalScalarSet(
    observationKeys,
    "output-disposition observation keys",
  );
  invariant(
    artifact.summary.observations === artifact.observations.length &&
      artifact.observations.every(
        (observation) =>
          observation.observationDigest ===
          portableOutputDispositionObservationDigest(observation),
      ),
    "output-disposition observations are incomplete or have invalid semantic digests",
  );
  invariant(
    rawDigest === authorityEntry.outputDispositionEvidenceRawContentDigest &&
      report.bindings.outputDispositionEvidenceRawContentDigest ===
        authorityEntry.outputDispositionEvidenceRawContentDigest,
    "output-disposition raw identity differs from independent authority",
  );
  return artifact;
}

function matchingCatalogEntry(catalog, key, schema, target, label) {
  invariant(catalog[key] === schema, `${label} catalog has the wrong schema`);
  const targetKey = canonicalJson(target);
  const matches = catalog[label].filter(
    (entry) => canonicalJson(entry.target) === targetKey,
  );
  invariant(
    matches.length === 1,
    `${label} catalog requires one exact target entry`,
  );
  return matches[0];
}

function validatePublicationJoins({
  report,
  reportBytes,
  attestations,
  advertisements,
  authority,
  authorityEntry,
}) {
  assertNoPublishedLocality(report, "report");
  assertNoPublishedLocality(attestations, "attestations");
  assertNoPublishedLocality(advertisements, "advertisements");
  const attestation = matchingCatalogEntry(
    attestations,
    "targetAttestationSchema",
    PORTABLE_TARGET_ATTESTATIONS_SCHEMA,
    authorityEntry.target,
    "attestations",
  );
  const advertisement = matchingCatalogEntry(
    advertisements,
    "targetAdvertisementSchema",
    PORTABLE_TARGET_ADVERTISEMENTS_SCHEMA,
    authorityEntry.target,
    "advertisements",
  );
  const bindings = report.bindings;
  const reportRawDigest = rawContentDigest(reportBytes);
  invariant(
    same(attestation.target, authorityEntry.target) &&
      attestation.conformanceDigest === report.conformanceDigest &&
      attestation.reportRawContentDigest === reportRawDigest &&
      attestation.sourceRevision === authority.sourceRevision &&
      attestation.sourceTreeDigest === authority.sourceTreeDigest &&
      attestation.portableArtifactId === authorityEntry.engine.artifactId &&
      attestation.scopeDigest === bindings.scopeDigest &&
      attestation.scopeDigest === authorityEntry.scopeDigest &&
      same(
        attestation.mappedEngineExecutionEvidence,
        bindings.mappedEngineExecutionEvidence,
      ) &&
      attestation.recipeCatalogDigest === authorityEntry.recipeCatalogDigest &&
      attestation.recipeCatalogRawContentDigest ===
        authorityEntry.recipeCatalogRawContentDigest &&
      attestation.publicSurfaceExecutionDigest ===
        authorityEntry.publicSurfaceExecutionDigest &&
      attestation.publicSurfaceExecutionRawContentDigest ===
        authorityEntry.publicSurfaceExecutionRawContentDigest &&
      attestation.outputDispositionEvidenceRawContentDigest ===
        authorityEntry.outputDispositionEvidenceRawContentDigest,
    "portable target attestation differs from report or independent authority",
  );
  invariant(
    same(advertisement.target, authorityEntry.target) &&
      advertisement.conformanceDigest === report.conformanceDigest &&
      advertisement.reportRawContentDigest === reportRawDigest &&
      advertisement.sourceRevision === authority.sourceRevision &&
      advertisement.sourceTreeDigest === authority.sourceTreeDigest &&
      same(advertisement.engine, authorityEntry.engine) &&
      advertisement.scopeDigest === bindings.scopeDigest &&
      advertisement.scopeDigest === authorityEntry.scopeDigest &&
      same(
        advertisement.mappedEngineExecutionEvidence,
        bindings.mappedEngineExecutionEvidence,
      ) &&
      advertisement.vocabularyDigest === authorityEntry.vocabularyDigest &&
      advertisement.registryDigest === authorityEntry.registryDigest &&
      advertisement.implementationManifestDigest ===
        authorityEntry.implementationManifestDigest &&
      advertisement.fixtureCatalogDigest ===
        authorityEntry.fixtureCatalogDigest &&
      advertisement.recipeCatalogDigest ===
        authorityEntry.recipeCatalogDigest &&
      advertisement.recipeCatalogRawContentDigest ===
        authorityEntry.recipeCatalogRawContentDigest &&
      advertisement.publicSurfaceExecutionDigest ===
        authorityEntry.publicSurfaceExecutionDigest &&
      advertisement.publicSurfaceExecutionRawContentDigest ===
        authorityEntry.publicSurfaceExecutionRawContentDigest &&
      advertisement.outputDispositionEvidenceRawContentDigest ===
        authorityEntry.outputDispositionEvidenceRawContentDigest,
    "portable target advertisement differs from report or independent authority",
  );
  return { advertisement, attestation };
}

/**
 * The sole authority-bearing entry point for the additive Phase-2 contract.
 * Every structured contract arrives as exact bytes, is strict-parsed and
 * schema-validated, then is joined to independently derived authority,
 * supervisor attempts, detached output bytes, and complete report semantics.
 */
export function validatePortablePromotionV2(input) {
  exactKeys(
    input,
    [
      "authorityBytes",
      "reportBytes",
      "attestationCatalogBytes",
      "advertisementCatalogBytes",
      "targetCellsBytes",
      "recipeCatalogBytes",
      "scopeArtifactBytes",
      "scopeExpansionDiffBytes",
      "scopeCellMappingBytes",
      "publicSurfaceExecutionBytes",
      "outputDispositionEvidenceBytes",
      "processes",
    ],
    "portable promotion validation input",
  );
  invariant(
    Array.isArray(input.processes) && input.processes.length > 0,
    "portable promotion requires detached mapped evidence",
  );

  const authority = validateAuthority(
    parseScopedSchemaExtension(
      input.authorityBytes,
      "authority",
      "portable promotion authority",
    ),
  );
  const report = parseScopedReport(
    input.reportBytes,
    "portable conformance report",
  );
  const attestations = parseScopedSchemaExtension(
    input.attestationCatalogBytes,
    "attestations",
    "portable target attestations",
  );
  const advertisements = parseValidated(
    input.advertisementCatalogBytes,
    "advertisements",
    "portable target advertisements",
  );
  const targetCells = parseValidated(
    input.targetCellsBytes,
    "targetCells",
    "target-cell catalog",
  );
  invariant(
    report.conformanceSchema === PORTABLE_CONFORMANCE_SCHEMA,
    "portable conformance report has the wrong schema",
  );
  assertCanonicalScalarSet(
    report.bindings.target.features,
    "report target.features",
  );
  assertCanonicalScalarSet(
    report.bindings.engine.target.structuralFeatures,
    "report engine.target.structuralFeatures",
  );
  const authorityEntry = authorityForReport(authority, report);
  const scopeBundle = validatePortableScopeBundle({
    scopeArtifactBytes: input.scopeArtifactBytes,
    scopeExpansionDiffBytes: input.scopeExpansionDiffBytes,
    scopeCellMappingBytes: input.scopeCellMappingBytes,
    expectedTarget: authorityEntry.target,
  });
  invariant(
    scopeBundle.scope.scopeDigest === report.bindings.scopeDigest &&
      scopeBundle.scope.scopeDigest === authorityEntry.scopeDigest,
    "scope artifact differs from report or independent authority",
  );
  assertCanonicalEvidenceReferences(
    report.bindings.mappedEngineExecutionEvidence,
    "report bindings.mappedEngineExecutionEvidence",
  );
  const references = new Map(
    report.bindings.mappedEngineExecutionEvidence.map((reference) => [
      reference.evidenceDigest,
      reference,
    ]),
  );
  validateCompleteReport(report, references, scopeBundle.scope);
  invariant(
    input.processes.length === references.size,
    "detached mapped-evidence membership differs from the report",
  );
  const seenEvidence = new Set();
  const processes = [];
  for (const process of input.processes) {
    assertBytes(
      process?.mappedEvidenceBytes,
      "detached mapped-engine evidence",
    );
    const peek = parseJsonStrict(
      process.mappedEvidenceBytes,
      "detached mapped-engine evidence",
    );
    const reference = references.get(peek?.evidenceDigest);
    invariant(
      reference,
      "detached mapped-engine evidence is not referenced by the report",
    );
    invariant(
      !seenEvidence.has(reference.evidenceDigest),
      "detached mapped-engine evidence is duplicated",
    );
    seenEvidence.add(reference.evidenceDigest);
    processes.push(
      validateProcessRecord({
        process,
        reference,
        report,
        authorityEntry,
        authority,
      }),
    );
  }
  invariant(
    seenEvidence.size === references.size,
    "report references missing detached mapped-engine evidence",
  );

  validateTargetCells(
    targetCells,
    input.targetCellsBytes,
    report,
    authorityEntry,
    advertisements,
    scopeBundle.scope,
  );
  const recipeCatalog = validateRecipeCatalog(
    input.recipeCatalogBytes,
    report,
    authorityEntry,
    scopeBundle.scope,
  );
  for (const execution of report.executions) {
    assertPortableExecutionBindingScopeReachable({
      bindingDigest: execution.bindingDigest,
      bindings: report.bindings,
      recipeCatalog,
      scopeArtifact: scopeBundle.scope,
    });
  }
  const publicSurfaceExecution = validatePublicSurfaceExecution(
    input.publicSurfaceExecutionBytes,
    report,
    authorityEntry,
  );
  const outputDispositionEvidence = validateOutputDispositionEvidence(
    input.outputDispositionEvidenceBytes,
    report,
    authorityEntry,
  );
  const publication = validatePublicationJoins({
    report,
    reportBytes: input.reportBytes,
    attestations,
    advertisements,
    authority,
    authorityEntry,
  });
  return {
    ...publication,
    authorityEntry,
    outputDispositionEvidence,
    processes,
    publicSurfaceExecution,
    recipeCatalog,
    report,
    scopeArtifact: scopeBundle.scope,
    scopeCellMapping: scopeBundle.mapping,
    scopeExpansionDiff: scopeBundle.diff,
    targetCells,
  };
}
