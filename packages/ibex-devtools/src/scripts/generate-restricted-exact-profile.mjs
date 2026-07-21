/**
 * Generate the Draft LLP 0033 restricted Exact embedder projection.
 *
 * This Phase 0 authority is intentionally non-promoting: every full CapSec
 * edge is projected exactly once, but all structural/reachability evidence is
 * pending and the additive advertisement family must remain empty.
 *
 * @ref LLP 0033#5-closed-world-surface-projection — total projection with no
 * silent absorption of new full-registry edges.
 * @ref LLP 0033#8-generated-authority-and-conformance — advertisements derive
 * only from complete profile-specific evidence.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

import {
  canonicalJson,
  capsecRoot,
  parseJsonStrict,
  readJsonStrict,
  repoRoot,
} from "./capsec-contract.mjs";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";
import {
  deriveRestrictedTargetAdvertisements,
  validateRestrictedFixturePlan,
} from "./restricted-exact-target-report.mjs";

const definitionPath = path.join(
  capsecRoot,
  "registry/restricted-exact-profile-definition.json",
);
const coveragePath = path.join(capsecRoot, "registry/coverage-edges.json");
const implementationManifestPath = path.join(
  capsecRoot,
  "generated/implementation-manifest.json",
);
const definitionSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-definition.schema.json",
);
const projectionSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-projection.schema.json",
);
const advertisementSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-advertisements.schema.json",
);
const fixturePlanPath = path.join(
  capsecRoot,
  "registry/restricted-exact-fixture-plan.json",
);
const fixturePlanSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-fixture-plan.schema.json",
);
const targetAttestationsPath = path.join(
  capsecRoot,
  "conformance/restricted-exact-target-attestations.json",
);
const targetAttestationsSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-target-attestations.schema.json",
);
const targetReportSchemaPath = path.join(
  capsecRoot,
  "schema/restricted-profile-target-report.schema.json",
);
const projectionPath = path.join(
  capsecRoot,
  "generated/restricted-exact-profile-projection.json",
);
const advertisementsPath = path.join(
  capsecRoot,
  "generated/restricted-exact-target-advertisements.json",
);
const validatorCache = new Map();

function sha256(bytes) {
  return `sha256-${crypto.createHash("sha256").update(bytes).digest("base64url")}`;
}

export function restrictedEdgeSetDigest(edges) {
  return sha256(Buffer.from(canonicalJson(edges.map((edge) => edge.id).sort()), "utf8"));
}

function schemaValidator(schemaPath) {
  const cached = validatorCache.get(schemaPath);
  if (cached) return cached;
  const schema = readJsonStrict(schemaPath);
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
  validatorCache.set(schemaPath, validate);
  return validate;
}

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    throw new Error(`${label} violates schema: ${JSON.stringify(validate.errors)}`);
  }
}

function assertSortedUnique(values, label) {
  const sorted = [...values].sort();
  if (new Set(values).size !== values.length) {
    throw new Error(`${label} contains duplicates`);
  }
  if (values.some((value, index) => value !== sorted[index])) {
    throw new Error(`${label} must be sorted`);
  }
}

function bindRows(entries, disposition, edgesById) {
  assertSortedUnique(entries.map((entry) => entry.edgeId), `${disposition} edge IDs`);
  return new Map(entries.map((entry) => {
    const edge = edgesById.get(entry.edgeId);
    if (!edge) throw new Error(`${disposition} names unknown edge ${entry.edgeId}`);
    if (edge.surface?.kind !== entry.surfaceKind || edge.surface?.name !== entry.surfaceName) {
      throw new Error(
        `${disposition} identity drift for ${entry.edgeId}: expected ${entry.surfaceKind}/${entry.surfaceName}, found ${edge.surface?.kind}/${edge.surface?.name}`,
      );
    }
    return [entry.edgeId, disposition];
  }));
}

function prettyJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function renderProjection(projection) {
  const markerValue = "__RESTRICTED_PROFILE_ROWS__";
  const withMarker = { ...projection, rows: markerValue };
  const marker = `  "rows": "${markerValue}",`;
  const compactRows = [
    '  "rows": [',
    projection.rows.map((row) => `    ${JSON.stringify(row)}`).join(",\n"),
    "  ],",
  ].join("\n");
  return `${JSON.stringify(withMarker, null, 2).replace(marker, compactRows)}\n`;
}

function assertRawMatches(rawBytes, value, label) {
  if (!rawBytes) return;
  const parsed = parseJsonStrict(rawBytes, label);
  if (canonicalJson(parsed) !== canonicalJson(value)) {
    throw new Error(`${label} bytes do not match the supplied object`);
  }
}

export function buildRestrictedExactProfile({
  coverage,
  definition,
  implementationManifest,
  fixturePlan,
  targetAttestations,
  raw = {},
}) {
  assertRawMatches(raw.definition, definition, "restricted profile definition");
  assertRawMatches(raw.coverage, coverage, "restricted profile coverage");
  assertRawMatches(
    raw.implementationManifest,
    implementationManifest,
    "restricted profile implementation manifest",
  );
  assertRawMatches(raw.fixturePlan, fixturePlan, "restricted fixture plan");
  assertRawMatches(
    raw.targetAttestations,
    targetAttestations,
    "restricted target attestations",
  );
  const validateDefinition = schemaValidator(definitionSchemaPath);
  assertSchema(validateDefinition, definition, "restricted profile definition");
  validateRestrictedFixturePlan(fixturePlan);
  assertSchema(
    schemaValidator(targetAttestationsSchemaPath),
    targetAttestations,
    "restricted target attestations",
  );
  if (coverage.coverageSchema !== "ibex/capsec-coverage/1" || coverage.profile !== definition.fullProfile) {
    throw new Error("restricted profile coverage authority mismatch");
  }
  if (
    implementationManifest.implementationManifestSchema !== "ibex/capsec-implementation/1"
    || implementationManifest.profile !== definition.fullProfile
  ) {
    throw new Error("restricted profile implementation-manifest authority mismatch");
  }

  const edgeIds = coverage.edges.map((edge) => edge.id).sort();
  assertSortedUnique(edgeIds, "full coverage edge IDs");
  const actualEdgeSetDigest = restrictedEdgeSetDigest(coverage.edges);
  if (definition.sourceEdgeSet.count !== edgeIds.length) {
    throw new Error(
      `restricted profile source edge count drift: expected ${definition.sourceEdgeSet.count}, found ${edgeIds.length}`,
    );
  }
  if (definition.sourceEdgeSet.digest !== actualEdgeSetDigest) {
    throw new Error(
      `restricted profile source edge digest drift: expected ${definition.sourceEdgeSet.digest}, found ${actualEdgeSetDigest}`,
    );
  }
  const implementationEdgeIds = [...new Set(
    implementationManifest.surfaces.map((surface) => surface.edgeId),
  )].sort();
  if (canonicalJson(edgeIds) !== canonicalJson(implementationEdgeIds)) {
    throw new Error("restricted profile coverage and implementation-manifest edge sets disagree");
  }

  assertSortedUnique(
    definition.candidateTargets.map((target) => `${target.triple}\0${target.features.join("\0")}`),
    "candidate targets",
  );
  for (const target of definition.candidateTargets) {
    assertSortedUnique(target.features, `${target.triple} features`);
  }

  const edgesById = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const reachable = bindRows(definition.reachable, "reachable", edgesById);
  const control = bindRows(
    definition.trustedControlPlane,
    "trusted-control-plane",
    edgesById,
  );
  for (const edgeId of reachable.keys()) {
    if (control.has(edgeId)) throw new Error(`restricted profile disposition overlap: ${edgeId}`);
  }

  const candidateTargetKeys = new Set(
    definition.candidateTargets.map((target) => canonicalJson(target)),
  );
  assertSortedUnique(
    definition.targetDispositionOverrides.map(
      (override) => `${canonicalJson(override.target)}\0${override.edgeId}`,
    ),
    "target disposition overrides",
  );
  for (const override of definition.targetDispositionOverrides) {
    if (!candidateTargetKeys.has(canonicalJson(override.target))) {
      throw new Error(`target disposition override names non-candidate ${override.target.triple}`);
    }
    const edge = edgesById.get(override.edgeId);
    if (!edge) throw new Error(`target disposition override names unknown edge ${override.edgeId}`);
    if (
      edge.surface?.kind !== override.surfaceKind
      || edge.surface?.name !== override.surfaceName
    ) {
      throw new Error(`target disposition override identity drift for ${override.edgeId}`);
    }
    const defaultDisposition = reachable.get(override.edgeId)
      ?? control.get(override.edgeId)
      ?? definition.structuralAbsencePolicy.complementDisposition;
    if (override.disposition === defaultDisposition) {
      throw new Error(`target disposition override is redundant for ${override.edgeId}`);
    }
  }

  const rows = edgeIds.map((edgeId) => {
    const disposition = reachable.get(edgeId)
      ?? control.get(edgeId)
      ?? definition.structuralAbsencePolicy.complementDisposition;
    return [edgeId, disposition, "pending"];
  });
  const counts = {
    total: rows.length,
    reachable: rows.filter((row) => row[1] === "reachable").length,
    structurallyAbsent: rows.filter((row) => row[1] === "structurally-absent").length,
    trustedControlPlane: rows.filter((row) => row[1] === "trusted-control-plane").length,
    evidenced: 0,
  };
  if (counts.reachable + counts.structurallyAbsent + counts.trustedControlPlane !== counts.total) {
    throw new Error("restricted profile projection is not total");
  }

  const projection = {
    projectionSchema: "ibex/restricted-profile-projection/1",
    profile: definition.profile,
    fullProfile: definition.fullProfile,
    status: "phase0-candidate-evidence-pending",
    definitionRawContentDigest: sha256(raw.definition ?? Buffer.from(canonicalJson(definition))),
    coverageRawContentDigest: sha256(raw.coverage ?? Buffer.from(canonicalJson(coverage))),
    implementationManifestRawContentDigest: sha256(
      raw.implementationManifest ?? Buffer.from(canonicalJson(implementationManifest)),
    ),
    schemaRawContentDigests: {
      advertisements: sha256(raw.advertisementSchema ?? fs.readFileSync(advertisementSchemaPath)),
      definition: sha256(raw.definitionSchema ?? fs.readFileSync(definitionSchemaPath)),
      fixturePlan: sha256(raw.fixturePlanSchema ?? fs.readFileSync(fixturePlanSchemaPath)),
      projection: sha256(raw.projectionSchema ?? fs.readFileSync(projectionSchemaPath)),
      targetAttestations: sha256(
        raw.targetAttestationsSchema ?? fs.readFileSync(targetAttestationsSchemaPath),
      ),
      targetReport: sha256(raw.targetReportSchema ?? fs.readFileSync(targetReportSchemaPath)),
    },
    sourceEdgeSet: {
      count: edgeIds.length,
      digest: actualEdgeSetDigest,
    },
    candidateTargets: definition.candidateTargets,
    counts,
    rows,
    promotionReady: false,
    blockers: [
      "no conformant content-addressed target report and attestation are committed",
      "reachable and trusted-control-plane executable evidence is pending",
      "structural-absence source-install and live-reachability evidence is pending",
      "external-supervisor teardown evidence and independent security review are pending",
    ].sort(),
  };
  const projectionText = renderProjection(projection);
  const derivedAdvertisements = deriveRestrictedTargetAdvertisements({
    targetAttestations,
    authorities: {
      projection,
      coverage,
      implementationManifest,
      fixturePlan,
      rawAuthorities: {
        definition: raw.definition ?? Buffer.from(canonicalJson(definition), "utf8"),
        projection: Buffer.from(projectionText, "utf8"),
        coverage: raw.coverage ?? Buffer.from(canonicalJson(coverage), "utf8"),
        implementationManifest:
          raw.implementationManifest
          ?? Buffer.from(canonicalJson(implementationManifest), "utf8"),
        fixturePlan: raw.fixturePlan ?? Buffer.from(canonicalJson(fixturePlan), "utf8"),
        reportSchema: raw.targetReportSchema ?? fs.readFileSync(targetReportSchemaPath),
      },
    },
  });
  const advertisements = {
    advertisementSchema: "ibex/restricted-profile-advertisements/1",
    profile: definition.profile,
    projectionRawContentDigest: sha256(Buffer.from(projectionText, "utf8")),
    advertisements: derivedAdvertisements,
  };

  assertSchema(schemaValidator(projectionSchemaPath), projection, "restricted profile projection");
  assertSchema(
    schemaValidator(advertisementSchemaPath),
    advertisements,
    "restricted profile advertisements",
  );
  validateRestrictedExactProfile(projection, advertisements, coverage);
  return { projection, projectionText, advertisements, advertisementsText: prettyJson(advertisements) };
}

export function validateRestrictedExactProfile(projection, advertisements, coverage) {
  const sourceIds = coverage.edges.map((edge) => edge.id).sort();
  const projectedIds = projection.rows.map((row) => row[0]);
  assertSortedUnique(projectedIds, "restricted projection rows");
  if (canonicalJson(sourceIds) !== canonicalJson(projectedIds)) {
    throw new Error("restricted projection is not a bijection over full coverage edges");
  }
  if (projection.counts.total !== projection.rows.length) {
    throw new Error("restricted projection count does not match its rows");
  }
  if (projection.counts.evidenced !== 0 || projection.rows.some((row) => row[2] !== "pending")) {
    throw new Error("Phase 0 restricted projection falsely claims evidence");
  }
  if (projection.promotionReady) {
    throw new Error("restricted source projection cannot itself claim target evidence");
  }
  assertSortedUnique(
    advertisements.advertisements.map(
      (row) => `${row.target.triple}\0${row.target.features.join("\0")}`,
    ),
    "restricted target advertisements",
  );
  const expectedProjectionDigest = sha256(Buffer.from(renderProjection(projection), "utf8"));
  if (advertisements.projectionRawContentDigest !== expectedProjectionDigest) {
    throw new Error("restricted advertisements do not bind exact projection bytes");
  }
}

export function loadAndBuildRestrictedExactProfile() {
  const definitionBytes = fs.readFileSync(definitionPath);
  const coverageBytes = fs.readFileSync(coveragePath);
  const implementationManifestBytes = fs.readFileSync(implementationManifestPath);
  const fixturePlanBytes = fs.readFileSync(fixturePlanPath);
  const targetAttestationsBytes = fs.readFileSync(targetAttestationsPath);
  return buildRestrictedExactProfile({
    definition: readJsonStrict(definitionPath),
    coverage: readJsonStrict(coveragePath),
    implementationManifest: readJsonStrict(implementationManifestPath),
    fixturePlan: readJsonStrict(fixturePlanPath),
    targetAttestations: readJsonStrict(targetAttestationsPath),
    raw: {
      definition: definitionBytes,
      coverage: coverageBytes,
      implementationManifest: implementationManifestBytes,
      fixturePlan: fixturePlanBytes,
      targetAttestations: targetAttestationsBytes,
      advertisementSchema: fs.readFileSync(advertisementSchemaPath),
      definitionSchema: fs.readFileSync(definitionSchemaPath),
      fixturePlanSchema: fs.readFileSync(fixturePlanSchemaPath),
      projectionSchema: fs.readFileSync(projectionSchemaPath),
      targetAttestationsSchema: fs.readFileSync(targetAttestationsSchemaPath),
      targetReportSchema: fs.readFileSync(targetReportSchemaPath),
    },
  });
}

function checkGenerated(pathName, expected) {
  const { path: confined } = assertConfinedGeneratedFile(repoRoot, pathName, pathName);
  const actual = fs.readFileSync(confined, "utf8");
  if (actual !== expected) {
    throw new Error(`${path.relative(repoRoot, pathName)} is stale; run bun run generate:restricted-exact-profile`);
  }
}

function main() {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check") || !write;
  if (write && process.argv.includes("--check")) throw new Error("choose --write or --check");
  const result = loadAndBuildRestrictedExactProfile();
  if (write) {
    writeGeneratedFilesTransactionally(repoRoot, [
      {
        path: projectionPath,
        content: result.projectionText,
        label: "restricted Exact profile projection",
      },
      {
        path: advertisementsPath,
        content: result.advertisementsText,
        label: "restricted Exact target advertisements",
      },
    ]);
  } else if (check) {
    checkGenerated(projectionPath, result.projectionText);
    checkGenerated(advertisementsPath, result.advertisementsText);
  }
  console.log(JSON.stringify({
    mode: write ? "write" : "check",
    profile: result.projection.profile,
    ...result.projection.counts,
    advertisements: result.advertisements.advertisements.length,
    promotionReady: result.projection.promotionReady,
  }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
