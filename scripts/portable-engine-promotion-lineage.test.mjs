import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { afterEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import {
  canonicalJson,
  parseJsonStrict,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";
import {
  commandAttemptDigest,
  mappedEngineExecutionEvidenceDigest,
  portableConformanceDigest,
  portableExecutionBindingDigest,
  portableFixtureEvidenceDigest,
  portableOutputDispositionObservationDigest,
  portablePublicSurfaceExecutionDigest,
  portablePublicSurfaceExecutionEvidenceDigest,
  portableRecipeCatalogDigest,
  portableRecipePlanDigest,
  rawContentDigest,
} from "../packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.mjs";
import { conformanceRunnerBindingDigest } from "../packages/ibex-devtools/src/scripts/capsec-conformance-runner-binding.mjs";
import {
  buildScopeArtifact,
  computeScopeCellMappingDigest,
  computeScopeExpansionDiffDigest,
} from "../packages/ibex-devtools/src/scripts/capsec-scope-artifact.mjs";
import {
  portableEnginePromotionLineagePlatformSupported,
  resolvePortableEnginePromotionPredecessor,
  verifyPortableEngineScopePredecessor,
} from "./portable-engine-promotion-lineage.mjs";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoots = new Set();
const catalogPath = "schemas/portable-engine-promotion-admission-catalog-v1.json";
const schemaPath = "schemas/portable-engine-promotion-admission-catalog-v2.schema.json";
const checkedAdmissionSchemaPath = "schemas/portable-engine-checked-promotion-admission-v2.schema.json";
const targetAttestationPath = "capsec/conformance/target-attestations.json";
const targetAdvertisementPath = "capsec/generated/target-advertisements.json";
const targetTriple = "aarch64-apple-darwin";
const portableVectors = parseJsonStrict(
  fs.readFileSync(
    path.join(
      sourceRoot,
      "schemas/vectors/portable-engine-provenance-v1.valid.json",
    ),
  ),
  "portable provenance test vectors",
);
const basePortableEngine = portableVectors.documents.portableIdentity;
const baseMappedEngine = portableVectors.documents.mappedInstance;
const artifactId = basePortableEngine.artifactId;
const admissionDomain = "ibex.portable-engine-promotion-admission.v2";
const checkedAdmissionDomain = "ibex.portable-engine-checked-promotion-admission.v2";
const lineageFloor = "afad4af9f4257eb8262cf8348e5fbb0a3c082ecf";
const target = Object.freeze({
  triple: targetTriple,
  features: Object.freeze([
    "hermes-frame-attribution",
    "native-compartments",
    "native-lockdown",
  ]),
});
const portableGraphAuthorityPaths = Object.freeze([
  "packages/ibex-devtools/src/scripts/verify-capsec-portable-promotion-bundle.mjs",
  "packages/ibex-devtools/src/scripts/capsec-portable-engine-evidence-contract.mjs",
  "packages/ibex-devtools/src/scripts/capsec-scope-artifact.mjs",
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
]);
const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  HOME: "/var/empty",
  XDG_CONFIG_HOME: "/var/empty",
  LC_ALL: "C",
  LANG: "C",
  GIT_CONFIG_COUNT: "0",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_NO_LAZY_FETCH: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
});

afterEach(async () => {
  for (const root of temporaryRoots) await fsp.rm(root, { recursive: true, force: true });
  temporaryRoots.clear();
});

function git(repoRoot, args, options = {}) {
  return execFileSync("/usr/bin/git", args, {
    cwd: repoRoot,
    env: gitEnvironment,
    encoding: options.encoding ?? "utf8",
    maxBuffer: 80 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function writeFile(repoRoot, relativePath, bytes) {
  const absolute = path.join(repoRoot, relativePath);
  await fsp.mkdir(path.dirname(absolute), { recursive: true });
  await fsp.writeFile(absolute, bytes, { mode: 0o644 });
}

async function copyAuthority(repoRoot, relativePath) {
  await writeFile(repoRoot, relativePath, await fsp.readFile(path.join(sourceRoot, relativePath)));
}

async function copyModuleClosure(repoRoot, relativePath, seen = new Set()) {
  const normalized = path.posix.normalize(relativePath);
  if (seen.has(normalized)) return;
  seen.add(normalized);
  await copyAuthority(repoRoot, normalized);
  const source = await fsp.readFile(path.join(sourceRoot, normalized), "utf8");
  const imports = source.matchAll(
    /(?:\bfrom\s*|\bimport\s*)["'](\.[^"']+)["']/gu,
  );
  for (const match of imports) {
    const imported = path.posix.normalize(
      path.posix.join(path.posix.dirname(normalized), match[1]),
    );
    if (!imported.endsWith(".mjs")) continue;
    assert(
      !imported.startsWith("../") && imported !== "..",
      `test module import escapes the fixture checkout: ${imported}`,
    );
    await copyModuleClosure(repoRoot, imported, seen);
  }
}

function indexEntry(repoRoot, relativePath) {
  const output = git(repoRoot, ["ls-files", "-s", "--", relativePath]).trim();
  const match = /^(100644|100755|120000|160000) ([0-9a-f]{40}) 0\t(.+)$/u.exec(output);
  assert(match, `missing exact index entry for ${relativePath}: ${output}`);
  assert.equal(match[3], relativePath);
  return { mode: match[1], objectId: match[2] };
}

function readIndexBytes(repoRoot, entry) {
  if (entry.mode === "160000") return null;
  return Buffer.from(git(repoRoot, ["cat-file", "blob", entry.objectId], { encoding: "buffer" }));
}

function artifactRow(repoRoot, role, relativePath, { advertisedMode = "100644" } = {}) {
  const entry = indexEntry(repoRoot, relativePath);
  const bytes = readIndexBytes(repoRoot, entry);
  return {
    role,
    path: relativePath,
    mode: advertisedMode,
    blobObjectId: entry.objectId,
    size: bytes?.length ?? 1,
    digest: bytes ? rawDigest(bytes) : `sha256-${"0".repeat(64)}`,
  };
}

async function initializeHistoryRepository() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-scope-history-"));
  temporaryRoots.add(root);
  const repoRoot = path.join(root, "checkout");
  git(root, ["clone", "--quiet", "--no-checkout", sourceRoot, repoRoot]);
  git(repoRoot, ["config", "user.name", "Ibex scope history test"]);
  git(repoRoot, ["config", "user.email", "ibex-scope-history@example.invalid"]);
  git(repoRoot, ["switch", "--quiet", "--create", "scope-history", lineageFloor]);
  await writeFile(repoRoot, catalogPath, `${canonicalJson({
    admissionPath: catalogPath,
    admissions: [],
    enabled: false,
    schema: "ibex/portable-engine-promotion-admission-catalog/2",
  })}\n`);
  await writeFile(repoRoot, targetAttestationPath, `${canonicalJson({
    targetAttestationSchema: "ibex/capsec-target-attestations/1",
    profile: "ibex/capsec/1",
    attestations: [],
  })}\n`);
  await writeFile(repoRoot, targetAdvertisementPath, `${canonicalJson({
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/1",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: digest("S"),
    advertisements: [],
  })}\n`);
  git(repoRoot, ["add", "--all"]);
  git(repoRoot, ["commit", "--quiet", "-m", "scoped lineage reset foundation"]);
  return { root, repoRoot, branch: "scope-history", promotionIndex: 0 };
}

async function resetHistoryRepository(fixture, { ordinaryCommits = 0 } = {}) {
  for (let index = 0; index < ordinaryCommits; index += 1) {
    git(fixture.repoRoot, ["commit", "--quiet", "--allow-empty", "-m", `ordinary descendant ${index + 1}`]);
  }
  fixture.ordinaryRevision = git(fixture.repoRoot, ["rev-parse", "HEAD"]).trim();
  await writeFile(fixture.repoRoot, catalogPath, `${canonicalJson({
    admissionPath: catalogPath,
    admissions: [],
    enabled: false,
    schema: "ibex/portable-engine-promotion-admission-catalog/2",
  })}\n`);
  await writeFile(fixture.repoRoot, targetAttestationPath, `${canonicalJson({
    targetAttestationSchema: "ibex/capsec-target-attestations/1",
    profile: "ibex/capsec/1",
    attestations: [],
  })}\n`);
  await writeFile(fixture.repoRoot, targetAdvertisementPath, `${canonicalJson({
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/1",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: digest("S"),
    advertisements: [],
  })}\n`);
  git(fixture.repoRoot, ["add", "--all"]);
  git(fixture.repoRoot, ["commit", "--quiet", "-m", "reset scoped publication foundation"]);
  fixture.resetRevision = git(fixture.repoRoot, ["rev-parse", "HEAD"]).trim();
  return fixture.resetRevision;
}

async function createHistoryPromotion(fixture, {
  targetOverride = target,
  predecessorScopeDigest = "genesis",
  variant = null,
} = {}) {
  fixture.promotionIndex += 1;
  const { repoRoot } = fixture;
  const sourceRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();
  const sourceTreeObjectId = git(repoRoot, ["show", "-s", "--format=%T", "HEAD"]).trim();
  const topicBranch = `scope-promotion-${fixture.promotionIndex}`;
  git(repoRoot, ["switch", "--quiet", "--create", topicBranch]);
  const evidenceRoot = `capsec/conformance/portable-promotions/${sourceRevision}/${targetOverride.triple}/${artifactId}`;
  const graph = validPortableBundleGraph({
    sourceRevision,
    sourceTreeObjectId,
    targetOverride,
    predecessorScopeDigest,
  });
  if (variant === "unknown-scope-schema") {
    const scopeMember = graph.members.find(
      (member) => member.logicalName === "scope-artifact",
    );
    assert(scopeMember);
    const unknownScope = parseJsonStrict(
      scopeMember.bytes,
      "history scope artifact",
    );
    unknownScope.scopeSchema = "ibex/capsec-scope/999";
    scopeMember.bytes = canonicalBytes(unknownScope);
  }
  const memberPath = (logicalName) =>
    logicalName === "portable-conformance-report"
      ? `${evidenceRoot}/conformance-report.json`
      : logicalName === "scope-artifact"
        ? `${evidenceRoot}/capsec-scope.json`
        : `${evidenceRoot}/${logicalName}.json`;
  for (const member of graph.members) {
    await writeFile(repoRoot, memberPath(member.logicalName), member.bytes);
  }
  if (variant === "bundle-digest-mismatch") {
    const manifest = parseJsonStrict(
      graph.manifestBytes,
      "history portable bundle manifest",
    );
    manifest.bundleDigest = digest("Z");
    graph.manifestBytes = exactBytes(manifest);
  }
  await writeFile(
    repoRoot,
    `${evidenceRoot}/promotion-bundle-manifest.json`,
    graph.manifestBytes,
  );
  const scopeMember = graph.members.find(
    (member) => member.logicalName === "scope-artifact",
  );
  const attestationMember = graph.members.find(
    (member) => member.logicalName === "target-attestations",
  );
  const advertisementMember = graph.members.find(
    (member) => member.logicalName === "target-advertisements",
  );
  assert(scopeMember && attestationMember && advertisementMember);
  const scope = parseJsonStrict(scopeMember.bytes, "history scope artifact");
  const declaredScopeDigest =
    variant === "scope-digest-mismatch" ? digest("Z") : graph.scopeDigest;
  await writeFile(repoRoot, targetAttestationPath, attestationMember.bytes);
  if (variant === "advertisement-mismatch") {
    const advertisements = parseJsonStrict(
      advertisementMember.bytes,
      "history target advertisements",
    );
    advertisements.advertisements[0].scopeDigest = digest("Y");
    await writeFile(
      repoRoot,
      targetAdvertisementPath,
      `${canonicalJson(advertisements)}\n`,
    );
  } else {
    await writeFile(
      repoRoot,
      targetAdvertisementPath,
      advertisementMember.bytes,
    );
  }
  git(repoRoot, ["add", "--all"]);
  const artifacts = [
    artifactRow(
      repoRoot,
      "conformance-evidence",
      `${evidenceRoot}/promotion-bundle-manifest.json`,
    ),
    ...graph.members.map((member) => {
      const role = member.logicalName === "scope-artifact"
        ? "scope-artifact"
        : "conformance-evidence";
      return artifactRow(repoRoot, role, memberPath(member.logicalName));
    }),
  ];
  const scopeRow = artifacts.find(
    (row) => row.path === `${evidenceRoot}/capsec-scope.json`,
  );
  if (variant === "scope-row-object-mismatch") {
    scopeRow.blobObjectId = "f".repeat(40);
  } else if (variant === "scope-row-size-mismatch") {
    scopeRow.size += 1;
  } else if (variant === "scope-row-digest-mismatch") {
    scopeRow.digest = `sha256-${"f".repeat(64)}`;
  } else if (variant === "missing-scope-row") {
    await fsp.rm(path.join(repoRoot, scopeRow.path));
  }
  artifacts.push(artifactRow(repoRoot, "target-attestation", targetAttestationPath));
  artifacts.push(artifactRow(repoRoot, "target-advertisement", targetAdvertisementPath));
  artifacts.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const admission = {
    schema: "ibex/portable-engine-promotion-admission/2",
    sourceRevision,
    sourceTreeObjectId,
    topology: "github-pull-request-merge/direct-single-commit-topic/1",
    target: clone(targetOverride),
    admittedScopeDigest: declaredScopeDigest,
    portableArtifactId: artifactId,
    artifacts,
    admissionDigest: digest("A"),
  };
  admission.admissionDigest = semanticDigest(admissionDomain, admission, ["admissionDigest"]);
  await writeFile(repoRoot, catalogPath, `${canonicalJson({
    admissionPath: catalogPath,
    admissions: [admission],
    enabled: true,
    schema:
      variant === "enabled-v1-catalog"
        ? "ibex/portable-engine-promotion-admission-catalog/1"
        : "ibex/portable-engine-promotion-admission-catalog/2",
  })}\n`);
  git(repoRoot, ["add", "--all"]);
  git(repoRoot, ["commit", "--quiet", "-m", `scoped promotion topic ${fixture.promotionIndex}`]);
  const topicRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();
  git(repoRoot, ["switch", "--quiet", fixture.branch]);
  git(repoRoot, ["merge", "--quiet", "--no-ff", "-m", `merge scoped promotion ${fixture.promotionIndex}`, topicBranch]);
  const mergeRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();
  return { admission, declaredScopeDigest, mergeRevision, scope, sourceRevision, topicRevision };
}

function resolveHistory(repoRoot, startRevision, targetOverride = target) {
  return resolvePortableEnginePromotionPredecessor({
    repoRoot,
    startRevision,
    target: clone(targetOverride),
  });
}

function roundOneCatalogCarrier(repoRoot, startRevision) {
  const lines = git(repoRoot, ["rev-list", "--first-parent", startRevision]).trim().split("\n").filter(Boolean);
  for (const revision of lines) {
    const raw = git(repoRoot, ["show", `${revision}:${catalogPath}`], { encoding: "utf8" });
    const catalog = JSON.parse(raw);
    if (catalog.enabled) return revision;
    if (revision === lineageFloor) break;
  }
  return null;
}

function roundTwoShapeOnlyAccepts(repoRoot, promotion) {
  const line = git(repoRoot, ["show", "-s", "--format=%P", promotion.mergeRevision]).trim().split(" ");
  return line.length === 2
    && line[0] === promotion.sourceRevision
    && semanticDigest(admissionDomain, promotion.admission, ["admissionDigest"])
      === promotion.admission.admissionDigest;
}

const digest = (character) => `sha256-${character.repeat(43)}`;
const clone = (value) => structuredClone(value);
const exactBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
const canonicalBytes = (value) => Buffer.from(canonicalJson(value), "utf8");

function canonicalScopeBundle(targetOverride, predecessorScopeDigest = "genesis") {
  const edgeId = "surface.portable.lineage";
  const predecessor = predecessorScopeDigest === "genesis"
    ? { kind: "genesis" }
    : { kind: "scope", scopeDigest: predecessorScopeDigest };
  const previousExpandedCellIds = predecessor.kind === "genesis" ? [] : [edgeId];
  const addedCellIds = predecessor.kind === "genesis" ? [edgeId] : [];
  const diff = {
    scopeExpansionDiffSchema: "ibex/capsec-scope-expansion-diff/1",
    profile: "ibex/capsec/1",
    target: clone(targetOverride),
    predecessor,
    previousExpandedCellIds,
    currentExpandedCellIds: [edgeId],
    addedCellIds,
    retiredCellIds: [],
    scopeExpansionDiffDigest: digest("A"),
  };
  diff.scopeExpansionDiffDigest = computeScopeExpansionDiffDigest(diff);
  const mapping = {
    scopeCellMappingSchema: "ibex/capsec-scope-cell-mapping/1",
    profile: "ibex/capsec/1",
    target: clone(targetOverride),
    predecessor,
    additions: addedCellIds,
    retirements: [],
    mappings: [],
    scopeCellMappingDigest: digest("A"),
  };
  mapping.scopeCellMappingDigest = computeScopeCellMappingDigest(mapping);
  const scope = buildScopeArtifact({
    target: clone(targetOverride),
    intensionalDefinition: {
      capabilityFamilies: ["fs"],
      surfaceKinds: ["native-op"],
    },
    expandedCellIds: [edgeId],
    closureEdges: [
      {
        fromEdgeId: edgeId,
        toEdgeId: edgeId,
        dependencyKind: "source-derived-route",
        implementationBranchId: "branch.portable-lineage",
        terminalObservedKey: "native-op:portableLineage",
        proofPaths: ["native-op:portableLineage"],
        sourceRefs: ["scripts/portable-engine-promotion-lineage.test.mjs#fixture"],
      },
    ],
    predecessor,
    expansionDiff: diff,
    cellMapping: mapping,
  });
  return { diff, mapping, scope };
}

function sourceTreeDigest(sourceTreeObjectId) {
  return `sha256-${createHash("sha256")
    .update(Buffer.from(`${sourceTreeObjectId}\n`, "utf8"))
    .digest("base64url")}`;
}

function withDigest(value, field, digestFunction) {
  value[field] = digest("A");
  value[field] = digestFunction(value);
  return value;
}

function validPortableBundleGraph({
  sourceRevision,
  sourceTreeObjectId,
  targetOverride = null,
  predecessorScopeDigest = "genesis",
}) {
  const treeDigest = sourceTreeDigest(sourceTreeObjectId);
  const target = targetOverride ?? {
      triple: targetTriple,
      features: [
        "hermes-frame-attribution",
        "native-compartments",
        "native-lockdown",
      ],
    };
  const scoped = canonicalScopeBundle(target, predecessorScopeDigest);
  const scopeDigest = scoped.scope.scopeDigest;
  const engine = clone(basePortableEngine);
  const conformanceRunner = {
    sourceRevision,
    sourceTreeDigest: treeDigest,
    artifactId: engine.artifactId,
    buildConsumptionDigest: digest("M"),
    postLinkSetDigest: digest("Q"),
    verificationDigest: digest("U"),
    testExecutableDigest: `sha256-${"e".repeat(64)}`,
  };
  const fixtureId = "fixture.portable-lineage";
  const executor = "ibex-exact-fixture-evidence-pilot";
  const targetCells = {
    targetCellSchema: "ibex/capsec-target-cells/1",
    profile: "ibex/capsec/1",
    cells: [
      {
        edgeId: "surface.portable.lineage",
        target: clone(target),
        disposition: "enforced",
        implementationBranchIds: ["branch.portable-lineage"],
        fixtures: [fixtureId],
        rationale: "Exact checked-Git promotion-lineage fixture.",
      },
    ],
  };
  const targetCellsBytes = exactBytes(targetCells);
  const recipe = withDigest(
    {
      fixtureId,
      status: "fully-executable",
      executor,
      planDigest: digest("A"),
    },
    "planDigest",
    portableRecipePlanDigest,
  );
  const recipes = withDigest(
    {
      recipeCatalogSchema: "ibex/capsec-executable-recipes/2",
      profile: "ibex/capsec/1",
      target: clone(target),
      recipes: [recipe],
      summary: {
        requiredFixtures: 1,
        fullyExecutableFixtures: 1,
        internallyVerifiedFixtures: 0,
        unresolvedFixtures: 0,
      },
      recipeCatalogDigest: digest("A"),
    },
    "recipeCatalogDigest",
    (value) => portableRecipeCatalogDigest(value, scopeDigest),
  );
  const recipeCatalogBytes = exactBytes(recipes);
  const publicExecution = withDigest(
    {
      fixtureId,
      outcome: "passed",
      executor,
      evidenceDigest: digest("A"),
    },
    "evidenceDigest",
    portablePublicSurfaceExecutionEvidenceDigest,
  );
  const publicSurface = withDigest(
    {
      publicSurfaceExecutionSchema: "ibex/capsec-public-surface-executions/2",
      profile: "ibex/capsec/1",
      sourceRevision,
      sourceTreeDigest: treeDigest,
      target: clone(target),
      engine: clone(engine),
      recipeCatalogDigest: recipes.recipeCatalogDigest,
      recipeCatalogRawContentDigest: rawContentDigest(recipeCatalogBytes),
      summary: {
        requiredFixtures: 1,
        executableFixtures: 1,
        internallyVerifiedFixtures: 0,
        residualFixtures: 0,
        executedFixtures: 1,
        passedFixtures: 1,
        failedFixtures: 0,
        missingFixtures: 0,
      },
      executions: [publicExecution],
      publicSurfaceExecutionDigest: digest("A"),
    },
    "publicSurfaceExecutionDigest",
    portablePublicSurfaceExecutionDigest,
  );
  const publicSurfaceExecutionBytes = exactBytes(publicSurface);
  const outputObservation = withDigest(
    {
      key: "output.portable-lineage",
      disposition: "non-path",
      proofKind: "compiled-runtime-return-record",
      observationDigest: digest("A"),
    },
    "observationDigest",
    portableOutputDispositionObservationDigest,
  );
  const outputDispositions = {
    outputDispositionEvidenceSchema:
      "ibex/capsec-output-disposition-evidence/4",
    profile: "ibex/capsec/1",
    status: "verified",
    sourceRevision,
    sourceTreeDigest: treeDigest,
    target: clone(target),
    engine: clone(engine),
    conformanceRunner: clone(conformanceRunner),
    summary: { observations: 1 },
    observations: [outputObservation],
  };
  const outputDispositionEvidenceBytes = exactBytes(outputDispositions);
  const bindings = {
    sourceRevision,
    sourceTreeDigest: treeDigest,
    conformanceRunner: clone(conformanceRunner),
    engine: clone(engine),
    target: clone(target),
    vocabularyDigest: digest("Q"),
    registryDigest: digest("U"),
    implementationManifestDigest: digest("Y"),
    fixtureCatalogDigest: digest("c"),
    scopeDigest,
    targetCellsRawContentDigest: rawContentDigest(targetCellsBytes),
    recipeCatalogDigest: recipes.recipeCatalogDigest,
    recipeCatalogRawContentDigest: rawContentDigest(recipeCatalogBytes),
    publicSurfaceExecutionDigest: publicSurface.publicSurfaceExecutionDigest,
    publicSurfaceExecutionRawContentDigest: rawContentDigest(
      publicSurfaceExecutionBytes,
    ),
    outputDispositionEvidenceRawContentDigest: rawContentDigest(
      outputDispositionEvidenceBytes,
    ),
  };
  const bindingDigest = portableExecutionBindingDigest(bindings);
  const fixture = withDigest(
    {
      fixtureEvidenceSchema: "ibex/capsec-portable-fixture-evidence/1",
      profile: "ibex/capsec/1",
      sourceRevision,
      sourceTreeDigest: treeDigest,
      target: clone(target),
      engine: clone(engine),
      fixtureId,
      outcome: "passed",
      executor,
      bindingDigest,
      artifactDigest: digest("A"),
    },
    "artifactDigest",
    portableFixtureEvidenceDigest,
  );
  const fixtureBytes = exactBytes(fixture);
  const fixtureRawDigest = rawContentDigest(fixtureBytes);
  const mappedEngine = clone(baseMappedEngine);
  mappedEngine.portable = clone(engine);
  mappedEngine.before.digest = engine.runtimeComponentDigest;
  mappedEngine.after.digest = engine.runtimeComponentDigest;
  mappedEngine.processArchitecture = targetTriple.split("-")[0];
  mappedEngine.observationDigest = semanticDigest(
    "ibex.mapped-engine-instance-identity.v1",
    mappedEngine,
    ["observationDigest"],
  );
  const mappedEvidence = withDigest(
    {
      mappedEngineExecutionEvidenceSchema:
        "ibex/capsec-mapped-engine-execution-evidence/1",
      profile: "ibex/capsec/1",
      authorityClass: "same-runner-authoritative",
      sourceRevision,
      sourceTreeDigest: treeDigest,
      target: clone(target),
      phaseId: "fixture-evidence",
      commandId: "exact-fixture-evidence",
      commandIdentityDigest: digest("E"),
      fixtureIds: [fixtureId],
      outputDigests: [fixtureRawDigest],
      engine: clone(engine),
      mappedEngine,
      evidenceDigest: digest("A"),
    },
    "evidenceDigest",
    mappedEngineExecutionEvidenceDigest,
  );
  const mappedEvidenceBytes = exactBytes(mappedEvidence);
  const commandAttempt = withDigest(
    {
      schema: "ibex/capsec-command-attempt/1",
      attemptId: "attempt-000001",
      commandId: mappedEvidence.commandId,
      commandIdentity: mappedEvidence.commandIdentityDigest,
      phase: mappedEvidence.phaseId,
      displayedInvocation: ["ibex", "--fixture-evidence"],
      declaredInputs: [
        {
          name: "conformanceRunner",
          digest: conformanceRunnerBindingDigest(conformanceRunner),
        },
      ],
      startedAt: "2026-07-20T00:00:00.000Z",
      finishedAt: "2026-07-20T00:00:01.000Z",
      elapsedMs: 1000,
      deadlineMs: 30000,
      gracePeriodMs: 5000,
      classification: "success",
      exitCode: 0,
      signal: null,
      cleanup: { actions: [], cleanupProven: true, escapedDescendants: [] },
      stdout: { bytes: 0, digest: digest("4"), tail: "", truncated: false },
      stderr: { bytes: 0, digest: digest("4"), tail: "", truncated: false },
      outputs: [
        {
          path: "/runner/evidence/fixture.json",
          bytes: fixtureBytes.byteLength,
          digest: fixtureRawDigest,
        },
        {
          path: "/runner/evidence/mapped.json",
          bytes: mappedEvidenceBytes.byteLength,
          digest: rawContentDigest(mappedEvidenceBytes),
        },
      ],
      attemptDigest: digest("A"),
    },
    "attemptDigest",
    commandAttemptDigest,
  );
  const commandAttemptBytes = exactBytes(commandAttempt);
  const evidenceReference = {
    evidenceDigest: mappedEvidence.evidenceDigest,
    rawContentDigest: rawContentDigest(mappedEvidenceBytes),
    attemptDigest: commandAttempt.attemptDigest,
    attemptRawContentDigest: rawContentDigest(commandAttemptBytes),
  };
  const report = withDigest(
    {
      conformanceSchema: "ibex/capsec-conformance/3",
      profile: "ibex/capsec/1",
      status: "conformant",
      bindings: {
        ...clone(bindings),
        mappedEngineExecutionEvidence: [evidenceReference],
      },
      summary: {
        cells: 1,
        conformantCells: 1,
        incompleteCells: 0,
        uncertifiedCells: 0,
        requiredFixtures: 1,
        passedFixtures: 1,
        missingFixtures: 0,
        failedFixtures: 0,
      },
      executions: [
        {
          fixtureId,
          outcome: "passed",
          executor,
          artifactDigest: fixture.artifactDigest,
          rawContentDigest: fixtureRawDigest,
          bindingDigest,
          mappedEngineExecutionEvidenceDigest: mappedEvidence.evidenceDigest,
        },
      ],
      cells: [
        {
          edgeId: "surface.portable.lineage",
          implementationBranchIds: ["branch.portable-lineage"],
          enforcementBranchIds: ["branch.portable-lineage"],
          status: "conformant",
          requiredFixtures: [fixtureId],
          passedFixtures: [fixtureId],
          missingFixtures: [],
          failedFixtures: [],
        },
      ],
      conformanceDigest: digest("A"),
    },
    "conformanceDigest",
    portableConformanceDigest,
  );
  const reportBytes = exactBytes(report);
  const authorityBytes = exactBytes({
    portablePromotionAuthoritySchema:
      "ibex/capsec-portable-promotion-authority/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest: treeDigest,
    targets: [
      {
        family: "macos",
        target: clone(target),
        engine: clone(engine),
        conformanceRunner: clone(conformanceRunner),
        vocabularyDigest: bindings.vocabularyDigest,
        registryDigest: bindings.registryDigest,
        implementationManifestDigest: bindings.implementationManifestDigest,
        fixtureCatalogDigest: bindings.fixtureCatalogDigest,
        scopeDigest,
        targetCellsRawContentDigest: bindings.targetCellsRawContentDigest,
        recipeCatalogDigest: bindings.recipeCatalogDigest,
        recipeCatalogRawContentDigest: bindings.recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          bindings.publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          bindings.outputDispositionEvidenceRawContentDigest,
      },
    ],
  });
  const attestationsBytes = exactBytes({
    targetAttestationSchema: "ibex/capsec-target-attestations/3",
    profile: "ibex/capsec/1",
    attestations: [
      {
        target: clone(target),
        scopeDigest,
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest: rawContentDigest(reportBytes),
        sourceRevision,
        sourceTreeDigest: treeDigest,
        portableArtifactId: artifactId,
        mappedEngineExecutionEvidence: [clone(evidenceReference)],
        recipeCatalogDigest: bindings.recipeCatalogDigest,
        recipeCatalogRawContentDigest: bindings.recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          bindings.publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          bindings.outputDispositionEvidenceRawContentDigest,
      },
    ],
  });
  const advertisementsBytes = exactBytes({
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/3",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: bindings.targetCellsRawContentDigest,
    advertisements: [
      {
        target: clone(target),
        scopeDigest,
        conformanceDigest: report.conformanceDigest,
        reportRawContentDigest: rawContentDigest(reportBytes),
        sourceRevision,
        sourceTreeDigest: treeDigest,
        engine: clone(engine),
        mappedEngineExecutionEvidence: [clone(evidenceReference)],
        vocabularyDigest: bindings.vocabularyDigest,
        registryDigest: bindings.registryDigest,
        implementationManifestDigest: bindings.implementationManifestDigest,
        fixtureCatalogDigest: bindings.fixtureCatalogDigest,
        recipeCatalogDigest: bindings.recipeCatalogDigest,
        recipeCatalogRawContentDigest: bindings.recipeCatalogRawContentDigest,
        publicSurfaceExecutionDigest: bindings.publicSurfaceExecutionDigest,
        publicSurfaceExecutionRawContentDigest:
          bindings.publicSurfaceExecutionRawContentDigest,
        outputDispositionEvidenceRawContentDigest:
          bindings.outputDispositionEvidenceRawContentDigest,
      },
    ],
  });
  const members = [
    ["portable-promotion-authority", authorityBytes],
    ["scope-artifact", canonicalBytes(scoped.scope)],
    ["scope-expansion-diff", canonicalBytes(scoped.diff)],
    ["scope-cell-mapping", canonicalBytes(scoped.mapping)],
    ["portable-conformance-report", reportBytes],
    ["target-attestations", attestationsBytes],
    ["target-advertisements", advertisementsBytes],
    ["target-cells", targetCellsBytes],
    ["recipes", recipeCatalogBytes],
    ["public-surface", publicSurfaceExecutionBytes],
    ["output-dispositions", outputDispositionEvidenceBytes],
    ["process-0001.mapped-evidence", mappedEvidenceBytes],
    ["process-0001.command-attempt", commandAttemptBytes],
    ["process-0001.fixture-000001", fixtureBytes],
  ].map(([logicalName, bytes]) => ({ logicalName, bytes }));
  const manifest = {
    portablePromotionBundleSchema: "ibex/capsec-portable-promotion-bundle/1",
    profile: "ibex/capsec/1",
    sourceRevision,
    sourceTreeDigest: treeDigest,
    target: clone(target),
    files: members.map(({ logicalName, bytes }) => ({
      logicalName,
      byteLength: bytes.byteLength,
      rawContentDigest: rawContentDigest(bytes),
    })),
    bundleDigest: digest("A"),
  };
  manifest.bundleDigest = semanticDigest(
    "ibex:capsec:portable-promotion-bundle:1",
    manifest,
    ["bundleDigest"],
  );
  return {
    manifestBytes: exactBytes(manifest),
    members,
    scopeDigest,
  };
}

async function initializeSourceRepository() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "ibex-promotion-lineage-"));
  temporaryRoots.add(root);
  const repoRoot = path.join(root, "checkout");
  git(root, ["clone", "--quiet", "--no-checkout", sourceRoot, repoRoot]);
  git(repoRoot, ["config", "user.name", "Ibex promotion test"]);
  git(repoRoot, ["config", "user.email", "ibex-promotion@example.invalid"]);
  git(repoRoot, ["config", "advice.addEmbeddedRepo", "false"]);
  git(repoRoot, ["switch", "--quiet", "--force-create", "main", lineageFloor]);

  for (const relativePath of [
    "scripts/portable-engine-promotion-lineage.mjs",
    "scripts/portable-engine-contract.mjs",
    "scripts/portable-engine-installer.mjs",
    "scripts/portable-engine-installer-core.mjs",
    schemaPath,
    checkedAdmissionSchemaPath,
    catalogPath,
    "schemas/portable-engine-provenance-trust-policy-v1.json",
    "capsec/registry/policy-rules.json",
    ...portableGraphAuthorityPaths,
  ]) {
    await copyAuthority(repoRoot, relativePath);
  }
  await copyModuleClosure(
    repoRoot,
    "packages/ibex-devtools/src/scripts/verify-capsec-portable-promotion-bundle.mjs",
  );
  await fsp.symlink(
    path.join(sourceRoot, "node_modules"),
    path.join(repoRoot, "node_modules"),
    "dir",
  );
  await writeFile(repoRoot, targetAttestationPath, `${JSON.stringify({
    targetAttestationSchema: "ibex/capsec-target-attestations/1",
    profile: "ibex/capsec/1",
    attestations: [],
  }, null, 2)}\n`);
  await writeFile(repoRoot, targetAdvertisementPath, `${JSON.stringify({
    targetAdvertisementSchema: "ibex/capsec-target-advertisements/1",
    profile: "ibex/capsec/1",
    targetCellsRawContentDigest: "sha256-bj5xdO8TVjq3Dkm-ZS4u9P8cLQrKwcnZg8UgrsXV6nU",
    advertisements: [],
  }, null, 2)}\n`);
  await writeFile(repoRoot, "src/source-authority.json", canonicalJson({ source: "closed" }));
  git(repoRoot, ["add", "--all"]);
  git(repoRoot, ["commit", "--quiet", "-m", "artifact source"]);
  return {
    root,
    repoRoot,
    sourceRevision: git(repoRoot, ["rev-parse", "HEAD"]).trim(),
    sourceTreeObjectId: git(repoRoot, ["show", "-s", "--format=%T", "HEAD"]).trim(),
  };
}

async function createNestedSubmodule(repoRoot, relativePath) {
  const nested = path.join(repoRoot, relativePath);
  await fsp.mkdir(nested, { recursive: true });
  git(nested, ["init", "--quiet", "--initial-branch=main"]);
  git(nested, ["config", "user.name", "Ibex promotion test"]);
  git(nested, ["config", "user.email", "ibex-promotion@example.invalid"]);
  await fsp.writeFile(path.join(nested, "payload.json"), canonicalJson({ nested: true }));
  git(nested, ["add", "payload.json"]);
  git(nested, ["commit", "--quiet", "-m", "nested"]);
  git(repoRoot, ["add", "--", relativePath]);
}

async function createPromotionRepository(options = {}) {
  const fixture = await initializeSourceRepository();
  const { repoRoot, sourceRevision, sourceTreeObjectId } = fixture;
  git(repoRoot, ["switch", "--quiet", "-c", "promotion"]);
  if (options.topicHasTwoCommits) git(repoRoot, ["commit", "--quiet", "--allow-empty", "-m", "promotion prelude"]);

  const evidenceRoot = `capsec/conformance/portable-promotions/${sourceRevision}/${targetTriple}/${artifactId}`;
  const evidencePath = `${evidenceRoot}/conformance-report.json`;
  const bundleManifestPath = `${evidenceRoot}/promotion-bundle-manifest.json`;
  const graph = validPortableBundleGraph({
    sourceRevision,
    sourceTreeObjectId,
  });
  if (options.fabricatedSubset) {
    graph.members = graph.members.slice(0, 8);
    const subsetManifest = parseJsonStrict(
      graph.manifestBytes,
      "portable subset manifest",
    );
    subsetManifest.files = subsetManifest.files.slice(0, 8);
    subsetManifest.bundleDigest = semanticDigest(
      "ibex:capsec:portable-promotion-bundle:1",
      subsetManifest,
      ["bundleDigest"],
    );
    graph.manifestBytes = exactBytes(subsetManifest);
  }
  if (options.sourceTreeMismatch) {
    const reboundManifest = parseJsonStrict(
      graph.manifestBytes,
      "portable source-tree mismatch manifest",
    );
    reboundManifest.sourceTreeDigest = digest("Z");
    reboundManifest.bundleDigest = semanticDigest(
      "ibex:capsec:portable-promotion-bundle:1",
      reboundManifest,
      ["bundleDigest"],
    );
    graph.manifestBytes = exactBytes(reboundManifest);
  }
  if (options.targetMismatch) {
    const reboundManifest = parseJsonStrict(
      graph.manifestBytes,
      "portable target mismatch manifest",
    );
    reboundManifest.target.features.push("wrong-self-authored-feature");
    reboundManifest.bundleDigest = semanticDigest(
      "ibex:capsec:portable-promotion-bundle:1",
      reboundManifest,
      ["bundleDigest"],
    );
    graph.manifestBytes = exactBytes(reboundManifest);
  }
  const memberPath = (logicalName) =>
    logicalName === "portable-conformance-report"
      ? evidencePath
      : logicalName === "scope-artifact"
        ? `${evidenceRoot}/capsec-scope.json`
      : `${evidenceRoot}/${logicalName}.json`;
  const reportMember = graph.members.find(
    (member) => member.logicalName === "portable-conformance-report",
  );
  const attestationMember = graph.members.find(
    (member) => member.logicalName === "target-attestations",
  );
  const advertisementMember = graph.members.find(
    (member) => member.logicalName === "target-advertisements",
  );
  const scopeMember = graph.members.find(
    (member) => member.logicalName === "scope-artifact",
  );
  assert(reportMember && attestationMember && advertisementMember && scopeMember);
  const evidenceBytes = options.copySourceBlob
    ? await fsp.readFile(path.join(repoRoot, "src/source-authority.json"))
    : options.bundleCoreMismatch
      ? Buffer.concat([reportMember.bytes, Buffer.from(" ", "utf8")])
      : reportMember.bytes;

  if (options.symlinkEvidence) {
    await fsp.mkdir(path.dirname(path.join(repoRoot, evidencePath)), { recursive: true });
    await fsp.symlink("conformance-report-target.json", path.join(repoRoot, evidencePath));
  } else if (options.submoduleEvidence) {
    await createNestedSubmodule(repoRoot, evidencePath);
  } else {
    await writeFile(repoRoot, evidencePath, evidenceBytes);
    if (options.executableEvidence) await fsp.chmod(path.join(repoRoot, evidencePath), 0o755);
  }
  for (const member of graph.members) {
    if (member.logicalName === "portable-conformance-report") continue;
    if (
      options.missingProcess &&
      member.logicalName === "process-0001.command-attempt"
    ) {
      continue;
    }
    await writeFile(repoRoot, memberPath(member.logicalName), member.bytes);
  }
  await writeFile(repoRoot, bundleManifestPath, graph.manifestBytes);
  await writeFile(repoRoot, targetAttestationPath, attestationMember.bytes);
  await writeFile(repoRoot, targetAdvertisementPath, advertisementMember.bytes);

  let codeDriftPath = null;
  if (options.codeDrift || options.listedCodeDrift) {
    codeDriftPath = "src/source-authority.json";
    await writeFile(repoRoot, codeDriftPath, canonicalJson({ source: "drifted" }));
  }
  let renamedEvidencePath = null;
  if (options.renameSourceBlob) {
    renamedEvidencePath = `${evidenceRoot}/renamed-source.json`;
    await fsp.rename(path.join(repoRoot, "src/source-authority.json"), path.join(repoRoot, renamedEvidencePath));
  }
  if (options.unlistedEquivalent) {
    await writeFile(repoRoot, `${evidenceRoot}/unlisted-equivalent.json`, evidenceBytes);
  }
  const duplicateEvidencePath = `${evidenceRoot}/duplicate-evidence.json`;
  if (options.duplicateEvidence) await writeFile(repoRoot, duplicateEvidencePath, evidenceBytes);
  if (options.authorityDriftPath) {
    const absoluteAuthority = path.join(repoRoot, options.authorityDriftPath);
    await fsp.appendFile(absoluteAuthority, "\n// promotion-time authority drift\n");
  }
  git(repoRoot, ["add", "--all"]);

  const evidenceRowPath = renamedEvidencePath ?? evidencePath;
  const artifacts = [
    artifactRow(repoRoot, "conformance-evidence", bundleManifestPath),
    ...graph.members
      .filter(
        (member) =>
          !(
            options.missingProcess &&
            member.logicalName === "process-0001.command-attempt"
          ),
      )
      .map((member) =>
        artifactRow(
          repoRoot,
          member.logicalName === "scope-artifact"
            ? "scope-artifact"
            : "conformance-evidence",
          member.logicalName === "portable-conformance-report"
            ? evidenceRowPath
            : memberPath(member.logicalName),
        ),
      ),
    artifactRow(repoRoot, "target-attestation", targetAttestationPath),
    artifactRow(repoRoot, "target-advertisement", targetAdvertisementPath),
  ];
  if (options.listedCodeDrift) {
    artifacts.push(artifactRow(repoRoot, "conformance-evidence", codeDriftPath));
  }
  if (options.duplicateEvidence) {
    artifacts.push(artifactRow(repoRoot, "conformance-evidence", duplicateEvidencePath));
  }
  if (options.duplicateArtifactRow) artifacts.push({ ...artifacts[0] });
  artifacts.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));

  const admission = {
    schema: "ibex/portable-engine-promotion-admission/2",
    sourceRevision,
    sourceTreeObjectId,
    topology: "github-pull-request-merge/direct-single-commit-topic/1",
    target: clone(target),
    admittedScopeDigest: graph.scopeDigest,
    portableArtifactId: artifactId,
    artifacts,
    admissionDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  options.mutateAdmission?.(admission);
  admission.admissionDigest = semanticDigest(admissionDomain, admission, ["admissionDigest"]);
  if (options.corruptAdmissionDigest) admission.admissionDigest = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  const catalog = {
    admissionPath: catalogPath,
    admissions: [admission],
    enabled: true,
    schema: "ibex/portable-engine-promotion-admission-catalog/2",
  };
  options.mutateCatalog?.(catalog);
  const catalogBytes = `${canonicalJson(catalog)}\n`;
  if (options.catalogSymlink) {
    const target = "promotion-catalog-symlink-target.json";
    await writeFile(repoRoot, `schemas/${target}`, catalogBytes);
    await fsp.unlink(path.join(repoRoot, catalogPath));
    await fsp.symlink(target, path.join(repoRoot, catalogPath));
  } else if (options.catalogSubmodule) {
    await fsp.unlink(path.join(repoRoot, catalogPath));
    await createNestedSubmodule(repoRoot, catalogPath);
  } else {
    await writeFile(repoRoot, catalogPath, catalogBytes);
  }
  git(repoRoot, ["add", "--all"]);
  git(repoRoot, ["commit", "--quiet", "-m", "review portable promotion"]);
  const promotionTopicRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();

  if (options.fastForward) {
    git(repoRoot, ["switch", "--quiet", "main"]);
    git(repoRoot, ["merge", "--quiet", "--ff-only", "promotion"]);
  } else {
    git(repoRoot, ["switch", "--quiet", "main"]);
    if (options.firstParentDrift) git(repoRoot, ["commit", "--quiet", "--allow-empty", "-m", "main moved"]);
    if (options.mergeTreeDrift) {
      git(repoRoot, ["merge", "--quiet", "--no-ff", "--no-commit", "promotion"]);
      await writeFile(repoRoot, "merge-only.json", canonicalJson({ forbidden: "merge drift" }));
      git(repoRoot, ["add", "merge-only.json"]);
      git(repoRoot, ["commit", "--quiet", "-m", "merge promotion with drift"]);
    } else {
      git(repoRoot, ["merge", "--quiet", "--no-ff", "-m", "merge promotion", "promotion"]);
    }
  }
  const promotionMergeRevision = git(repoRoot, ["rev-parse", "HEAD"]).trim();
  if (options.laterDescendant) {
    git(repoRoot, ["commit", "--quiet", "--allow-empty", "-m", "later descendant"]);
  }
  return {
    ...fixture,
    evidencePath,
    evidenceObjectId: indexEntry(repoRoot, evidencePath).objectId,
    promotionTopicRevision,
    promotionMergeRevision,
  };
}

function runVerifier(repoRoot) {
  const script = path.join(repoRoot, "scripts/portable-engine-promotion-lineage.mjs");
  const result = spawnSync(process.execPath, [script], {
    cwd: repoRoot,
    env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !["NODE_OPTIONS", "NODE_PATH"].includes(name))),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30_000,
  });
  return result;
}

function verifiedResult(repoRoot) {
  const result = runVerifier(repoRoot);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertVerifierRefuses(repoRoot, pattern) {
  const result = runVerifier(repoRoot);
  assert.notEqual(result.status, 0, `verifier unexpectedly accepted: ${result.stdout}`);
  assert.match(result.stderr, pattern);
}

function runCheckedAdmission(repoRoot, selection) {
  const program = [
    "import { verifyPortableEngineCheckoutAdmission } from './scripts/portable-engine-installer.mjs';",
    "const selection = JSON.parse(process.env.IBEX_TEST_PROMOTION_SELECTION);",
    "process.stdout.write(`${JSON.stringify(verifyPortableEngineCheckoutAdmission(selection))}\\n`);",
  ].join("\n");
  return spawnSync(process.execPath, ["--input-type=module", "--eval", program], {
    cwd: repoRoot,
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !["NODE_OPTIONS", "NODE_PATH"].includes(name))),
      IBEX_TEST_PROMOTION_SELECTION: JSON.stringify({ repoRoot, ...selection }),
    },
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30_000,
  });
}

function checkedAdmissionResult(repoRoot, selection = {}) {
  const result = runCheckedAdmission(repoRoot, {
    expectedSourceRevision: selection.expectedSourceRevision,
    artifactId: selection.artifactId ?? artifactId,
  });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function assertCheckedAdmissionRefuses(repoRoot, selection, pattern) {
  const result = runCheckedAdmission(repoRoot, selection);
  assert.notEqual(result.status, 0, `checked admission unexpectedly accepted: ${result.stdout}`);
  assert.match(result.stderr, pattern);
}

describe("portable engine promotion admission schema and foundation", () => {
  test("the production trust adapter is explicitly Darwin-only", () => {
    assert.equal(portableEnginePromotionLineagePlatformSupported("darwin"), true);
    assert.equal(portableEnginePromotionLineagePlatformSupported("linux"), false);
    assert.equal(portableEnginePromotionLineagePlatformSupported("win32"), false);
  });

  test("disabled checked catalog grants no authority and active vectors are schema-valid mechanics only", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(sourceRoot, schemaPath), "utf8"));
    const vectors = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/vectors/portable-engine-promotion-admission-v2.valid.json"), "utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    assert.equal(validate(vectors.disabledCatalog), true, JSON.stringify(validate.errors));
    assert.equal(validate(vectors.activeCatalog), true, JSON.stringify(validate.errors));
    assert.equal(
      semanticDigest(admissionDomain, vectors.activeCatalog.admissions[0], ["admissionDigest"]),
      vectors.activeCatalog.admissions[0].admissionDigest,
    );

    const foundationBytes = fs.readFileSync(path.join(sourceRoot, catalogPath));
    const foundation = parseJsonStrict(foundationBytes, "checked promotion foundation");
    assert.equal(foundationBytes.toString("utf8"), `${canonicalJson(foundation)}\n`);
    assert.equal(foundation.schema, "ibex/portable-engine-promotion-admission-catalog/1");
    assert.equal(foundation.enabled, false);
    assert.deepEqual(foundation.admissions, []);
    assert.equal(vectors.disabledCatalog.admissionPath, catalogPath, "v2 changes the contract, never the tracked catalog path");

    const policy = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/portable-engine-provenance-trust-policy-v1.json"), "utf8"));
    const attestations = JSON.parse(fs.readFileSync(path.join(sourceRoot, targetAttestationPath), "utf8"));
    const advertisements = JSON.parse(fs.readFileSync(path.join(sourceRoot, targetAdvertisementPath), "utf8"));
    assert.equal(policy.portableArtifactAcceptanceEnabled, false);
    assert.deepEqual(attestations.attestations, []);
    assert.deepEqual(advertisements.advertisements, []);
  });

  test("schema rejects a disabled nonempty catalog and an active empty catalog", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(sourceRoot, schemaPath), "utf8"));
    const vectors = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/vectors/portable-engine-promotion-admission-v2.valid.json"), "utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    assert.equal(validate({ ...vectors.activeCatalog, enabled: false }), false);
    assert.equal(validate({ ...vectors.disabledCatalog, enabled: true }), false);
  });

  test("admission artifact bounds cover the scope-bearing 15-row graph through 100,003 rows", () => {
    const schema = JSON.parse(
      fs.readFileSync(path.join(sourceRoot, schemaPath), "utf8"),
    );
    assert.equal(schema.$defs.admission.properties.artifacts.minItems, 15);
    assert.equal(schema.$defs.admission.properties.artifacts.maxItems, 100_003);
    const vectors = JSON.parse(
      fs.readFileSync(
        path.join(
          sourceRoot,
          "schemas/vectors/portable-engine-promotion-admission-v2.valid.json",
        ),
        "utf8",
      ),
    );
    const validate = new Ajv2020({ allErrors: false, strict: true }).compile(
      schema,
    );
    const minimum = structuredClone(vectors.activeCatalog);
    assert.equal(minimum.admissions[0].artifacts.length, 15);
    assert.equal(validate(minimum), true, JSON.stringify(validate.errors));

    const belowMinimum = structuredClone(minimum);
    belowMinimum.admissions[0].artifacts.pop();
    assert.equal(validate(belowMinimum), false);

    const emptyTuple = structuredClone(minimum);
    emptyTuple.admissions[0].target.features = [];
    assert.equal(validate(emptyTuple), false, "an active scope identity must carry a non-empty feature tuple");

    // Validate the array cardinality boundary independently. Running the full
    // unique-object comparison over 100,003 synthetic rows would turn this
    // contract test into a quadratic stress test unrelated to admission.
    const validateBounds = new Ajv2020({ strict: true }).compile({
      type: "array",
      minItems: schema.$defs.admission.properties.artifacts.minItems,
      maxItems: schema.$defs.admission.properties.artifacts.maxItems,
    });
    assert.equal(validateBounds(new Array(100_003)), true);
    assert.equal(validateBounds(new Array(100_004)), false);
  });

  test("checked admission schema freezes one common A/C result shape", () => {
    const schema = JSON.parse(fs.readFileSync(path.join(sourceRoot, checkedAdmissionSchemaPath), "utf8"));
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    const vectors = JSON.parse(fs.readFileSync(path.join(sourceRoot, "schemas/vectors/portable-engine-promotion-admission-v2.valid.json"), "utf8"));
    const diagnostic = vectors.checkedDiagnostic;
    assert.equal(validate(diagnostic), true, JSON.stringify(validate.errors));
    assert.equal(validate({ ...diagnostic, authorized: true }), false);
    assert.equal(validate({ ...diagnostic, note: "open field" }), false);
    const diagnosticWithoutSelectedFeatures = structuredClone(diagnostic);
    diagnosticWithoutSelectedFeatures.target.features = [];
    assert.equal(validate(diagnosticWithoutSelectedFeatures), true, JSON.stringify(validate.errors));
    const authorizedWithoutFeatures = structuredClone(vectors.checkedAuthorized);
    authorizedWithoutFeatures.target.features = [];
    assert.equal(validate(authorizedWithoutFeatures), false);
  });
});

describe("M27 evolvable scoped promotion history", () => {
  test("F6a authenticates genesis at the pinned floor's first parent only", async () => {
    const fixture = await initializeHistoryRepository();
    const startRevision = git(fixture.repoRoot, ["rev-parse", "HEAD"]).trim();
    assert.equal(resolveHistory(fixture.repoRoot, startRevision), null);
    const floorParents = git(fixture.repoRoot, ["show", "-s", "--format=%P", lineageFloor]).trim().split(" ");
    assert.equal(floorParents.length, 2, "the pinned floor is load-bearingly a merge");
    const first = spawnSync("/usr/bin/git", ["cat-file", "-e", `${floorParents[0]}:${catalogPath}`], {
      cwd: fixture.repoRoot,
      env: gitEnvironment,
      encoding: "utf8",
    });
    const second = spawnSync("/usr/bin/git", ["cat-file", "-e", `${floorParents[1]}:${catalogPath}`], {
      cwd: fixture.repoRoot,
      env: gitEnvironment,
      encoding: "utf8",
    });
    assert.notEqual(first.status, 0, "the floor's first parent must lack the catalog");
    assert.equal(second.status, 0, "the second parent is intentionally not part of the genesis absence claim");
  });

  test("F6b skips inherited active catalogs across ordinary commits, reset, and promotion 2", async () => {
    const fixture = await initializeHistoryRepository();
    const promotion1 = await createHistoryPromotion(fixture);
    await resetHistoryRepository(fixture, { ordinaryCommits: 2 });

    // Round 1 selected the newest revision merely carrying an enabled catalog.
    // That negative-control algorithm selects the ordinary descendant, not R1,
    // so this fixture would fail against the round-1 text.
    assert.equal(roundOneCatalogCarrier(fixture.repoRoot, fixture.resetRevision), fixture.ordinaryRevision);
    assert.notEqual(fixture.ordinaryRevision, promotion1.mergeRevision);

    const promotion2 = await createHistoryPromotion(fixture, {
      predecessorScopeDigest: promotion1.declaredScopeDigest,
    });
    const prior = resolveHistory(fixture.repoRoot, promotion2.sourceRevision);
    assert.equal(prior.admittedScopeDigest, promotion1.declaredScopeDigest);
    assert.equal(
      promotion2.scope.predecessor.scopeDigest,
      prior.admittedScopeDigest,
    );
  });

  test("F6c and F6d refuse a stale predecessor and false genesis relative to intact history", async () => {
    const fixture = await initializeHistoryRepository();
    const promotion1 = await createHistoryPromotion(fixture);
    await resetHistoryRepository(fixture, { ordinaryCommits: 1 });
    const prior = resolveHistory(fixture.repoRoot, fixture.resetRevision);
    assert.equal(prior.admittedScopeDigest, promotion1.declaredScopeDigest);
    assert.throws(
      () => verifyPortableEngineScopePredecessor({
        repoRoot: fixture.repoRoot,
        startRevision: fixture.resetRevision,
        target: clone(target),
        predecessorScopeDigest: digest("O"),
      }),
      /does not equal the latest admitted scope/u,
      "a stale digest must exercise the same production refusal as the current promotion",
    );
    assert.throws(
      () => verifyPortableEngineScopePredecessor({
        repoRoot: fixture.repoRoot,
        startRevision: fixture.resetRevision,
        target: clone(target),
        predecessorScopeDigest: "genesis",
      }),
      /does not equal the latest admitted scope/u,
      "false genesis must exercise the same production refusal as the current promotion",
    );
  });

  test("F6e closes shallow, graft, and replace-ref truncation without claiming reconstruction resistance", async () => {
    const fixture = await initializeHistoryRepository();
    const shallowRoot = path.join(fixture.root, "shallow");
    git(fixture.root, ["clone", "--quiet", "--depth", "1", `file://${fixture.repoRoot}`, shallowRoot]);
    const shallowHead = git(shallowRoot, ["rev-parse", "HEAD"]).trim();
    assert.throws(
      () => resolveHistory(shallowRoot, shallowHead),
      /shallow repository/u,
      "F6e covers history truncation; it deliberately does not claim to close reconstruction on the pinned floor",
    );

    const graftPath = path.join(fixture.repoRoot, ".git/info/grafts");
    await fsp.mkdir(path.dirname(graftPath), { recursive: true });
    await fsp.writeFile(graftPath, `${git(fixture.repoRoot, ["rev-parse", "HEAD"]).trim()} ${lineageFloor}\n`);
    assert.throws(() => resolveHistory(fixture.repoRoot, git(fixture.repoRoot, ["rev-parse", "HEAD"]).trim()), /grafts control/u);
    await fsp.rm(graftPath);

    const head = git(fixture.repoRoot, ["rev-parse", "HEAD"]).trim();
    git(fixture.repoRoot, ["replace", head, lineageFloor]);
    assert.throws(() => resolveHistory(fixture.repoRoot, head), /replace refs/u);
  });

  test("F6f tree-unbacked variants pass admission shape and fail the M27(i) joins", async () => {
    for (const [variant, pattern] of [
      ["missing-scope-row", /changed-path set mismatch/u],
      ["scope-row-object-mismatch", /checked blob object ID mismatch/u],
      ["scope-row-size-mismatch", /checked blob size mismatch/u],
      ["scope-row-digest-mismatch", /checked blob raw digest mismatch/u],
      ["scope-digest-mismatch", /admittedScopeDigest is not backed/u],
    ]) {
      const fixture = await initializeHistoryRepository();
      const promotion = await createHistoryPromotion(fixture, { variant });
      assert.equal(
        promotion.admission.artifacts.filter((row) => row.role === "scope-artifact").length,
        1,
        `${variant} must reach M27(i) with the required scope-artifact role`,
      );
      if (variant === "missing-scope-row") {
        const scopePath = promotion.admission.artifacts.find(
          (row) => row.role === "scope-artifact",
        ).path;
        const trackedScope = spawnSync(
          "/usr/bin/git",
          ["cat-file", "-e", `${promotion.mergeRevision}:${scopePath}`],
          { cwd: fixture.repoRoot, env: gitEnvironment, encoding: "utf8" },
        );
        assert.notEqual(
          trackedScope.status,
          0,
          "missing-scope-row must retain the canonical row while omitting its blob from the merge tree",
        );
      }
      // This is the executable round-2 negative control: merge topology and
      // the unkeyed admission self-digest are both valid for every variant.
      assert.equal(roundTwoShapeOnlyAccepts(fixture.repoRoot, promotion), true);
      assert.throws(
        () => resolveHistory(fixture.repoRoot, promotion.mergeRevision),
        pattern,
        `${variant} must pass the round-2 predicate and fail the M27(i) joins`,
      );
    }
  });

  test("F6f-4 refuses a hop whose own advertisement contradicts its admitted scope", async () => {
    const fixture = await initializeHistoryRepository();
    const promotion = await createHistoryPromotion(fixture, { variant: "advertisement-mismatch" });
    assert.throws(
      () => resolveHistory(fixture.repoRoot, promotion.mergeRevision),
      /advertisement scopeDigest differs/u,
    );
  });

  test("F6f-5 accepts a new scope role only at the reserved evidence-prefix path", async () => {
    const fixture = await initializeHistoryRepository();
    const promotion = await createHistoryPromotion(fixture);
    const scopePath = promotion.admission.artifacts.find((row) => row.role === "scope-artifact").path;
    const oldHeadRolePredicate = spawnSync("/usr/bin/git", [
      "cat-file",
      "-e",
      `${promotion.sourceRevision}:${scopePath}`,
    ], { cwd: fixture.repoRoot, env: gitEnvironment, encoding: "utf8" });
    assert.notEqual(
      oldHeadRolePredicate.status,
      0,
      "HEAD before M19 refused this positive control by requiring every non-conformance role to pre-exist",
    );
    const admitted = resolveHistory(fixture.repoRoot, promotion.mergeRevision);
    assert.equal(admitted.admittedScopeDigest, promotion.declaredScopeDigest);
    assert.equal(scopePath.endsWith("/capsec-scope.json"), true);
  });

  test("current-schema historical hops also run the full portable graph checks", async () => {
    const fixture = await initializeHistoryRepository();
    const promotion = await createHistoryPromotion(fixture, {
      variant: "bundle-digest-mismatch",
    });
    assert.throws(
      () => resolveHistory(fixture.repoRoot, promotion.mergeRevision),
      /portable bundle manifest digest mismatch/u,
    );
  });

  test("historical dispatch refuses unknown scope schemas and enabled v1 catalogs", async () => {
    for (const [variant, pattern] of [
      ["unknown-scope-schema", /unsupported scope schema/u],
      ["enabled-v1-catalog", /enabled v1 catalog cannot anchor scoped lineage/u],
    ]) {
      const fixture = await initializeHistoryRepository();
      const promotion = await createHistoryPromotion(fixture, { variant });
      assert.throws(
        () => resolveHistory(fixture.repoRoot, promotion.mergeRevision),
        pattern,
      );
    }
  });

  test("F6g selection is per full tuple even when two scopes share one triple", async () => {
    const fixture = await initializeHistoryRepository();
    const promotion1 = await createHistoryPromotion(fixture);
    await resetHistoryRepository(fixture, { ordinaryCommits: 1 });
    const target2 = {
      triple: targetTriple,
      features: [...target.features, "scope-two"],
    };
    assert.equal(resolveHistory(fixture.repoRoot, fixture.resetRevision, target2), null, "T1 must not become T2's predecessor");
    assert.equal(resolveHistory(fixture.repoRoot, fixture.resetRevision, target).admittedScopeDigest, promotion1.declaredScopeDigest);
    const promotion2 = await createHistoryPromotion(fixture, {
      targetOverride: target2,
      predecessorScopeDigest: promotion1.declaredScopeDigest,
    });
    const actualPrior = resolveHistory(fixture.repoRoot, promotion2.sourceRevision, target2);
    assert.equal(actualPrior, null, "T2 correctly reaches fresh genesis despite T1 sharing its triple");
    assert.throws(
      () => verifyPortableEngineScopePredecessor({
        repoRoot: fixture.repoRoot,
        startRevision: promotion2.sourceRevision,
        target: target2,
        predecessorScopeDigest: promotion2.scope.predecessor.scopeDigest,
      }),
      /genesis scope must carry/u,
      "a T2 scope naming T1's digest is refused rather than creating cross-feature ancestry",
    );
  });
});

describe("portable engine checked Git promotion lineage", { skip: process.platform !== "darwin" }, () => {
  test("source A stays disabled while a genuinely valid complete v2 graph verifies at its exact one-commit PR merge C", async () => {
    const fixture = await createPromotionRepository();
    const result = verifiedResult(fixture.repoRoot);
    assert.equal(result.authorized, true);
    assert.equal(result.sourceRevision, fixture.sourceRevision);
    assert.equal(result.promotionTopicRevision, fixture.promotionTopicRevision);
    assert.equal(result.currentRevision, fixture.promotionMergeRevision);
    assert.equal(result.portableArtifactId, artifactId);

    git(fixture.repoRoot, ["switch", "--quiet", "--detach", fixture.sourceRevision]);
    const sourceResult = verifiedResult(fixture.repoRoot);
    assert.equal(sourceResult.authorized, false);
    assert.equal(sourceResult.admission, null);
  });

  test("the production checked selection binds source A and exact merge C separately", async () => {
    const fixture = await createPromotionRepository();
    const promoted = checkedAdmissionResult(fixture.repoRoot, { expectedSourceRevision: fixture.sourceRevision });
    assert.deepEqual(Object.keys(promoted).sort(), [
      "schema",
      "authorized",
      "currentRevision",
      "sourceRevision",
      "promotionTopicRevision",
      "sourceTreeObjectId",
      "target",
      "portableArtifactId",
      "admissionDigest",
      "admittedScopeDigest",
      "predecessorScopeDigest",
      "verificationDigest",
    ].sort());
    assert.equal(promoted.authorized, true);
    assert.equal(promoted.currentRevision, fixture.promotionMergeRevision);
    assert.equal(promoted.sourceRevision, fixture.sourceRevision);
    assert.equal(promoted.promotionTopicRevision, fixture.promotionTopicRevision);
    assert.equal(promoted.sourceTreeObjectId, fixture.sourceTreeObjectId);
    assert.deepEqual(promoted.target, target);
    assert.equal(promoted.portableArtifactId, artifactId);
    assert.match(promoted.admittedScopeDigest, /^sha256-[A-Za-z0-9_-]{43}$/u);
    assert.equal(promoted.predecessorScopeDigest, "genesis");
    assert.equal(
      promoted.verificationDigest,
      semanticDigest(checkedAdmissionDomain, promoted, ["verificationDigest"]),
    );
    const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
      JSON.parse(fs.readFileSync(path.join(sourceRoot, checkedAdmissionSchemaPath), "utf8")),
    );
    assert.equal(validate(promoted), true, JSON.stringify(validate.errors));

    git(fixture.repoRoot, ["switch", "--quiet", "--detach", fixture.sourceRevision]);
    const diagnostic = checkedAdmissionResult(fixture.repoRoot, { expectedSourceRevision: fixture.sourceRevision });
    assert.equal(diagnostic.authorized, false);
    assert.equal(diagnostic.currentRevision, fixture.sourceRevision);
    assert.equal(diagnostic.sourceRevision, fixture.sourceRevision);
    assert.equal(diagnostic.promotionTopicRevision, null);
    assert.equal(diagnostic.sourceTreeObjectId, null);
    assert.equal(diagnostic.admissionDigest, null);
    assert.deepEqual(diagnostic.target, { triple: targetTriple, features: [] });
    assert.equal(diagnostic.admittedScopeDigest, null);
    assert.equal(diagnostic.predecessorScopeDigest, null);
    assert.equal(
      diagnostic.verificationDigest,
      semanticDigest(checkedAdmissionDomain, diagnostic, ["verificationDigest"]),
    );
    assert.equal(validate(diagnostic), true, JSON.stringify(validate.errors));
  });

  test("checked selection refuses source, target, and artifact substitution", async () => {
    const fixture = await createPromotionRepository();
    const selection = {
      expectedSourceRevision: fixture.sourceRevision,
      artifactId,
    };
    assertCheckedAdmissionRefuses(
      fixture.repoRoot,
      { ...selection, expectedSourceRevision: "f".repeat(40) },
      /source revision differs/u,
    );
    assertCheckedAdmissionRefuses(
      fixture.repoRoot,
      { ...selection, targetTriple: "x86_64-apple-darwin" },
      /unknown option targetTriple/u,
    );
    assertCheckedAdmissionRefuses(
      fixture.repoRoot,
      { ...selection, artifactId: "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
      /artifact ID differs/u,
    );
  });

  test("a canonical linked worktree gitfile and packed symbolic ref both verify", async () => {
    const linkedFixture = await createPromotionRepository();
    const linkedRoot = path.join(linkedFixture.root, "linked-checkout");
    git(linkedFixture.repoRoot, ["worktree", "add", "--quiet", "--detach", linkedRoot, "HEAD"]);
    await fsp.symlink(
      path.join(sourceRoot, "node_modules"),
      path.join(linkedRoot, "node_modules"),
      "dir",
    );
    const linkedResult = verifiedResult(linkedRoot);
    assert.equal(linkedResult.authorized, true);
    assert.equal(linkedResult.currentRevision, linkedFixture.promotionMergeRevision);

    const packedFixture = await createPromotionRepository();
    git(packedFixture.repoRoot, ["pack-refs", "--all"]);
    const packedResult = verifiedResult(packedFixture.repoRoot);
    assert.equal(packedResult.authorized, true);
  });

  test("gitfile, symbolic-ref, and HTTP-alternate selector substitution is refused", async () => {
    const linkedFixture = await createPromotionRepository();
    const linkedRoot = path.join(linkedFixture.root, "linked-checkout");
    git(linkedFixture.repoRoot, ["worktree", "add", "--quiet", "--detach", linkedRoot, "HEAD"]);
    await fsp.symlink(
      path.join(sourceRoot, "node_modules"),
      path.join(linkedRoot, "node_modules"),
      "dir",
    );
    await fsp.link(path.join(linkedRoot, ".git"), path.join(linkedFixture.root, "gitfile-hardlink"));
    assertVerifierRefuses(linkedRoot, /trusted regular files must have one filesystem link/u);

    const refFixture = await createPromotionRepository();
    const refPath = path.join(refFixture.repoRoot, ".git", "refs", "heads", "main");
    const refTarget = path.join(refFixture.repoRoot, ".git", "refs", "heads", "main-target");
    await fsp.rename(refPath, refTarget);
    await fsp.symlink("main-target", refPath);
    assertVerifierRefuses(refFixture.repoRoot, /trusted file path must be canonical and symlink-free|checked Git .*failed/u);

    const alternateFixture = await createPromotionRepository();
    const infoRoot = path.join(alternateFixture.repoRoot, ".git", "objects", "info");
    await fsp.mkdir(infoRoot, { recursive: true });
    await fsp.writeFile(path.join(infoRoot, "http-alternates"), "https://example.invalid/objects\n");
    assertVerifierRefuses(alternateFixture.repoRoot, /Git HTTP object alternates: forbidden control path exists/u);
  });

  test("an unchanged later descendant cannot inherit an admission", async () => {
    const fixture = await createPromotionRepository({ laterDescendant: true });
    assertVerifierRefuses(fixture.repoRoot, /exact two-parent promotion merge/u);
    assertCheckedAdmissionRefuses(fixture.repoRoot, {
      expectedSourceRevision: fixture.sourceRevision,
      artifactId,
    }, /exact two-parent promotion merge/u);
  });

  test("fast-forward and squash-shaped single-parent promotion commits are refused", async () => {
    const fixture = await createPromotionRepository({ fastForward: true });
    assertVerifierRefuses(fixture.repoRoot, /exact two-parent promotion merge/u);
  });

  test("the promotion topic must be one direct commit from source A", async () => {
    const fixture = await createPromotionRepository({ topicHasTwoCommits: true });
    assertVerifierRefuses(fixture.repoRoot, /one direct commit whose sole parent/u);
  });

  test("source A must be the merge first parent and C must have P's exact tree", async () => {
    const wrongParent = await createPromotionRepository({ firstParentDrift: true });
    assertVerifierRefuses(wrongParent.repoRoot, /first parent must equal/u);
    const wrongTree = await createPromotionRepository({ mergeTreeDrift: true });
    assertVerifierRefuses(wrongTree.repoRoot, /merge tree must equal/u);
  });

  test("code drift fails even when the active catalog attempts to list it", async () => {
    const unlisted = await createPromotionRepository({ codeDrift: true });
    assertVerifierRefuses(unlisted.repoRoot, /changed-path set mismatch/u);
    const listed = await createPromotionRepository({ listedCodeDrift: true });
    assertVerifierRefuses(listed.repoRoot, /outside the source\/target\/artifact-scoped promotion namespace/u);
  });

  test("equivalent but unlisted files and renames fail the exact changed-path set", async () => {
    const extra = await createPromotionRepository({ unlistedEquivalent: true });
    assertVerifierRefuses(extra.repoRoot, /changed-path set mismatch/u);
    const renamed = await createPromotionRepository({ renameSourceBlob: true });
    assertVerifierRefuses(renamed.repoRoot, /exactly one conformance report/u);
  });

  test("copies of source blobs are refused even at an admitted evidence path", async () => {
    const fixture = await createPromotionRepository({ copySourceBlob: true });
    assertVerifierRefuses(fixture.repoRoot, /copied source blob is forbidden/u);
  });

  test("a self-authored manifest/core subset cannot impersonate the filesystem-verified graph", async () => {
    const fixture = await createPromotionRepository({
      fabricatedSubset: true,
    });
    assertVerifierRefuses(
      fixture.repoRoot,
      /expected 15\.\.100003 rows|manifest member count is outside the bound|no detached process/u,
    );
  });

  test("a manifest cannot omit one required detached-process member", async () => {
    const fixture = await createPromotionRepository({ missingProcess: true });
    assertVerifierRefuses(
      fixture.repoRoot,
      /expected 15\.\.100003 rows|omits portable bundle member process-0001\.command-attempt/u,
    );
  });

  test("promotion core bytes must be byte-exact members of the verified bundle graph", async () => {
    const fixture = await createPromotionRepository({
      bundleCoreMismatch: true,
    });
    assertVerifierRefuses(
      fixture.repoRoot,
      /portable-conformance-report: byte length mismatch|raw-content digest mismatch/u,
    );
  });

  test("manifest source-tree identity must derive from the admitted Git tree object", async () => {
    const fixture = await createPromotionRepository({
      sourceTreeMismatch: true,
    });
    assertVerifierRefuses(
      fixture.repoRoot,
      /source-tree identity differs from checked authority/u,
    );
  });

  test("a self-consistent target object must equal the exact source-A candidate target", async () => {
    const fixture = await createPromotionRepository({ targetMismatch: true });
    assertVerifierRefuses(
      fixture.repoRoot,
      /portable bundle target differs from checked authority/u,
    );
  });

  test("duplicate catalog rows and duplicate promoted blob objects are refused", async () => {
    const duplicateRow = await createPromotionRepository({ duplicateArtifactRow: true });
    assertVerifierRefuses(duplicateRow.repoRoot, /duplicate artifact path/u);
    const duplicateBlob = await createPromotionRepository({ duplicateEvidence: true });
    assertVerifierRefuses(duplicateBlob.repoRoot, /copied promotion blobs are forbidden/u);
  });

  test("executable, symlink, and submodule promotion artifacts are refused", async () => {
    const executable = await createPromotionRepository({ executableEvidence: true });
    assertVerifierRefuses(executable.repoRoot, /expected one checked regular blob/u);
    const symlink = await createPromotionRepository({ symlinkEvidence: true });
    assertVerifierRefuses(symlink.repoRoot, /expected one checked regular blob/u);
    const submodule = await createPromotionRepository({ submoduleEvidence: true });
    assertVerifierRefuses(submodule.repoRoot, /expected one checked regular blob/u);
  });

  test("the checked catalog itself cannot be a symlink or submodule", async () => {
    const symlink = await createPromotionRepository({ catalogSymlink: true });
    assertVerifierRefuses(symlink.repoRoot, /running authority .*catalog.*not a checked non-executable blob/u);
    const submodule = await createPromotionRepository({ catalogSubmodule: true });
    assertVerifierRefuses(submodule.repoRoot, /running authority .*catalog.*not a checked non-executable blob/u);
  });

  test("promotion-time verifier or schema drift is outside the exact path set", async () => {
    const moduleDrift = await createPromotionRepository({
      authorityDriftPath: "scripts/portable-engine-promotion-lineage.mjs",
    });
    assertVerifierRefuses(moduleDrift.repoRoot, /changed-path set mismatch/u);
    const schemaDrift = await createPromotionRepository({ authorityDriftPath: schemaPath });
    assertVerifierRefuses(schemaDrift.repoRoot, /changed-path set mismatch/u);
    const checkedSchemaDrift = await createPromotionRepository({ authorityDriftPath: checkedAdmissionSchemaPath });
    assertVerifierRefuses(checkedSchemaDrift.repoRoot, /changed-path set mismatch/u);
  });

  test("blob object, size, digest, and admission-digest substitutions fail", async () => {
    const wrongObject = await createPromotionRepository({
      mutateAdmission(admission) {
        admission.artifacts[0].blobObjectId = "f".repeat(40);
      },
    });
    assertVerifierRefuses(wrongObject.repoRoot, /checked blob object ID mismatch/u);
    const wrongSize = await createPromotionRepository({
      mutateAdmission(admission) {
        admission.artifacts[0].size += 1;
      },
    });
    assertVerifierRefuses(wrongSize.repoRoot, /checked blob size mismatch/u);
    const wrongDigest = await createPromotionRepository({
      mutateAdmission(admission) {
        admission.artifacts[0].digest = `sha256-${"f".repeat(64)}`;
      },
    });
    assertVerifierRefuses(wrongDigest.repoRoot, /checked blob raw digest mismatch/u);
    const wrongAdmissionDigest = await createPromotionRepository({ corruptAdmissionDigest: true });
    assertVerifierRefuses(wrongAdmissionDigest.repoRoot, /admissionDigest mismatch/u);
  });

  test("the admission path is fixed and unknown catalog fields fail closed", async () => {
    const wrongPath = await createPromotionRepository({
      mutateCatalog(catalog) {
        catalog.admissionPath = "capsec/conformance/portable-promotions/catalog.json";
      },
    });
    assertVerifierRefuses(wrongPath.repoRoot, /admissionPath must name the exact checked catalog path/u);
    const unknown = await createPromotionRepository({
      mutateCatalog(catalog) {
        catalog.note = "not-authority";
      },
    });
    assertVerifierRefuses(unknown.repoRoot, /expected exact fields/u);
  });

  test("dirty tracked or untracked state is refused", async () => {
    const fixture = await createPromotionRepository();
    await writeFile(fixture.repoRoot, "untracked.json", canonicalJson({ dirty: true }));
    assertVerifierRefuses(fixture.repoRoot, /exactly clean tracked and untracked worktree/u);
  });

  test("raw loose-object substitution is caught by independent Git object hashing", async () => {
    const fixture = await createPromotionRepository();
    const hostile = Buffer.from("hostile-but-same-object-name", "utf8");
    const loosePath = path.join(
      fixture.repoRoot,
      ".git",
      "objects",
      fixture.evidenceObjectId.slice(0, 2),
      fixture.evidenceObjectId.slice(2),
    );
    await fsp.chmod(loosePath, 0o600);
    await fsp.writeFile(
      loosePath,
      deflateSync(Buffer.concat([Buffer.from(`blob ${hostile.length}\0`, "ascii"), hostile])),
    );
    assertVerifierRefuses(fixture.repoRoot, /failed independent content hashing|checked Git cat-file failed/u);
  });
});
