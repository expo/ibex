#!/usr/bin/env bun

// @ref LLP 0035#portable-package-contract — the golden authority DAG binds
// each independently reviewed input projection before deriving artifact ID.
// @ref LLP 0035#cross-runner-conformance-authority — downstream descriptor,
// assignment, bundle, and detached-provenance digests form an acyclic chain.

import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../../..");
const vectorPath = path.join(
  repoRoot,
  "schemas/vectors/portable-engine-provenance-v1.valid.json",
);
const trustPolicyPath = path.join(
  repoRoot,
  "schemas/portable-engine-provenance-trust-policy-v1.json",
);
const schemasDir = path.join(repoRoot, "schemas");
const schemaFiles = [
  "portable-engine-common-v1.schema.json",
  "portable-engine-provenance-trust-policy-v1.schema.json",
  "portable-engine-source-tree-identity-v1.schema.json",
  "portable-engine-reviewed-profile-identity-v1.schema.json",
  "portable-engine-export-set-v1.schema.json",
  "portable-engine-header-set-v1.schema.json",
  "portable-engine-abi-contract-v1.schema.json",
  "portable-engine-host-tool-compatibility-v1.schema.json",
  "portable-engine-manifest-v1.schema.json",
  "portable-engine-installation-receipt-v1.schema.json",
  "portable-engine-artifact-identity-v1.schema.json",
  "mapped-engine-instance-identity-v1.schema.json",
  "portable-engine-suite-lineage-v1.schema.json",
  "portable-engine-shard-assignment-v1.schema.json",
  "portable-engine-assignment-bundle-v1.schema.json",
  "portable-engine-diagnostic-shard-manifest-v1.schema.json",
  "portable-engine-diagnostic-shard-bundle-v1.schema.json",
  "portable-engine-diagnostic-shard-provenance-v1.schema.json",
];
const documentSchemas = {
  trustPolicy: "portable-engine-provenance-trust-policy-v1.schema.json",
  sourceTreeIdentity: "portable-engine-source-tree-identity-v1.schema.json",
  reviewedProfileIdentity:
    "portable-engine-reviewed-profile-identity-v1.schema.json",
  requiredExports: "portable-engine-export-set-v1.schema.json",
  forbiddenExports: "portable-engine-export-set-v1.schema.json",
  headerSet: "portable-engine-header-set-v1.schema.json",
  abiContract: "portable-engine-abi-contract-v1.schema.json",
  manifest: "portable-engine-manifest-v1.schema.json",
  installationReceipt: "portable-engine-installation-receipt-v1.schema.json",
  portableIdentity: "portable-engine-artifact-identity-v1.schema.json",
  mappedInstance: "mapped-engine-instance-identity-v1.schema.json",
  suite: "portable-engine-suite-lineage-v1.schema.json",
  assignment: "portable-engine-shard-assignment-v1.schema.json",
  assignmentBundle: "portable-engine-assignment-bundle-v1.schema.json",
  diagnosticManifest:
    "portable-engine-diagnostic-shard-manifest-v1.schema.json",
  diagnosticBundle: "portable-engine-diagnostic-shard-bundle-v1.schema.json",
  diagnosticProvenance:
    "portable-engine-diagnostic-shard-provenance-v1.schema.json",
};

const mode = process.argv.slice(2).join(" ");
if (mode !== "--write" && mode !== "--check") {
  throw new Error(
    "usage: bun packages/ibex-devtools/src/scripts/update-portable-engine-provenance-vectors.mjs (--check|--write)",
  );
}

const originalVectorBytes = fs.readFileSync(vectorPath);
const vector = parseJsonStrict(originalVectorBytes, vectorPath);
const documents = vector.documents;
const checkedHostToolFixtureSources = new Map([
  [
    "share/compatibility/host-tools/input/smoke.js",
    path.join(
      repoRoot,
      "tests/fixtures/portable-engine/host-tools/smoke.js",
    ),
  ],
]);
for (const fixture of vector.rawFixtures.hostToolInputs) {
  const sourcePath = checkedHostToolFixtureSources.get(fixture.path);
  if (!sourcePath) {
    throw new Error(`host-tool fixture has no checked source: ${fixture.path}`);
  }
  fixture.bytesBase64 = fs.readFileSync(sourcePath).toString("base64");
}
if (
  checkedHostToolFixtureSources.size !== vector.rawFixtures.hostToolInputs.length
) {
  throw new Error("checked host-tool fixture membership differs from the vector");
}
documents.trustPolicy = parseJsonStrict(
  fs.readFileSync(trustPolicyPath),
  trustPolicyPath,
);

const ajv = new Ajv2020({ allErrors: true, strict: true });
for (const schemaFile of schemaFiles) {
  const schemaPath = path.join(schemasDir, schemaFile);
  ajv.addSchema(parseJsonStrict(fs.readFileSync(schemaPath), schemaPath));
}
const validateDocument = (schemaFile, document, label) => {
  const validate = ajv.getSchema(`https://ibex.dev/schemas/${schemaFile}`);
  if (!validate) throw new Error(`schema is not registered: ${schemaFile}`);
  if (!validate(document)) {
    throw new Error(`${label}: ${JSON.stringify(validate.errors)}`);
  }
};
const validateDocuments = (phase) => {
  for (const [documentName, schemaFile] of Object.entries(documentSchemas)) {
    validateDocument(
      schemaFile,
      documents[documentName],
      `${phase} ${documentName}`,
    );
  }
  documents.hostToolCompatibilityDocuments.forEach((document, index) =>
    validateDocument(
      "portable-engine-host-tool-compatibility-v1.schema.json",
      document,
      `${phase} hostToolCompatibilityDocuments[${index}]`,
    ),
  );
};
validateDocuments("input");

const digest = (domain, document, omitFields = []) =>
  computeDomainDigest(domain, document, omitFields);
const clone = (value) => structuredClone(value);
const rawDigest = (bytes) =>
  `sha256-${createHash("sha256").update(bytes).digest("hex")}`;
const rawDigestPrefix = (value, label) => {
  if (!/^sha256-[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label} is not a lowercase raw SHA-256 digest`);
  }
  return value.slice("sha256-".length, "sha256-".length + 12);
};
const assertSame = (actual, expected, label) => {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label}: mismatch`);
  }
};
const gitObjectId = (format, type, bytes) =>
  createHash(format)
    .update(`${type} ${bytes.length}\0`)
    .update(bytes)
    .digest("hex");

const commitObject = Buffer.from(
  vector.rawFixtures.sourceCommitObjectBase64,
  "base64",
);
const treeObject = Buffer.from(
  vector.rawFixtures.sourceTreeObjectBase64,
  "base64",
);
const sourceTreeIdentity = documents.sourceTreeIdentity;
sourceTreeIdentity.sourceRevisionObjectContent = {
  path: "META-INF/authority/source-tree/commit.content",
  digest: rawDigest(commitObject),
  size: commitObject.length,
  encoding: "raw-uncompressed-git-object-content",
};
sourceTreeIdentity.treeObjectContent = {
  path: "META-INF/authority/source-tree/tree.content",
  digest: rawDigest(treeObject),
  size: treeObject.length,
  encoding: "raw-uncompressed-git-object-content",
};
const targetPolicies = documents.trustPolicy.admittedTargets.filter(
  (row) => row.triple === documents.manifest.target.triple,
);
if (targetPolicies.length !== 1) {
  throw new Error("golden manifest target is not exactly admitted");
}
const targetPolicy = targetPolicies[0];
if (sourceTreeIdentity.gitObjectFormat !== targetPolicy.sourceTreeGitObjectFormat) {
  throw new Error("golden source-tree object format is not admitted");
}
sourceTreeIdentity.sourceRevision = gitObjectId(
  sourceTreeIdentity.gitObjectFormat,
  sourceTreeIdentity.sourceRevisionObjectType,
  commitObject,
);
const commitHeaderEnd = commitObject.indexOf(Buffer.from("\n\n", "ascii"));
if (commitHeaderEnd === -1) throw new Error("commit fixture has no header terminator");
const treeLines = commitObject
  .subarray(0, commitHeaderEnd)
  .toString("latin1")
  .split("\n")
  .filter((line) => line.startsWith("tree "));
if (treeLines.length !== 1) throw new Error("commit fixture must name one tree");
if (!/^tree [0-9a-f]+$/u.test(treeLines[0])) {
  throw new Error("commit fixture tree header is not lowercase hexadecimal");
}
sourceTreeIdentity.treeObjectId = treeLines[0].slice("tree ".length);
if (
  gitObjectId(
    sourceTreeIdentity.gitObjectFormat,
    sourceTreeIdentity.treeObjectType,
    treeObject,
  ) !== sourceTreeIdentity.treeObjectId
) {
  throw new Error("tree fixture does not match the commit tree edge");
}
documents.manifest.build.sourceRevision = sourceTreeIdentity.sourceRevision;

const profileReceiptBytes = Buffer.from(
  vector.rawFixtures.profileReceiptBytesBase64,
  "base64",
);
const profileReceipt = parseJsonStrict(
  profileReceiptBytes,
  "profile receipt fixture",
);
const { reviewedProfileIdentityDigest: _profileDigest, ...manifestProfile } =
  documents.manifest.profile;
assertSame(manifestProfile, targetPolicy.profile, "golden admitted profile");
if (
  profileReceipt.profileId !== targetPolicy.profile.id ||
  profileReceipt.targetVariant !== targetPolicy.profile.targetVariant ||
  profileReceipt.origin.kind !== targetPolicy.reviewedProfileOriginKind
) {
  throw new Error("profile receipt is not the admitted profile");
}
const reviewedSource = profileReceipt.origin.reviewedProfileIdentity;
if (reviewedSource.artifact === "facebook/hermes") {
  if (!/^[0-9a-f]{40}$/u.test(reviewedSource.sourceCommit)) {
    throw new Error("reviewed Hermes source commit is not 40 lowercase hex");
  }
  if (reviewedSource.sourceRef !== `${reviewedSource.sourceVersion}-stable`) {
    throw new Error("reviewed Hermes source ref is not derived from its version");
  }
  if (profileReceipt.origin.kind === "source-patched-cache") {
    const expectedCacheKey =
      `${reviewedSource.sourceCommit.slice(0, 12)}` +
      `-p${rawDigestPrefix(reviewedSource.patchStackDigest, "patch stack digest")}` +
      `-ba${rawDigestPrefix(
        reviewedSource.sourceBuildAuthorityDigests["scripts/build-hermes.sh"],
        "Apple build authority digest",
      )}` +
      `-bl${rawDigestPrefix(
        reviewedSource.sourceBuildAuthorityDigests[
          "scripts/build-hermes-linux.sh"
        ],
        "Linux build authority digest",
      )}` +
      `-a${rawDigestPrefix(
        reviewedSource.patchApplicationAuthorityDigest,
        "patch application authority digest",
      )}` +
      `-i${rawDigestPrefix(
        reviewedSource.patchIdentityAuthorityDigest,
        "patch identity authority digest",
      )}` +
      "-oapple";
    if (profileReceipt.origin.cacheKey !== expectedCacheKey) {
      throw new Error("profile receipt cache key is not the reviewed Release key");
    }
  }
  documents.manifest.source = {
    artifact: reviewedSource.artifact,
    sourceCommit: reviewedSource.sourceCommit,
    sourceRef: reviewedSource.sourceRef,
    sourceVersion: reviewedSource.sourceVersion,
    patchStackDigest: reviewedSource.patchStackDigest,
  };
}
documents.reviewedProfileIdentity.profileId = profileReceipt.profileId;
documents.reviewedProfileIdentity.targetVariant = profileReceipt.targetVariant;
documents.reviewedProfileIdentity.originKind = profileReceipt.origin.kind;
documents.reviewedProfileIdentity.receiptDigest = rawDigest(profileReceiptBytes);
documents.reviewedProfileIdentity.reviewedProfileIdentity = clone(
  profileReceipt.origin.reviewedProfileIdentity,
);
documents.manifest.profile.id = profileReceipt.profileId;
documents.manifest.profile.targetVariant = profileReceipt.targetVariant;

documents.manifest.build.sourceTreeDigest = digest(
  "ibex.portable-engine-source-tree-identity.v1",
  documents.sourceTreeIdentity,
);
documents.manifest.profile.reviewedProfileIdentityDigest = digest(
  "ibex.portable-engine-reviewed-profile-identity.v1",
  documents.reviewedProfileIdentity,
);
documents.manifest.interface.requiredExportsDigest = digest(
  "ibex.portable-engine-required-exports.v1",
  documents.requiredExports,
);
documents.manifest.interface.forbiddenExportsDigest = digest(
  "ibex.portable-engine-forbidden-exports.v1",
  documents.forbiddenExports,
);
documents.manifest.interface.headerSetDigest = digest(
  "ibex.portable-engine-header-set.v1",
  documents.headerSet,
);
documents.abiContract.headerSetDigest =
  documents.manifest.interface.headerSetDigest;
documents.abiContract.requiredExportsDigest =
  documents.manifest.interface.requiredExportsDigest;
documents.abiContract.forbiddenExportsDigest =
  documents.manifest.interface.forbiddenExportsDigest;
documents.manifest.interface.abiContractDigest = digest(
  "ibex.portable-engine-abi-contract.v1",
  documents.abiContract,
);
const compatibilityDocuments = documents.hostToolCompatibilityDocuments;
if (
  !Array.isArray(compatibilityDocuments) ||
  compatibilityDocuments.length !== documents.manifest.interface.hostTools.length
) {
  throw new Error("host tool and compatibility-document membership differs");
}
assertSame(
  compatibilityDocuments.map(({ toolRole, toolPath }) => ({
    toolRole,
    toolPath,
  })),
  targetPolicy.requiredHostTools,
  "golden required host-tool membership",
);
const existingGoldenAuthorityDigests = new Map(
  documents.manifest.build.authorityDigests.map((row) => [row.path, row.digest]),
);
documents.manifest.build.authorityDigests = targetPolicy.buildAuthorityPaths.map(
  (authorityPath) => ({
    path: authorityPath,
    // Core source-profile authorities retain their hand-authored receipt joins.
    // New outer-producer inputs receive stable synthetic fixture digests; this
    // updater is a schema-vector generator, never the physical packager.
    digest:
      existingGoldenAuthorityDigests.get(authorityPath) ??
      rawDigest(
        Buffer.from(
          `ibex portable engine golden build authority\0${authorityPath}`,
          "utf8",
        ),
      ),
  }),
);
assertSame(
  documents.manifest.build.authorityDigests.map((row) => row.path),
  targetPolicy.buildAuthorityPaths,
  "golden build-authority membership",
);
if (targetPolicy.nonSystemLoadableComponentPolicy !== "runtime-only") {
  throw new Error("unknown non-system loadable component policy");
}
const nonSystemLoadableComponents =
  documents.manifest.interface.loadableComponents.filter(
    (component) => !component.system,
  );
if (
  nonSystemLoadableComponents.length !== 1 ||
  nonSystemLoadableComponents[0].role !== "runtime" ||
  nonSystemLoadableComponents[0].path !== documents.manifest.runtimeComponent
) {
  throw new Error("golden non-system loadable component topology is not admitted");
}
for (const [mode, exportSet] of [
  ["required", documents.requiredExports],
  ["forbidden", documents.forbiddenExports],
]) {
  assertSame(
    exportSet.matchers,
    targetPolicy.exportPolicy[`${mode}Matchers`],
    `${mode} export matcher policy`,
  );
  const expectedComponents = nonSystemLoadableComponents
    .map(({ path: componentPath, digest: componentDigest }) => ({
      path: componentPath,
      digest: componentDigest,
    }))
    .sort((left, right) =>
      Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")),
    );
  assertSame(
    exportSet.components,
    expectedComponents,
    `${mode} export component completeness`,
  );
}
for (const hostTool of documents.manifest.interface.hostTools) {
  const matches = compatibilityDocuments.filter(
    (document) =>
      document.toolPath === hostTool.path && document.toolDigest === hostTool.digest,
  );
  if (matches.length !== 1) {
    throw new Error(`host tool has no unique compatibility document: ${hostTool.path}`);
  }
}

const rawJcsEntry = (pathname, document) => {
  const bytes = Buffer.from(canonicalJson(document), "utf8");
  return {
    kind: "regular",
    role: "metadata",
    path: pathname,
    digest: `sha256-${createHash("sha256").update(bytes).digest("hex")}`,
    size: bytes.length,
    executable: false,
  };
};
const rawFileEntry = (pathname, role, bytes, executable = false) => ({
  kind: "regular",
  role,
  path: pathname,
  digest: rawDigest(bytes),
  size: bytes.length,
  executable,
});
const hostToolAuthorityEntries = compatibilityDocuments.map((document) => {
  const compatibilityDigest = digest(
    "ibex.portable-engine-host-tool-compatibility.v1",
    document,
  );
  return rawJcsEntry(
    `META-INF/authority/host-tools/${compatibilityDigest}.json`,
    document,
  );
});
const authorityInputEntries = [
  { kind: "directory", role: "metadata", path: "META-INF" },
  {
    kind: "directory",
    role: "metadata",
    path: "META-INF/authority",
  },
  rawJcsEntry("META-INF/authority/abi-contract.json", documents.abiContract),
  rawJcsEntry(
    "META-INF/authority/forbidden-exports.json",
    documents.forbiddenExports,
  ),
  rawJcsEntry("META-INF/authority/header-set.json", documents.headerSet),
  {
    kind: "directory",
    role: "metadata",
    path: "META-INF/authority/host-tools",
  },
  ...hostToolAuthorityEntries,
  rawJcsEntry(
    "META-INF/authority/required-exports.json",
    documents.requiredExports,
  ),
  rawJcsEntry(
    "META-INF/authority/reviewed-profile-identity.json",
    documents.reviewedProfileIdentity,
  ),
  rawJcsEntry(
    "META-INF/authority/source-tree-identity.json",
    documents.sourceTreeIdentity,
  ),
  {
    kind: "directory",
    role: "metadata",
    path: "META-INF/authority/source-tree",
  },
  rawFileEntry(
    documents.sourceTreeIdentity.sourceRevisionObjectContent.path,
    "metadata",
    commitObject,
  ),
  rawFileEntry(
    documents.sourceTreeIdentity.treeObjectContent.path,
    "metadata",
    treeObject,
  ),
];
const rawHostToolInputs = new Map();
for (const fixture of vector.rawFixtures.hostToolInputs) {
  if (rawHostToolInputs.has(fixture.path)) {
    throw new Error(`duplicate raw host-tool fixture: ${fixture.path}`);
  }
  rawHostToolInputs.set(fixture.path, fixture);
}
const declaredFixturePaths = new Set();
const declaredWorkspacePaths = new Set();
for (const document of compatibilityDocuments) {
  for (const fixture of document.inputFixtures) {
    if (declaredFixturePaths.has(fixture.fixturePayloadPath)) {
      throw new Error(`duplicate fixture payload path: ${fixture.fixturePayloadPath}`);
    }
    if (declaredWorkspacePaths.has(fixture.workspacePath)) {
      throw new Error(`duplicate fixture workspace path: ${fixture.workspacePath}`);
    }
    const raw = rawHostToolInputs.get(fixture.fixturePayloadPath);
    if (!raw) {
      throw new Error(`fixture bytes are absent: ${fixture.fixturePayloadPath}`);
    }
    const bytes = Buffer.from(raw.bytesBase64, "base64");
    fixture.digest = rawDigest(bytes);
    fixture.size = bytes.length;
    fixture.executable = raw.executable;
    declaredFixturePaths.add(fixture.fixturePayloadPath);
    declaredWorkspacePaths.add(fixture.workspacePath);
  }
}
assertSame(
  [...declaredFixturePaths].sort(),
  [...rawHostToolInputs.keys()].sort(),
  "complete host-tool fixture declarations",
);
for (const hostTool of documents.manifest.interface.hostTools) {
  const matches = compatibilityDocuments.filter(
    (document) =>
      document.toolPath === hostTool.path && document.toolDigest === hostTool.digest,
  );
  if (matches.length !== 1) {
    throw new Error(`host tool has no unique compatibility document: ${hostTool.path}`);
  }
  hostTool.compatibilityDigest = digest(
    "ibex.portable-engine-host-tool-compatibility.v1",
    matches[0],
  );
}
const rawHostToolInputEntries = vector.rawFixtures.hostToolInputs.map(
  ({ path: fixturePath, bytesBase64, executable }) =>
    rawFileEntry(
      fixturePath,
      "compatibility-fixture",
      Buffer.from(bytesBase64, "base64"),
      executable,
    ),
);
const fixturePaths = new Set(rawHostToolInputEntries.map((entry) => entry.path));
const fixtureDirectoryPaths = new Set();
for (const fixturePath of fixturePaths) {
  const segments = fixturePath.split("/");
  for (let length = 1; length < segments.length; length += 1) {
    fixtureDirectoryPaths.add(segments.slice(0, length).join("/"));
  }
}
let manifestEntries = documents.manifest.entries
  .filter(
    (entry) =>
      entry.path !== "META-INF" &&
      entry.path !== "META-INF/authority" &&
      !entry.path.startsWith("META-INF/authority/"),
  )
  .filter(
    (entry) =>
      entry.path !== documents.reviewedProfileIdentity.receiptPath &&
      entry.role !== "compatibility-fixture",
  );
const existingDirectories = new Set(
  manifestEntries
    .filter((entry) => entry.kind === "directory")
    .map((entry) => entry.path),
);
const fixtureDirectoryEntries = [...fixtureDirectoryPaths]
  .filter((directoryPath) => !existingDirectories.has(directoryPath))
  .map((directoryPath) => ({
    kind: "directory",
    role: "compatibility-fixture",
    path: directoryPath,
  }));
manifestEntries = manifestEntries
  .concat(authorityInputEntries)
  .concat(fixtureDirectoryEntries)
  .concat(rawHostToolInputEntries)
  .concat(
    rawFileEntry(
      documents.reviewedProfileIdentity.receiptPath,
      "profile-receipt",
      profileReceiptBytes,
    ),
  );
documents.manifest.entries = manifestEntries
  .sort((left, right) =>
    Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")),
  );
documents.manifest.artifactId = digest(
  "ibex.portable-engine-manifest.v1",
  documents.manifest,
  ["artifactId"],
);

const receipt = documents.installationReceipt;
receipt.artifactId = documents.manifest.artifactId;
receipt.manifestDigest = digest(
  "ibex.portable-engine-manifest-digest.v1",
  documents.manifest,
);
receipt.verificationPolicyDigest = digest(
  "ibex.portable-engine-provenance-trust-policy.v1",
  documents.trustPolicy,
);
receipt.repository = documents.manifest.build.repository;
receipt.publisherWorkflow = documents.manifest.build.publisherWorkflow;
receipt.sourceRef = documents.manifest.build.sourceRef;
receipt.sourceRevision = documents.manifest.build.sourceRevision;
const rawBundle = Buffer.from(
  vector.rawFixtures.detachedBundleByteProjectionBase64,
  "base64",
);
parseJsonStrict(rawBundle, "engine provenance bundle fixture");
receipt.provenanceBundleDigest = rawDigest(rawBundle);

const runtime = documents.manifest.interface.loadableComponents.find(
  (row) =>
    row.system === false &&
    row.role === "runtime" &&
    row.path === documents.manifest.runtimeComponent,
);
if (!runtime) throw new Error("manifest has no exact runtime component");
const { reviewedProfileIdentityDigest, ...portableProfile } =
  documents.manifest.profile;
documents.portableIdentity = {
  schema: "ibex/portable-engine-artifact-identity/1",
  artifactId: documents.manifest.artifactId,
  artifactKind: documents.manifest.artifactKind,
  target: clone(documents.manifest.target),
  profile: portableProfile,
  runtimeComponentDigest: runtime.digest,
  reviewedProfileIdentityDigest,
  interfaceContractDigest: digest(
    "ibex.portable-engine-interface.v1",
    documents.manifest.interface,
  ),
};

documents.mappedInstance.portable = clone(documents.portableIdentity);
documents.mappedInstance.before.digest = runtime.digest;
documents.mappedInstance.after.digest = runtime.digest;
documents.mappedInstance.observationDigest = digest(
  "ibex.mapped-engine-instance-identity.v1",
  documents.mappedInstance,
  ["observationDigest"],
);

const suite = documents.suite;
suite.sourceRevision = documents.manifest.build.sourceRevision;
suite.sourceTreeDigest = documents.manifest.build.sourceTreeDigest;
suite.target = clone(documents.manifest.target);
suite.portableArtifactId = documents.manifest.artifactId;

const assignment = documents.assignment;
assignment.suiteLineageId = suite.suiteLineageId;
assignment.suiteDescriptorDigest = digest(
  "ibex.portable-engine-suite-lineage.v1",
  suite,
);
documents.assignmentBundle.suite = clone(suite);
documents.assignmentBundle.assignments = [clone(assignment)];

const diagnosticManifest = documents.diagnosticManifest;
diagnosticManifest.suiteLineageId = suite.suiteLineageId;
diagnosticManifest.suitePlanDigest = suite.suitePlanDigest;
diagnosticManifest.assignmentDigest = digest(
  "ibex.portable-engine-shard-assignment.v1",
  assignment,
);
diagnosticManifest.sourceRevision = suite.sourceRevision;
diagnosticManifest.sourceTreeDigest = suite.sourceTreeDigest;
diagnosticManifest.target = clone(suite.target);
diagnosticManifest.engineProfile = documents.portableIdentity.profile.id;
diagnosticManifest.featureSet = clone(suite.target.structuralFeatures);
diagnosticManifest.portableEngine = clone(documents.portableIdentity);
diagnosticManifest.mappedEngine = clone(documents.mappedInstance);
diagnosticManifest.manifestDigest = digest(
  "ibex.portable-engine-diagnostic-shard-manifest.v1",
  diagnosticManifest,
  ["manifestDigest"],
);

const diagnosticBundle = documents.diagnosticBundle;
diagnosticBundle.assignmentBundle = clone(documents.assignmentBundle);
diagnosticBundle.manifest = clone(diagnosticManifest);
diagnosticBundle.coordinatorProvenance.subjectDigest = digest(
  "ibex.portable-engine-assignment-bundle.v1",
  documents.assignmentBundle,
);
diagnosticBundle.coordinatorProvenance.repository =
  suite.coordinatorWorkflow.repository;
diagnosticBundle.coordinatorProvenance.workflowPath =
  suite.coordinatorWorkflow.workflowPath;
diagnosticBundle.coordinatorProvenance.sourceRef =
  suite.coordinatorWorkflow.sourceRef;
diagnosticBundle.coordinatorProvenance.sourceRevision = suite.sourceRevision;
diagnosticBundle.engineDistributionProvenance.subjectDigest =
  receipt.archiveDigest;
diagnosticBundle.engineDistributionProvenance.provenanceBundleDigest =
  receipt.provenanceBundleDigest;
diagnosticBundle.engineDistributionProvenance.repository = receipt.repository;
diagnosticBundle.engineDistributionProvenance.workflowPath =
  receipt.publisherWorkflow;
diagnosticBundle.engineDistributionProvenance.sourceRef = receipt.sourceRef;
diagnosticBundle.engineDistributionProvenance.sourceRevision =
  receipt.sourceRevision;
diagnosticBundle.engineDistributionProvenance.runnerClass = receipt.runnerClass;
diagnosticBundle.sourceObservation.sourceRevision = suite.sourceRevision;
diagnosticBundle.sourceObservation.sourceTreeDigest = suite.sourceTreeDigest;

documents.diagnosticProvenance.subjectDigest = digest(
  "ibex.portable-engine-diagnostic-shard-bundle.v1",
  diagnosticBundle,
);
documents.diagnosticProvenance.repository =
  assignment.assignedShardWorkflow.repository;
documents.diagnosticProvenance.workflowPath =
  assignment.assignedShardWorkflow.workflowPath;
documents.diagnosticProvenance.sourceRef =
  assignment.assignedShardWorkflow.sourceRef;
documents.diagnosticProvenance.sourceRevision = suite.sourceRevision;

const projections = [
  [
    "source-tree-identity-digest",
    "sourceTreeIdentity",
    "ibex.portable-engine-source-tree-identity.v1",
    [],
  ],
  [
    "reviewed-profile-identity-digest",
    "reviewedProfileIdentity",
    "ibex.portable-engine-reviewed-profile-identity.v1",
    [],
  ],
  [
    "required-exports-digest",
    "requiredExports",
    "ibex.portable-engine-required-exports.v1",
    [],
  ],
  [
    "forbidden-exports-digest",
    "forbiddenExports",
    "ibex.portable-engine-forbidden-exports.v1",
    [],
  ],
  [
    "header-set-digest",
    "headerSet",
    "ibex.portable-engine-header-set.v1",
    [],
  ],
  [
    "abi-contract-digest",
    "abiContract",
    "ibex.portable-engine-abi-contract.v1",
    [],
  ],
  ...compatibilityDocuments.map((document, index) => [
    `host-tool-compatibility-digest:${document.toolPath}`,
    `hostToolCompatibilityDocuments.${index}`,
    "ibex.portable-engine-host-tool-compatibility.v1",
    [],
  ]),
  [
    "portable-artifact-id",
    "manifest",
    "ibex.portable-engine-manifest.v1",
    ["artifactId"],
  ],
  [
    "portable-manifest-digest",
    "manifest",
    "ibex.portable-engine-manifest-digest.v1",
    [],
  ],
  [
    "trust-policy-digest",
    "trustPolicy",
    "ibex.portable-engine-provenance-trust-policy.v1",
    [],
  ],
  [
    "interface-contract-digest",
    "manifest.interface",
    "ibex.portable-engine-interface.v1",
    [],
  ],
  [
    "mapped-observation-digest",
    "mappedInstance",
    "ibex.mapped-engine-instance-identity.v1",
    ["observationDigest"],
  ],
  [
    "suite-descriptor-digest",
    "suite",
    "ibex.portable-engine-suite-lineage.v1",
    [],
  ],
  [
    "shard-assignment-digest",
    "assignment",
    "ibex.portable-engine-shard-assignment.v1",
    [],
  ],
  [
    "assignment-bundle-digest",
    "assignmentBundle",
    "ibex.portable-engine-assignment-bundle.v1",
    [],
  ],
  [
    "diagnostic-manifest-digest",
    "diagnosticManifest",
    "ibex.portable-engine-diagnostic-shard-manifest.v1",
    ["manifestDigest"],
  ],
  [
    "diagnostic-shard-bundle-digest",
    "diagnosticBundle",
    "ibex.portable-engine-diagnostic-shard-bundle.v1",
    [],
  ],
];

const resolve = (dottedPath) =>
  dottedPath.split(".").reduce((value, key) => value[key], documents);
vector.projections = projections.map(
  ([id, documentPath, domain, omitFields]) => ({
    id,
    documentPath,
    domain,
    omitFields,
    expectedDigest: digest(domain, resolve(documentPath), omitFields),
  }),
);

const output = `${JSON.stringify(vector, null, 2)}\n`;
validateDocuments("output");
if (mode === "--check") {
  if (!originalVectorBytes.equals(Buffer.from(output, "utf8"))) {
    throw new Error(
      "portable engine provenance vectors are stale; rerun with --write",
    );
  }
  process.stdout.write("portable engine provenance vectors checked\n");
  process.exit(0);
}
const temporaryPath = `${vectorPath}.tmp-${process.pid}`;
try {
  fs.writeFileSync(temporaryPath, output, { flag: "wx" });
  fs.renameSync(temporaryPath, vectorPath);
} finally {
  if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
}
