// @ref LLP 0035#manifest — portable identity is an exact JCS/I-JSON manifest
// projection with typed digests, canonical sets, and a self-excluding ID.
// @ref LLP 0035#runtime-identity-split — portable identity must stay path-free,
// while mapped-instance evidence binds the local object and pre/post bytes.
// @ref LLP 0035#cross-runner-conformance-authority — coordinator assignment,
// diagnostic shard evidence, and detached provenance form an acyclic digest DAG.
// @ref LLP 0032#shard-manifest — shard manifests are exact-field records whose
// semantic digest omits only their own manifestDigest field.

import { describe, expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertIJson,
  assertNoDuplicateJsonKeys,
  canonicalJson,
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../../..");
const schemasDir = path.join(repoRoot, "schemas");
const vectorsDir = path.join(schemasDir, "vectors");

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

// Domain and projection are one contract. The full manifest gets a distinct
// domain from artifactId even though both start from the same schema object.
const baseProjectionContract = [
  {
    id: "source-tree-identity-digest",
    documentPath: "sourceTreeIdentity",
    domain: "ibex.portable-engine-source-tree-identity.v1",
    omitFields: [],
    boundPath: "manifest.build.sourceTreeDigest",
  },
  {
    id: "reviewed-profile-identity-digest",
    documentPath: "reviewedProfileIdentity",
    domain: "ibex.portable-engine-reviewed-profile-identity.v1",
    omitFields: [],
    boundPath: "manifest.profile.reviewedProfileIdentityDigest",
  },
  {
    id: "required-exports-digest",
    documentPath: "requiredExports",
    domain: "ibex.portable-engine-required-exports.v1",
    omitFields: [],
    boundPath: "manifest.interface.requiredExportsDigest",
  },
  {
    id: "forbidden-exports-digest",
    documentPath: "forbiddenExports",
    domain: "ibex.portable-engine-forbidden-exports.v1",
    omitFields: [],
    boundPath: "manifest.interface.forbiddenExportsDigest",
  },
  {
    id: "header-set-digest",
    documentPath: "headerSet",
    domain: "ibex.portable-engine-header-set.v1",
    omitFields: [],
    boundPath: "manifest.interface.headerSetDigest",
  },
  {
    id: "abi-contract-digest",
    documentPath: "abiContract",
    domain: "ibex.portable-engine-abi-contract.v1",
    omitFields: [],
    boundPath: "manifest.interface.abiContractDigest",
  },
  {
    id: "portable-artifact-id",
    documentPath: "manifest",
    domain: "ibex.portable-engine-manifest.v1",
    omitFields: ["artifactId"],
    boundPath: "manifest.artifactId",
  },
  {
    id: "portable-manifest-digest",
    documentPath: "manifest",
    domain: "ibex.portable-engine-manifest-digest.v1",
    omitFields: [],
    boundPath: "installationReceipt.manifestDigest",
  },
  {
    id: "trust-policy-digest",
    documentPath: "trustPolicy",
    domain: "ibex.portable-engine-provenance-trust-policy.v1",
    omitFields: [],
    boundPath: "installationReceipt.verificationPolicyDigest",
  },
  {
    id: "interface-contract-digest",
    documentPath: "manifest.interface",
    domain: "ibex.portable-engine-interface.v1",
    omitFields: [],
    boundPath: "portableIdentity.interfaceContractDigest",
  },
  {
    id: "mapped-observation-digest",
    documentPath: "mappedInstance",
    domain: "ibex.mapped-engine-instance-identity.v1",
    omitFields: ["observationDigest"],
    boundPath: "mappedInstance.observationDigest",
  },
  {
    id: "suite-descriptor-digest",
    documentPath: "suite",
    domain: "ibex.portable-engine-suite-lineage.v1",
    omitFields: [],
    boundPath: "assignment.suiteDescriptorDigest",
  },
  {
    id: "shard-assignment-digest",
    documentPath: "assignment",
    domain: "ibex.portable-engine-shard-assignment.v1",
    omitFields: [],
    boundPath: "diagnosticManifest.assignmentDigest",
  },
  {
    id: "assignment-bundle-digest",
    documentPath: "assignmentBundle",
    domain: "ibex.portable-engine-assignment-bundle.v1",
    omitFields: [],
    boundPath: "diagnosticBundle.coordinatorProvenance.subjectDigest",
  },
  {
    id: "diagnostic-manifest-digest",
    documentPath: "diagnosticManifest",
    domain: "ibex.portable-engine-diagnostic-shard-manifest.v1",
    omitFields: ["manifestDigest"],
    boundPath: "diagnosticManifest.manifestDigest",
  },
  {
    id: "diagnostic-shard-bundle-digest",
    documentPath: "diagnosticBundle",
    domain: "ibex.portable-engine-diagnostic-shard-bundle.v1",
    omitFields: [],
    boundPath: "diagnosticProvenance.subjectDigest",
  },
];

const publisherTrust = {
  repository: "ccheever/ibex",
  workflowPath: ".github/workflows/hermes-artifacts.yml",
  sourceRef: "refs/heads/main",
  runnerClass: "github-hosted",
};

function readStrict(filePath) {
  return parseJsonStrict(fs.readFileSync(filePath), path.relative(repoRoot, filePath));
}

function loadInvalidVectors() {
  const filePath = path.join(
    vectorsDir,
    "portable-engine-provenance-v1.invalid.json",
  );
  const bytes = fs.readFileSync(filePath);
  const text = bytes.toString("utf8");
  assertNoDuplicateJsonKeys(text, path.relative(repoRoot, filePath));
  const value = JSON.parse(text);
  assertIJson(value, path.relative(repoRoot, filePath));
  return value;
}

const validVectors = readStrict(
  path.join(vectorsDir, "portable-engine-provenance-v1.valid.json"),
);
const abiProjectionIndex = baseProjectionContract.findIndex(
  (projection) => projection.id === "abi-contract-digest",
);
if (abiProjectionIndex === -1) throw new Error("ABI projection is absent");
const hostToolProjectionContract =
  validVectors.documents.hostToolCompatibilityDocuments.map(
    (document, documentIndex) => {
      const hostToolIndices = validVectors.documents.manifest.interface.hostTools
        .map((tool, index) => ({ index, tool }))
        .filter(
          ({ tool }) =>
            tool.path === document.toolPath && tool.digest === document.toolDigest,
        )
        .map(({ index }) => index);
      if (hostToolIndices.length !== 1) {
        throw new Error(
          `host-tool projection has no unique manifest row: ${document.toolPath}`,
        );
      }
      return {
        id: `host-tool-compatibility-digest:${document.toolPath}`,
        documentPath: `hostToolCompatibilityDocuments.${documentIndex}`,
        domain: "ibex.portable-engine-host-tool-compatibility.v1",
        omitFields: [],
        boundPath: `manifest.interface.hostTools.${hostToolIndices[0]}.compatibilityDigest`,
      };
    },
  );
const projectionContract = [
  ...baseProjectionContract.slice(0, abiProjectionIndex + 1),
  ...hostToolProjectionContract,
  ...baseProjectionContract.slice(abiProjectionIndex + 1),
];
const checkedTrustPolicy = readStrict(
  path.join(schemasDir, "portable-engine-provenance-trust-policy-v1.json"),
);
const invalidVectors = loadInvalidVectors();

function buildAjv() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const file of schemaFiles) {
    ajv.addSchema(readStrict(path.join(schemasDir, file)));
  }
  return ajv;
}

function validatorFor(ajv, schemaFile) {
  const validate = ajv.getSchema(`https://ibex.dev/schemas/${schemaFile}`);
  if (!validate) throw new Error(`schema was not registered: ${schemaFile}`);
  return validate;
}

function assertSchemaValid(ajv, schemaFile, value, label) {
  const validate = validatorFor(ajv, schemaFile);
  if (!validate(value)) {
    throw new Error(`${label}: ${JSON.stringify(validate.errors)}`);
  }
}

function resolvePath(root, dottedPath) {
  return dottedPath.split(".").reduce((value, key) => value[key], root);
}

function pointerTokens(pointer) {
  if (pointer === "") return [];
  if (!pointer.startsWith("/")) throw new Error(`invalid JSON pointer: ${pointer}`);
  return pointer
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
}

function pointerValue(root, pointer) {
  return pointerTokens(pointer).reduce((value, token) => value[token], root);
}

function pointerParent(root, pointer) {
  const tokens = pointerTokens(pointer);
  if (tokens.length === 0) throw new Error("cannot mutate the document root");
  const key = tokens.pop();
  const parent = tokens.reduce((value, token) => value[token], root);
  return { key, parent };
}

function applyMutation(document, mutation) {
  if (mutation.op === "sequence") {
    mutation.mutations.forEach((item) => applyMutation(document, item));
    return;
  }
  if (mutation.op === "swap") {
    const array = pointerValue(document, mutation.path);
    const [left, right] = mutation.indices;
    [array[left], array[right]] = [array[right], array[left]];
    return;
  }

  const { key, parent } = pointerParent(document, mutation.path);
  if (mutation.op === "remove") {
    if (Array.isArray(parent)) parent.splice(Number(key), 1);
    else delete parent[key];
    return;
  }
  if (mutation.op === "add" || mutation.op === "replace") {
    if (mutation.op === "add" && Array.isArray(parent)) {
      parent.splice(Number(key), 0, structuredClone(mutation.value));
    } else {
      parent[key] = structuredClone(mutation.value);
    }
    return;
  }
  throw new Error(`unsupported mutation: ${mutation.op}`);
}

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertSame(actual, expected, label) {
  invariant(canonicalJson(actual) === canonicalJson(expected), `${label}: mismatch`);
}

function assertExactFields(value, expected, label) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label}: expected object`,
  );
  const actual = Object.keys(value).sort(utf8Compare);
  const sortedExpected = [...expected].sort(utf8Compare);
  assertSame(actual, sortedExpected, `${label} exact fields`);
}

function rawSha256(bytes) {
  return `sha256-${createHash("sha256").update(bytes).digest("hex")}`;
}

function rawDigestPrefix(value, label) {
  invariant(
    /^sha256-[0-9a-f]{64}$/u.test(value),
    `${label}: not a lowercase raw SHA-256 digest`,
  );
  return value.slice("sha256-".length, "sha256-".length + 12);
}

function gitObjectId(format, type, bytes) {
  invariant(format === "sha1" || format === "sha256", "unsupported Git object format");
  return createHash(format)
    .update(`${type} ${bytes.length}\0`)
    .update(bytes)
    .digest("hex");
}

function assertNfc(value, label = "$") {
  if (typeof value === "string") {
    invariant(value.normalize("NFC") === value, `${label}: string is not NFC`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNfc(item, `${label}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    invariant(key.normalize("NFC") === key, `${label}: key is not NFC`);
    assertNfc(child, `${label}.${key}`);
  }
}

function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function assertSortedUnique(rows, keyOf, label, { requireNfc = true } = {}) {
  let prior;
  for (const [index, row] of rows.entries()) {
    const key = keyOf(row);
    if (requireNfc) {
      invariant(key.normalize("NFC") === key, `${label}[${index}]: key is not NFC`);
    }
    if (prior !== undefined) {
      invariant(
        utf8Compare(prior, key) < 0,
        `${label}: rows are not strictly sorted and unique`,
      );
    }
    prior = key;
  }
}

function assertStringSet(values, label) {
  assertSortedUnique(values, (value) => value, label);
}

function assertExactUtf8StringSet(values, label) {
  assertSortedUnique(values, (value) => value, label, { requireNfc: false });
}

function rawJcsEntry(pathname, document) {
  const bytes = Buffer.from(canonicalJson(document), "utf8");
  return {
    kind: "regular",
    role: "metadata",
    path: pathname,
    digest: `sha256-${createHash("sha256").update(bytes).digest("hex")}`,
    size: bytes.length,
    executable: false,
  };
}

function expectedAuthorityInputEntries(documents) {
  const hostToolEntries = documents.hostToolCompatibilityDocuments.map(
    (document) => {
      const compatibilityDigest = computeDomainDigest(
        "ibex.portable-engine-host-tool-compatibility.v1",
        document,
      );
      return rawJcsEntry(
        `META-INF/authority/host-tools/${compatibilityDigest}.json`,
        document,
      );
    },
  );
  const rows = [
    {
      kind: "directory",
      role: "metadata",
      path: "META-INF",
    },
    {
      kind: "directory",
      role: "metadata",
      path: "META-INF/authority",
    },
    rawJcsEntry(
      "META-INF/authority/abi-contract.json",
      documents.abiContract,
    ),
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
    ...hostToolEntries,
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
    {
      kind: "regular",
      role: "metadata",
      path: documents.sourceTreeIdentity.sourceRevisionObjectContent.path,
      digest: documents.sourceTreeIdentity.sourceRevisionObjectContent.digest,
      size: documents.sourceTreeIdentity.sourceRevisionObjectContent.size,
      executable: false,
    },
    {
      kind: "regular",
      role: "metadata",
      path: documents.sourceTreeIdentity.treeObjectContent.path,
      digest: documents.sourceTreeIdentity.treeObjectContent.digest,
      size: documents.sourceTreeIdentity.treeObjectContent.size,
      executable: false,
    },
  ];
  return rows.sort((left, right) => utf8Compare(left.path, right.path));
}

function admittedTarget(triple) {
  const matches = checkedTrustPolicy.admittedTargets.filter(
    (row) => row.triple === triple,
  );
  invariant(matches.length === 1, `target is not exactly admitted: ${triple}`);
  return matches[0];
}

function admittedNonSystemLoadableComponents(manifest, targetPolicy) {
  invariant(
    targetPolicy.nonSystemLoadableComponentPolicy === "runtime-only",
    "unknown non-system loadable component policy",
  );
  const components = manifest.interface.loadableComponents.filter(
    (component) => !component.system,
  );
  invariant(
    components.length === 1 &&
      components[0].role === "runtime" &&
      components[0].path === manifest.runtimeComponent,
    "non-system loadable component topology is not admitted",
  );
  return components;
}

function payloadEquivalenceKey(payloadPath, triple, pathPolicy) {
  const family = admittedTarget(triple).targetFamily;
  const reserved = new Set(pathPolicy.windowsReservedDeviceNames);
  return payloadPath
    .split("/")
    .map((rawSegment) => {
      let segment = rawSegment.normalize(pathPolicy.unicodeNormalization);
      if (
        (family === "apple" && pathPolicy.appleCaseFolded) ||
        (family === "windows" && pathPolicy.windowsCaseFolded)
      ) {
        // The production implementation must use the versioned Unicode default
        // case-fold table named by policy. These vectors exercise its ASCII
        // subset and freeze the policy identifier independently.
        segment = segment.toLocaleLowerCase("en-US");
      }
      if (family === "windows" && pathPolicy.windowsTrailingDotSpaceCollapse) {
        segment = segment.replace(/[. ]+$/u, "");
      }
      invariant(segment.length > 0, "payload path has an empty equivalent segment");
      if (family === "windows") {
        const deviceStem = segment.split(".", 1)[0];
        invariant(!reserved.has(deviceStem), `reserved Windows device name: ${rawSegment}`);
      }
      return segment;
    })
    .join("/");
}

function resolveSymlinkTarget(entry, entries, maxDepth) {
  const base = path.posix.dirname(entry.path);
  const segments = base === "." ? [] : base.split("/");
  for (const segment of entry.target.split("/")) {
    if (segment === ".") continue;
    if (segment === "..") {
      invariant(segments.length > 0, `${entry.path}: symlink escapes payload`);
      segments.pop();
    } else {
      segments.push(segment);
    }
  }
  const resolved = segments.join("/");
  invariant(resolved.length > 0, `${entry.path}: symlink resolves to payload root`);
  invariant(entries.has(resolved), `${entry.path}: symlink target is undeclared`);

  const resolvedSegments = resolved.split("/");
  for (let length = 1; length < resolvedSegments.length; length += 1) {
    const ancestor = entries.get(resolvedSegments.slice(0, length).join("/"));
    invariant(ancestor?.kind === "directory", `${entry.path}: undeclared target ancestor`);
  }

  const visited = new Set([entry.path]);
  let current = entries.get(resolved);
  let depth = 1;
  while (current?.kind === "symlink") {
    invariant(!visited.has(current.path), `${entry.path}: symlink cycle`);
    invariant(depth < maxDepth, `${entry.path}: symlink depth limit exceeded`);
    visited.add(current.path);
    const nextBase = path.posix.dirname(current.path);
    const nextSegments = nextBase === "." ? [] : nextBase.split("/");
    for (const segment of current.target.split("/")) {
      if (segment === ".") continue;
      if (segment === "..") {
        invariant(nextSegments.length > 0, `${current.path}: symlink escapes payload`);
        nextSegments.pop();
      } else {
        nextSegments.push(segment);
      }
    }
    current = entries.get(nextSegments.join("/"));
    invariant(current !== undefined, `${entry.path}: symlink chain target is undeclared`);
    depth += 1;
  }
}

function manifestSemantics(manifest) {
  assertNfc(manifest, "manifest");
  assertStringSet(manifest.target.structuralFeatures, "target.structuralFeatures");
  assertSortedUnique(
    manifest.build.authorityDigests,
    (row) => row.path,
    "build.authorityDigests",
  );
  assertSortedUnique(
    manifest.interface.hostTools,
    (row) => `${row.role}\0${row.path}`,
    "interface.hostTools",
  );
  assertSortedUnique(
    manifest.interface.loadableComponents,
    (row) => `${row.system ? "1" : "0"}\0${row.role}\0${row.path ?? row.name}`,
    "interface.loadableComponents",
  );
  const equivalenceKeys = new Set();
  for (const entry of manifest.entries) {
    const key = payloadEquivalenceKey(
      entry.path,
      manifest.target.triple,
      checkedTrustPolicy.payloadPathPolicy,
    );
    invariant(!equivalenceKeys.has(key), `target-filesystem path collision: ${entry.path}`);
    equivalenceKeys.add(key);
  }
  assertSortedUnique(manifest.entries, (row) => row.path, "entries");

  const entries = new Map(manifest.entries.map((entry) => [entry.path, entry]));
  for (const entry of manifest.entries.filter((row) => row.kind === "symlink")) {
    resolveSymlinkTarget(
      entry,
      entries,
      checkedTrustPolicy.archiveLimits.maxSymlinkDepth,
    );
  }

  invariant(
    manifest.entries.length <= checkedTrustPolicy.archiveLimits.maxMemberCount,
    "manifest exceeds archive member limit",
  );
  let expandedBytes = 0;
  for (const entry of manifest.entries.filter((row) => row.kind === "regular")) {
    invariant(
      entry.size <= checkedTrustPolicy.archiveLimits.maxRegularFileBytes,
      `${entry.path}: regular-file limit exceeded`,
    );
    expandedBytes += entry.size;
  }
  invariant(
    expandedBytes <= checkedTrustPolicy.archiveLimits.maxExpandedBytes,
    "manifest exceeds expanded-byte limit",
  );

  const targetPolicy = admittedTarget(manifest.target.triple);
  assertSame(
    manifest.target.structuralFeatures,
    targetPolicy.structuralFeatures,
    "manifest admitted target features",
  );
  const { reviewedProfileIdentityDigest: _reviewedProfileDigest, ...profile } =
    manifest.profile;
  assertSame(profile, targetPolicy.profile, "manifest admitted profile");
  admittedNonSystemLoadableComponents(manifest, targetPolicy);
  assertSame(
    manifest.build.authorityDigests.map((row) => row.path),
    targetPolicy.buildAuthorityPaths,
    "manifest admitted build-authority membership",
  );
  const family = targetPolicy.targetFamily;
  const admittedSystemDependencies = new Set(
    checkedTrustPolicy.platformSystemDependencies[
      targetPolicy.systemDependencyPolicyKey
    ],
  );
  for (const row of manifest.interface.loadableComponents.filter(
    (component) => component.system,
  )) {
    invariant(
      admittedSystemDependencies.has(row.name),
      `system dependency is not admitted for ${family}: ${row.name}`,
    );
  }
  const requireRegularEntry = (row, label) => {
    const entry = entries.get(row.path);
    invariant(entry?.kind === "regular", `${label}: path is not a regular entry`);
    invariant(entry.digest === row.digest, `${label}: entry digest disagreement`);
  };
  manifest.interface.hostTools.forEach((row, index) =>
    requireRegularEntry(row, `interface.hostTools[${index}]`),
  );
  manifest.interface.loadableComponents
    .filter((row) => !row.system)
    .forEach((row, index) =>
      requireRegularEntry(row, `interface.loadableComponents[${index}]`),
    );

  const runtime = manifest.interface.loadableComponents.find(
    (row) =>
      row.system === false &&
      row.role === "runtime" &&
      row.path === manifest.runtimeComponent,
  );
  invariant(runtime !== undefined, "runtimeComponent: missing exact runtime row");
  requireRegularEntry(runtime, "runtimeComponent");

  if (family === "windows") {
    const runtimeDirectory = path.posix.dirname(manifest.runtimeComponent);
    const basenames = new Set();
    for (const row of manifest.interface.loadableComponents.filter(
      (component) => !component.system,
    )) {
      invariant(
        path.posix.dirname(row.path) === runtimeDirectory,
        "Windows loadable component is not co-located with the runtime",
      );
      const basename = path.posix
        .basename(row.path)
        .normalize("NFC")
        .toLocaleLowerCase("en-US")
        .replace(/[. ]+$/u, "");
      invariant(!basenames.has(basename), "Windows loader basename collision");
      basenames.add(basename);
    }
  }

  invariant(
    manifest.build.repository === publisherTrust.repository &&
      manifest.build.publisherWorkflow === publisherTrust.workflowPath &&
      manifest.build.sourceRef === publisherTrust.sourceRef,
    "manifest: publisher trust root mismatch",
  );
  invariant(
    manifest.artifactId ===
      computeDomainDigest(
        "ibex.portable-engine-manifest.v1",
        manifest,
        ["artifactId"],
      ),
    "manifest: artifactId mismatch",
  );
}

function authorityInputSemantics(documents, rawFixtures) {
  const {
    abiContract,
    forbiddenExports,
    headerSet,
    hostToolCompatibilityDocuments,
    manifest,
    requiredExports,
    reviewedProfileIdentity,
    sourceTreeIdentity,
  } = documents;
  const manifestEntries = new Map(
    manifest.entries.map((entry) => [entry.path, entry]),
  );

  for (const [name, document] of Object.entries({
    abiContract,
    headerSet,
    reviewedProfileIdentity,
    sourceTreeIdentity,
  })) {
    assertNfc(document, name);
  }
  hostToolCompatibilityDocuments.forEach((document, index) =>
    assertNfc(document, `hostToolCompatibilityDocuments[${index}]`),
  );

  const commitObject = Buffer.from(rawFixtures.sourceCommitObjectBase64, "base64");
  const treeObject = Buffer.from(rawFixtures.sourceTreeObjectBase64, "base64");
  invariant(
    gitObjectId(
      sourceTreeIdentity.gitObjectFormat,
      sourceTreeIdentity.sourceRevisionObjectType,
      commitObject,
    ) === sourceTreeIdentity.sourceRevision,
    "source revision is not the declared Git commit object",
  );
  invariant(
    gitObjectId(
      sourceTreeIdentity.gitObjectFormat,
      sourceTreeIdentity.treeObjectType,
      treeObject,
    ) === sourceTreeIdentity.treeObjectId,
    "tree object ID does not bind the supplied Git tree object",
  );
  for (const [label, descriptor, bytes] of [
    [
      "source revision object content",
      sourceTreeIdentity.sourceRevisionObjectContent,
      commitObject,
    ],
    ["tree object content", sourceTreeIdentity.treeObjectContent, treeObject],
  ]) {
    invariant(
      descriptor.encoding === "raw-uncompressed-git-object-content" &&
        descriptor.digest === rawSha256(bytes) &&
        descriptor.size === bytes.length,
      `${label} does not bind its exact bytes`,
    );
    const entry = manifestEntries.get(descriptor.path);
    invariant(
      entry?.kind === "regular" &&
        entry.role === "metadata" &&
        entry.digest === descriptor.digest &&
        entry.size === descriptor.size &&
        entry.executable === false,
      `${label} is not an exact payload member`,
    );
  }
  const commitHeaderEnd = commitObject.indexOf(Buffer.from("\n\n", "ascii"));
  invariant(commitHeaderEnd !== -1, "commit object has no header terminator");
  const treeLines = commitObject
    .subarray(0, commitHeaderEnd)
    .toString("latin1")
    .split("\n")
    .filter((line) => line.startsWith("tree "));
  invariant(treeLines.length === 1, "commit object does not name exactly one tree");
  invariant(
    /^tree [0-9a-f]+$/u.test(treeLines[0]),
    "commit object tree header is not lowercase hexadecimal",
  );
  invariant(
    treeLines[0] === `tree ${sourceTreeIdentity.treeObjectId}`,
    "Git commit does not point to the declared tree object",
  );
  invariant(
    sourceTreeIdentity.repository === manifest.build.repository &&
      sourceTreeIdentity.sourceRevision === manifest.build.sourceRevision &&
      sourceTreeIdentity.sourceRef === manifest.build.sourceRef,
    "source tree identity does not join the manifest build authority",
  );
  invariant(
    sourceTreeIdentity.gitObjectFormat ===
      admittedTarget(manifest.target.triple).sourceTreeGitObjectFormat,
    "source tree Git object format is not admitted",
  );
  invariant(
    manifest.build.sourceTreeDigest ===
      computeDomainDigest(
        "ibex.portable-engine-source-tree-identity.v1",
        sourceTreeIdentity,
      ),
    "sourceTreeDigest does not bind the source tree identity document",
  );

  const targetPolicy = admittedTarget(manifest.target.triple);
  invariant(
    reviewedProfileIdentity.profileId === manifest.profile.id &&
      reviewedProfileIdentity.targetVariant === manifest.profile.targetVariant &&
      reviewedProfileIdentity.targetTriple === manifest.target.triple,
    "reviewed profile identity does not join the manifest profile and target",
  );
  const expectedOriginKind = targetPolicy.reviewedProfileOriginKind;
  invariant(
    reviewedProfileIdentity.originKind === expectedOriginKind,
    "reviewed profile origin is not admissible for the target family",
  );
  const profileReceiptBytes = Buffer.from(
    rawFixtures.profileReceiptBytesBase64,
    "base64",
  );
  invariant(
    rawSha256(profileReceiptBytes) === reviewedProfileIdentity.receiptDigest,
    "reviewed profile receipt digest does not bind its exact bytes",
  );
  const profileReceiptEntry = manifestEntries.get(
    reviewedProfileIdentity.receiptPath,
  );
  invariant(
    profileReceiptEntry?.kind === "regular" &&
      profileReceiptEntry.role === "profile-receipt" &&
      profileReceiptEntry.digest === reviewedProfileIdentity.receiptDigest &&
      profileReceiptEntry.size === profileReceiptBytes.length,
    "reviewed profile receipt is not an exact payload member",
  );
  const profileReceipt = parseJsonStrict(
    profileReceiptBytes,
    "reviewed profile receipt fixture",
  );
  assertExactFields(
    profileReceipt,
    ["artifact", "origin", "profileId", "schema", "targetVariant"],
    "profile receipt",
  );
  assertExactFields(
    profileReceipt.artifact,
    ["binaryDigest", "fileName", "targetArchitecture"],
    "profile receipt artifact",
  );
  assertExactFields(
    profileReceipt.origin,
    ["cacheKey", "kind", "reviewedProfileIdentity"],
    "profile receipt origin",
  );
  invariant(
    profileReceipt.schema === "ibex/hermes-profile-provenance-receipt/2" &&
      profileReceipt.profileId === reviewedProfileIdentity.profileId &&
      profileReceipt.targetVariant === reviewedProfileIdentity.targetVariant &&
      profileReceipt.origin.kind === reviewedProfileIdentity.originKind,
    "reviewed profile projection disagrees with receipt discriminators",
  );
  assertSame(
    profileReceipt.origin.reviewedProfileIdentity,
    reviewedProfileIdentity.reviewedProfileIdentity,
    "reviewed profile projection from receipt",
  );
  invariant(
    profileReceipt.artifact.binaryDigest ===
      manifestEntries.get(manifest.runtimeComponent)?.digest &&
      profileReceipt.artifact.fileName ===
        path.posix.basename(manifest.runtimeComponent) &&
      targetPolicy.receiptTargetArchitectures.includes(
        profileReceipt.artifact.targetArchitecture,
      ),
    "profile receipt artifact does not bind the admitted runtime",
  );
  const reviewed = reviewedProfileIdentity.reviewedProfileIdentity;
  if (reviewed.artifact === "facebook/hermes") {
    invariant(
      /^[0-9a-f]{40}$/u.test(reviewed.sourceCommit),
      "reviewed Hermes source commit is not 40 lowercase hex",
    );
    invariant(
      reviewed.sourceRef === `${reviewed.sourceVersion}-stable`,
      "reviewed Hermes source ref is not derived from its version",
    );
    if (reviewedProfileIdentity.originKind === "source-patched-cache") {
      const expectedCacheKey =
        `${reviewed.sourceCommit.slice(0, 12)}` +
        `-p${rawDigestPrefix(reviewed.patchStackDigest, "patch stack digest")}` +
        `-ba${rawDigestPrefix(
          reviewed.sourceBuildAuthorityDigests["scripts/build-hermes.sh"],
          "Apple build authority digest",
        )}` +
        `-bl${rawDigestPrefix(
          reviewed.sourceBuildAuthorityDigests[
            "scripts/build-hermes-linux.sh"
          ],
          "Linux build authority digest",
        )}` +
        `-a${rawDigestPrefix(
          reviewed.patchApplicationAuthorityDigest,
          "patch application authority digest",
        )}` +
        `-i${rawDigestPrefix(
          reviewed.patchIdentityAuthorityDigest,
          "patch identity authority digest",
        )}` +
        "-oapple";
      invariant(
        profileReceipt.origin.cacheKey === expectedCacheKey,
        "profile receipt cache key is not the reviewed Release key",
      );
    }
    invariant(
      reviewed.artifact === manifest.source.artifact &&
        reviewed.sourceCommit === manifest.source.sourceCommit &&
        reviewed.sourceRef === manifest.source.sourceRef &&
        reviewed.sourceVersion === manifest.source.sourceVersion &&
        reviewed.patchStackDigest === manifest.source.patchStackDigest,
      "reviewed source profile does not join the manifest source authority",
    );
    const authorityDigests = new Map(
      manifest.build.authorityDigests.map((row) => [row.path, row.digest]),
    );
    invariant(
      authorityDigests.get("scripts/apply-hermes-patches.sh") ===
        reviewed.patchApplicationAuthorityDigest &&
        authorityDigests.get("scripts/hermes-version.sh") ===
          reviewed.patchIdentityAuthorityDigest,
      "reviewed profile does not join the patch authorities",
    );
    if (reviewedProfileIdentity.originKind === "source-patched-cache") {
      invariant(
        Object.entries(reviewed.sourceBuildAuthorityDigests).every(
          ([authorityPath, authorityDigest]) =>
            authorityDigests.get(authorityPath) === authorityDigest,
        ),
        "reviewed profile does not join every source-build authority",
      );
    } else {
      invariant(
        authorityDigests.get("scripts/build-hermes-windows.ps1") ===
          reviewed.sourceBuildAuthorityDigest &&
          authorityDigests.get("scripts/install-windows-hermes.ps1") ===
            reviewed.sourceInstallerAuthorityDigest,
        "reviewed Windows profile does not join its build and installer authorities",
      );
    }
  }
  invariant(
    manifest.profile.reviewedProfileIdentityDigest ===
      computeDomainDigest(
        "ibex.portable-engine-reviewed-profile-identity.v1",
        reviewedProfileIdentity,
      ),
    "reviewedProfileIdentityDigest does not bind its input document",
  );

  const expectedExtractor = targetPolicy.exportExtractor;
  const expectedExportComponents = admittedNonSystemLoadableComponents(
    manifest,
    targetPolicy,
  )
    .map(({ path: componentPath, digest: componentDigest }) => ({
      path: componentPath,
      digest: componentDigest,
    }))
    .sort((left, right) => utf8Compare(left.path, right.path));
  for (const [mode, exportSet] of [
    ["required", requiredExports],
    ["forbidden", forbiddenExports],
  ]) {
    invariant(exportSet.mode === mode, `${mode} export document has the wrong mode`);
    invariant(
      exportSet.targetTriple === manifest.target.triple &&
        exportSet.extractor === expectedExtractor,
      `${mode} export document does not join the manifest target`,
    );
    assertSortedUnique(
      exportSet.components,
      (row) => row.path,
      `${mode}Exports.components`,
    );
    assertSame(
      exportSet.components,
      expectedExportComponents,
      `${mode} export component completeness`,
    );
    const observedSymbols = [];
    for (const component of exportSet.components) {
      const entry = manifestEntries.get(component.path);
      invariant(
        entry?.kind === "regular" && entry.digest === component.digest,
        `${mode} export component is not an exact payload member`,
      );
      const observations = rawFixtures.exportObservations.filter(
        (row) =>
          row.componentPath === component.path &&
          row.extractor === exportSet.extractor,
      );
      invariant(
        observations.length === 1,
        `${mode} export component has no unique observation`,
      );
      const observation = observations[0];
      assertExactFields(
        observation,
        ["componentPath", "extractor", "symbolNameBytesBase64"],
        `${mode} export observation`,
      );
      invariant(
        Array.isArray(observation.symbolNameBytesBase64),
        `${mode} export observation names are not an array`,
      );
      const symbols = observation.symbolNameBytesBase64.map((encoded, index) => {
        const bytes = Buffer.from(encoded, "base64");
        invariant(
          bytes.toString("base64") === encoded,
          `${mode} export observation[${index}] is not canonical base64`,
        );
        const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        invariant(
          Buffer.from(value, "utf8").equals(bytes),
          `${mode} export observation[${index}] is not canonical UTF-8`,
        );
        return value;
      });
      invariant(
        symbols.length > 0 && symbols.every((symbol) => symbol.length > 0),
        "export observation contains an empty symbol",
      );
      assertExactUtf8StringSet(symbols, `${mode}Exports.observedSymbols`);
      observedSymbols.push(...symbols.map((symbol) => Buffer.from(symbol, "utf8")));
    }
    assertSortedUnique(
      exportSet.matchers,
      (row) => `${row.kind}\0${row.value}`,
      `${mode}Exports.matchers`,
      { requireNfc: false },
    );
    assertSame(
      exportSet.matchers,
      targetPolicy.exportPolicy[`${mode}Matchers`],
      `${mode} export matcher policy`,
    );
    for (const matcher of exportSet.matchers) {
      const needle = Buffer.from(matcher.value, "utf8");
      const matches = observedSymbols.some((symbol) =>
        matcher.kind === "exact"
          ? symbol.equals(needle)
          : symbol.indexOf(needle) !== -1,
      );
      invariant(
        mode === "required" ? matches : !matches,
        `${mode} export matcher has the wrong observed result: ${matcher.value}`,
      );
    }
  }
  invariant(
    manifest.interface.requiredExportsDigest ===
      computeDomainDigest(
        "ibex.portable-engine-required-exports.v1",
        requiredExports,
      ),
    "requiredExportsDigest does not bind the requirement set",
  );
  invariant(
    manifest.interface.forbiddenExportsDigest ===
      computeDomainDigest(
        "ibex.portable-engine-forbidden-exports.v1",
        forbiddenExports,
      ),
    "forbiddenExportsDigest does not bind the rejection set",
  );

  invariant(
    headerSet.targetTriple === manifest.target.triple,
    "header set does not join the manifest target",
  );
  assertStringSet(headerSet.includeRoots, "headerSet.includeRoots");
  assertSortedUnique(headerSet.headers, (row) => row.path, "headerSet.headers");
  for (const includeRoot of headerSet.includeRoots) {
    invariant(
      manifestEntries.get(includeRoot)?.kind === "directory",
      "header include root is not a declared directory",
    );
  }
  for (const header of headerSet.headers) {
    invariant(
      headerSet.includeRoots.some(
        (root) => header.path.startsWith(`${root}/`) && header.path !== root,
      ),
      "header is outside every declared include root",
    );
  }
  const manifestHeaders = manifest.entries
    .filter((entry) => entry.kind === "regular" && entry.role === "header")
    .map(({ path: headerPath, digest, size }) => ({
      path: headerPath,
      digest,
      size,
    }));
  assertSame(manifestHeaders, headerSet.headers, "complete header membership");
  invariant(
    manifest.interface.headerSetDigest ===
      computeDomainDigest("ibex.portable-engine-header-set.v1", headerSet),
    "headerSetDigest does not bind the header inventory",
  );

  assertSame(abiContract.target, manifest.target, "ABI target");
  assertStringSet(abiContract.contractFeatures, "abiContract.contractFeatures");
  invariant(
    abiContract.headerSetDigest === manifest.interface.headerSetDigest &&
      abiContract.requiredExportsDigest ===
        manifest.interface.requiredExportsDigest &&
      abiContract.forbiddenExportsDigest ===
        manifest.interface.forbiddenExportsDigest,
    "ABI contract does not bind the header and export contracts",
  );
  const {
    schema: _abiSchema,
    target: _abiTarget,
    headerSetDigest: _headerSetDigest,
    requiredExportsDigest: _requiredExportsDigest,
    forbiddenExportsDigest: _forbiddenExportsDigest,
    ...abiDimensions
  } = abiContract;
  assertSame(
    abiDimensions,
    targetPolicy.directJsiAbi,
    "ABI dimensions admitted for target",
  );
  invariant(
    manifest.interface.abiContractDigest ===
      computeDomainDigest("ibex.portable-engine-abi-contract.v1", abiContract),
    "abiContractDigest does not bind the ABI contract",
  );

  assertSortedUnique(
    hostToolCompatibilityDocuments,
    (document) => `${document.toolRole}\0${document.toolPath}`,
    "hostToolCompatibilityDocuments",
  );
  const rawHostToolInputs = new Map();
  for (const fixture of rawFixtures.hostToolInputs) {
    assertExactFields(
      fixture,
      ["bytesBase64", "executable", "path"],
      "raw host-tool fixture",
    );
    invariant(
      !rawHostToolInputs.has(fixture.path),
      `duplicate raw host-tool fixture: ${fixture.path}`,
    );
    rawHostToolInputs.set(fixture.path, Buffer.from(fixture.bytesBase64, "base64"));
  }
  const consumedFixturePaths = new Set();
  const admittedHostTools = hostToolCompatibilityDocuments.map(
    ({ toolRole, toolPath }) => ({ toolRole, toolPath }),
  );
  assertSame(
    admittedHostTools,
    targetPolicy.requiredHostTools,
    "required host-tool membership",
  );
  for (const [documentIndex, hostToolCompatibility] of
    hostToolCompatibilityDocuments.entries()) {
    const label = `hostToolCompatibilityDocuments[${documentIndex}]`;
    invariant(
      hostToolCompatibility.actualHostTriple ===
        targetPolicy.hostTool.actualHostTriple,
      `${label}: actual host is not admitted`,
    );
    assertSame(
      hostToolCompatibility.binaryMachine,
      targetPolicy.hostTool.binaryMachine,
      `${label}: binary machine`,
    );
    const {
      environmentMode,
      environment,
      stdin,
      workingDirectoryLifetime,
      argv0,
      timeoutMs,
      maxStdoutBytes,
      maxStderrBytes,
      maxOutputBytes,
    } = hostToolCompatibility;
    assertSame(
      {
        environmentMode,
        environment,
        stdin,
        workingDirectoryLifetime,
        argv0,
        timeoutMs,
        maxStdoutBytes,
        maxStderrBytes,
        maxOutputBytes,
      },
      targetPolicy.hostTool.executionContract,
      `${label}: admitted execution contract`,
    );
    invariant(
      hostToolCompatibility.dependencyClosure.extractor.format ===
        targetPolicy.hostTool.dependencyExtractorFormat,
      `${label}: dependency extractor is not admitted`,
    );
    assertSortedUnique(
      hostToolCompatibility.environment,
      (row) => row.name,
      `${label}.environment`,
    );
    assertSortedUnique(
      hostToolCompatibility.inputFixtures,
      (row) => `${row.fixturePayloadPath}\0${row.workspacePath}`,
      `${label}.inputFixtures`,
    );
    const fixturePayloadPaths = new Set();
    const fixtureWorkspacePaths = new Set();
    for (const fixture of hostToolCompatibility.inputFixtures) {
      invariant(
        !fixturePayloadPaths.has(fixture.fixturePayloadPath),
        `${label}: duplicate fixture payload path`,
      );
      invariant(
        !fixtureWorkspacePaths.has(fixture.workspacePath),
        `${label}: duplicate fixture workspace path`,
      );
      fixturePayloadPaths.add(fixture.fixturePayloadPath);
      fixtureWorkspacePaths.add(fixture.workspacePath);
      const bytes = rawHostToolInputs.get(fixture.fixturePayloadPath);
      invariant(bytes !== undefined, `${label}: fixture bytes are absent`);
      invariant(
        rawSha256(bytes) === fixture.digest && bytes.length === fixture.size,
        `${label}: fixture bytes disagree with the behavior document`,
      );
      const entry = manifestEntries.get(fixture.fixturePayloadPath);
      invariant(
        entry?.kind === "regular" &&
          entry.role === "compatibility-fixture" &&
          entry.digest === fixture.digest &&
          entry.size === fixture.size &&
          entry.executable === fixture.executable,
        `${label}: fixture is not an exact manifest payload member`,
      );
      consumedFixturePaths.add(fixture.fixturePayloadPath);
    }
    assertSortedUnique(
      hostToolCompatibility.dependencyClosure.nonSystemDependencies,
      (row) => row.path,
      `${label}.dependencyClosure.nonSystemDependencies`,
    );
    for (const dependency of
      hostToolCompatibility.dependencyClosure.nonSystemDependencies) {
      const entry = manifestEntries.get(dependency.path);
      invariant(
        entry?.kind === "regular" && entry.digest === dependency.digest,
        `${label}: non-system dependency is not an exact payload member`,
      );
    }
    assertStringSet(
      hostToolCompatibility.dependencyClosure.systemDependencies,
      `${label}.dependencyClosure.systemDependencies`,
    );
    const admittedHostDependencies = new Set(
      checkedTrustPolicy.platformSystemDependencies[
        targetPolicy.hostTool.systemDependencyPolicyKey
      ],
    );
    invariant(
      hostToolCompatibility.dependencyClosure.systemDependencies.every(
        (dependency) => admittedHostDependencies.has(dependency),
      ),
      `${label}: host system dependency is not admitted`,
    );
    assertSortedUnique(
      hostToolCompatibility.invocations,
      (row) => row.id,
      `${label}.invocations`,
    );
    for (const [index, invocation] of
      hostToolCompatibility.invocations.entries()) {
      invariant(
        invocation.stdoutSize <= hostToolCompatibility.maxStdoutBytes &&
          invocation.stderrSize <= hostToolCompatibility.maxStderrBytes,
        `${label}.invocations[${index}]: captured stream limit exceeded`,
      );
      assertSortedUnique(
        invocation.outputFiles,
        (row) => row.path,
        `${label}.invocations[${index}].outputFiles`,
      );
      invariant(
        invocation.outputFiles.reduce((sum, output) => sum + output.size, 0) <=
          hostToolCompatibility.maxOutputBytes,
        `${label}.invocations[${index}]: output byte limit exceeded`,
      );
      assertSortedUnique(
        invocation.bytecodeOutputs,
        (row) => row.path,
        `${label}.invocations[${index}].bytecodeOutputs`,
      );
      for (const bytecode of invocation.bytecodeOutputs) {
        const output = invocation.outputFiles.find(
          (candidate) => candidate.path === bytecode.path,
        );
        invariant(output !== undefined, "bytecode observation names no output file");
        invariant(
          bytecode.bytecodeVersion === manifest.profile.hermesBytecodeVersion,
          "host tool produced another Hermes bytecode version",
        );
        const source = hostToolCompatibility.inputFixtures.find(
          (input) =>
            input.workspacePath === bytecode.sourcePath &&
            input.digest === bytecode.sourceDigest,
        );
        invariant(
          source !== undefined && invocation.argv.includes(bytecode.sourcePath),
          "bytecode observation does not bind an invoked source fixture",
        );
      }
    }
    const matchingHostTools = manifest.interface.hostTools.filter(
      (row) =>
        row.path === hostToolCompatibility.toolPath &&
        row.digest === hostToolCompatibility.toolDigest,
    );
    invariant(
      matchingHostTools.length === 1,
      `${label}: compatibility has no exact manifest tool`,
    );
    invariant(
      matchingHostTools[0].compatibilityDigest ===
        computeDomainDigest(
          "ibex.portable-engine-host-tool-compatibility.v1",
          hostToolCompatibility,
        ),
      `${label}: compatibilityDigest does not bind its behavior vector`,
    );
  }
  assertSame(
    [...consumedFixturePaths].sort(utf8Compare),
    [...rawHostToolInputs.keys()].sort(utf8Compare),
    "complete host-tool fixture byte membership",
  );
  invariant(
    manifest.interface.hostTools.length ===
      hostToolCompatibilityDocuments.length,
    "host-tool behavior document membership is incomplete",
  );

  const authorityEntries = manifest.entries.filter(
    (entry) =>
      entry.path === "META-INF" || entry.path.startsWith("META-INF/authority"),
  );
  assertSame(
    authorityEntries,
    expectedAuthorityInputEntries(documents),
    "portable authority input payload membership",
  );
}

function expectedPortableIdentity(manifest) {
  const runtime = manifest.interface.loadableComponents.find(
    (row) =>
      row.system === false &&
      row.role === "runtime" &&
      row.path === manifest.runtimeComponent,
  );
  const {
    reviewedProfileIdentityDigest,
    ...profile
  } = manifest.profile;
  return {
    schema: "ibex/portable-engine-artifact-identity/1",
    artifactId: manifest.artifactId,
    artifactKind: manifest.artifactKind,
    target: manifest.target,
    profile,
    runtimeComponentDigest: runtime.digest,
    reviewedProfileIdentityDigest,
    interfaceContractDigest: computeDomainDigest(
      "ibex.portable-engine-interface.v1",
      manifest.interface,
    ),
  };
}

function mappedInstanceSemantics(mapped, portable) {
  assertSame(mapped.portable, portable, "mapped portable identity");
  assertSame(mapped.localObject, mapped.before.object, "before object identity");
  assertSame(mapped.localObject, mapped.after.object, "after object identity");
  invariant(
    mapped.before.digest === portable.runtimeComponentDigest &&
      mapped.after.digest === portable.runtimeComponentDigest,
    "mapped runtime digest does not match portable identity",
  );
  invariant(mapped.before.size === mapped.after.size, "mapped size changed");

  const targetPolicy = admittedTarget(portable.target.triple);
  invariant(
    mapped.mappingProof.class === targetPolicy.mappingProof.class &&
      mapped.mappingProof.platformObservation.platform ===
        targetPolicy.mappingProof.platform,
    "mapping proof is not admitted for the portable target",
  );
  const observation = mapped.mappingProof.platformObservation;
  if (mapped.mappingProof.class === "macos-proc-pid-region-path-info") {
    invariant(observation.platform === "macos", "macOS proof discriminator mismatch");
    assertSame(observation.mappedObject, mapped.localObject, "macOS mapped object");
  } else if (mapped.mappingProof.class === "linux-proc-self-maps") {
    invariant(observation.platform === "linux", "Linux proof discriminator mismatch");
    assertSame(observation.mappedObject, mapped.localObject, "Linux mapped object");
  } else {
    invariant(
      observation.platform === "windows",
      "Windows proof discriminator mismatch",
    );
    assertSame(
      observation.runtimeModule.object,
      mapped.localObject,
      "Windows runtime module object",
    );
    invariant(
      observation.runtimeModule.digest === portable.runtimeComponentDigest,
      "Windows runtime module digest mismatch",
    );
  }

  invariant(
    mapped.observationDigest ===
      computeDomainDigest(
        "ibex.mapped-engine-instance-identity.v1",
        mapped,
        ["observationDigest"],
      ),
    "mapped observationDigest mismatch",
  );
}

function assignmentSemantics(suite, assignment) {
  assertStringSet(suite.target.structuralFeatures, "suite.target.structuralFeatures");
  assertStringSet(suite.expectedShardIds, "suite.expectedShardIds");
  assertStringSet(suite.expectedCommandIds, "suite.expectedCommandIds");
  assertStringSet(suite.expectedFixtureIds, "suite.expectedFixtureIds");
  assertStringSet(assignment.expectedCommandIds, "assignment.expectedCommandIds");
  assertStringSet(assignment.expectedRecipeIds, "assignment.expectedRecipeIds");
  assertStringSet(assignment.expectedFixtureIds, "assignment.expectedFixtureIds");
  invariant(
    assignment.suiteLineageId === suite.suiteLineageId,
    "assignment suite lineage mismatch",
  );
  invariant(
    assignment.suiteDescriptorDigest ===
      computeDomainDigest("ibex.portable-engine-suite-lineage.v1", suite),
    "assignment suite descriptor mismatch",
  );
  invariant(suite.expectedShardIds.includes(assignment.shardId), "unexpected shard ID");
  invariant(assignment.authorityClass === "diagnostic", "v1 cross-runner assignment is not diagnostic");
  invariant(
    assignment.assignedShardWorkflow.repository ===
      suite.coordinatorWorkflow.repository &&
      assignment.assignedShardWorkflow.sourceRef ===
        suite.coordinatorWorkflow.sourceRef,
    "assignment workflow trust root mismatch",
  );
  invariant(
    assignment.assignedShardWorkflow.workflowPath !==
      suite.coordinatorWorkflow.workflowPath,
    "coordinator and shard signer identities are not distinct",
  );
}

function bundleSemantics(documents, rawFixtures = validVectors.rawFixtures) {
  const {
    assignment,
    assignmentBundle,
    diagnosticBundle,
    diagnosticManifest,
    diagnosticProvenance,
    installationReceipt,
    manifest,
    mappedInstance,
    portableIdentity,
    suite,
    trustPolicy,
  } = documents;

  authorityInputSemantics(documents, rawFixtures);
  manifestSemantics(manifest);
  invariant(
    installationReceipt.artifactId === manifest.artifactId,
    "receipt artifactId mismatch",
  );
  invariant(
    installationReceipt.manifestDigest ===
      computeDomainDigest("ibex.portable-engine-manifest-digest.v1", manifest),
    "receipt manifestDigest mismatch",
  );
  assertSame(trustPolicy, checkedTrustPolicy, "checked trust policy");
  invariant(
    installationReceipt.verificationPolicyDigest ===
      computeDomainDigest(
        "ibex.portable-engine-provenance-trust-policy.v1",
        trustPolicy,
      ),
    "receipt verificationPolicyDigest mismatch",
  );
  const detachedBundleBytes = Buffer.from(
    rawFixtures.detachedBundleByteProjectionBase64,
    "base64",
  );
  invariant(
    detachedBundleBytes.length <=
      trustPolicy.provenanceBundleBytes.maxBundleBytes,
    "detached provenance bundle exceeds the byte limit",
  );
  const detachedBundle = parseJsonStrict(
    detachedBundleBytes,
    "detached provenance byte-projection fixture",
  );
  invariant(
    detachedBundle.mediaType === trustPolicy.provenanceBundleBytes.mediaType,
    "detached provenance bundle media type mismatch",
  );
  invariant(
    installationReceipt.provenanceBundleDigest === rawSha256(detachedBundleBytes),
    "receipt does not bind the exact detached provenance bytes",
  );
  invariant(
    trustPolicy.portableArtifactAcceptanceEnabled === false &&
      trustPolicy.enginePublisher.enabled === true &&
      trustPolicy.authoritativeConformance.sameRunnerOnly === true &&
      Object.values(trustPolicy.crossRunnerConformance).every(
        (enabled) => enabled === false,
      ),
    "trust policy enables unsupported cross-runner authority",
  );
  assertStringSet(
    trustPolicy.payloadPathPolicy.windowsReservedDeviceNames,
    "trustPolicy.payloadPathPolicy.windowsReservedDeviceNames",
  );
  for (const [family, names] of Object.entries(
    trustPolicy.platformSystemDependencies,
  )) {
    assertStringSet(names, `trustPolicy.platformSystemDependencies.${family}`);
  }
  invariant(
    trustPolicy.archiveLimits.maxRegularFileBytes <=
      trustPolicy.archiveLimits.maxExpandedBytes &&
      trustPolicy.archiveLimits.maxArchiveBytes <=
        trustPolicy.archiveLimits.maxExpandedBytes,
    "trust policy archive limits are internally inconsistent",
  );
  invariant(
    installationReceipt.repository === publisherTrust.repository &&
      installationReceipt.publisherWorkflow === publisherTrust.workflowPath &&
      installationReceipt.sourceRef === publisherTrust.sourceRef &&
      installationReceipt.runnerClass === publisherTrust.runnerClass &&
      installationReceipt.sourceRevision === manifest.build.sourceRevision,
    "receipt publisher trust root mismatch",
  );

  assertSame(
    portableIdentity,
    expectedPortableIdentity(manifest),
    "portable identity projection",
  );
  mappedInstanceSemantics(mappedInstance, portableIdentity);

  invariant(suite.portableArtifactId === manifest.artifactId, "suite artifact mismatch");
  invariant(suite.sourceRevision === manifest.build.sourceRevision, "suite revision mismatch");
  invariant(suite.sourceTreeDigest === manifest.build.sourceTreeDigest, "suite tree mismatch");
  assertSame(suite.target, manifest.target, "suite target");
  assignmentSemantics(suite, assignment);

  assertSame(assignmentBundle.suite, suite, "assignment bundle suite");
  assertSame(assignmentBundle.assignments, [assignment], "assignment bundle rows");
  assertSortedUnique(
    assignmentBundle.assignments,
    (row) => row.shardId,
    "assignmentBundle.assignments",
  );
  assertSame(
    assignmentBundle.assignments.map((row) => row.shardId),
    suite.expectedShardIds,
    "complete shard membership",
  );
  assertSame(
    assignmentBundle.assignments.flatMap((row) => row.expectedCommandIds).sort(),
    suite.expectedCommandIds,
    "complete command membership",
  );
  assertSame(
    assignmentBundle.assignments.flatMap((row) => row.expectedFixtureIds).sort(),
    suite.expectedFixtureIds,
    "complete fixture membership",
  );

  invariant(
    diagnosticManifest.manifestDigest ===
      computeDomainDigest(
        "ibex.portable-engine-diagnostic-shard-manifest.v1",
        diagnosticManifest,
        ["manifestDigest"],
      ),
    "diagnostic manifestDigest mismatch",
  );
  invariant(
    diagnosticManifest.assignmentDigest ===
      computeDomainDigest("ibex.portable-engine-shard-assignment.v1", assignment),
    "diagnostic assignment digest mismatch",
  );
  invariant(
    diagnosticManifest.suiteLineageId === suite.suiteLineageId &&
      diagnosticManifest.suitePlanDigest === suite.suitePlanDigest &&
      diagnosticManifest.sourceRevision === suite.sourceRevision &&
      diagnosticManifest.sourceTreeDigest === suite.sourceTreeDigest,
    "diagnostic suite/source binding mismatch",
  );
  assertSame(diagnosticManifest.target, suite.target, "diagnostic target");
  assertSame(
    diagnosticManifest.featureSet,
    suite.target.structuralFeatures,
    "diagnostic feature set",
  );
  invariant(
    diagnosticManifest.engineProfile === portableIdentity.profile.id,
    "diagnostic engine profile mismatch",
  );
  assertSame(diagnosticManifest.portableEngine, portableIdentity, "diagnostic portable engine");
  assertSame(diagnosticManifest.mappedEngine, mappedInstance, "diagnostic mapped engine");
  invariant(
    diagnosticManifest.shardId === assignment.shardId &&
      diagnosticManifest.authorityClass === assignment.authorityClass &&
      diagnosticManifest.shardAttempt === assignment.shardAttempt,
    "diagnostic shard identity mismatch",
  );
  assertSame(
    diagnosticManifest.expectedCommandIds,
    assignment.expectedCommandIds,
    "diagnostic command membership",
  );
  assertSame(
    diagnosticManifest.expectedRecipeIds,
    assignment.expectedRecipeIds,
    "diagnostic recipe membership",
  );
  assertSame(
    diagnosticManifest.expectedFixtureIds,
    assignment.expectedFixtureIds,
    "diagnostic fixture membership",
  );
  assertStringSet(diagnosticManifest.featureSet, "diagnosticManifest.featureSet");
  assertStringSet(
    diagnosticManifest.expectedCommandIds,
    "diagnosticManifest.expectedCommandIds",
  );
  assertStringSet(
    diagnosticManifest.expectedRecipeIds,
    "diagnosticManifest.expectedRecipeIds",
  );
  assertStringSet(
    diagnosticManifest.expectedFixtureIds,
    "diagnosticManifest.expectedFixtureIds",
  );
  assertSortedUnique(
    diagnosticManifest.declaredOutputs,
    (row) => row.name,
    "diagnosticManifest.declaredOutputs",
  );

  assertSame(
    diagnosticBundle.assignmentBundle,
    assignmentBundle,
    "diagnostic assignment bundle",
  );
  assertSame(diagnosticBundle.manifest, diagnosticManifest, "diagnostic manifest");
  invariant(
    diagnosticBundle.coordinatorProvenance.subjectDigest ===
      computeDomainDigest(
        "ibex.portable-engine-assignment-bundle.v1",
        assignmentBundle,
      ),
    "coordinator provenance subject mismatch",
  );
  invariant(
    diagnosticBundle.coordinatorProvenance.repository ===
      suite.coordinatorWorkflow.repository &&
      diagnosticBundle.coordinatorProvenance.workflowPath ===
        suite.coordinatorWorkflow.workflowPath &&
      diagnosticBundle.coordinatorProvenance.sourceRef ===
        suite.coordinatorWorkflow.sourceRef &&
      diagnosticBundle.coordinatorProvenance.sourceRevision ===
        suite.sourceRevision,
    "coordinator provenance identity mismatch",
  );
  invariant(
    diagnosticBundle.engineDistributionProvenance.subjectDigest ===
      installationReceipt.archiveDigest &&
      diagnosticBundle.engineDistributionProvenance.provenanceBundleDigest ===
        installationReceipt.provenanceBundleDigest &&
      diagnosticBundle.engineDistributionProvenance.repository ===
        installationReceipt.repository &&
      diagnosticBundle.engineDistributionProvenance.workflowPath ===
        installationReceipt.publisherWorkflow &&
      diagnosticBundle.engineDistributionProvenance.sourceRef ===
        installationReceipt.sourceRef &&
      diagnosticBundle.engineDistributionProvenance.sourceRevision ===
        installationReceipt.sourceRevision &&
      diagnosticBundle.engineDistributionProvenance.runnerClass ===
        installationReceipt.runnerClass,
    "engine distribution provenance mismatch",
  );
  assertSame(
    diagnosticBundle.outputs.map(({ name, digest }) => ({ name, digest })),
    diagnosticManifest.declaredOutputs,
    "declared output digest join",
  );
  assertSortedUnique(
    diagnosticBundle.outputs,
    (row) => row.name,
    "diagnosticBundle.outputs",
  );
  assertSortedUnique(
    diagnosticBundle.commandEnvelopeRecords,
    (row) => row.name,
    "diagnosticBundle.commandEnvelopeRecords",
  );
  assertSame(
    diagnosticBundle.commandEnvelopeRecords.map((row) => row.name),
    assignment.expectedCommandIds,
    "command envelope membership",
  );
  assertSortedUnique(
    diagnosticBundle.fixtureEvidence,
    (row) => row.name,
    "diagnosticBundle.fixtureEvidence",
  );
  assertSame(
    diagnosticBundle.fixtureEvidence.map((row) => row.name),
    assignment.expectedFixtureIds,
    "fixture evidence membership",
  );
  assertSortedUnique(
    diagnosticBundle.toolchainObservations,
    (row) => row.name,
    "diagnosticBundle.toolchainObservations",
  );
  invariant(
    diagnosticBundle.sourceObservation.sourceRevision === suite.sourceRevision &&
      diagnosticBundle.sourceObservation.sourceTreeDigest === suite.sourceTreeDigest,
    "source observation mismatch",
  );

  invariant(
    diagnosticProvenance.subjectDigest ===
      computeDomainDigest(
        "ibex.portable-engine-diagnostic-shard-bundle.v1",
        diagnosticBundle,
      ),
    "diagnostic shard provenance subject mismatch",
  );
  invariant(
    diagnosticProvenance.repository ===
      assignment.assignedShardWorkflow.repository &&
      diagnosticProvenance.workflowPath ===
        assignment.assignedShardWorkflow.workflowPath &&
      diagnosticProvenance.sourceRef ===
        assignment.assignedShardWorkflow.sourceRef &&
      diagnosticProvenance.sourceRevision === suite.sourceRevision &&
      diagnosticProvenance.runnerClass === publisherTrust.runnerClass &&
      diagnosticProvenance.workflowRunId ===
        diagnosticManifest.workflowRunId &&
      diagnosticProvenance.workflowRunAttempt ===
        diagnosticManifest.workflowRunAttempt &&
      diagnosticProvenance.shardId === assignment.shardId &&
      diagnosticProvenance.authorityClass === "diagnostic",
    "diagnostic shard provenance identity mismatch",
  );
}

describe("LLP 0035 portable engine authority schemas", () => {
  test("strict Draft 2020-12 schemas accept the complete golden DAG", () => {
    const ajv = buildAjv();
    for (const [documentName, schemaFile] of Object.entries(documentSchemas)) {
      const document = validVectors.documents[documentName];
      assertIJson(document, documentName);
      assertSchemaValid(ajv, schemaFile, document, documentName);
    }
    validVectors.documents.hostToolCompatibilityDocuments.forEach(
      (document, index) => {
        assertIJson(document, `hostToolCompatibilityDocuments[${index}]`);
        assertSchemaValid(
          ajv,
          "portable-engine-host-tool-compatibility-v1.schema.json",
          document,
          `hostToolCompatibilityDocuments[${index}]`,
        );
      },
    );
    bundleSemantics(validVectors.documents);
  });

  test("golden DAG updater is schema-checked and content-idempotent", () => {
    const result = Bun.spawnSync({
      cmd: [
        "bun",
        path.join(
          repoRoot,
          "packages/ibex-devtools/src/scripts/update-portable-engine-provenance-vectors.mjs",
        ),
        "--check",
      ],
      cwd: repoRoot,
      stdout: "pipe",
      stderr: "pipe",
    });
    if (result.exitCode !== 0) {
      throw new Error(new TextDecoder().decode(result.stderr));
    }
    expect(new TextDecoder().decode(result.stdout)).toContain(
      "portable engine provenance vectors checked",
    );
  });

  test("detached bundle fixture proves only the raw-byte projection while acceptance is disabled", () => {
    const bytes = Buffer.from(
      validVectors.rawFixtures.detachedBundleByteProjectionBase64,
      "base64",
    );
    const fixture = parseJsonStrict(
      bytes,
      "detached provenance byte-projection fixture",
    );
    expect(bytes.length).toBeLessThanOrEqual(
      checkedTrustPolicy.provenanceBundleBytes.maxBundleBytes,
    );
    expect(fixture.mediaType).toBe(
      checkedTrustPolicy.provenanceBundleBytes.mediaType,
    );
    expect(fixture.verificationMaterial).toEqual({});
    expect(fixture.dsseEnvelope).toEqual({});
    expect(checkedTrustPolicy.portableArtifactAcceptanceEnabled).toBe(false);
    expect(
      checkedTrustPolicy.provenanceBundleBytes
        .acceptanceRequiresOfflineVerification,
    ).toBe(true);
    const digest = rawSha256(bytes);
    expect(digest).toBe(
      validVectors.documents.installationReceipt.provenanceBundleDigest,
    );

    const normalized = Buffer.from(bytes.toString("utf8").trimEnd(), "utf8");
    expect(createHash("sha256").update(normalized).digest("hex")).not.toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  test("a coherent unsupported-target rewrite has no fallback family", () => {
    const documents = structuredClone(validVectors.documents);
    const unsupported = "aarch64-unknown-freebsd";
    documents.manifest.target.triple = unsupported;
    documents.reviewedProfileIdentity.targetTriple = unsupported;
    documents.requiredExports.targetTriple = unsupported;
    documents.forbiddenExports.targetTriple = unsupported;
    documents.headerSet.targetTriple = unsupported;
    documents.abiContract.target.triple = unsupported;
    expect(() =>
      authorityInputSemantics(documents, validVectors.rawFixtures),
    ).toThrow("target is not exactly admitted");
  });

  test("Git source identity verifies the commit object to tree object edge", () => {
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const treeBytes = Buffer.from(rawFixtures.sourceTreeObjectBase64, "base64");
    rawFixtures.sourceTreeObjectBase64 = Buffer.concat([
      treeBytes,
      Buffer.from([0]),
    ]).toString("base64");
    expect(() =>
      authorityInputSemantics(validVectors.documents, rawFixtures),
    ).toThrow("tree object ID does not bind");
  });

  test("raw Git objects are exact offline payload members", () => {
    const documents = structuredClone(validVectors.documents);
    const commitPath =
      documents.sourceTreeIdentity.sourceRevisionObjectContent.path;
    const commitEntry = documents.manifest.entries.find(
      (entry) => entry.path === commitPath,
    );
    commitEntry.digest = `sha256-${"0".repeat(64)}`;
    expect(() =>
      authorityInputSemantics(documents, validVectors.rawFixtures),
    ).toThrow("source revision object content is not an exact payload member");
  });

  test("Git source identity cannot coherently switch object formats", () => {
    const documents = structuredClone(validVectors.documents);
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const treeBytes = Buffer.from(rawFixtures.sourceTreeObjectBase64, "base64");
    const treeId = gitObjectId("sha256", "tree", treeBytes);
    const originalCommit = new TextDecoder().decode(
      Buffer.from(rawFixtures.sourceCommitObjectBase64, "base64"),
    );
    const commitBytes = Buffer.from(
      originalCommit.replace(/^tree [0-9a-f]+$/mu, `tree ${treeId}`),
      "utf8",
    );
    rawFixtures.sourceCommitObjectBase64 = commitBytes.toString("base64");
    documents.sourceTreeIdentity.gitObjectFormat = "sha256";
    documents.sourceTreeIdentity.treeObjectId = treeId;
    documents.sourceTreeIdentity.sourceRevision = gitObjectId(
      "sha256",
      "commit",
      commitBytes,
    );
    documents.sourceTreeIdentity.sourceRevisionObjectContent.digest =
      rawSha256(commitBytes);
    documents.sourceTreeIdentity.sourceRevisionObjectContent.size =
      commitBytes.length;
    const commitEntry = documents.manifest.entries.find(
      (entry) =>
        entry.path ===
        documents.sourceTreeIdentity.sourceRevisionObjectContent.path,
    );
    commitEntry.digest = rawSha256(commitBytes);
    commitEntry.size = commitBytes.length;
    documents.manifest.build.sourceRevision =
      documents.sourceTreeIdentity.sourceRevision;
    expect(() => authorityInputSemantics(documents, rawFixtures)).toThrow(
      "source tree Git object format is not admitted",
    );
  });

  test("manifest profile cannot coherently select another build mode", () => {
    const manifest = structuredClone(validVectors.documents.manifest);
    manifest.profile.configuration = "Debug";
    manifest.profile.debugger = true;
    manifest.profile.hermesBytecodeVersion = 97;
    expect(() => manifestSemantics(manifest)).toThrow(
      "manifest admitted profile",
    );
  });

  test("manifest build authorities include the reviewed publisher workflow", () => {
    const manifest = structuredClone(validVectors.documents.manifest);
    manifest.build.authorityDigests = manifest.build.authorityDigests.filter(
      (row) => row.path !== ".github/workflows/hermes-artifacts.yml",
    );
    expect(() => manifestSemantics(manifest)).toThrow(
      "manifest admitted build-authority membership",
    );
  });

  test("reviewed profile projection is derived from exact receipt bytes", () => {
    const documents = structuredClone(validVectors.documents);
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const receipt = parseJsonStrict(
      Buffer.from(rawFixtures.profileReceiptBytesBase64, "base64"),
      "profile receipt mutation source",
    );
    receipt.origin.reviewedProfileIdentity.sourceVersion = "0.13.1";
    const receiptBytes = Buffer.from(`${JSON.stringify(receipt)}\n`, "utf8");
    rawFixtures.profileReceiptBytesBase64 = receiptBytes.toString("base64");
    documents.reviewedProfileIdentity.receiptDigest = rawSha256(receiptBytes);
    const receiptEntry = documents.manifest.entries.find(
      (entry) => entry.path === documents.reviewedProfileIdentity.receiptPath,
    );
    receiptEntry.digest = rawSha256(receiptBytes);
    receiptEntry.size = receiptBytes.length;
    expect(() => authorityInputSemantics(documents, rawFixtures)).toThrow(
      "reviewed profile projection from receipt",
    );
  });

  test("reviewed source ref keeps the producer's version-stable shape", () => {
    const documents = structuredClone(validVectors.documents);
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const receipt = parseJsonStrict(
      Buffer.from(rawFixtures.profileReceiptBytesBase64, "base64"),
      "profile receipt source-ref mutation",
    );
    receipt.origin.reviewedProfileIdentity.sourceRef = "refs/tags/v0.13.0";
    const receiptBytes = Buffer.from(`${JSON.stringify(receipt)}\n`, "utf8");
    rawFixtures.profileReceiptBytesBase64 = receiptBytes.toString("base64");
    documents.reviewedProfileIdentity.receiptDigest = rawSha256(receiptBytes);
    documents.reviewedProfileIdentity.reviewedProfileIdentity.sourceRef =
      receipt.origin.reviewedProfileIdentity.sourceRef;
    documents.manifest.source.sourceRef =
      receipt.origin.reviewedProfileIdentity.sourceRef;
    const receiptEntry = documents.manifest.entries.find(
      (entry) => entry.path === documents.reviewedProfileIdentity.receiptPath,
    );
    receiptEntry.digest = rawSha256(receiptBytes);
    receiptEntry.size = receiptBytes.length;
    expect(() => authorityInputSemantics(documents, rawFixtures)).toThrow(
      "reviewed Hermes source ref is not derived from its version",
    );
  });

  test("reviewed source cache key is reconstructed from its authorities", () => {
    const documents = structuredClone(validVectors.documents);
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const receipt = parseJsonStrict(
      Buffer.from(rawFixtures.profileReceiptBytesBase64, "base64"),
      "profile receipt cache-key mutation",
    );
    receipt.origin.cacheKey = `b${receipt.origin.cacheKey.slice(1)}`;
    const receiptBytes = Buffer.from(`${JSON.stringify(receipt)}\n`, "utf8");
    rawFixtures.profileReceiptBytesBase64 = receiptBytes.toString("base64");
    documents.reviewedProfileIdentity.receiptDigest = rawSha256(receiptBytes);
    const receiptEntry = documents.manifest.entries.find(
      (entry) => entry.path === documents.reviewedProfileIdentity.receiptPath,
    );
    receiptEntry.digest = rawSha256(receiptBytes);
    receiptEntry.size = receiptBytes.length;
    expect(() => authorityInputSemantics(documents, rawFixtures)).toThrow(
      "profile receipt cache key is not the reviewed Release key",
    );
  });

  test("export observations prove required presence and forbidden absence", () => {
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const observation = rawFixtures.exportObservations[0];
    observation.symbolNameBytesBase64.unshift(
      Buffer.from("CDPAgent", "utf8").toString("base64"),
    );
    expect(() =>
      authorityInputSemantics(validVectors.documents, rawFixtures),
    ).toThrow("forbidden export matcher has the wrong observed result");
  });

  test("export matchers cannot be weakened inside a coherent package", () => {
    const documents = structuredClone(validVectors.documents);
    documents.forbiddenExports.matchers =
      documents.forbiddenExports.matchers.slice(1);
    expect(() =>
      authorityInputSemantics(documents, validVectors.rawFixtures),
    ).toThrow("forbidden export matcher policy");
  });

  test("export checks cover every non-system loadable component", () => {
    const documents = structuredClone(validVectors.documents);
    const extraDigest = `sha256-${"6".repeat(64)}`;
    documents.manifest.interface.loadableComponents.splice(1, 0, {
      role: "runtime-dependency",
      path: "lib/libextra.dylib",
      digest: extraDigest,
      system: false,
    });
    documents.manifest.entries.push({
      kind: "regular",
      role: "runtime-dependency",
      path: "lib/libextra.dylib",
      digest: extraDigest,
      size: 4096,
      executable: true,
    });
    documents.manifest.entries.sort((left, right) =>
      utf8Compare(left.path, right.path),
    );
    expect(() =>
      authorityInputSemantics(documents, validVectors.rawFixtures),
    ).toThrow("non-system loadable component topology is not admitted");
  });

  test("the admitted host-tool set cannot be removed", () => {
    const documents = structuredClone(validVectors.documents);
    documents.manifest.interface.hostTools = [];
    documents.hostToolCompatibilityDocuments = [];
    expect(() =>
      authorityInputSemantics(documents, validVectors.rawFixtures),
    ).toThrow("required host-tool membership");
  });

  test("manifest-carried host-tool fixture bytes are exact", () => {
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    rawFixtures.hostToolInputs[0].bytesBase64 = Buffer.from(
      "globalThis.answer = 43;\n",
      "utf8",
    ).toString("base64");
    expect(() =>
      authorityInputSemantics(validVectors.documents, rawFixtures),
    ).toThrow("fixture bytes disagree");
  });

  test("host-tool fixtures cannot overwrite one staged workspace path", () => {
    const documents = structuredClone(validVectors.documents);
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    const bytes = Buffer.from("globalThis.other = 7;\n", "utf8");
    const fixturePayloadPath =
      "share/compatibility/host-tools/input/other.js";
    rawFixtures.hostToolInputs.unshift({
      path: fixturePayloadPath,
      bytesBase64: bytes.toString("base64"),
      executable: false,
    });
    documents.hostToolCompatibilityDocuments[0].inputFixtures.unshift({
      fixturePayloadPath,
      workspacePath: "input/smoke.js",
      digest: rawSha256(bytes),
      size: bytes.length,
      executable: false,
    });
    documents.manifest.entries.push({
      kind: "regular",
      role: "compatibility-fixture",
      path: fixturePayloadPath,
      digest: rawSha256(bytes),
      size: bytes.length,
      executable: false,
    });
    documents.manifest.entries.sort((left, right) =>
      utf8Compare(left.path, right.path),
    );
    expect(() => authorityInputSemantics(documents, rawFixtures)).toThrow(
      "duplicate fixture workspace path",
    );
  });

  test("detached bundle byte limit fails before any provenance authority", () => {
    const rawFixtures = structuredClone(validVectors.rawFixtures);
    rawFixtures.detachedBundleByteProjectionBase64 = Buffer.alloc(
      checkedTrustPolicy.provenanceBundleBytes.maxBundleBytes + 1,
      0x20,
    ).toString("base64");
    expect(() => bundleSemantics(validVectors.documents, rawFixtures)).toThrow(
      "detached provenance bundle exceeds the byte limit",
    );
  });

  test("JCS cases and explicit domain-separated projections match goldens", () => {
    for (const vector of validVectors.canonicalizationCases) {
      expect(canonicalJson(vector.value)).toBe(vector.expectedCanonical);
    }

    expect(
      validVectors.projections.map(
        ({ id, documentPath, domain, omitFields }) => ({
          id,
          documentPath,
          domain,
          omitFields,
        }),
      ),
    ).toEqual(
      projectionContract.map(({ boundPath: _boundPath, ...projection }) =>
        projection,
      ),
    );

    for (const projection of projectionContract) {
      invariant(!projection.domain.includes("\0"), `${projection.id}: domain contains NUL`);
      const vector = validVectors.projections.find(
        (candidate) => candidate.id === projection.id,
      );
      const document = resolvePath(validVectors.documents, projection.documentPath);
      const digest = computeDomainDigest(
        projection.domain,
        document,
        projection.omitFields,
      );
      expect(digest).toBe(vector.expectedDigest);
      expect(digest).toBe(resolvePath(validVectors.documents, projection.boundPath));
      expect(canonicalJson(JSON.parse(canonicalJson(document)))).toBe(
        canonicalJson(document),
      );
    }
  });

  for (const vector of invalidVectors.parseCases) {
    test(`rejects invalid strict JSON vector: ${vector.id}`, () => {
      const bytes = vector.rawBytesBase64
        ? Buffer.from(vector.rawBytesBase64, "base64")
        : Buffer.from(vector.rawJson, "utf8");
      expect(() => parseJsonStrict(bytes, vector.id)).toThrow();
    });
  }

  for (const vector of invalidVectors.cases) {
    test(`rejects mutation vector: ${vector.id}`, () => {
      const documents = structuredClone(validVectors.documents);
      const document = resolvePath(documents, vector.documentPath);
      applyMutation(document, vector.mutation);
      const ajv = buildAjv();
      const validate = validatorFor(ajv, vector.schema);
      const schemaValid = validate(document);

      if (vector.expected === "schema-invalid") {
        expect(schemaValid).toBe(false);
      } else {
        expect(schemaValid).toBe(true);
        expect(() => bundleSemantics(documents)).toThrow();
      }
    });
  }
});
