// @ref LLP 0034#manifest — portable identity is an exact JCS/I-JSON manifest
// projection with typed digests, canonical sets, and a self-excluding ID.
// @ref LLP 0034#runtime-identity-split — portable identity must stay path-free,
// while mapped-instance evidence binds the local object and pre/post bytes.
// @ref LLP 0034#cross-runner-conformance-authority — coordinator assignment,
// diagnostic shard evidence, and detached provenance form an acyclic digest DAG.
// @ref LLP 0032#shard-manifest — shard manifests are exact-field records whose
// semantic digest omits only their own manifestDigest field.

import { describe, expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
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
const projectionContract = [
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
    parent[key] = structuredClone(mutation.value);
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

function assertSortedUnique(rows, keyOf, label) {
  let prior;
  for (const [index, row] of rows.entries()) {
    const key = keyOf(row);
    invariant(key.normalize("NFC") === key, `${label}[${index}]: key is not NFC`);
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

function targetFamily(triple) {
  if (triple.includes("windows")) return "windows";
  if (triple.includes("apple")) return "apple";
  return "linux";
}

function payloadEquivalenceKey(payloadPath, triple, pathPolicy) {
  const family = targetFamily(triple);
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

  const family = targetFamily(manifest.target.triple);
  const admittedSystemDependencies = new Set(
    checkedTrustPolicy.platformSystemDependencies[family],
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

  if (manifest.target.triple.includes("windows")) {
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

function bundleSemantics(documents) {
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
  invariant(
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

describe("LLP 0034 portable engine authority schemas", () => {
  test("strict Draft 2020-12 schemas accept the complete golden DAG", () => {
    const ajv = buildAjv();
    for (const [documentName, schemaFile] of Object.entries(documentSchemas)) {
      const document = validVectors.documents[documentName];
      assertIJson(document, documentName);
      assertSchemaValid(ajv, schemaFile, document, documentName);
    }
    bundleSemantics(validVectors.documents);
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
      const document = documents[vector.documentPath];
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
