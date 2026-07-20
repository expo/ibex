#!/usr/bin/env node

// Fail-closed joins used by the GitHub-hosted macOS physical-promotion
// ceremony. This helper does not create or edit a promotion commit: it only
// validates source-A release inputs, invokes the fixed production installer,
// and selects the exact build-consumption record named by Cargo's retained
// JSON stream.
//
// @ref LLP 0035#transport-and-distribution-provenance — release discovery is
// revision-scoped, exact-member, content-digest bound, and rechecked after the
// four assets are downloaded by immutable API IDs.
// @ref LLP 0035#promotion-lineage-and-admission — physical execution at A must
// retain the checked diagnostic admission and may not manufacture P or C.
// @ref LLP 0035#build-consumption-and-post-link-contracts — the post-link gate
// consumes the one build record reached from the retained Cargo JSON stream.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertCanonicalJsonBytes,
  canonicalJson,
  parseJsonStrict,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";
import { installPortableEngine } from "./portable-engine-installer.mjs";

const RELEASE_PLAN_SCHEMA =
  "ibex/portable-engine-physical-promotion-release-plan/1";
const INSTALLATION_SCHEMA =
  "ibex/portable-engine-physical-promotion-installation/1";
const BUILD_SELECTION_SCHEMA =
  "ibex/portable-engine-physical-promotion-build-selection/1";
const RELEASE_PLAN_DOMAIN =
  "ibex.portable-engine-physical-promotion-release-plan.v1\0";
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const SEMANTIC_DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const RAW_DIGEST_PATTERN = /^sha256-[0-9a-f]{64}$/u;
const API_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const DECIMAL_PATTERN = /^[1-9][0-9]*$/u;
const SAFE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,511}$/u;
const MAX_METADATA_BYTES = 4 * 1024 * 1024;
const MAX_PLAN_BYTES = 1024 * 1024;
const MAX_INSTALLATION_BYTES = 1024 * 1024;
const MAX_CARGO_MESSAGES_BYTES = 64 * 1024 * 1024;
const MAX_CARGO_MESSAGE_BYTES = 4 * 1024 * 1024;
const MAX_SIDECAR_BYTES = 4096;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const trustPolicy = parseJsonStrict(
  fs.readFileSync(
    path.join(
      repoRoot,
      "schemas/portable-engine-provenance-trust-policy-v1.json",
    ),
  ),
  "checked portable-engine trust policy",
);

function refuse(message) {
  throw new Error(message);
}

function invariant(condition, message) {
  if (!condition) refuse(message);
}

function exactKeys(value, expected, label) {
  invariant(
    value && typeof value === "object" && !Array.isArray(value),
    `${label}: expected an object`,
  );
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  invariant(
    actual.length === wanted.length &&
      actual.every((key, index) => key === wanted[index]),
    `${label}: expected exact fields ${wanted.join(", ")}; got ${actual.join(", ")}`,
  );
}

function positiveInteger(value, label) {
  invariant(Number.isSafeInteger(value) && value > 0, `${label}: expected a positive safe integer`);
  return value;
}

function timestamp(value, label) {
  invariant(
    typeof value === "string" &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value) &&
      Number.isFinite(Date.parse(value)),
    `${label}: expected one UTC RFC3339 timestamp`,
  );
  return value;
}

function safeName(value, label) {
  invariant(
    typeof value === "string" && SAFE_NAME_PATTERN.test(value),
    `${label}: outside the closed basename grammar`,
  );
  invariant(path.basename(value) === value, `${label}: must be one basename`);
  return value;
}

function sourceRevision(value, label = "source revision") {
  invariant(
    typeof value === "string" && SOURCE_REVISION_PATTERN.test(value),
    `${label}: expected one lowercase SHA-1 commit ID`,
  );
  return value;
}

function readPinned(filePath, maximumBytes, label) {
  const absolute = path.resolve(filePath);
  const lexical = fs.lstatSync(absolute, { bigint: true });
  invariant(
    lexical.isFile() && !lexical.isSymbolicLink() && lexical.nlink === 1n,
    `${label}: expected one no-follow, single-link regular file`,
  );
  if (typeof process.getuid === "function") {
    invariant(
      lexical.uid === BigInt(process.getuid()),
      `${label}: file is not owned by the effective UID`,
    );
  }
  invariant(
    lexical.size > 0n && lexical.size <= BigInt(maximumBytes),
    `${label}: byte size is outside the bound`,
  );
  const descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    invariant(
      opened.dev === lexical.dev &&
        opened.ino === lexical.ino &&
        opened.size === lexical.size,
      `${label}: file identity changed while opening`,
    );
    const bytes = fs.readFileSync(descriptor);
    invariant(
      bytes.byteLength === Number(opened.size),
      `${label}: file changed while reading`,
    );
    const after = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(absolute, { bigint: true });
    for (const observed of [after, pathAfter]) {
      invariant(
        observed.isFile() &&
          !observed.isSymbolicLink() &&
          observed.nlink === 1n &&
          observed.dev === opened.dev &&
          observed.ino === opened.ino &&
          observed.size === opened.size &&
          observed.mtimeNs === opened.mtimeNs &&
          observed.ctimeNs === opened.ctimeNs,
        `${label}: file object changed while reading`,
      );
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function readStrictJson(filePath, maximumBytes, label, canonical = false) {
  const bytes = readPinned(filePath, maximumBytes, label);
  const value = parseJsonStrict(bytes, label);
  if (canonical) assertCanonicalJsonBytes(bytes, value, label);
  return { bytes, value };
}

function writeCanonicalExclusive(filePath, value, label) {
  const absolute = path.resolve(filePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true, mode: 0o700 });
  const descriptor = fs.openSync(
    absolute,
    fs.constants.O_WRONLY |
      fs.constants.O_CREAT |
      fs.constants.O_EXCL |
      NOFOLLOW,
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, Buffer.from(canonicalJson(value), "utf8"));
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const status = fs.lstatSync(absolute, { bigint: true });
  invariant(
    status.isFile() && !status.isSymbolicLink() && status.nlink === 1n,
    `${label}: output is not one regular file`,
  );
}

function planDigest(plan) {
  const projection = structuredClone(plan);
  delete projection.planDigest;
  const hash = crypto.createHash("sha256");
  hash.update(Buffer.from(RELEASE_PLAN_DOMAIN, "utf8"));
  hash.update(Buffer.from(canonicalJson(projection), "utf8"));
  return `sha256-${hash.digest("base64url")}`;
}

function roleLimits() {
  return new Map([
    ["archive", trustPolicy.archiveLimits.maxArchiveBytes],
    ["archive-checksum", MAX_SIDECAR_BYTES],
    ["provenance-bundle", trustPolicy.provenanceBundleBytes.maxBundleBytes],
    ["provenance-checksum", MAX_SIDECAR_BYTES],
  ]);
}

export function buildPortableReleasePlan({
  metadata,
  sourceRevision: selectedRevision,
  releaseTag,
  archiveName,
}) {
  sourceRevision(selectedRevision);
  safeName(releaseTag, "portable release tag");
  safeName(archiveName, "portable archive name");
  invariant(
    releaseTag.endsWith(`-${selectedRevision}`),
    "portable release tag is not revision-scoped to source A",
  );
  invariant(
    archiveName.endsWith(`-${selectedRevision}.tar.gz`),
    "portable archive name is not revision-scoped to source A",
  );
  invariant(metadata && typeof metadata === "object" && !Array.isArray(metadata), "release metadata: expected an object");
  invariant(metadata.tag_name === releaseTag, "release metadata names another tag");
  invariant(
    metadata.target_commitish === selectedRevision,
    "release target does not equal exact source A",
  );
  invariant(metadata.draft === false, "portable release is still a draft");
  invariant(metadata.prerelease === true, "portable release must remain a prerelease");
  invariant(
    metadata.name === `Hermes portable artifact ${selectedRevision}`,
    "portable release title differs from the producer contract",
  );
  const releaseId = positiveInteger(metadata.id, "portable release ID");
  const releaseCreatedAt = timestamp(
    metadata.created_at,
    "portable release created_at",
  );
  const releasePublishedAt = timestamp(
    metadata.published_at,
    "portable release published_at",
  );
  invariant(Array.isArray(metadata.assets), "release metadata has no asset list");

  const names = new Map([
    ["archive", archiveName],
    ["archive-checksum", `${archiveName}.sha256`],
    ["provenance-bundle", `${archiveName}.sigstore.json`],
    ["provenance-checksum", `${archiveName}.sigstore.json.sha256`],
  ]);
  const expectedNames = [...names.values()].sort();
  invariant(
    metadata.assets.length === expectedNames.length,
    "portable release must contain exactly the four archive/provenance members",
  );
  invariant(
    new Set(metadata.assets.map((asset) => asset?.name)).size ===
      metadata.assets.length,
    "portable release contains duplicate asset names",
  );
  invariant(
    [...metadata.assets.map((asset) => asset?.name)].sort().every(
      (name, index) => name === expectedNames[index],
    ),
    "portable release contains a missing or unexpected asset",
  );

  const limits = roleLimits();
  const ids = new Set();
  const assets = [...names].map(([role, name]) => {
    const asset = metadata.assets.find((candidate) => candidate.name === name);
    const id = positiveInteger(asset.id, `${role} asset ID`);
    invariant(!ids.has(id), "portable release reuses an asset ID");
    ids.add(id);
    invariant(asset.state === "uploaded", `${role} asset is not uploaded`);
    const size = positiveInteger(asset.size, `${role} asset size`);
    invariant(size <= limits.get(role), `${role} asset exceeds its byte bound`);
    invariant(
      typeof asset.digest === "string" &&
        API_DIGEST_PATTERN.test(asset.digest),
      `${role} asset lacks one lowercase GitHub SHA-256 digest`,
    );
    return {
      role,
      id,
      name,
      size,
      digest: asset.digest,
      createdAt: timestamp(asset.created_at, `${role} asset created_at`),
      updatedAt: timestamp(asset.updated_at, `${role} asset updated_at`),
    };
  });
  const plan = {
    schema: RELEASE_PLAN_SCHEMA,
    sourceRevision: selectedRevision,
    repository: trustPolicy.enginePublisher.repository,
    release: {
      id: releaseId,
      tag: releaseTag,
      targetCommitish: selectedRevision,
      createdAt: releaseCreatedAt,
      publishedAt: releasePublishedAt,
    },
    assets,
    planDigest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
  plan.planDigest = planDigest(plan);
  return plan;
}

function validateReleasePlan(plan, label = "portable release plan") {
  exactKeys(
    plan,
    ["schema", "sourceRevision", "repository", "release", "assets", "planDigest"],
    label,
  );
  invariant(plan.schema === RELEASE_PLAN_SCHEMA, `${label}: unexpected schema`);
  sourceRevision(plan.sourceRevision, `${label} source revision`);
  invariant(
    plan.repository === trustPolicy.enginePublisher.repository,
    `${label}: unexpected repository`,
  );
  invariant(Array.isArray(plan.assets) && plan.assets.length === 4, `${label}: incomplete asset set`);
  invariant(
    SEMANTIC_DIGEST_PATTERN.test(plan.planDigest) &&
      plan.planDigest === planDigest(plan),
    `${label}: digest mismatch`,
  );
  return plan;
}

export function verifyPortableReleaseDownload({ plan, metadata, directory }) {
  validateReleasePlan(plan);
  const archive = plan.assets.find((asset) => asset.role === "archive");
  invariant(archive, "portable release plan has no archive");
  const currentPlan = buildPortableReleasePlan({
    metadata,
    sourceRevision: plan.sourceRevision,
    releaseTag: plan.release.tag,
    archiveName: archive.name,
  });
  invariant(
    canonicalJson(currentPlan) === canonicalJson(plan),
    "portable release metadata changed across exact-ID downloads",
  );

  const absoluteDirectory = path.resolve(directory);
  const realDirectory = fs.realpathSync(absoluteDirectory);
  invariant(
    realDirectory === absoluteDirectory,
    "portable download directory is redirected",
  );
  const directoryStatus = fs.lstatSync(absoluteDirectory, { bigint: true });
  invariant(
    directoryStatus.isDirectory() && !directoryStatus.isSymbolicLink(),
    "portable download root is not one directory",
  );
  if (typeof process.getuid === "function") {
    invariant(
      directoryStatus.uid === BigInt(process.getuid()),
      "portable download root is not owned by the effective UID",
    );
  }
  invariant(
    (Number(directoryStatus.mode & 0o7777n) & 0o7022) === 0,
    "portable download root has unsafe mode bits",
  );
  const expectedNames = plan.assets.map((asset) => asset.name).sort();
  const actualNames = fs.readdirSync(absoluteDirectory).sort();
  invariant(
    actualNames.length === expectedNames.length &&
      actualNames.every((name, index) => name === expectedNames[index]),
    "portable download directory does not have exact four-file membership",
  );

  const bytesByRole = new Map();
  for (const asset of plan.assets) {
    const limit = roleLimits().get(asset.role);
    const bytes = readPinned(
      path.join(absoluteDirectory, asset.name),
      limit,
      `${asset.role} downloaded asset`,
    );
    invariant(bytes.byteLength === asset.size, `${asset.role} downloaded size differs from GitHub metadata`);
    invariant(
      `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}` ===
        asset.digest,
      `${asset.role} downloaded digest differs from GitHub metadata`,
    );
    bytesByRole.set(asset.role, bytes);
  }
  const archiveHex = plan.assets
    .find((asset) => asset.role === "archive")
    .digest.slice("sha256:".length);
  const bundleAsset = plan.assets.find(
    (asset) => asset.role === "provenance-bundle",
  );
  const bundleHex = bundleAsset.digest.slice("sha256:".length);
  invariant(
    bytesByRole
      .get("archive-checksum")
      .equals(Buffer.from(`${archiveHex}  ${archive.name}\n`, "ascii")),
    "archive checksum sidecar does not bind the downloaded archive",
  );
  invariant(
    bytesByRole
      .get("provenance-checksum")
      .equals(Buffer.from(`${bundleHex}  ${bundleAsset.name}\n`, "ascii")),
    "provenance checksum sidecar does not bind the downloaded bundle",
  );
  const bundle = parseJsonStrict(
    bytesByRole.get("provenance-bundle"),
    "downloaded Sigstore bundle",
  );
  invariant(
    bundle?.mediaType ===
      trustPolicy.provenanceBundleBytes.mediaType,
    "downloaded provenance has an unexpected Sigstore media type",
  );
  return {
    archivePath: path.join(absoluteDirectory, archive.name),
    bundlePath: path.join(absoluteDirectory, bundleAsset.name),
  };
}

export async function installPhysicalPromotionSourceA({
  archivePath,
  bundlePath,
  expectedSourceRevision,
  selectedRepoRoot = repoRoot,
}) {
  sourceRevision(expectedSourceRevision);
  const installed = await installPortableEngine({
    archivePath: path.resolve(archivePath),
    bundlePath: path.resolve(bundlePath),
    expectedSourceRevision,
    repoRoot: path.resolve(selectedRepoRoot),
  });
  invariant(installed.authorized === false, "source A unexpectedly received promotion authority");
  invariant(installed.diagnosticOnly === true, "source A install is not marked diagnostic-only");
  invariant(
    installed.promotionAdmission?.schema ===
      "ibex/portable-engine-checked-promotion-admission/1" &&
      installed.promotionAdmission.authorized === false &&
      installed.promotionAdmission.currentRevision === expectedSourceRevision &&
      installed.promotionAdmission.sourceRevision === expectedSourceRevision &&
      installed.promotionAdmission.promotionTopicRevision === null &&
      installed.promotionAdmission.sourceTreeObjectId === null &&
      installed.promotionAdmission.admissionDigest === null,
    "source A did not produce the exact disabled checked admission",
  );
  invariant(
    installed.manifest?.build?.sourceRevision === expectedSourceRevision,
    "installed manifest names another source revision",
  );
  invariant(
    SEMANTIC_DIGEST_PATTERN.test(installed.manifest?.artifactId),
    "installed manifest has no portable artifact ID",
  );
  invariant(
    RAW_DIGEST_PATTERN.test(installed.transport?.receipt?.archiveDigest),
    "installed transport has no archive digest",
  );
  invariant(
    RAW_DIGEST_PATTERN.test(
      installed.transport?.receipt?.provenanceBundleDigest,
    ),
    "installed transport has no provenance-bundle digest",
  );
  const signer = installed.transport?.verification?.signer;
  invariant(
    signer &&
      DECIMAL_PATTERN.test(signer.runId) &&
      DECIMAL_PATTERN.test(signer.runAttempt),
    "offline verification has no exact producer run/attempt",
  );
  const result = {
    schema: INSTALLATION_SCHEMA,
    sourceRevision: expectedSourceRevision,
    targetTriple: installed.manifest.target.triple,
    artifactId: installed.manifest.artifactId,
    archiveDigest: installed.transport.receipt.archiveDigest,
    provenanceBundleDigest:
      installed.transport.receipt.provenanceBundleDigest,
    manifestDigest: installed.transport.receipt.manifestDigest,
    installationReceiptDigest: semanticDigest(
      "ibex.portable-engine-installation-receipt.v1",
      installed.transport.receipt,
    ),
    verificationPolicyDigest:
      installed.transport.receipt.verificationPolicyDigest,
    subjectName: installed.transport.verification.subject.name,
    producer: {
      repository: signer.repository,
      workflowPath: signer.workflowPath,
      sourceRef: signer.sourceRef,
      runId: signer.runId,
      runAttempt: signer.runAttempt,
    },
    checkedAdmission: structuredClone(installed.promotionAdmission),
  };
  return result;
}

function validateInstallation(value, label = "physical-promotion installation") {
  exactKeys(
    value,
    [
      "schema",
      "sourceRevision",
      "targetTriple",
      "artifactId",
      "archiveDigest",
      "provenanceBundleDigest",
      "manifestDigest",
      "installationReceiptDigest",
      "verificationPolicyDigest",
      "subjectName",
      "producer",
      "checkedAdmission",
    ],
    label,
  );
  invariant(value.schema === INSTALLATION_SCHEMA, `${label}: unexpected schema`);
  sourceRevision(value.sourceRevision, `${label} source revision`);
  invariant(SEMANTIC_DIGEST_PATTERN.test(value.artifactId), `${label}: malformed artifact ID`);
  invariant(RAW_DIGEST_PATTERN.test(value.archiveDigest), `${label}: malformed archive digest`);
  invariant(RAW_DIGEST_PATTERN.test(value.provenanceBundleDigest), `${label}: malformed bundle digest`);
  for (const field of [
    "manifestDigest",
    "installationReceiptDigest",
    "verificationPolicyDigest",
  ]) {
    invariant(
      SEMANTIC_DIGEST_PATTERN.test(value[field]),
      `${label}: malformed ${field}`,
    );
  }
  safeName(value.subjectName, `${label} subject name`);
  exactKeys(
    value.producer,
    ["repository", "workflowPath", "sourceRef", "runId", "runAttempt"],
    `${label} producer`,
  );
  invariant(DECIMAL_PATTERN.test(value.producer.runId), `${label}: malformed producer run ID`);
  invariant(DECIMAL_PATTERN.test(value.producer.runAttempt), `${label}: malformed producer run attempt`);
  invariant(
    value.checkedAdmission?.authorized === false &&
      value.checkedAdmission.currentRevision === value.sourceRevision &&
      value.checkedAdmission.sourceRevision === value.sourceRevision,
    `${label}: source-A diagnostic admission is absent`,
  );
  return value;
}

export function verifyProducerRun({ installation, metadata }) {
  validateInstallation(installation);
  const publisher = trustPolicy.enginePublisher;
  invariant(
    installation.producer.repository === publisher.repository &&
      installation.producer.workflowPath === publisher.workflowPath &&
      installation.producer.sourceRef === publisher.sourceRef,
    "installed provenance producer differs from checked policy",
  );
  invariant(metadata && typeof metadata === "object" && !Array.isArray(metadata), "producer run metadata: expected an object");
  invariant(
    String(metadata.id) === installation.producer.runId,
    "producer run API result has another run ID",
  );
  invariant(
    String(metadata.run_attempt) === installation.producer.runAttempt,
    "producer run API result has another attempt",
  );
  invariant(metadata.head_sha === installation.sourceRevision, "producer run API result has another source revision");
  invariant(metadata.head_branch === "main", "producer run did not execute from main");
  invariant(metadata.path === publisher.workflowPath, "producer run has another workflow path");
  invariant(metadata.name === publisher.workflowName, "producer run has another workflow name");
  invariant(publisher.allowedTriggers.includes(metadata.event), "producer run used a forbidden trigger");
  invariant(metadata.status === "completed" && metadata.conclusion === "success", "producer run did not complete successfully");
  invariant(
    metadata.repository?.full_name === publisher.repository &&
      String(metadata.repository?.id) === publisher.repositoryId &&
      String(metadata.repository?.owner?.id) === publisher.repositoryOwnerId,
    "producer run repository identity differs from checked policy",
  );
  timestamp(metadata.created_at, "producer run created_at");
  timestamp(metadata.updated_at, "producer run updated_at");
  timestamp(metadata.run_started_at, "producer run run_started_at");
}

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

export function selectBuildConsumption({
  cargoMessagesPath,
  installation,
  selectedRepoRoot = repoRoot,
}) {
  validateInstallation(installation);
  const root = fs.realpathSync(path.resolve(selectedRepoRoot));
  const targetRoot = fs.realpathSync(path.join(root, "target"));
  const cargoBytes = readPinned(
    cargoMessagesPath,
    MAX_CARGO_MESSAGES_BYTES,
    "retained Cargo JSON stream",
  );
  const lines = cargoBytes.toString("utf8").split("\n");
  invariant(lines.at(-1) === "", "Cargo JSON stream must end with exactly one LF");
  lines.pop();
  invariant(lines.length > 0, "Cargo JSON stream is empty");
  const outDirectories = new Set();
  for (const [index, line] of lines.entries()) {
    invariant(Buffer.byteLength(line) <= MAX_CARGO_MESSAGE_BYTES, `Cargo JSON message ${index + 1} exceeds its byte bound`);
    const message = parseJsonStrict(
      Buffer.from(line, "utf8"),
      `Cargo JSON message ${index + 1}`,
    );
    if (
      message?.reason === "build-script-executed" &&
      typeof message.out_dir === "string"
    ) {
      outDirectories.add(path.resolve(message.out_dir));
    }
  }
  const matches = [];
  for (const outDirectory of outDirectories) {
    if (!isWithin(targetRoot, outDirectory)) continue;
    const lexicalCandidate = path.join(
      outDirectory,
      "portable_engine_build_consumption.json",
    );
    if (!fs.existsSync(lexicalCandidate)) continue;
    const candidate = fs.realpathSync(lexicalCandidate);
    invariant(
      candidate === lexicalCandidate && isWithin(targetRoot, candidate),
      "portable build-consumption candidate is redirected outside target",
    );
    const { value: build } = readStrictJson(
      candidate,
      MAX_INSTALLATION_BYTES,
      "portable build-consumption candidate",
      true,
    );
    if (
      build?.schema === "ibex/portable-engine-build-consumption/1" &&
      build.portable?.artifactId === installation.artifactId &&
      build.target?.triple === installation.targetTriple &&
      build.manifestDigest === installation.manifestDigest &&
      build.installationReceiptDigest ===
        installation.installationReceiptDigest &&
      build.verificationPolicyDigest ===
        installation.verificationPolicyDigest &&
      SEMANTIC_DIGEST_PATTERN.test(build.consumptionDigest)
    ) {
      matches.push({ candidate, build });
    }
  }
  invariant(matches.length === 1, `Cargo JSON stream selected ${matches.length} matching portable build-consumption records`);
  const [{ candidate, build }] = matches;
  const relativePath = path.relative(root, candidate);
  invariant(
    relativePath.split(path.sep)[0] === "target" &&
      !relativePath.includes("\n") &&
      !relativePath.includes("\r"),
    "selected portable build-consumption path is unsafe",
  );
  return {
    schema: BUILD_SELECTION_SCHEMA,
    sourceRevision: installation.sourceRevision,
    artifactId: installation.artifactId,
    archiveDigest: installation.archiveDigest,
    cargoMessagesDigest: rawDigest(cargoBytes),
    buildConsumptionPath: relativePath.split(path.sep).join("/"),
    buildConsumptionDigest: build.consumptionDigest,
  };
}

function parseOptions(argv, allowed, required) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    invariant(allowed.has(name), `unknown option ${name ?? "<missing>"}`);
    invariant(
      typeof value === "string" && !value.startsWith("--"),
      `${name}: expected one value`,
    );
    invariant(!values.has(name), `duplicate option ${name}`);
    values.set(name, value);
  }
  for (const name of required) invariant(values.has(name), `missing option ${name}`);
  return values;
}

async function main(argv) {
  const command = argv[0];
  const rest = argv.slice(1);
  if (command === "plan-release") {
    const options = parseOptions(
      rest,
      new Set(["--metadata", "--source-revision", "--release-tag", "--archive-name", "--output"]),
      ["--metadata", "--source-revision", "--release-tag", "--archive-name", "--output"],
    );
    const { value: metadata } = readStrictJson(
      options.get("--metadata"),
      MAX_METADATA_BYTES,
      "GitHub release metadata",
    );
    const plan = buildPortableReleasePlan({
      metadata,
      sourceRevision: options.get("--source-revision"),
      releaseTag: options.get("--release-tag"),
      archiveName: options.get("--archive-name"),
    });
    writeCanonicalExclusive(options.get("--output"), plan, "portable release plan");
    return;
  }
  if (command === "verify-release-download") {
    const options = parseOptions(
      rest,
      new Set(["--plan", "--metadata", "--directory"]),
      ["--plan", "--metadata", "--directory"],
    );
    const { value: plan } = readStrictJson(
      options.get("--plan"),
      MAX_PLAN_BYTES,
      "portable release plan",
      true,
    );
    const { value: metadata } = readStrictJson(
      options.get("--metadata"),
      MAX_METADATA_BYTES,
      "GitHub release metadata after download",
    );
    verifyPortableReleaseDownload({
      plan,
      metadata,
      directory: options.get("--directory"),
    });
    return;
  }
  if (command === "install-source-a") {
    const options = parseOptions(
      rest,
      new Set(["--archive", "--bundle", "--source-revision", "--repo-root", "--output"]),
      ["--archive", "--bundle", "--source-revision", "--repo-root", "--output"],
    );
    const result = await installPhysicalPromotionSourceA({
      archivePath: options.get("--archive"),
      bundlePath: options.get("--bundle"),
      expectedSourceRevision: options.get("--source-revision"),
      selectedRepoRoot: options.get("--repo-root"),
    });
    writeCanonicalExclusive(options.get("--output"), result, "physical-promotion installation result");
    return;
  }
  if (command === "verify-producer-run") {
    const options = parseOptions(
      rest,
      new Set(["--installation", "--metadata"]),
      ["--installation", "--metadata"],
    );
    const { value: installation } = readStrictJson(
      options.get("--installation"),
      MAX_INSTALLATION_BYTES,
      "physical-promotion installation result",
      true,
    );
    const { value: metadata } = readStrictJson(
      options.get("--metadata"),
      MAX_METADATA_BYTES,
      "exact producer run metadata",
    );
    verifyProducerRun({ installation, metadata });
    return;
  }
  if (command === "select-build-consumption") {
    const options = parseOptions(
      rest,
      new Set(["--cargo-messages", "--installation", "--repo-root", "--output"]),
      ["--cargo-messages", "--installation", "--repo-root", "--output"],
    );
    const { value: installation } = readStrictJson(
      options.get("--installation"),
      MAX_INSTALLATION_BYTES,
      "physical-promotion installation result",
      true,
    );
    const selection = selectBuildConsumption({
      cargoMessagesPath: options.get("--cargo-messages"),
      installation,
      selectedRepoRoot: options.get("--repo-root"),
    });
    writeCanonicalExclusive(options.get("--output"), selection, "portable build selection");
    return;
  }
  refuse(
    "usage: node scripts/portable-engine-physical-promotion.mjs <plan-release|verify-release-download|install-source-a|verify-producer-run|select-build-consumption> ...",
  );
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(
      `portable-engine-physical-promotion: ${error.message}\n`,
    );
    process.exitCode = 1;
  });
}
