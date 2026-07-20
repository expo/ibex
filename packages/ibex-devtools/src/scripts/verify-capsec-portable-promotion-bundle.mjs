#!/usr/bin/env node

// Final filesystem-to-byte-graph gate before a physical promotion bundle is
// handed to immutable artifact storage. It reconstructs the sole v2 validator
// input from exact directory membership; report, attestation, advertisement,
// and manifest bytes therefore retain the locality-free contract even though
// the bundle also carries detached machine-local mapped evidence.
//
// @ref LLP 0035#reports-and-advertisements — publication bytes are accepted
// only through validatePortablePromotionV2 and exact raw-content joins.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  parseJsonStrict,
  semanticDigest as computeDomainDigest,
} from "../../../../scripts/portable-engine-contract.mjs";
import {
  rawContentDigest,
  validatePortablePromotionV2,
} from "./capsec-portable-engine-evidence-contract.mjs";

const BUNDLE_SCHEMA = "ibex/capsec-portable-promotion-bundle/1";
const BUNDLE_DOMAIN = "ibex:capsec:portable-promotion-bundle:1";
const PROFILE = "ibex/capsec/1";
const DIGEST_PATTERN = /^sha256-[A-Za-z0-9_-]{43}$/u;
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const LOGICAL_NAME_PATTERN = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/u;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_MEMBER_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_MEMBERS = 100_000;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const EFFECTIVE_UID =
  typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : typeof process.getuid === "function"
      ? BigInt(process.getuid())
      : null;
const CORE_NAMES = Object.freeze([
  "portable-promotion-authority",
  "portable-conformance-report",
  "target-attestations",
  "target-advertisements",
  "target-cells",
  "recipes",
  "public-surface",
  "output-dispositions",
]);

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
    `${label}: unknown or missing fields`,
  );
}

function readPinned(filePath, maximumBytes, label) {
  const before = fs.lstatSync(filePath, { bigint: true });
  invariant(
    before.isFile() && !before.isSymbolicLink() && before.nlink === 1n,
    `${label}: expected one no-follow, single-link regular file`,
  );
  if (EFFECTIVE_UID !== null) {
    invariant(
      before.uid === EFFECTIVE_UID,
      `${label}: file is not owned by the effective UID`,
    );
  }
  invariant(
    (Number(before.mode & 0o7777n) & 0o7022) === 0,
    `${label}: file has unsafe mode bits`,
  );
  invariant(
    before.size > 0n && before.size <= BigInt(maximumBytes),
    `${label}: byte size is outside the bound`,
  );
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    invariant(
      opened.dev === before.dev &&
        opened.ino === before.ino &&
        opened.size === before.size,
      `${label}: file identity changed while opening`,
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(filePath, { bigint: true });
    for (const current of [after, pathAfter]) {
      invariant(
        current.isFile() &&
          !current.isSymbolicLink() &&
          current.nlink === 1n &&
          current.dev === opened.dev &&
          current.ino === opened.ino &&
          current.size === opened.size &&
          current.mtimeNs === opened.mtimeNs &&
          current.ctimeNs === opened.ctimeNs,
        `${label}: file object changed while reading`,
      );
    }
    invariant(bytes.byteLength === Number(opened.size), `${label}: short read`);
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function processGroups(files) {
  const groups = new Map();
  for (const file of files) {
    const match = file.logicalName.match(
      /^process-([0-9]{4})\.(mapped-evidence|command-attempt|fixture-([0-9]{6}))$/u,
    );
    if (!match) continue;
    const processIndex = Number(match[1]);
    const group = groups.get(processIndex) ?? {
      mappedEvidenceBytes: null,
      commandAttemptBytes: null,
      fixtureBytes: new Map(),
    };
    if (match[2] === "mapped-evidence") {
      invariant(group.mappedEvidenceBytes === null, "duplicate mapped evidence member");
      group.mappedEvidenceBytes = file.bytes;
    } else if (match[2] === "command-attempt") {
      invariant(group.commandAttemptBytes === null, "duplicate command-attempt member");
      group.commandAttemptBytes = file.bytes;
    } else {
      const fixtureIndex = Number(match[3]);
      invariant(!group.fixtureBytes.has(fixtureIndex), "duplicate fixture member");
      group.fixtureBytes.set(fixtureIndex, file.bytes);
    }
    groups.set(processIndex, group);
  }
  const indexes = [...groups.keys()].sort((left, right) => left - right);
  invariant(indexes.length > 0, "portable bundle has no detached process");
  invariant(
    indexes.every((value, index) => value === index + 1),
    "portable bundle process numbering is not contiguous",
  );
  return indexes.map((index) => {
    const group = groups.get(index);
    invariant(
      group.mappedEvidenceBytes && group.commandAttemptBytes,
      `process ${index}: mapped evidence or command attempt is missing`,
    );
    const fixtureIndexes = [...group.fixtureBytes.keys()].sort(
      (left, right) => left - right,
    );
    invariant(
      fixtureIndexes.length > 0 &&
        fixtureIndexes.every((value, fixtureIndex) => value === fixtureIndex + 1),
      `process ${index}: fixture numbering is empty or noncontiguous`,
    );
    return {
      mappedEvidenceBytes: group.mappedEvidenceBytes,
      commandAttemptBytes: group.commandAttemptBytes,
      outputArtifactBytes: fixtureIndexes.map((fixtureIndex) =>
        group.fixtureBytes.get(fixtureIndex),
      ),
    };
  });
}

function parseManifest(manifestBytes, expectedSourceRevision) {
  invariant(
    Buffer.isBuffer(manifestBytes) &&
      manifestBytes.byteLength > 0 &&
      manifestBytes.byteLength <= MAX_MANIFEST_BYTES,
    "portable bundle manifest byte size is outside the bound",
  );
  invariant(
    SOURCE_REVISION_PATTERN.test(expectedSourceRevision),
    "expected source revision must be one lowercase SHA-1 commit ID",
  );
  const manifest = parseJsonStrict(manifestBytes, "portable bundle manifest");
  exactKeys(
    manifest,
    [
      "portablePromotionBundleSchema",
      "profile",
      "sourceRevision",
      "sourceTreeDigest",
      "target",
      "files",
      "bundleDigest",
    ],
    "portable bundle manifest",
  );
  invariant(
    manifest.portablePromotionBundleSchema === BUNDLE_SCHEMA &&
      manifest.profile === PROFILE &&
      manifest.sourceRevision === expectedSourceRevision &&
      DIGEST_PATTERN.test(manifest.sourceTreeDigest) &&
      DIGEST_PATTERN.test(manifest.bundleDigest),
    "portable bundle manifest identity is malformed or from another source",
  );
  invariant(
    manifest.bundleDigest ===
      computeDomainDigest(BUNDLE_DOMAIN, manifest, ["bundleDigest"]),
    "portable bundle manifest digest mismatch",
  );
  invariant(
    Array.isArray(manifest.files) &&
      manifest.files.length > CORE_NAMES.length &&
      manifest.files.length <= MAX_MEMBERS,
    "portable bundle manifest member count is outside the bound",
  );
  const logicalNames = [];
  const seenNames = new Set();
  for (const [index, file] of manifest.files.entries()) {
    exactKeys(
      file,
      ["logicalName", "byteLength", "rawContentDigest"],
      `portable bundle file row ${index}`,
    );
    invariant(
      typeof file.logicalName === "string" &&
        LOGICAL_NAME_PATTERN.test(file.logicalName) &&
        !seenNames.has(file.logicalName) &&
        Number.isSafeInteger(file.byteLength) &&
        file.byteLength > 0 &&
        file.byteLength <= MAX_MEMBER_BYTES &&
        DIGEST_PATTERN.test(file.rawContentDigest),
      `portable bundle file row ${index} is malformed or duplicate`,
    );
    seenNames.add(file.logicalName);
    logicalNames.push(file.logicalName);
  }
  invariant(
    CORE_NAMES.every((logicalName, index) => logicalNames[index] === logicalName),
    "portable bundle does not carry the exact ordered core logical members",
  );
  invariant(
    logicalNames.every(
      (logicalName) =>
        CORE_NAMES.includes(logicalName) || logicalName.startsWith("process-"),
    ),
    "portable bundle has an unexpected logical member",
  );
  return { logicalNames, manifest };
}

/**
 * Validate one complete exact-byte bundle graph independently of its storage
 * medium. Filesystem verification and checked-Git promotion lineage both use
 * this entry point, so neither can replace the detached graph with a
 * self-authored manifest/core subset.
 */
export function validatePortablePromotionBundleGraph({
  manifestBytes,
  members,
  expectedSourceRevision,
  expectedSourceTreeDigest = null,
  expectedTarget = null,
  expectedPortableArtifactId = null,
}) {
  const { logicalNames, manifest } = parseManifest(
    manifestBytes,
    expectedSourceRevision,
  );
  if (expectedSourceTreeDigest !== null) {
    invariant(
      DIGEST_PATTERN.test(expectedSourceTreeDigest) &&
        manifest.sourceTreeDigest === expectedSourceTreeDigest,
      "portable bundle source-tree identity differs from checked authority",
    );
  }
  if (expectedTarget !== null) {
    invariant(
      canonicalJson(manifest.target) === canonicalJson(expectedTarget),
      "portable bundle target differs from checked authority",
    );
  }
  if (expectedPortableArtifactId !== null) {
    invariant(
      DIGEST_PATTERN.test(expectedPortableArtifactId),
      "expected portable artifact ID is malformed",
    );
  }
  invariant(
    Array.isArray(members) && members.length === manifest.files.length,
    "portable bundle exact member set differs from its manifest",
  );
  const supplied = new Map();
  for (const [index, member] of members.entries()) {
    exactKeys(member, ["logicalName", "bytes"], `portable bundle member ${index}`);
    invariant(
      typeof member.logicalName === "string" &&
        LOGICAL_NAME_PATTERN.test(member.logicalName) &&
        !supplied.has(member.logicalName) &&
        Buffer.isBuffer(member.bytes),
      `portable bundle member ${index} is malformed or duplicate`,
    );
    supplied.set(member.logicalName, member.bytes);
  }
  invariant(
    supplied.size === logicalNames.length &&
      logicalNames.every((logicalName) => supplied.has(logicalName)),
    "portable bundle exact member set differs from its manifest",
  );
  let totalBytes = manifestBytes.byteLength;
  const files = manifest.files.map((file) => {
    const bytes = supplied.get(file.logicalName);
    totalBytes += bytes.byteLength;
    invariant(totalBytes <= MAX_TOTAL_BYTES, "portable bundle exceeds its total byte bound");
    invariant(bytes.byteLength === file.byteLength, `${file.logicalName}: byte length mismatch`);
    invariant(
      rawContentDigest(bytes) === file.rawContentDigest,
      `${file.logicalName}: raw-content digest mismatch`,
    );
    return { ...file, bytes };
  });
  const processes = processGroups(files);
  const expectedOrder = [...CORE_NAMES];
  processes.forEach((process, processIndex) => {
    const prefix = `process-${String(processIndex + 1).padStart(4, "0")}`;
    expectedOrder.push(`${prefix}.mapped-evidence`, `${prefix}.command-attempt`);
    process.outputArtifactBytes.forEach((_bytes, fixtureIndex) => {
      expectedOrder.push(
        `${prefix}.fixture-${String(fixtureIndex + 1).padStart(6, "0")}`,
      );
    });
  });
  invariant(
    logicalNames.length === expectedOrder.length &&
      logicalNames.every((logicalName, index) => logicalName === expectedOrder[index]),
    "portable bundle member order or detached process groups are incomplete",
  );
  const byName = new Map(files.map((file) => [file.logicalName, file.bytes]));
  const validated = validatePortablePromotionV2({
    authorityBytes: byName.get("portable-promotion-authority"),
    reportBytes: byName.get("portable-conformance-report"),
    attestationCatalogBytes: byName.get("target-attestations"),
    advertisementCatalogBytes: byName.get("target-advertisements"),
    targetCellsBytes: byName.get("target-cells"),
    recipeCatalogBytes: byName.get("recipes"),
    publicSurfaceExecutionBytes: byName.get("public-surface"),
    outputDispositionEvidenceBytes: byName.get("output-dispositions"),
    processes,
  });
  invariant(
    validated.report.bindings?.sourceRevision === expectedSourceRevision &&
      validated.report.bindings?.sourceTreeDigest === manifest.sourceTreeDigest &&
      canonicalJson(validated.report.bindings?.target) === canonicalJson(manifest.target) &&
      (expectedPortableArtifactId === null ||
        validated.report.bindings?.engine?.artifactId === expectedPortableArtifactId),
    "portable bundle validator, manifest, and checked identities differ",
  );
  return { bundleDigest: manifest.bundleDigest, manifest, validated };
}

export function verifyPortablePromotionBundleDirectory({
  directory,
  expectedSourceRevision,
}) {
  invariant(
    SOURCE_REVISION_PATTERN.test(expectedSourceRevision),
    "expected source revision must be one lowercase SHA-1 commit ID",
  );
  const absolute = path.resolve(directory);
  invariant(fs.realpathSync(absolute) === absolute, "portable bundle directory is redirected");
  const directoryStatus = fs.lstatSync(absolute, { bigint: true });
  invariant(
    directoryStatus.isDirectory() && !directoryStatus.isSymbolicLink(),
    "portable bundle path is not one directory",
  );
  if (EFFECTIVE_UID !== null) {
    invariant(
      directoryStatus.uid === EFFECTIVE_UID,
      "portable bundle directory is not owned by the effective UID",
    );
  }
  invariant(
    (Number(directoryStatus.mode & 0o7777n) & 0o7022) === 0,
    "portable bundle directory has unsafe mode bits",
  );
  const manifestPath = path.join(absolute, "bundle-manifest.json");
  const manifestBytes = readPinned(
    manifestPath,
    MAX_MANIFEST_BYTES,
    "portable bundle manifest",
  );
  const { logicalNames, manifest } = parseManifest(
    manifestBytes,
    expectedSourceRevision,
  );
  const expectedNames = [
    "bundle-manifest.json",
    ...logicalNames.map((logicalName) => `${logicalName}.json`),
  ].sort();
  const actualNames = fs.readdirSync(absolute).sort();
  invariant(
    actualNames.length === expectedNames.length &&
      actualNames.every((name, index) => name === expectedNames[index]),
    "portable bundle directory has missing or unexpected files",
  );

  const members = manifest.files.map((file) => {
    const bytes = readPinned(
      path.join(absolute, `${file.logicalName}.json`),
      MAX_MEMBER_BYTES,
      `portable bundle ${file.logicalName}`,
    );
    return { logicalName: file.logicalName, bytes };
  });
  return validatePortablePromotionBundleGraph({
    manifestBytes,
    members,
    expectedSourceRevision,
  });
}

function main(argv) {
  if (
    argv.length !== 4 ||
    argv[0] !== "--directory" ||
    argv[2] !== "--expected-source-revision"
  ) {
    refuse(
      "usage: bun verify-capsec-portable-promotion-bundle.mjs --directory PATH --expected-source-revision 40_HEX",
    );
  }
  const result = verifyPortablePromotionBundleDirectory({
    directory: argv[1],
    expectedSourceRevision: argv[3],
  });
  process.stdout.write(`${result.bundleDigest}\n`);
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `verify-capsec-portable-promotion-bundle: ${error.message}\n`,
    );
    process.exitCode = 1;
  }
}
