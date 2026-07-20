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
  computeDomainDigest,
  parseJsonStrict,
} from "./capsec-contract.mjs";
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
const CORE_NAMES = Object.freeze([
  "portable-promotion-authority",
  "portable-conformance-report",
  "portable-target-attestations",
  "portable-target-advertisements",
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
  if (typeof process.getuid === "function") {
    invariant(
      before.uid === BigInt(process.getuid()),
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
  if (typeof process.getuid === "function") {
    invariant(
      directoryStatus.uid === BigInt(process.getuid()),
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
  const logicalNames = manifest.files.map((file) => file?.logicalName);
  invariant(
    logicalNames.every(
      (logicalName) =>
        typeof logicalName === "string" &&
        LOGICAL_NAME_PATTERN.test(logicalName),
    ) && new Set(logicalNames).size === logicalNames.length,
    "portable bundle logical names are malformed or duplicate",
  );
  for (const coreName of CORE_NAMES) {
    invariant(logicalNames.includes(coreName), `portable bundle is missing ${coreName}`);
  }
  invariant(
    logicalNames.every(
      (logicalName) =>
        CORE_NAMES.includes(logicalName) || logicalName.startsWith("process-"),
    ),
    "portable bundle has an unexpected logical member",
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

  let totalBytes = manifestBytes.byteLength;
  const files = manifest.files.map((file, index) => {
    exactKeys(
      file,
      ["logicalName", "byteLength", "rawContentDigest"],
      `portable bundle file row ${index}`,
    );
    invariant(
      Number.isSafeInteger(file.byteLength) &&
        file.byteLength > 0 &&
        file.byteLength <= MAX_MEMBER_BYTES &&
        DIGEST_PATTERN.test(file.rawContentDigest),
      `${file.logicalName}: manifest size or digest is malformed`,
    );
    const bytes = readPinned(
      path.join(absolute, `${file.logicalName}.json`),
      MAX_MEMBER_BYTES,
      `portable bundle ${file.logicalName}`,
    );
    totalBytes += bytes.byteLength;
    invariant(totalBytes <= MAX_TOTAL_BYTES, "portable bundle exceeds its total byte bound");
    invariant(bytes.byteLength === file.byteLength, `${file.logicalName}: byte length mismatch`);
    invariant(
      rawContentDigest(bytes) === file.rawContentDigest,
      `${file.logicalName}: raw-content digest mismatch`,
    );
    return { ...file, bytes };
  });
  const byName = new Map(files.map((file) => [file.logicalName, file.bytes]));
  const input = {
    authorityBytes: byName.get("portable-promotion-authority"),
    reportBytes: byName.get("portable-conformance-report"),
    attestationCatalogBytes: byName.get("portable-target-attestations"),
    advertisementCatalogBytes: byName.get("portable-target-advertisements"),
    targetCellsBytes: byName.get("target-cells"),
    recipeCatalogBytes: byName.get("recipes"),
    publicSurfaceExecutionBytes: byName.get("public-surface"),
    outputDispositionEvidenceBytes: byName.get("output-dispositions"),
    processes: processGroups(files),
  };
  const validated = validatePortablePromotionV2(input);
  invariant(
    validated.report.bindings?.sourceRevision === expectedSourceRevision &&
      canonicalJson(validated.report.bindings?.target) ===
        canonicalJson(manifest.target),
    "portable bundle validator and manifest identities differ",
  );
  return { bundleDigest: manifest.bundleDigest, manifest, validated };
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
