// Deterministic final-executable evidence for the portable macOS Hermes gate.
// The production entry point obtains its store snapshot only through the fixed
// installer verifier. Injectable dependencies are confined to the explicitly
// test-only entry point at the bottom of this file.
//
// @ref LLP 0035#build-consumption-and-post-link-contracts — one canonical
// result is emitted for every bounded Cargo final-executable identity, after
// direct Mach-O inspection and a fresh portable-store/transport verification.
// @ref LLP 0035#content-addressed-installation — runtime resolution must land
// in the exact checkout-local artifact payload selected by build consumption.

import Ajv2020 from "ajv/dist/2020.js";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";

import {
  assertCanonicalJsonBytes,
  assertExactKeys,
  canonicalJson,
  compareUtf8,
  parseJsonStrict,
  parseMachO,
  rawDigest,
  semanticDigest,
} from "./portable-engine-contract.mjs";

const TARGET_TRIPLE = "aarch64-apple-darwin";
const BUILD_SCHEMA = "ibex/portable-engine-build-consumption/1";
const POST_LINK_SCHEMA = "ibex/portable-engine-post-link-verification/1";
const POST_LINK_SET_SCHEMA =
  "ibex/portable-engine-post-link-verification-set/1";
const ENUMERATION_SCHEMA = "ibex/portable-engine-cargo-executable-set/1";
const ENUMERATION_MODE = "cargo-test-no-run-all-targets";
const ENUMERATION_PATH =
  "config/portable-engine-cargo-executables-authenticated-v1.json";
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_CARGO_MESSAGES_BYTES = 64 * 1024 * 1024;
const MAX_CARGO_MESSAGE_BYTES = 4 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024;
const MAX_EXECUTABLE_COUNT = 4096;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const OPEN_READ_NOFOLLOW = fs.constants.O_RDONLY | NOFOLLOW;
const OPEN_CREATE_EXCLUSIVE =
  fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW;
const SCHEMA_PATHS = Object.freeze([
  "schemas/portable-engine-common-v1.schema.json",
  "schemas/portable-engine-provenance-trust-policy-v1.schema.json",
  "schemas/portable-engine-manifest-v1.schema.json",
  "schemas/portable-engine-installation-receipt-v1.schema.json",
  "schemas/portable-engine-artifact-identity-v1.schema.json",
  "schemas/portable-engine-header-set-v1.schema.json",
  "schemas/portable-engine-cargo-executable-set-v1.schema.json",
  "schemas/portable-engine-build-consumption-v1.schema.json",
  "schemas/portable-engine-post-link-verification-v1.schema.json",
  "schemas/portable-engine-post-link-verification-set-v1.schema.json",
]);
const FINAL_CARGO_KINDS = new Set(["bench", "bin", "example", "lib", "test"]);
const EVIDENCE_TARGET_KINDS = new Set(["bench", "bin", "example", "test"]);
const LOADER_RELATIVE_RPATH =
  /^@(?:executable_path|loader_path)(?:\/(?!\/)[A-Za-z0-9._+ -]+)*$/u;
const SEMANTIC_DIGEST = /^sha256-[A-Za-z0-9_-]{43}$/u;
const RAW_DIGEST = /^sha256-[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function equalJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function assertSame(left, right, label) {
  assert(
    equalJson(left, right),
    `${label}: expected ${canonicalJson(right)}, got ${canonicalJson(left)}`,
  );
}

function assertRawDigest(value, label) {
  assert(
    typeof value === "string" && RAW_DIGEST.test(value),
    `${label}: invalid raw digest`,
  );
}

function assertSemanticDigest(value, label) {
  assert(
    typeof value === "string" && SEMANTIC_DIGEST.test(value),
    `${label}: invalid semantic digest`,
  );
}

function assertSortedUniqueStrings(values, label) {
  assert(Array.isArray(values), `${label}: expected an array`);
  for (let index = 0; index < values.length; index += 1) {
    assert(
      typeof values[index] === "string",
      `${label}[${index}]: expected a string`,
    );
    if (index > 0) {
      assert(
        compareUtf8(values[index - 1], values[index]) < 0,
        `${label}: must be sorted and unique`,
      );
    }
  }
}

function assertRowsSortedUnique(rows, keyFor, label) {
  assert(Array.isArray(rows), `${label}: expected an array`);
  let prior = null;
  for (let index = 0; index < rows.length; index += 1) {
    const key = keyFor(rows[index]);
    assert(typeof key === "string", `${label}[${index}]: invalid sort key`);
    if (prior !== null)
      assert(
        compareUtf8(prior, key) < 0,
        `${label}: must be sorted and unique`,
      );
    prior = key;
  }
}

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return (
    relative !== "" &&
    !relative.startsWith(`..${path.sep}`) &&
    relative !== ".." &&
    !path.isAbsolute(relative)
  );
}

function fileObjectEqual(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function readPinnedRegular(
  filePath,
  label,
  maximumBytes,
  afterRead = null,
) {
  const realPath = await fsp.realpath(filePath).catch((error) => {
    if (error && error.code === "ENOENT") fail(`${label}: file is missing`);
    throw error;
  });
  assert(
    realPath === filePath,
    `${label}: path is redirected through a symlink`,
  );
  const handle = await fsp.open(filePath, OPEN_READ_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    assert(
      before.isFile() && !before.isSymbolicLink(),
      `${label}: expected one no-follow regular file`,
    );
    assert(before.nlink === 1n, `${label}: hard-linked files are forbidden`);
    assert(
      before.size > 0n && before.size <= BigInt(maximumBytes),
      `${label}: size is outside the bound`,
    );
    const bytes = Buffer.allocUnsafe(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        null,
      );
      assert(bytesRead > 0, `${label}: short read`);
      offset += bytesRead;
    }
    const trailing = Buffer.allocUnsafe(1);
    const { bytesRead: trailingBytes } = await handle.read(
      trailing,
      0,
      1,
      null,
    );
    assert(trailingBytes === 0, `${label}: file grew while it was being read`);
    if (afterRead)
      await afterRead({ bytes: Buffer.from(bytes), filePath, handle });
    const after = await handle.stat({ bigint: true });
    assert(
      fileObjectEqual(before, after),
      `${label}: file object changed while it was being read`,
    );
    return bytes;
  } finally {
    await handle.close();
  }
}

async function readCanonicalJsonFile(
  filePath,
  label,
  maximumBytes = MAX_JSON_BYTES,
) {
  const bytes = await readPinnedRegular(filePath, label, maximumBytes);
  const value = parseJsonStrict(bytes, label);
  assertCanonicalJsonBytes(bytes, value, label);
  return { bytes, value };
}

async function buildSchemaValidators(context) {
  assert(
    context && typeof context.readRevisionFile === "function",
    "verified store context does not expose checked-revision schema reads",
  );
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const relativePath of SCHEMA_PATHS) {
    const bytes = Buffer.from(await context.readRevisionFile(relativePath));
    assert(
      bytes.length > 0 && bytes.length <= 2 * 1024 * 1024,
      `${relativePath}: schema size is outside the bound`,
    );
    ajv.addSchema(parseJsonStrict(bytes, relativePath));
  }
  const validate = (schemaFile, value, label) => {
    const validator = ajv.getSchema(`https://ibex.dev/schemas/${schemaFile}`);
    assert(validator, `${label}: checked schema ${schemaFile} is unavailable`);
    if (!validator(value))
      fail(
        `${label}: schema validation failed: ${JSON.stringify(validator.errors)}`,
      );
  };
  return Object.freeze({
    build(value, label) {
      validate(
        "portable-engine-build-consumption-v1.schema.json",
        value,
        label,
      );
    },
    enumeration(value, label) {
      validate(
        "portable-engine-cargo-executable-set-v1.schema.json",
        value,
        label,
      );
    },
    headerSet(value, label) {
      validate("portable-engine-header-set-v1.schema.json", value, label);
    },
    manifest(value, label) {
      validate("portable-engine-manifest-v1.schema.json", value, label);
    },
    policy(value, label) {
      validate(
        "portable-engine-provenance-trust-policy-v1.schema.json",
        value,
        label,
      );
    },
    postLink(value, label) {
      validate(
        "portable-engine-post-link-verification-v1.schema.json",
        value,
        label,
      );
    },
    postLinkSet(value, label) {
      validate(
        "portable-engine-post-link-verification-set-v1.schema.json",
        value,
        label,
      );
    },
    receipt(value, label) {
      validate(
        "portable-engine-installation-receipt-v1.schema.json",
        value,
        label,
      );
    },
  });
}

function expectedEvidenceKind(cargoTargetKind, profileTest) {
  if (cargoTargetKind === "test" || cargoTargetKind === "lib") return "test";
  if (cargoTargetKind === "bin" && profileTest) return "test";
  return cargoTargetKind;
}

function validateEnumerationManifest(value) {
  assertExactKeys(
    value,
    [
      "schema",
      "mode",
      "package",
      "targetTriple",
      "ibexFeatures",
      "cargoArguments",
      "targets",
    ],
    "Cargo executable enumeration manifest",
  );
  assert(
    value.schema === ENUMERATION_SCHEMA,
    "Cargo executable enumeration manifest: wrong schema",
  );
  assert(
    value.mode === ENUMERATION_MODE,
    "Cargo executable enumeration manifest: wrong mode",
  );
  assertExactKeys(
    value.package,
    ["manifestPath", "name", "version"],
    "Cargo executable enumeration package",
  );
  assert(
    value.package.name === "ibex-runtime",
    "Cargo executable enumeration manifest: wrong package name",
  );
  assert(
    value.package.manifestPath === "Cargo.toml",
    "Cargo executable enumeration manifest: wrong package manifest path",
  );
  assert(
    typeof value.package.version === "string" &&
      /^[0-9]+\.[0-9]+\.[0-9]+$/u.test(value.package.version),
    "Cargo executable enumeration manifest: invalid package version",
  );
  assert(
    value.targetTriple === TARGET_TRIPLE,
    "Cargo executable enumeration manifest: wrong target triple",
  );
  assertSortedUniqueStrings(
    value.ibexFeatures,
    "Cargo executable enumeration manifest Ibex features",
  );
  const expectedCargoArguments = [
    "test",
    "--locked",
    "--no-run",
    "--all-targets",
    "--features",
    value.ibexFeatures.join(","),
    "--message-format=json",
  ];
  assertSame(
    value.cargoArguments,
    expectedCargoArguments,
    "Cargo executable enumeration arguments",
  );
  assert(
    Array.isArray(value.targets) &&
      value.targets.length > 0 &&
      value.targets.length <= MAX_EXECUTABLE_COUNT,
    "Cargo executable enumeration manifest: target count is outside the bound",
  );
  const identities = new Set();
  const logicalNames = new Set();
  let priorSortKey = null;
  for (let index = 0; index < value.targets.length; index += 1) {
    const row = value.targets[index];
    assertExactKeys(
      row,
      [
        "cargoTargetKind",
        "cargoTargetKinds",
        "cargoTargetName",
        "logicalName",
        "profileTest",
        "targetKind",
      ],
      `Cargo executable enumeration manifest target ${index}`,
    );
    assert(
      typeof row.cargoTargetName === "string" &&
        /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(row.cargoTargetName),
      `Cargo executable enumeration manifest target ${index}: invalid Cargo target name`,
    );
    assert(
      typeof row.cargoTargetKind === "string" &&
        FINAL_CARGO_KINDS.has(row.cargoTargetKind),
      `Cargo executable enumeration manifest target ${index}: invalid Cargo target kind`,
    );
    assertSortedUniqueStrings(
      row.cargoTargetKinds,
      `Cargo executable enumeration manifest target ${index} Cargo target kinds`,
    );
    if (row.cargoTargetKind === "lib") {
      assert(
        row.cargoTargetKinds.every((kind) =>
          ["cdylib", "dylib", "lib", "rlib", "staticlib"].includes(kind),
        ),
        `Cargo executable enumeration manifest target ${index}: invalid library target-kind set`,
      );
    } else {
      assertSame(
        row.cargoTargetKinds,
        [row.cargoTargetKind],
        `Cargo executable enumeration manifest target ${index} target-kind set`,
      );
    }
    assert(
      typeof row.profileTest === "boolean",
      `Cargo executable enumeration manifest target ${index}: invalid test profile flag`,
    );
    assert(
      EVIDENCE_TARGET_KINDS.has(row.targetKind),
      `Cargo executable enumeration manifest target ${index}: invalid evidence target kind`,
    );
    assert(
      row.targetKind ===
        expectedEvidenceKind(row.cargoTargetKind, row.profileTest),
      `Cargo executable enumeration manifest target ${index}: Cargo/evidence target kinds disagree`,
    );
    assert(
      row.logicalName === `${row.targetKind}/${row.cargoTargetName}`,
      `Cargo executable enumeration manifest target ${index}: logicalName is not the closed Cargo identity`,
    );
    if (row.cargoTargetKind === "lib") {
      assert(
        row.profileTest,
        `Cargo executable enumeration manifest target ${index}: a lib row must be a test harness`,
      );
    }
    const identity = `${row.cargoTargetKind}\0${row.cargoTargetName}\0${row.profileTest}`;
    assert(
      !identities.has(identity),
      `Cargo executable enumeration manifest target ${index}: duplicate Cargo identity`,
    );
    identities.add(identity);
    assert(
      !logicalNames.has(row.logicalName),
      `Cargo executable enumeration manifest target ${index}: duplicate logical identity`,
    );
    logicalNames.add(row.logicalName);
    const sortKey = `${row.logicalName}\0${row.cargoTargetKind}\0${row.profileTest}`;
    if (priorSortKey !== null) {
      assert(
        compareUtf8(priorSortKey, sortKey) < 0,
        "Cargo executable enumeration manifest targets must be sorted and unique",
      );
    }
    priorSortKey = sortKey;
  }
  return value;
}

function recognizedCargoKind(target, profileTest) {
  assert(
    target && typeof target === "object" && !Array.isArray(target),
    "Cargo compiler artifact has no target object",
  );
  assert(
    Array.isArray(target.kind),
    "Cargo compiler artifact target.kind is not an array",
  );
  const kinds = new Set(target.kind);
  const recognized = [...FINAL_CARGO_KINDS].filter((kind) => kinds.has(kind));
  if (recognized.length === 0) return null;
  assert(
    recognized.length === 1,
    "Cargo compiler artifact has an ambiguous final target kind",
  );
  return recognized[0];
}

function normalizedCargoKind(target, profileTest) {
  const direct = recognizedCargoKind(target, profileTest);
  if (direct !== null) return direct;
  const kinds = new Set(target.kind);
  if (
    profileTest &&
    ["cdylib", "dylib", "lib", "rlib", "staticlib"].some((kind) =>
      kinds.has(kind),
    )
  ) {
    return "lib";
  }
  return null;
}

function parseCargoMessages(bytes, enumeration, repoRoot) {
  assert(
    bytes.length > 0 && bytes.length <= MAX_CARGO_MESSAGES_BYTES,
    "Cargo JSON message stream size is outside the bound",
  );
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const lines = text.split("\n");
  const expected = new Map(
    enumeration.targets.map((row) => [
      `${row.cargoTargetKind}\0${row.cargoTargetName}\0${row.profileTest}`,
      row,
    ]),
  );
  const observed = new Map();
  const expectedManifestPath = path.join(
    repoRoot,
    ...enumeration.package.manifestPath.split("/"),
  );
  let selectedPackageId = null;
  let buildFinishedCount = 0;
  let buildFinishedSeen = false;
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index] === "") continue;
    const lineBytes = Buffer.from(lines[index], "utf8");
    assert(
      lineBytes.length <= MAX_CARGO_MESSAGE_BYTES,
      `Cargo JSON message ${index + 1} exceeds the line bound`,
    );
    const message = parseJsonStrict(
      lineBytes,
      `Cargo JSON message ${index + 1}`,
    );
    assert(
      message && typeof message === "object" && !Array.isArray(message),
      `Cargo JSON message ${index + 1}: expected an object`,
    );
    assert(
      !buildFinishedSeen,
      "Cargo JSON message appeared after build-finished",
    );
    if (message.reason === "build-finished") {
      buildFinishedCount += 1;
      assert(
        message.success === true,
        "Cargo --no-run build did not finish successfully",
      );
      buildFinishedSeen = true;
      continue;
    }
    if (message.reason !== "compiler-artifact") continue;
    if (
      typeof message.manifest_path !== "string" ||
      !path.isAbsolute(message.manifest_path) ||
      path.resolve(message.manifest_path) !== expectedManifestPath
    ) {
      continue;
    }
    assert(
      typeof message.package_id === "string" && message.package_id.length > 0,
      "root Cargo compiler artifact has no package ID",
    );
    assert(
      message.package_id.endsWith(
        `#${enumeration.package.name}@${enumeration.package.version}`,
      ),
      "root Cargo compiler artifact package ID disagrees with checked package identity",
    );
    if (selectedPackageId === null) selectedPackageId = message.package_id;
    assert(
      message.package_id === selectedPackageId,
      "root Cargo compiler artifacts disagree on package ID",
    );
    if (message.executable === null || message.executable === undefined)
      continue;
    assert(
      typeof message.target.name === "string",
      "Cargo compiler artifact target name is absent",
    );
    assert(
      message.profile && typeof message.profile.test === "boolean",
      "Cargo compiler artifact profile.test is absent",
    );
    const cargoTargetKind = normalizedCargoKind(
      message.target,
      message.profile.test,
    );
    if (cargoTargetKind === null) continue;
    const identity = `${cargoTargetKind}\0${message.target.name}\0${message.profile.test}`;
    const selected = expected.get(identity);
    assert(
      selected,
      `Cargo emitted unexpected final executable ${identity.replaceAll("\0", "/")}`,
    );
    assertSame(
      [...message.target.kind].sort(compareUtf8),
      selected.cargoTargetKinds,
      `${selected.logicalName} Cargo target kinds`,
    );
    assert(
      !observed.has(identity),
      `Cargo emitted duplicate final executable ${selected.logicalName}`,
    );
    assert(
      typeof message.executable === "string" &&
        path.isAbsolute(message.executable),
      `${selected.logicalName}: Cargo executable path is not absolute`,
    );
    const executablePath = path.resolve(message.executable);
    const targetRoot = path.join(repoRoot, "target");
    assert(
      isWithin(targetRoot, executablePath),
      `${selected.logicalName}: Cargo executable escapes the checkout target directory`,
    );
    observed.set(identity, { ...selected, executablePath });
  }
  assert(
    buildFinishedCount === 1,
    `Cargo JSON message stream must contain exactly one successful build-finished record; found ${buildFinishedCount}`,
  );
  assert(
    selectedPackageId !== null,
    "Cargo JSON message stream contains no root package artifacts",
  );
  const missing = [...expected.entries()]
    .filter(([identity]) => !observed.has(identity))
    .map(([, row]) => row.logicalName)
    .sort(compareUtf8);
  assert(
    missing.length === 0,
    `Cargo JSON message stream is missing final executables: ${missing.join(", ")}`,
  );
  return [...observed.values()].sort((left, right) =>
    compareUtf8(left.logicalName, right.logicalName),
  );
}

function derivePortableIdentity(manifest) {
  const runtimeRows = manifest.interface.loadableComponents.filter(
    (row) => row.system === false && row.role === "runtime",
  );
  assert(
    runtimeRows.length === 1,
    `portable manifest must contain exactly one non-system runtime; found ${runtimeRows.length}`,
  );
  const runtime = runtimeRows[0];
  assert(
    runtime.path === manifest.runtimeComponent,
    "portable manifest runtime rows disagree",
  );
  return {
    schema: "ibex/portable-engine-artifact-identity/1",
    artifactId: manifest.artifactId,
    artifactKind: manifest.artifactKind,
    target: structuredClone(manifest.target),
    profile: {
      id: manifest.profile.id,
      targetVariant: manifest.profile.targetVariant,
      configuration: manifest.profile.configuration,
      debugger: manifest.profile.debugger,
      hermesBytecodeVersion: manifest.profile.hermesBytecodeVersion,
    },
    runtimeComponentDigest: runtime.digest,
    reviewedProfileIdentityDigest:
      manifest.profile.reviewedProfileIdentityDigest,
    interfaceContractDigest: semanticDigest(
      "ibex.portable-engine-interface.v1",
      manifest.interface,
    ),
  };
}

function regularEntry(manifest, relativePath, label) {
  const matches = manifest.entries.filter(
    (entry) => entry.kind === "regular" && entry.path === relativePath,
  );
  assert(
    matches.length === 1,
    `${label}: expected exactly one regular manifest entry`,
  );
  return matches[0];
}

function compareRows(left, right) {
  return compareUtf8(canonicalJson(left), canonicalJson(right));
}

function validateBuildJoins(
  build,
  manifest,
  receipt,
  policy,
  targetPolicy,
  headerSet,
) {
  assert(build.schema === BUILD_SCHEMA, "build consumption: wrong schema");
  assert(
    build.consumptionDigest ===
      semanticDigest("ibex.portable-engine-build-consumption.v1", build, [
        "consumptionDigest",
      ]),
    "build consumption digest mismatch",
  );
  assertSame(
    build.portable,
    derivePortableIdentity(manifest),
    "build consumption portable identity",
  );
  const manifestDigest = semanticDigest(
    "ibex.portable-engine-manifest-digest.v1",
    manifest,
  );
  const receiptDigest = semanticDigest(
    "ibex.portable-engine-installation-receipt.v1",
    receipt,
  );
  const policyDigest = semanticDigest(
    "ibex.portable-engine-provenance-trust-policy.v1",
    policy,
  );
  assert(
    build.manifestDigest === manifestDigest,
    "build consumption manifest digest mismatch",
  );
  assert(
    build.installationReceiptDigest === receiptDigest,
    "build consumption installation receipt digest mismatch",
  );
  assert(
    build.verificationPolicyDigest === policyDigest,
    "build consumption policy digest mismatch",
  );
  assert(
    receipt.artifactId === manifest.artifactId,
    "installation receipt artifact ID mismatch",
  );
  assert(
    receipt.manifestDigest === manifestDigest,
    "installation receipt manifest digest mismatch",
  );
  assert(
    receipt.verificationPolicyDigest === policyDigest,
    "installation receipt policy digest mismatch",
  );
  assertSame(build.target, manifest.target, "build consumption target");
  assertSame(
    build.target,
    targetPolicy && {
      triple: targetPolicy.triple,
      structuralFeatures: targetPolicy.structuralFeatures,
    },
    "build consumption admitted target",
  );
  assert(
    build.target.triple === TARGET_TRIPLE,
    "build consumption is not the portable macOS arm64 target",
  );
  assertSortedUniqueStrings(
    build.target.structuralFeatures,
    "build consumption structural features",
  );
  assertSortedUniqueStrings(
    build.ibexFeatures,
    "build consumption Ibex features",
  );
  assert(
    targetPolicy.nonSystemLoadableComponentPolicy === "runtime-only",
    "admitted target does not require runtime-only non-system loading",
  );

  const runtimeEntry = regularEntry(
    manifest,
    manifest.runtimeComponent,
    "manifest runtime component",
  );
  assert(
    build.portable.runtimeComponentDigest === runtimeEntry.digest,
    "portable identity and manifest runtime entry digests disagree",
  );
  const expectedRuntime = {
    path: runtimeEntry.path,
    digest: runtimeEntry.digest,
    size: runtimeEntry.size,
  };
  assertSame(
    build.runtimeComponent,
    expectedRuntime,
    "build consumption runtime component",
  );
  const expectedLinkInputs = manifest.entries
    .filter(
      (entry) =>
        entry.kind === "regular" &&
        ["runtime", "link-input"].includes(entry.role),
    )
    .map((entry) => ({
      role: entry.role,
      path: entry.path,
      digest: entry.digest,
      size: entry.size,
    }))
    .sort(compareRows);
  assertRowsSortedUnique(
    build.linkInputs,
    (row) => `${row.role}\0${row.path}`,
    "build consumption link inputs",
  );
  const observedLinkInputs = [...build.linkInputs].sort(compareRows);
  assertSame(
    observedLinkInputs,
    expectedLinkInputs,
    "build consumption link inputs",
  );
  const nonSystem = manifest.interface.loadableComponents.filter(
    (row) => row.system === false,
  );
  const expectedDependencies = nonSystem
    .filter((row) => row.role === "runtime-dependency")
    .map((row) => {
      const entry = regularEntry(
        manifest,
        row.path,
        `manifest runtime dependency ${row.path}`,
      );
      return {
        role: "runtime-dependency",
        path: row.path,
        digest: row.digest,
        size: entry.size,
      };
    })
    .sort(compareRows);
  assertRowsSortedUnique(
    build.nonSystemLoadableDependencies,
    (row) => `${row.role}\0${row.path}`,
    "build consumption non-system dependencies",
  );
  assertSame(
    [...build.nonSystemLoadableDependencies].sort(compareRows),
    expectedDependencies,
    "build consumption non-system dependencies",
  );
  assert(
    expectedDependencies.length === 0,
    "portable macOS v1 admits no non-system loadable dependency beyond the runtime",
  );

  const expectedHeaderFiles = [...headerSet.headers];
  assertRowsSortedUnique(
    build.headers.files,
    (row) => row.path,
    "build consumption header files",
  );
  assertSame(
    build.headers.files,
    expectedHeaderFiles,
    "build consumption header files",
  );
  assert(
    build.headers.headerSetDigest ===
      semanticDigest("ibex.portable-engine-header-set.v1", headerSet),
    "build consumption header-set digest mismatch",
  );
  assertSame(
    build.headers.includeRoots,
    headerSet.includeRoots,
    "build consumption include roots",
  );
  for (const file of expectedHeaderFiles) {
    assert(
      headerSet.includeRoots.some((root) => file.path.startsWith(`${root}/`)),
      `${file.path}: header is outside every include root`,
    );
  }

  const expectedHostTools = manifest.interface.hostTools
    .map((tool) => {
      const entry = regularEntry(
        manifest,
        tool.path,
        `manifest host tool ${tool.path}`,
      );
      assert(
        entry.digest === tool.digest,
        `${tool.path}: host-tool interface and entry digests disagree`,
      );
      return { ...tool, size: entry.size };
    })
    .sort(compareRows);
  assertRowsSortedUnique(
    build.hostTools,
    (row) => `${row.role}\0${row.path}`,
    "build consumption host tools",
  );
  assertSame(
    [...build.hostTools].sort(compareRows),
    expectedHostTools,
    "build consumption host tools",
  );
  return { manifestDigest, receiptDigest, policyDigest, runtimeEntry };
}

async function readAuthenticatedHeaderSet(artifactRoot, manifest, validators) {
  const relativePath = "META-INF/authority/header-set.json";
  const entry = regularEntry(
    manifest,
    relativePath,
    "manifest header-set authority",
  );
  assert(entry.role === "metadata", "header-set authority has the wrong role");
  const { bytes, value } = await readCanonicalJsonFile(
    path.join(artifactRoot, "payload", ...relativePath.split("/")),
    "authenticated header-set authority",
  );
  assert(
    bytes.length === entry.size && rawDigest(bytes) === entry.digest,
    "header-set authority bytes do not join the portable manifest",
  );
  validators.headerSet(value, "authenticated header-set authority");
  assert(
    value.targetTriple === TARGET_TRIPLE,
    "authenticated header set has the wrong target triple",
  );
  assertSortedUniqueStrings(
    value.includeRoots,
    "authenticated header-set include roots",
  );
  assertRowsSortedUnique(
    value.headers,
    (row) => row.path,
    "authenticated header-set files",
  );
  const manifestHeaders = manifest.entries
    .filter(
      (candidate) =>
        candidate.kind === "regular" && candidate.role === "header",
    )
    .map(({ path: pathname, digest, size }) => ({
      path: pathname,
      digest,
      size,
    }))
    .sort((left, right) => compareUtf8(left.path, right.path));
  assertSame(
    value.headers,
    manifestHeaders,
    "authenticated header set and portable manifest",
  );
  assert(
    manifest.interface.headerSetDigest ===
      semanticDigest("ibex.portable-engine-header-set.v1", value),
    "authenticated header-set digest does not join the portable manifest",
  );
  return value;
}

function payloadRevalidation(manifest, build, digests) {
  const regular = manifest.entries.filter((entry) => entry.kind === "regular");
  const regularByteCount = regular.reduce((total, entry) => {
    const next = total + entry.size;
    assert(
      Number.isSafeInteger(next),
      "portable manifest regular-byte count exceeds the safe integer range",
    );
    return next;
  }, 0);
  assert(
    manifest.entries.length > 0 && regular.length > 0 && regularByteCount > 0,
    "portable manifest payload counts must be positive",
  );
  return {
    artifactId: manifest.artifactId,
    buildConsumptionDigest: build.consumptionDigest,
    manifestDigest: digests.manifestDigest,
    installationReceiptDigest: digests.receiptDigest,
    verificationPolicyDigest: digests.policyDigest,
    manifestEntryCount: manifest.entries.length,
    regularEntryCount: regular.length,
    regularByteCount,
    manifestGraphValidation: "complete-exact-membership-path-and-link-graph",
    transportProvenanceReverified: true,
  };
}

async function pathExistsNoFollow(candidate) {
  try {
    return await fsp.lstat(candidate, { bigint: true });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

function expandExecutableRpath(rpath, executablePath) {
  const token = rpath.startsWith("@loader_path")
    ? "@loader_path"
    : "@executable_path";
  const suffix = rpath.slice(token.length);
  assert(
    suffix === "" || suffix.startsWith("/"),
    `invalid loader-relative RPATH ${rpath}`,
  );
  return path.resolve(path.dirname(executablePath), suffix.replace(/^\//u, ""));
}

async function verifyRuntimeResolution({
  executablePath,
  targetKind,
  observation,
  artifactRoot,
  manifest,
  runtimeEntry,
}) {
  assert(
    observation.fileType === 2,
    "final engine executable is not MH_EXECUTE",
  );
  assert(
    observation.cpuSubtype === 0,
    "final engine executable is not ARM64_ALL",
  );
  assert(
    observation.dylinker === "/usr/lib/dyld",
    "final engine executable has the wrong dynamic linker",
  );
  assert(
    observation.dyldEnvironment.length === 0,
    "final engine executable embeds a DYLD environment",
  );
  assert(
    observation.rpaths.length > 0,
    "final engine executable has no LC_RPATH",
  );
  for (const rpath of observation.rpaths) {
    assert(
      LOADER_RELATIVE_RPATH.test(rpath),
      `final engine executable has non-loader-relative RPATH ${rpath}`,
    );
  }
  assert(
    manifest.runtimeComponent.startsWith("lib/"),
    "portable runtime component is not beneath payload/lib",
  );
  const expectedRuntimePath = path.join(
    artifactRoot,
    "payload",
    ...manifest.runtimeComponent.split("/"),
  );
  const targetRoot = path.dirname(path.dirname(artifactRoot));
  const expectedExecutableDirectory =
    targetKind === "bin"
      ? path.join(targetRoot, "debug")
      : targetKind === "example"
        ? path.join(targetRoot, "debug", "examples")
        : path.join(targetRoot, "debug", "deps");
  assert(
    path.dirname(executablePath) === expectedExecutableDirectory,
    `final ${targetKind} executable is outside its checked Cargo output directory`,
  );
  const expectedRpathRoot = path.join(artifactRoot, "payload", "lib");
  const relativeRpathRoot = path.relative(
    path.dirname(executablePath),
    expectedRpathRoot,
  );
  assert(
    relativeRpathRoot.length > 0 && !path.isAbsolute(relativeRpathRoot),
    "portable runtime RPATH root is not relative to the final executable",
  );
  const expectedRpath = `@loader_path/${relativeRpathRoot
    .split(path.sep)
    .join("/")}`;
  const runtimeBytes = await readPinnedRegular(
    expectedRuntimePath,
    "portable runtime component",
    MAX_EXECUTABLE_BYTES,
  );
  assert(
    runtimeBytes.length === runtimeEntry.size,
    "portable runtime size changed after store verification",
  );
  assert(
    rawDigest(runtimeBytes) === runtimeEntry.digest,
    "portable runtime digest changed after store verification",
  );
  const runtimeObservation = parseMachO(runtimeBytes, {
    architecture: "arm64",
    requireExternalDefinedSymbols: false,
  });
  assert(
    runtimeObservation.fileType === 6,
    "portable runtime component is not MH_DYLIB",
  );
  const expectedInstallName = `@rpath/${manifest.runtimeComponent.slice("lib/".length)}`;
  assert(
    runtimeObservation.dylibId === expectedInstallName,
    "portable runtime LC_ID_DYLIB disagrees with its manifest path",
  );
  const runtimeDependencies = observation.dependencyCommands.filter(
    (row) => row.installName === expectedInstallName,
  );
  assert(
    runtimeDependencies.length === 1,
    `final executable must load exactly one selected Hermes runtime; found ${runtimeDependencies.length}`,
  );
  assert(
    runtimeDependencies[0].command === "LC_LOAD_DYLIB",
    "selected Hermes runtime is not loaded with LC_LOAD_DYLIB",
  );

  const installSuffix = expectedInstallName.slice("@rpath/".length);
  let exactResolutionCount = 0;
  for (const rpath of observation.rpaths) {
    const candidate = path.resolve(
      expandExecutableRpath(rpath, executablePath),
      ...installSuffix.split("/"),
    );
    const status = await pathExistsNoFollow(candidate);
    if (!status) continue;
    assert(
      status.isFile() && !status.isSymbolicLink(),
      `${rpath}: Hermes resolution candidate is not one no-follow regular file`,
    );
    const realCandidate = await fsp.realpath(candidate);
    assert(
      realCandidate === candidate,
      `${rpath}: Hermes resolution candidate is redirected through a symlink`,
    );
    assert(
      candidate === expectedRuntimePath,
      `${rpath}: Hermes resolves outside the selected artifact payload`,
    );
    exactResolutionCount += 1;
  }
  assert(
    exactResolutionCount === 1,
    `selected Hermes runtime must have exactly one existing RPATH resolution; found ${exactResolutionCount}`,
  );
  assertSame(
    observation.rpaths,
    [expectedRpath],
    "final engine executable canonical portable RPATH",
  );
  return { expectedInstallName, expectedRuntimePath };
}

async function auditExecutable({
  selected,
  artifactRoot,
  manifest,
  runtimeEntry,
  policy,
  targetPolicy,
  afterExecutableRead,
}) {
  const realExecutable = await fsp
    .realpath(selected.executablePath)
    .catch((error) => {
      if (error && error.code === "ENOENT")
        fail(`${selected.logicalName}: Cargo executable is missing`);
      throw error;
    });
  assert(
    realExecutable === selected.executablePath,
    `${selected.logicalName}: Cargo executable path is redirected through a symlink`,
  );
  const bytes = await readPinnedRegular(
    selected.executablePath,
    `${selected.logicalName} final executable`,
    MAX_EXECUTABLE_BYTES,
    afterExecutableRead,
  );
  const observation = parseMachO(bytes, {
    architecture: "arm64",
    finalExecutableAudit: true,
    requireExternalDefinedSymbols: false,
  });
  const { expectedInstallName } = await verifyRuntimeResolution({
    executablePath: selected.executablePath,
    targetKind: selected.targetKind,
    observation,
    artifactRoot,
    manifest,
    runtimeEntry,
  });
  const systemDependencies =
    policy.platformSystemDependencies[targetPolicy.systemDependencyPolicyKey];
  assertSortedUniqueStrings(
    systemDependencies,
    "portable policy system dependencies",
  );
  const systemAllowlist = new Set(systemDependencies);
  const dependencies = observation.dependencyCommands.map((row) => {
    if (row.installName === expectedInstallName) {
      return {
        command: row.command,
        installName: row.installName,
        resolution: {
          class: "portable-component",
          path: manifest.runtimeComponent,
          digest: runtimeEntry.digest,
        },
      };
    }
    assert(
      systemAllowlist.has(row.installName),
      `final executable has non-admitted dependency ${row.installName}`,
    );
    return {
      command: row.command,
      installName: row.installName,
      resolution: { class: "platform-system", name: row.installName },
    };
  });
  return {
    executable: {
      logicalName: selected.logicalName,
      targetKind: selected.targetKind,
      digest: observation.executableDigest,
      size: observation.executableSize,
    },
    audit: {
      class: "macos-macho-final-engine-executable",
      format: "mach-o",
      architecture: "arm64",
      cpuSubtype: "all",
      fileType: "execute",
      dynamicLinker: observation.dylinker,
      dyldEnvironment: observation.dyldEnvironment,
      rpaths: observation.rpaths,
      dependencies,
    },
  };
}

function assertVerifiedStoreShape(verified, repoRoot, artifactId) {
  assert(
    verified && typeof verified === "object" && !Array.isArray(verified),
    "store verifier returned no result",
  );
  assert(
    typeof verified.artifactRoot === "string",
    "store verifier returned no artifact root",
  );
  const expectedArtifactRoot = path.join(
    repoRoot,
    "target",
    "hermes-artifacts",
    artifactId,
  );
  assert(
    path.resolve(verified.artifactRoot) === expectedArtifactRoot,
    "store verifier selected the wrong checkout-local artifact root",
  );
  assert(
    verified.manifest && typeof verified.manifest === "object",
    "store verifier returned no manifest",
  );
  assert(
    verified.context && typeof verified.context === "object",
    "store verifier returned no checked context",
  );
  assert(
    verified.context.policy && typeof verified.context.policy === "object",
    "store verifier returned no checked policy",
  );
  assert(
    verified.context.targetPolicy &&
      typeof verified.context.targetPolicy === "object",
    "store verifier returned no admitted target policy",
  );
  assert(
    verified.transport?.receipt &&
      typeof verified.transport.receipt === "object",
    "store verifier returned no reverified transport receipt",
  );
  return { expectedArtifactRoot };
}

async function assertOutputAbsent(outputDirectory, repoRoot) {
  const targetRoot = path.join(repoRoot, "target");
  const realTargetRoot = await fsp.realpath(targetRoot);
  assert(
    realTargetRoot === targetRoot,
    "checkout target directory is redirected through a symlink",
  );
  assert(
    isWithin(targetRoot, outputDirectory),
    "post-link evidence output must be beneath the checkout target directory",
  );
  try {
    await fsp.lstat(outputDirectory);
    fail("post-link evidence output already exists");
  } catch (error) {
    if (!error || error.code !== "ENOENT") throw error;
  }
}

async function fsyncDirectory(directory) {
  const handle = await fsp.open(directory, fs.constants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeCanonicalExclusive(filePath, value) {
  const handle = await fsp.open(filePath, OPEN_CREATE_EXCLUSIVE, 0o600);
  try {
    await handle.writeFile(Buffer.from(canonicalJson(value), "utf8"));
    await handle.chmod(0o444);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function buildEvidenceSet(build, enumeration, records) {
  const results = records.map((record, index) => {
    const evidenceBytes = Buffer.from(canonicalJson(record), "utf8");
    return {
      logicalName: record.executable.logicalName,
      targetKind: record.executable.targetKind,
      evidenceFile: `${String(index).padStart(4, "0")}.json`,
      evidenceDigest: rawDigest(evidenceBytes),
      verificationDigest: record.verificationDigest,
    };
  });
  const completion = {
    schema: POST_LINK_SET_SCHEMA,
    portable: structuredClone(build.portable),
    buildConsumptionDigest: build.consumptionDigest,
    enumerationDigest: semanticDigest(
      "ibex.portable-engine-cargo-executable-set.v1",
      enumeration,
    ),
    results,
    outcome: "verified",
    setDigest: "",
  };
  completion.setDigest = semanticDigest(
    "ibex.portable-engine-post-link-verification-set.v1",
    completion,
    ["setDigest"],
  );
  return completion;
}

async function emitEvidenceDirectory(outputDirectory, records, completion) {
  const parent = path.dirname(outputDirectory);
  try {
    await fsp.mkdir(parent, { mode: 0o700 });
  } catch (error) {
    if (!error || error.code !== "EEXIST") throw error;
  }
  const parentStatus = await fsp.lstat(parent);
  assert(
    parentStatus.isDirectory() && !parentStatus.isSymbolicLink(),
    "post-link evidence output parent is not one no-follow directory",
  );
  const canonicalParent = await fsp.realpath(parent);
  assert(
    canonicalParent === parent,
    "post-link evidence output parent is redirected through a symlink",
  );
  const temporary = path.join(
    parent,
    `.${path.basename(outputDirectory)}.tmp-${randomBytes(16).toString("hex")}`,
  );
  await fsp.mkdir(temporary, { mode: 0o700 });
  try {
    for (let index = 0; index < records.length; index += 1) {
      await writeCanonicalExclusive(
        path.join(temporary, `${String(index).padStart(4, "0")}.json`),
        records[index],
      );
    }
    await writeCanonicalExclusive(
      path.join(temporary, "COMPLETE.json"),
      completion,
    );
    await fsyncDirectory(temporary);
    await fsp.chmod(temporary, 0o555);
    await fsyncDirectory(temporary);
    await fsp.rename(temporary, outputDirectory);
    await fsyncDirectory(outputDirectory);
    await fsyncDirectory(parent);
  } catch (error) {
    await fsp.chmod(temporary, 0o700).catch(() => {});
    await fsp.rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

function exactOptions(options) {
  assertExactKeys(
    options,
    [
      "archiveDigest",
      "buildConsumptionPath",
      "cargoMessagesPath",
      "expectedSourceRevision",
      "repoRoot",
    ],
    "portable post-link options",
  );
  assert(
    typeof options.repoRoot === "string" && path.isAbsolute(options.repoRoot),
    "portable post-link repoRoot must be absolute",
  );
  assert(
    /^[0-9a-f]{40}$/u.test(options.expectedSourceRevision),
    "portable post-link expectedSourceRevision must be one SHA-1 commit ID",
  );
  for (const field of ["buildConsumptionPath", "cargoMessagesPath"]) {
    assert(
      typeof options[field] === "string" && path.isAbsolute(options[field]),
      `portable post-link ${field} must be absolute`,
    );
  }
  if (options.archiveDigest !== null)
    assertRawDigest(options.archiveDigest, "portable post-link archive digest");
  const selected = {
    ...options,
    repoRoot: path.resolve(options.repoRoot),
    buildConsumptionPath: path.resolve(options.buildConsumptionPath),
    cargoMessagesPath: path.resolve(options.cargoMessagesPath),
  };
  const targetRoot = path.join(selected.repoRoot, "target");
  assert(
    isWithin(targetRoot, selected.buildConsumptionPath),
    "portable build consumption must be beneath the checkout target directory",
  );
  assert(
    isWithin(targetRoot, selected.cargoMessagesPath),
    "Cargo JSON message stream must be beneath the checkout target directory",
  );
  return Object.freeze(selected);
}

async function verifyPortableEnginePostLinkCore(options, dependencies) {
  const selectedOptions = exactOptions(options);
  assertExactKeys(
    dependencies,
    ["afterExecutableRead", "verifyStore"],
    "portable post-link dependencies",
  );
  assert(
    typeof dependencies.verifyStore === "function",
    "portable post-link store verifier is absent",
  );
  if (dependencies.afterExecutableRead !== null) {
    assert(
      typeof dependencies.afterExecutableRead === "function",
      "portable post-link executable read hook is invalid",
    );
  }
  const { value: build } = await readCanonicalJsonFile(
    selectedOptions.buildConsumptionPath,
    "portable build consumption",
  );
  assert(
    build && typeof build === "object" && !Array.isArray(build),
    "portable build consumption: expected an object",
  );
  assert(
    build.portable && typeof build.portable === "object",
    "portable build consumption: portable identity is absent",
  );
  assertSemanticDigest(
    build.portable.artifactId,
    "portable build consumption artifact ID",
  );
  assertSemanticDigest(
    build.consumptionDigest,
    "portable build consumption digest",
  );
  const outputDirectory = path.join(
    selectedOptions.repoRoot,
    "target",
    "portable-engine-post-link",
    build.consumptionDigest,
  );
  await assertOutputAbsent(outputDirectory, selectedOptions.repoRoot);
  const storeOptions = {
    artifactId: build.portable.artifactId,
    expectedSourceRevision: selectedOptions.expectedSourceRevision,
    repoRoot: selectedOptions.repoRoot,
    ...(selectedOptions.archiveDigest === null
      ? {}
      : { archiveDigest: selectedOptions.archiveDigest }),
  };
  const verified = await dependencies.verifyStore(storeOptions);
  const { expectedArtifactRoot } = assertVerifiedStoreShape(
    verified,
    selectedOptions.repoRoot,
    build.portable.artifactId,
  );
  const validators = await buildSchemaValidators(verified.context);
  validators.policy(verified.context.policy, "checked portable policy");
  validators.manifest(verified.manifest, "reverified portable manifest");
  validators.receipt(
    verified.transport.receipt,
    "reverified installation receipt",
  );
  validators.build(build, "portable build consumption");
  assert(
    verified.context.policy.portableArtifactAcceptanceEnabled === false,
    "post-link foundation requires portable acceptance to remain closed",
  );
  assert(
    verified.manifest.artifactId === build.portable.artifactId,
    "store manifest and build consumption artifact IDs differ",
  );
  assert(
    verified.manifest.build.sourceRevision ===
      selectedOptions.expectedSourceRevision,
    "store manifest and selected checkout revisions differ",
  );
  assert(
    verified.transport.receipt.sourceRevision ===
      selectedOptions.expectedSourceRevision,
    "installation receipt and selected checkout revisions differ",
  );
  assert(
    verified.transport.archive?.digest ===
      verified.transport.receipt.archiveDigest,
    "reverified transport archive and receipt digests differ",
  );
  const headerSet = await readAuthenticatedHeaderSet(
    expectedArtifactRoot,
    verified.manifest,
    validators,
  );
  const digests = validateBuildJoins(
    build,
    verified.manifest,
    verified.transport.receipt,
    verified.context.policy,
    verified.context.targetPolicy,
    headerSet,
  );
  const revalidation = payloadRevalidation(verified.manifest, build, digests);
  const enumerationBytes = Buffer.from(
    await verified.context.readRevisionFile(ENUMERATION_PATH),
  );
  assert(
    enumerationBytes.length > 0 && enumerationBytes.length <= MAX_JSON_BYTES,
    "checked Cargo executable enumeration manifest size is outside the bound",
  );
  const enumeration = parseJsonStrict(
    enumerationBytes,
    "checked Cargo executable enumeration manifest",
  );
  assertCanonicalJsonBytes(
    enumerationBytes,
    enumeration,
    "checked Cargo executable enumeration manifest",
  );
  validators.enumeration(
    enumeration,
    "checked Cargo executable enumeration manifest",
  );
  validateEnumerationManifest(enumeration);
  assertSame(
    enumeration.ibexFeatures,
    build.ibexFeatures,
    "checked Cargo executable enumeration features",
  );
  const cargoMessages = await readPinnedRegular(
    selectedOptions.cargoMessagesPath,
    "Cargo JSON message stream",
    MAX_CARGO_MESSAGES_BYTES,
  );
  const executables = parseCargoMessages(
    cargoMessages,
    enumeration,
    selectedOptions.repoRoot,
  );
  const records = [];
  for (const selected of executables) {
    const observed = await auditExecutable({
      selected,
      artifactRoot: expectedArtifactRoot,
      manifest: verified.manifest,
      runtimeEntry: digests.runtimeEntry,
      policy: verified.context.policy,
      targetPolicy: verified.context.targetPolicy,
      afterExecutableRead: dependencies.afterExecutableRead,
    });
    const record = {
      schema: POST_LINK_SCHEMA,
      portable: structuredClone(build.portable),
      buildConsumptionDigest: build.consumptionDigest,
      manifestDigest: digests.manifestDigest,
      installationReceiptDigest: digests.receiptDigest,
      verificationPolicyDigest: digests.policyDigest,
      target: structuredClone(build.target),
      ibexFeatures: [...build.ibexFeatures],
      executable: observed.executable,
      payloadRevalidation: structuredClone(revalidation),
      audit: observed.audit,
      outcome: "verified",
      verificationDigest: "",
    };
    record.verificationDigest = semanticDigest(
      "ibex.portable-engine-post-link-verification.v1",
      record,
      ["verificationDigest"],
    );
    validators.postLink(record, `${selected.logicalName} post-link evidence`);
    records.push(record);
  }
  const completion = buildEvidenceSet(build, enumeration, records);
  validators.postLinkSet(completion, "complete post-link evidence set");
  await emitEvidenceDirectory(outputDirectory, records, completion);
  return Object.freeze({
    completion: Object.freeze(completion),
    outputDirectory,
    records: Object.freeze(records.map((record) => Object.freeze(record))),
  });
}

export async function verifyPortableEnginePostLinkProductionCore(options) {
  const { verifyPortableEngineStore } =
    await import("./portable-engine-installer.mjs");
  return await verifyPortableEnginePostLinkCore(options, {
    verifyStore: verifyPortableEngineStore,
    afterExecutableRead: null,
  });
}

export async function verifyPortableEnginePostLinkTestOnly(
  options,
  dependencies,
) {
  return await verifyPortableEnginePostLinkCore(options, {
    verifyStore: dependencies?.verifyStore,
    afterExecutableRead: dependencies?.afterExecutableRead ?? null,
  });
}

export const cargoExecutableEnumerationContractTestOnly = Object.freeze({
  mode: ENUMERATION_MODE,
  path: ENUMERATION_PATH,
  schema: ENUMERATION_SCHEMA,
});
