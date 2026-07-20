/**
 * Validate LLP 0023's versioned VFS result union against both language
 * consumers and generate its complete pairwise-precedence corpus.
 *
 * @ref LLP 0023#72-the-structured-result-and-its-error-classes — a new reason
 * cannot ship without an explicit discriminant, JS code, order, and every
 * ambiguous pair fixture.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
export const sourcePath = path.join(
  repoRoot,
  "llp",
  "fixtures",
  "0023-vfs-error-union.v1.json",
);
export const generatedPath = path.join(
  repoRoot,
  "llp",
  "fixtures",
  "0023-vfs-error-precedence.generated.json",
);
const rustPath = path.join(repoRoot, "src", "host", "abi.rs");
const headerPath = path.join(repoRoot, "include", "exact_runtime.h");
const vfsPath = path.join(repoRoot, "src", "vfs", "mod.rs");
const posixFsPath = path.join(repoRoot, "src", "engine", "hermes_runtime_fs.cc");

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return `sha256-${crypto.createHash("sha256").update(value).digest("base64url")}`;
}

function unique(values, label) {
  if (new Set(values).size !== values.length) {
    throw new Error(`${label} must be unique`);
  }
}

export function validateVfsErrorUnion(value) {
  if (!value || value.schema !== "ibex/llp0023-vfs-error-union/1") {
    throw new Error("unsupported VFS error-union schema");
  }
  if (value.abiVersion !== 1 || !Array.isArray(value.reasons) || value.reasons.length === 0) {
    throw new Error("VFS error union must declare ABI v1 and a nonempty reason set");
  }
  for (const reason of value.reasons) {
    if (
      !reason ||
      typeof reason.id !== "string" ||
      !/^[a-z][a-z0-9-]*$/.test(reason.id) ||
      typeof reason.rustVariant !== "string" ||
      !/^[A-Z][A-Za-z0-9]*$/.test(reason.rustVariant) ||
      typeof reason.cConstant !== "string" ||
      !/^EX_HOST_VFS_RESULT_[A-Z0-9_]+$/.test(reason.cConstant) ||
      !Number.isInteger(reason.discriminant) ||
      reason.discriminant <= 0 ||
      !Number.isInteger(reason.precedence) ||
      reason.precedence < 0 ||
      typeof reason.code !== "string" ||
      reason.code.length === 0 ||
      typeof reason.phase !== "string" ||
      reason.phase.length === 0
    ) {
      throw new Error(`invalid VFS error reason ${JSON.stringify(reason)}`);
    }
  }
  unique(value.reasons.map((reason) => reason.id), "VFS error ids");
  unique(value.reasons.map((reason) => reason.rustVariant), "VFS Rust variants");
  unique(value.reasons.map((reason) => reason.cConstant), "VFS C constants");
  unique(value.reasons.map((reason) => reason.discriminant), "VFS discriminants");
  unique(value.reasons.map((reason) => reason.precedence), "VFS precedence ranks");
  const expectedRanks = value.reasons.map((_, index) => index);
  const actualRanks = value.reasons
    .map((reason) => reason.precedence)
    .sort((left, right) => left - right);
  if (JSON.stringify(actualRanks) !== JSON.stringify(expectedRanks)) {
    throw new Error("VFS precedence ranks must be contiguous from zero");
  }
  if (value.reasons.find((reason) => reason.id === "stale-session")?.precedence !== 0) {
    throw new Error("stale-session must precede every path/operation reason");
  }
  if (JSON.stringify(value.perStageRule) !== JSON.stringify([
    "containment",
    "authorization",
    "existence",
  ])) {
    throw new Error("VFS per-stage order must be containment -> authorization -> existence");
  }
  return value;
}

function sourceConstants(source, pattern) {
  return new Map(
    [...source.matchAll(pattern)].map((match) => [match[1], Number(match[2])]),
  );
}

function rustEnumVariants(source, enumName) {
  const declaration = new RegExp(
    `\\bpub\\s+enum\\s+${enumName}\\s*\\{([\\s\\S]*?)^\\}`,
    "mu",
  ).exec(source);
  if (!declaration) {
    throw new Error(`Rust source is missing pub enum ${enumName}`);
  }
  return new Set(
    [...declaration[1].matchAll(/^\s*([A-Z][A-Za-z0-9]*)\s*(?:,|\(|\{)/gmu)].map(
      (match) => match[1],
    ),
  );
}

function assertExactSet(actual, expected, label) {
  const missing = [...expected].filter((value) => !actual.has(value)).sort();
  const extra = [...actual].filter((value) => !expected.has(value)).sort();
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `${label} must exactly match the VFS error dataset; missing=${JSON.stringify(missing)} extra=${JSON.stringify(extra)}`,
    );
  }
}

export function assertLanguageConsumers(union, { rust, header, vfs, posixFs }) {
  const rustConstants = sourceConstants(
    rust,
    /pub const (EX_HOST_VFS_RESULT_[A-Z0-9_]+): u32 = (\d+);/g,
  );
  const headerConstants = sourceConstants(
    header,
    /\b(EX_HOST_VFS_RESULT_[A-Z0-9_]+)\s*=\s*(\d+)/g,
  );
  const variants = rustEnumVariants(vfs, "VfsReason");
  const rustDiscriminants = new Map(
    [...rust.matchAll(/VfsReason::([A-Z][A-Za-z0-9]+)\s*=>\s*(EX_HOST_VFS_RESULT_[A-Z0-9_]+)/g)]
      .map((match) => [match[1], match[2]]),
  );
  const rustPrecedence = new Map(
    [...vfs.matchAll(/VfsReason::([A-Z][A-Za-z0-9]+)\s*=>\s*(\d+),/g)]
      .map((match) => [match[1], Number(match[2])]),
  );
  const rustCodes = new Map(
    [...vfs.matchAll(/VfsReason::([A-Z][A-Za-z0-9]+)\s*=>\s*"([A-Z0-9_]+)",/g)]
      .map((match) => [match[1], match[2]]),
  );
  const cppCodes = new Map(
    [...posixFs.matchAll(/case\s+(EX_HOST_VFS_RESULT_[A-Z0-9_]+):\s*(?:default:\s*)?return\s*\{"([A-Z0-9_]+)"/g)]
      .map((match) => [match[1], match[2]]),
  );
  const expected = new Map([["EX_HOST_VFS_RESULT_OK", 0]]);
  for (const reason of union.reasons) expected.set(reason.cConstant, reason.discriminant);
  const expectedVariants = new Set(
    union.reasons.map((reason) => reason.rustVariant),
  );
  const expectedReasonConstants = new Set(
    union.reasons.map((reason) => reason.cConstant),
  );
  assertExactSet(variants, expectedVariants, "VfsReason variants");
  assertExactSet(
    new Set(rustDiscriminants.keys()),
    expectedVariants,
    "vfs_reason_discriminant arms",
  );
  assertExactSet(
    new Set(rustPrecedence.keys()),
    expectedVariants,
    "VfsReason precedence arms",
  );
  assertExactSet(
    new Set(rustCodes.keys()),
    expectedVariants,
    "VfsReason stable-code arms",
  );
  assertExactSet(
    new Set(cppCodes.keys()),
    expectedReasonConstants,
    "C++ VFS result-code arms",
  );
  for (const [constant, value] of expected) {
    if (rustConstants.get(constant) !== value) {
      throw new Error(`Rust ${constant} must equal ${value}`);
    }
    if (headerConstants.get(constant) !== value) {
      throw new Error(`C ${constant} must equal ${value}`);
    }
  }
  for (const reason of union.reasons) {
    if (!variants.has(reason.rustVariant)) {
      throw new Error(`VfsReason is missing ${reason.rustVariant}`);
    }
    if (rustDiscriminants.get(reason.rustVariant) !== reason.cConstant) {
      throw new Error(
        `Rust ${reason.rustVariant} must project to ${reason.cConstant}`,
      );
    }
    if (rustPrecedence.get(reason.rustVariant) !== reason.precedence) {
      throw new Error(
        `Rust ${reason.rustVariant} precedence must equal ${reason.precedence}`,
      );
    }
    if (rustCodes.get(reason.rustVariant) !== reason.code) {
      throw new Error(`Rust ${reason.rustVariant} code must equal ${reason.code}`);
    }
    if (cppCodes.get(reason.cConstant) !== reason.code) {
      throw new Error(`C++ ${reason.cConstant} code must equal ${reason.code}`);
    }
  }
  assertExactSet(
    new Set(rustConstants.keys()),
    new Set(expected.keys()),
    "Rust VFS result constants",
  );
  assertExactSet(
    new Set(headerConstants.keys()),
    new Set(expected.keys()),
    "C VFS result constants",
  );
}

export function buildPairwiseCorpus(union, sourceText) {
  const ordered = [...union.reasons].sort(
    (left, right) => left.precedence - right.precedence,
  );
  const pairs = [];
  for (let left = 0; left < ordered.length; left += 1) {
    for (let right = left + 1; right < ordered.length; right += 1) {
      pairs.push({
        id: `${ordered[left].id}-before-${ordered[right].id}`,
        contenders: [ordered[left].id, ordered[right].id],
        winner: ordered[left].id,
        winnerCode: ordered[left].code,
        winnerDiscriminant: ordered[left].discriminant,
      });
    }
  }
  return {
    schema: "ibex/llp0023-vfs-error-precedence-corpus/1",
    sourceDigest: sha256(sourceText),
    abiVersion: union.abiVersion,
    reasonCount: ordered.length,
    pairCount: pairs.length,
    perStageRule: union.perStageRule,
    pairs,
  };
}

export function generateVfsErrorUnion({ write = false } = {}) {
  const sourceText = fs.readFileSync(sourcePath, "utf8");
  const union = validateVfsErrorUnion(JSON.parse(sourceText));
  assertLanguageConsumers(union, {
    rust: fs.readFileSync(rustPath, "utf8"),
    header: fs.readFileSync(headerPath, "utf8"),
    vfs: fs.readFileSync(vfsPath, "utf8"),
    posixFs: fs.readFileSync(posixFsPath, "utf8"),
  });
  const output = canonicalJson(buildPairwiseCorpus(union, sourceText));
  if (write) {
    writeGeneratedFilesTransactionally(
      repoRoot,
      [{
        path: generatedPath,
        content: output,
        label: "LLP 0023 VFS error precedence corpus",
      }],
    );
    return;
  }
  const { path: confined } = assertConfinedGeneratedFile(
    repoRoot,
    generatedPath,
    "LLP 0023 VFS error precedence corpus",
  );
  if (!fs.existsSync(confined) || fs.readFileSync(confined, "utf8") !== output) {
    throw new Error(
      "LLP 0023 VFS error precedence corpus is stale; run bun run generate:vfs-error-union",
    );
  }
}

if (import.meta.main) {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  if (write === check) throw new Error("pass exactly one of --write or --check");
  generateVfsErrorUnion({ write });
}
