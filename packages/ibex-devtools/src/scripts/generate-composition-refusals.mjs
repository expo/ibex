#!/usr/bin/env bun

/**
 * Generate ibex's typed composition-refusal projection from the vendored
 * Exact-side lockstep registry.
 *
 * @ref LLP 0056#63-registry-mechanics-parity-generated-halves — the Rust half
 * is generated from the byte-pinned registry and never maintained in parallel.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..", "..", "..");
const sourcePath = path.join(
  repoRoot,
  "tests",
  "fixtures",
  "prepared-composition",
  "v1",
  "refusals.generated.json",
);
const outputPath = path.join(
  repoRoot,
  "src",
  "module_loader",
  "composition_refusals_generated.rs",
);

function relative(filePath) {
  return path.relative(repoRoot, filePath).split(path.sep).join("/");
}

function rustString(value) {
  return JSON.stringify(value);
}

function variantForCode(code) {
  return code
    .split(/[^A-Za-z0-9]+/u)
    .filter(Boolean)
    .map((part) => `${part[0].toUpperCase()}${part.slice(1)}`)
    .join("");
}

function loadRegistry() {
  const registry = JSON.parse(fs.readFileSync(sourcePath, "utf8"));
  if (
    registry.schema !== "exact/prepared-composition-refusals/1" ||
    !Array.isArray(registry.admissionRows) ||
    registry.admissionRows.length !== 38
  ) {
    throw new Error("composition refusal registry must carry the v1 schema and 38 rows");
  }

  const codes = new Set();
  const variants = new Set();
  for (const [index, row] of registry.admissionRows.entries()) {
    const variant = variantForCode(row.code);
    if (
      row.ordinal !== index + 1 ||
      !Number.isInteger(row.step) ||
      row.step < 1 ||
      row.step > 8 ||
      !["A", "P", "E"].includes(row.class) ||
      typeof row.code !== "string" ||
      variant.length === 0 ||
      codes.has(row.code) ||
      variants.has(variant)
    ) {
      throw new Error(`invalid composition refusal row at ordinal ${index + 1}`);
    }
    codes.add(row.code);
    variants.add(variant);
  }

  const expectedDefaultKeys = ["1", "2a", "2b", "3", "4", "5", "6", "7", "8"];
  if (
    JSON.stringify(Object.keys(registry.stepDefaults).sort()) !==
      JSON.stringify([...expectedDefaultKeys].sort()) ||
    expectedDefaultKeys.some((step) => !codes.has(registry.stepDefaults[step]))
  ) {
    throw new Error("composition refusal step defaults are incomplete or invalid");
  }
  if (
    !Array.isArray(registry.environmentCodes) ||
    registry.environmentCodes.length !== 4 ||
    new Set(registry.environmentCodes).size !== 4 ||
    registry.environmentCodes.some((code) => codes.has(code))
  ) {
    throw new Error("composition environment codes must be four unique non-admission codes");
  }
  return registry;
}

function renderRegistry(registry) {
  const rows = registry.admissionRows.map((row) => ({
    ...row,
    variant: variantForCode(row.code),
    classVariant: { A: "Attacker", P: "ProducerDefect", E: "Environment" }[
      row.class
    ],
  }));
  const variants = rows
    .map((row) => `    /// Registry ordinal ${row.ordinal}: ${row.code}.\n    ${row.variant},`)
    .join("\n");
  const all = rows.map((row) => `        Self::${row.variant},`).join("\n");
  const codeArms = rows
    .map((row) => `            Self::${row.variant} => ${rustString(row.code)},`)
    .join("\n");
  const ordinalArms = rows
    .map((row) => `            Self::${row.variant} => ${row.ordinal},`)
    .join("\n");
  const stepArms = rows
    .map((row) => `            Self::${row.variant} => ${row.step},`)
    .join("\n");
  const classArms = rows
    .map(
      (row) =>
        `            Self::${row.variant} => CompositionRefusalClass::${row.classVariant},`,
    )
    .join("\n");
  const fromCodeArms = rows
    .map((row) => `            ${rustString(row.code)} => Some(Self::${row.variant}),`)
    .join("\n");
  const defaultOrder = ["1", "2a", "2b", "3", "4", "5", "6", "7", "8"];
  const defaultArms = defaultOrder
    .map((step) => {
      const variant = variantForCode(registry.stepDefaults[step]);
      return `        ${rustString(step)} => Some(CompositionRefusalCode::${variant}),`;
    })
    .join("\n");
  const environmentCodes = registry.environmentCodes
    .map((code) => `    ${rustString(code)},`)
    .join("\n");

  return `// GENERATED FILE - DO NOT EDIT.
// Generator: bun run generate:composition-refusals
// Vendored source: tests/fixtures/prepared-composition/v1/refusals.generated.json
// @ref LLP 0056#63-registry-mechanics-parity-generated-halves

/// Closed composition-admission refusal vocabulary in registry ordinal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompositionRefusalCode {
${variants}
}

impl CompositionRefusalCode {
    /// All 38 admission refusal codes in normative ordinal order.
    pub const ALL: [CompositionRefusalCode; 38] = [
${all}
    ];

    /// Return the exact lockstep registry code.
    pub fn as_str(&self) -> &'static str {
        match self {
${codeArms}
        }
    }

    /// Return the normative one-based registry ordinal.
    pub fn ordinal(&self) -> u32 {
        match self {
${ordinalArms}
        }
    }

    /// Return the admission step that owns this refusal.
    pub fn step(&self) -> u8 {
        match self {
${stepArms}
        }
    }

    /// Return the registry's attacker/producer/environment class.
    pub fn class(&self) -> CompositionRefusalClass {
        match self {
${classArms}
        }
    }

    /// Resolve an exact registry code to its typed refusal variant.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
${fromCodeArms}
            _ => None,
        }
    }
}

/// Security/operational classification assigned by the lockstep registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompositionRefusalClass {
    /// Attacker-controlled or tamper-shaped failure.
    Attacker,
    /// Invalid state emitted by a producer.
    ProducerDefect,
    /// Runtime or verifier environment mismatch.
    Environment,
}

impl CompositionRefusalClass {
    /// Return the exact one-letter registry class.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Attacker => "A",
            Self::ProducerDefect => "P",
            Self::Environment => "E",
        }
    }
}

/// Return the registry's single default refusal for an admission step label.
pub fn composition_step_default(step: &str) -> Option<CompositionRefusalCode> {
    match step {
${defaultArms}
        _ => None,
    }
}

/// Exact-side environment outcomes that are intentionally outside admission.
pub const COMPOSITION_ENVIRONMENT_CODES_V1: [&str; 4] = [
${environmentCodes}
];
`;
}

function main(argv) {
  const write = argv.includes("--write");
  const check = argv.includes("--check");
  const unknown = argv.filter((argument) => !["--write", "--check"].includes(argument));
  if (unknown.length > 0 || write === check) {
    throw new Error(
      "usage: bun packages/ibex-devtools/src/scripts/generate-composition-refusals.mjs (--write|--check)",
    );
  }

  const rendered = renderRegistry(loadRegistry());
  if (write) {
    writeGeneratedFilesTransactionally(repoRoot, [
      {
        path: outputPath,
        content: rendered,
        label: "generated composition refusal registry",
      },
    ]);
    console.log(`wrote ${relative(outputPath)}`);
    return;
  }

  try {
    assertConfinedGeneratedFile(repoRoot, outputPath, "generated composition refusal registry");
    if (fs.readFileSync(outputPath, "utf8") !== rendered) {
      throw new Error("byte mismatch");
    }
    console.log("composition refusal registry is current");
  } catch {
    console.error(
      `composition refusal registry is stale: ${relative(outputPath)}; run bun run generate:composition-refusals`,
    );
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : String(error));
    process.exitCode = 1;
  }
}
