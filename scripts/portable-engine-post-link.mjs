#!/usr/bin/env bun

// Production-safe boundary and command for portable macOS post-link evidence.
// The implementation imports the production installer verifier internally;
// callers cannot substitute store, schema, or provenance-verification logic.
//
// @ref LLP 0035#build-consumption-and-post-link-contracts — the gate consumes
// one canonical build record plus a complete bounded Cargo artifact set.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyPortableEnginePostLinkProductionCore } from "./portable-engine-post-link-core.mjs";

const OPTION_NAMES = new Map([
  ["--archive-digest", "archiveDigest"],
  ["--build-consumption", "buildConsumptionPath"],
  ["--cargo-messages", "cargoMessagesPath"],
  ["--expected-source-revision", "expectedSourceRevision"],
  ["--repo-root", "repoRoot"],
]);
const REQUIRED = Object.freeze([
  "buildConsumptionPath",
  "cargoMessagesPath",
  "expectedSourceRevision",
]);

function exactOptions(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(
      "verifyPortableEnginePostLink: expected one options object",
    );
  }
  const allowed = new Set([...OPTION_NAMES.values()]);
  for (const key of Object.keys(input)) {
    if (!allowed.has(key))
      throw new Error(`verifyPortableEnginePostLink: unknown option ${key}`);
  }
  for (const key of REQUIRED) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) {
      throw new Error(`verifyPortableEnginePostLink: missing option ${key}`);
    }
  }
  return Object.freeze({
    archiveDigest: input.archiveDigest ?? null,
    buildConsumptionPath: path.resolve(input.buildConsumptionPath),
    cargoMessagesPath: path.resolve(input.cargoMessagesPath),
    expectedSourceRevision: input.expectedSourceRevision,
    repoRoot: path.resolve(input.repoRoot ?? process.cwd()),
  });
}

export async function verifyPortableEnginePostLink(options) {
  if (arguments.length !== 1) {
    throw new Error(
      "verifyPortableEnginePostLink accepts exactly one production options object",
    );
  }
  return await verifyPortableEnginePostLinkProductionCore(
    exactOptions(options),
  );
}

function usage() {
  return [
    "usage: bun scripts/portable-engine-post-link.mjs \\",
    "  --expected-source-revision <40-hex-commit> \\",
    "  --build-consumption <canonical-json> \\",
    "  --cargo-messages <cargo-json-lines> \\",
    "  [--archive-digest <sha256-hex>] [--repo-root <checkout>]",
  ].join("\n");
}

function parseArguments(argv) {
  if (argv.includes("--help") || argv.includes("-h")) return null;
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!OPTION_NAMES.has(flag))
      throw new Error(`unknown argument ${flag ?? "<missing>"}`);
    if (value === undefined || value.startsWith("--"))
      throw new Error(`${flag}: expected one value`);
    const key = OPTION_NAMES.get(flag);
    if (Object.prototype.hasOwnProperty.call(values, key))
      throw new Error(`${flag}: duplicate option`);
    values[key] = value;
  }
  return values;
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const values = parseArguments(process.argv.slice(2));
    if (values === null) {
      process.stdout.write(`${usage()}\n`);
    } else {
      const result = await verifyPortableEnginePostLink(values);
      process.stdout.write(
        `wrote ${result.records.length} post-link evidence record(s) to ${result.outputDirectory}\n`,
      );
    }
  } catch (error) {
    process.stderr.write(
      `portable-engine-post-link: ${error.message}\n${usage()}\n`,
    );
    process.exitCode = 1;
  }
}
