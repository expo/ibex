#!/usr/bin/env node
// Production entry point for a provenance-authenticated portable Hermes Cargo
// invocation. Verifier injection is intentionally unavailable here.

import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyPortableEngineStore } from "./portable-engine-installer.mjs";
import { loadProductionCargoTargetMap, requireProductionCleanCheckout, runPortableHermesCargoCore, spawnProductionCargo } from "./portable-engine-build-preflight-core.mjs";

function exactOptions(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("runPortableHermesCargo expects one options object");
  const fields = Object.keys(input).sort();
  const expected = ["archiveDigest", "artifactId", "cargoArgs", "expectedSourceRevision", "repoRoot"];
  if (JSON.stringify(fields) !== JSON.stringify(expected)) throw new Error("runPortableHermesCargo received malformed exact options");
  return Object.freeze(Object.fromEntries(fields.map((field) => [field, input[field]])));
}

export async function runPortableHermesCargo(options) {
  if (arguments.length !== 1) throw new Error("runPortableHermesCargo accepts exactly one production options object");
  return await runPortableHermesCargoCore(exactOptions(options), {
    verifyStore: verifyPortableEngineStore,
    spawnCargo: spawnProductionCargo,
    loadCargoTargetMap: loadProductionCargoTargetMap,
    requireCleanCheckout: requireProductionCleanCheckout,
  });
}

function parseCli(arguments_) {
  const values = { repoRoot: process.cwd() };
  const seen = new Set();
  let index = 0;
  while (index < arguments_.length && arguments_[index] !== "--") {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!value) throw new Error(`${name}: missing value`);
    if (seen.has(name)) throw new Error(`duplicate portable build option ${name}`);
    seen.add(name);
    if (name === "--repo-root") values.repoRoot = path.resolve(value);
    else if (name === "--artifact-id") values.artifactId = value;
    else if (name === "--archive-digest") values.archiveDigest = value;
    else if (name === "--expected-source-revision") values.expectedSourceRevision = value;
    else throw new Error(`unknown portable build option ${name}`);
    index += 2;
  }
  if (arguments_[index] !== "--") throw new Error("portable build options must end with -- before Cargo arguments");
  values.cargoArgs = arguments_.slice(index + 1);
  return values;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const outcome = await runPortableHermesCargo(parseCli(process.argv.slice(2)));
    if (outcome.signal) {
      process.kill(process.pid, outcome.signal);
    } else {
      process.exitCode = outcome.code ?? 1;
    }
  } catch (error) {
    process.stderr.write(`portable Hermes Cargo runner refused: ${error.message}\n`);
    process.exitCode = 1;
  }
}
