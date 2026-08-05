// @ref LLP 0030#1-workflow-and-type-separation — the diagnostic graph wire
// projection is closed and cannot accept an armed workflow or authority field.
// @ref LLP 0030#4-decisions-and-would-deny-evidence — receipt constants,
// bounds, and outcome classification are schema-enforced where JSON Schema can
// express them; arithmetic count reconciliation is enforced by the Rust type.

import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../../../..");
const schemasDir = path.join(repoRoot, "schemas");
const vectorsDir = path.join(schemasDir, "vectors");

const validVectors = readJson("diagnostic-audit-v1.valid.json", vectorsDir);
const invalidVectors = readJson("diagnostic-audit-v1.invalid.json", vectorsDir);
const schemaByDocument = {
  graphSnapshot: readJson(
    "diagnostic-graph-snapshot-v1.schema.json",
    schemasDir,
  ),
  executionReceipt: readJson(
    "diagnostic-audit-execution-receipt-v1.schema.json",
    schemasDir,
  ),
};

function readJson(name, directory) {
  return JSON.parse(fs.readFileSync(path.join(directory, name), "utf8"));
}

function applyMutation(document, mutationPath, mutation) {
  let cursor = document;
  for (const rawSegment of mutationPath ? mutationPath.split(".") : []) {
    const match = /^([^[]+)(?:\[(\d+)\])?$/.exec(rawSegment);
    if (!match) throw new Error(`invalid mutation path segment ${rawSegment}`);
    cursor = cursor[match[1]];
    if (match[2] !== undefined) cursor = cursor[Number(match[2])];
  }
  Object.assign(cursor, mutation);
}

function compileSchemas() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  return Object.fromEntries(
    Object.entries(schemaByDocument).map(([name, schema]) => [
      name,
      ajv.compile(schema),
    ]),
  );
}

test("diagnostic audit schemas compile strictly and accept their valid vectors", () => {
  const validators = compileSchemas();
  for (const [name, validate] of Object.entries(validators)) {
    expect(validate(validVectors.documents[name])).toBe(true);
  }
});

test("diagnostic audit schemas refuse every shape-expressible invalid vector", () => {
  const validators = compileSchemas();
  const semanticOnly = new Set(["counts-do-not-reconcile"]);
  const seenSemanticOnly = new Set();

  for (const invalid of invalidVectors.cases) {
    const document = structuredClone(validVectors.documents[invalid.document]);
    applyMutation(document, invalid.mutationPath ?? "", invalid.mutation);
    const acceptedByShapeSchema = validators[invalid.document](document);
    if (semanticOnly.has(invalid.id)) {
      seenSemanticOnly.add(invalid.id);
      expect(acceptedByShapeSchema).toBe(true);
    } else {
      expect(acceptedByShapeSchema).toBe(false);
    }
  }

  expect([...seenSemanticOnly]).toEqual([...semanticOnly]);
});
