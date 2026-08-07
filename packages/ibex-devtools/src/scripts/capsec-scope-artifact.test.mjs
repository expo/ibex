import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import { semanticDigest } from "../../../../scripts/portable-engine-contract.mjs";
import {
  SCOPE_DOMAIN,
  SCOPE_SCHEMA,
  computeScopeDigest,
  expandScope,
} from "./capsec-scope-artifact.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

test("scope schemas are strict JSON Schema 2020-12 documents", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const scope = JSON.parse(
    fs.readFileSync(path.join(repoRoot, "schemas/capsec-scope-v1.schema.json")),
  );
  ajv.addSchema(scope);
  const diff = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "schemas/capsec-scope-expansion-diff-v1.schema.json"),
    ),
  );
  ajv.addSchema(diff);
  const mapping = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "schemas/capsec-scope-cell-mapping-v1.schema.json"),
    ),
  );
  assert.doesNotThrow(() => ajv.compile(mapping));
});

test("scope digest uses the v1 domain and excludes only its self digest", () => {
  const artifact = {
    scopeSchema: SCOPE_SCHEMA,
    profile: "ibex/capsec/1",
    marker: "fixture",
    scopeDigest: "sha256-stale",
  };
  assert.equal(
    computeScopeDigest(artifact),
    semanticDigest(SCOPE_DOMAIN, artifact, ["scopeDigest"]),
  );
  assert.equal(
    computeScopeDigest({ ...artifact, scopeDigest: "sha256-other" }),
    computeScopeDigest(artifact),
  );
  assert.notEqual(
    computeScopeDigest({ ...artifact, marker: "changed" }),
    computeScopeDigest(artifact),
  );
});

test("complete-cell expansion uses set-only selectors and follows dependencies", () => {
  const inventory = [
    {
      edgeId: "surface.builtin.fs.read.a",
      surfaceKind: "builtin",
      capabilityFamilySets: [["fs"], ["fs", "network"]],
      dependencyEdgeIds: ["surface.native-op.fs.read.b"],
    },
    {
      edgeId: "surface.native-op.fs.read.b",
      surfaceKind: "native-op",
      capabilityFamilySets: [["network"]],
      dependencyEdgeIds: [],
    },
    {
      edgeId: "surface.host-abi.fs.read.c",
      surfaceKind: "host-abi",
      capabilityFamilySets: [["fs"]],
      dependencyEdgeIds: [],
    },
  ];
  assert.deepEqual(
    expandScope(
      { capabilityFamilies: ["fs"], surfaceKinds: ["builtin", "native-op"] },
      inventory,
    ),
    ["surface.builtin.fs.read.a", "surface.native-op.fs.read.b"],
  );
  assert.deepEqual(inventory[0].capabilityFamilySets[1], ["fs", "network"]);
});

test("scope expansion refuses free-form selectors and unresolved dependencies", () => {
  const inventory = [
    {
      edgeId: "surface.builtin.fs.read.a",
      surfaceKind: "builtin",
      capabilityFamilySets: [["fs"]],
      dependencyEdgeIds: ["surface.native-op.missing.b"],
    },
  ];
  assert.throws(
    () =>
      expandScope(
        {
          capabilityFamilies: ["fs"],
          surfaceKinds: ["builtin"],
          predicate: "edgeId.startsWith('surface')",
        },
        inventory,
      ),
    /unknown or missing fields/u,
  );
  assert.throws(
    () =>
      expandScope(
        { capabilityFamilies: ["fs"], surfaceKinds: ["builtin"] },
        inventory,
      ),
    /unresolved scope dependency/u,
  );
});
