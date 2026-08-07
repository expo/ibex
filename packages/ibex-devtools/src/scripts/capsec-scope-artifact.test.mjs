import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import { semanticDigest } from "../../../../scripts/portable-engine-contract.mjs";
import {
  SCOPE_CELL_MAPPING_DOMAIN,
  SCOPE_DOMAIN,
  SCOPE_EXPANSION_DIFF_DOMAIN,
  SCOPE_SCHEMA,
  buildScopeCellMapping,
  buildScopeExpansionDiff,
  computeScopeCellMappingDigest,
  computeScopeDigest,
  computeScopeExpansionDiffDigest,
  deriveScopeExpansion,
  expandScope,
  generateScopeArtifacts,
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

const target = {
  triple: "aarch64-apple-darwin",
  features: ["hermes-frame-attribution", "native-compartments"],
};
const edgeA = "surface.builtin.fs.read.aaaaaaa";
const edgeB = "surface.native-op.fs.read.bbbbbbb";
const edgeC = "surface.native-op.fs.stat.ccccccc";

function sourceClosureFixture() {
  const coverage = {
    edges: [
      {
        id: edgeA,
        surface: { kind: "builtin", name: "fixture:a" },
      },
      {
        id: edgeB,
        surface: { kind: "native-op", name: "__fixtureB" },
      },
      {
        id: edgeC,
        surface: { kind: "native-op", name: "__fixtureC" },
      },
    ],
  };
  const implementation = {
    surfaces: [
      {
        edgeId: edgeA,
        observedKey: "builtin:fixture:a",
        branchId: `${edgeA}.main`,
        enforcementRoute: {
          sourceRefs: ["fixture.js#a"],
          proofPaths: ["builtin:fixture:a"],
          terminalObservedKey: "builtin:fixture:a",
        },
      },
      {
        edgeId: edgeB,
        observedKey: "native-op:__fixtureB",
        branchId: `${edgeB}.main`,
        enforcementRoute: {
          sourceRefs: ["fixture.cc#b"],
          proofPaths: ["native-op:__fixtureB"],
          terminalObservedKey: "native-op:__fixtureB",
        },
      },
      {
        edgeId: edgeC,
        observedKey: "native-op:__fixtureC",
        branchId: `${edgeC}.main`,
        enforcementRoute: {
          sourceRefs: ["fixture.cc#c"],
          proofPaths: ["native-op:__fixtureC"],
          terminalObservedKey: "native-op:__fixtureC",
        },
      },
    ],
  };
  const catalog = [
    {
      edgeId: edgeA,
      implementationBranchIds: [`${edgeA}.main`],
      fixtureBindings: [{ actionIds: ["fs:read"] }],
    },
    {
      edgeId: edgeB,
      implementationBranchIds: [`${edgeB}.main`],
      fixtureBindings: [{ actionIds: ["network:connect"] }],
    },
    {
      edgeId: edgeC,
      implementationBranchIds: [`${edgeC}.main`],
      fixtureBindings: [{ actionIds: ["env:read"] }],
    },
  ];
  const surfaceInventory = {
    surfaces: [
      {
        observedKey: "builtin:fixture:a",
        metadata: {
          enforcementRouteEvidence: {
            kind: "static-builtin-call-graph",
            ambiguousCallees: [],
            terminals: ["__fixtureB", "__fixtureC"],
            paths: [
              "fixture:a -> __fixtureB",
              "fixture:a -> branch -> __fixtureC",
            ],
          },
        },
      },
      { observedKey: "native-op:__fixtureB", metadata: {} },
      { observedKey: "native-op:__fixtureC", metadata: {} },
    ],
  };
  return { coverage, implementation, catalog, surfaceInventory };
}

test("source closure includes every argument-selected terminal alternative", () => {
  const fixture = sourceClosureFixture();
  const expansion = deriveScopeExpansion({
    intensionalDefinition: {
      capabilityFamilies: ["fs"],
      surfaceKinds: ["builtin"],
    },
    ...fixture,
  });
  assert.deepEqual(expansion.expandedCellIds, [edgeA, edgeB, edgeC]);
  assert.deepEqual(
    expansion.closureEdges
      .filter((edge) => edge.fromEdgeId === edgeA)
      .map((edge) => [edge.toEdgeId, edge.dependencyKind]),
    [
      [edgeB, "argument-selected-branch-alternative"],
      [edgeC, "argument-selected-branch-alternative"],
    ],
  );

  fixture.surfaceInventory.surfaces[0].metadata.enforcementRouteEvidence.ambiguousCallees = [
    "dynamic-call-receiver:fixture",
  ];
  assert.throws(
    () =>
      deriveScopeExpansion({
        intensionalDefinition: {
          capabilityFamilies: ["fs"],
          surfaceKinds: ["builtin"],
        },
        ...fixture,
      }),
    /retains ambiguous callees/u,
  );
});

function predecessorScope(expandedCellIds) {
  const predecessor = {
    scopeSchema: SCOPE_SCHEMA,
    target,
    expandedCellIds,
  };
  predecessor.scopeDigest = computeScopeDigest(predecessor);
  return predecessor;
}

test("F7: a retired cell still in the live inventory refuses", () => {
  const predecessor = predecessorScope([edgeA]);
  assert.throws(
    () =>
      buildScopeExpansionDiff({
        target,
        predecessorScope: predecessor,
        currentExpandedCellIds: [edgeB],
        liveInventoryEdgeIds: [edgeA, edgeB],
      }),
    /retire live inventory cells/u,
  );
  const diff = buildScopeExpansionDiff({
    target,
    predecessorScope: predecessor,
    currentExpandedCellIds: [edgeB, edgeC],
    liveInventoryEdgeIds: [edgeB, edgeC],
  });
  assert.deepEqual(diff.addedCellIds, [edgeB, edgeC]);
  assert.deepEqual(diff.retiredCellIds, [edgeA]);
  assert.equal(
    diff.scopeExpansionDiffDigest,
    semanticDigest(SCOPE_EXPANSION_DIFF_DOMAIN, diff, [
      "scopeExpansionDiffDigest",
    ]),
  );
});

test("F9: split and merge mappings must partition both changed sides exactly once", () => {
  const expansionDiff = buildScopeExpansionDiff({
    target,
    predecessorScope: predecessorScope([edgeA]),
    currentExpandedCellIds: [edgeB, edgeC],
    liveInventoryEdgeIds: [edgeB, edgeC],
  });
  assert.throws(
    () =>
      buildScopeCellMapping({
        target,
        expansionDiff,
        inventoryHistory: {
          additions: [],
          retirements: [],
          mappings: [
            {
              kind: "split",
              predecessorCellIds: [edgeA],
              successorCellIds: [edgeB],
            },
          ],
        },
      }),
    /non-partitioning split cardinality|not total exactly once/u,
  );
  assert.throws(
    () =>
      buildScopeCellMapping({
        target,
        expansionDiff,
        inventoryHistory: {
          additions: [],
          retirements: [],
          mappings: [
            {
              kind: "rename",
              predecessorCellIds: [edgeA],
              successorCellIds: [edgeB],
            },
            {
              kind: "rename",
              predecessorCellIds: [edgeA],
              successorCellIds: [edgeC],
            },
          ],
        },
      }),
    /not total exactly once on the predecessor side/u,
  );
  const mapping = buildScopeCellMapping({
    target,
    expansionDiff,
    inventoryHistory: {
      additions: [],
      retirements: [],
      mappings: [
        {
          kind: "split",
          predecessorCellIds: [edgeA],
          successorCellIds: [edgeB, edgeC],
        },
      ],
    },
  });
  assert.equal(
    mapping.scopeCellMappingDigest,
    semanticDigest(SCOPE_CELL_MAPPING_DOMAIN, mapping, [
      "scopeCellMappingDigest",
    ]),
  );

  const mergeDiff = buildScopeExpansionDiff({
    target,
    predecessorScope: predecessorScope([edgeA, edgeB]),
    currentExpandedCellIds: [edgeC],
    liveInventoryEdgeIds: [edgeC],
  });
  assert.throws(
    () =>
      buildScopeCellMapping({
        target,
        expansionDiff: mergeDiff,
        inventoryHistory: {
          additions: [],
          retirements: [],
          mappings: [
            {
              kind: "merge",
              predecessorCellIds: [edgeA],
              successorCellIds: [edgeC],
            },
          ],
        },
      }),
    /non-partitioning merge cardinality|not total exactly once/u,
  );
  assert.doesNotThrow(() =>
    buildScopeCellMapping({
      target,
      expansionDiff: mergeDiff,
      inventoryHistory: {
        additions: [],
        retirements: [],
        mappings: [
          {
            kind: "merge",
            predecessorCellIds: [edgeA, edgeB],
            successorCellIds: [edgeC],
          },
        ],
      },
    }),
  );
});

test("generator creates three mutually bound, schema-valid artifacts", () => {
  const artifacts = generateScopeArtifacts({
    target,
    intensionalDefinition: {
      capabilityFamilies: ["fs"],
      surfaceKinds: ["builtin"],
    },
    ...sourceClosureFixture(),
  });
  assert.equal(
    artifacts.scope.scopeExpansionDiffDigest,
    artifacts.expansionDiff.scopeExpansionDiffDigest,
  );
  assert.equal(
    artifacts.scope.scopeCellMappingDigest,
    artifacts.cellMapping.scopeCellMappingDigest,
  );
  assert.equal(artifacts.scope.scopeDigest, computeScopeDigest(artifacts.scope));

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const filename of [
    "capsec-scope-v1.schema.json",
    "capsec-scope-expansion-diff-v1.schema.json",
    "capsec-scope-cell-mapping-v1.schema.json",
  ]) {
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(repoRoot, "schemas", filename))));
  }
  for (const [filename, artifact] of [
    ["capsec-scope-v1.schema.json", artifacts.scope],
    ["capsec-scope-expansion-diff-v1.schema.json", artifacts.expansionDiff],
    ["capsec-scope-cell-mapping-v1.schema.json", artifacts.cellMapping],
  ]) {
    const validate = ajv.getSchema(`https://ibex.dev/schemas/${filename}`);
    assert.equal(validate(artifact), true, JSON.stringify(validate.errors));
  }
});

test("M22: full-inventory catalog derivation has no scoped variant", () => {
  const source = fs.readFileSync(
    path.join(
      repoRoot,
      "packages/ibex-devtools/src/scripts/capsec-conformance.mjs",
    ),
    "utf8",
  );
  assert.equal(
    source.match(/export function fixtureCatalogForTarget\s*\(/gu)?.length,
    1,
  );
  assert.match(
    source,
    /export function fixtureCatalogForTarget\s*\(\{\s*coverage,\s*implementation,\s*target,?\s*\}\)/u,
  );
  assert.doesNotMatch(source, /fixtureCatalog(?:For|By)[A-Za-z]*Scope/iu);
});
