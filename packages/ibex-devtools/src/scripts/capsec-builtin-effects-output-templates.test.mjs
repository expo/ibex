// @ref LLP 0023#6-path-bearing-observables — membership and recipes are
// derived from source inventory plus effects coverage, never output policy.

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverRepositorySurfaces } from "./capsec-surface-inventory.mjs";
import {
  BUILTIN_EFFECTS_DESCRIPTOR_RESIDUAL_FAMILY_COUNTS,
  BUILTIN_EFFECTS_OUTPUT_INVOCATION_SCHEMA,
  BUILTIN_EFFECTS_REGISTRAR_FAMILY_COUNTS,
  authoredBuiltinEffectsOutputInvocation,
  builtinEffectsOutputRouteManifest,
  isBuiltinEffectsOutputTargetSurface,
} from "./capsec-builtin-effects-output-templates.mjs";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);

async function effectRows() {
  const catalog = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/generated/output-shape-catalog.json"),
      "utf8",
    ),
  );
  const coverage = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/coverage-edges.json"),
      "utf8",
    ),
  );
  const rules = JSON.parse(
    fs.readFileSync(
      path.join(repoRoot, "capsec/registry/policy-rules.json"),
      "utf8",
    ),
  );
  const target = rules.initialProfile.candidateTargets[0];
  const inventory = await discoverRepositorySurfaces(repoRoot);
  const surfaces = new Map(
    inventory.surfaces.map((surface) => [
      `${surface.kind}:${surface.name}`,
      surface,
    ]),
  );
  const edges = new Map(coverage.edges.map((edge) => [edge.id, edge]));
  const selected = [];
  const missing = [];
  for (const row of catalog.rows) {
    const coverageEdge = edges.get(row.key.surfaceId);
    if (
      row.key.sourceKind !== "builtin" ||
      row.key.output !== "[[return]]" ||
      coverageEdge?.classification !== "effects"
    ) {
      continue;
    }
    const surface = surfaces.get(
      `${coverageEdge.surface.kind}:${coverageEdge.surface.name}`,
    );
    if (!isBuiltinEffectsOutputTargetSurface(surface)) continue;
    const invocation = authoredBuiltinEffectsOutputInvocation({
      catalogKey: row.key,
      coverage,
      coverageEdge,
      surface,
      target,
    });
    if (!invocation) {
      missing.push({ row, coverageEdge, surface });
    } else {
      selected.push({ row, coverageEdge, surface, invocation });
    }
  }
  return { selected, missing };
}

const loaded = effectRows();

function countFamilies(rows) {
  const counts = Object.create(null);
  for (const row of rows) {
    const family = row.invocation.sourceDescriptor.sourceKey;
    counts[family] = (counts[family] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort());
}

describe("builtin effects output recipes", () => {
  test("accounts for the exact 605 callable-return rows", async () => {
    const { selected, missing } = await loaded;
    expect(missing).toEqual([]);
    expect(selected).toHaveLength(605);
    const registrar = selected.filter(
      (row) => row.invocation.cohort === "registrar",
    );
    const descriptorResidual = selected.filter(
      (row) => row.invocation.cohort === "descriptor-residual",
    );
    expect(registrar).toHaveLength(605);
    expect(descriptorResidual).toHaveLength(0);
    expect(countFamilies(registrar)).toEqual(
      BUILTIN_EFFECTS_REGISTRAR_FAMILY_COUNTS,
    );
    expect(countFamilies(descriptorResidual)).toEqual(
      BUILTIN_EFFECTS_DESCRIPTOR_RESIDUAL_FAMILY_COUNTS,
    );
    expect(
      builtinEffectsOutputRouteManifest(
        selected.map((row) => row.invocation),
      ),
    ).toMatchObject({
      total: 605,
      cohorts: { registrar: 605 },
    });
  }, 30_000);

  test("binds every executable operation to one exact inventoried source", async () => {
    const { selected } = await loaded;
    let selectedNoEffectBranches = 0;
    for (const { row, coverageEdge, surface, invocation } of selected) {
      expect(invocation.invocationSchema).toBe(
        BUILTIN_EFFECTS_OUTPUT_INVOCATION_SCHEMA,
      );
      expect(invocation.coverageEdgeId).toBe(row.key.surfaceId);
      expect(invocation.surfaceObservedKey).toBe(surface.observedKey);
      expect(invocation.coverageClassification).toBe("effects");
      expect(invocation.sourceDescriptor.sourceKey).toBe(
        surface.metadata.sourceKey,
      );
      expect(invocation.sourceDescriptor.exportName).toBe(
        surface.metadata.exportName,
      );
      expect(invocation.sourceDescriptor.sourceRef).toBe(surface.sourceRefs[0]);
      expect(new Set(["call", "construct", "get"])).toContain(
        invocation.route.operation,
      );
      expect(invocation.route.cleanup).toEqual({
        kind: "fixture-owned-resource-release",
      });
      expect(invocation.completion).toEqual({
        kind: "event-loop-quiescence",
        timeoutMilliseconds: 1_000,
      });
      expect(invocation.decisionEvidence).toMatchObject({
        kind: "coverage-bound-typed-effects",
        carrierEdgeId: coverageEdge.id,
      });
      expect(invocation.decisionEvidence.typedRoutes.length).toBeGreaterThan(0);
      expect(
        invocation.decisionEvidence.typedRoutes.map(
          (route) => route.coverageEdgeId,
        ),
      ).toContain(coverageEdge.id);
      for (const route of invocation.decisionEvidence.typedRoutes) {
        expect(route.actionStages.length).toBeGreaterThan(0);
        for (const action of route.actionStages) {
          expect(action.actionId.length).toBeGreaterThan(0);
          expect(action.stages.length).toBeGreaterThan(0);
        }
      }
      const noEffectBranch = invocation.decisionEvidence.selectedNoEffectBranch;
      if (noEffectBranch !== null) {
        selectedNoEffectBranches += 1;
        const sourceBranch = coverageEdge.logicalBranches.find(
          (branch) => branch.id === noEffectBranch.branchId,
        );
        expect(sourceBranch.effects).toEqual([]);
        expect(noEffectBranch.carrierEdgeId).toBe(coverageEdge.id);
        expect(noEffectBranch.conditions).toEqual(sourceBranch.when);
      }
      const coveredCaps = [
        ...new Set(coverageEdge.effects.map((effect) => effect.cap)),
      ].sort();
      const boundedCaps = invocation.route.authorityBounds.map(
        (bound) => bound.cap,
      );
      expect(
        coveredCaps.every((cap) => boundedCaps.includes(cap)),
      ).toBe(true);
      expect(
        boundedCaps.filter((cap) => !coveredCaps.includes(cap)).every(
          (cap) => cap === "env:read",
        ),
      ).toBe(true);
      const encoded = JSON.stringify(invocation);
      for (const forbidden of [
        "disposition",
        "expectation",
        "expectedResult",
        "normalizedValue",
        "observedOutcome",
      ]) {
        expect(encoded).not.toContain(forbidden);
      }
    }
    expect(selectedNoEffectBranches).toBe(316);
  }, 30_000);

  test("uses isolated public-family fixtures and honest source operations", async () => {
    const byExport = new Map(
      (await loaded).selected.map((row) => [
        `${row.invocation.sourceDescriptor.sourceKey}:${row.invocation.sourceDescriptor.exportName}`,
        row.invocation,
      ]),
    );
    // Accessors and unresolved descriptor values are `[[value]]` catalog
    // rows in v2. They are property observations, not callable-return probes.
    for (const identity of [
      "node_http:ClientRequest.connection",
      "node_fs_promises:access",
      "node_os:platform",
    ]) {
      expect(byExport.has(identity), identity).toBe(false);
    }
    expect(byExport.get("node_net:Socket.write").route).toMatchObject({
      operation: "call",
      receiver: { kind: "prototype-shell", ownerPath: ["Socket"] },
      arguments: [{ kind: "json", value: "ibex-output-shape" }],
    });
    expect(byExport.get("node_http:Agent").route.operation).toBe("construct");
    expect(byExport.get("node_fs:readFileSync").route.arguments).toEqual([
      {
        kind: "json",
        value: expect.stringMatching(
          /^\/project\/fixtures\/surface\.builtin\.export\.node\.fs\.readfilesync\./,
        ),
      },
    ]);
    expect(byExport.get("node_fs:rename").route.arguments).toEqual([
      {
        kind: "json",
        value: expect.stringMatching(/^\/project\/fixtures\//),
      },
      {
        kind: "json",
        value: expect.stringMatching(/^\/project\/fixtures\//),
      },
      { kind: "noop-function" },
    ]);
    for (const identity of [
      "node_fs:readFile",
      "node_fs:writeFile",
      "node_fs_promises:readFile",
      "node_fs_promises:writeFile",
    ]) {
      const terminal = identity.endsWith("readFile")
        ? "__exactFsReadFileAsync"
        : "__exactFsWriteFileAsync";
      const typedRoute = byExport
        .get(identity)
        .decisionEvidence.typedRoutes.find(
          (candidate) =>
            candidate.sourceBinding?.nativeTerminal === terminal,
        );
      expect(typedRoute.internalObserverActionStages).toContainEqual({
        actionId: "fs:list",
        stages: ["discovery", "repeat", "requested"],
      });
      expect(typedRoute.sourceBinding).toMatchObject({
        kind: "source-authored-native-filesystem-terminal",
        nativeTerminal: terminal,
      });
    }
    for (const invocation of byExport.values()) {
      expect(invocation.route.fixture).toEqual({
        kind: "isolated-family-fixture",
        family: invocation.sourceDescriptor.sourceKey,
        network: "private-loopback-only",
        filesystem: "private-project-tree-only",
        process: "controlled-helper-only",
      });
    }
  }, 30_000);
});
