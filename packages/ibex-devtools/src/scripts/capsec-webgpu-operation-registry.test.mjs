// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// @ref LLP 0021#generated-semantic-datasets

import { describe, expect, test } from "bun:test";
import fs from "node:fs";

import {
  assertExactWebGpuPrivateOperationRegistry,
  authenticateWebGpuProductionPlan,
  buildWebGpuPrivateOperationRegistry,
  buildWebGpuOperationSurfaces,
  loadAuthenticatedWebGpuProductionPlan,
  parseWebGpuProductionPlanSource,
  WEBGPU_PRODUCTION_PLAN_PATH,
  WEBGPU_WRAPPER_AUTHORITY_PATH,
  webGpuOperationSemantics,
} from "./capsec-webgpu-operation-registry.mjs";

const repoRoot = new URL("../../../..", import.meta.url).pathname;

function readInputs() {
  const source = fs.readFileSync(
    new URL(`../../../../${WEBGPU_PRODUCTION_PLAN_PATH}`, import.meta.url),
    "utf8",
  );
  const authority = JSON.parse(
    fs.readFileSync(
      new URL(`../../../../${WEBGPU_WRAPPER_AUTHORITY_PATH}`, import.meta.url),
      "utf8",
    ),
  );
  return {
    plan: parseWebGpuProductionPlanSource(source),
    authority,
  };
}

function readRegistryInputs(authenticated) {
  const readJson = (relativePath) =>
    JSON.parse(
      fs.readFileSync(
        new URL(`../../../../${relativePath}`, import.meta.url),
        "utf8",
      ),
    );
  return {
    authenticated,
    coverage: readJson("capsec/registry/coverage-edges.json"),
    implementationRows: readJson(
      "capsec/generated/implementation-manifest.json",
    ).surfaces,
    targetCells: readJson("capsec/registry/target-cells.json"),
    targetAdvertisements: readJson(
      "capsec/generated/target-advertisements.json",
    ),
  };
}

describe("construction-private WebGPU CapSec operation registry", () => {
  test("derives one reviewed edge source from every authenticated active route", () => {
    const authenticated = loadAuthenticatedWebGpuProductionPlan(repoRoot);
    const surfaces = buildWebGpuOperationSurfaces(authenticated);
    expect(authenticated.routes).toHaveLength(63);
    expect(surfaces).toHaveLength(65);
    expect(new Set(surfaces.map((surface) => surface.observedKey)).size).toBe(
      65,
    );
    expect(
      authenticated.routes.filter(
        (route) => webGpuOperationSemantics(route).classification === "closed",
      ),
    ).toHaveLength(22);
    expect(
      authenticated.routes.filter(
        (route) =>
          webGpuOperationSemantics(route).classification === "non-capability",
      ),
    ).toHaveLength(41);
  });

  test("rejects removed, mutated, and forged route identities", () => {
    const { plan, authority } = readInputs();

    const removed = structuredClone(plan);
    removed.routes.pop();
    expect(() =>
      authenticateWebGpuProductionPlan({ plan: removed, authority }),
    ).toThrow(/routes differ from authenticated wrapper authority/);

    const mutated = structuredClone(plan);
    mutated.routes[0].wireId += 1;
    expect(() =>
      authenticateWebGpuProductionPlan({ plan: mutated, authority }),
    ).toThrow(/routes differ from authenticated wrapper authority/);

    const forged = structuredClone(plan);
    forged.routes.push({
      ...forged.routes[0],
      operationId: "GPUQueue.copyExternalImageToTexture.forged",
    });
    expect(() =>
      authenticateWebGpuProductionPlan({ plan: forged, authority }),
    ).toThrow(/routes differ from authenticated wrapper authority/);
  });

  test(
    "keeps native authority sessions bijective while WP1 and public issuance stay closed",
    () => {
      const authenticated = loadAuthenticatedWebGpuProductionPlan(repoRoot);
      const registryInputs = readRegistryInputs(authenticated);
      const generated = buildWebGpuPrivateOperationRegistry(registryInputs);
      expect(generated.webgpuOperationRegistrySchema).toBe(
        "ibex/webgpu-private-capsec-operations/2",
      );
      expect(generated.operationCount).toBe(63);
      expect(generated.privateTargetCellCount).toBe(65);
      expect(
        generated.operations.filter((operation) => operation.authoritySession),
      ).toHaveLength(27);
      expect(generated.providerIdentity).toMatchObject({
        abiVersion: 0x0002_0000,
        topologyId: 1,
        profileId: "exact-webgpu-v1-draft",
        profileDigest:
          "6144f1569b6f5b93fbee4fd8a63f954312b3fb1a2709f1f83267645aaf89fd49",
      });
      expect(generated.providerIdentity.sortedOperationIds).toHaveLength(63);
      expect(
        new Set(generated.operations.map((operation) => operation.edgeId)).size,
      ).toBe(63);
      expect(
        new Set(
          generated.privateTargetCells.map((cell) => cell.id),
        ).size,
      ).toBe(65);
      expect(generated.presentationAuthority).toMatchObject({
        schema: "ibex/webgpu-presentation-authority/1",
        captureOperationId: "GPUCanvasContext.getCurrentTexture",
        branches: [
          {
            id: "acquire",
            operationId: "navigator.gpu.canvas.acquire",
            action: "gpu:operation",
          },
          {
            id: "present",
            operationId: "navigator.gpu.canvas.present",
            action: "gpu:operation",
          },
        ],
        phasePrograms: [
          {
            phase: "entry",
            decisions: [{ invocation: "capture-and-retain" }],
          },
          {
            phase: "entry-recheck",
            decisions: [{ invocation: "transient-current-call" }],
          },
          {
            phase: "acquire-admission",
            decisions: [
              { branch: "acquire", invocation: "evaluate" },
              { branch: "present", invocation: "evaluate" },
            ],
          },
          {
            phase: "candidate-commit",
            decisions: [
              {
                branch: "acquire",
                invocation: "evaluate-and-then-batch",
              },
              {
                branch: "present",
                invocation: "evaluate-and-then-batch",
              },
            ],
            continuationAfter: { branch: "present", stage: "commit" },
          },
          {
            phase: "handoff-repeat",
            decisions: [{ invocation: "evaluate-and-then-batch" }],
            continuationAfter: { branch: "present", stage: "repeat" },
          },
        ],
      });
      expect(
        generated.privateTargetCells.every(
          (cell) =>
            cell.supportDisposition ===
              "supported-construction-private-only" &&
            cell.publicInstallDisposition === "absent" &&
            cell.platformSupportClaim === "none" &&
            !cell.positiveAuthority.startsWith("granted"),
        ),
      ).toBe(true);
      expect(generated.operations).toContainEqual(expect.objectContaining({
        operationId: "GPUDevice.createComputePipeline",
        wireId: 3202875898,
        edgeClassification: "closed",
        authoritySession: {
          decisionKind: "typed-positive",
          action: "gpu:operation",
          stages: ["requested", "commit", "repeat"],
          targetCellDisposition: "complete",
        },
      }));
      expect(generated.operations).toContainEqual(expect.objectContaining({
        operationId: "GPUDevice.pushErrorScope",
        edgeClassification: "non-capability",
        authoritySession: {
          decisionKind: "structural-control-plane",
          stages: ["requested", "commit", "repeat"],
          targetCellDisposition: "non-capability",
        },
      }));
      expect(
        generated.privateTargetCells.find((cell) =>
          cell.id.includes("gpu.requestadapter"),
        ),
      ).toMatchObject({
        capsecDisposition: "complete",
        positiveAuthority: "typed-gpu-operation-no-public-grant-issuer",
      });
      expect(generated.publicBoundary).toMatchObject({
        navigatorGpu: "absent",
        positiveGrantIssuer: "absent",
        wp1TargetAdvertisements: "empty",
        platformSupportClaim: "none",
      });
      expect(generated.operations).toContainEqual(expect.objectContaining({
        operationId: "GPUQueue.copyExternalImageToTexture",
        wireId: 1909541119,
        edgeClassification: "closed",
        authoritySession: {
          decisionKind: "typed-positive",
          action: "gpu:operation",
          stages: ["requested", "commit", "repeat"],
          targetCellDisposition: "complete",
        },
      }));
      expect(registryInputs.targetAdvertisements.advertisements).toEqual([]);
      const operationEdgeIds = new Set(
        generated.operations.map((operation) => operation.edgeId),
      );
      expect(
        registryInputs.targetCells.cells
          .filter((cell) => operationEdgeIds.has(cell.edgeId))
          .every(
            (cell) =>
              cell.disposition === "unsupported" && cell.fixtures.length === 0,
          ),
      ).toBe(true);

      const forged = structuredClone(generated);
      forged.publicBoundary.positiveGrantIssuer = "caller-digest";
      expect(() =>
        assertExactWebGpuPrivateOperationRegistry(forged, generated),
      ).toThrow(/differs from its authenticated source derivation/);
    },
    90_000,
  );

  test("fails closed when full CapSec branch projections are stale", () => {
    const authenticated = loadAuthenticatedWebGpuProductionPlan(repoRoot);
    const base = readRegistryInputs(authenticated);
    const operationId = "GPU.requestAdapter";
    const edge = base.coverage.edges.find(
      (candidate) =>
        candidate.surface?.kind === "native-op" &&
        candidate.surface?.name ===
          `construction-private:webgpu:${operationId}`,
    );
    expect(edge).toBeDefined();
    const implementationIndex = base.implementationRows.findIndex(
      (row) => row.edgeId === edge.id,
    );
    const targetCellIndex = base.targetCells.cells.findIndex(
      (cell) => cell.edgeId === edge.id,
    );
    expect(implementationIndex).toBeGreaterThanOrEqual(0);
    expect(targetCellIndex).toBeGreaterThanOrEqual(0);

    const mutations = [
      (inputs) => {
        inputs.implementationRows[implementationIndex].branchId += ".stale";
      },
      (inputs) => {
        inputs.implementationRows[implementationIndex].sourceRefs[0] +=
          ":stale";
      },
      (inputs) => {
        inputs.implementationRows[
          implementationIndex
        ].enforcementRoute.sourceRefs[0] += ":stale";
      },
      (inputs) => {
        inputs.targetCells.cells[
          targetCellIndex
        ].implementationBranchIds[0] += ".stale";
      },
    ];
    for (const mutate of mutations) {
      const inputs = structuredClone(base);
      mutate(inputs);
      expect(() => buildWebGpuPrivateOperationRegistry(inputs)).toThrow(
        /GPU\.requestAdapter: full CapSec projections are stale for authenticated wire ID 1574056057; run bun run generate:capsec-registry before generate:webgpu-capsec-registry/,
      );
    }
  });
});
