// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// @ref LLP 0021#generated-semantic-datasets

import { describe, expect, test } from "bun:test";
import fs from "node:fs";

import {
  assertExactWebGpuPrivateOperationRegistry,
  authenticateWebGpuProductionPlan,
  buildWebGpuOperationSurfaces,
  loadAuthenticatedWebGpuProductionPlan,
  parseWebGpuProductionPlanSource,
  WEBGPU_PRODUCTION_PLAN_PATH,
  WEBGPU_WRAPPER_AUTHORITY_PATH,
  webGpuOperationSemantics,
} from "./capsec-webgpu-operation-registry.mjs";
import { renderCapsecRegistry } from "./generate-capsec-registry.mjs";

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

describe("construction-private WebGPU CapSec operation registry", () => {
  test("derives one reviewed edge source from every authenticated active route", () => {
    const authenticated = loadAuthenticatedWebGpuProductionPlan(repoRoot);
    const surfaces = buildWebGpuOperationSurfaces(authenticated);
    expect(authenticated.routes).toHaveLength(57);
    expect(surfaces).toHaveLength(57);
    expect(new Set(surfaces.map((surface) => surface.observedKey)).size).toBe(
      57,
    );
    expect(
      authenticated.routes.filter(
        (route) => webGpuOperationSemantics(route).classification === "closed",
      ),
    ).toHaveLength(20);
    expect(
      authenticated.routes.filter(
        (route) =>
          webGpuOperationSemantics(route).classification === "non-capability",
      ),
    ).toHaveLength(37);
  });

  test("rejects removed, mutated, and staged-only route identities", () => {
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
      operationId:
        forged.stagedWorkloadClosure.additionalOperations[0].operationId,
    });
    expect(() =>
      authenticateWebGpuProductionPlan({ plan: forged, authority }),
    ).toThrow(/routes differ from authenticated wrapper authority/);
  });

  test(
    "keeps native authority sessions bijective while WP1 and public issuance stay closed",
    async () => {
      const rendered = await renderCapsecRegistry();
      const generated = JSON.parse(
        rendered.rendered.get(
          new URL(
            "../../../../capsec/generated/webgpu-private-operation-registry.json",
            import.meta.url,
          ).pathname,
        ),
      );
      expect(generated.operationCount).toBe(57);
      expect(generated.privateTargetCellCount).toBe(57);
      expect(
        generated.operations.filter((operation) => operation.authoritySession),
      ).toHaveLength(24);
      expect(generated.providerIdentity).toMatchObject({
        abiVersion: 0x0002_0000,
        topologyId: 1,
        profileId: "exact-webgpu-v1-draft",
        profileDigest:
          "eeda83784ff4297760619cb7df54f0e2f227a70562561909c47ecc9dc3232d95",
      });
      expect(generated.providerIdentity.sortedOperationIds).toHaveLength(46);
      expect(
        new Set(generated.operations.map((operation) => operation.edgeId)).size,
      ).toBe(57);
      expect(
        new Set(
          generated.privateTargetCells.map((cell) => cell.id),
        ).size,
      ).toBe(57);
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
        wireId: 2342501516,
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
      expect(rendered.targetAdvertisements.advertisements).toEqual([]);
      const operationEdgeIds = new Set(
        generated.operations.map((operation) => operation.edgeId),
      );
      expect(
        rendered.targetCells.cells
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
});
