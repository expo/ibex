/**
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 * @ref LLP 0019#the-enforced-conformance-seam
 */

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  REVIEWED_DIGESTS,
  REVIEWED_SEMANTIC_DIGESTS,
  WRAPPER_ROUTE_ASSIGNMENTS,
  buildWebGpuWrapperPlan,
  renderWebGpuTestWrapper,
  validateWebGpuWrapperAuthority,
  validateWebGpuWrapperSemantics,
} from "./webgpu-test-wrapper-generator.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDirectory, "../../../..");
const authorityPath = path.join(
  root,
  "tests/fixtures/webgpu-test-wrapper-authority-v1.json",
);
const generatedPath = path.join(root, "tests/fixtures/webgpu-test-wrapper.generated.js");
const semanticsPath = path.join(
  root,
  "tests/fixtures/webgpu-test-wrapper-semantics-v1.json",
);
const authority = JSON.parse(fs.readFileSync(authorityPath, "utf8"));
const semantics = JSON.parse(fs.readFileSync(semanticsPath, "utf8"));

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

describe("test-only WebGPU wrapper generator", () => {
  test("binds the reviewed normalized projection and all subordinate digests", () => {
    const { computed } = validateWebGpuWrapperAuthority(authority);
    expect(computed).toEqual(REVIEWED_DIGESTS);
    expect(authority.provenance.normalizedProjectionComparison).toBe(
      "required-across-outer-ibex-repins",
    );
    expect(authority.provenance.sourceCommitAndArtifactSha256Disposition).toBe(
      "provenance-only-not-executable-acceptance",
    );
  });

  test("carries every authenticated operation field into one bijective wrapper route", () => {
    const plan = buildWebGpuWrapperPlan(authority, semantics);
    expect(plan.routes).toHaveLength(25);
    expect(WRAPPER_ROUTE_ASSIGNMENTS).toHaveLength(25);
    expect(new Set(plan.routes.map((route) => route.operationId)).size).toBe(25);
    expect(new Set(plan.routes.map((route) => route.wireId)).size).toBe(25);
    for (const operation of authority.payload.operations) {
      const route = plan.routes.find((candidate) => candidate.operationId === operation.operationId);
      const assignment = WRAPPER_ROUTE_ASSIGNMENTS.find(
        (candidate) => candidate[0] === operation.operationId,
      );
      expect(route).toEqual({
        ...operation,
        interfaceName: assignment[1],
        memberName: assignment[2],
        fakeProviderEntry:
          semantics.fakeClientData.providerEntryOperationIds.includes(
            operation.operationId,
          ),
      });
    }
    expect(plan.fakeClientData.disposition).toBe(
      "deterministic-test-data-not-exact-profile-authority",
    );
    expect(plan.semantic.limitPolicy.limits).toHaveLength(36);
    expect(plan.semantic.providerRoutingPrograms.map((program) => program.operationId)).toEqual([
      "GPU.requestAdapter",
      "GPUAdapter.requestDevice",
      "GPUCanvasContext.configure",
      "GPUCanvasContext.unconfigure",
      "GPUDevice.createCommandEncoder",
      "GPUDevice.createRenderPipeline",
      "GPUDevice.createShaderModule",
      "GPUDevice.destroy",
      "GPUDevice.popErrorScope",
      "GPUQueue.submit",
      "GPUTexture.createView",
      "GPUTexture.destroy",
    ]);
    expect(plan.semantic.requestDeviceProviderDescriptor.policy).toBe(
      "generated-logical-limits-plus-versioned-service-internal-requirements-only",
    );
    expect(
      plan.semantic.requestDeviceProviderDescriptor.providerReadyPredicate.relation,
    ).toContain("raw request descriptor is unavailable at this boundary");
  });

  test("binds the separate limit and requestDevice semantic projection", () => {
    const validated = validateWebGpuWrapperSemantics(semantics);
    expect(validated.computed).toEqual(REVIEWED_SEMANTIC_DIGESTS);
    expect(semantics.provenance.normalizedSemanticComparison).toBe(
      "required-across-outer-ibex-repins",
    );
    expect(validated.semanticProjection.requestDeviceRouting.terminals).toHaveLength(17);
    expect(validated.semanticProjection.requestDeviceFailureProgram.branches).toHaveLength(10);
    expect(validated.semanticProjection.providerRoutingPrograms).toHaveLength(12);
  });

  test("renders deterministically as a portable expression with no install surface", () => {
    const first = renderWebGpuTestWrapper(authority, semantics);
    const second = renderWebGpuTestWrapper(clone(authority), clone(semantics));
    expect(second).toBe(first);
    expect(fs.readFileSync(generatedPath, "utf8")).toBe(first);
    expect(first).not.toMatch(/(?:^|\n)\s*(?:import|export)\s/u);
    expect(first).not.toContain("globalThis");
    expect(first).not.toContain("navigator.gpu");
    expect(first).not.toContain("__exactGpuBridge");
    expect(first).not.toContain("runtime-entry");
    expect(first).not.toContain("constructor");
    expect(first).toMatch(/new WeakMap\b/u);

    const factory = (0, eval)(first);
    expect(typeof factory).toBe("function");
    const harness = factory();
    expect(harness.gpu.getPreferredCanvasFormat()).toBe("bgra8unorm");
    const prototype = Object.getPrototypeOf(harness.gpu);
    expect(Object.getPrototypeOf(prototype)).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(prototype, "constructor")).toBe(false);
    expect(Object.keys(harness).sort()).toEqual([
      "cancel",
      "closeAccount",
      "closeRealm",
      "createCanvasContext",
      "describe",
      "gpu",
      "injectError",
      "inspect",
      "present",
      "providerLoss",
      "retire",
      "setRequestDeviceFacts",
    ]);
  });

  test("uses real TypeError objects and route-driven singleton wire identity", async () => {
    const factory = (0, eval)(renderWebGpuTestWrapper(authority, semantics));
    const harness = factory();
    const borrowed = Object.getPrototypeOf(harness.gpu).requestAdapter;
    let receiverError;
    try {
      borrowed.call({});
    } catch (error) {
      receiverError = error;
    }
    expect(receiverError).toBeInstanceOf(TypeError);
    expect(receiverError.name).toBe("TypeError");

    const adapter = await harness.gpu.requestAdapter();
    await adapter.requestDevice();
    await adapter.requestDevice();
    const observation = harness.inspect();
    const adapterReceipt = observation.serviceReceipts.find(
      (receipt) => receipt.operationName === "GPU.requestAdapter",
    );
    const deviceReceipts = observation.serviceReceipts.filter(
      (receipt) => receipt.operationName === "GPUAdapter.requestDevice",
    );
    expect(adapterReceipt.receiverRef).toBeNull();
    expect(adapterReceipt.authenticatedIngressContext.receiverRef).toBeNull();
    expect(adapterReceipt.authenticatedIngressContext.adapterOperationOrdinal).toBe(0);
    expect(deviceReceipts.map((receipt) =>
      receipt.authenticatedIngressContext.adapterOperationOrdinal)).toEqual([1, 2]);
  });

  test("treats recursive source commit and full-artifact SHA as provenance only", () => {
    const mutation = clone(authority);
    mutation.provenance.sourceCommit = "f".repeat(40);
    mutation.provenance.sourceArtifactSha256 = "e".repeat(64);
    expect(renderWebGpuTestWrapper(mutation, semantics)).toBe(
      renderWebGpuTestWrapper(authority, semantics),
    );
  });

  test("fails closed on routing, semantics, vocabulary, provider, and inventory mutations", () => {
    const mutations = [];

    const routing = clone(authority);
    routing.payload.operations[0].resultTiming = "mutated-timing";
    mutations.push(routing);

    const semantics = clone(authority);
    semantics.payload.operations[0].semanticSha256 = "0".repeat(64);
    mutations.push(semantics);

    const vocabulary = clone(authority);
    vocabulary.payload.eventModel.deliveryOrder = "mutated-order";
    mutations.push(vocabulary);

    const provider = clone(authority);
    provider.payload.providerDescriptor.runtimeRoutingDigest = "0".repeat(64);
    mutations.push(provider);

    const missing = clone(authority);
    missing.payload.operations.pop();
    mutations.push(missing);

    const duplicate = clone(authority);
    duplicate.payload.operations[1].operationId =
      duplicate.payload.operations[0].operationId;
    mutations.push(duplicate);

    const installed = clone(authority);
    installed.payload.installInventory.actualInstalledOperationCount = 1;
    mutations.push(installed);

    for (const mutation of mutations) {
      expect(() => validateWebGpuWrapperAuthority(mutation)).toThrow();
    }
  });

  test("fails closed on limit, terminal, predicate, and fake-client semantic mutations", () => {
    const mutations = [];

    const direction = clone(semantics);
    direction.semanticProjection.limitPolicy.limits[0].betterDirection = "lower";
    mutations.push(direction);

    const terminal = clone(semantics);
    terminal.semanticProjection.requestDeviceRouting.terminals[0].resultDisposition =
      "promise-resolve-object";
    mutations.push(terminal);

    const predicateClass = clone(semantics);
    predicateClass.semanticProjection.requestDeviceFailureProgram.branches[0]
      .orderedPredicates[0].failureClass = "security-error";
    mutations.push(predicateClass);

    const predicateTiming = clone(semantics);
    predicateTiming.semanticProjection.requestDeviceFailureProgram.branches[0]
      .orderedPredicates[0].failureTiming = "none";
    mutations.push(predicateTiming);

    const predicateWire = clone(semantics);
    predicateWire.semanticProjection.requestDeviceFailureProgram.branches[0]
      .orderedPredicates[0].predicateWireId += 1;
    mutations.push(predicateWire);

    const fakeEntry = clone(semantics);
    fakeEntry.fakeClientData.providerEntryOperationIds.pop();
    mutations.push(fakeEntry);

    const providerDescriptor = clone(semantics);
    providerDescriptor.semanticProjection.requestDeviceProviderDescriptor.policy =
      "raw-descriptor-forwarding";
    mutations.push(providerDescriptor);

    const providerRouting = clone(semantics);
    providerRouting.semanticProjection.providerRoutingPrograms[0].terminals[0]
      .providerTokenCount = 1;
    mutations.push(providerRouting);

    for (const mutation of mutations) {
      expect(() => validateWebGpuWrapperSemantics(mutation)).toThrow();
    }
  });
});
