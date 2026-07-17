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
import { portableWebGpuTestWrapperFactory } from "./webgpu-test-wrapper-portable.mjs";

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
    const nativePrograms = authority.payload.wireEnvelope.nativeCodecPrograms;
    expect(nativePrograms.schema).toBe("ibex/webgpu-native-codec-programs/2");
    expect(nativePrograms.scope.excluded).toBe(
      "full-call-or-event-construction-and-global-v2-carrier-validation",
    );
    expect(nativePrograms.carrierValidationDependency.programOwns).toBe(
      "selected-payload-layout-plus-operation-specific-carrier-joins-and-constraints-only",
    );
    expect(nativePrograms.routes.map((route) => route.operationId)).toEqual([
      "GPU.requestAdapter",
      "GPUAdapter.requestDevice",
    ]);
    expect(nativePrograms.routes[0].request.catalog.wireTag).toBe(2);
    expect(nativePrograms.routes[0].completion.catalog.wireTag).toBe(6);
    expect(nativePrograms.routes[0].completion.variants[0].payload).toEqual({
      kind: "empty",
      exactLengthBytes: 0,
    });
    expect(
      nativePrograms.routes[0].completion.variants[1].payload.fields.at(-1),
    ).toEqual({
      name: "serviceDetachedExpired",
      type: "u8",
      constraint: "boolean-zero-or-one",
    });
    const requestDevice = nativePrograms.routes[1];
    expect(requestDevice.request.catalog.wireTag).toBe(3);
    expect(requestDevice.completion.catalog.wireTag).toBe(4);
    expect(requestDevice.request.executablePrerequisites).toEqual([
      "generatedLogicalProviderDescriptor",
      "authenticatedResultSelectionIdentity",
    ]);
    expect(
      nativePrograms.types.requestDeviceDescriptorV1.fields.find(
        (field) => field.name === "requiredLimits",
      ).value.key,
    ).toBe("string");
    expect(
      requestDevice.request.semanticServiceDerivations.map((row) => row.ownership),
    ).toEqual([
      "native-semantic-service-derived-never-payload-or-wrapper-supplied",
      "native-semantic-service-allocated-never-payload-or-wrapper-supplied",
    ]);
    expect(requestDevice.completion.variants.map((variant) => variant.name)).toEqual([
      "live-object",
      "detached-not-admitted-object",
      "detached-admitted-object",
    ]);
    expect(requestDevice.completion.serviceResultJoins.at(-1)).toEqual({
      payloadPath: "body.diagnosticMessage",
      serviceResultPath: "nativeSemanticServiceResult.diagnosticMessage",
      operator: "equal-never-caller-selected",
    });
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
    expect(plan.semantic.featurePolicy.defaultFeatures).toEqual({
      core: ["core-features-and-limits"],
      compatibility: [],
    });
    expect(plan.semantic.limitPolicy.limits[0]).toMatchObject({
      coreDefault: 8192,
      compatibilityDefault: 4096,
      profileBucket: { core: 8192, compatibility: 8192 },
      capabilityGrantBoundary: { core: 8192, compatibility: 8192 },
    });
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
    expect(
      validated.semanticProjection.limitPolicy.requestValidation
        .unknownNonUndefined,
    ).toBe("operation-error-promise-rejection");
    expect(validated.semanticProjection.featurePolicy.newDeviceFeatureImplications)
      .toEqual([
        {
          feature: "texture-formats-tier2",
          implies: "texture-formats-tier1",
        },
        {
          feature: "texture-formats-tier1",
          implies: "rg11b10ufloat-renderable",
        },
      ]);
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

    const shutdown = clone(authority);
    shutdown.payload.providerDescriptor.serviceShutdownPolicy.clock = "wall";
    mutations.push(shutdown);

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

    const nativeSchema = clone(authority);
    nativeSchema.payload.wireEnvelope.nativeCodecPrograms.schema =
      "ibex/webgpu-native-codec-programs/1";
    mutations.push(nativeSchema);

    const nativeBodyOrder = clone(authority);
    nativeBodyOrder.payload.wireEnvelope.nativeCodecPrograms.routes[0]
      .request.payload.fields.reverse();
    mutations.push(nativeBodyOrder);

    const nativeScope = clone(authority);
    nativeScope.payload.wireEnvelope.nativeCodecPrograms.scope.excluded = "none";
    mutations.push(nativeScope);

    const nativeCarrierDependency = clone(authority);
    nativeCarrierDependency.payload.wireEnvelope.nativeCodecPrograms
      .carrierValidationDependency.globallyOwnedCarrierInvariants.pop();
    mutations.push(nativeCarrierDependency);

    const nativeCatalog = clone(authority);
    nativeCatalog.payload.wireEnvelope.nativeCodecPrograms.routes[0]
      .request.catalog.wireTag = 3;
    mutations.push(nativeCatalog);

    const nativeOptions = clone(authority);
    nativeOptions.payload.wireEnvelope.nativeCodecPrograms.types
      .requestAdapterOptionsV1.unknownFields = "ignore";
    mutations.push(nativeOptions);

    const nativeJoin = clone(authority);
    nativeJoin.payload.wireEnvelope.nativeCodecPrograms.routes[0]
      .request.carrierJoins.pop();
    mutations.push(nativeJoin);

    const nativeNull = clone(authority);
    nativeNull.payload.wireEnvelope.nativeCodecPrograms.routes[0]
      .completion.variants[0].payload.exactLengthBytes = 13;
    mutations.push(nativeNull);

    const nativeProviderJoin = clone(authority);
    nativeProviderJoin.payload.wireEnvelope.nativeCodecPrograms.routes[0]
      .completion.variants[1].carrierJoins[0].carrierPath =
        "record.operation_result.operation.result_device.provider_generation";
    mutations.push(nativeProviderJoin);

    const nativeDetachedState = clone(authority);
    nativeDetachedState.payload.wireEnvelope.nativeCodecPrograms.routes[0]
      .completion.variants[1].payload.fields.at(-1).constraint = "positive";
    mutations.push(nativeDetachedState);

    const nativeRequestDeviceDerivation = clone(authority);
    nativeRequestDeviceDerivation.payload.wireEnvelope.nativeCodecPrograms.routes[1]
      .request.semanticServiceDerivations[0].ownership = "wrapper-supplied";
    mutations.push(nativeRequestDeviceDerivation);

    const nativeRequestDeviceDiagnostic = clone(authority);
    nativeRequestDeviceDiagnostic.payload.wireEnvelope.nativeCodecPrograms.routes[1]
      .completion.serviceResultJoins.pop();
    mutations.push(nativeRequestDeviceDiagnostic);

    const nativeRequestDeviceTransition = clone(authority);
    nativeRequestDeviceTransition.payload.wireEnvelope.nativeCodecPrograms.routes[1]
      .completion.variants[2].carrierConstraints[0].value = 1;
    mutations.push(nativeRequestDeviceTransition);

    for (const mutation of mutations) {
      expect(() => validateWebGpuWrapperAuthority(mutation)).toThrow();
    }
  });

  test("fails closed on limit, terminal, predicate, and fake-client semantic mutations", () => {
    const mutations = [];

    const direction = clone(semantics);
    direction.semanticProjection.limitPolicy.limits[0].betterDirection = "lower";
    mutations.push(direction);

    const compatibilityDefault = clone(semantics);
    compatibilityDefault.semanticProjection.limitPolicy.limits[0]
      .compatibilityDefault += 1;
    mutations.push(compatibilityDefault);

    const compatibilityGrant = clone(semantics);
    compatibilityGrant.semanticProjection.limitPolicy.limits[0]
      .capabilityGrantBoundary.compatibility += 1;
    mutations.push(compatibilityGrant);

    const defaultFeatures = clone(semantics);
    defaultFeatures.semanticProjection.featurePolicy.defaultFeatures.core = [];
    mutations.push(defaultFeatures);

    const adapterImplication = clone(semantics);
    adapterImplication.semanticProjection.featurePolicy
      .adapterFeatureImplications[0].implies = "timestamp-query";
    mutations.push(adapterImplication);

    const newDeviceImplication = clone(semantics);
    newDeviceImplication.semanticProjection.featurePolicy
      .newDeviceFeatureImplications.reverse();
    mutations.push(newDeviceImplication);

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

  test("portable factory fails closed on inconsistent fake adapter capabilities", () => {
    const mutations = [];

    const missingDefault = clone(buildWebGpuWrapperPlan(authority, semantics));
    missingDefault.fakeClientData.adapterFeatures = ["timestamp-query"];
    mutations.push(missingDefault);

    const unknownFeature = clone(buildWebGpuWrapperPlan(authority, semantics));
    unknownFeature.fakeClientData.adapterFeatures.push("not-a-profile-feature");
    mutations.push(unknownFeature);

    const missingAdapterImplication = clone(
      buildWebGpuWrapperPlan(authority, semantics),
    );
    missingAdapterImplication.fakeClientData.adapterFeatures =
      missingAdapterImplication.fakeClientData.adapterFeatures.filter(
        (name) => name !== "texture-compression-bc",
      );
    mutations.push(missingAdapterImplication);

    const missingNewDeviceAddition = clone(
      buildWebGpuWrapperPlan(authority, semantics),
    );
    missingNewDeviceAddition.fakeClientData.adapterFeatures =
      missingNewDeviceAddition.fakeClientData.adapterFeatures.filter(
        (name) => name !== "rg11b10ufloat-renderable",
      );
    mutations.push(missingNewDeviceAddition);

    const incompleteLimits = clone(buildWebGpuWrapperPlan(authority, semantics));
    delete incompleteLimits.fakeClientData.adapterLimits.maxTextureDimension1D;
    mutations.push(incompleteLimits);

    const worseThanCoreDefault = clone(
      buildWebGpuWrapperPlan(authority, semantics),
    );
    worseThanCoreDefault.fakeClientData.adapterLimits.maxTextureDimension1D =
      4096;
    mutations.push(worseThanCoreDefault);

    for (const mutation of mutations) {
      expect(() => portableWebGpuTestWrapperFactory(mutation)).toThrow(
        /capability plan/,
      );
    }
  });
});
