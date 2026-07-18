/**
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 * @ref LLP 0019#the-enforced-conformance-seam
 */

import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CONDITIONAL_PROVIDER_OPERATION_IDS,
  CONDITIONAL_PROVIDER_ROUTE_COUNT,
  NATIVE_CODEC_ROUTE_IDS,
  REVIEWED_DIGESTS,
  REVIEWED_SEMANTIC_DIGESTS,
  WRAPPER_ROUTE_ASSIGNMENTS,
  WRAPPER_ROUTE_COUNT,
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

function nativeRoute(value, operationId) {
  const route = value.payload.wireEnvelope.nativeCodecPrograms.routes.find(
    (candidate) => candidate.operationId === operationId,
  );
  if (!route) throw new Error(`missing native codec route: ${operationId}`);
  return route;
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
    expect(nativePrograms.routes.map((route) => route.operationId)).toEqual(
      NATIVE_CODEC_ROUTE_IDS,
    );
    const requestAdapter = nativeRoute(authority, "GPU.requestAdapter");
    expect(requestAdapter.request.catalog.wireTag).toBe(2);
    expect(requestAdapter.completion.catalog.wireTag).toBe(6);
    expect(requestAdapter.completion.variants[0].payload).toEqual({
      kind: "empty",
      exactLengthBytes: 0,
    });
    expect(
      requestAdapter.completion.variants[1].payload.fields.at(-1),
    ).toEqual({
      name: "serviceDetachedExpired",
      type: "u8",
      constraint: "boolean-zero-or-one",
    });
    const requestDevice = nativeRoute(authority, "GPUAdapter.requestDevice");
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
    const createBindGroupLayout = nativeRoute(
      authority,
      "GPUDevice.createBindGroupLayout",
    );
    expect(createBindGroupLayout.request.catalog.wireTag).toBe(15);
    expect(createBindGroupLayout.completion.catalog.wireTag).toBe(2);
    expect(createBindGroupLayout.request.executablePrerequisites).toEqual([]);
    expect(createBindGroupLayout.request.carrierConstraints.find(
      (constraint) => constraint.carrierPath === "target.kind",
    )?.valueFrom).toBe("objectKindTags.GPUBindGroupLayout");
    expect(
      createBindGroupLayout.request.semanticServiceBoundary.requiredAfterDecode,
    ).toEqual([
      "authenticate-contiguous-sealed-local-timeline-prefix",
      "validate-current-live-device-generation",
      "validate-operation-coverage",
      "validate-authorized-live-account",
      "validate-bind-group-layout-descriptor-under-logical-device-capabilities",
      "reserve-bind-group-layout-handle-and-aggregate-envelope",
      "authenticate-wrapper-allocated-bind-group-layout-target",
      "select-provider-admission-and-physical-sequence",
    ]);
    const createBuffer = nativeRoute(authority, "GPUDevice.createBuffer");
    expect(createBuffer.wireId).toBe(3212558232);
    expect(createBuffer.request.catalog.wireTag).toBe(17);
    expect(createBuffer.completion.catalog.wireTag).toBe(2);
    expect(createBuffer.request.executablePrerequisites).toEqual([]);
    expect(createBuffer.request.carrierConstraints.find(
      (constraint) => constraint.carrierPath === "target.kind",
    )?.valueFrom).toBe("objectKindTags.GPUBuffer");
    expect(createBuffer.request.semanticServiceBoundary.requiredAfterDecode).toEqual([
      "authenticate-contiguous-sealed-local-timeline-prefix",
      "validate-current-live-device-generation",
      "validate-operation-coverage",
      "validate-authorized-live-account-and-aggregate-envelope",
      "validate-buffer-descriptor-under-reviewed-workload",
      "validate-buffer-size-under-logical-max-and-structural-ceiling",
      "validate-buffer-usage-closed-bits",
      "validate-buffer-map-usage-combination",
      "validate-buffer-mapped-at-creation-alignment",
      "authenticate-wrapper-allocated-buffer-target-provenance",
      "validate-wrapper-allocated-buffer-target-generation",
      "reserve-buffer-table-and-dual-ledger-capacity",
      "reserve-buffer-provider-request-completion-and-physical-sequence",
      "validate-buffer-label-under-reviewed-workload",
    ]);
    expect(nativePrograms.types.bufferDescriptorV1).toMatchObject({
      kind: "closed-dictionary",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      fields: [
        { name: "label", required: true, value: { kind: "string" } },
        { name: "mappedAtCreation", required: true, value: { kind: "boolean" } },
        {
          name: "size",
          required: true,
          value: {
            kind: "u64",
            constraints: ["js-safe-integer", "maximum-268435456"],
          },
        },
        { name: "usage", required: true, value: { kind: "u32" } },
      ],
    });
    const bindGroupLayoutType = nativePrograms.types.bindGroupLayoutDescriptorV1;
    expect(bindGroupLayoutType).toMatchObject({
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
    });
    expect(bindGroupLayoutType).not.toHaveProperty("workloadClosure");
    const bindGroupLayoutFields = Object.fromEntries(
      bindGroupLayoutType.fields.map((field) => [field.name, field]),
    );
    expect(bindGroupLayoutFields.label.value).toEqual({ kind: "string" });
    expect(bindGroupLayoutFields.entries.value).toMatchObject({
      minCount: 0,
      maxCountFrom: "codecLayout.sequenceMaxCount",
    });
    expect(bindGroupLayoutFields.entries.value).not.toHaveProperty("constraints");
    const bindGroupLayoutEntryFields = Object.fromEntries(
      bindGroupLayoutFields.entries.value.element.fields.map(
        (field) => [field.name, field],
      ),
    );
    expect(Object.keys(bindGroupLayoutEntryFields)).toEqual([
      "binding",
      "buffer",
      "externalTexture",
      "sampler",
      "storageTexture",
      "texture",
      "visibility",
    ]);
    expect(bindGroupLayoutFields.entries.value.element)
      .not.toHaveProperty("constraints");
    const storageFields = Object.fromEntries(
      bindGroupLayoutEntryFields.storageTexture.value.fields.map(
        (field) => [field.name, field],
      ),
    );
    const textureFields = Object.fromEntries(
      bindGroupLayoutEntryFields.texture.value.fields.map(
        (field) => [field.name, field],
      ),
    );
    expect(storageFields.format.value).toEqual({
      kind: "string-enum",
      valuesFrom: "webIdlVocabulary.gpuTextureFormats",
    });
    expect(storageFields.viewDimension.value.values).toEqual([
      "1d",
      "2d",
      "2d-array",
      "cube",
      "cube-array",
      "3d",
    ]);
    expect(textureFields.viewDimension.value.values).toEqual(
      storageFields.viewDimension.value.values,
    );
    const createCommandEncoder = nativeRoute(
      authority,
      "GPUDevice.createCommandEncoder",
    );
    expect(createCommandEncoder.request.catalog.wireTag).toBe(5);
    expect(createCommandEncoder.completion.catalog.wireTag).toBe(2);
    expect(createCommandEncoder.request.executablePrerequisites).toEqual([]);
    expect(createCommandEncoder.request.carrierConstraints.find(
      (constraint) => constraint.carrierPath === "target.kind",
    )?.valueFrom).toBe("objectKindTags.GPUCommandEncoder");
    expect(createCommandEncoder.completion.variants.map(
      (variant) => variant.name,
    )).toEqual(["operation-success"]);
    const createShaderModule = nativeRoute(
      authority,
      "GPUDevice.createShaderModule",
    );
    expect(createShaderModule.request.catalog.wireTag).toBe(7);
    expect(createShaderModule.completion.catalog.wireTag).toBe(2);
    expect(createShaderModule.request.executablePrerequisites).toEqual([]);
    expect(
      createShaderModule.request.semanticServiceBoundary.requiredAfterDecode,
    ).toEqual([
      "authenticate-contiguous-sealed-local-timeline-prefix",
      "validate-current-live-device-generation",
      "validate-operation-coverage",
      "validate-authorized-live-account",
      "validate-wgsl-with-naga-under-logical-capabilities",
      "reserve-shader-module-handle-and-aggregate-envelope",
      "authenticate-wrapper-allocated-shader-module-target",
      "select-provider-admission-and-physical-sequence",
    ]);
    expect(nativePrograms.types.shaderModuleDescriptorV1.fields).toEqual([
      { name: "label", required: true, value: { kind: "string" } },
      { name: "code", required: true, value: { kind: "string" } },
    ]);
    expect(createShaderModule.request.carrierConstraints.find(
      (constraint) => constraint.carrierPath === "target.kind",
    )?.valueFrom).toBe("objectKindTags.GPUShaderModule");
    expect(createShaderModule.completion.variants.map(
      (variant) => variant.name,
    )).toEqual(["operation-success"]);
    const deviceDestroy = nativeRoute(authority, "GPUDevice.destroy");
    expect(deviceDestroy.request.catalog.wireTag).toBe(12);
    expect(deviceDestroy.completion.catalog.wireTag).toBe(2);
    expect(deviceDestroy.request.executablePrerequisites).toEqual([]);
    expect(deviceDestroy.request.valueConstraints.at(-1)).toEqual({
      payloadPath: "convertedArguments",
      operator: "exact-null",
    });
    expect(deviceDestroy.completion.payload).toEqual({
      kind: "empty",
      exactLengthBytes: 0,
    });
    expect(deviceDestroy.completion.variants.map((variant) => variant.name)).toEqual([
      "repeat-cleanup-noop",
      "first-cleanup-provider",
    ]);
    expect(
      deviceDestroy.completion.semanticTerminalMapping.terminals.map((terminal) => ({
        terminalId: terminal.terminalId,
        providerTokenCount: terminal.providerTokenCount,
        physicalSequenceCount: terminal.physicalSequenceCount,
        eventKind: terminal.event.kind,
        completionVariant: terminal.event.completionVariant ?? null,
      })),
    ).toEqual([
      {
        terminalId: "repeat-cleanup-noop",
        providerTokenCount: 0,
        physicalSequenceCount: 0,
        eventKind: "operation-result",
        completionVariant: "repeat-cleanup-noop",
      },
      {
        terminalId: "first-cleanup-rejection",
        providerTokenCount: 0,
        physicalSequenceCount: 0,
        eventKind: "device-error",
        completionVariant: null,
      },
      {
        terminalId: "first-cleanup-provider",
        providerTokenCount: 1,
        physicalSequenceCount: 1,
        eventKind: "operation-result",
        completionVariant: "first-cleanup-provider",
      },
    ]);
    expect(
      deviceDestroy.completion.semanticTerminalMapping.terminals[1].event,
    ).toEqual({
      kind: "device-error",
      kindValue: 2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
      completionPayloadEncoderEligibility: "excluded-not-an-operation-result",
    });
  });

  test("carries every authenticated operation field into one bijective wrapper route", () => {
    const plan = buildWebGpuWrapperPlan(authority, semantics);
    expect(plan.routes).toHaveLength(WRAPPER_ROUTE_COUNT);
    expect(WRAPPER_ROUTE_ASSIGNMENTS).toHaveLength(WRAPPER_ROUTE_COUNT);
    expect(new Set(plan.routes.map((route) => route.operationId)).size).toBe(
      WRAPPER_ROUTE_COUNT,
    );
    expect(new Set(plan.routes.map((route) => route.wireId)).size).toBe(
      WRAPPER_ROUTE_COUNT,
    );
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
    expect(
      plan.semantic.providerRoutingPrograms.map((program) => program.operationId),
    ).toEqual(CONDITIONAL_PROVIDER_OPERATION_IDS);
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
    expect(validated.semanticProjection.providerRoutingPrograms).toHaveLength(
      CONDITIONAL_PROVIDER_ROUTE_COUNT,
    );
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
    nativeRoute(nativeBodyOrder, "GPU.requestAdapter")
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
    nativeRoute(nativeCatalog, "GPU.requestAdapter").request.catalog.wireTag = 3;
    mutations.push(nativeCatalog);

    const nativeOptions = clone(authority);
    nativeOptions.payload.wireEnvelope.nativeCodecPrograms.types
      .requestAdapterOptionsV1.unknownFields = "ignore";
    mutations.push(nativeOptions);

    const nativeJoin = clone(authority);
    nativeRoute(nativeJoin, "GPU.requestAdapter").request.carrierJoins.pop();
    mutations.push(nativeJoin);

    const nativeNull = clone(authority);
    nativeRoute(nativeNull, "GPU.requestAdapter")
      .completion.variants[0].payload.exactLengthBytes = 13;
    mutations.push(nativeNull);

    const nativeProviderJoin = clone(authority);
    nativeRoute(nativeProviderJoin, "GPU.requestAdapter")
      .completion.variants[1].carrierJoins[0].carrierPath =
        "record.operation_result.operation.result_device.provider_generation";
    mutations.push(nativeProviderJoin);

    const nativeDetachedState = clone(authority);
    nativeRoute(nativeDetachedState, "GPU.requestAdapter")
      .completion.variants[1].payload.fields.at(-1).constraint = "positive";
    mutations.push(nativeDetachedState);

    const nativeRequestDeviceDerivation = clone(authority);
    nativeRoute(nativeRequestDeviceDerivation, "GPUAdapter.requestDevice")
      .request.semanticServiceDerivations[0].ownership = "wrapper-supplied";
    mutations.push(nativeRequestDeviceDerivation);

    const nativeRequestDeviceDiagnostic = clone(authority);
    nativeRoute(nativeRequestDeviceDiagnostic, "GPUAdapter.requestDevice")
      .completion.serviceResultJoins.pop();
    mutations.push(nativeRequestDeviceDiagnostic);

    const nativeRequestDeviceTransition = clone(authority);
    nativeRoute(nativeRequestDeviceTransition, "GPUAdapter.requestDevice")
      .completion.variants[2].carrierConstraints[0].value = 1;
    mutations.push(nativeRequestDeviceTransition);

    const nativeBindGroupLayoutTarget = clone(authority);
    nativeRoute(nativeBindGroupLayoutTarget, "GPUDevice.createBindGroupLayout")
      .request.carrierConstraints.find(
        (constraint) => constraint.carrierPath === "target.kind",
      ).valueFrom = "objectKindTags.GPUShaderModule";
    mutations.push(nativeBindGroupLayoutTarget);

    const nativeBindGroupLayoutValidationOrder = clone(authority);
    const nativeBindGroupLayoutValidationSteps =
      nativeRoute(
        nativeBindGroupLayoutValidationOrder,
        "GPUDevice.createBindGroupLayout",
      ).request.semanticServiceBoundary.requiredAfterDecode;
    [nativeBindGroupLayoutValidationSteps[4], nativeBindGroupLayoutValidationSteps[5]] = [
      nativeBindGroupLayoutValidationSteps[5],
      nativeBindGroupLayoutValidationSteps[4],
    ];
    mutations.push(nativeBindGroupLayoutValidationOrder);

    const nativeBindGroupLayoutSequenceBound = clone(authority);
    nativeBindGroupLayoutSequenceBound.payload.wireEnvelope.nativeCodecPrograms.types
      .bindGroupLayoutDescriptorV1.fields[1].value.maxCountFrom =
        "semanticProjection.typeGpuEntryMaximum";
    mutations.push(nativeBindGroupLayoutSequenceBound);

    const nativeBufferValidationOrder = clone(authority);
    const nativeBufferValidationSteps = nativeRoute(
      nativeBufferValidationOrder,
      "GPUDevice.createBuffer",
    ).request.semanticServiceBoundary.requiredAfterDecode;
    [nativeBufferValidationSteps[11], nativeBufferValidationSteps[12]] = [
      nativeBufferValidationSteps[12],
      nativeBufferValidationSteps[11],
    ];
    mutations.push(nativeBufferValidationOrder);

    const nativeBufferCeiling = clone(authority);
    nativeBufferCeiling.payload.wireEnvelope.nativeCodecPrograms.types
      .bufferDescriptorV1.fields[2].value.constraints[1] = "maximum-16777216";
    mutations.push(nativeBufferCeiling);

    const nativeShaderDescriptor = clone(authority);
    nativeShaderDescriptor.payload.wireEnvelope.nativeCodecPrograms.types
      .shaderModuleDescriptorV1.unknownFields = "ignore";
    mutations.push(nativeShaderDescriptor);

    const nativeShaderTarget = clone(authority);
    nativeRoute(nativeShaderTarget, "GPUDevice.createShaderModule")
      .request.carrierConstraints.find(
        (constraint) => constraint.carrierPath === "target.kind",
      ).valueFrom = "objectKindTags.GPUCommandEncoder";
    mutations.push(nativeShaderTarget);

    const nativeShaderValidationOrder = clone(authority);
    const nativeShaderValidationSteps =
      nativeRoute(nativeShaderValidationOrder, "GPUDevice.createShaderModule")
        .request.semanticServiceBoundary.requiredAfterDecode;
    [nativeShaderValidationSteps[4], nativeShaderValidationSteps[5]] = [
      nativeShaderValidationSteps[5],
      nativeShaderValidationSteps[4],
    ];
    mutations.push(nativeShaderValidationOrder);

    const nativeDeviceDestroyTimeline = clone(authority);
    nativeRoute(nativeDeviceDestroyTimeline, "GPUDevice.destroy")
      .request.valueConstraints[0].operator = "exact-empty-sequence";
    mutations.push(nativeDeviceDestroyTimeline);

    const nativeDeviceDestroyAdmission = clone(authority);
    nativeRoute(nativeDeviceDestroyAdmission, "GPUDevice.destroy")
      .completion.variants[1].carrierConstraints[1].operator = "equal";
    mutations.push(nativeDeviceDestroyAdmission);

    const nativeDeviceDestroyTerminal = clone(authority);
    nativeRoute(nativeDeviceDestroyTerminal, "GPUDevice.destroy")
      .completion.semanticTerminalMapping.terminals[2].terminalId =
        "generic-admitted-cleanup";
    mutations.push(nativeDeviceDestroyTerminal);

    const nativeDeviceDestroyTerminalCount = clone(authority);
    nativeRoute(nativeDeviceDestroyTerminalCount, "GPUDevice.destroy")
      .completion.semanticTerminalMapping.terminals[2].providerTokenCount = 0;
    mutations.push(nativeDeviceDestroyTerminalCount);

    const nativeDeviceDestroyErrorMapping = clone(authority);
    nativeRoute(nativeDeviceDestroyErrorMapping, "GPUDevice.destroy")
      .completion.semanticTerminalMapping.terminals[1].event.kind =
        "operation-result";
    mutations.push(nativeDeviceDestroyErrorMapping);

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
