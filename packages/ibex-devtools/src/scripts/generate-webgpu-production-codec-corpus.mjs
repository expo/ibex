#!/usr/bin/env bun
/**
 * Emit language-neutral byte vectors by executing the generated production
 * conversion and codec implementation itself. Native consumers pin this
 * corpus instead of maintaining hand-authored examples that can drift from
 * WebIDL defaults or the private IBGQ/IBGR layout.
 *
 * This is conformance input only. It does not install navigator.gpu or claim a
 * native decoder/provider exists.
 *
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 * @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
  WEBGPU_EXECUTABLE_CODEC_MANIFEST,
  WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT,
} from "../../../ibex-runtime-js/src/webgpu/production-codecs.generated.ts";
import { WEBGPU_PRODUCTION_PLAN } from "../../../ibex-runtime-js/src/webgpu/production-plan.generated.ts";
import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../../../..");
const manifestPath =
  "tests/fixtures/webgpu-production-codec-manifest-v1.generated.json";
const semanticsPath =
  "tests/fixtures/webgpu-test-wrapper-semantics-v1.json";
const renderPipelineConversionPath =
  "tests/fixtures/webgpu-render-pipeline-conversion-v1.json";
const computePipelineConversionPath =
  "tests/fixtures/webgpu-compute-pipeline-conversion-v1.json";
const outputPath =
  "tests/fixtures/webgpu-production-codec-corpus-v1.generated.json";
const operationId = "GPU.requestAdapter";
const requestDeviceOperationId = "GPUAdapter.requestDevice";
const createBindGroupOperationId = "GPUDevice.createBindGroup";
const createBindGroupLayoutOperationId = "GPUDevice.createBindGroupLayout";
const createBufferOperationId = "GPUDevice.createBuffer";
const createPipelineLayoutOperationId = "GPUDevice.createPipelineLayout";
const createComputePipelineOperationId = "GPUDevice.createComputePipeline";
const createRenderPipelineOperationId = "GPUDevice.createRenderPipeline";
const createSamplerOperationId = "GPUDevice.createSampler";
const createTextureOperationId = "GPUDevice.createTexture";
const createTextureViewOperationId = "GPUTexture.createView";
const createCommandEncoderOperationId = "GPUDevice.createCommandEncoder";
const createShaderModuleOperationId = "GPUDevice.createShaderModule";
const deviceDestroyOperationId = "GPUDevice.destroy";
const bufferDestroyOperationId = "GPUBuffer.destroy";
const bufferMapAsyncOperationId = "GPUBuffer.mapAsync";
const bufferUnmapOperationId = "GPUBuffer.unmap";
const canvasConfigureOperationId = "GPUCanvasContext.configure";
const canvasUnconfigureOperationId = "GPUCanvasContext.unconfigure";
const textureDestroyOperationId = "GPUTexture.destroy";
const queueWriteBufferOperationId = "GPUQueue.writeBuffer";
const queueWriteTextureOperationId = "GPUQueue.writeTexture";
const queueSubmitOperationId = "GPUQueue.submit";

function fail(message) {
  throw new Error(message);
}

function toHex(value) {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString(
    "hex",
  );
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function mutatedBytes(value, mutate) {
  const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    .slice();
  mutate(bytes, new DataView(bytes.buffer));
  return bytes;
}

function withTrailingByte(value) {
  const source = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  const bytes = new Uint8Array(source.byteLength + 1);
  bytes.set(source);
  bytes[source.byteLength] = 0xa5;
  return bytes;
}

function buildCorpus() {
  const route = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === operationId,
  );
  if (!route) fail(`${operationId} is absent from the generated production plan`);
  const requestCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
    (candidate) => candidate.tag === route.serviceArgumentCodec,
  );
  const completionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) => candidate.tag === route.serviceCompletionCodec,
    );
  if (
    !requestCodec?.executableFromCurrentAuthenticatedInputs ||
    requestCodec.unavailableSemanticFields.length !== 0 ||
    !completionCodec
  ) {
    fail(`${operationId} is not an executable generated codec route`);
  }
  const nativeRoute = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
    .find((candidate) => candidate.operationId === operationId);
  if (
    !nativeRoute ||
    nativeRoute.wireId !== route.wireId ||
    nativeRoute.request.catalog.tag !== requestCodec.tag ||
    nativeRoute.request.catalog.wireTag !== requestCodec.wireTag ||
    nativeRoute.completion.catalog.tag !== completionCodec.tag ||
    nativeRoute.completion.catalog.wireTag !== completionCodec.wireTag
  ) {
    fail("requestAdapter native codegen program does not select the generated route");
  }

  const wrapperAccess = Object.freeze({
    reference() {
      fail("requestAdapter conversion must not inspect a wrapper reference");
    },
  });
  const receiver = Object.freeze({
    kind: "GPU",
    objectId: "23",
    objectGeneration: "4",
    logicalDeviceId: "0",
    logicalDeviceGeneration: "0",
    providerGeneration: "0",
  });
  const zeroDevice = Object.freeze({
    logical_device_id: "0",
    logical_device_generation: "0",
    provider_generation: "0",
  });
  const requestCarrier = Object.freeze({
    operation_id: route.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: zeroDevice,
    provider_generation: "0",
    operation_instance_id: "11",
    promise_id: "7",
    captured_scope_id: "0",
    adapter_ordinal: "0",
    device_ingress_ordinal: "0",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPU,
      flags: 0,
      object_id: "23",
      object_generation: "4",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.None,
      flags: 0,
      object_id: "0",
      object_generation: "0",
    }),
  });
  const requestVector = (id, options, expectedConvertedArguments) => {
    const convertedArguments =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        operationId,
        [options],
        wrapperAccess,
      );
    if (
      canonicalJson(convertedArguments) !==
      canonicalJson(expectedConvertedArguments)
    ) {
      fail(`${id} WebIDL projection drifted`);
    }
    const bytes = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      Object.freeze({
        operationId,
        wireId: route.wireId,
        convertedArguments,
        receiver,
        capturedScopeId: "0",
        adapterOrdinal: "0",
        deviceIngressOrdinal: "0",
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
      }),
    );
    const expected = {
      receiver,
      target: null,
      capturedScopeId: "0",
      adapterOrdinal: "0",
      deviceIngressOrdinal: "0",
      queueIngressOrdinal: "0",
      sealedLocalTimeline: [],
      convertedArguments: expectedConvertedArguments,
    };
    const inspected =
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes);
    if (
      canonicalJson(inspected) !==
      canonicalJson({
        operationId,
        codec: requestCodec.tag,
        ...expected,
      })
    ) {
      fail(`${id} generated request does not round-trip through inspection`);
    }
    return {
      id,
      kind: "request",
      carrierProjection: requestCarrier,
      bytesHex: toHex(bytes),
      expected,
    };
  };
  const defaultRequest = requestVector(
    "request-adapter-default",
    undefined,
    Object.freeze({
      forceFallbackAdapter: false,
      featureLevel: "core",
      xrCompatible: false,
    }),
  );
  const highPerformanceRequest = requestVector(
    "request-adapter-high-performance",
    Object.freeze({
      powerPreference: "high-performance",
      forceFallbackAdapter: false,
    }),
    Object.freeze({
      forceFallbackAdapter: false,
      featureLevel: "core",
      xrCompatible: false,
      powerPreference: "high-performance",
    }),
  );
  const compatibilityRequest = requestVector(
    "request-adapter-compatibility-low-power",
    Object.freeze({
      featureLevel: "compatibility",
      powerPreference: "low-power",
      forceFallbackAdapter: true,
      xrCompatible: true,
    }),
    Object.freeze({
      forceFallbackAdapter: true,
      featureLevel: "compatibility",
      xrCompatible: true,
      powerPreference: "low-power",
    }),
  );

  const liveObjectResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(operationId, {
      kind: "adapter",
      objectId: "41",
      objectGeneration: "2",
      providerGeneration: "9",
      serviceDetachedExpired: false,
      features: [
        "core-features-and-limits",
        "texture-compression-bc",
        "timestamp-query",
      ],
    });
  const detachedExpiredObjectResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(operationId, {
      kind: "adapter",
      objectId: "42",
      objectGeneration: "3",
      providerGeneration: "9",
      serviceDetachedExpired: true,
      features: ["core-features-and-limits"],
    });
  const nullResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(operationId, {
      kind: "null",
    });
  const objectResultEvent = Object.freeze({
    kind: 1,
    operationId: route.wireId,
    resultKind: 3,
    status: 0,
    providerAdmission: 1,
    physicalSequence: "5",
    deviceTransition: 0,
    ingressLogicalDeviceId: "0",
    ingressLogicalDeviceGeneration: "0",
    ingressProviderGeneration: "0",
    logicalDeviceId: "0",
    logicalDeviceGeneration: "0",
    providerGeneration: "0",
    operationProviderGeneration: "9",
    payload: liveObjectResult,
  });
  const nullResultEvent = Object.freeze({
    kind: 1,
    operationId: route.wireId,
    resultKind: 2,
    status: 0,
    providerAdmission: 1,
    physicalSequence: "5",
    deviceTransition: 0,
    ingressLogicalDeviceId: "0",
    ingressLogicalDeviceGeneration: "0",
    ingressProviderGeneration: "0",
    logicalDeviceId: "0",
    logicalDeviceGeneration: "0",
    providerGeneration: "0",
    operationProviderGeneration: "9",
    payload: nullResult,
  });
  const notAdmittedNullResultEvent = Object.freeze({
    ...nullResultEvent,
    providerAdmission: 0,
    physicalSequence: "0",
    operationProviderGeneration: "0",
  });
  const resultCarrierProjection = (
    resultKind,
    providerAdmission = 1,
    physicalSequence = "5",
    providerGeneration = "9",
  ) => ({
    kind: 1,
    record: {
      operation_result: {
        result_kind: resultKind,
        status: 0,
        operation: {
          operation_id: route.wireId,
          operation_instance_id: "11",
          promise_id: "7",
          provider_admission: providerAdmission,
          physical_sequence: physicalSequence,
          captured_scope_id: "0",
          adapter_ordinal: "0",
          device_ingress_ordinal: "0",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: zeroDevice,
          result_device: zeroDevice,
          provider_generation: providerGeneration,
          receiver: requestCarrier.receiver,
          target: requestCarrier.target,
        },
      },
    },
  });
  const decodedLiveObject =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      operationId,
      objectResultEvent,
    );
  const decodedDetachedExpiredObject =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      operationId,
      Object.freeze({
        ...objectResultEvent,
        payload: detachedExpiredObjectResult,
      }),
    );
  const decodedNull = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
    operationId,
    nullResultEvent,
  );
  const decodedNotAdmittedNull =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      operationId,
      notAdmittedNullResultEvent,
    );
  if (
    canonicalJson(decodedLiveObject) !==
      canonicalJson({
        kind: "object",
        object: {
          kind: "GPUAdapter",
          objectId: "41",
          objectGeneration: "2",
          providerGeneration: "9",
          serviceDetachedExpired: false,
          features: [
            "core-features-and-limits",
            "texture-compression-bc",
            "timestamp-query",
          ],
        },
      }) ||
    canonicalJson(decodedDetachedExpiredObject) !==
      canonicalJson({
        kind: "object",
        object: {
          kind: "GPUAdapter",
          objectId: "42",
          objectGeneration: "3",
          providerGeneration: "9",
          serviceDetachedExpired: true,
          features: ["core-features-and-limits"],
        },
      }) ||
    canonicalJson(decodedNull) !== canonicalJson({ kind: "null" }) ||
    canonicalJson(decodedNotAdmittedNull) !== canonicalJson({ kind: "null" })
  ) {
    fail("requestAdapter generated result does not join event provenance");
  }

  const requestDeviceRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === requestDeviceOperationId,
  );
  if (!requestDeviceRoute) {
    fail(`${requestDeviceOperationId} is absent from the generated production plan`);
  }
  const requestDeviceRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === requestDeviceRoute.serviceArgumentCodec,
    );
  const requestDeviceCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) => candidate.tag === requestDeviceRoute.serviceCompletionCodec,
    );
  const requestDeviceNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === requestDeviceOperationId,
    );
  if (
    !requestDeviceRequestCodec ||
    requestDeviceRequestCodec.executableFromCurrentAuthenticatedInputs ||
    !requestDeviceRequestCodec.nativeProgramPrerequisitesRepresented ||
    canonicalJson(requestDeviceRequestCodec.unavailableSemanticFields) !==
      canonicalJson([
        "generatedLogicalProviderDescriptor",
        "authenticatedResultSelectionIdentity",
      ]) ||
    !requestDeviceCompletionCodec ||
    !requestDeviceNativeRoute ||
    requestDeviceNativeRoute.request.catalog.wireTag !==
      requestDeviceRequestCodec.wireTag ||
    requestDeviceNativeRoute.completion.catalog.wireTag !==
      requestDeviceCompletionCodec.wireTag
  ) {
    fail(
      "requestDevice native codegen program must be represented while production admission remains blocked",
    );
  }

  const requestDeviceReceiver = Object.freeze({
    kind: "GPUAdapter",
    objectId: "70",
    objectGeneration: "1",
    logicalDeviceId: "0",
    logicalDeviceGeneration: "0",
    providerGeneration: "9",
  });
  const requestDeviceRequestCarrier = Object.freeze({
    operation_id: requestDeviceRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: zeroDevice,
    provider_generation: "9",
    operation_instance_id: "12",
    promise_id: "8",
    captured_scope_id: "0",
    adapter_ordinal: "1",
    device_ingress_ordinal: "0",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUAdapter,
      flags: 0,
      object_id: "70",
      object_generation: "1",
    }),
    target: requestCarrier.target,
  });
  const requestDeviceDescriptor = Object.freeze({
    label: "corpus-device",
    requiredFeatures: Object.freeze(["shader-f16", "timestamp-query"]),
    requiredLimits: Object.freeze({
      maxBindGroups: 8,
      maxStorageBuffersPerShaderStage: 12,
    }),
    defaultQueue: Object.freeze({ label: "corpus-queue" }),
  });
  const convertedRequestDeviceDescriptor =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      requestDeviceOperationId,
      [requestDeviceDescriptor],
      wrapperAccess,
    );
  if (
    canonicalJson(convertedRequestDeviceDescriptor) !==
      canonicalJson(requestDeviceDescriptor)
  ) {
    fail("requestDevice WebIDL descriptor projection drifted");
  }
  const requestDeviceBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      Object.freeze({
        operationId: requestDeviceOperationId,
        wireId: requestDeviceRoute.wireId,
        convertedArguments: convertedRequestDeviceDescriptor,
        receiver: requestDeviceReceiver,
        capturedScopeId: "0",
        adapterOrdinal: "1",
        deviceIngressOrdinal: "0",
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
      }),
    );
  const inspectedRequestDevice =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      requestDeviceBytes,
    );
  if (
    canonicalJson(inspectedRequestDevice) !== canonicalJson({
      operationId: requestDeviceOperationId,
      codec: requestDeviceRequestCodec.tag,
      receiver: requestDeviceReceiver,
      target: null,
      capturedScopeId: "0",
      adapterOrdinal: "1",
      deviceIngressOrdinal: "0",
      queueIngressOrdinal: "0",
      sealedLocalTimeline: [],
      convertedArguments: requestDeviceDescriptor,
    })
  ) {
    fail("requestDevice generated request does not round-trip through inspection");
  }

  const semanticAuthority = JSON.parse(fs.readFileSync(
    path.join(repositoryRoot, semanticsPath),
    "utf8",
  ));
  const unknownLimitDisposition = semanticAuthority.semanticProjection
    ?.limitPolicy?.requestValidation?.unknownNonUndefined;
  if (unknownLimitDisposition !== "operation-error-promise-rejection") {
    fail("unknown requestDevice limit disposition drifted");
  }
  const assertSemanticTerminalCounts = (
    operationId,
    terminalId,
    providerAdmission,
    physicalSequence,
  ) => {
    const program = semanticAuthority.semanticProjection?.providerRoutingPrograms
      ?.find((candidate) => candidate.operationId === operationId);
    const terminal = program?.terminals?.find(
      (candidate) => candidate.terminalId === terminalId,
    );
    const physicalSequenceCount = physicalSequence === "0" ? 0 : 1;
    if (
      !terminal ||
      terminal.providerTokenCount !== providerAdmission ||
      terminal.physicalSequenceCount !== physicalSequenceCount
    ) {
      fail(
        `${operationId} ${terminalId} completion carrier disagrees with semantic authority`,
      );
    }
  };
  const hostileRequiredLimits = Object.defineProperty({}, "__proto__", {
    value: 4,
    writable: true,
    enumerable: true,
    configurable: true,
  });
  const convertedUnknownLimitDescriptor =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      requestDeviceOperationId,
      [{ requiredLimits: hostileRequiredLimits }],
      wrapperAccess,
    );
  const convertedUnknownLimits =
    convertedUnknownLimitDescriptor.requiredLimits;
  if (
    Object.getPrototypeOf(convertedUnknownLimits) !== null ||
    !Object.prototype.hasOwnProperty.call(convertedUnknownLimits, "__proto__") ||
    convertedUnknownLimits.__proto__ !== 4
  ) {
    fail("unknown requestDevice limit witness was not preserved by conversion");
  }
  const unknownLimitRequestBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      Object.freeze({
        operationId: requestDeviceOperationId,
        wireId: requestDeviceRoute.wireId,
        convertedArguments: convertedUnknownLimitDescriptor,
        receiver: requestDeviceReceiver,
        capturedScopeId: "0",
        adapterOrdinal: "1",
        deviceIngressOrdinal: "0",
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
      }),
    );
  const inspectedUnknownLimitRequest =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      unknownLimitRequestBytes,
    );
  const inspectedUnknownLimits = inspectedUnknownLimitRequest
    .convertedArguments.requiredLimits;
  if (
    Object.getPrototypeOf(inspectedUnknownLimits) !== null ||
    !Object.prototype.hasOwnProperty.call(inspectedUnknownLimits, "__proto__") ||
    inspectedUnknownLimits.__proto__ !== 4 ||
    canonicalJson(inspectedUnknownLimitRequest) !== canonicalJson({
      operationId: requestDeviceOperationId,
      codec: requestDeviceRequestCodec.tag,
      receiver: requestDeviceReceiver,
      target: null,
      capturedScopeId: "0",
      adapterOrdinal: "1",
      deviceIngressOrdinal: "0",
      queueIngressOrdinal: "0",
      sealedLocalTimeline: [],
      convertedArguments: convertedUnknownLimitDescriptor,
    })
  ) {
    fail("unknown requestDevice limit witness did not round-trip to native ingress");
  }

  const deviceLimits = Object.freeze(Object.fromEntries(
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames.map(
      (name, index) => [name, index + 1],
    ),
  ));
  const deviceResultBase = Object.freeze({
    kind: "device",
    objectId: "81",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
    queueObjectId: "82",
    queueObjectGeneration: "3",
    features: Object.freeze(["shader-f16", "timestamp-query"]),
    limits: deviceLimits,
  });
  const liveDeviceResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      requestDeviceOperationId,
      { ...deviceResultBase, diagnosticMessage: "" },
    );
  const detachedDeviceResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      requestDeviceOperationId,
      {
        ...deviceResultBase,
        diagnosticMessage: "native semantic service selected an already-lost device",
      },
    );
  const requestDeviceEventBase = Object.freeze({
    kind: 1,
    operationId: requestDeviceRoute.wireId,
    resultKind: 3,
    status: 0,
    ingressLogicalDeviceId: "0",
    ingressLogicalDeviceGeneration: "0",
    ingressProviderGeneration: "0",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
    operationProviderGeneration: "9",
    capturedScopeId: "0",
    adapterOrdinal: "1",
    deviceIngressOrdinal: "0",
    queueIngressOrdinal: "0",
    receiverKind: 2,
    receiverFlags: 0,
    receiverId: "70",
    receiverGeneration: "1",
    targetKind: 0,
    targetFlags: 0,
    targetId: "0",
    targetGeneration: "0",
  });
  const liveDeviceEvent = Object.freeze({
    ...requestDeviceEventBase,
    providerAdmission: 1,
    physicalSequence: "6",
    deviceTransition: 1,
    detachedAlreadyLost: false,
    payload: liveDeviceResult,
  });
  const detachedNotAdmittedEvent = Object.freeze({
    ...requestDeviceEventBase,
    providerAdmission: 0,
    physicalSequence: "0",
    deviceTransition: 2,
    detachedAlreadyLost: true,
    lossReason: 1,
    backendClass: 0,
    payload: detachedDeviceResult,
  });
  const detachedAdmittedEvent = Object.freeze({
    ...detachedNotAdmittedEvent,
    providerAdmission: 1,
    physicalSequence: "7",
  });
  const decodedLiveDevice =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      requestDeviceOperationId,
      liveDeviceEvent,
    );
  const decodedDetachedNotAdmitted =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      requestDeviceOperationId,
      detachedNotAdmittedEvent,
    );
  const decodedDetachedAdmitted =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      requestDeviceOperationId,
      detachedAdmittedEvent,
    );
  const expectedLiveDevice = {
    kind: "object",
    object: {
      kind: "GPUDevice",
      objectId: "81",
      objectGeneration: "2",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
      features: ["shader-f16", "timestamp-query"],
      limits: deviceLimits,
      queue: { objectId: "82", objectGeneration: "3" },
      alreadyLost: undefined,
    },
  };
  const expectedDetachedDevice = {
    kind: "object",
    object: {
      ...expectedLiveDevice.object,
      alreadyLost: {
        reason: "unknown",
        message: "native semantic service selected an already-lost device",
      },
    },
  };
  if (
    canonicalJson(decodedLiveDevice) !== canonicalJson(expectedLiveDevice) ||
    canonicalJson(decodedDetachedNotAdmitted) !==
      canonicalJson(expectedDetachedDevice) ||
    canonicalJson(decodedDetachedAdmitted) !==
      canonicalJson(expectedDetachedDevice)
  ) {
    fail("requestDevice generated results do not preserve transition provenance");
  }

  const requestDeviceCarrierProjection = (
    providerAdmission,
    physicalSequence,
    deviceTransition,
  ) => ({
    kind: 1,
    record: {
      operation_result: {
        result_kind: 3,
        status: 0,
        operation: {
          operation_id: requestDeviceRoute.wireId,
          operation_instance_id: "12",
          promise_id: "8",
          provider_admission: providerAdmission,
          physical_sequence: physicalSequence,
          captured_scope_id: "0",
          adapter_ordinal: "1",
          device_ingress_ordinal: "0",
          queue_ingress_ordinal: "0",
          device_transition: deviceTransition,
          ingress_device: zeroDevice,
          result_device: {
            logical_device_id: "55",
            logical_device_generation: "1",
            provider_generation: "9",
          },
          provider_generation: "9",
          receiver: {
            kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUAdapter,
            flags: 0,
            object_id: "70",
            object_generation: "1",
          },
          target: requestCarrier.target,
        },
      },
    },
  });

  const createBindGroupRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createBindGroupOperationId,
  );
  const createBindGroupRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === createBindGroupRoute?.serviceArgumentCodec,
    );
  const createBindGroupCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) => candidate.tag === createBindGroupRoute?.serviceCompletionCodec,
    );
  const createBindGroupNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createBindGroupOperationId,
    );
  const bindGroupEvidence =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.typeGpuBindGroupWorkloadEvidence;
  if (
    !createBindGroupRoute ||
    !createBindGroupRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createBindGroupRequestCodec.nativeProgramPrerequisitesRepresented ||
    createBindGroupRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createBindGroupCompletionCodec ||
    !createBindGroupNativeRoute ||
    createBindGroupNativeRoute.request.catalog.wireTag !==
      createBindGroupRequestCodec.wireTag ||
    createBindGroupNativeRoute.completion.catalog.wireTag !==
      createBindGroupCompletionCodec.wireTag ||
    bindGroupEvidence.callCount !== 18 ||
    bindGroupEvidence.maximumEntriesPerDescriptor !== 5 ||
    bindGroupEvidence.maximumLabelUtf8Bytes !== 57 ||
    bindGroupEvidence.acceptedWitnesses.length !== 18
  ) {
    fail(
      "GPUDevice.createBindGroup native codegen program or authenticated full witness evidence is incomplete",
    );
  }
  const createBindGroupReceiver = Object.freeze({
    kind: "GPUDevice",
    objectId: "80",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const bindGroupBrands = new WeakMap();
  const bindGroupReference = (kind, objectId, objectGeneration = "1") => Object.freeze({
    kind,
    objectId: String(objectId),
    objectGeneration: String(objectGeneration),
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const bindGroupBrand = (kind, objectId, objectGeneration = "1") => {
    const object = {};
    bindGroupBrands.set(
      object,
      bindGroupReference(kind, objectId, objectGeneration),
    );
    return Object.freeze(object);
  };
  const bindGroupWrapperAccess = Object.freeze({
    referenceIfBranded(value, expectedKind) {
      const reference = value && typeof value === "object"
        ? bindGroupBrands.get(value)
        : undefined;
      if (!reference) return undefined;
      if (expectedKind && reference.kind !== expectedKind) {
        throw new TypeError("wrong WebGPU object brand");
      }
      return reference;
    },
    reference(value, expectedKind) {
      const reference = value && typeof value === "object"
        ? bindGroupBrands.get(value)
        : undefined;
      if (!reference || (expectedKind && reference.kind !== expectedKind)) {
        throw new TypeError("wrong WebGPU object brand");
      }
      return reference;
    },
  });
  const createBindGroupInput = (convertedArguments, target) => Object.freeze({
    operationId: createBindGroupOperationId,
    wireId: createBindGroupRoute.wireId,
    convertedArguments,
    receiver: createBindGroupReceiver,
    target,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const dependencyRetentionTerminalUnwinds = Object.freeze({
    "operation-success": 1,
    "provider-failure": 1,
    "device-loss": 1,
    cancellation: 1,
    "pre-admission-rollback": 1,
  });
  const createBindGroupWorkloadVectors = bindGroupEvidence.acceptedWitnesses.map(
    (witness, callIndex) => {
      if (
        sha256(Buffer.from(witness.convertedDescriptorCanonicalJson, "utf8")) !==
          witness.convertedDescriptorSha256 ||
        sha256(Buffer.from(witness.joinedCanonicalJson, "utf8")) !==
          witness.joinedSha256 ||
        sha256(Buffer.from(witness.witnessCanonicalJson, "utf8")) !==
          witness.witnessSha256
      ) {
        fail(`${witness.id} bind-group full witness digest drifted`);
      }
      const convertedWitness = JSON.parse(
        witness.convertedDescriptorCanonicalJson,
      );
      const joinedWitness = JSON.parse(witness.joinedCanonicalJson);
      const fullWitness = JSON.parse(witness.witnessCanonicalJson);
      if (
        canonicalJson({ convertedDescriptor: convertedWitness, joined: joinedWitness }) !==
          witness.witnessCanonicalJson ||
        canonicalJson(fullWitness) !== witness.witnessCanonicalJson ||
        joinedWitness.workloadId !== witness.workloadId ||
        joinedWitness.sequence !== witness.evidenceSequence ||
        joinedWitness.traceOrdinal !== witness.evidenceTraceOrdinal ||
        convertedWitness.layout.creationSequence !==
          joinedWitness.layoutCreationSequence
      ) {
        fail(`${witness.id} bind-group full witness identity drifted`);
      }
      const layoutObjectId = 1_000 + callIndex;
      const target = bindGroupReference("GPUBindGroup", 2_000 + callIndex, "2");
      const layoutGeneration = String(
        1 + (convertedWitness.layout.creationSequence % 3),
      );
      const layoutObject = bindGroupBrand(
        "GPUBindGroupLayout",
        layoutObjectId,
        layoutGeneration,
      );
      const layoutReference = bindGroupReference(
        "GPUBindGroupLayout",
        layoutObjectId,
        layoutGeneration,
      );
      const expectedEntries = [];
      const provenanceEntries = [];
      const retainedDependencies = [layoutReference];
      const rawEntries = convertedWitness.entries.map((convertedEntry, entryIndex) => {
        const joinedEntry = joinedWitness.entries[entryIndex];
        if (
          joinedEntry.binding !== convertedEntry.binding ||
          joinedEntry.resourceKind !== convertedEntry.resource.resourceKind
        ) {
          fail(`${witness.id} bind-group converted/joined entry drifted`);
        }
        const objectId = 3_000 + callIndex * 10 + entryIndex;
        if (joinedEntry.resourceKind === "GPUBufferBinding") {
          const creatorSequence = convertedEntry.resource.buffer.creationSequence;
          if (creatorSequence !== joinedEntry.bufferCreationSequence) {
            fail(`${witness.id} bind-group buffer creator sequence drifted`);
          }
          const objectGeneration = String(1 + (creatorSequence % 3));
          const bufferObject = bindGroupBrand(
            "GPUBuffer",
            objectId,
            objectGeneration,
          );
          const bufferReference = bindGroupReference(
            "GPUBuffer",
            objectId,
            objectGeneration,
          );
          const hasSize = Object.hasOwn(convertedEntry.resource, "size");
          if (hasSize !== Object.hasOwn(joinedEntry, "size")) {
            fail(`${witness.id} bind-group optional buffer size presence drifted`);
          }
          const expectedResource = Object.freeze({
            resourceKind: "GPUBufferBinding",
            buffer: bufferReference,
            offset: convertedEntry.resource.offset,
            ...(hasSize ? { size: convertedEntry.resource.size } : {}),
          });
          expectedEntries.push(Object.freeze({
            binding: convertedEntry.binding,
            resource: expectedResource,
          }));
          provenanceEntries.push(Object.freeze({
            binding: convertedEntry.binding,
            resourceKind: "GPUBufferBinding",
            creatorSequence,
            runtimeReference: bufferReference,
            creatorDescriptor: joinedEntry.bufferDescriptor,
            optionalSizePresent: hasSize,
          }));
          retainedDependencies.push(bufferReference);
          return Object.freeze({
            binding: convertedEntry.binding,
            resource: Object.freeze({
              buffer: bufferObject,
              offset: convertedEntry.resource.offset,
              ...(hasSize ? { size: convertedEntry.resource.size } : {}),
            }),
          });
        }
        const kind = joinedEntry.resourceKind;
        const creatorSequence = convertedEntry.resource.reference.creationSequence;
        const expectedCreatorSequence = kind === "GPUSampler"
          ? joinedEntry.samplerCreationSequence
          : joinedEntry.viewCreationSequence;
        if (creatorSequence !== expectedCreatorSequence) {
          fail(`${witness.id} bind-group resource creator sequence drifted`);
        }
        const objectGeneration = String(1 + (creatorSequence % 3));
        const resourceObject = bindGroupBrand(kind, objectId, objectGeneration);
        const resourceReference = bindGroupReference(
          kind,
          objectId,
          objectGeneration,
        );
        const parent = kind === "GPUTextureView"
          ? (() => {
              const parentSequence = joinedEntry.textureOrigin.creationSequence;
              if (
                convertedEntry.resource.reference.textureCreationSequence !==
                  parentSequence ||
                canonicalJson(convertedEntry.resource.reference.textureOrigin) !==
                  canonicalJson(joinedEntry.textureOrigin)
              ) {
                fail(`${witness.id} bind-group texture parent/origin drifted`);
              }
              const parentReference = bindGroupReference(
                "GPUTexture",
                6_000 + callIndex * 10 + entryIndex,
                String(1 + (parentSequence % 3)),
              );
              retainedDependencies.push(parentReference);
              return Object.freeze({
                creatorSequence: parentSequence,
                runtimeReference: parentReference,
                descriptor: joinedEntry.parentTexture,
                origin: joinedEntry.textureOrigin,
              });
            })()
          : undefined;
        expectedEntries.push(Object.freeze({
          binding: convertedEntry.binding,
          resource: Object.freeze({
            resourceKind: kind,
            reference: resourceReference,
          }),
        }));
        provenanceEntries.push(Object.freeze({
          binding: convertedEntry.binding,
          resourceKind: kind,
          creatorSequence,
          runtimeReference: resourceReference,
          ...(kind === "GPUSampler"
            ? {
                creatorDescriptor: joinedEntry.samplerDescriptor,
                samplerClass: Object.freeze({
                  isFiltering: joinedEntry.isFiltering,
                  isComparison: joinedEntry.isComparison,
                }),
              }
            : {
                creatorDescriptor: joinedEntry.viewDescriptor,
                parent,
              }),
        }));
        retainedDependencies.push(resourceReference);
        return Object.freeze({
          binding: convertedEntry.binding,
          resource: resourceObject,
        });
      });
      const rawDescriptor = Object.freeze({
        label: convertedWitness.label,
        entries: Object.freeze(rawEntries),
        layout: layoutObject,
      });
      const expectedConvertedArguments = Object.freeze({
        label: convertedWitness.label,
        entries: Object.freeze(expectedEntries),
        layout: layoutReference,
      });
      const convertedArguments =
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          createBindGroupOperationId,
          [rawDescriptor],
          bindGroupWrapperAccess,
        );
      if (
        canonicalJson(convertedArguments) !==
          canonicalJson(expectedConvertedArguments)
      ) {
        fail(`${witness.id} bind-group WebIDL conversion drifted`);
      }
      const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        createBindGroupInput(convertedArguments, target),
      );
      const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        bytes,
      );
      if (
        canonicalJson(inspected.convertedArguments) !==
          canonicalJson(expectedConvertedArguments)
      ) {
        fail(`${witness.id} bind-group request did not round-trip`);
      }
      const semanticProvenanceWitness = Object.freeze({
        sourceDevice: createBindGroupReceiver,
        serviceDerivedCreationAccount: Object.freeze({
          accountId: String(7_000 + callIndex),
          accountGeneration: "3",
          state: "LIVE",
          source: "authenticated-device-table-never-wrapper-payload",
        }),
        serviceDerivedAggregateEnvelope: Object.freeze({
          envelopeId: String(8_000 + callIndex),
          envelopeGeneration: "4",
          state: "LIVE",
          source: "authenticated-account-arbiter-never-wrapper-payload",
        }),
        layout: Object.freeze({
          creatorSequence: convertedWitness.layout.creationSequence,
          runtimeReference: layoutReference,
          creatorDescriptor: joinedWitness.layoutDescriptor,
        }),
        resources: Object.freeze(provenanceEntries),
        target,
        dependencyRetention: Object.freeze({
          dependencies: Object.freeze(retainedDependencies),
          commitStep:
            "commit-bind-group-layout-and-resource-dependency-retention-before-provider-admission",
          providerAdmissionStep:
            "reserve-bind-group-provider-request-completion-and-physical-sequence",
          unwindStep:
            "arm-exactly-once-terminal-unwind-for-bind-group-dependency-retention",
          terminalUnwindCounts: dependencyRetentionTerminalUnwinds,
        }),
      });
      return Object.freeze({
        id: `create-bind-group-workload-call-${String(callIndex + 1).padStart(2, "0")}`,
        kind: "request",
        operationId: createBindGroupOperationId,
        bytesHex: toHex(bytes),
        expected: Object.freeze({
          receiver: createBindGroupReceiver,
          target,
          capturedScopeId: "2",
          adapterOrdinal: "0",
          deviceIngressOrdinal: "3",
          queueIngressOrdinal: "0",
          sealedLocalTimeline: Object.freeze([]),
          convertedArguments: expectedConvertedArguments,
          semanticProvenanceWitness,
        }),
        workloadEvidence: Object.freeze({
          id: witness.id,
          workloadId: witness.workloadId,
          evidenceSequence: witness.evidenceSequence,
          evidenceTraceOrdinal: witness.evidenceTraceOrdinal,
          convertedDescriptorSha256: witness.convertedDescriptorSha256,
          joinedSha256: witness.joinedSha256,
          witnessSha256: witness.witnessSha256,
          convertedDescriptorWitness: convertedWitness,
          joinedWitness,
        }),
      });
    },
  );
  const createBindGroupCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createBindGroupOperationId,
      { kind: "none" },
    );
  if (createBindGroupCompletion.byteLength !== 0) {
    fail("GPUDevice.createBindGroup terminal receipt must have empty bytes");
  }
  const firstBindGroupVector = createBindGroupWorkloadVectors[0];
  const firstBindGroupConverted = firstBindGroupVector.expected.convertedArguments;
  const firstBindGroupTarget = firstBindGroupVector.expected.target;
  const bindGroupVectorWith = (predicate, label) => {
    const vector = createBindGroupWorkloadVectors.find((candidate) =>
      candidate.workloadEvidence.joinedWitness.entries.some(predicate)
    );
    if (!vector) fail(`bind-group corpus lacks ${label} witness`);
    return vector;
  };
  const bufferBindGroupVector = bindGroupVectorWith(
    (entry) => entry.resourceKind === "GPUBufferBinding",
    "buffer",
  );
  const samplerBindGroupVector = bindGroupVectorWith(
    (entry) => entry.resourceKind === "GPUSampler",
    "sampler",
  );
  const sampledTextureBindGroupVector = bindGroupVectorWith(
    (entry) => entry.resourceKind === "GPUTextureView" && entry.layout.texture,
    "sampled texture",
  );
  const storageTextureBindGroupVector = bindGroupVectorWith(
    (entry) => entry.resourceKind === "GPUTextureView" &&
      entry.layout.storageTexture,
    "storage texture",
  );
  const bindGroupStructuralRejection = (id, mutate, expectedErrorIncludes) => {
    const converted = structuredClone(firstBindGroupConverted);
    mutate(converted);
    let errorMessage = "";
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        createBindGroupInput(converted, firstBindGroupTarget),
      );
    } catch (error) {
      errorMessage = String(error?.message ?? error);
    }
    if (!errorMessage.includes(expectedErrorIncludes)) {
      fail(`${id} did not reject at the structural boundary: ${errorMessage}`);
    }
    return Object.freeze({
      id,
      kind: "structural-rejection",
      operationId: createBindGroupOperationId,
      structuralBoundary: "generated-native-request-encoder-before-bytes",
      expected: Object.freeze({
        errorIncludes: expectedErrorIncludes,
        encodedByteCount: 0,
        providerTokenCount: 0,
        physicalSequenceCount: 0,
      }),
    });
  };
  const createBindGroupStructuralRejections = Object.freeze([
    bindGroupStructuralRejection(
      "create-bind-group-missing-layout-structurally-rejected",
      (descriptor) => { delete descriptor.layout; },
      "canonical descriptor",
    ),
    bindGroupStructuralRejection(
      "create-bind-group-unknown-member-structurally-rejected",
      (descriptor) => { descriptor.unknown = true; },
      "canonical descriptor",
    ),
    bindGroupStructuralRejection(
      "create-bind-group-wrong-layout-kind-structurally-rejected",
      (descriptor) => { descriptor.layout.kind = "GPUBuffer"; },
      "layout has an invalid",
    ),
    bindGroupStructuralRejection(
      "create-bind-group-entry-missing-resource-structurally-rejected",
      (descriptor) => { delete descriptor.entries[0].resource; },
      "closed dictionary",
    ),
    bindGroupStructuralRejection(
      "create-bind-group-invalid-buffer-range-structurally-rejected",
      (descriptor) => {
        descriptor.entries = [{
          binding: 0,
          resource: {
            resourceKind: "GPUBufferBinding",
            buffer: bindGroupReference("GPUBuffer", 9_999),
            offset: -1,
          },
        }];
      },
      "buffer entry",
    ),
    bindGroupStructuralRejection(
      "create-bind-group-unknown-resource-kind-structurally-rejected",
      (descriptor) => { descriptor.entries[0].resource.resourceKind = "GPUQuerySet"; },
      "resource entry",
    ),
  ]);
  const semanticBindGroupDescriptor = (id, convertedArguments, predicate) => {
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      createBindGroupInput(convertedArguments, firstBindGroupTarget),
    );
    return Object.freeze({
      id,
      kind: "semantic-rejection",
      operationId: createBindGroupOperationId,
      semanticTerminalId: "later-predicate-rejection",
      firstFailingPredicate: predicate,
      providerTokenCount: 0,
      physicalSequenceCount: 0,
      bytesHex: toHex(bytes),
      expected: Object.freeze({ convertedArguments }),
    });
  };
  const semanticBindGroupStateMutation = (id, vector, mutation, predicate) =>
    Object.freeze({
      id,
      kind: "semantic-rejection",
      operationId: createBindGroupOperationId,
      semanticTerminalId: "later-predicate-rejection",
      firstFailingPredicate: predicate,
      providerTokenCount: 0,
      physicalSequenceCount: 0,
      bytesHex: vector.bytesHex,
      expected: Object.freeze({
        convertedArguments: vector.expected.convertedArguments,
        authenticatedStateMutation: Object.freeze(mutation),
        dependencyRetentionUnwindCount: 1,
      }),
    });
  const sampledTextureEntry = sampledTextureBindGroupVector.workloadEvidence
    .joinedWitness.entries.find((entry) => entry.resourceKind === "GPUTextureView");
  const samplerEntry = samplerBindGroupVector.workloadEvidence.joinedWitness.entries
    .find((entry) => entry.resourceKind === "GPUSampler");
  const storageTextureEntry = storageTextureBindGroupVector.workloadEvidence
    .joinedWitness.entries.find((entry) => entry.layout.storageTexture);
  const createBindGroupSemanticRejections = Object.freeze([
    semanticBindGroupDescriptor(
      "create-bind-group-empty-entries-rejected",
      Object.freeze({ ...firstBindGroupConverted, entries: Object.freeze([]) }),
      "validate-bind-group-entry-layout-cardinality-and-exact-binding-join",
    ),
    semanticBindGroupDescriptor(
      "create-bind-group-overlong-label-rejected",
      Object.freeze({ ...firstBindGroupConverted, label: "x".repeat(58) }),
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupDescriptor(
      "create-bind-group-unreviewed-range-rejected",
      Object.freeze({
        ...bufferBindGroupVector.expected.convertedArguments,
        entries: Object.freeze(bufferBindGroupVector.expected.convertedArguments.entries.map(
          (entry, index) => index === 0 &&
              entry.resource.resourceKind === "GPUBufferBinding"
            ? Object.freeze({
              ...entry,
              resource: Object.freeze({ ...entry.resource, offset: 4 }),
            })
            : entry,
        )),
      }),
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-sampler-class-mutation-rejected",
      samplerBindGroupVector,
      {
        binding: samplerEntry.binding,
        field: "samplerClass.isFiltering",
        from: samplerEntry.isFiltering,
        to: !samplerEntry.isFiltering,
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-texture-format-mutation-rejected",
      sampledTextureBindGroupVector,
      {
        binding: sampledTextureEntry.binding,
        field: "parentTexture.format",
        from: sampledTextureEntry.parentTexture.format,
        to: "rgba8sint",
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-texture-dimension-mutation-rejected",
      sampledTextureBindGroupVector,
      {
        binding: sampledTextureEntry.binding,
        field: "parentTexture.dimension",
        from: sampledTextureEntry.parentTexture.dimension,
        to: "3d",
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-texture-sample-type-mutation-rejected",
      sampledTextureBindGroupVector,
      {
        binding: sampledTextureEntry.binding,
        field: "layout.texture.sampleType",
        from: sampledTextureEntry.layout.texture.sampleType,
        to: "sint",
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-texture-usage-mutation-rejected",
      sampledTextureBindGroupVector,
      {
        binding: sampledTextureEntry.binding,
        field: "parentTexture.usage",
        from: sampledTextureEntry.parentTexture.usage,
        to: sampledTextureEntry.parentTexture.usage & ~4,
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-texture-sample-count-mutation-rejected",
      sampledTextureBindGroupVector,
      {
        binding: sampledTextureEntry.binding,
        field: "parentTexture.sampleCount",
        from: sampledTextureEntry.parentTexture.sampleCount,
        to: 4,
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-storage-compatibility-mutation-rejected",
      storageTextureBindGroupVector,
      {
        binding: storageTextureEntry.binding,
        field: "parentTexture.format",
        from: storageTextureEntry.parentTexture.format,
        to: "rgba8unorm",
      },
      "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
    ),
    semanticBindGroupStateMutation(
      "create-bind-group-dependency-retention-reservation-rejected",
      firstBindGroupVector,
      {
        field: "dependencyRetention.commit",
        from: "all-dependencies-reserved",
        to: "resource-credit-exhausted",
      },
      "commit-bind-group-layout-and-resource-dependency-retention-before-provider-admission",
    ),
  ]);

  const createBindGroupLayoutRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createBindGroupLayoutOperationId,
  );
  const createBindGroupLayoutRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createBindGroupLayoutRoute?.serviceArgumentCodec,
    );
  const createBindGroupLayoutCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createBindGroupLayoutRoute?.serviceCompletionCodec,
    );
  const createBindGroupLayoutNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createBindGroupLayoutOperationId,
    );
  if (
    !createBindGroupLayoutRoute ||
    !createBindGroupLayoutRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createBindGroupLayoutRequestCodec.nativeProgramPrerequisitesRepresented ||
    createBindGroupLayoutRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createBindGroupLayoutCompletionCodec ||
    !createBindGroupLayoutNativeRoute ||
    createBindGroupLayoutNativeRoute.request.catalog.wireTag !==
      createBindGroupLayoutRequestCodec.wireTag ||
    createBindGroupLayoutNativeRoute.completion.catalog.wireTag !==
      createBindGroupLayoutCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createBindGroupLayout native codegen program is not executable from authenticated inputs",
    );
  }
  const createBindGroupLayoutReceiver = Object.freeze({
    kind: "GPUDevice",
    objectId: "80",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const createBindGroupLayoutTarget = Object.freeze({
    kind: "GPUBindGroupLayout",
    objectId: "86",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const createBindGroupLayoutDescriptor = Object.freeze({
    label: "corpus-layout",
    entries: Object.freeze([
      Object.freeze({
        binding: 0,
        visibility: 7,
        buffer: Object.freeze({}),
      }),
      Object.freeze({
        binding: 1,
        visibility: 2,
        sampler: Object.freeze({ type: "non-filtering" }),
      }),
      Object.freeze({
        binding: 2,
        visibility: 6,
        texture: Object.freeze({}),
      }),
      Object.freeze({
        binding: 3,
        visibility: 7,
        storageTexture: Object.freeze({ format: "rgba16float" }),
      }),
    ]),
  });
  const expectedCreateBindGroupLayoutArguments = Object.freeze({
    label: "corpus-layout",
    entries: Object.freeze([
      Object.freeze({
        binding: 0,
        visibility: 7,
        buffer: Object.freeze({
          type: "uniform",
          hasDynamicOffset: false,
          minBindingSize: 0,
        }),
      }),
      Object.freeze({
        binding: 1,
        visibility: 2,
        sampler: Object.freeze({ type: "non-filtering" }),
      }),
      Object.freeze({
        binding: 2,
        visibility: 6,
        texture: Object.freeze({
          sampleType: "float",
          viewDimension: "2d",
          multisampled: false,
        }),
      }),
      Object.freeze({
        binding: 3,
        visibility: 7,
        storageTexture: Object.freeze({
          access: "write-only",
          format: "rgba16float",
          viewDimension: "2d",
        }),
      }),
    ]),
  });
  const convertedCreateBindGroupLayoutArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      createBindGroupLayoutOperationId,
      [createBindGroupLayoutDescriptor],
      wrapperAccess,
    );
  if (
    canonicalJson(convertedCreateBindGroupLayoutArguments) !==
      canonicalJson(expectedCreateBindGroupLayoutArguments)
  ) {
    fail("GPUDevice.createBindGroupLayout descriptor projection drifted");
  }
  const createBindGroupLayoutInput = (convertedArguments) => Object.freeze({
    operationId: createBindGroupLayoutOperationId,
    wireId: createBindGroupLayoutRoute.wireId,
    convertedArguments,
    receiver: createBindGroupLayoutReceiver,
    target: createBindGroupLayoutTarget,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const createBindGroupLayoutBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      createBindGroupLayoutInput(convertedCreateBindGroupLayoutArguments),
    );
  const expectedCreateBindGroupLayoutRequest = Object.freeze({
    receiver: createBindGroupLayoutReceiver,
    target: createBindGroupLayoutTarget,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
    convertedArguments: expectedCreateBindGroupLayoutArguments,
  });
  const inspectedCreateBindGroupLayout =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      createBindGroupLayoutBytes,
    );
  if (
    canonicalJson(inspectedCreateBindGroupLayout) !== canonicalJson({
      operationId: createBindGroupLayoutOperationId,
      codec: createBindGroupLayoutRequestCodec.tag,
      ...expectedCreateBindGroupLayoutRequest,
    })
  ) {
    fail(
      "GPUDevice.createBindGroupLayout generated request does not round-trip through inspection",
    );
  }
  const createBindGroupLayoutCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createBindGroupLayoutOperationId,
      { kind: "none" },
    );
  if (createBindGroupLayoutCompletion.byteLength !== 0) {
    fail(
      "GPUDevice.createBindGroupLayout terminal receipt must have an empty completion payload",
    );
  }
  const createBindGroupLayoutRequestCarrier = Object.freeze({
    operation_id: createBindGroupLayoutRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "15",
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUBindGroupLayout,
      flags: 0,
      object_id: "86",
      object_generation: "1",
    }),
  });
  const createBindGroupLayoutCompletionCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createBindGroupLayoutRoute.wireId,
          operation_instance_id: "15",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "10",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "3",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: createBindGroupLayoutRequestCarrier.ingress_device,
          result_device: createBindGroupLayoutRequestCarrier.ingress_device,
          provider_generation: "9",
          receiver: createBindGroupLayoutRequestCarrier.receiver,
          target: createBindGroupLayoutRequestCarrier.target,
        }),
      }),
    }),
  });

  const bindGroupLayoutRejectionVector = (
    id,
    rawDescriptor,
    expectedErrorIncludes,
  ) => {
    const convertedArguments =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        createBindGroupLayoutOperationId,
        [rawDescriptor],
        wrapperAccess,
      );
    const requestBytes =
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        createBindGroupLayoutInput(convertedArguments),
      );
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      requestBytes,
    );
    if (
      canonicalJson(inspected.convertedArguments) !==
        canonicalJson(convertedArguments)
    ) {
      fail(`${id} did not reach the post-decode semantic boundary intact`);
    }
    return Object.freeze({
      id,
      kind: "semantic-rejection",
      operationId: createBindGroupLayoutOperationId,
      semanticTerminalId: "later-predicate-rejection",
      errorTiming: "device-timeline",
      providerTokenCount: 0,
      physicalSequenceCount: 0,
      rawDescriptor,
      convertedArguments,
      bytesHex: toHex(requestBytes),
      expected: Object.freeze({
        codegenDisposition: "encoded-for-post-decode-semantic-validation",
        semanticErrorIncludes: expectedErrorIncludes,
      }),
    });
  };
  const bindGroupLayoutRejectionVectors = Object.freeze([
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-empty-entries-rejected",
      { entries: [] },
      "exceeds the reviewed workload bounds",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-sixth-entry-rejected",
      {
        entries: [0, 1, 2, 3, 4, 5].map((binding) => ({
          binding,
          visibility: 7,
          buffer: {},
        })),
      },
      "exceeds the reviewed workload bounds",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-binding-gap-rejected",
      {
        entries: [
          { binding: 0, visibility: 7, buffer: {} },
          { binding: 2, visibility: 7, buffer: {} },
        ],
      },
      "violates binding, visibility, or resource closure",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-duplicate-binding-rejected",
      {
        entries: [
          { binding: 0, visibility: 7, buffer: {} },
          { binding: 0, visibility: 7, buffer: {} },
        ],
      },
      "violates binding, visibility, or resource closure",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-visibility-rejected",
      {
        entries: [{ binding: 0, visibility: 1, buffer: {} }],
      },
      "violates binding, visibility, or resource closure",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-comparison-sampler-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          sampler: { type: "comparison" },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-external-texture-rejected",
      {
        entries: [{ binding: 0, visibility: 7, externalTexture: {} }],
      },
      "violates binding, visibility, or resource closure",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-dynamic-buffer-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          buffer: { hasDynamicOffset: true, minBindingSize: 1 },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-alternate-texture-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          texture: {
            sampleType: "depth",
            viewDimension: "cube",
            multisampled: true,
          },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-alternate-storage-texture-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          storageTexture: {
            access: "read-only",
            format: "rgba8unorm",
            viewDimension: "3d",
          },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-storage-cube-dimension-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          storageTexture: {
            access: "write-only",
            format: "rgba16float",
            viewDimension: "cube",
          },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-storage-cube-array-dimension-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          storageTexture: {
            access: "write-only",
            format: "astc-12x12-unorm-srgb",
            viewDimension: "cube-array",
          },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-max-safe-buffer-size-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          buffer: { minBindingSize: Number.MAX_SAFE_INTEGER },
        }],
      },
      "outside the pinned TypeGPU resource subset",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-multiple-resource-members-rejected",
      {
        entries: [{
          binding: 0,
          visibility: 7,
          buffer: {},
          sampler: {},
        }],
      },
      "violates binding, visibility, or resource closure",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-zero-resource-members-rejected",
      {
        entries: [{ binding: 0, visibility: 7 }],
      },
      "violates binding, visibility, or resource closure",
    ),
    bindGroupLayoutRejectionVector(
      "create-bind-group-layout-overlong-label-rejected",
      {
        label: "💡".repeat(15),
        entries: [{ binding: 0, visibility: 7, buffer: {} }],
      },
      "exceeds the reviewed workload bounds",
    ),
  ]);

  const createBufferRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createBufferOperationId,
  );
  const createBufferRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === createBufferRoute?.serviceArgumentCodec,
    );
  const createBufferCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) => candidate.tag === createBufferRoute?.serviceCompletionCodec,
    );
  const createBufferNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createBufferOperationId,
    );
  if (
    !createBufferRoute ||
    !createBufferRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createBufferRequestCodec.nativeProgramPrerequisitesRepresented ||
    createBufferRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createBufferCompletionCodec ||
    !createBufferNativeRoute ||
    createBufferNativeRoute.request.catalog.wireTag !== 17 ||
    createBufferNativeRoute.request.catalog.wireTag !==
      createBufferRequestCodec.wireTag ||
    createBufferNativeRoute.completion.catalog.wireTag !==
      createBufferCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createBuffer native codegen program is not executable from authenticated inputs",
    );
  }
  const createBufferReceiver = createBindGroupLayoutReceiver;
  const reviewedBufferSizes = Object.freeze([
    22_020_096,
    22_020_096,
    2_621_440,
    2_621_440,
    262_144,
    4,
    4,
    4,
    4,
    12,
    12,
    12,
    12,
    12,
    16,
    16,
    72,
    72,
    72,
    128,
    136,
  ]);
  const reviewedBufferUsages = Object.freeze([9, 76, 140, 172]);
  const reviewedBufferRawDescriptors = Object.freeze(
    reviewedBufferSizes.map((size, index) => Object.freeze({
      label: index === 0
        ? "typegpu-buffer-max-21"
        : `typegpu-buffer-${String(index + 1).padStart(2, "0")}`,
      ...(index % 3 === 0
        ? { mappedAtCreation: true }
        : index % 3 === 1
          ? { mappedAtCreation: false }
          : {}),
      size,
      usage: reviewedBufferUsages[index % reviewedBufferUsages.length],
    })),
  );
  if (
    reviewedBufferRawDescriptors.length !== 21 ||
    reviewedBufferSizes.reduce((sum, size) => sum + size, 0) !== 49_545_804 ||
    canonicalJson([...new Set(reviewedBufferSizes)].sort((a, b) => a - b)) !==
      canonicalJson([4, 12, 16, 72, 128, 136, 262144, 2621440, 22020096]) ||
    Math.max(...reviewedBufferRawDescriptors.map(
      (descriptor) => Buffer.byteLength(descriptor.label, "utf8"),
    )) !== 21
  ) {
    fail("GPUDevice.createBuffer reviewed 21-call workload evidence drifted");
  }
  const createBufferTarget = (index) => Object.freeze({
    kind: "GPUBuffer",
    objectId: String(87 + index),
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const createBufferInput = (convertedArguments, index = 0) => Object.freeze({
    operationId: createBufferOperationId,
    wireId: createBufferRoute.wireId,
    convertedArguments,
    receiver: createBufferReceiver,
    target: createBufferTarget(index),
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: String(4 + index),
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const createBufferRequestCarrier = (index) => Object.freeze({
    operation_id: createBufferRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: String(16 + index),
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: String(4 + index),
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUBuffer,
      flags: 0,
      object_id: String(87 + index),
      object_generation: "1",
    }),
  });
  const createBufferWorkloadVectors = Object.freeze(
    reviewedBufferRawDescriptors.map((rawDescriptor, index) => {
      const convertedArguments =
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          createBufferOperationId,
          [rawDescriptor],
          wrapperAccess,
        );
      const expectedConvertedArguments = Object.freeze({
        label: rawDescriptor.label,
        mappedAtCreation: rawDescriptor.mappedAtCreation === true,
        size: rawDescriptor.size,
        usage: rawDescriptor.usage,
      });
      if (
        canonicalJson(convertedArguments) !==
          canonicalJson(expectedConvertedArguments)
      ) {
        fail(`GPUDevice.createBuffer workload call ${index + 1} conversion drifted`);
      }
      const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(createBufferInput(convertedArguments, index));
      const expected = Object.freeze({
        receiver: createBufferReceiver,
        target: createBufferTarget(index),
        capturedScopeId: "2",
        adapterOrdinal: "0",
        deviceIngressOrdinal: String(4 + index),
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
        convertedArguments: expectedConvertedArguments,
      });
      const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(bytes);
      if (
        canonicalJson(inspected) !== canonicalJson({
          operationId: createBufferOperationId,
          codec: createBufferRequestCodec.tag,
          ...expected,
        })
      ) {
        fail(`GPUDevice.createBuffer workload call ${index + 1} round-trip drifted`);
      }
      return Object.freeze({
        id: `create-buffer-workload-call-${String(index + 1).padStart(2, "0")}`,
        kind: "request",
        carrierProjection: createBufferRequestCarrier(index),
        trust:
          "untrusted-wrapper-record-prefix-and-descriptor-join-only-never-authority",
        semanticOwner: "native-semantic-service-before-provider-admission",
        bytesHex: toHex(bytes),
        expected,
        accountingEvidence: Object.freeze({
          resourceBytes: rawDescriptor.size,
          mappedExtentBytes:
            rawDescriptor.mappedAtCreation === true ? rawDescriptor.size : 0,
          stagingBytes: 0,
          backingChargeRule:
            "mapped-extent-is-observability-only-and-does-not-double-charge-resource-bytes",
        }),
      });
    }),
  );
  const createBufferCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createBufferOperationId,
      { kind: "none" },
    );
  if (createBufferCompletion.byteLength !== 0) {
    fail("GPUDevice.createBuffer terminal receipt must have an empty payload");
  }
  const createBufferCompletionCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createBufferRoute.wireId,
          operation_instance_id: "16",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "11",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "4",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: createBufferRequestCarrier(0).ingress_device,
          result_device: createBufferRequestCarrier(0).ingress_device,
          provider_generation: "9",
          receiver: createBufferRequestCarrier(0).receiver,
          target: createBufferRequestCarrier(0).target,
        }),
      }),
    }),
  });
  const createBufferSemanticSteps = Object.freeze(
    createBufferNativeRoute.request.semanticServiceBoundary.requiredAfterDecode,
  );
  const expectedCreateBufferSemanticSteps = Object.freeze([
    "authenticate-contiguous-sealed-local-timeline-prefix",
    "validate-current-live-device-generation",
    "validate-operation-coverage",
    "validate-authorized-live-account-and-aggregate-envelope",
    "validate-buffer-descriptor-under-reviewed-workload",
    "validate-buffer-size-under-logical-max-and-structural-ceiling",
    "validate-buffer-usage-closed-bits",
    "validate-buffer-map-usage-combination",
    "authenticate-wrapper-allocated-buffer-target-provenance",
    "validate-wrapper-allocated-buffer-target-generation",
    "reserve-buffer-table-and-dual-ledger-capacity",
    "reserve-buffer-provider-request-completion-and-physical-sequence",
    "validate-buffer-label-under-reviewed-workload",
  ]);
  if (canonicalJson(createBufferSemanticSteps) !== canonicalJson(
    expectedCreateBufferSemanticSteps,
  )) {
    fail("GPUDevice.createBuffer semantic step order drifted");
  }
  const positiveBufferVector = createBufferWorkloadVectors[19];
  const createBufferAdversarialMutations = Object.freeze([
    [
      "sealed-timeline-gap",
      "authenticate-contiguous-sealed-local-timeline-prefix",
      { sealedLocalTimelinePrefixContiguous: false },
    ],
    [
      "stale-device-generation",
      "validate-current-live-device-generation",
      { deviceGeneration: "stale" },
    ],
    [
      "coverage-absent",
      "validate-operation-coverage",
      { operationCoverageInstalled: false },
    ],
    [
      "aggregate-envelope-not-live",
      "validate-authorized-live-account-and-aggregate-envelope",
      { aggregateEnvelopeState: "CLOSED" },
    ],
    [
      "unreviewed-workload-size",
      "validate-buffer-descriptor-under-reviewed-workload",
      { descriptor: { size: 8 } },
    ],
    [
      "logical-max-below-size",
      "validate-buffer-size-under-logical-max-and-structural-ceiling",
      { logicalMaxBufferSize: 64 },
    ],
    [
      "closed-usage-mask-mismatch",
      "validate-buffer-usage-closed-bits",
      { allowedBufferUsageMask: 12 },
    ],
    [
      "illegal-map-usage-combination",
      "validate-buffer-map-usage-combination",
      { reviewedUsageSetAdds: 3, usage: 3 },
    ],
    [
      "foreign-target-provenance",
      "authenticate-wrapper-allocated-buffer-target-provenance",
      { targetLogicalDeviceId: "56" },
    ],
    [
      "stale-target-generation",
      "validate-wrapper-allocated-buffer-target-generation",
      { targetSlotGeneration: "2" },
    ],
    [
      "dual-ledger-capacity-exhausted",
      "reserve-buffer-table-and-dual-ledger-capacity",
      { aggregateEnvelopeResourceCredit: 0 },
    ],
    [
      "provider-completion-credit-exhausted",
      "reserve-buffer-provider-request-completion-and-physical-sequence",
      { completionCredit: 0 },
    ],
    [
      "overlong-label",
      "validate-buffer-label-under-reviewed-workload",
      { label: "x".repeat(44) },
    ],
  ]);
  const createBufferMutationStepIds = createBufferAdversarialMutations.map(
    ([, semanticStepId]) => semanticStepId,
  );
  if (
    new Set(createBufferMutationStepIds).size !==
      createBufferMutationStepIds.length ||
    canonicalJson(createBufferMutationStepIds) !==
      canonicalJson(createBufferSemanticSteps)
  ) {
    fail(
      "GPUDevice.createBuffer adversarial mutations must map bijectively to semantic steps",
    );
  }
  const createBufferAdversarialVectors = Object.freeze(
    createBufferAdversarialMutations.map(
      ([suffix, firstFailingSemanticStep, mutation]) => {
        const firstFailureIndex = createBufferSemanticSteps.indexOf(
          firstFailingSemanticStep,
        );
        return Object.freeze({
          id: `create-buffer-${suffix}-rejected`,
          kind: "semantic-rejection",
          operationId: createBufferOperationId,
          semanticTerminalId: "later-predicate-rejection",
          semanticStepIndex: firstFailureIndex + 1,
          firstFailingSemanticStep,
          earlierSemanticStepsMustPass: createBufferSemanticSteps.slice(
            0,
            firstFailureIndex,
          ),
          mutation,
          bytesHex: positiveBufferVector.bytesHex,
          expected: Object.freeze({
            codegenDisposition: "encoded-for-post-decode-semantic-validation",
            providerTokenCount: 0,
            physicalSequenceCount: 0,
          }),
        });
      },
    ),
  );

  const RESOURCE_SOURCE_AFFINITY_STEP =
    "authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table";

  function applyResourceSemanticMutation(baseDescriptor, mutation) {
    const descriptor = structuredClone(baseDescriptor);
    const semanticState = {
      sourceReceiverTableEntryPresent: true,
      sealedLocalTimelinePrefixContiguous: true,
      deviceGeneration: "current",
      operationCoverageInstalled: true,
      aggregateEnvelopeState: "LIVE",
      logicalMaxSamplerAnisotropy: 16,
      maxTextureDimension2D: 8192,
      allowedFormats: ["rgba8unorm", "rgba16float"],
      allowedTextureUsageMask: 0x3f,
      targetLogicalDeviceId: "55",
      targetSlotGeneration: "1",
      resourceUnitCredit: 1,
      deviceObjectTableCredit: 1,
      aggregateEnvelopeResourceCredit: Number.MAX_SAFE_INTEGER,
      providerRequestCredit: 1,
      completionCredit: 1,
    };
    const descriptorKeys = new Set([
      ...Object.keys(descriptor),
      "textureBindingViewDimension",
    ]);
    if (mutation.descriptor) Object.assign(descriptor, mutation.descriptor);
    for (const [key, value] of Object.entries(mutation)) {
      if (key === "descriptor") continue;
      if (descriptorKeys.has(key)) descriptor[key] = structuredClone(value);
      else semanticState[key] = structuredClone(value);
    }
    return { descriptor, semanticState };
  }

  function exactReviewedDescriptor(descriptor, reviewedDescriptors) {
    const encoded = canonicalJson(descriptor);
    return reviewedDescriptors.some((candidate) => canonicalJson(candidate) === encoded);
  }

  function samplerSemanticStepPasses(step, descriptor, state, reviewedDescriptors) {
    switch (step) {
      case RESOURCE_SOURCE_AFFINITY_STEP:
        return state.sourceReceiverTableEntryPresent === true;
      case "authenticate-contiguous-sealed-local-timeline-prefix":
        return state.sealedLocalTimelinePrefixContiguous === true;
      case "validate-current-live-device-generation":
        return state.deviceGeneration === "current";
      case "validate-operation-coverage":
        return state.operationCoverageInstalled === true;
      case "validate-authorized-live-account-and-aggregate-envelope":
        return state.aggregateEnvelopeState === "LIVE";
      case "validate-sampler-lod-order-and-range":
        return Number.isFinite(descriptor.lodMinClamp) &&
          Number.isFinite(descriptor.lodMaxClamp) &&
          descriptor.lodMinClamp >= 0 &&
          descriptor.lodMaxClamp >= descriptor.lodMinClamp;
      case "validate-sampler-anisotropy-and-filter-combination":
        return descriptor.maxAnisotropy >= 1 &&
          descriptor.maxAnisotropy <= state.logicalMaxSamplerAnisotropy &&
          (descriptor.maxAnisotropy === 1 ||
            (descriptor.magFilter === "linear" &&
              descriptor.minFilter === "linear" &&
              descriptor.mipmapFilter === "linear"));
      case "validate-sampler-label-under-reviewed-workload":
        return Buffer.byteLength(descriptor.label, "utf8") <= 14 &&
          ["", "nearestSampler", "linearSampler", "sampler"].includes(
            descriptor.label,
          );
      case "validate-sampler-descriptor-under-reviewed-workload":
        return exactReviewedDescriptor(descriptor, reviewedDescriptors);
      case "authenticate-wrapper-allocated-sampler-target-provenance":
        return state.targetLogicalDeviceId === "55";
      case "validate-wrapper-allocated-sampler-target-generation":
        return state.targetSlotGeneration === "1";
      case "reserve-sampler-table-and-resource-ledger-capacity":
        return state.resourceUnitCredit > 0 && state.deviceObjectTableCredit > 0;
      case "reserve-sampler-provider-request-completion-and-physical-sequence":
        return state.providerRequestCredit > 0 && state.completionCredit > 0;
      default:
        fail(`GPUDevice.createSampler has no executable semantic oracle for ${step}`);
    }
  }

  function textureSemanticStepPasses(step, descriptor, state, reviewedDescriptors) {
    switch (step) {
      case RESOURCE_SOURCE_AFFINITY_STEP:
        return state.sourceReceiverTableEntryPresent === true;
      case "authenticate-contiguous-sealed-local-timeline-prefix":
        return state.sealedLocalTimelinePrefixContiguous === true;
      case "validate-current-live-device-generation":
        return state.deviceGeneration === "current";
      case "validate-operation-coverage":
        return state.operationCoverageInstalled === true;
      case "validate-authorized-live-account-and-aggregate-envelope":
        return state.aggregateEnvelopeState === "LIVE";
      case "validate-texture-extent-under-logical-limits-and-structural-bounds":
        return descriptor.dimension === "2d" &&
          descriptor.size.width > 0 &&
          descriptor.size.height > 0 &&
          descriptor.size.depthOrArrayLayers > 0 &&
          descriptor.size.width <= state.maxTextureDimension2D &&
          descriptor.size.height <= state.maxTextureDimension2D;
      case "validate-texture-format-under-logical-capabilities":
        return state.allowedFormats.includes(descriptor.format);
      case "validate-texture-usage-closed-bits-and-format-compatibility":
        return descriptor.usage > 0 &&
          (descriptor.usage & ~state.allowedTextureUsageMask) === 0;
      case "validate-texture-mip-level-and-sample-count-bounds": {
        const maximumMipLevels =
          Math.floor(Math.log2(Math.max(descriptor.size.width, descriptor.size.height))) + 1;
        return descriptor.mipLevelCount >= 1 &&
          descriptor.mipLevelCount <= maximumMipLevels &&
          [1, 4].includes(descriptor.sampleCount) &&
          (descriptor.sampleCount === 1 || descriptor.mipLevelCount === 1);
      }
      case "validate-texture-view-formats-compatibility":
        return new Set(descriptor.viewFormats).size === descriptor.viewFormats.length &&
          descriptor.viewFormats.every((format) =>
            format === descriptor.format ||
            (descriptor.format === "rgba8unorm" && format === "rgba8unorm-srgb") ||
            (descriptor.format === "rgba8unorm-srgb" && format === "rgba8unorm")
          );
      case "validate-texture-binding-view-dimension-compatibility":
        return descriptor.textureBindingViewDimension === undefined ||
          descriptor.textureBindingViewDimension === "2d" ||
          (descriptor.textureBindingViewDimension === "2d-array" &&
            descriptor.size.depthOrArrayLayers >= 1) ||
          ((descriptor.textureBindingViewDimension === "cube" ||
            descriptor.textureBindingViewDimension === "cube-array") &&
            descriptor.size.depthOrArrayLayers >= 6 &&
            descriptor.size.depthOrArrayLayers % 6 === 0);
      case "validate-texture-label-under-reviewed-workload":
        return Buffer.byteLength(descriptor.label, "utf8") <= 13 &&
          ["", "texture", "trackTexture", "bezierTexture"].includes(
            descriptor.label,
          );
      case "validate-texture-descriptor-under-reviewed-workload":
        return exactReviewedDescriptor(descriptor, reviewedDescriptors);
      case "authenticate-wrapper-allocated-texture-target-provenance":
        return state.targetLogicalDeviceId === "55";
      case "validate-wrapper-allocated-texture-target-generation":
        return state.targetSlotGeneration === "1";
      case "compute-checked-texture-resource-bytes-and-reserve-dual-ledger-capacity":
        return state.deviceObjectTableCredit > 0 &&
          state.aggregateEnvelopeResourceCredit > 0;
      case "reserve-texture-provider-request-completion-and-physical-sequence":
        return state.providerRequestCredit > 0 && state.completionCredit > 0;
      default:
        fail(`GPUDevice.createTexture has no executable semantic oracle for ${step}`);
    }
  }

  function resourceSemanticReachabilityEvidence({
    operationId,
    semanticSteps,
    mutation,
    expectedFailureIndex,
    baseDescriptor,
    reviewedDescriptors,
  }) {
    const { descriptor, semanticState } = applyResourceSemanticMutation(
      baseDescriptor,
      mutation,
    );
    const evaluator = operationId === createSamplerOperationId
      ? samplerSemanticStepPasses
      : textureSemanticStepPasses;
    const predicateResults = semanticSteps.map((step) => Object.freeze({
      step,
      passed: evaluator(step, descriptor, semanticState, reviewedDescriptors),
    }));
    const firstFailureIndex = predicateResults.findIndex((result) => !result.passed);
    if (firstFailureIndex !== expectedFailureIndex) {
      fail(
        `${operationId} semantic mutation expected first failure ${expectedFailureIndex + 1} ` +
          `but executable oracle found ${firstFailureIndex + 1}`,
      );
    }
    return Object.freeze({
      oracle: "resource-semantic-first-failure-v1",
      evaluatedPredicateResults: Object.freeze(predicateResults),
      firstFailingSemanticStep: semanticSteps[firstFailureIndex],
      earlierSemanticStepsAllPassed: predicateResults
        .slice(0, firstFailureIndex)
        .every((result) => result.passed),
      providerTokenCount: 0,
      physicalSequenceCount: 0,
    });
  }

  function buildResourceCorpus({
    operationId,
    targetKind,
    targetKindTag,
    targetObjectIdBase,
    operationInstanceIdBase,
    rawDescriptors,
    expectedDescriptors,
    semanticMutations,
    accountingEvidence,
  }) {
    const route = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === operationId,
    );
    const requestCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === route?.serviceArgumentCodec,
    );
    const completionCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) => candidate.tag === route?.serviceCompletionCodec,
    );
    const nativeRoute =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
        (candidate) => candidate.operationId === operationId,
      );
    if (
      !route ||
      !requestCodec?.nativeProgramPrerequisitesRepresented ||
      !requestCodec.executableFromCurrentAuthenticatedInputs ||
      requestCodec.unavailableSemanticFields.length !== 0 ||
      !completionCodec ||
      !nativeRoute ||
      nativeRoute.request.catalog.wireTag !== requestCodec.wireTag ||
      nativeRoute.completion.catalog.wireTag !== completionCodec.wireTag
    ) {
      fail(`${operationId} native codegen program is not executable from authenticated inputs`);
    }
    const receiver = createBindGroupLayoutReceiver;
    const target = (index) => Object.freeze({
      kind: targetKind,
      objectId: String(targetObjectIdBase + index),
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    });
    const input = (convertedArguments, index) => Object.freeze({
      operationId,
      wireId: route.wireId,
      convertedArguments,
      receiver,
      target: target(index),
      capturedScopeId: "2",
      adapterOrdinal: "0",
      deviceIngressOrdinal: String(40 + index),
      queueIngressOrdinal: "0",
      sealedLocalTimeline: Object.freeze([]),
    });
    const carrier = (index) => Object.freeze({
      operation_id: route.wireId,
      flags: 0,
      topology_id:
        WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
          .providerTopologyId,
      ingress_device: Object.freeze({
        logical_device_id: "55",
        logical_device_generation: "1",
        provider_generation: "9",
      }),
      provider_generation: "9",
      operation_instance_id: String(operationInstanceIdBase + index),
      promise_id: "0",
      captured_scope_id: "2",
      adapter_ordinal: "0",
      device_ingress_ordinal: String(40 + index),
      queue_ingress_ordinal: "0",
      receiver: Object.freeze({
        kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
        flags: 0,
        object_id: "80",
        object_generation: "2",
      }),
      target: Object.freeze({
        kind: targetKindTag,
        flags: 0,
        object_id: String(targetObjectIdBase + index),
        object_generation: "1",
      }),
    });
    const requestVectors = Object.freeze(rawDescriptors.map((rawDescriptor, index) => {
      const convertedArguments =
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          operationId,
          [rawDescriptor],
          wrapperAccess,
        );
      if (canonicalJson(convertedArguments) !== canonicalJson(expectedDescriptors[index])) {
        fail(`${operationId} reviewed call ${index + 1} conversion drifted`);
      }
      const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        input(convertedArguments, index),
      );
      const expected = Object.freeze({
        receiver,
        target: target(index),
        capturedScopeId: "2",
        adapterOrdinal: "0",
        deviceIngressOrdinal: String(40 + index),
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
        convertedArguments: expectedDescriptors[index],
      });
      const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes);
      if (canonicalJson(inspected) !== canonicalJson({
        operationId,
        codec: requestCodec.tag,
        ...expected,
      })) {
        fail(`${operationId} reviewed call ${index + 1} round-trip drifted`);
      }
      return Object.freeze({
        id: `${operationId === createSamplerOperationId ? "create-sampler" : "create-texture"}-workload-call-${String(index + 1).padStart(2, "0")}`,
        kind: "request",
        carrierProjection: carrier(index),
        trust: "untrusted-wrapper-record-prefix-and-descriptor-join-only-never-authority",
        semanticOwner: "native-semantic-service-before-provider-admission",
        bytesHex: toHex(bytes),
        expected,
        accountingEvidence: accountingEvidence[index],
      });
    }));
    const completion = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      operationId,
      { kind: "none" },
    );
    if (completion.byteLength !== 0) {
      fail(`${operationId} terminal receipt must have an empty payload`);
    }
    const completionCarrier = Object.freeze({
      kind: 1,
      record: Object.freeze({
        operation_result: Object.freeze({
          result_kind: 0,
          status: 0,
          operation: Object.freeze({
            operation_id: route.wireId,
            operation_instance_id: String(operationInstanceIdBase),
            promise_id: "0",
            provider_admission: 1,
            physical_sequence: "31",
            captured_scope_id: "2",
            adapter_ordinal: "0",
            device_ingress_ordinal: "40",
            queue_ingress_ordinal: "0",
            device_transition: 0,
            ingress_device: carrier(0).ingress_device,
            result_device: carrier(0).ingress_device,
            provider_generation: "9",
            receiver: carrier(0).receiver,
            target: carrier(0).target,
          }),
        }),
      }),
    });
    const semanticSteps = Object.freeze(
      nativeRoute.request.semanticServiceBoundary.requiredAfterDecode,
    );
    if (semanticSteps.length !== semanticMutations.length) {
      fail(`${operationId} semantic step/mutation inventory drifted`);
    }
    const semanticRejections = Object.freeze(semanticMutations.map(
      ([suffix, mutation], index) => {
        const reachabilityEvidence = resourceSemanticReachabilityEvidence({
          operationId,
          semanticSteps,
          mutation,
          expectedFailureIndex: index,
          baseDescriptor: expectedDescriptors[0],
          reviewedDescriptors: expectedDescriptors,
        });
        return Object.freeze({
          id: `${operationId === createSamplerOperationId ? "create-sampler" : "create-texture"}-${suffix}-rejected`,
          kind: "semantic-rejection",
          operationId,
          semanticTerminalId: "later-predicate-rejection",
          semanticStepIndex: index + 1,
          firstFailingSemanticStep: semanticSteps[index],
          earlierSemanticStepsMustPass: semanticSteps.slice(0, index),
          mutation,
          reachabilityEvidence,
          bytesHex: requestVectors[0].bytesHex,
          expected: Object.freeze({
            codegenDisposition: "encoded-for-post-decode-semantic-validation",
            providerTokenCount: 0,
            physicalSequenceCount: 0,
          }),
        });
      }),
    );
    return Object.freeze({
      route,
      requestCodec,
      completionCodec,
      nativeRoute,
      requestVectors,
      semanticSteps,
      semanticRejections,
      successVector: Object.freeze({
        id: `${operationId === createSamplerOperationId ? "create-sampler" : "create-texture"}-operation-success-result`,
        kind: "result",
        semanticTerminalId: "operation-success",
        carrierProjection: completionCarrier,
        bytesHex: toHex(completion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      }),
    });
  }

  const samplerDefaults = Object.freeze({
    addressModeU: "clamp-to-edge",
    addressModeV: "clamp-to-edge",
    addressModeW: "clamp-to-edge",
    label: "",
    lodMaxClamp: 32,
    lodMinClamp: 0,
    magFilter: "nearest",
    maxAnisotropy: 1,
    minFilter: "nearest",
    mipmapFilter: "nearest",
  });
  const samplerRawDescriptors = Object.freeze([
    { magFilter: "linear", minFilter: "linear" },
    { label: "nearestSampler", magFilter: "nearest", minFilter: "nearest" },
    { label: "linearSampler", magFilter: "linear", minFilter: "linear" },
    { label: "sampler", magFilter: "linear", minFilter: "linear" },
  ]);
  const samplerExpectedDescriptors = Object.freeze([
    Object.freeze({ ...samplerDefaults, magFilter: "linear", minFilter: "linear" }),
    Object.freeze({ ...samplerDefaults, label: "nearestSampler" }),
    Object.freeze({ ...samplerDefaults, label: "linearSampler", magFilter: "linear", minFilter: "linear" }),
    Object.freeze({ ...samplerDefaults, label: "sampler", magFilter: "linear", minFilter: "linear" }),
  ]);
  const samplerCorpus = buildResourceCorpus({
    operationId: createSamplerOperationId,
    targetKind: "GPUSampler",
    targetKindTag: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUSampler,
    targetObjectIdBase: 160,
    operationInstanceIdBase: 60,
    rawDescriptors: samplerRawDescriptors,
    expectedDescriptors: samplerExpectedDescriptors,
    accountingEvidence: samplerRawDescriptors.map(() => Object.freeze({
      resourceBytes: 0,
      mappedExtentBytes: 0,
      stagingBytes: 0,
      resourceUnitCharge: 1,
      backingChargeRule: "sampler-has-no-byte-backing-but-consumes-one-resource-table-and-ledger-unit",
    })),
    semanticMutations: [
      ["source-receiver-table-entry-missing", { sourceReceiverTableEntryPresent: false }],
      ["sealed-timeline-gap", { sealedLocalTimelinePrefixContiguous: false }],
      ["stale-device-generation", { deviceGeneration: "stale" }],
      ["coverage-absent", { operationCoverageInstalled: false }],
      ["aggregate-envelope-not-live", { aggregateEnvelopeState: "CLOSED" }],
      ["lod-order-mismatch", { lodMinClamp: 4, lodMaxClamp: 2 }],
      ["anisotropy-filter-mismatch", { maxAnisotropy: 2, minFilter: "nearest" }],
      ["overlong-label", { label: "x".repeat(15) }],
      ["unreviewed-workload", { addressModeU: "repeat" }],
      ["foreign-target-provenance", { targetLogicalDeviceId: "56" }],
      ["stale-target-generation", { targetSlotGeneration: "2" }],
      ["resource-ledger-capacity-exhausted", { resourceUnitCredit: 0 }],
      ["provider-completion-credit-exhausted", { completionCredit: 0 }],
    ],
  });

  const textureRawDescriptors = Object.freeze([
    { dimension: "2d", format: "rgba8unorm", label: "texture", mipLevelCount: 1, sampleCount: 1, size: [32, 64], usage: 23, viewFormats: [] },
    { format: "rgba8unorm", size: [64, 128], usage: 22 },
    { format: "rgba8unorm", size: [32, 64], usage: 17 },
    { dimension: "2d", format: "rgba8unorm", label: "trackTexture", mipLevelCount: 1, sampleCount: 1, size: [512, 512], usage: 23, viewFormats: [] },
    { dimension: "2d", format: "rgba16float", label: "bezierTexture", mipLevelCount: 1, sampleCount: 1, size: [256, 128], usage: 31, viewFormats: [] },
  ]);
  const textureExpectedDescriptors = Object.freeze([
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "texture", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 64, width: 32 }), usage: 23, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 128, width: 64 }), usage: 22, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 64, width: 32 }), usage: 17, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "trackTexture", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 512, width: 512 }), usage: 23, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba16float", label: "bezierTexture", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 128, width: 256 }), usage: 31, viewFormats: Object.freeze([]) }),
  ]);
  const textureBytes = Object.freeze([8_192, 32_768, 8_192, 1_048_576, 262_144]);
  const textureCorpus = buildResourceCorpus({
    operationId: createTextureOperationId,
    targetKind: "GPUTexture",
    targetKindTag: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUTexture,
    targetObjectIdBase: 170,
    operationInstanceIdBase: 70,
    rawDescriptors: textureRawDescriptors,
    expectedDescriptors: textureExpectedDescriptors,
    accountingEvidence: textureBytes.map((resourceBytes) => Object.freeze({
      resourceBytes,
      mappedExtentBytes: 0,
      stagingBytes: 0,
      backingChargeRule: "checked-format-block-byte-size-times-complete-mip-extent-without-double-charge",
    })),
    semanticMutations: [
      ["source-receiver-table-entry-missing", { sourceReceiverTableEntryPresent: false }],
      ["sealed-timeline-gap", { sealedLocalTimelinePrefixContiguous: false }],
      ["stale-device-generation", { deviceGeneration: "stale" }],
      ["coverage-absent", { operationCoverageInstalled: false }],
      ["aggregate-envelope-not-live", { aggregateEnvelopeState: "CLOSED" }],
      ["logical-dimension-limit", { maxTextureDimension2D: 31 }],
      ["format-capability-missing", { allowedFormats: [] }],
      ["usage-format-mismatch", { usage: 0 }],
      ["mip-sample-bounds", { mipLevelCount: 8 }],
      ["view-format-incompatible", { viewFormats: ["bgra8unorm"] }],
      ["binding-view-dimension-incompatible", { textureBindingViewDimension: "cube" }],
      ["overlong-label", { label: "x".repeat(14) }],
      ["unreviewed-workload", {
        size: { width: 16, height: 16, depthOrArrayLayers: 1 },
      }],
      ["foreign-target-provenance", { targetLogicalDeviceId: "56" }],
      ["stale-target-generation", { targetSlotGeneration: "2" }],
      ["resource-ledger-capacity-exhausted", { aggregateEnvelopeResourceCredit: 0 }],
      ["provider-completion-credit-exhausted", { completionCredit: 0 }],
    ],
  });
  if (textureBytes.reduce((sum, value) => sum + value, 0) !== 1_359_872) {
    fail("GPUDevice.createTexture checked workload byte evidence drifted");
  }

  const createTextureViewRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createTextureViewOperationId,
  );
  const createTextureViewRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createTextureViewRoute?.serviceArgumentCodec,
    );
  const createTextureViewCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createTextureViewRoute?.serviceCompletionCodec,
    );
  const createTextureViewNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createTextureViewOperationId,
    );
  if (
    !createTextureViewRoute ||
    !createTextureViewRequestCodec?.nativeProgramPrerequisitesRepresented ||
    !createTextureViewRequestCodec.executableFromCurrentAuthenticatedInputs ||
    createTextureViewRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createTextureViewCompletionCodec ||
    !createTextureViewNativeRoute ||
    createTextureViewNativeRoute.request.catalog.wireTag !== 9 ||
    createTextureViewNativeRoute.request.catalog.wireTag !==
      createTextureViewRequestCodec.wireTag ||
    createTextureViewNativeRoute.completion.catalog.wireTag !==
      createTextureViewCompletionCodec.wireTag
  ) {
    fail(
      "GPUTexture.createView native codegen program is not executable from authenticated inputs",
    );
  }

  const textureViewDefaults = Object.freeze({
    aspect: "all",
    baseArrayLayer: 0,
    baseMipLevel: 0,
    label: "",
    swizzle: "rgba",
    usage: 0,
  });
  const geneticCanvasSequences = Object.freeze([
    200, 224, 305, 317, 396, 408, 487, 499, 578,
    590, 669, 681, 760, 772, 940, 952, 1065, 1077,
  ]);
  const geneticCanvasCalls = geneticCanvasSequences.map(
    (traceSequence, epochIndex) => Object.freeze({
      sourceWorkload: "typegpu-genetic-racing",
      traceSequence,
      nonCartesianClassId: "genetic-canvas-premultiplied-default",
      rawDescriptor: Object.freeze({}),
      receiverTexture: Object.freeze({
        dimension: "2d",
        extentSource: "canvas-current-runtime-size-not-recorded",
        format: "bgra8unorm",
        label: "",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 16,
        viewFormats: Object.freeze([]),
      }),
      originClass: "canvas-current",
      alphaMode: "premultiplied",
      currentEpoch: epochIndex + 1,
    }),
  );
  const textureViewWorkloadCalls = Object.freeze([
    Object.freeze({
      sourceWorkload: "typegpu-genetic-racing",
      traceSequence: 16,
      nonCartesianClassId: "genetic-device-default-64-usage22",
      rawDescriptor: Object.freeze({}),
      receiverTexture: Object.freeze({
        depthOrArrayLayers: 1,
        dimension: "2d",
        format: "rgba8unorm",
        height: 64,
        label: "",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 22,
        viewFormats: Object.freeze([]),
        width: 64,
      }),
      originClass: "device-created",
      creationSequence: 8,
    }),
    Object.freeze({
      sourceWorkload: "typegpu-genetic-racing",
      traceSequence: 17,
      nonCartesianClassId: "genetic-device-default-32-usage17",
      rawDescriptor: Object.freeze({}),
      receiverTexture: Object.freeze({
        depthOrArrayLayers: 1,
        dimension: "2d",
        format: "rgba8unorm",
        height: 32,
        label: "",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 17,
        viewFormats: Object.freeze([]),
        width: 32,
      }),
      originClass: "device-created",
      creationSequence: 14,
    }),
    Object.freeze({
      sourceWorkload: "typegpu-genetic-racing",
      traceSequence: 128,
      nonCartesianClassId: "genetic-device-track-explicit",
      rawDescriptor: Object.freeze({
        dimension: "2d",
        format: "rgba8unorm",
        label: "trackView",
      }),
      receiverTexture: Object.freeze({
        depthOrArrayLayers: 1,
        dimension: "2d",
        format: "rgba8unorm",
        height: 512,
        label: "trackTexture",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 23,
        viewFormats: Object.freeze([]),
        width: 512,
      }),
      originClass: "device-created",
      creationSequence: 50,
    }),
    ...geneticCanvasCalls.slice(0, 2),
    Object.freeze({
      sourceWorkload: "typegpu-genetic-racing",
      traceSequence: 228,
      nonCartesianClassId: "genetic-device-car-sprite-explicit",
      rawDescriptor: Object.freeze({
        dimension: "2d",
        format: "rgba8unorm",
        label: "carSpriteView",
      }),
      receiverTexture: Object.freeze({
        depthOrArrayLayers: 1,
        dimension: "2d",
        format: "rgba8unorm",
        height: 32,
        label: "texture",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 23,
        viewFormats: Object.freeze([]),
        width: 32,
      }),
      originClass: "device-created",
      creationSequence: 5,
    }),
    ...geneticCanvasCalls.slice(2),
    Object.freeze({
      sourceWorkload: "typegpu-jelly-slider",
      traceSequence: 55,
      nonCartesianClassId: "jelly-device-bezier-write-explicit",
      rawDescriptor: Object.freeze({
        dimension: "2d",
        format: "rgba16float",
        label: "bezierWriteView",
      }),
      receiverTexture: Object.freeze({
        depthOrArrayLayers: 1,
        dimension: "2d",
        format: "rgba16float",
        height: 128,
        label: "bezierTexture",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 31,
        viewFormats: Object.freeze([]),
        width: 256,
      }),
      originClass: "device-created",
      creationSequence: 54,
    }),
    Object.freeze({
      sourceWorkload: "typegpu-jelly-slider",
      traceSequence: 60,
      nonCartesianClassId: "jelly-canvas-opaque-default",
      rawDescriptor: Object.freeze({}),
      receiverTexture: Object.freeze({
        dimension: "2d",
        extentSource: "canvas-current-runtime-size-not-recorded",
        format: "bgra8unorm",
        label: "",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 16,
        viewFormats: Object.freeze([]),
      }),
      originClass: "canvas-current",
      alphaMode: "opaque",
      currentEpoch: 1,
    }),
    Object.freeze({
      sourceWorkload: "typegpu-jelly-slider",
      traceSequence: 73,
      nonCartesianClassId: "jelly-device-bezier-texture-explicit",
      rawDescriptor: Object.freeze({
        dimension: "2d",
        format: "rgba16float",
        label: "bezierTexture",
      }),
      receiverTexture: Object.freeze({
        depthOrArrayLayers: 1,
        dimension: "2d",
        format: "rgba16float",
        height: 128,
        label: "bezierTexture",
        mipLevelCount: 1,
        sampleCount: 1,
        usage: 31,
        viewFormats: Object.freeze([]),
        width: 256,
      }),
      originClass: "device-created",
      creationSequence: 54,
    }),
  ]);
  const textureViewClassMultiplicity = Object.freeze([
    Object.freeze({ classId: "genetic-device-default-64-usage22", count: 1 }),
    Object.freeze({ classId: "genetic-device-default-32-usage17", count: 1 }),
    Object.freeze({ classId: "genetic-device-track-explicit", count: 1 }),
    Object.freeze({ classId: "genetic-canvas-premultiplied-default", count: 18 }),
    Object.freeze({ classId: "genetic-device-car-sprite-explicit", count: 1 }),
    Object.freeze({ classId: "jelly-device-bezier-write-explicit", count: 1 }),
    Object.freeze({ classId: "jelly-canvas-opaque-default", count: 1 }),
    Object.freeze({ classId: "jelly-device-bezier-texture-explicit", count: 1 }),
  ]);
  if (
    textureViewWorkloadCalls.length !== 25 ||
    textureViewClassMultiplicity.length !== 8 ||
    textureViewClassMultiplicity.reduce((sum, entry) => sum + entry.count, 0) !== 25 ||
    textureViewWorkloadCalls.filter(
      (entry) => entry.sourceWorkload === "typegpu-genetic-racing",
    ).length !== 22 ||
    textureViewWorkloadCalls.filter(
      (entry) => entry.sourceWorkload === "typegpu-jelly-slider",
    ).length !== 3
  ) {
    fail("GPUTexture.createView reviewed 25-call/8-class workload evidence drifted");
  }

  const textureViewReceiver = (index) => Object.freeze({
    kind: "GPUTexture",
    objectId: String(300 + index),
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const textureViewTarget = (index) => Object.freeze({
    kind: "GPUTextureView",
    objectId: String(400 + index),
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const textureViewConfiguredDeviceRef = Object.freeze({
    kind: "GPUDevice",
    objectId: "80",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const canvasCurrentOrigin = (spec, index) => {
    const contextId = spec.sourceWorkload === "typegpu-genetic-racing"
      ? "190"
      : "191";
    const contextRef = Object.freeze({
      kind: "GPUCanvasContext",
      objectId: contextId,
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    });
    const targetAuthorityDigest = sha256(canonicalJson({
      contextId,
      configuredDeviceRef: textureViewConfiguredDeviceRef,
      configurationGeneration: "1",
    }));
    const mintOperationProvenance = Object.freeze({
      operationInstanceId: String(1_000 + spec.traceSequence),
      deviceIngressOrdinal: String(100 + index),
    });
    const digestInput = Object.freeze({
      originClass: "canvas-current",
      receiverTextureRef: textureViewReceiver(index),
      contextRef,
      attachmentGeneration: "1",
      contextGeneration: "1",
      configurationGeneration: "1",
      currentEpoch: String(spec.currentEpoch),
      mintOperationProvenance,
      configuredDeviceRef: textureViewConfiguredDeviceRef,
      format: "bgra8unorm",
      usage: 16,
      alphaMode: spec.alphaMode,
      colorSpace: "srgb",
      targetAuthorityDigest,
      surfaceAccountToken:
        spec.sourceWorkload === "typegpu-genetic-racing" ? "700" : "701",
      surfaceAccountGeneration: "1",
    });
    const textureOriginDigest =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.deriveTextureOriginDigest(
        digestInput,
      );
    const nodeTextureOriginDigest = sha256(
      `exact.webgpu.texture-origin.v1\0${canonicalJson(digestInput)}`,
    );
    if (textureOriginDigest !== nodeTextureOriginDigest) {
      fail("GPUTexture.createView codec-owned texture origin digest drifted from Node SHA-256");
    }
    const { receiverTextureRef: _receiverTextureRef, ...origin } = digestInput;
    return Object.freeze({
      ...origin,
      textureOriginDigest,
    });
  };
  const expectedTextureViewDescriptor = (rawDescriptor) => Object.freeze({
    ...textureViewDefaults,
    ...rawDescriptor,
  });
  const textureViewConvertedArguments = (spec, index) => {
    const converted =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        createTextureViewOperationId,
        [spec.rawDescriptor],
        wrapperAccess,
      );
    const expected = expectedTextureViewDescriptor(spec.rawDescriptor);
    if (canonicalJson(converted) !== canonicalJson(expected)) {
      fail(
        `GPUTexture.createView reviewed call ${index + 1} conversion drifted`,
      );
    }
    return Object.freeze({
      converted,
      ...(spec.originClass === "canvas-current"
        ? { currentOrigin: canvasCurrentOrigin(spec, index) }
        : {}),
    });
  };
  const textureViewInput = (spec, index) => Object.freeze({
    operationId: createTextureViewOperationId,
    wireId: createTextureViewRoute.wireId,
    convertedArguments: textureViewConvertedArguments(spec, index),
    receiver: textureViewReceiver(index),
    target: textureViewTarget(index),
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: String(100 + index),
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const textureViewCarrier = (index) => Object.freeze({
    operation_id: createTextureViewRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: String(200 + index),
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: String(100 + index),
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUTexture,
      flags: 0,
      object_id: textureViewReceiver(index).objectId,
      object_generation: "1",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUTextureView,
      flags: 0,
      object_id: textureViewTarget(index).objectId,
      object_generation: "1",
    }),
  });
  const textureViewWorkloadVectors = Object.freeze(
    textureViewWorkloadCalls.map((spec, index) => {
      const input = textureViewInput(spec, index);
      const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(input);
      const expected = Object.freeze({
        receiver: input.receiver,
        target: input.target,
        capturedScopeId: "2",
        adapterOrdinal: "0",
        deviceIngressOrdinal: String(100 + index),
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
        convertedArguments: input.convertedArguments,
      });
      const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(bytes);
      if (canonicalJson(inspected) !== canonicalJson({
        operationId: createTextureViewOperationId,
        codec: createTextureViewRequestCodec.tag,
        ...expected,
      })) {
        fail(
          `GPUTexture.createView reviewed call ${index + 1} round-trip drifted`,
        );
      }
      return Object.freeze({
        id: `create-texture-view-workload-call-${String(index + 1).padStart(2, "0")}`,
        kind: "request",
        carrierProjection: textureViewCarrier(index),
        trust:
          "untrusted-wrapper-record-prefix-descriptor-origin-and-source-affine-join-only-never-authority",
        semanticOwner: "native-semantic-service-before-provider-admission",
        bytesHex: toHex(bytes),
        expected,
        workloadEvidence: Object.freeze({
          sourceWorkload: spec.sourceWorkload,
          traceSequence: spec.traceSequence,
          nonCartesianClassId: spec.nonCartesianClassId,
          receiverTexture: spec.receiverTexture,
          originClass: spec.originClass,
          ...(spec.originClass === "canvas-current"
            ? { currentEpoch: spec.currentEpoch, alphaMode: spec.alphaMode }
            : { creationSequence: spec.creationSequence }),
        }),
        accountingEvidence: Object.freeze({
          resourceBytes: 0,
          mappedExtentBytes: 0,
          stagingBytes: 0,
          independentViewUnitCharge: 1,
          backingChargeRule:
            "view-aliases-parent-backing-and-must-not-double-charge-texture-bytes",
        }),
      });
    }),
  );
  if (
    textureViewWorkloadVectors.filter(
      (vector) => vector.expected.convertedArguments.currentOrigin === undefined,
    ).length !== 6 ||
    textureViewWorkloadVectors.filter(
      (vector) => vector.expected.convertedArguments.currentOrigin !== undefined,
    ).length !== 19
  ) {
    fail("GPUTexture.createView device-created/canvas-current split drifted");
  }

  function textureViewStructuralRejection(
    suffix,
    description,
    mutate,
  ) {
    const canvasIndex = 3;
    const malformedInput = structuredClone(
      textureViewInput(textureViewWorkloadCalls[canvasIndex], canvasIndex),
    );
    mutate(malformedInput);
    let rejection = null;
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        malformedInput,
      );
    } catch (error) {
      rejection = error;
    }
    if (!(rejection instanceof TypeError)) {
      fail(
        `GPUTexture.createView structural case ${suffix} did not reject before encoding`,
      );
    }
    return Object.freeze({
      id: `create-texture-view-${suffix}-structurally-rejected`,
      kind: "structural-rejection",
      operationId: createTextureViewOperationId,
      structuralBoundary: "generated-native-request-encoder-before-bytes",
      description,
      malformedInput,
      expected: Object.freeze({
        errorName: "TypeError",
        errorMessage: rejection.message,
        encodedByteCount: 0,
        providerTokenCount: 0,
        physicalSequenceCount: 0,
      }),
    });
  }
  const textureViewStructuralRejections = Object.freeze([
    textureViewStructuralRejection(
      "missing-swizzle-default",
      "converted descriptors must materialize the swizzle default",
      (input) => { delete input.convertedArguments.converted.swizzle; },
    ),
    textureViewStructuralRejection(
      "unknown-descriptor-member",
      "converted descriptors are closed dictionaries",
      (input) => { input.convertedArguments.converted.unknown = 1; },
    ),
    textureViewStructuralRejection(
      "invalid-swizzle-syntax",
      "swizzle syntax is checked synchronously before semantic features",
      (input) => { input.convertedArguments.converted.swizzle = "rgbx"; },
    ),
    textureViewStructuralRejection(
      "null-current-origin",
      "a present canvas-current origin must be a complete dictionary",
      (input) => { input.convertedArguments.currentOrigin = null; },
    ),
    textureViewStructuralRejection(
      "incomplete-current-origin",
      "canvas-current origin generations cannot be omitted",
      (input) => {
        delete input.convertedArguments.currentOrigin.contextGeneration;
      },
    ),
    textureViewStructuralRejection(
      "unknown-current-origin-member",
      "canvas-current origin is a closed authenticated comparison tuple",
      (input) => { input.convertedArguments.currentOrigin.unknown = true; },
    ),
    textureViewStructuralRejection(
      "invalid-origin-digest",
      "texture-origin digest must be lowercase SHA-256 hex",
      (input) => {
        input.convertedArguments.currentOrigin.textureOriginDigest = "forged";
      },
    ),
    textureViewStructuralRejection(
      "non-current-origin-class",
      "a carried origin tuple is valid only for canvas-current textures",
      (input) => {
        input.convertedArguments.currentOrigin.originClass = "device-created";
      },
    ),
    textureViewStructuralRejection(
      "wrong-context-reference-kind",
      "canvas origin contextRef must be a full GPUCanvasContext reference",
      (input) => {
        input.convertedArguments.currentOrigin.contextRef.kind = "GPUDevice";
      },
    ),
    textureViewStructuralRejection(
      "foreign-target-device",
      "wrapper target and source texture must share device provenance",
      (input) => { input.target.logicalDeviceId = "56"; },
    ),
    textureViewStructuralRejection(
      "wrong-receiver-kind",
      "source-affine receiver must be a full GPUTexture reference",
      (input) => { input.receiver.kind = "GPUDevice"; },
    ),
  ]);

  const textureViewSemanticSteps = Object.freeze(
    createTextureViewNativeRoute.request.semanticServiceBoundary
      .requiredAfterDecode,
  );
  const expectedTextureViewSemanticSteps = Object.freeze([
    "authenticate-source-affine-texture-receiver-and-reconstruct-authority-from-texture-table",
    "authenticate-contiguous-sealed-local-timeline-prefix",
    "validate-current-live-undestroyed-texture-device-and-provider-generation",
    "authenticate-current-texture-origin-provenance-and-epoch",
    "validate-operation-coverage",
    "validate-authorized-live-source-account-and-aggregate-envelope-with-alias-accounting",
    "validate-texture-view-format-and-aspect-compatibility",
    "validate-texture-view-dimension-compatibility",
    "validate-texture-view-subresource-range",
    "validate-texture-view-usage-and-swizzle-capability",
    "validate-texture-view-label-under-reviewed-workload",
    "validate-exact-texture-view-descriptor-parent-origin-workload-tuples",
    "authenticate-wrapper-allocated-texture-view-target-provenance",
    "validate-wrapper-allocated-texture-view-target-generation",
    "reserve-texture-view-table-and-independent-cost-without-backing-double-charge",
    "reserve-texture-view-provider-request-completion-and-physical-sequence",
  ]);
  if (
    canonicalJson(textureViewSemanticSteps) !==
      canonicalJson(expectedTextureViewSemanticSteps)
  ) {
    fail("GPUTexture.createView semantic step order drifted");
  }

  function textureViewSemanticStepPasses(step, state) {
    switch (step) {
      case expectedTextureViewSemanticSteps[0]:
        return state.sourceTextureTableEntryPresent === true &&
          state.receiverSourceAffinityMatches === true;
      case expectedTextureViewSemanticSteps[1]:
        return state.sealedLocalTimelinePrefixContiguous === true;
      case expectedTextureViewSemanticSteps[2]:
        return state.receiverLifecycleState === "LIVE" &&
          state.deviceGeneration === "current" &&
          state.providerGeneration === "current";
      case expectedTextureViewSemanticSteps[3]:
        return state.currentOriginAuthenticated === true &&
          state.currentOriginEpoch === "current";
      case expectedTextureViewSemanticSteps[4]:
        return state.operationCoverageInstalled === true;
      case expectedTextureViewSemanticSteps[5]:
        return state.sourceAccountState === "LIVE" &&
          state.aggregateEnvelopeState === "LIVE";
      case expectedTextureViewSemanticSteps[6]:
        return state.formatAspectCompatible === true;
      case expectedTextureViewSemanticSteps[7]:
        return state.dimensionCompatible === true;
      case expectedTextureViewSemanticSteps[8]:
        return state.subresourceRangeValid === true;
      case expectedTextureViewSemanticSteps[9]:
        return state.usageAndSwizzleCapabilityValid === true;
      case expectedTextureViewSemanticSteps[10]:
        return state.labelWithinReviewedWorkload === true;
      case expectedTextureViewSemanticSteps[11]:
        return state.reviewedDescriptorParentOriginTuplePresent === true;
      case expectedTextureViewSemanticSteps[12]:
        return state.targetProvenanceMatchesSource === true;
      case expectedTextureViewSemanticSteps[13]:
        return state.targetGeneration === "current";
      case expectedTextureViewSemanticSteps[14]:
        return state.viewTableCredit > 0 &&
          state.independentViewCostCredit > 0 &&
          state.parentBackingByteCharge === 0;
      case expectedTextureViewSemanticSteps[15]:
        return state.providerRequestCredit > 0 &&
          state.completionCredit > 0 &&
          state.physicalSequenceReservationCredit > 0;
      default:
        fail(
          `GPUTexture.createView has no executable semantic oracle for ${step}`,
        );
    }
  }

  const textureViewBaseSemanticState = Object.freeze({
    sourceTextureTableEntryPresent: true,
    receiverSourceAffinityMatches: true,
    sealedLocalTimelinePrefixContiguous: true,
    receiverLifecycleState: "LIVE",
    deviceGeneration: "current",
    providerGeneration: "current",
    currentOriginAuthenticated: true,
    currentOriginEpoch: "current",
    operationCoverageInstalled: true,
    sourceAccountState: "LIVE",
    aggregateEnvelopeState: "LIVE",
    formatAspectCompatible: true,
    dimensionCompatible: true,
    subresourceRangeValid: true,
    usageAndSwizzleCapabilityValid: true,
    labelWithinReviewedWorkload: true,
    reviewedDescriptorParentOriginTuplePresent: true,
    targetProvenanceMatchesSource: true,
    targetGeneration: "current",
    viewTableCredit: 1,
    independentViewCostCredit: 1,
    parentBackingByteCharge: 0,
    providerRequestCredit: 1,
    completionCredit: 1,
    physicalSequenceReservationCredit: 1,
  });
  const textureViewSemanticMutations = Object.freeze([
    Object.freeze([
      "source-receiver-table-entry-missing",
      Object.freeze({
        sourceTextureTableEntryPresent: false,
        receiverSourceAffinityMatches: false,
      }),
    ]),
    Object.freeze([
      "sealed-timeline-gap",
      Object.freeze({ sealedLocalTimelinePrefixContiguous: false }),
    ]),
    Object.freeze([
      "destroyed-receiver-current-origin-stale-collision",
      Object.freeze({
        receiverLifecycleState: "DESTROYED",
        currentOriginAuthenticated: false,
        currentOriginEpoch: "stale",
      }),
    ]),
    Object.freeze([
      "stale-current-origin-coverage-account-collision",
      Object.freeze({
        currentOriginAuthenticated: false,
        currentOriginEpoch: "stale",
        operationCoverageInstalled: false,
        sourceAccountState: "CLOSED",
        aggregateEnvelopeState: "CLOSED",
      }),
    ]),
    Object.freeze([
      "coverage-absent",
      Object.freeze({ operationCoverageInstalled: false }),
    ]),
    Object.freeze([
      "source-account-not-live",
      Object.freeze({ sourceAccountState: "CLOSED" }),
    ]),
    Object.freeze([
      "format-aspect-incompatible",
      Object.freeze({ formatAspectCompatible: false }),
    ]),
    Object.freeze([
      "dimension-incompatible",
      Object.freeze({ dimensionCompatible: false }),
    ]),
    Object.freeze([
      "subresource-range-invalid",
      Object.freeze({ subresourceRangeValid: false }),
    ]),
    Object.freeze([
      "usage-swizzle-capability-missing",
      Object.freeze({ usageAndSwizzleCapabilityValid: false }),
    ]),
    Object.freeze([
      "overlong-label",
      Object.freeze({ labelWithinReviewedWorkload: false }),
    ]),
    Object.freeze([
      "unreviewed-workload-tuple",
      Object.freeze({ reviewedDescriptorParentOriginTuplePresent: false }),
    ]),
    Object.freeze([
      "foreign-target-provenance",
      Object.freeze({ targetProvenanceMatchesSource: false }),
    ]),
    Object.freeze([
      "stale-target-generation",
      Object.freeze({ targetGeneration: "stale" }),
    ]),
    Object.freeze([
      "view-capacity-exhausted",
      Object.freeze({ viewTableCredit: 0 }),
    ]),
    Object.freeze([
      "provider-completion-credit-exhausted",
      Object.freeze({ completionCredit: 0 }),
    ]),
  ]);
  const textureViewPositiveCanvasVector = textureViewWorkloadVectors[3];
  const textureViewSemanticRejections = Object.freeze(
    textureViewSemanticMutations.map(([suffix, mutation], expectedIndex) => {
      const semanticState = Object.freeze({
        ...textureViewBaseSemanticState,
        ...mutation,
      });
      const predicateResults = Object.freeze(
        textureViewSemanticSteps.map((step) => Object.freeze({
          step,
          passed: textureViewSemanticStepPasses(step, semanticState),
        })),
      );
      const firstFailureIndex = predicateResults.findIndex(
        (result) => !result.passed,
      );
      if (firstFailureIndex !== expectedIndex) {
        fail(
          `GPUTexture.createView semantic mutation ${suffix} expected first failure ` +
            `${expectedIndex + 1} but executable oracle found ${firstFailureIndex + 1}`,
        );
      }
      const failedSemanticSteps = predicateResults
        .filter((result) => !result.passed)
        .map((result) => result.step);
      return Object.freeze({
        id: `create-texture-view-${suffix}-rejected`,
        kind: "semantic-rejection",
        operationId: createTextureViewOperationId,
        semanticTerminalId: "later-predicate-rejection",
        semanticStepIndex: expectedIndex + 1,
        firstFailingSemanticStep: textureViewSemanticSteps[expectedIndex],
        earlierSemanticStepsMustPass:
          textureViewSemanticSteps.slice(0, expectedIndex),
        mutation,
        collisionWitness: Object.freeze({
          failedSemanticSteps,
          firstFailureWins: textureViewSemanticSteps[expectedIndex],
          stateBeforeOrigin:
            suffix === "destroyed-receiver-current-origin-stale-collision",
          originBeforeCoverageAndAccount:
            suffix === "stale-current-origin-coverage-account-collision",
        }),
        reachabilityEvidence: Object.freeze({
          oracle: "texture-view-semantic-first-failure-v1",
          evaluatedPredicateResults: predicateResults,
          firstFailingSemanticStep:
            textureViewSemanticSteps[firstFailureIndex],
          earlierSemanticStepsAllPassed: predicateResults
            .slice(0, firstFailureIndex)
            .every((result) => result.passed),
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        }),
        bytesHex: textureViewPositiveCanvasVector.bytesHex,
        expected: Object.freeze({
          codegenDisposition: "encoded-for-post-decode-semantic-validation",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        }),
      });
    }),
  );
  const createTextureViewCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createTextureViewOperationId,
      { kind: "none" },
    );
  if (createTextureViewCompletion.byteLength !== 0) {
    fail("GPUTexture.createView terminal receipt must have an empty payload");
  }
  const textureViewSuccessCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createTextureViewRoute.wireId,
          operation_instance_id: "203",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "91",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "103",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: textureViewCarrier(3).ingress_device,
          result_device: textureViewCarrier(3).ingress_device,
          provider_generation: "9",
          receiver: textureViewCarrier(3).receiver,
          target: textureViewCarrier(3).target,
        }),
      }),
    }),
  });
  const textureViewSuccessVector = Object.freeze({
    id: "create-texture-view-operation-success-result",
    kind: "result",
    semanticTerminalId: "operation-success",
    carrierProjection: textureViewSuccessCarrier,
    bytesHex: toHex(createTextureViewCompletion),
    semanticAdmissionEvidence: Object.freeze({
      allPredicatesPassedInOrder: textureViewSemanticSteps,
      providerTokenCount: 1,
      physicalSequenceCount: 1,
      physicalSequenceAllocatedOnlyAfterPredicateIndex:
        textureViewSemanticSteps.length,
    }),
    expected: Object.freeze({ kind: "terminal-receipt", value: "undefined" }),
  });

  const createPipelineLayoutRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createPipelineLayoutOperationId,
  );
  const createPipelineLayoutRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createPipelineLayoutRoute?.serviceArgumentCodec,
    );
  const createPipelineLayoutCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createPipelineLayoutRoute?.serviceCompletionCodec,
    );
  const createPipelineLayoutNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createPipelineLayoutOperationId,
    );
  if (
    !createPipelineLayoutRoute ||
    !createPipelineLayoutRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createPipelineLayoutRequestCodec.nativeProgramPrerequisitesRepresented ||
    createPipelineLayoutRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createPipelineLayoutCompletionCodec ||
    !createPipelineLayoutNativeRoute ||
    createPipelineLayoutNativeRoute.request.catalog.wireTag !==
      createPipelineLayoutRequestCodec.wireTag ||
    createPipelineLayoutNativeRoute.completion.catalog.wireTag !==
      createPipelineLayoutCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createPipelineLayout native codegen program is not executable from authenticated inputs",
    );
  }
  const pipelineLayoutWrapper = Object.freeze({
    corpusBrand: "GPUBindGroupLayout",
  });
  const pipelineLayoutWrapperAccess = Object.freeze({
    referenceIfBranded(value, expectedKind) {
      if (value !== pipelineLayoutWrapper) return undefined;
      if (expectedKind !== "GPUBindGroupLayout") {
        throw new TypeError("wrong WebGPU object brand");
      }
      return createBindGroupLayoutTarget;
    },
    reference(value, expectedKind) {
      if (
        value !== pipelineLayoutWrapper ||
        expectedKind !== "GPUBindGroupLayout"
      ) {
        throw new TypeError("unbranded corpus bind group layout");
      }
      return createBindGroupLayoutTarget;
    },
  });
  const createPipelineLayoutTarget = Object.freeze({
    kind: "GPUPipelineLayout",
    objectId: "87",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const createPipelineLayoutDescriptor = Object.freeze({
    label: "finalizeReductionPipeline - Pipeline Layout",
    bindGroupLayouts: Object.freeze([pipelineLayoutWrapper]),
    immediateSize: 0,
  });
  const expectedCreatePipelineLayoutArguments = Object.freeze({
    label: "finalizeReductionPipeline - Pipeline Layout",
    bindGroupLayouts: Object.freeze([createBindGroupLayoutTarget]),
    immediateSize: 0,
  });
  const convertedCreatePipelineLayoutArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      createPipelineLayoutOperationId,
      [createPipelineLayoutDescriptor],
      pipelineLayoutWrapperAccess,
    );
  if (
    canonicalJson(convertedCreatePipelineLayoutArguments) !==
      canonicalJson(expectedCreatePipelineLayoutArguments) ||
    Buffer.byteLength(expectedCreatePipelineLayoutArguments.label, "utf8") !== 43
  ) {
    fail("GPUDevice.createPipelineLayout descriptor projection drifted");
  }
  const createPipelineLayoutInput = (convertedArguments) => Object.freeze({
    operationId: createPipelineLayoutOperationId,
    wireId: createPipelineLayoutRoute.wireId,
    convertedArguments,
    receiver: createBindGroupLayoutReceiver,
    target: createPipelineLayoutTarget,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const createPipelineLayoutBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      createPipelineLayoutInput(convertedCreatePipelineLayoutArguments),
    );
  const expectedCreatePipelineLayoutRequest = Object.freeze({
    receiver: createBindGroupLayoutReceiver,
    target: createPipelineLayoutTarget,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
    convertedArguments: expectedCreatePipelineLayoutArguments,
  });
  const inspectedCreatePipelineLayout =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      createPipelineLayoutBytes,
    );
  if (
    canonicalJson(inspectedCreatePipelineLayout) !== canonicalJson({
      operationId: createPipelineLayoutOperationId,
      codec: createPipelineLayoutRequestCodec.tag,
      ...expectedCreatePipelineLayoutRequest,
    })
  ) {
    fail(
      "GPUDevice.createPipelineLayout generated request does not round-trip through inspection",
    );
  }
  const createPipelineLayoutCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createPipelineLayoutOperationId,
      { kind: "none" },
    );
  if (createPipelineLayoutCompletion.byteLength !== 0) {
    fail(
      "GPUDevice.createPipelineLayout terminal receipt must have an empty completion payload",
    );
  }
  const createPipelineLayoutRequestCarrier = Object.freeze({
    operation_id: createPipelineLayoutRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "16",
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUPipelineLayout,
      flags: 0,
      object_id: "87",
      object_generation: "1",
    }),
  });
  const createPipelineLayoutCompletionCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createPipelineLayoutRoute.wireId,
          operation_instance_id: "16",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "11",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "3",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: createPipelineLayoutRequestCarrier.ingress_device,
          result_device: createPipelineLayoutRequestCarrier.ingress_device,
          provider_generation: "9",
          receiver: createPipelineLayoutRequestCarrier.receiver,
          target: createPipelineLayoutRequestCarrier.target,
        }),
      }),
    }),
  });
  const pipelineLayoutBoundaryVector = (
    id,
    convertedArguments,
    predicate,
    semanticFixture,
  ) => {
    const requestBytes =
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        createPipelineLayoutInput(convertedArguments),
      );
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      requestBytes,
    );
    if (
      canonicalJson(inspected.convertedArguments) !==
        canonicalJson(convertedArguments)
    ) {
      fail(`${id} did not reach the post-decode semantic boundary intact`);
    }
    return Object.freeze({
      id,
      kind: "semantic-rejection",
      operationId: createPipelineLayoutOperationId,
      semanticTerminalId: "later-predicate-rejection",
      errorTiming: "device-timeline",
      providerTokenCount: 0,
      physicalSequenceCount: 0,
      convertedArguments,
      semanticFixture,
      bytesHex: toHex(requestBytes),
      expected: Object.freeze({
        codegenDisposition: "encoded-for-post-decode-semantic-validation",
        failingPredicate: predicate,
      }),
    });
  };
  const liveBindGroupLayoutReference = createBindGroupLayoutTarget;
  const pipelineLayoutRejectionVectors = Object.freeze([
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-empty-groups-rejected",
      { label: "empty", bindGroupLayouts: [], immediateSize: 0 },
      "validate-pipeline-layout-group-count-under-reviewed-workload",
      { reviewedGroupCount: { minimum: 1, maximum: 2 } },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-null-group-rejected",
      { label: "null", bindGroupLayouts: [null], immediateSize: 0 },
      "validate-pipeline-layout-non-null-group-positions",
      { nullPosition: 0 },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-third-group-rejected",
      {
        label: "three",
        bindGroupLayouts: [
          liveBindGroupLayoutReference,
          liveBindGroupLayoutReference,
          liveBindGroupLayoutReference,
        ],
        immediateSize: 0,
      },
      "validate-pipeline-layout-group-count-under-reviewed-workload",
      { reviewedGroupCount: { maximum: 2 } },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-logical-max-bind-groups-rejected",
      {
        label: "logical-limit",
        bindGroupLayouts: [
          liveBindGroupLayoutReference,
          liveBindGroupLayoutReference,
        ],
        immediateSize: 0,
      },
      "validate-pipeline-layout-count-under-logical-max-bind-groups",
      { logicalLimits: { maxBindGroups: 1 } },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-foreign-group-rejected",
      {
        label: "foreign",
        bindGroupLayouts: [
          { ...liveBindGroupLayoutReference, logicalDeviceId: "56" },
        ],
        immediateSize: 0,
      },
      "authenticate-pipeline-layout-bind-group-layout-full-references",
      { expectedLogicalDeviceId: "55" },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-stale-group-rejected",
      {
        label: "stale",
        bindGroupLayouts: [
          { ...liveBindGroupLayoutReference, objectGeneration: "2" },
        ],
        immediateSize: 0,
      },
      "validate-current-live-nonexclusive-bind-group-layout-generations",
      { objectRegistry: { objectId: "86", currentGeneration: "1" } },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-exclusive-group-rejected",
      {
        label: "exclusive",
        bindGroupLayouts: [liveBindGroupLayoutReference],
        immediateSize: 0,
      },
      "validate-current-live-nonexclusive-bind-group-layout-generations",
      { objectRegistry: { objectId: "86", exclusiveOwner: "other-layout" } },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-aggregate-binding-limit-rejected",
      {
        label: "aggregate",
        bindGroupLayouts: [
          liveBindGroupLayoutReference,
          liveBindGroupLayoutReference,
        ],
        immediateSize: 0,
      },
      "validate-pipeline-layout-aggregate-binding-slots-under-logical-limits",
      {
        retainedBindingMetadata: [
          { fragmentSamplers: 9 },
          { fragmentSamplers: 8 },
        ],
        logicalLimits: { maxSamplersPerShaderStage: 16 },
      },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-immediate-alignment-rejected",
      {
        label: "unaligned",
        bindGroupLayouts: [liveBindGroupLayoutReference],
        immediateSize: 2,
      },
      "validate-pipeline-layout-immediate-alignment",
      { immediateAlignment: 4 },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-immediate-limit-rejected",
      {
        label: "immediate-limit",
        bindGroupLayouts: [liveBindGroupLayoutReference],
        immediateSize: 256,
      },
      "validate-pipeline-layout-immediate-size-under-logical-limit",
      { logicalLimits: { maxImmediateSize: 128 } },
    ),
    pipelineLayoutBoundaryVector(
      "create-pipeline-layout-overlong-label-rejected",
      {
        label: "x".repeat(44),
        bindGroupLayouts: [liveBindGroupLayoutReference],
        immediateSize: 0,
      },
      "validate-pipeline-layout-label-under-reviewed-workload",
      { reviewedUtf8LabelMaximum: 43 },
    ),
  ]);

  const createComputePipelineRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createComputePipelineOperationId,
  );
  const createComputePipelineRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createComputePipelineRoute?.serviceArgumentCodec,
    );
  const createComputePipelineCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createComputePipelineRoute?.serviceCompletionCodec,
    );
  const createComputePipelineNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createComputePipelineOperationId,
    );
  if (
    !createComputePipelineRoute ||
    !createComputePipelineRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createComputePipelineRequestCodec.nativeProgramPrerequisitesRepresented ||
    createComputePipelineRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createComputePipelineCompletionCodec ||
    !createComputePipelineNativeRoute ||
    createComputePipelineNativeRoute.request.catalog.wireTag !==
      createComputePipelineRequestCodec.wireTag ||
    createComputePipelineNativeRoute.completion.catalog.wireTag !==
      createComputePipelineCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createComputePipeline native codegen program is not executable from authenticated inputs",
    );
  }
  const computePipelineConversion = JSON.parse(
    fs.readFileSync(
      path.join(repositoryRoot, computePipelineConversionPath),
      "utf8",
    ),
  );
  if (
    computePipelineConversion.schema !==
      "ibex/webgpu-compute-pipeline-conversion-fixtures/1" ||
    !Array.isArray(computePipelineConversion.rows) ||
    computePipelineConversion.rows.length !== 7 ||
    sha256(canonicalJson(computePipelineConversion.rows)) !==
      computePipelineConversion.source?.projectionSha256
  ) {
    fail("GPUDevice.createComputePipeline conversion fixture drifted");
  }
  const computePipelineLayoutWrapper = Object.freeze({
    corpusBrand: "GPUPipelineLayout.compute",
  });
  const computeModuleWrapper = Object.freeze({
    corpusBrand: "GPUShaderModule.compute",
  });
  const computePipelineLayoutReference = Object.freeze({
    kind: "GPUPipelineLayout",
    objectId: "114",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const computeModuleReference = Object.freeze({
    kind: "GPUShaderModule",
    objectId: "115",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const computePipelineWrapperAccess = Object.freeze({
    referenceIfBranded(value, expectedKind) {
      if (
        expectedKind === "GPUPipelineLayout" &&
        value === computePipelineLayoutWrapper
      ) {
        return computePipelineLayoutReference;
      }
      if (value === computeModuleWrapper) {
        return this.reference(value, expectedKind);
      }
      return undefined;
    },
    reference(value, expectedKind) {
      if (
        expectedKind === "GPUPipelineLayout" &&
        value === computePipelineLayoutWrapper
      ) {
        return computePipelineLayoutReference;
      }
      if (
        expectedKind === "GPUShaderModule" &&
        value === computeModuleWrapper
      ) {
        return computeModuleReference;
      }
      throw new TypeError(`unbranded corpus ${expectedKind}`);
    },
  });
  const computePipelineTarget = (index) => Object.freeze({
    kind: "GPUComputePipeline",
    objectId: String(120 + index),
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const computePipelineInput = (convertedArguments, index) => Object.freeze({
    operationId: createComputePipelineOperationId,
    wireId: createComputePipelineRoute.wireId,
    convertedArguments,
    receiver: createBindGroupLayoutReceiver,
    target: computePipelineTarget(index),
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: String(60 + index),
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const computePipelineCarrier = (index) => Object.freeze({
    operation_id: createComputePipelineRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: String(100 + index),
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: String(60 + index),
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUComputePipeline,
      flags: 0,
      object_id: String(120 + index),
      object_generation: "1",
    }),
  });
  const computePipelineDescriptorForRow = (row) => Object.freeze({
    label: row.label,
    layout: computePipelineLayoutWrapper,
    compute: Object.freeze({ module: computeModuleWrapper }),
  });
  const computePipelineId = (label) => label
    .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
    .toLowerCase();
  const computePipelineRequestVector = (
    id,
    descriptor,
    index,
    evidence,
    expectedPresence,
  ) => {
    const convertedArguments =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        createComputePipelineOperationId,
        [descriptor],
        computePipelineWrapperAccess,
      );
    const compute = convertedArguments.compute;
    if (
      !Object.hasOwn(compute, "constants") ||
      Object.hasOwn(compute, "entryPoint") !== expectedPresence.entryPoint ||
      canonicalJson(compute.constants) !== expectedPresence.constantsCanonicalJson
    ) {
      fail(`${id} did not preserve the authenticated compute WebIDL presence`);
    }
    const input = computePipelineInput(convertedArguments, index);
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      input,
    );
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes);
    const expected = Object.freeze({
      receiver: input.receiver,
      target: input.target,
      capturedScopeId: "2",
      adapterOrdinal: "0",
      deviceIngressOrdinal: String(60 + index),
      queueIngressOrdinal: "0",
      sealedLocalTimeline: Object.freeze([]),
      convertedArguments,
    });
    if (
      canonicalJson(inspected) !== canonicalJson({
        operationId: createComputePipelineOperationId,
        codec: createComputePipelineRequestCodec.tag,
        ...expected,
      })
    ) {
      fail(`${id} generated request does not round-trip through inspection`);
    }
    return Object.freeze({
      id,
      kind: "request",
      operationId: createComputePipelineOperationId,
      carrierProjection: computePipelineCarrier(index),
      trust:
        "untrusted-wrapper-record-prefix-and-descriptor-references-only-never-authority",
      semanticOwner: "native-semantic-service-before-provider-admission",
      bytesHex: toHex(bytes),
      expected,
      reviewedWorkloadEvidence: evidence,
    });
  };
  const computePipelineCohortVectors = Object.freeze(
    computePipelineConversion.rows.map((row, index) =>
      computePipelineRequestVector(
        `create-compute-pipeline-${computePipelineId(row.label)}-request`,
        computePipelineDescriptorForRow(row),
        index,
        Object.freeze({
          workloadId: row.workloadId,
          label: row.label,
          layoutKind: row.layoutKind,
          sourceConstantsPresence: row.sourceConstantsPresence,
          entryPointPresence: row.entryPointPresence,
          shaderSourceSha256: row.shaderSourceSha256,
        }),
        Object.freeze({
          constantsCanonicalJson: "{}",
          entryPoint: false,
        }),
      )
    ),
  );
  const computePipelinePresentVector = computePipelineRequestVector(
    "create-compute-pipeline-auto-layout-present-constants-entry-point-request",
    Object.freeze({
      label: "compute-present",
      layout: "auto",
      compute: Object.freeze({
        constants: Object.freeze({ zeta: 2, alpha: 1 }),
        entryPoint: "main",
        module: computeModuleWrapper,
      }),
    }),
    7,
    Object.freeze({
      workloadId: "presence-and-canonical-order",
      layoutKind: "auto",
      sourceConstantsPresence: "present",
      entryPointPresence: "present",
    }),
    Object.freeze({
      constantsCanonicalJson: '{"alpha":1,"zeta":2}',
      entryPoint: true,
    }),
  );
  const computePipelineSemanticBoundaryVector = (id, mutate, predicate, index) => {
    const convertedArguments = structuredClone(
      computePipelineCohortVectors[0].expected.convertedArguments,
    );
    mutate(convertedArguments);
    const input = computePipelineInput(convertedArguments, index);
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(input);
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes);
    if (canonicalJson(inspected.convertedArguments) !== canonicalJson(convertedArguments)) {
      fail(`${id} did not reach the semantic boundary intact`);
    }
    return Object.freeze({
      id,
      kind: "semantic-rejection",
      operationId: createComputePipelineOperationId,
      semanticTerminalId: "later-predicate-rejection",
      carrierProjection: computePipelineCarrier(index),
      bytesHex: toHex(bytes),
      expected: Object.freeze({
        codegenDisposition: "encoded-for-post-decode-semantic-validation",
        failingPredicate: predicate,
        providerTokenCount: 0,
        physicalSequenceCount: 0,
      }),
    });
  };
  const computePipelineSemanticRejections = Object.freeze([
    computePipelineSemanticBoundaryVector(
      "create-compute-pipeline-cross-device-layout-semantically-rejected",
      (descriptor) => { descriptor.layout.logicalDeviceId = "56"; },
      "authenticate-explicit-pipeline-layout-full-reference-or-validate-auto-layout-policy",
      8,
    ),
    computePipelineSemanticBoundaryVector(
      "create-compute-pipeline-cross-device-shader-semantically-rejected",
      (descriptor) => { descriptor.compute.module.logicalDeviceId = "56"; },
      "authenticate-current-same-device-shader-module-full-reference-and-creator-order",
      9,
    ),
  ]);
  const computePipelineStructuralRejection = (id, mutate) => {
    const convertedArguments = structuredClone(
      computePipelineCohortVectors[0].expected.convertedArguments,
    );
    mutate(convertedArguments);
    let rejection = null;
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        computePipelineInput(convertedArguments, 10),
      );
    } catch (error) {
      rejection = error;
    }
    if (!(rejection instanceof TypeError)) {
      fail(`${id} did not reject before native payload encoding`);
    }
    return Object.freeze({
      id,
      kind: "structural-rejection",
      operationId: createComputePipelineOperationId,
      structuralBoundary: "generated-native-request-encoder-before-bytes",
      expected: Object.freeze({
        errorName: "TypeError",
        errorMessage: rejection.message,
        encodedByteCount: 0,
        providerTokenCount: 0,
        physicalSequenceCount: 0,
      }),
    });
  };
  const computePipelineStructuralRejections = Object.freeze([
    computePipelineStructuralRejection(
      "create-compute-pipeline-missing-materialized-constants-structurally-rejected",
      (descriptor) => { delete descriptor.compute.constants; },
    ),
    computePipelineStructuralRejection(
      "create-compute-pipeline-nonfinite-constant-structurally-rejected",
      (descriptor) => { descriptor.compute.constants.invalid = Infinity; },
    ),
    computePipelineStructuralRejection(
      "create-compute-pipeline-missing-module-structurally-rejected",
      (descriptor) => { delete descriptor.compute.module; },
    ),
  ]);
  const createComputePipelineCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createComputePipelineOperationId,
      { kind: "none" },
    );
  if (createComputePipelineCompletion.byteLength !== 0) {
    fail("GPUDevice.createComputePipeline terminal receipt must have an empty payload");
  }
  const computePipelineSuccessCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createComputePipelineRoute.wireId,
          operation_instance_id: "100",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "59",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "60",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: computePipelineCarrier(0).ingress_device,
          result_device: computePipelineCarrier(0).ingress_device,
          provider_generation: "9",
          receiver: computePipelineCarrier(0).receiver,
          target: computePipelineCarrier(0).target,
        }),
      }),
    }),
  });
  const computePipelineSemanticSteps = Object.freeze(
    createComputePipelineNativeRoute.request.semanticServiceBoundary
      .requiredAfterDecode,
  );
  if (computePipelineSemanticSteps.length !== 19) {
    fail("GPUDevice.createComputePipeline semantic step inventory drifted");
  }

  const createRenderPipelineRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createRenderPipelineOperationId,
  );
  const createRenderPipelineRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createRenderPipelineRoute?.serviceArgumentCodec,
    );
  const createRenderPipelineCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createRenderPipelineRoute?.serviceCompletionCodec,
    );
  const createRenderPipelineNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createRenderPipelineOperationId,
    );
  if (
    !createRenderPipelineRoute ||
    !createRenderPipelineRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createRenderPipelineRequestCodec.nativeProgramPrerequisitesRepresented ||
    createRenderPipelineRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createRenderPipelineCompletionCodec ||
    !createRenderPipelineNativeRoute ||
    createRenderPipelineNativeRoute.request.catalog.wireTag !==
      createRenderPipelineRequestCodec.wireTag ||
    createRenderPipelineNativeRoute.completion.catalog.wireTag !==
      createRenderPipelineCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createRenderPipeline native codegen program is not executable from authenticated inputs",
    );
  }
  const renderPipelineConversion = JSON.parse(
    fs.readFileSync(
      path.join(repositoryRoot, renderPipelineConversionPath),
      "utf8",
    ),
  );
  if (
    renderPipelineConversion.schema !==
      "ibex/webgpu-render-pipeline-conversion-fixtures/1" ||
    !Array.isArray(renderPipelineConversion.rows) ||
    renderPipelineConversion.rows.length !== 4
  ) {
    fail("GPUDevice.createRenderPipeline conversion fixture drifted");
  }
  const renderPipelineLayoutWrapper = Object.freeze({
    corpusBrand: "GPUPipelineLayout",
  });
  const renderVertexModuleWrapper = Object.freeze({
    corpusBrand: "GPUShaderModule.vertex",
  });
  const renderFragmentModuleWrapper = Object.freeze({
    corpusBrand: "GPUShaderModule.fragment",
  });
  const renderPipelineLayoutReference = Object.freeze({
    kind: "GPUPipelineLayout",
    objectId: "94",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const renderVertexModuleReference = Object.freeze({
    kind: "GPUShaderModule",
    objectId: "95",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const renderFragmentModuleReference = Object.freeze({
    kind: "GPUShaderModule",
    objectId: "96",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const renderPipelineWrapperAccess = Object.freeze({
    referenceIfBranded(value, expectedKind) {
      if (
        expectedKind === "GPUPipelineLayout" &&
        value === renderPipelineLayoutWrapper
      ) {
        return renderPipelineLayoutReference;
      }
      if (
        value === renderVertexModuleWrapper ||
        value === renderFragmentModuleWrapper
      ) {
        return this.reference(value, expectedKind);
      }
      return undefined;
    },
    reference(value, expectedKind) {
      if (
        expectedKind === "GPUPipelineLayout" &&
        value === renderPipelineLayoutWrapper
      ) {
        return renderPipelineLayoutReference;
      }
      if (
        expectedKind === "GPUShaderModule" &&
        value === renderVertexModuleWrapper
      ) {
        return renderVertexModuleReference;
      }
      if (
        expectedKind === "GPUShaderModule" &&
        value === renderFragmentModuleWrapper
      ) {
        return renderFragmentModuleReference;
      }
      throw new TypeError(`unbranded corpus ${expectedKind}`);
    },
  });
  const renderPipelineTarget = (index) => Object.freeze({
    kind: "GPURenderPipeline",
    objectId: String(100 + index),
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const renderPipelineInput = (convertedArguments, index) => Object.freeze({
    operationId: createRenderPipelineOperationId,
    wireId: createRenderPipelineRoute.wireId,
    convertedArguments,
    receiver: createBindGroupLayoutReceiver,
    target: renderPipelineTarget(index),
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: String(40 + index),
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
  });
  const renderPipelineCarrier = (index) => Object.freeze({
    operation_id: createRenderPipelineRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: String(80 + index),
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: String(40 + index),
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPURenderPipeline,
      flags: 0,
      object_id: String(100 + index),
      object_generation: "1",
    }),
  });
  const renderPipelineDescriptorForRow = (row, layout = renderPipelineLayoutWrapper) =>
    Object.freeze({
      label: row.label,
      layout,
      ...(row.sourcePrimitivePresence === "present"
        ? { primitive: row.primitive }
        : {}),
      vertex: Object.freeze({
        module: renderVertexModuleWrapper,
        ...(row.sourceVertexBuffersPresence === "present"
          ? { buffers: row.vertexBuffers }
          : {}),
      }),
      fragment: Object.freeze({
        module: renderFragmentModuleWrapper,
        targets: Object.freeze([
          Object.freeze({
            format: row.targetFormat,
            ...(row.blend ? { blend: row.blend } : {}),
          }),
        ]),
      }),
    });
  const renderPipelineId = (workload) => workload
    .replace(/([a-z0-9])([A-Z])/gu, "$1-$2")
    .toLowerCase();
  const renderPipelineRequestVector = (
    id,
    descriptor,
    index,
    evidence,
    expectMaterializedDefaults = true,
  ) => {
    const convertedArguments =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        createRenderPipelineOperationId,
        [descriptor],
        renderPipelineWrapperAccess,
      );
    if (
      expectMaterializedDefaults &&
      !convertedArguments ||
      (expectMaterializedDefaults &&
        (canonicalJson(convertedArguments.vertex.constants) !== "{}" ||
          !Array.isArray(convertedArguments.vertex.buffers) ||
          canonicalJson(convertedArguments.fragment.constants) !== "{}" ||
          convertedArguments.fragment.targets[0].writeMask !== 0x0f ||
          canonicalJson(convertedArguments.multisample) !==
            canonicalJson({ alphaToCoverageEnabled: false, count: 1, mask: 0xffff_ffff }) ||
          typeof convertedArguments.primitive !== "object"))
    ) {
      fail(`${id} did not materialize the authenticated WebIDL defaults`);
    }
    const input = renderPipelineInput(convertedArguments, index);
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      input,
    );
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes);
    const expected = Object.freeze({
      receiver: input.receiver,
      target: input.target,
      capturedScopeId: "2",
      adapterOrdinal: "0",
      deviceIngressOrdinal: String(40 + index),
      queueIngressOrdinal: "0",
      sealedLocalTimeline: Object.freeze([]),
      convertedArguments,
    });
    if (
      canonicalJson(inspected) !== canonicalJson({
        operationId: createRenderPipelineOperationId,
        codec: createRenderPipelineRequestCodec.tag,
        ...expected,
      })
    ) {
      fail(`${id} generated request does not round-trip through inspection`);
    }
    return Object.freeze({
      id,
      kind: "request",
      operationId: createRenderPipelineOperationId,
      carrierProjection: renderPipelineCarrier(index),
      trust:
        "untrusted-wrapper-record-prefix-and-descriptor-references-only-never-authority",
      semanticOwner: "native-semantic-service-before-provider-admission",
      bytesHex: toHex(bytes),
      expected,
      reviewedWorkloadEvidence: evidence,
    });
  };
  const renderPipelineCohortVectors = Object.freeze(
    renderPipelineConversion.rows.map((row, index) =>
      renderPipelineRequestVector(
        `create-render-pipeline-${renderPipelineId(row.workload)}-request`,
        renderPipelineDescriptorForRow(row),
        index,
        Object.freeze({
          workload: row.workload,
          sourceVertexBuffersPresence: row.sourceVertexBuffersPresence,
          sourcePrimitivePresence: row.sourcePrimitivePresence,
          targetFormat: row.targetFormat,
        }),
      )
    ),
  );
  const renderPipelineAutoVector = renderPipelineRequestVector(
    "create-render-pipeline-auto-layout-request",
    renderPipelineDescriptorForRow(renderPipelineConversion.rows[0], "auto"),
    4,
    Object.freeze({ workload: "layout-auto", layout: "auto" }),
  );
  const renderPipelineFullStateDescriptor = Object.freeze({
    label: "full-state-pipeline",
    layout: renderPipelineLayoutWrapper,
    depthStencil: Object.freeze({
      depthBias: -2,
      depthBiasClamp: 0.5,
      depthBiasSlopeScale: 1.25,
      depthCompare: "less-equal",
      depthWriteEnabled: true,
      format: "depth24plus-stencil8",
      stencilBack: Object.freeze({
        compare: "always",
        depthFailOp: "increment-clamp",
        failOp: "keep",
        passOp: "replace",
      }),
      stencilFront: Object.freeze({
        compare: "less",
        depthFailOp: "decrement-wrap",
        failOp: "zero",
        passOp: "invert",
      }),
      stencilReadMask: 0x0f0f_0f0f,
      stencilWriteMask: 0xf0f0_f0f0,
    }),
    fragment: Object.freeze({
      constants: Object.freeze({ tint: 0.75 }),
      entryPoint: "fs_main",
      module: renderFragmentModuleWrapper,
      targets: Object.freeze([
        Object.freeze({
          blend: Object.freeze({
            alpha: Object.freeze({
              dstFactor: "one-minus-src-alpha",
              operation: "add",
              srcFactor: "src-alpha",
            }),
            color: Object.freeze({
              dstFactor: "one",
              operation: "reverse-subtract",
              srcFactor: "constant",
            }),
          }),
          format: "bgra8unorm",
          writeMask: 0x07,
        }),
      ]),
    }),
    multisample: Object.freeze({
      alphaToCoverageEnabled: true,
      count: 4,
      mask: 0x00ff_00ff,
    }),
    primitive: Object.freeze({
      cullMode: "back",
      frontFace: "cw",
      stripIndexFormat: "uint32",
      topology: "triangle-strip",
      unclippedDepth: true,
    }),
    vertex: Object.freeze({
      buffers: Object.freeze([
        Object.freeze({
          arrayStride: 16,
          attributes: Object.freeze([
            Object.freeze({ format: "float32x4", offset: 0, shaderLocation: 3 }),
          ]),
          stepMode: "vertex",
        }),
      ]),
      constants: Object.freeze({ scale: 2 }),
      entryPoint: "vs_main",
      module: renderVertexModuleWrapper,
    }),
  });
  const renderPipelineFullStateVector = renderPipelineRequestVector(
    "create-render-pipeline-full-state-request",
    renderPipelineFullStateDescriptor,
    5,
    Object.freeze({ workload: "full-descriptor-field-preservation" }),
    false,
  );
  const renderPipelineSemanticBoundaryVector = (id, mutate, predicate, index) => {
    const convertedArguments = structuredClone(
      renderPipelineCohortVectors[0].expected.convertedArguments,
    );
    mutate(convertedArguments);
    const input = renderPipelineInput(convertedArguments, index);
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(input);
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes);
    if (canonicalJson(inspected.convertedArguments) !== canonicalJson(convertedArguments)) {
      fail(`${id} did not reach the semantic boundary intact`);
    }
    return Object.freeze({
      id,
      kind: "semantic-rejection",
      operationId: createRenderPipelineOperationId,
      semanticTerminalId: "later-predicate-rejection",
      carrierProjection: renderPipelineCarrier(index),
      bytesHex: toHex(bytes),
      expected: Object.freeze({
        codegenDisposition: "encoded-for-post-decode-semantic-validation",
        failingPredicate: predicate,
        providerTokenCount: 0,
        physicalSequenceCount: 0,
      }),
    });
  };
  const renderPipelineSemanticRejections = Object.freeze([
    renderPipelineSemanticBoundaryVector(
      "create-render-pipeline-cross-device-layout-semantically-rejected",
      (descriptor) => { descriptor.layout.logicalDeviceId = "56"; },
      "authenticate-explicit-pipeline-layout-full-reference-or-validate-auto-layout-policy",
      6,
    ),
    renderPipelineSemanticBoundaryVector(
      "create-render-pipeline-cross-device-shader-semantically-rejected",
      (descriptor) => { descriptor.vertex.module.logicalDeviceId = "56"; },
      "authenticate-current-same-device-shader-module-full-references-and-creator-order",
      7,
    ),
  ]);
  const renderPipelineStructuralRejection = (id, mutate) => {
    const convertedArguments = structuredClone(
      renderPipelineCohortVectors[0].expected.convertedArguments,
    );
    mutate(convertedArguments);
    let rejection = null;
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        renderPipelineInput(convertedArguments, 8),
      );
    } catch (error) {
      rejection = error;
    }
    if (!(rejection instanceof TypeError)) {
      fail(`${id} did not reject before native payload encoding`);
    }
    return Object.freeze({
      id,
      kind: "structural-rejection",
      operationId: createRenderPipelineOperationId,
      structuralBoundary: "generated-native-request-encoder-before-bytes",
      expected: Object.freeze({
        errorName: "TypeError",
        errorMessage: rejection.message,
        encodedByteCount: 0,
        providerTokenCount: 0,
        physicalSequenceCount: 0,
      }),
    });
  };
  const renderPipelineStructuralRejections = Object.freeze([
    renderPipelineStructuralRejection(
      "create-render-pipeline-missing-write-mask-structurally-rejected",
      (descriptor) => { delete descriptor.fragment.targets[0].writeMask; },
    ),
    renderPipelineStructuralRejection(
      "create-render-pipeline-invalid-vertex-format-structurally-rejected",
      (descriptor) => {
        descriptor.vertex.buffers = [{
          arrayStride: 4,
          attributes: [{ format: "invalid", offset: 0, shaderLocation: 0 }],
          stepMode: "vertex",
        }];
      },
    ),
  ]);
  const createRenderPipelineCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createRenderPipelineOperationId,
      { kind: "none" },
    );
  if (createRenderPipelineCompletion.byteLength !== 0) {
    fail("GPUDevice.createRenderPipeline terminal receipt must have an empty payload");
  }
  const renderPipelineSuccessCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createRenderPipelineRoute.wireId,
          operation_instance_id: "80",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "39",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "40",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: renderPipelineCarrier(0).ingress_device,
          result_device: renderPipelineCarrier(0).ingress_device,
          provider_generation: "9",
          receiver: renderPipelineCarrier(0).receiver,
          target: renderPipelineCarrier(0).target,
        }),
      }),
    }),
  });
  const renderPipelineSemanticSteps = Object.freeze(
    createRenderPipelineNativeRoute.request.semanticServiceBoundary
      .requiredAfterDecode,
  );
  if (renderPipelineSemanticSteps.length !== 19) {
    fail("GPUDevice.createRenderPipeline semantic step inventory drifted");
  }

  const createCommandEncoderRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createCommandEncoderOperationId,
  );
  const createCommandEncoderRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createCommandEncoderRoute?.serviceArgumentCodec,
    );
  const createCommandEncoderCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createCommandEncoderRoute?.serviceCompletionCodec,
    );
  const createCommandEncoderNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createCommandEncoderOperationId,
    );
  if (
    !createCommandEncoderRoute ||
    !createCommandEncoderRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createCommandEncoderRequestCodec.nativeProgramPrerequisitesRepresented ||
    createCommandEncoderRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createCommandEncoderCompletionCodec ||
    !createCommandEncoderNativeRoute ||
    createCommandEncoderNativeRoute.request.catalog.wireTag !==
      createCommandEncoderRequestCodec.wireTag ||
    createCommandEncoderNativeRoute.completion.catalog.wireTag !==
      createCommandEncoderCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createCommandEncoder native codegen program is not executable from authenticated inputs",
    );
  }
  const createCommandEncoderReceiver = Object.freeze({
    kind: "GPUDevice",
    objectId: "80",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const createCommandEncoderTarget = Object.freeze({
    kind: "GPUCommandEncoder",
    objectId: "82",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const convertedCreateCommandEncoderArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      createCommandEncoderOperationId,
      [Object.freeze({ label: "corpus-encoder" })],
      wrapperAccess,
    );
  if (
    canonicalJson(convertedCreateCommandEncoderArguments) !==
      canonicalJson({ label: "corpus-encoder" })
  ) {
    fail("GPUDevice.createCommandEncoder descriptor projection drifted");
  }
  const createCommandEncoderBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      Object.freeze({
        operationId: createCommandEncoderOperationId,
        wireId: createCommandEncoderRoute.wireId,
        convertedArguments: convertedCreateCommandEncoderArguments,
        receiver: createCommandEncoderReceiver,
        target: createCommandEncoderTarget,
        capturedScopeId: "2",
        adapterOrdinal: "0",
        deviceIngressOrdinal: "3",
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
      }),
    );
  const expectedCreateCommandEncoderRequest = Object.freeze({
    receiver: createCommandEncoderReceiver,
    target: createCommandEncoderTarget,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
    convertedArguments: convertedCreateCommandEncoderArguments,
  });
  const inspectedCreateCommandEncoder =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      createCommandEncoderBytes,
    );
  if (
    canonicalJson(inspectedCreateCommandEncoder) !== canonicalJson({
      operationId: createCommandEncoderOperationId,
      codec: createCommandEncoderRequestCodec.tag,
      ...expectedCreateCommandEncoderRequest,
    })
  ) {
    fail(
      "GPUDevice.createCommandEncoder generated request does not round-trip through inspection",
    );
  }
  const createCommandEncoderCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createCommandEncoderOperationId,
      { kind: "none" },
    );
  if (createCommandEncoderCompletion.byteLength !== 0) {
    fail(
      "GPUDevice.createCommandEncoder terminal receipt must have an empty completion payload",
    );
  }
  const createCommandEncoderRequestCarrier = Object.freeze({
    operation_id: createCommandEncoderRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "13",
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUCommandEncoder,
      flags: 0,
      object_id: "82",
      object_generation: "1",
    }),
  });
  const createCommandEncoderCompletionCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createCommandEncoderRoute.wireId,
          operation_instance_id: "13",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "8",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "3",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: createCommandEncoderRequestCarrier.ingress_device,
          result_device: createCommandEncoderRequestCarrier.ingress_device,
          provider_generation: "9",
          receiver: createCommandEncoderRequestCarrier.receiver,
          target: createCommandEncoderRequestCarrier.target,
        }),
      }),
    }),
  });

  const createShaderModuleRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === createShaderModuleOperationId,
  );
  const createShaderModuleRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === createShaderModuleRoute?.serviceArgumentCodec,
    );
  const createShaderModuleCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === createShaderModuleRoute?.serviceCompletionCodec,
    );
  const createShaderModuleNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === createShaderModuleOperationId,
    );
  if (
    !createShaderModuleRoute ||
    !createShaderModuleRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !createShaderModuleRequestCodec.nativeProgramPrerequisitesRepresented ||
    createShaderModuleRequestCodec.unavailableSemanticFields.length !== 0 ||
    !createShaderModuleCompletionCodec ||
    !createShaderModuleNativeRoute ||
    createShaderModuleNativeRoute.request.catalog.wireTag !==
      createShaderModuleRequestCodec.wireTag ||
    createShaderModuleNativeRoute.completion.catalog.wireTag !==
      createShaderModuleCompletionCodec.wireTag
  ) {
    fail(
      "GPUDevice.createShaderModule native codegen program is not executable from authenticated inputs",
    );
  }
  const createShaderModuleReceiver = Object.freeze({
    kind: "GPUDevice",
    objectId: "80",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const createShaderModuleTarget = Object.freeze({
    kind: "GPUShaderModule",
    objectId: "84",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const convertedCreateShaderModuleArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      createShaderModuleOperationId,
      [Object.freeze({ label: "corpus-shader", code: "@vertex fn main() {}" })],
      wrapperAccess,
    );
  if (
    canonicalJson(convertedCreateShaderModuleArguments) !==
      canonicalJson({ label: "corpus-shader", code: "@vertex fn main() {}" })
  ) {
    fail("GPUDevice.createShaderModule descriptor projection drifted");
  }
  const createShaderModuleBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      Object.freeze({
        operationId: createShaderModuleOperationId,
        wireId: createShaderModuleRoute.wireId,
        convertedArguments: convertedCreateShaderModuleArguments,
        receiver: createShaderModuleReceiver,
        target: createShaderModuleTarget,
        capturedScopeId: "2",
        adapterOrdinal: "0",
        deviceIngressOrdinal: "3",
        queueIngressOrdinal: "0",
        sealedLocalTimeline: Object.freeze([]),
      }),
    );
  const expectedCreateShaderModuleRequest = Object.freeze({
    receiver: createShaderModuleReceiver,
    target: createShaderModuleTarget,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: Object.freeze([]),
    convertedArguments: convertedCreateShaderModuleArguments,
  });
  const inspectedCreateShaderModule =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      createShaderModuleBytes,
    );
  if (
    canonicalJson(inspectedCreateShaderModule) !== canonicalJson({
      operationId: createShaderModuleOperationId,
      codec: createShaderModuleRequestCodec.tag,
      ...expectedCreateShaderModuleRequest,
    })
  ) {
    fail(
      "GPUDevice.createShaderModule generated request does not round-trip through inspection",
    );
  }
  const createShaderModuleCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      createShaderModuleOperationId,
      { kind: "none" },
    );
  if (createShaderModuleCompletion.byteLength !== 0) {
    fail(
      "GPUDevice.createShaderModule terminal receipt must have an empty completion payload",
    );
  }
  const createShaderModuleRequestCarrier = Object.freeze({
    operation_id: createShaderModuleRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "14",
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "80",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUShaderModule,
      flags: 0,
      object_id: "84",
      object_generation: "1",
    }),
  });
  const createShaderModuleCompletionCarrier = Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: createShaderModuleRoute.wireId,
          operation_instance_id: "14",
          promise_id: "0",
          provider_admission: 1,
          physical_sequence: "9",
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "3",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: createShaderModuleRequestCarrier.ingress_device,
          result_device: createShaderModuleRequestCarrier.ingress_device,
          provider_generation: "9",
          receiver: createShaderModuleRequestCarrier.receiver,
          target: createShaderModuleRequestCarrier.target,
        }),
      }),
    }),
  });

  const deviceDestroyRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === deviceDestroyOperationId,
  );
  const deviceDestroyLocalRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === "GPURenderPassEncoder.draw",
  );
  if (
    !deviceDestroyRoute ||
    !deviceDestroyLocalRoute ||
    deviceDestroyLocalRoute.operationInstanceIdentity !==
      "wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record"
  ) {
    fail(`${deviceDestroyOperationId} is absent from the generated production plan`);
  }
  const deviceDestroyRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === deviceDestroyRoute.serviceArgumentCodec,
    );
  const deviceDestroyCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) => candidate.tag === deviceDestroyRoute.serviceCompletionCodec,
    );
  const deviceDestroyNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === deviceDestroyOperationId,
    );
  if (
    !deviceDestroyRequestCodec?.executableFromCurrentAuthenticatedInputs ||
    !deviceDestroyRequestCodec.nativeProgramPrerequisitesRepresented ||
    deviceDestroyRequestCodec.unavailableSemanticFields.length !== 0 ||
    !deviceDestroyCompletionCodec ||
    !deviceDestroyNativeRoute ||
    deviceDestroyNativeRoute.request.catalog.wireTag !==
      deviceDestroyRequestCodec.wireTag ||
    deviceDestroyNativeRoute.completion.catalog.wireTag !==
      deviceDestroyCompletionCodec.wireTag
  ) {
    fail("GPUDevice.destroy native codegen program is not executable from authenticated inputs");
  }
  const deviceDestroyReceiver = Object.freeze({
    kind: "GPUDevice",
    objectId: "81",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const deviceDestroyLocalReceiver = Object.freeze({
    kind: "GPURenderPassEncoder",
    objectId: "91",
    objectGeneration: "4",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const deviceDestroyTimeline = Object.freeze([
    Object.freeze({
      operationId: deviceDestroyLocalRoute.wireId,
      operationName: deviceDestroyLocalRoute.operationId,
      operationInstanceId: "12",
      deviceIngressOrdinal: "2",
      capturedScopeId: "2",
      receiverRef: deviceDestroyLocalReceiver,
      wrapperAllocatedTargetRef: null,
      argumentBody: Object.freeze({
        vertexCount: 3,
        instanceCount: 1,
        firstVertex: 0,
        firstInstance: 0,
      }),
      logicalError: null,
    }),
  ]);
  const convertedDeviceDestroyArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      deviceDestroyOperationId,
      [],
      wrapperAccess,
    );
  if (convertedDeviceDestroyArguments !== null) {
    fail("GPUDevice.destroy none-v1 argument projection drifted");
  }
  const deviceDestroyBytes =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      Object.freeze({
        operationId: deviceDestroyOperationId,
        wireId: deviceDestroyRoute.wireId,
        convertedArguments: convertedDeviceDestroyArguments,
        receiver: deviceDestroyReceiver,
        capturedScopeId: "2",
        adapterOrdinal: "0",
        deviceIngressOrdinal: "3",
        queueIngressOrdinal: "0",
        sealedLocalTimeline: deviceDestroyTimeline,
      }),
    );
  const expectedDeviceDestroyRequest = {
    receiver: deviceDestroyReceiver,
    target: null,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: deviceDestroyTimeline,
    convertedArguments: null,
  };
  const inspectedDeviceDestroy =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      deviceDestroyBytes,
    );
  if (
    canonicalJson(inspectedDeviceDestroy) !== canonicalJson({
      operationId: deviceDestroyOperationId,
      codec: deviceDestroyRequestCodec.tag,
      ...expectedDeviceDestroyRequest,
    })
  ) {
    fail("GPUDevice.destroy generated request does not round-trip through inspection");
  }
  const deviceDestroyCompletion =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      deviceDestroyOperationId,
      { kind: "none" },
    );
  if (deviceDestroyCompletion.byteLength !== 0) {
    fail("GPUDevice.destroy terminal receipt must have an empty completion payload");
  }
  const deviceDestroyRequestCarrier = Object.freeze({
    operation_id: deviceDestroyRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "13",
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
      flags: 0,
      object_id: "81",
      object_generation: "2",
    }),
    target: Object.freeze({
      kind: 0,
      flags: 0,
      object_id: "0",
      object_generation: "0",
    }),
  });
  const deviceDestroyCompletionCarrier = (
    providerAdmission,
    physicalSequence,
  ) => ({
    kind: 1,
    record: {
      operation_result: {
        result_kind: 0,
        status: 0,
        operation: {
          operation_id: deviceDestroyRoute.wireId,
          operation_instance_id: "13",
          promise_id: "0",
          provider_admission: providerAdmission,
          physical_sequence: physicalSequence,
          captured_scope_id: "2",
          adapter_ordinal: "0",
          device_ingress_ordinal: "3",
          queue_ingress_ordinal: "0",
          device_transition: 0,
          ingress_device: deviceDestroyRequestCarrier.ingress_device,
          result_device: deviceDestroyRequestCarrier.ingress_device,
          provider_generation: "9",
          receiver: deviceDestroyRequestCarrier.receiver,
          target: deviceDestroyRequestCarrier.target,
        },
      },
    },
  });

  const lifecycleOperationIds = [
    bufferDestroyOperationId,
    bufferMapAsyncOperationId,
    bufferUnmapOperationId,
  ];
  const lifecycleRoutes = new Map();
  for (const lifecycleOperationId of lifecycleOperationIds) {
    const lifecycleRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === lifecycleOperationId,
    );
    const lifecycleNativeRoute =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
        (candidate) => candidate.operationId === lifecycleOperationId,
      );
    const lifecycleRequestCodec =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
        (candidate) => candidate.tag === lifecycleRoute?.serviceArgumentCodec,
      );
    const lifecycleCompletionCodec =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
        (candidate) => candidate.tag === lifecycleRoute?.serviceCompletionCodec,
      );
    if (
      !lifecycleRoute ||
      !lifecycleNativeRoute ||
      !lifecycleRequestCodec?.nativeProgramPrerequisitesRepresented ||
      !lifecycleRequestCodec.executableFromCurrentAuthenticatedInputs ||
      lifecycleRequestCodec.unavailableSemanticFields.length !== 0 ||
      !lifecycleCompletionCodec ||
      lifecycleNativeRoute.request.catalog.wireTag !==
        lifecycleRequestCodec.wireTag ||
      lifecycleNativeRoute.completion.catalog.wireTag !==
        lifecycleCompletionCodec.wireTag
    ) {
      fail(`${lifecycleOperationId} lifecycle codec route is not executable`);
    }
    lifecycleRoutes.set(lifecycleOperationId, Object.freeze({
      route: lifecycleRoute,
      nativeRoute: lifecycleNativeRoute,
      requestCodec: lifecycleRequestCodec,
      completionCodec: lifecycleCompletionCodec,
    }));
  }
  const bufferReceiver = Object.freeze({
    kind: "GPUBuffer",
    objectId: "101",
    objectGeneration: "3",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const convertedBufferDestroyArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      bufferDestroyOperationId,
      [],
      wrapperAccess,
    );
  const convertedBufferUnmapArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      bufferUnmapOperationId,
      [],
      wrapperAccess,
    );
  const convertedMapReadArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      bufferMapAsyncOperationId,
      [1, 0],
      wrapperAccess,
    );
  const convertedMapWriteArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      bufferMapAsyncOperationId,
      [2, 16, 4],
      wrapperAccess,
    );
  if (
    convertedBufferDestroyArguments !== null ||
    convertedBufferUnmapArguments !== null ||
    canonicalJson(convertedMapReadArguments) !==
      canonicalJson({ mode: 1, offset: 0 }) ||
    canonicalJson(convertedMapWriteArguments) !==
      canonicalJson({ mode: 2, offset: 16, size: 4 })
  ) {
    fail("GPUBuffer lifecycle public conversion projection drifted");
  }
  const encodeLifecycleRequest = (
    lifecycleOperationId,
    convertedArguments,
    bufferLifecycle,
  ) => {
    const metadata = lifecycleRoutes.get(lifecycleOperationId);
    const input = Object.freeze({
      operationId: lifecycleOperationId,
      wireId: metadata.route.wireId,
      convertedArguments,
      receiver: bufferReceiver,
      capturedScopeId: "2",
      adapterOrdinal: "0",
      deviceIngressOrdinal: "3",
      queueIngressOrdinal: "0",
      sealedLocalTimeline: Object.freeze([]),
      bufferLifecycle,
    });
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    const productionBytes = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input);
    if (toHex(bytes) !== toHex(productionBytes)) {
      fail(`${lifecycleOperationId} production and codegen request bytes differ`);
    }
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(bytes);
    return Object.freeze({ metadata, bytes, inspected });
  };
  const emptyCleanupBody = Object.freeze({
    kind: "cleanup-v1",
    cleanupAction: 0,
    cleanupGeneration: "0",
    cancelledMapGeneration: "0",
    activeMapGeneration: "0",
    activeMapMode: 0,
    mappedOffset: "0",
    mappedSize: "0",
    writeback: new Uint8Array(0),
  });
  const destroyWriteBody = Object.freeze({
    kind: "cleanup-v1",
    cleanupAction: 2,
    cleanupGeneration: "7",
    cancelledMapGeneration: "6",
    activeMapGeneration: "5",
    activeMapMode: 2,
    mappedOffset: "16",
    mappedSize: "4",
    writeback: Uint8Array.from([1, 2, 3, 4]),
  });
  const unmapReadBody = Object.freeze({
    kind: "cleanup-v1",
    cleanupAction: 1,
    cleanupGeneration: "10",
    cancelledMapGeneration: "9",
    activeMapGeneration: "8",
    activeMapMode: 1,
    mappedOffset: "0",
    mappedSize: "4",
    writeback: new Uint8Array(0),
  });
  const unmapWriteBody = Object.freeze({
    kind: "cleanup-v1",
    cleanupAction: 1,
    cleanupGeneration: "11",
    cancelledMapGeneration: "0",
    activeMapGeneration: "9",
    activeMapMode: 2,
    mappedOffset: "16",
    mappedSize: "4",
    writeback: Uint8Array.from([5, 6, 7, 8]),
  });
  const mapReadBody = Object.freeze({
    kind: "map-async-v1",
    pendingMapGeneration: "8",
    mode: 1,
    offset: "0",
    requestedSizePresent: 0,
    requestedSize: "0",
  });
  const mapWriteBody = Object.freeze({
    kind: "map-async-v1",
    pendingMapGeneration: "9",
    mode: 2,
    offset: "16",
    requestedSizePresent: 1,
    requestedSize: "4",
  });
  const lifecycleRequests = Object.freeze([
    ["buffer-destroy-noop-request", bufferDestroyOperationId,
      convertedBufferDestroyArguments, emptyCleanupBody],
    ["buffer-destroy-map-write-request", bufferDestroyOperationId,
      convertedBufferDestroyArguments, destroyWriteBody],
    ["buffer-map-async-read-omitted-size-request", bufferMapAsyncOperationId,
      convertedMapReadArguments, mapReadBody],
    ["buffer-map-async-write-present-size-request", bufferMapAsyncOperationId,
      convertedMapWriteArguments, mapWriteBody],
    ["buffer-unmap-noop-request", bufferUnmapOperationId,
      convertedBufferUnmapArguments, emptyCleanupBody],
    ["buffer-unmap-map-read-request", bufferUnmapOperationId,
      convertedBufferUnmapArguments, unmapReadBody],
    ["buffer-unmap-map-write-request", bufferUnmapOperationId,
      convertedBufferUnmapArguments, unmapWriteBody],
  ].map(([id, lifecycleOperationId, convertedArguments, body]) => {
    const encoded = encodeLifecycleRequest(
      lifecycleOperationId,
      convertedArguments,
      body,
    );
    return Object.freeze({ id, operationId: lifecycleOperationId, body, ...encoded });
  }));
  const requestById = new Map(lifecycleRequests.map((entry) => [entry.id, entry]));
  const mapCompletionInputs = Object.freeze([
    Object.freeze({
      kind: "buffer-map",
      variant: "mapped-bytes",
      pendingMapGeneration: "8",
      mode: 1,
      offset: "0",
      size: "4",
      ownedBytes: Uint8Array.from([9, 10, 11, 12]),
    }),
    ...["provider-operation-error", "allocation-range-error", "late-cancelled-cleanup"]
      .map((variant) => Object.freeze({
        kind: "buffer-map",
        variant,
        pendingMapGeneration: "9",
        mode: 2,
        offset: "16",
        size: "4",
        ownedBytes: new Uint8Array(0),
      })),
  ]);
  const mapCompletions = mapCompletionInputs.map((result) => Object.freeze({
    result,
    bytes: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      bufferMapAsyncOperationId,
      result,
    ),
  }));
  const cleanupTerminalBytes = new Map([
    ...["repeat-cleanup-noop", "first-cleanup-rejection", "first-cleanup-provider"]
      .map((terminal) => [
        `${bufferDestroyOperationId}:${terminal}`,
        WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
          bufferDestroyOperationId,
          { kind: "buffer-cleanup", terminal },
        ),
      ]),
    ...["unmapped-noop", "cleanup-rejection", "cleanup-provider"]
      .map((terminal) => [
        `${bufferUnmapOperationId}:${terminal}`,
        WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
          bufferUnmapOperationId,
          { kind: "buffer-cleanup", terminal },
        ),
      ]),
  ]);
  if ([...cleanupTerminalBytes.values()].some((bytes) => bytes.byteLength !== 0)) {
    fail("GPUBuffer cleanup terminals must encode empty receipt payloads");
  }
  const lifecycleRequestCarrier = (entry, promiseId = "0") => Object.freeze({
    operation_id: entry.metadata.route.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "31",
    promise_id: promiseId,
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "0",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUBuffer,
      flags: 0,
      object_id: "101",
      object_generation: "3",
    }),
    target: Object.freeze({
      kind: 0,
      flags: 0,
      object_id: "0",
      object_generation: "0",
    }),
  });
  const lifecycleCompletionCarrier = (
    entry,
    resultKind,
    promiseId,
    providerAdmission,
    physicalSequence,
  ) => {
    const requestCarrier = lifecycleRequestCarrier(entry, promiseId);
    return Object.freeze({
      kind: 1,
      record: Object.freeze({
        operation_result: Object.freeze({
          result_kind: resultKind,
          status: 0,
          operation: Object.freeze({
            operation_id: requestCarrier.operation_id,
            operation_instance_id: requestCarrier.operation_instance_id,
            promise_id: promiseId,
            provider_admission: providerAdmission,
            physical_sequence: physicalSequence,
            captured_scope_id: requestCarrier.captured_scope_id,
            adapter_ordinal: requestCarrier.adapter_ordinal,
            device_ingress_ordinal: requestCarrier.device_ingress_ordinal,
            queue_ingress_ordinal: requestCarrier.queue_ingress_ordinal,
            device_transition: 0,
            ingress_device: requestCarrier.ingress_device,
            result_device: requestCarrier.ingress_device,
            provider_generation: requestCarrier.provider_generation,
            receiver: requestCarrier.receiver,
            target: requestCarrier.target,
          }),
        }),
      }),
    });
  };
  const mappedCompletion = mapCompletions[0].bytes;
  const lifecycleBinaryRejections = Object.freeze([
    {
      id: "buffer-destroy-request-truncated-rejected",
      operationId: bufferDestroyOperationId,
      direction: "request",
      mutation: "truncate-final-writeback-byte",
      bytes: requestById.get("buffer-destroy-map-write-request").bytes.slice(0, -1),
    },
    {
      id: "buffer-destroy-request-trailing-byte-rejected",
      operationId: bufferDestroyOperationId,
      direction: "request",
      mutation: "append-trailing-byte",
      bytes: withTrailingByte(requestById.get("buffer-destroy-noop-request").bytes),
    },
    {
      id: "buffer-destroy-request-owned-byte-bound-rejected",
      operationId: bufferDestroyOperationId,
      direction: "request",
      mutation: "owned-byte-length-max-plus-one",
      bytes: mutatedBytes(
        requestById.get("buffer-destroy-map-write-request").bytes,
        (_bytes, view) => {
          view.setUint32(131, WEBGPU_EXECUTABLE_CODEC_MANIFEST.maxPayloadBytes + 1, true);
          view.setUint32(135, 0, true);
        },
      ),
    },
    {
      id: "buffer-destroy-request-map-read-writeback-rejected",
      operationId: bufferDestroyOperationId,
      direction: "request",
      mutation: "change-map-write-mode-to-read-with-owned-bytes",
      bytes: mutatedBytes(
        requestById.get("buffer-destroy-map-write-request").bytes,
        (_bytes, view) => view.setUint32(111, 1, true),
      ),
    },
    {
      id: "buffer-map-async-request-invalid-mode-rejected",
      operationId: bufferMapAsyncOperationId,
      direction: "request",
      mutation: "mode-zero",
      bytes: mutatedBytes(
        requestById.get("buffer-map-async-read-omitted-size-request").bytes,
        (_bytes, view) => view.setUint32(94, 0, true),
      ),
    },
    {
      id: "buffer-map-async-result-unknown-variant-rejected",
      operationId: bufferMapAsyncOperationId,
      direction: "completion",
      mutation: "variant-zero",
      bytes: mutatedBytes(mappedCompletion, (bytes) => { bytes[12] = 0; }),
    },
    {
      id: "buffer-map-async-result-size-mismatch-rejected",
      operationId: bufferMapAsyncOperationId,
      direction: "completion",
      mutation: "mapped-size-five-for-four-owned-bytes",
      bytes: mutatedBytes(
        mappedCompletion,
        (_bytes, view) => {
          view.setUint32(33, 5, true);
          view.setUint32(37, 0, true);
        },
      ),
    },
    {
      id: "buffer-map-async-result-truncated-rejected",
      operationId: bufferMapAsyncOperationId,
      direction: "completion",
      mutation: "truncate-final-owned-byte",
      bytes: mappedCompletion.slice(0, -1),
    },
    {
      id: "buffer-map-async-result-trailing-byte-rejected",
      operationId: bufferMapAsyncOperationId,
      direction: "completion",
      mutation: "append-trailing-byte",
      bytes: withTrailingByte(mappedCompletion),
    },
  ]);

  const canvasLifecycleOperationIds = [
    canvasConfigureOperationId,
    canvasUnconfigureOperationId,
    textureDestroyOperationId,
  ];
  const canvasLifecycleRoutes = new Map();
  for (const canvasOperationId of canvasLifecycleOperationIds) {
    const canvasRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === canvasOperationId,
    );
    const canvasNativeRoute =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
        (candidate) => candidate.operationId === canvasOperationId,
      );
    const canvasRequestCodec =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
        (candidate) => candidate.tag === canvasRoute?.serviceArgumentCodec,
      );
    const canvasCompletionCodec =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
        (candidate) => candidate.tag === canvasRoute?.serviceCompletionCodec,
      );
    if (
      !canvasRoute ||
      !canvasNativeRoute ||
      !canvasRequestCodec?.nativeProgramPrerequisitesRepresented ||
      !canvasRequestCodec.executableFromCurrentAuthenticatedInputs ||
      canvasRequestCodec.unavailableSemanticFields.length !== 0 ||
      !canvasCompletionCodec ||
      canvasNativeRoute.request.catalog.wireTag !== canvasRequestCodec.wireTag ||
      canvasNativeRoute.completion.catalog.wireTag !==
        canvasCompletionCodec.wireTag
    ) {
      fail(`${canvasOperationId} canvas lifecycle codec route is not executable`);
    }
    canvasLifecycleRoutes.set(canvasOperationId, Object.freeze({
      route: canvasRoute,
      nativeRoute: canvasNativeRoute,
      requestCodec: canvasRequestCodec,
      completionCodec: canvasCompletionCodec,
    }));
  }
  const canvasDeviceBrand = Object.freeze({ corpusBrand: "GPUDevice" });
  const canvasDeviceRef = Object.freeze({
    kind: "GPUDevice",
    objectId: "140",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const canvasContextRef = Object.freeze({
    kind: "GPUCanvasContext",
    objectId: "141",
    objectGeneration: "2",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const canvasTextureRef = Object.freeze({
    kind: "GPUTexture",
    objectId: "142",
    objectGeneration: "1",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const canvasWrapperAccess = Object.freeze({
    referenceIfBranded(value, expectedKind) {
      return value === canvasDeviceBrand && expectedKind === "GPUDevice"
        ? canvasDeviceRef
        : undefined;
    },
    reference(value, expectedKind) {
      if (value !== canvasDeviceBrand || expectedKind !== "GPUDevice") {
        throw new TypeError("wrong WebGPU object brand");
      }
      return canvasDeviceRef;
    },
  });
  const convertedCanvasConfigureDefaults =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      canvasConfigureOperationId,
      [Object.freeze({ device: canvasDeviceBrand, format: "bgra8unorm" })],
      canvasWrapperAccess,
    );
  const convertedCanvasConfigure =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      canvasConfigureOperationId,
      [Object.freeze({
        alphaMode: "premultiplied",
        colorSpace: "display-p3",
        device: canvasDeviceBrand,
        format: "bgra8unorm",
        toneMapping: Object.freeze({ mode: "standard" }),
        usage: 17,
        viewFormats: Object.freeze(["rgba8unorm", "rgba8unorm"]),
      })],
      canvasWrapperAccess,
    );
  const convertedCanvasExtendedToneMapping =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      canvasConfigureOperationId,
      [Object.freeze({
        device: canvasDeviceBrand,
        format: "bgra8unorm",
        toneMapping: Object.freeze({ mode: "extended" }),
      })],
      canvasWrapperAccess,
    );
  const convertedCanvasUnconfigure =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      canvasUnconfigureOperationId,
      [],
      canvasWrapperAccess,
    );
  const convertedTextureDestroy =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      textureDestroyOperationId,
      [],
      canvasWrapperAccess,
    );
  if (
    convertedCanvasUnconfigure !== null ||
    convertedTextureDestroy !== null ||
    convertedCanvasConfigureDefaults.format !== "bgra8unorm" ||
    convertedCanvasConfigureDefaults.usage !== 16 ||
    convertedCanvasConfigureDefaults.viewFormats.length !== 0 ||
    convertedCanvasConfigureDefaults.alphaMode !== "opaque" ||
    convertedCanvasConfigureDefaults.colorSpace !== "srgb" ||
    convertedCanvasConfigureDefaults.toneMapping.mode !== "standard" ||
    convertedCanvasConfigure.format !== "bgra8unorm" ||
    convertedCanvasConfigure.usage !== 17 ||
    JSON.stringify(convertedCanvasConfigure.viewFormats) !==
      JSON.stringify(["rgba8unorm", "rgba8unorm"]) ||
    convertedCanvasConfigure.alphaMode !== "premultiplied" ||
    convertedCanvasConfigure.colorSpace !== "display-p3" ||
    convertedCanvasConfigure.toneMapping.mode !== "standard" ||
    convertedCanvasExtendedToneMapping.toneMapping.mode !== "extended"
  ) {
    fail("canvas lifecycle public conversion projection drifted");
  }
  const canvasTargetAuthorityDigest = "ab".repeat(32);
  const canvasConfigureBody = Object.freeze({
    kind: "canvas-configure-v1",
    receiverContextRef: canvasContextRef,
    attachmentGeneration: "3",
    contextGeneration: "5",
    configurationGeneration: "8",
    configuredDeviceRef: canvasDeviceRef,
    format: "bgra8unorm",
    usage: 17,
    viewFormats: Object.freeze(["rgba8unorm", "rgba8unorm"]),
    alphaMode: "premultiplied",
    colorSpace: "display-p3",
    toneMappingMode: "standard",
    targetAuthorityDigest: canvasTargetAuthorityDigest,
    surfaceAccountToken: "19",
    surfaceAccountGeneration: "23",
  });
  const canvasUnconfigureBody = Object.freeze({
    kind: "canvas-unconfigure-v1",
    receiverContextRef: canvasContextRef,
    attachmentGeneration: "3",
    contextGeneration: "5",
    configurationGeneration: "8",
    terminalIntent: "first-cleanup",
    targetAuthorityDigest: canvasTargetAuthorityDigest,
    surfaceAccountToken: "19",
    surfaceAccountGeneration: "23",
  });
  const canvasTextureOriginDigest =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.deriveTextureOriginDigest(
      Object.freeze({
        originClass: "canvas-current",
        receiverTextureRef: canvasTextureRef,
        contextRef: canvasContextRef,
        attachmentGeneration: "3",
        contextGeneration: "5",
        configurationGeneration: "8",
        currentEpoch: "13",
        mintOperationProvenance: Object.freeze({
          operationInstanceId: "61",
          deviceIngressOrdinal: "29",
        }),
        configuredDeviceRef: canvasDeviceRef,
        format: "bgra8unorm",
        usage: 17,
        alphaMode: "premultiplied",
        colorSpace: "display-p3",
        targetAuthorityDigest: canvasTargetAuthorityDigest,
        surfaceAccountToken: "19",
        surfaceAccountGeneration: "23",
      }),
    );
  const canvasDestroyCurrentOrigin = Object.freeze({
    kind: "canvas-current-v1",
    contextRef: canvasContextRef,
    attachmentGeneration: "3",
    contextGeneration: "5",
    configurationGeneration: "8",
    currentEpoch: "13",
    mintOperationProvenance: Object.freeze({
      operationInstanceId: "61",
      deviceIngressOrdinal: "29",
    }),
    textureOriginDigest: canvasTextureOriginDigest,
  });
  const textureDestroyBody = (
    terminalIntent,
    materializationState,
    origin,
  ) => Object.freeze({
    kind: "texture-destroy-v1",
    receiverTextureRef: canvasTextureRef,
    terminalIntent,
    materializationState,
    origin,
  });
  const encodeCanvasLifecycleRequest = (
    canvasOperationId,
    receiver,
    convertedArguments,
    canvasService,
  ) => {
    const metadata = canvasLifecycleRoutes.get(canvasOperationId);
    const input = Object.freeze({
      operationId: canvasOperationId,
      wireId: metadata.route.wireId,
      convertedArguments,
      receiver,
      capturedScopeId: "2",
      adapterOrdinal: "0",
      deviceIngressOrdinal: "30",
      queueIngressOrdinal: "0",
      sealedLocalTimeline: Object.freeze([]),
      canvasService,
    });
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    const productionBytes = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input);
    if (toHex(bytes) !== toHex(productionBytes)) {
      fail(`${canvasOperationId} production and codegen request bytes differ`);
    }
    return Object.freeze({
      metadata,
      bytes,
      inspected: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(bytes),
    });
  };
  const canvasLifecycleRequests = Object.freeze([
    Object.freeze({
      id: "canvas-configure-next-generation-request",
      operationId: canvasConfigureOperationId,
      encoded: encodeCanvasLifecycleRequest(
        canvasConfigureOperationId,
        canvasContextRef,
        convertedCanvasConfigure,
        canvasConfigureBody,
      ),
    }),
    Object.freeze({
      id: "canvas-unconfigure-retiring-generation-request",
      operationId: canvasUnconfigureOperationId,
      encoded: encodeCanvasLifecycleRequest(
        canvasUnconfigureOperationId,
        canvasContextRef,
        convertedCanvasUnconfigure,
        canvasUnconfigureBody,
      ),
    }),
    Object.freeze({
      id: "texture-destroy-device-created-first-cleanup-request",
      operationId: textureDestroyOperationId,
      encoded: encodeCanvasLifecycleRequest(
        textureDestroyOperationId,
        canvasTextureRef,
        convertedTextureDestroy,
        textureDestroyBody(
          "first-cleanup",
          "unmaterialized",
          Object.freeze({ kind: "device-created-v1" }),
        ),
      ),
    }),
    Object.freeze({
      id: "texture-destroy-expired-canvas-current-request",
      operationId: textureDestroyOperationId,
      encoded: encodeCanvasLifecycleRequest(
        textureDestroyOperationId,
        canvasTextureRef,
        convertedTextureDestroy,
        textureDestroyBody(
          "first-expired-cleanup",
          "materialized",
          canvasDestroyCurrentOrigin,
        ),
      ),
    }),
    Object.freeze({
      id: "texture-destroy-repeat-cleanup-noop-request",
      operationId: textureDestroyOperationId,
      encoded: encodeCanvasLifecycleRequest(
        textureDestroyOperationId,
        canvasTextureRef,
        convertedTextureDestroy,
        textureDestroyBody(
          "repeat-cleanup-noop",
          "materialized",
          canvasDestroyCurrentOrigin,
        ),
      ),
    }),
  ]);
  const canvasRequestById = new Map(
    canvasLifecycleRequests.map((entry) => [entry.id, entry]),
  );
  const canvasTerminalBytes = new Map([
    [
      `${canvasConfigureOperationId}:operation-success`,
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        canvasConfigureOperationId,
        { kind: "canvas-terminal", terminal: "operation-success" },
      ),
    ],
    [
      `${canvasUnconfigureOperationId}:first-cleanup-provider`,
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        canvasUnconfigureOperationId,
        { kind: "canvas-terminal", terminal: "first-cleanup-provider" },
      ),
    ],
    ...["repeat-cleanup-noop", "first-cleanup-provider"].map((terminal) => [
      `${textureDestroyOperationId}:${terminal}`,
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        textureDestroyOperationId,
        { kind: "canvas-terminal", terminal },
      ),
    ]),
  ]);
  if ([...canvasTerminalBytes.values()].some((bytes) => bytes.byteLength !== 0)) {
    fail("canvas lifecycle terminals must encode empty receipt payloads");
  }
  const canvasRequestCarrier = (entry) => {
    const receiver = entry.operationId === textureDestroyOperationId
      ? canvasTextureRef
      : canvasContextRef;
    return Object.freeze({
      operation_id: entry.encoded.metadata.route.wireId,
      flags: 0,
      topology_id:
        WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
          .providerTopologyId,
      ingress_device: Object.freeze({
        logical_device_id: "55",
        logical_device_generation: "1",
        provider_generation: "9",
      }),
      provider_generation: "9",
      operation_instance_id: "62",
      promise_id: "0",
      captured_scope_id: "2",
      adapter_ordinal: "0",
      device_ingress_ordinal: "30",
      queue_ingress_ordinal: "0",
      receiver: Object.freeze({
        kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags[receiver.kind],
        flags: 0,
        object_id: receiver.objectId,
        object_generation: receiver.objectGeneration,
      }),
      target: Object.freeze({
        kind: 0,
        flags: 0,
        object_id: "0",
        object_generation: "0",
      }),
    });
  };
  const canvasCarrierMutationEntries = [
    canvasRequestById.get("canvas-configure-next-generation-request"),
    canvasRequestById.get("canvas-unconfigure-retiring-generation-request"),
    canvasRequestById.get("texture-destroy-expired-canvas-current-request"),
  ];
  const canvasCarrierMutationCases = Object.freeze([
    Object.freeze({
      id: "operation-id",
      field: "operation_id",
      mutate: (carrier) => ({
        ...carrier,
        operation_id: carrier.operation_id + 1,
      }),
    }),
    Object.freeze({
      id: "operation-instance-id",
      field: "operation_instance_id",
      mutate: (carrier) => ({ ...carrier, operation_instance_id: "0" }),
    }),
    Object.freeze({
      id: "captured-scope-id",
      field: "captured_scope_id",
      mutate: (carrier) => ({ ...carrier, captured_scope_id: "3" }),
    }),
    Object.freeze({
      id: "device-ingress-ordinal",
      field: "device_ingress_ordinal",
      mutate: (carrier) => ({ ...carrier, device_ingress_ordinal: "31" }),
    }),
    Object.freeze({
      id: "ingress-logical-device-id",
      field: "ingress_device.logical_device_id",
      mutate: (carrier) => ({
        ...carrier,
        ingress_device: {
          ...carrier.ingress_device,
          logical_device_id: "56",
        },
      }),
    }),
    Object.freeze({
      id: "ingress-logical-device-generation",
      field: "ingress_device.logical_device_generation",
      mutate: (carrier) => ({
        ...carrier,
        ingress_device: {
          ...carrier.ingress_device,
          logical_device_generation: "2",
        },
      }),
    }),
    Object.freeze({
      id: "ingress-provider-generation",
      field: "ingress_device.provider_generation",
      mutate: (carrier) => ({
        ...carrier,
        ingress_device: {
          ...carrier.ingress_device,
          provider_generation: "10",
        },
      }),
    }),
    Object.freeze({
      id: "operation-provider-generation",
      field: "provider_generation",
      mutate: (carrier) => ({ ...carrier, provider_generation: "10" }),
    }),
    Object.freeze({
      id: "receiver-kind",
      field: "receiver.kind",
      mutate: (carrier) => ({
        ...carrier,
        receiver: {
          ...carrier.receiver,
          kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice,
        },
      }),
    }),
    Object.freeze({
      id: "receiver-object-id",
      field: "receiver.object_id",
      mutate: (carrier) => ({
        ...carrier,
        receiver: { ...carrier.receiver, object_id: "999" },
      }),
    }),
    Object.freeze({
      id: "receiver-object-generation",
      field: "receiver.object_generation",
      mutate: (carrier) => ({
        ...carrier,
        receiver: { ...carrier.receiver, object_generation: "3" },
      }),
    }),
    Object.freeze({
      id: "non-null-target",
      field: "target",
      mutate: (carrier) => ({
        ...carrier,
        target: {
          kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUTexture,
          flags: 0,
          object_id: "142",
          object_generation: "1",
        },
      }),
    }),
  ]);
  const canvasCarrierRejections = Object.freeze(
    canvasCarrierMutationEntries.flatMap((entry) => {
      const carrier = canvasRequestCarrier(entry);
      return canvasCarrierMutationCases.map((mutation) => Object.freeze({
        id: `${entry.id}-carrier-${mutation.id}-rejected`,
        operationId: entry.operationId,
        kind: "carrier-rejection",
        carrierProjection: Object.freeze(mutation.mutate(carrier)),
        authenticatedCarrierMutation: Object.freeze({
          field: mutation.field,
          originalCarrierProjection: carrier,
        }),
        bytesHex: toHex(entry.encoded.bytes),
        expected: Object.freeze({
          rejection:
            "authenticated-carrier-mismatch-before-payload-decode-or-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        }),
      }));
    }),
  );
  const canvasCompletionCarrier = (
    entry,
    providerAdmission,
    physicalSequence,
  ) => {
    const requestCarrier = canvasRequestCarrier(entry);
    return Object.freeze({
      kind: 1,
      record: Object.freeze({
        operation_result: Object.freeze({
          result_kind: 0,
          status: 0,
          operation: Object.freeze({
            operation_id: requestCarrier.operation_id,
            operation_instance_id: requestCarrier.operation_instance_id,
            promise_id: "0",
            provider_admission: providerAdmission,
            physical_sequence: physicalSequence,
            captured_scope_id: requestCarrier.captured_scope_id,
            adapter_ordinal: requestCarrier.adapter_ordinal,
            device_ingress_ordinal: requestCarrier.device_ingress_ordinal,
            queue_ingress_ordinal: requestCarrier.queue_ingress_ordinal,
            device_transition: 0,
            ingress_device: requestCarrier.ingress_device,
            result_device: requestCarrier.ingress_device,
            provider_generation: requestCarrier.provider_generation,
            receiver: requestCarrier.receiver,
            target: requestCarrier.target,
          }),
        }),
      }),
    });
  };
  const configureBytes = canvasRequestById.get(
    "canvas-configure-next-generation-request",
  ).encoded.bytes;
  const unconfigureBytes = canvasRequestById.get(
    "canvas-unconfigure-retiring-generation-request",
  ).encoded.bytes;
  const expiredTextureDestroyBytes = canvasRequestById.get(
    "texture-destroy-expired-canvas-current-request",
  ).encoded.bytes;
  const canvasConfigureEnumOffset = 12 + 41 + 1 + 32 + 5 + 41 + 24 +
    41 + 4 + "bgra8unorm".length + 4 + 4 +
    canvasConfigureBody.viewFormats.reduce(
      (size, format) => size + 4 + format.length,
      0,
    );
  const canvasConfigureViewFormatCountOffset =
    canvasConfigureEnumOffset -
    canvasConfigureBody.viewFormats.reduce(
      (size, format) => size + 4 + format.length,
      0,
    ) - 4;
  const canvasBinaryRejections = Object.freeze([
    ...[
      ["alpha-mode", 0],
      ["color-space", 1],
      ["tone-mapping-mode", 2],
    ].map(([name, offset]) => Object.freeze({
      id: `canvas-configure-unknown-${name}-tag-rejected`,
      operationId: canvasConfigureOperationId,
      mutation: `${name}-tag-255`,
      bytes: mutatedBytes(configureBytes, (bytes) => {
        bytes[canvasConfigureEnumOffset + offset] = 0xff;
      }),
    })),
    {
      id: "canvas-configure-view-format-count-bound-rejected",
      operationId: canvasConfigureOperationId,
      mutation: "view-format-count-max-plus-one",
      bytes: mutatedBytes(configureBytes, (_bytes, view) => {
        view.setUint32(
          canvasConfigureViewFormatCountOffset,
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount + 1,
          true,
        );
      }),
    },
    {
      id: "canvas-configure-extended-tone-mapping-body-rejected",
      operationId: canvasConfigureOperationId,
      mutation: "tone-mapping-mode-extended-tag",
      bytes: mutatedBytes(configureBytes, (bytes) => {
        bytes[canvasConfigureEnumOffset + 2] = 2;
      }),
    },
    {
      id: "canvas-unconfigure-unknown-terminal-intent-tag-rejected",
      operationId: canvasUnconfigureOperationId,
      mutation: "terminal-intent-tag-255",
      bytes: mutatedBytes(unconfigureBytes, (bytes) => { bytes[156] = 0xff; }),
    },
    ...[
      ["terminal-intent", 132],
      ["materialization", 133],
      ["origin", 134],
    ].map(([name, offset]) => Object.freeze({
      id: `texture-destroy-unknown-${name}-tag-rejected`,
      operationId: textureDestroyOperationId,
      mutation: `${name}-tag-255`,
      bytes: mutatedBytes(expiredTextureDestroyBytes, (bytes) => {
        bytes[offset] = 0xff;
      }),
    })),
    {
      id: "texture-destroy-request-truncated-rejected",
      operationId: textureDestroyOperationId,
      mutation: "truncate-final-origin-digest-byte",
      bytes: expiredTextureDestroyBytes.slice(0, -1),
    },
    {
      id: "texture-destroy-request-trailing-byte-rejected",
      operationId: textureDestroyOperationId,
      mutation: "append-trailing-byte",
      bytes: withTrailingByte(expiredTextureDestroyBytes),
    },
  ]);
  for (const rejection of canvasBinaryRejections) {
    let rejected = false;
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(rejection.bytes);
    } catch {
      rejected = true;
    }
    if (!rejected) fail(`${rejection.id} did not fail closed`);
  }

  const queueWriteBufferRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === queueWriteBufferOperationId,
  );
  const queueWriteBufferNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === queueWriteBufferOperationId,
    );
  const queueWriteBufferRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === queueWriteBufferRoute?.serviceArgumentCodec,
    );
  const queueWriteBufferCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === queueWriteBufferRoute?.serviceCompletionCodec,
    );
  const queueWriteTextureRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === queueWriteTextureOperationId,
  );
  const queueWriteTextureNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === queueWriteTextureOperationId,
    );
  const queueWriteTextureRequestCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === queueWriteTextureRoute?.serviceArgumentCodec,
    );
  const queueWriteTextureCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === queueWriteTextureRoute?.serviceCompletionCodec,
    );
  const queueSubmitCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
    (candidate) =>
      candidate.tag ===
        "gpu-sealed-command-program-sequence-service-request-v1",
  );
  const queueSubmitRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === queueSubmitOperationId,
  );
  const queueSubmitNativeRoute =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (candidate) => candidate.operationId === queueSubmitOperationId,
    );
  const queueSubmitCompletionCodec =
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.find(
      (candidate) =>
        candidate.tag === queueSubmitRoute?.serviceCompletionCodec,
    );
  if (
    !queueWriteBufferRoute ||
    !queueWriteBufferNativeRoute ||
    !queueWriteBufferRequestCodec?.nativeProgramPrerequisitesRepresented ||
    !queueWriteBufferRequestCodec.executableFromCurrentAuthenticatedInputs ||
    queueWriteBufferRequestCodec.unavailableSemanticFields.length !== 0 ||
    !queueWriteBufferCompletionCodec ||
    queueWriteBufferRequestCodec.wireTag !== 23 ||
    queueWriteBufferNativeRoute.request.catalog.wireTag !== 23 ||
    queueWriteBufferNativeRoute.completion.catalog.wireTag !==
      queueWriteBufferCompletionCodec.wireTag ||
    !queueWriteTextureRoute ||
    !queueWriteTextureNativeRoute ||
    !queueWriteTextureRequestCodec?.nativeProgramPrerequisitesRepresented ||
    !queueWriteTextureRequestCodec.executableFromCurrentAuthenticatedInputs ||
    queueWriteTextureRequestCodec.unavailableSemanticFields.length !== 0 ||
    !queueWriteTextureCompletionCodec ||
    queueWriteTextureRequestCodec.wireTag !== 25 ||
    queueWriteTextureNativeRoute.request.catalog.wireTag !== 25 ||
    queueWriteTextureNativeRoute.completion.catalog.wireTag !==
      queueWriteTextureCompletionCodec.wireTag ||
    !queueSubmitRoute ||
    !queueSubmitNativeRoute ||
    !queueSubmitCodec?.nativeProgramPrerequisitesRepresented ||
    !queueSubmitCodec.executableFromCurrentAuthenticatedInputs ||
    queueSubmitCodec.unavailableSemanticFields.length !== 0 ||
    queueSubmitCodec.wireTag !== 11 ||
    queueSubmitNativeRoute.request.catalog.wireTag !== 11 ||
    !queueSubmitCompletionCodec ||
    queueSubmitNativeRoute.completion.catalog.wireTag !==
      queueSubmitCompletionCodec.wireTag
  ) {
    fail("GPUQueue writeBuffer/writeTexture/submit native codec boundary drifted");
  }
  const queueReceiver = Object.freeze({
    kind: "GPUQueue",
    objectId: "201",
    objectGeneration: "5",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const queueDestination = Object.freeze({
    kind: "GPUBuffer",
    objectId: "202",
    objectGeneration: "6",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const queueDestinationBrand = Object.freeze({ corpusBrand: "GPUBuffer" });
  const queueTextureDestination = Object.freeze({
    kind: "GPUTexture",
    objectId: "203",
    objectGeneration: "7",
    logicalDeviceId: "55",
    logicalDeviceGeneration: "1",
    providerGeneration: "9",
  });
  const queueTextureDestinationBrand = Object.freeze({ corpusBrand: "GPUTexture" });
  const queueWrapperAccess = Object.freeze({
    referenceIfBranded(value, expectedKind) {
      if (value === queueDestinationBrand && expectedKind === "GPUBuffer") {
        return queueDestination;
      }
      if (
        value === queueTextureDestinationBrand && expectedKind === "GPUTexture"
      ) {
        return queueTextureDestination;
      }
      return undefined;
    },
    reference(value, expectedKind) {
      if (value === queueDestinationBrand && expectedKind === "GPUBuffer") {
        return queueDestination;
      }
      if (
        value === queueTextureDestinationBrand && expectedKind === "GPUTexture"
      ) {
        return queueTextureDestination;
      }
      throw new TypeError("unbranded queue upload destination");
    },
  });
  const convertQueueWriteBuffer = (
    sourceValues,
    destinationOffset,
    dataOffset,
    size,
  ) => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
    queueWriteBufferOperationId,
    [
      queueDestinationBrand,
      destinationOffset,
      Uint8Array.from(sourceValues),
      ...(dataOffset === undefined ? [] : [dataOffset]),
      ...(size === undefined ? [] : [size]),
    ],
    queueWrapperAccess,
  );
  const queueWriteBufferInput = (convertedArguments) => Object.freeze({
    operationId: queueWriteBufferOperationId,
    wireId: queueWriteBufferRoute.wireId,
    convertedArguments,
    receiver: queueReceiver,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "4",
    sealedLocalTimeline: Object.freeze([]),
  });
  const queueWriteBufferRequest = (
    id,
    sourceValues,
    destinationOffset,
    dataOffset,
    size,
  ) => {
    const codegenConverted = convertQueueWriteBuffer(
      sourceValues,
      destinationOffset,
      dataOffset,
      size,
    );
    const codegenBytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(queueWriteBufferInput(codegenConverted));
    const productionConverted = convertQueueWriteBuffer(
      sourceValues,
      destinationOffset,
      dataOffset,
      size,
    );
    const productionBytes = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(queueWriteBufferInput(productionConverted));
    if (toHex(codegenBytes) !== toHex(productionBytes)) {
      fail(`${id} production and codegen request bytes differ`);
    }
    return Object.freeze({
      id,
      bytes: codegenBytes,
      inspected: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(codegenBytes),
    });
  };
  const queueWriteBufferRequests = Object.freeze([
    queueWriteBufferRequest(
      "queue-write-buffer-zero-byte-request",
      [],
      1,
      undefined,
      undefined,
    ),
    queueWriteBufferRequest(
      "queue-write-buffer-four-byte-request",
      [1, 2, 3, 4],
      12,
      undefined,
      undefined,
    ),
    queueWriteBufferRequest(
      "queue-write-buffer-selected-snapshot-request",
      [1, 2, 3, 4, 5, 6, 7, 8],
      16,
      4,
      4,
    ),
  ]);
  const queueWriteBufferRequestById = new Map(
    queueWriteBufferRequests.map((entry) => [entry.id, entry]),
  );
  const queueWriteBufferCarrier = Object.freeze({
    operation_id: queueWriteBufferRoute.wireId,
    flags: 0,
    topology_id:
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.constants
        .providerTopologyId,
    ingress_device: Object.freeze({
      logical_device_id: "55",
      logical_device_generation: "1",
      provider_generation: "9",
    }),
    provider_generation: "9",
    operation_instance_id: "61",
    promise_id: "0",
    captured_scope_id: "2",
    adapter_ordinal: "0",
    device_ingress_ordinal: "3",
    queue_ingress_ordinal: "4",
    receiver: Object.freeze({
      kind: WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUQueue,
      flags: 0,
      object_id: "201",
      object_generation: "5",
    }),
    target: Object.freeze({
      kind: 0,
      flags: 0,
      object_id: "0",
      object_generation: "0",
    }),
  });
  const queueWriteBufferCompletionCarrier = (
    providerAdmission,
    physicalSequence,
  ) => Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: queueWriteBufferCarrier.operation_id,
          operation_instance_id: queueWriteBufferCarrier.operation_instance_id,
          promise_id: "0",
          provider_admission: providerAdmission,
          physical_sequence: physicalSequence,
          captured_scope_id: queueWriteBufferCarrier.captured_scope_id,
          adapter_ordinal: "0",
          device_ingress_ordinal:
            queueWriteBufferCarrier.device_ingress_ordinal,
          queue_ingress_ordinal: queueWriteBufferCarrier.queue_ingress_ordinal,
          device_transition: 0,
          ingress_device: queueWriteBufferCarrier.ingress_device,
          result_device: queueWriteBufferCarrier.ingress_device,
          provider_generation: "9",
          receiver: queueWriteBufferCarrier.receiver,
          target: queueWriteBufferCarrier.target,
        }),
      }),
    }),
  });
  const queueWriteBufferCompletionBytes = new Map(
    ["later-predicate-rejection", "operation-success"].map((terminal) => [
      terminal,
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        queueWriteBufferOperationId,
        { kind: "queue-write-buffer", terminal },
      ),
    ]),
  );
  if (
    [...queueWriteBufferCompletionBytes.values()].some(
      (bytes) => bytes.byteLength !== 0,
    )
  ) {
    fail("GPUQueue.writeBuffer terminals must encode empty receipt payloads");
  }
  const queueWriteBufferPositive = queueWriteBufferRequestById.get(
    "queue-write-buffer-four-byte-request",
  ).bytes;
  const queueWriteBufferBinaryRejections = Object.freeze([
    {
      id: "queue-write-buffer-request-truncated-rejected",
      mutation: "truncate-final-owned-byte",
      bytes: queueWriteBufferPositive.slice(0, -1),
    },
    {
      id: "queue-write-buffer-request-trailing-byte-rejected",
      mutation: "append-trailing-byte",
      bytes: withTrailingByte(queueWriteBufferPositive),
    },
    {
      id: "queue-write-buffer-request-destination-kind-rejected",
      mutation: "destination-kind-GPUDevice",
      bytes: mutatedBytes(queueWriteBufferPositive, (bytes) => {
        bytes[86] = WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice;
      }),
    },
    {
      id: "queue-write-buffer-request-cross-device-rejected",
      mutation: "destination-logical-device-id-differs",
      bytes: mutatedBytes(
        queueWriteBufferPositive,
        (_bytes, view) => view.setUint32(103, 56, true),
      ),
    },
    {
      id: "queue-write-buffer-request-cross-provider-rejected",
      mutation: "destination-provider-generation-differs",
      bytes: mutatedBytes(
        queueWriteBufferPositive,
        (_bytes, view) => view.setUint32(119, 10, true),
      ),
    },
    {
      id: "queue-write-buffer-request-unsafe-offset-rejected",
      mutation: "destination-offset-over-js-safe-u64",
      bytes: mutatedBytes(
        queueWriteBufferPositive,
        (_bytes, view) => view.setUint32(131, 0x0020_0000, true),
      ),
    },
    {
      id: "queue-write-buffer-request-misaligned-byte-length-rejected",
      mutation: "owned-byte-length-three",
      bytes: mutatedBytes(
        queueWriteBufferPositive,
        (_bytes, view) => view.setUint32(135, 3, true),
      ),
    },
    {
      id: "queue-write-buffer-request-owned-byte-bound-rejected",
      mutation: "owned-byte-length-exact-bound-plus-one",
      bytes: mutatedBytes(
        queueWriteBufferPositive,
        (_bytes, view) => view.setUint32(135, 16_777_074, true),
      ),
    },
  ]);

  const convertQueueWriteTexture = ({
    aspect = "all",
    bytes,
    bytesPerRow,
    mipLevel = 0,
    offset = 0,
    origin = { x: 0, y: 0, z: 0 },
    rowsPerImage,
    size,
  }) => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
    queueWriteTextureOperationId,
    [
      {
        aspect,
        mipLevel,
        origin,
        texture: queueTextureDestinationBrand,
      },
      Uint8Array.from(bytes),
      {
        offset,
        ...(bytesPerRow === undefined ? {} : { bytesPerRow }),
        ...(rowsPerImage === undefined ? {} : { rowsPerImage }),
      },
      size,
    ],
    queueWrapperAccess,
  );
  const queueWriteTextureInput = (convertedArguments) => Object.freeze({
    operationId: queueWriteTextureOperationId,
    wireId: queueWriteTextureRoute.wireId,
    convertedArguments,
    receiver: queueReceiver,
    capturedScopeId: "2",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "3",
    queueIngressOrdinal: "5",
    sealedLocalTimeline: Object.freeze([]),
  });
  const queueWriteTextureRequest = (id, options) => {
    const codegenConverted = convertQueueWriteTexture(options);
    const codegenBytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(queueWriteTextureInput(codegenConverted));
    const productionConverted = convertQueueWriteTexture(options);
    const productionBytes = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(queueWriteTextureInput(productionConverted));
    if (toHex(codegenBytes) !== toHex(productionBytes)) {
      fail(`${id} production and codegen request bytes differ`);
    }
    return Object.freeze({
      id,
      bytes: codegenBytes,
      inspected: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(codegenBytes),
    });
  };
  const queueWriteTextureRequests = Object.freeze([
    queueWriteTextureRequest("queue-write-texture-zero-byte-request", {
      bytes: [],
      size: { width: 0, height: 1, depthOrArrayLayers: 1 },
    }),
    queueWriteTextureRequest("queue-write-texture-row-request", {
      bytes: Array.from({ length: 256 }, (_value, index) => index & 0xff),
      bytesPerRow: 256,
      rowsPerImage: 1,
      size: { width: 1, height: 1, depthOrArrayLayers: 1 },
    }),
    queueWriteTextureRequest("queue-write-texture-iterable-shape-request", {
      aspect: "depth-only",
      bytes: [5, 6, 7, 8],
      mipLevel: 2,
      offset: 1,
      origin: [1, 2, 3],
      size: [1, 1, 1],
    }),
  ]);
  const queueWriteTextureRequestById = new Map(
    queueWriteTextureRequests.map((entry) => [entry.id, entry]),
  );
  const queueWriteTextureCarrier = Object.freeze({
    ...queueWriteBufferCarrier,
    operation_id: queueWriteTextureRoute.wireId,
    operation_instance_id: "63",
    queue_ingress_ordinal: "5",
  });
  const queueWriteTextureCompletionCarrier = (
    providerAdmission,
    physicalSequence,
  ) => Object.freeze({
    kind: 1,
    record: Object.freeze({
      operation_result: Object.freeze({
        result_kind: 0,
        status: 0,
        operation: Object.freeze({
          operation_id: queueWriteTextureCarrier.operation_id,
          operation_instance_id:
            queueWriteTextureCarrier.operation_instance_id,
          promise_id: "0",
          provider_admission: providerAdmission,
          physical_sequence: physicalSequence,
          captured_scope_id: queueWriteTextureCarrier.captured_scope_id,
          adapter_ordinal: "0",
          device_ingress_ordinal:
            queueWriteTextureCarrier.device_ingress_ordinal,
          queue_ingress_ordinal:
            queueWriteTextureCarrier.queue_ingress_ordinal,
          device_transition: 0,
          ingress_device: queueWriteTextureCarrier.ingress_device,
          result_device: queueWriteTextureCarrier.ingress_device,
          provider_generation: "9",
          receiver: queueWriteTextureCarrier.receiver,
          target: queueWriteTextureCarrier.target,
        }),
      }),
    }),
  });
  const queueWriteTextureCompletionBytes = new Map(
    ["later-predicate-rejection", "operation-success"].map((terminal) => [
      terminal,
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        queueWriteTextureOperationId,
        { kind: "queue-write-texture", terminal },
      ),
    ]),
  );
  if (
    [...queueWriteTextureCompletionBytes.values()].some(
      (bytes) => bytes.byteLength !== 0,
    )
  ) {
    fail("GPUQueue.writeTexture terminals must encode empty receipt payloads");
  }
  const queueWriteTexturePositive = queueWriteTextureRequestById.get(
    "queue-write-texture-row-request",
  ).bytes;
  const queueWriteTextureSemanticRejections = Object.freeze([
    {
      id: "queue-write-texture-request-cross-device-rejected",
      mutation: "destination-logical-device-id-differs",
      bytes: mutatedBytes(
        queueWriteTexturePositive,
        (_bytes, view) => view.setUint32(103, 56, true),
      ),
    },
    {
      id: "queue-write-texture-request-cross-provider-rejected",
      mutation: "destination-provider-generation-differs",
      bytes: mutatedBytes(
        queueWriteTexturePositive,
        (_bytes, view) => view.setUint32(119, 10, true),
      ),
    },
  ].map((entry) => Object.freeze({
    ...entry,
    inspected: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      entry.bytes,
    ),
  })));
  const queueWriteTextureBinaryRejections = Object.freeze([
    {
      id: "queue-write-texture-request-truncated-rejected",
      mutation: "truncate-final-owned-byte",
      bytes: queueWriteTexturePositive.slice(0, -1),
    },
    {
      id: "queue-write-texture-request-trailing-byte-rejected",
      mutation: "append-trailing-byte",
      bytes: withTrailingByte(queueWriteTexturePositive),
    },
    {
      id: "queue-write-texture-request-destination-kind-rejected",
      mutation: "destination-kind-GPUDevice",
      bytes: mutatedBytes(queueWriteTexturePositive, (bytes) => {
        bytes[86] = WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags.GPUDevice;
      }),
    },
    {
      id: "queue-write-texture-request-origin-shape-rejected",
      mutation: "origin-shape-tag-two",
      bytes: mutatedBytes(queueWriteTexturePositive, (bytes) => {
        bytes[143] = 2;
      }),
    },
    {
      id: "queue-write-texture-request-aspect-rejected",
      mutation: "aspect-tag-three",
      bytes: mutatedBytes(queueWriteTexturePositive, (bytes) => {
        bytes[148] = 3;
      }),
    },
    {
      id: "queue-write-texture-request-layout-presence-rejected",
      mutation: "bytes-per-row-absent-with-nonzero-value",
      bytes: mutatedBytes(queueWriteTexturePositive, (bytes) => {
        bytes[157] = 0;
      }),
    },
    {
      id: "queue-write-texture-request-extent-shape-rejected",
      mutation: "extent-iterable-length-zero",
      bytes: mutatedBytes(queueWriteTexturePositive, (bytes) => {
        bytes[179] = 1;
      }),
    },
    {
      id: "queue-write-texture-request-unsafe-offset-rejected",
      mutation: "data-layout-offset-over-js-safe-u64",
      bytes: mutatedBytes(
        queueWriteTexturePositive,
        (_bytes, view) => view.setUint32(153, 0x0020_0000, true),
      ),
    },
    {
      id: "queue-write-texture-request-owned-byte-bound-rejected",
      mutation: "owned-byte-length-exact-bound-plus-one",
      bytes: mutatedBytes(
        queueWriteTexturePositive,
        (_bytes, view) => view.setUint32(184, 16_777_025, true),
      ),
    },
  ]);
  for (const rejection of queueWriteTextureBinaryRejections) {
    let rejected = false;
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(rejection.bytes);
    } catch {
      rejected = true;
    }
    if (!rejected) fail(`${rejection.id} did not fail closed`);
  }

  const queueSubmitVariants = Object.freeze([
    "GPUCanvasContext.getCurrentTexture",
    "GPUCommandEncoder.beginComputePass",
    "GPUCommandEncoder.beginRenderPass",
    "GPUCommandEncoder.clearBuffer",
    "GPUCommandEncoder.copyBufferToBuffer",
    "GPUCommandEncoder.copyTextureToTexture",
    "GPUComputePassEncoder.setPipeline",
    "GPUComputePassEncoder.setBindGroup",
    "GPUComputePassEncoder.dispatchWorkgroups",
    "GPUComputePassEncoder.end",
    "GPURenderPassEncoder.setPipeline",
    "GPURenderPassEncoder.setBindGroup",
    "GPURenderPassEncoder.setVertexBuffer",
    "GPURenderPassEncoder.draw",
    "GPURenderPassEncoder.end",
    "GPUCommandEncoder.finish",
  ]);
  const stagedSubmitIdentities = new Map(
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.operations
      .map((entry) => [entry.operationId, entry]),
  );
  const activeSubmitIdentities = new Map(
    WEBGPU_PRODUCTION_PLAN.routes.map((entry) => [entry.operationId, entry]),
  );
  const promotedSubmitIdentities = new Set(
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.authenticatedPromotions.map(
      (entry) => entry.operationId,
    ),
  );
  const queueSubmitIdentity = (operationName) => {
    const staged = stagedSubmitIdentities.get(operationName);
    const active = activeSubmitIdentities.get(operationName);
    const authenticatedPromotion =
      staged !== undefined &&
      active !== undefined &&
      promotedSubmitIdentities.has(operationName);
    if (
      (staged === undefined && active === undefined) ||
      (staged !== undefined && active !== undefined && !authenticatedPromotion)
    ) {
      fail(`ambiguous queue-submit record identity: ${operationName}`);
    }
    return staged && !authenticatedPromotion
      ? Object.freeze({
          recordIdentityClass: "staged-local",
          operationId: staged.localRecordId,
          operationIdentitySha256: staged.recordIdentitySha256,
        })
      : Object.freeze({
          recordIdentityClass: "active-route",
          operationId: active.wireId,
          operationIdentitySha256: null,
        });
  };
  const submitReferences = Object.freeze({
    queue: queueReceiver,
    device: Object.freeze({
      kind: "GPUDevice",
      objectId: "207",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    adapter: Object.freeze({
      kind: "GPUAdapter",
      objectId: "208",
      objectGeneration: "1",
      logicalDeviceId: "0",
      logicalDeviceGeneration: "0",
      providerGeneration: "9",
    }),
    canvas: Object.freeze({
      kind: "GPUCanvasContext",
      objectId: "209",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    encoder: Object.freeze({
      kind: "GPUCommandEncoder",
      objectId: "210",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    computePass: Object.freeze({
      kind: "GPUComputePassEncoder",
      objectId: "211",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    renderPass: Object.freeze({
      kind: "GPURenderPassEncoder",
      objectId: "212",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    commandBuffer: Object.freeze({
      kind: "GPUCommandBuffer",
      objectId: "213",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    sourceBuffer: Object.freeze({
      kind: "GPUBuffer",
      objectId: "220",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    destinationBuffer: Object.freeze({
      kind: "GPUBuffer",
      objectId: "221",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    sourceTexture: Object.freeze({
      kind: "GPUTexture",
      objectId: "222",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    destinationTexture: Object.freeze({
      kind: "GPUTexture",
      objectId: "223",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    textureView: Object.freeze({
      kind: "GPUTextureView",
      objectId: "224",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    bindGroup: Object.freeze({
      kind: "GPUBindGroup",
      objectId: "225",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    renderPipeline: Object.freeze({
      kind: "GPURenderPipeline",
      objectId: "226",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
    computePipeline: Object.freeze({
      kind: "GPUComputePipeline",
      objectId: "227",
      objectGeneration: "1",
      logicalDeviceId: "55",
      logicalDeviceGeneration: "1",
      providerGeneration: "9",
    }),
  });
  const submitRecord = ({
    operationName,
    ingress,
    receiverRef,
    commandEncoderRef = null,
    passRef = null,
    wrapperAllocatedTargetRef = null,
    argumentBody,
    logicalError = null,
  }) => Object.freeze({
    ...queueSubmitIdentity(operationName),
    operationName,
    operationInstanceId: String(100 + ingress),
    deviceIngressOrdinal: String(ingress),
    capturedScopeId: "0",
    receiverRef,
    commandEncoderRef,
    passRef,
    wrapperAllocatedTargetRef,
    argumentBody,
    logicalError,
  });
  const timelineOnlyOriginDigestInput = Object.freeze({
    originClass: "canvas-current",
    receiverTextureRef: submitReferences.sourceTexture,
    contextRef: submitReferences.canvas,
    attachmentGeneration: "31",
    contextGeneration: "37",
    configurationGeneration: "8",
    currentEpoch: "13",
    mintOperationProvenance: Object.freeze({
      operationInstanceId: "110",
      deviceIngressOrdinal: "10",
    }),
    configuredDeviceRef: submitReferences.device,
    format: "bgra8unorm",
    usage: 17,
    alphaMode: "premultiplied",
    colorSpace: "display-p3",
    targetAuthorityDigest: "ef".repeat(32),
    surfaceAccountToken: "41",
    surfaceAccountGeneration: "43",
  });
  const {
    receiverTextureRef: _timelineOnlyReceiverTextureRef,
    ...timelineOnlyOriginFacts
  } = timelineOnlyOriginDigestInput;
  const timelineOnlyCurrentOrigin = Object.freeze({
    ...timelineOnlyOriginFacts,
    textureOriginDigest: WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .deriveTextureOriginDigest(timelineOnlyOriginDigestInput),
  });
  const timelineOnlySubmitRecord = submitRecord({
    operationName: "GPUCanvasContext.getCurrentTexture",
    ingress: 10,
    receiverRef: submitReferences.canvas,
    wrapperAllocatedTargetRef: submitReferences.sourceTexture,
    argumentBody: Object.freeze({ currentOrigin: timelineOnlyCurrentOrigin }),
  });
  const commandRecords = Object.freeze([
    submitRecord({
      operationName: "GPUCommandEncoder.beginComputePass",
      ingress: 11,
      receiverRef: submitReferences.encoder,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.computePass,
      wrapperAllocatedTargetRef: submitReferences.computePass,
      argumentBody: Object.freeze({ label: "compute", timestampWrites: null }),
    }),
    submitRecord({
      operationName: "GPUComputePassEncoder.setPipeline",
      ingress: 12,
      receiverRef: submitReferences.computePass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.computePass,
      argumentBody: Object.freeze({ pipeline: submitReferences.computePipeline }),
    }),
    submitRecord({
      operationName: "GPUComputePassEncoder.setBindGroup",
      ingress: 13,
      receiverRef: submitReferences.computePass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.computePass,
      argumentBody: Object.freeze({
        index: 0,
        bindGroup: submitReferences.bindGroup,
        dynamicOffsets: Object.freeze([16]),
        overload: "iterable",
      }),
    }),
    submitRecord({
      operationName: "GPUComputePassEncoder.dispatchWorkgroups",
      ingress: 14,
      receiverRef: submitReferences.computePass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.computePass,
      argumentBody: Object.freeze({
        workgroupCountX: 2,
        workgroupCountY: 3,
        workgroupCountZ: 4,
      }),
    }),
    submitRecord({
      operationName: "GPUComputePassEncoder.end",
      ingress: 15,
      receiverRef: submitReferences.computePass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.computePass,
      argumentBody: Object.freeze({
        usedBindGroups: Object.freeze([submitReferences.bindGroup]),
      }),
    }),
    submitRecord({
      operationName: "GPUCommandEncoder.clearBuffer",
      ingress: 16,
      receiverRef: submitReferences.encoder,
      commandEncoderRef: submitReferences.encoder,
      argumentBody: Object.freeze({
        buffer: submitReferences.destinationBuffer,
        offset: 0,
        size: 4,
      }),
    }),
    submitRecord({
      operationName: "GPUCommandEncoder.copyBufferToBuffer",
      ingress: 17,
      receiverRef: submitReferences.encoder,
      commandEncoderRef: submitReferences.encoder,
      argumentBody: Object.freeze({
        source: submitReferences.sourceBuffer,
        sourceOffset: 0,
        destination: submitReferences.destinationBuffer,
        destinationOffset: 4,
        size: 8,
        overload: "full",
      }),
    }),
    submitRecord({
      operationName: "GPUCommandEncoder.copyTextureToTexture",
      ingress: 18,
      receiverRef: submitReferences.encoder,
      commandEncoderRef: submitReferences.encoder,
      argumentBody: Object.freeze({
        source: Object.freeze({
          aspect: "all",
          mipLevel: 0,
          origin: Object.freeze({ x: 1, y: 2, z: 0 }),
          texture: submitReferences.sourceTexture,
        }),
        destination: Object.freeze({
          aspect: "all",
          mipLevel: 0,
          origin: Object.freeze({ x: 2, y: 1, z: 0 }),
          texture: submitReferences.destinationTexture,
        }),
        copySize: Object.freeze({ width: 4, height: 5, depthOrArrayLayers: 1 }),
      }),
    }),
    submitRecord({
      operationName: "GPUCommandEncoder.beginRenderPass",
      ingress: 19,
      receiverRef: submitReferences.encoder,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.renderPass,
      wrapperAllocatedTargetRef: submitReferences.renderPass,
      argumentBody: Object.freeze({
        label: "render",
        colorAttachments: Object.freeze([
          null,
          Object.freeze({
            view: submitReferences.textureView,
            loadOp: "clear",
            storeOp: "store",
            clearValue: Object.freeze({ r: 0.1, g: 0.2, b: 0.3, a: 1 }),
            depthSlice: 2,
          }),
        ]),
      }),
    }),
    submitRecord({
      operationName: "GPURenderPassEncoder.setPipeline",
      ingress: 20,
      receiverRef: submitReferences.renderPass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.renderPass,
      argumentBody: submitReferences.renderPipeline,
    }),
    submitRecord({
      operationName: "GPURenderPassEncoder.setBindGroup",
      ingress: 21,
      receiverRef: submitReferences.renderPass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.renderPass,
      argumentBody: Object.freeze({
        index: 0,
        bindGroup: submitReferences.bindGroup,
        dynamicOffsets: Object.freeze([32]),
        overload: "uint32-range",
      }),
    }),
    submitRecord({
      operationName: "GPURenderPassEncoder.setVertexBuffer",
      ingress: 22,
      receiverRef: submitReferences.renderPass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.renderPass,
      argumentBody: Object.freeze({
        slot: 0,
        buffer: submitReferences.destinationBuffer,
        offset: 0,
        size: 8,
      }),
    }),
    submitRecord({
      operationName: "GPURenderPassEncoder.draw",
      ingress: 23,
      receiverRef: submitReferences.renderPass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.renderPass,
      argumentBody: Object.freeze([3, 1, 0, 0]),
    }),
    submitRecord({
      operationName: "GPURenderPassEncoder.end",
      ingress: 24,
      receiverRef: submitReferences.renderPass,
      commandEncoderRef: submitReferences.encoder,
      passRef: submitReferences.renderPass,
      argumentBody: null,
    }),
    submitRecord({
      operationName: "GPUCommandEncoder.finish",
      ingress: 25,
      receiverRef: submitReferences.encoder,
      commandEncoderRef: submitReferences.encoder,
      wrapperAllocatedTargetRef: submitReferences.commandBuffer,
      argumentBody: Object.freeze({
        descriptor: Object.freeze({ label: "program" }),
        usedBindGroups: Object.freeze([submitReferences.bindGroup]),
      }),
    }),
  ]);
  if (
    commandRecords.length !== 15 ||
    new Set(commandRecords.map((record) => record.operationName)).size !== 15 ||
    queueSubmitVariants.some((operationName) =>
      operationName !== "GPUCanvasContext.getCurrentTexture" &&
      !commandRecords.some((record) => record.operationName === operationName))
  ) {
    fail("queue-submit corpus does not cover all 15 command-record variants");
  }
  const queueSubmitInput = ({
    timeline,
    records,
    invalid = false,
    wrapperValidationError,
  }) => Object.freeze({
    operationId: queueSubmitOperationId,
    wireId: queueSubmitRoute.wireId,
    receiver: queueReceiver,
    capturedScopeId: "0",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "30",
    queueIngressOrdinal: "31",
    sealedLocalTimeline: Object.freeze(timeline),
    convertedArguments: Object.freeze({
      commandBuffers: Object.freeze(records === null
        ? []
        : [Object.freeze({
            commandBuffer: submitReferences.commandBuffer,
            invalid,
            records: Object.freeze(records),
          })]),
      wrapperValidationError,
    }),
  });
  const queueSubmitRequest = (id, input) => {
    const codegenBytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    const productionBytes = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input);
    if (toHex(codegenBytes) !== toHex(productionBytes)) {
      fail(`${id} production and codegen request bytes differ`);
    }
    return Object.freeze({
      id,
      bytes: codegenBytes,
      inspected: WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(codegenBytes),
    });
  };
  const queueSubmitPositive = queueSubmitRequest(
    "queue-submit-all-record-kinds-request",
    queueSubmitInput({
      timeline: [timelineOnlySubmitRecord, ...commandRecords],
      records: commandRecords,
    }),
  );
  const beginRenderIndex = commandRecords.findIndex(
    (record) => record.operationName === "GPUCommandEncoder.beginRenderPass",
  );
  const beginRenderWithoutDepthSlice = Object.freeze({
    ...commandRecords[beginRenderIndex],
    argumentBody: Object.freeze({
      ...commandRecords[beginRenderIndex].argumentBody,
      colorAttachments: Object.freeze([
        null,
        Object.freeze({
          view: submitReferences.textureView,
          loadOp: "clear",
          storeOp: "store",
          clearValue: Object.freeze({ r: 0.1, g: 0.2, b: 0.3, a: 1 }),
        }),
      ]),
    }),
  });
  const recordsWithoutDepthSlice = Object.freeze(commandRecords.map(
    (record, index) => index === beginRenderIndex
      ? beginRenderWithoutDepthSlice
      : record,
  ));
  const queueSubmitWithoutDepthSlice = queueSubmitRequest(
    "queue-submit-null-slot-depth-slice-absent-request",
    queueSubmitInput({
      timeline: [timelineOnlySubmitRecord, ...recordsWithoutDepthSlice],
      records: recordsWithoutDepthSlice,
    }),
  );
  const queueSubmitTimelineOnly = queueSubmitRequest(
    "queue-submit-empty-program-timeline-only-request",
    queueSubmitInput({ timeline: [timelineOnlySubmitRecord], records: null }),
  );
  const queueSubmitEmpty = queueSubmitRequest(
    "queue-submit-empty-request",
    queueSubmitInput({ timeline: [], records: null }),
  );
  const logicalErrorIndex = commandRecords.findIndex(
    (record) => record.operationName === "GPUComputePassEncoder.setPipeline",
  );
  const logicalErrorRecords = Object.freeze(commandRecords.map((record, index) =>
    index === logicalErrorIndex
      ? Object.freeze({
          ...record,
          argumentBody: Object.freeze({ pipeline: submitReferences.adapter }),
          logicalError: Object.freeze({
            name: "GPUValidationError",
            message: "Compute pipeline is invalid for this pass",
          }),
        })
      : record));
  const queueSubmitLogicalError = queueSubmitRequest(
    "queue-submit-logical-error-program-request",
    queueSubmitInput({
      timeline: [timelineOnlySubmitRecord, ...logicalErrorRecords],
      records: logicalErrorRecords,
      invalid: true,
      wrapperValidationError: Object.freeze({
        name: "GPUValidationError",
        message: "Command buffer contains invalid recorded commands",
      }),
    }),
  );
  const parseQueueSubmitLayout = (bytes) => {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let cursor = 86;
    const recordCount = view.getUint32(cursor, true);
    cursor += 4;
    const records = [];
    for (let index = 0; index < recordCount; index += 1) {
      const length = view.getUint32(cursor, true);
      cursor += 4;
      records.push(Object.freeze({ start: cursor, length }));
      cursor += length;
    }
    const pendingCountOffset = cursor;
    const pendingCount = view.getUint32(cursor, true);
    cursor += 4;
    const pendingIndicesOffset = cursor;
    cursor += pendingCount * 4;
    const programCountOffset = cursor;
    const programCount = view.getUint32(cursor, true);
    cursor += 4;
    const programs = [];
    for (let index = 0; index < programCount; index += 1) {
      const start = cursor;
      const invalidOffset = start + 41;
      const finishPositionOffset = start + 42;
      const recordCountOffset = start + 46;
      const programRecordCount = view.getUint32(recordCountOffset, true);
      const indicesOffset = start + 50;
      const digestOffset = indicesOffset + programRecordCount * 4;
      programs.push(Object.freeze({
        start,
        invalidOffset,
        finishPositionOffset,
        recordCountOffset,
        recordCount: programRecordCount,
        indicesOffset,
        digestOffset,
      }));
      cursor = digestOffset + 32;
    }
    return Object.freeze({
      records: Object.freeze(records),
      pendingCountOffset,
      pendingCount,
      pendingIndicesOffset,
      programCountOffset,
      programCount,
      programs: Object.freeze(programs),
      wrapperErrorOffset: cursor,
    });
  };
  const queueSubmitPositiveLayout = parseQueueSubmitLayout(
    queueSubmitPositive.bytes,
  );
  const queueSubmitTimelineOnlyLayout = parseQueueSubmitLayout(
    queueSubmitTimelineOnly.bytes,
  );
  const logicalErrorLayout = parseQueueSubmitLayout(queueSubmitLogicalError.bytes);
  const concatenateBytes = (...chunks) => Uint8Array.from(Buffer.concat(
    chunks.map((chunk) => Buffer.from(chunk)),
  ));
  const u32Bytes = (value) => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    return bytes;
  };
  const asciiOffset = (bytes, value) => {
    const needle = Buffer.from(value, "utf8");
    outer: for (let offset = 0; offset <= bytes.byteLength - needle.length; offset += 1) {
      for (let index = 0; index < needle.length; index += 1) {
        if (bytes[offset + index] !== needle[index]) continue outer;
      }
      return offset;
    }
    fail(`queue-submit mutation key is absent: ${value}`);
  };
  const queueSubmitBinaryRejections = [];
  for (const [recordIndex, record] of queueSubmitPositive.inspected.recordTable.entries()) {
    queueSubmitBinaryRejections.push(Object.freeze({
      id: `queue-submit-record-kind-${recordIndex}-rejected`,
      mutation: `unknown-record-kind-${record.operationName}`,
      bytes: mutatedBytes(queueSubmitPositive.bytes, (bytes) => {
        bytes[queueSubmitPositiveLayout.records[recordIndex].start + 1] = 0xff;
      }),
    }));
  }
  const firstActiveIndex = queueSubmitPositive.inspected.recordTable.findIndex(
    (record) => record.recordIdentityClass === "active-route",
  );
  const beginComputeTableIndex = queueSubmitPositive.inspected.recordTable.findIndex(
    (record) => record.operationName === "GPUCommandEncoder.beginComputePass",
  );
  const canvasCurrentTableIndex = queueSubmitPositive.inspected.recordTable.findIndex(
    (record) => record.operationName === "GPUCanvasContext.getCurrentTexture",
  );
  const depthSliceOffset = asciiOffset(queueSubmitPositive.bytes, "depthSlice") +
    Buffer.byteLength("depthSlice");
  const canvasCurrentOriginDigestOffset = asciiOffset(
    queueSubmitPositive.bytes,
    timelineOnlyCurrentOrigin.textureOriginDigest,
  );
  if (canvasCurrentTableIndex < 0) {
    fail("queue-submit canvas-current record is absent from the positive table");
  }
  if (
    queueSubmitPositive.bytes[depthSliceOffset] !==
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.valueTags.u32
  ) {
    fail("queue-submit depthSlice value offset drifted");
  }
  queueSubmitBinaryRejections.push(
    ...[
      ["object-id", 13],
      ["object-generation", 21],
      ["logical-device-id", 29],
      ["logical-device-generation", 37],
      ["provider-generation", 45],
    ].map(([name, offset]) => Object.freeze({
      id: `queue-submit-zero-receiver-${name}-rejected`,
      mutation: `zero-receiver-${name}`,
      bytes: mutatedBytes(queueSubmitEmpty.bytes, (bytes) => {
        bytes.fill(0, offset, offset + 8);
      }),
    })),
    Object.freeze({
      id: "queue-submit-unreferenced-record-table-row-rejected",
      mutation: "record-table-row-removed-from-exact-index-union",
      bytes: concatenateBytes(
        queueSubmitTimelineOnly.bytes.slice(
          0,
          queueSubmitTimelineOnlyLayout.pendingCountOffset,
        ),
        u32Bytes(0),
        queueSubmitTimelineOnly.bytes.slice(
          queueSubmitTimelineOnlyLayout.pendingIndicesOffset + 4,
        ),
      ),
    }),
    Object.freeze({
      id: "queue-submit-aggregate-program-record-bound-rejected",
      mutation: "sixty-nine-fifteen-record-programs-exceed-aggregate-bound",
      bytes: (() => {
        const repeatedProgramCount = 69;
        const program = queueSubmitPositiveLayout.programs[0];
        const programBytes = queueSubmitPositive.bytes.slice(
          program.start,
          queueSubmitPositiveLayout.wrapperErrorOffset,
        );
        return concatenateBytes(
          queueSubmitPositive.bytes.slice(
            0,
            queueSubmitPositiveLayout.programCountOffset,
          ),
          u32Bytes(repeatedProgramCount),
          ...Array.from({ length: repeatedProgramCount }, () => programBytes),
          queueSubmitPositive.bytes.slice(
            queueSubmitPositiveLayout.wrapperErrorOffset,
          ),
        );
      })(),
    }),
    Object.freeze({
      id: "queue-submit-record-identity-class-rejected",
      mutation: "identity-class-three",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (bytes) => {
        bytes[queueSubmitPositiveLayout.records[0].start] = 3;
      }),
    }),
    Object.freeze({
      id: "queue-submit-active-identity-digest-rejected",
      mutation: "active-record-zero-identity-digest-bit",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (bytes) => {
        bytes[queueSubmitPositiveLayout.records[firstActiveIndex].start + 8] ^= 1;
      }),
    }),
    Object.freeze({
      id: "queue-submit-canvas-current-target-retarget-rejected",
      mutation: "canvas-current-wrapper-target-object-id-999",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(
          queueSubmitPositiveLayout.records[canvasCurrentTableIndex].start + 109,
          999,
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-canvas-current-origin-digest-rejected",
      mutation: "canvas-current-origin-digest-byte-without-target-rebind",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (bytes) => {
        bytes[canvasCurrentOriginDigestOffset] =
          bytes[canvasCurrentOriginDigestOffset] === 0x30 ? 0x31 : 0x30;
      }),
    }),
    Object.freeze({
      id: "queue-submit-record-receiver-generation-drift-rejected",
      mutation: "encoder-receiver-generation-two",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(
          queueSubmitPositiveLayout.records[beginComputeTableIndex].start + 73,
          2,
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-pass-generation-drift-rejected",
      mutation: "begin-compute-pass-ref-generation-two",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(
          queueSubmitPositiveLayout.records[beginComputeTableIndex].start + 157,
          2,
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-record-ingress-order-rejected",
      mutation: "second-record-ingress-equals-first",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(
          queueSubmitPositiveLayout.records[1].start + 48,
          10,
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-pending-index-reuse-rejected",
      mutation: "second-pending-index-equals-first",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(
          queueSubmitPositiveLayout.pendingIndicesOffset + 4,
          view.getUint32(queueSubmitPositiveLayout.pendingIndicesOffset, true),
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-program-index-reuse-rejected",
      mutation: "second-program-index-equals-first",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        const program = queueSubmitPositiveLayout.programs[0];
        view.setUint32(
          program.indicesOffset + 4,
          view.getUint32(program.indicesOffset, true),
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-finish-position-rejected",
      mutation: "finish-position-zero",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(
          queueSubmitPositiveLayout.programs[0].finishPositionOffset,
          0,
          true,
        );
      }),
    }),
    Object.freeze({
      id: "queue-submit-command-buffer-generation-drift-rejected",
      mutation: "program-command-buffer-generation-two",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(queueSubmitPositiveLayout.programs[0].start + 9, 2, true);
      }),
    }),
    Object.freeze({
      id: "queue-submit-command-program-digest-rejected",
      mutation: "command-program-digest-bit",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (bytes) => {
        bytes[queueSubmitPositiveLayout.programs[0].digestOffset] ^= 1;
      }),
    }),
    Object.freeze({
      id: "queue-submit-depth-slice-record-mutation-rejected",
      mutation: "depthSlice-two-to-three-without-digest-rewrite",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (_bytes, view) => {
        view.setUint32(depthSliceOffset + 1, 3, true);
      }),
    }),
    Object.freeze({
      id: "queue-submit-record-logical-error-tag-rejected",
      mutation: "record-logical-error-tag-four",
      bytes: mutatedBytes(queueSubmitPositive.bytes, (bytes) => {
        const record = queueSubmitPositiveLayout.records[beginComputeTableIndex];
        bytes[record.start + 231] = 4;
      }),
    }),
    Object.freeze({
      id: "queue-submit-wrapper-logical-error-tag-rejected",
      mutation: "wrapper-logical-error-tag-four",
      bytes: mutatedBytes(queueSubmitLogicalError.bytes, (bytes) => {
        bytes[logicalErrorLayout.wrapperErrorOffset] = 4;
      }),
    }),
    Object.freeze({
      id: "queue-submit-request-truncated-rejected",
      mutation: "truncate-final-byte",
      bytes: queueSubmitPositive.bytes.slice(0, -1),
    }),
    Object.freeze({
      id: "queue-submit-request-trailing-byte-rejected",
      mutation: "append-trailing-byte",
      bytes: withTrailingByte(queueSubmitPositive.bytes),
    }),
  );
  for (const rejection of queueSubmitBinaryRejections) {
    let rejected = false;
    try {
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(rejection.bytes);
    } catch {
      rejected = true;
    }
    if (!rejected) fail(`${rejection.id} did not fail closed`);
  }
  const queueSubmitRequests = Object.freeze([
    queueSubmitPositive,
    queueSubmitWithoutDepthSlice,
    queueSubmitTimelineOnly,
    queueSubmitEmpty,
    queueSubmitLogicalError,
  ]);
  const queueSubmitCarrier = Object.freeze({
    ...queueWriteBufferCarrier,
    operation_id: queueSubmitRoute.wireId,
    operation_instance_id: "62",
    captured_scope_id: "0",
    device_ingress_ordinal: "30",
    queue_ingress_ordinal: "31",
  });
  const canonicalUtf8Dictionary =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeCanonicalValue(
      Object.freeze({
        "\u{10000}": 1,
        "\ue000": 2,
      }),
    );
  const manifestBytes = fs.readFileSync(
    assertConfinedGeneratedFile(
      repositoryRoot,
      manifestPath,
      "WebGPU language-neutral codec manifest",
    ).path,
  );

  return {
    schema: "ibex/webgpu-production-codec-corpus/2",
    disposition:
      "generated-language-neutral-request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-compute-pipeline-create-render-pipeline-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-canvas-configure-canvas-unconfigure-texture-destroy-queue-write-buffer-queue-write-texture-queue-submit-positive-and-adversarial-interoperability-vectors-no-native-install-claim",
    supportClaim: "none",
    carrierProjectionScope:
      "operation-specific-native-program-fields-plus-global-v2-carrier-examples-not-a-complete-abi-record",
    source: {
      manifestPath,
      manifestSha256: sha256(manifestBytes),
    },
    profileId: WEBGPU_EXECUTABLE_CODEC_MANIFEST.profileId,
    scopeId: WEBGPU_EXECUTABLE_CODEC_MANIFEST.scopeId,
    digests: WEBGPU_EXECUTABLE_CODEC_MANIFEST.digests,
    operation: {
      operationId,
      wireId: route.wireId,
      nativeCodecProgramSchema:
        WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
      requestCodec: requestCodec.tag,
      requestCodecTag: requestCodec.wireTag,
      completionCodec: completionCodec.tag,
      completionCodecTag: completionCodec.wireTag,
    },
    operations: [
      {
        operationId,
        wireId: route.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: requestCodec.tag,
        requestCodecTag: requestCodec.wireTag,
        completionCodec: completionCodec.tag,
        completionCodecTag: completionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
      },
      {
        operationId: requestDeviceOperationId,
        wireId: requestDeviceRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: requestDeviceRequestCodec.tag,
        requestCodecTag: requestDeviceRequestCodec.wireTag,
        completionCodec: requestDeviceCompletionCodec.tag,
        completionCodecTag: requestDeviceCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: false,
        unavailableSemanticFields:
          requestDeviceRequestCodec.unavailableSemanticFields,
        testOnlyPayloadCodegenEvidence: true,
      },
      {
        operationId: createBindGroupOperationId,
        wireId: createBindGroupRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createBindGroupRequestCodec.tag,
        requestCodecTag: createBindGroupRequestCodec.wireTag,
        completionCodec: createBindGroupCompletionCodec.tag,
        completionCodecTag: createBindGroupCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createBindGroupNativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          corpusSha256: bindGroupEvidence.corpusSha256,
          callCount: bindGroupEvidence.callCount,
          maximumEntriesPerDescriptor:
            bindGroupEvidence.maximumEntriesPerDescriptor,
          maximumLabelUtf8Bytes: bindGroupEvidence.maximumLabelUtf8Bytes,
          acceptedFullWitnessSha256s:
            bindGroupEvidence.acceptedWitnesses.map(
              (witness) => witness.witnessSha256,
            ),
          predicateRule:
            "exact-generated-18-call-full-converted-and-joined-provenance-witness-set-after-broad-structural-decode-and-full-generation-qualified-reference-joins",
        },
      },
      {
        operationId: createBindGroupLayoutOperationId,
        wireId: createBindGroupLayoutRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createBindGroupLayoutRequestCodec.tag,
        requestCodecTag: createBindGroupLayoutRequestCodec.wireTag,
        completionCodec: createBindGroupLayoutCompletionCodec.tag,
        completionCodecTag: createBindGroupLayoutCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createBindGroupLayoutNativeRoute.completion.semanticTerminalMapping,
      },
      {
        operationId: createBufferOperationId,
        wireId: createBufferRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createBufferRequestCodec.tag,
        requestCodecTag: createBufferRequestCodec.wireTag,
        completionCodec: createBufferCompletionCodec.tag,
        completionCodecTag: createBufferCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createBufferNativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          callCount: 21,
          totalResourceBytes: 49_545_804,
          distinctSizes: [
            4, 12, 16, 72, 128, 136, 262144, 2621440, 22020096,
          ],
          distinctUsages: [9, 76, 140, 172],
          mappedAtCreationForms: ["omitted", false, true],
          maximumLabelUtf8Bytes: 21,
          runtimeQuotaRule:
            "evidence-only-not-mutable-runtime-count-or-aggregate-quota",
        },
        semanticStepOrder: createBufferSemanticSteps,
      },
      {
        operationId: createPipelineLayoutOperationId,
        wireId: createPipelineLayoutRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createPipelineLayoutRequestCodec.tag,
        requestCodecTag: createPipelineLayoutRequestCodec.wireTag,
        completionCodec: createPipelineLayoutCompletionCodec.tag,
        completionCodecTag: createPipelineLayoutCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createPipelineLayoutNativeRoute.completion.semanticTerminalMapping,
      },
      {
        operationId: createComputePipelineOperationId,
        wireId: createComputePipelineRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createComputePipelineRequestCodec.tag,
        requestCodecTag: createComputePipelineRequestCodec.wireTag,
        completionCodec: createComputePipelineCompletionCodec.tag,
        completionCodecTag: createComputePipelineCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createComputePipelineNativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          cohortCount: 7,
          workloadCallCounts: {
            "typegpu-genetic-racing": 6,
            "typegpu-jelly-slider": 1,
          },
          projectionSha256:
            computePipelineConversion.source.projectionSha256,
          layoutModes: ["explicit", "auto"],
          sourceConstantsPresence: ["omitted", "present"],
          entryPointPresence: ["omitted", "present"],
          presenceVector:
            "create-compute-pipeline-auto-layout-present-constants-entry-point-request",
        },
        structuralRejectionCount: computePipelineStructuralRejections.length,
        semanticStepOrder: computePipelineSemanticSteps,
      },
      {
        operationId: createRenderPipelineOperationId,
        wireId: createRenderPipelineRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createRenderPipelineRequestCodec.tag,
        requestCodecTag: createRenderPipelineRequestCodec.wireTag,
        completionCodec: createRenderPipelineCompletionCodec.tag,
        completionCodecTag: createRenderPipelineCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createRenderPipelineNativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          cohortCount: 4,
          cohorts: renderPipelineConversion.rows.map((row) => row.workload),
          layoutModes: ["explicit", "auto"],
          fieldPreservationVector: "create-render-pipeline-full-state-request",
          WebIdlMaterializedDefaults:
            renderPipelineConversion.materializedDefaults,
          WebIdlSharedOmissions: renderPipelineConversion.sharedOmissions,
        },
        structuralRejectionCount: renderPipelineStructuralRejections.length,
        semanticStepOrder: renderPipelineSemanticSteps,
      },
      {
        operationId: createSamplerOperationId,
        wireId: samplerCorpus.route.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: samplerCorpus.requestCodec.tag,
        requestCodecTag: samplerCorpus.requestCodec.wireTag,
        completionCodec: samplerCorpus.completionCodec.tag,
        completionCodecTag: samplerCorpus.completionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          samplerCorpus.nativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          callCount: 4,
          labels: ["", "nearestSampler", "linearSampler", "sampler"],
          filters: ["nearest", "linear"],
          maximumLabelUtf8Bytes: 14,
          byteBacking: "none-one-resource-table-and-ledger-unit-per-sampler",
        },
        semanticStepOrder: samplerCorpus.semanticSteps,
      },
      {
        operationId: createTextureOperationId,
        wireId: textureCorpus.route.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: textureCorpus.requestCodec.tag,
        requestCodecTag: textureCorpus.requestCodec.wireTag,
        completionCodec: textureCorpus.completionCodec.tag,
        completionCodecTag: textureCorpus.completionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          textureCorpus.nativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          callCount: 5,
          totalResourceBytes: 1_359_872,
          extents: [[32, 64, 1], [64, 128, 1], [32, 64, 1], [512, 512, 1], [256, 128, 1]],
          formats: ["rgba8unorm", "rgba16float"],
          usages: [17, 22, 23, 31],
          mipLevelCounts: [1],
          sampleCounts: [1],
          maximumLabelUtf8Bytes: 13,
        },
        semanticStepOrder: textureCorpus.semanticSteps,
      },
      {
        operationId: createTextureViewOperationId,
        wireId: createTextureViewRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createTextureViewRequestCodec.tag,
        requestCodecTag: createTextureViewRequestCodec.wireTag,
        completionCodec: createTextureViewCompletionCodec.tag,
        completionCodecTag: createTextureViewCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createTextureViewNativeRoute.completion.semanticTerminalMapping,
        reviewedWorkloadEvidence: {
          callCount: 25,
          sourceCallCounts: {
            "typegpu-genetic-racing": 22,
            "typegpu-jelly-slider": 3,
          },
          nonCartesianDescriptorParentOriginClassCount: 8,
          classMultiplicity: textureViewClassMultiplicity,
          originClassCallCounts: {
            "device-created": 6,
            "canvas-current": 19,
          },
          descriptorDefaults: textureViewDefaults,
          sourceAffineJoins: [
            "receiver-full-reference-to-authenticated-texture-table-row",
            "receiver-and-target-device-provider-generation-equality",
            "target-full-reference-to-wrapper-allocation-provenance",
            "canvas-context-configured-device-and-surface-account-join",
          ],
          viewAccountingRule:
            "one-independent-view-unit-with-zero-parent-backing-byte-double-charge",
        },
        structuralRejectionCount: textureViewStructuralRejections.length,
        semanticStepOrder: textureViewSemanticSteps,
        firstFailureRules: {
          destroyedReceiverBeforeCurrentOrigin:
            "destroyed-receiver-current-origin-stale-collision",
          currentOriginBeforeCoverageAndAccount:
            "stale-current-origin-coverage-account-collision",
          physicalSequence:
            "allocated-only-after-all-sixteen-logical-predicates-pass",
        },
      },
      {
        operationId: createCommandEncoderOperationId,
        wireId: createCommandEncoderRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createCommandEncoderRequestCodec.tag,
        requestCodecTag: createCommandEncoderRequestCodec.wireTag,
        completionCodec: createCommandEncoderCompletionCodec.tag,
        completionCodecTag: createCommandEncoderCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createCommandEncoderNativeRoute.completion.semanticTerminalMapping,
      },
      {
        operationId: createShaderModuleOperationId,
        wireId: createShaderModuleRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: createShaderModuleRequestCodec.tag,
        requestCodecTag: createShaderModuleRequestCodec.wireTag,
        completionCodec: createShaderModuleCompletionCodec.tag,
        completionCodecTag: createShaderModuleCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          createShaderModuleNativeRoute.completion.semanticTerminalMapping,
      },
      {
        operationId: deviceDestroyOperationId,
        wireId: deviceDestroyRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: deviceDestroyRequestCodec.tag,
        requestCodecTag: deviceDestroyRequestCodec.wireTag,
        completionCodec: deviceDestroyCompletionCodec.tag,
        completionCodecTag: deviceDestroyCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          deviceDestroyNativeRoute.completion.semanticTerminalMapping,
      },
      ...lifecycleOperationIds.map((lifecycleOperationId) => {
        const metadata = lifecycleRoutes.get(lifecycleOperationId);
        return {
          operationId: lifecycleOperationId,
          wireId: metadata.route.wireId,
          nativeCodecProgramSchema:
            WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
          requestCodec: metadata.requestCodec.tag,
          requestCodecTag: metadata.requestCodec.wireTag,
          completionCodec: metadata.completionCodec.tag,
          completionCodecTag: metadata.completionCodec.wireTag,
          productionExecutableFromCurrentAuthenticatedInputs: true,
          semanticTerminalMapping:
            metadata.nativeRoute.completion.semanticTerminalMapping,
          bodySchema: metadata.nativeRoute.request.payload.fields.at(-1).type,
          completionBodySchema:
            lifecycleOperationId === bufferMapAsyncOperationId
              ? metadata.nativeRoute.completion.payload.fields.at(-1).type
              : "empty",
        };
      }),
      ...canvasLifecycleOperationIds.map((canvasOperationId) => {
        const metadata = canvasLifecycleRoutes.get(canvasOperationId);
        return {
          operationId: canvasOperationId,
          wireId: metadata.route.wireId,
          nativeCodecProgramSchema:
            WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
          requestCodec: metadata.requestCodec.tag,
          requestCodecTag: metadata.requestCodec.wireTag,
          completionCodec: metadata.completionCodec.tag,
          completionCodecTag: metadata.completionCodec.wireTag,
          productionExecutableFromCurrentAuthenticatedInputs: true,
          semanticTerminalMapping:
            metadata.nativeRoute.completion.semanticTerminalMapping,
          bodySchema: metadata.nativeRoute.request.payload.fields.at(-1).type,
          completionBodySchema: "empty",
          authoritySource:
            "wrapper-owned-closed-generation-and-origin-projection",
        };
      }),
      {
        operationId: queueWriteBufferOperationId,
        wireId: queueWriteBufferRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: queueWriteBufferRequestCodec.tag,
        requestCodecTag: queueWriteBufferRequestCodec.wireTag,
        completionCodec: queueWriteBufferCompletionCodec.tag,
        completionCodecTag: queueWriteBufferCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          queueWriteBufferNativeRoute.completion.semanticTerminalMapping,
        bodySchema:
          queueWriteBufferNativeRoute.request.payload.fields.at(-1).type,
        completionBodySchema: "empty",
      },
      {
        operationId: queueWriteTextureOperationId,
        wireId: queueWriteTextureRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: queueWriteTextureRequestCodec.tag,
        requestCodecTag: queueWriteTextureRequestCodec.wireTag,
        completionCodec: queueWriteTextureCompletionCodec.tag,
        completionCodecTag: queueWriteTextureCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          queueWriteTextureNativeRoute.completion.semanticTerminalMapping,
        bodySchema:
          queueWriteTextureNativeRoute.request.payload.fields.at(-1).type,
        completionBodySchema: "empty",
      },
      {
        operationId: queueSubmitOperationId,
        wireId: queueSubmitRoute.wireId,
        nativeCodecProgramSchema:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.schema,
        requestCodec: queueSubmitCodec.tag,
        requestCodecTag: queueSubmitCodec.wireTag,
        completionCodec: queueSubmitCompletionCodec.tag,
        completionCodecTag: queueSubmitCompletionCodec.wireTag,
        productionExecutableFromCurrentAuthenticatedInputs: true,
        semanticTerminalMapping:
          queueSubmitNativeRoute.completion.semanticTerminalMapping,
        bodySchema:
          queueSubmitNativeRoute.request.payload.fields.at(-1).type,
        commandRecordSchema: "commandRecordV1",
        commandProgramDigestDomain: "exact/webgpu-command-program/v1\\0",
        commandRecordVariantCount: 15,
        timelineOnlyRecordVariantCount: 1,
        completionBodySchema: "empty",
      },
    ],
    vectors: [
      defaultRequest,
      highPerformanceRequest,
      compatibilityRequest,
      {
        id: "request-device-converted-descriptor-ingress",
        kind: "request",
        carrierProjection: requestDeviceRequestCarrier,
        trust:
          "untrusted-webidl-converted-semantic-service-ingress-only-never-provider-input",
        nativeSemanticServiceDerivations: [
          "generatedLogicalProviderDescriptor",
          "authenticatedResultSelectionIdentity",
        ],
        bytesHex: toHex(requestDeviceBytes),
        expected: {
          receiver: requestDeviceReceiver,
          target: null,
          capturedScopeId: "0",
          adapterOrdinal: "1",
          deviceIngressOrdinal: "0",
          queueIngressOrdinal: "0",
          sealedLocalTimeline: [],
          convertedArguments: requestDeviceDescriptor,
        },
      },
      {
        id: "request-device-unknown-limit-semantic-witness",
        kind: "request",
        carrierProjection: requestDeviceRequestCarrier,
        trust:
          "untrusted-webidl-converted-semantic-service-ingress-only-never-provider-input",
        unknownNonUndefinedLimitDisposition: unknownLimitDisposition,
        semanticOwner: "native-semantic-service-before-provider-admission",
        rawDescriptorProviderInput: "forbidden",
        bytesHex: toHex(unknownLimitRequestBytes),
        expected: {
          receiver: requestDeviceReceiver,
          target: null,
          capturedScopeId: "0",
          adapterOrdinal: "1",
          deviceIngressOrdinal: "0",
          queueIngressOrdinal: "0",
          sealedLocalTimeline: [],
          convertedArguments: convertedUnknownLimitDescriptor,
        },
      },
      {
        id: "request-device-live-object-result",
        kind: "result",
        carrierProjection: requestDeviceCarrierProjection(1, "6", 1),
        event: {
          ...liveDeviceEvent,
          payload: undefined,
        },
        bytesHex: toHex(liveDeviceResult),
        expected: expectedLiveDevice,
      },
      {
        id: "request-device-detached-not-admitted-object-result",
        kind: "result",
        carrierProjection: requestDeviceCarrierProjection(0, "0", 2),
        event: {
          ...detachedNotAdmittedEvent,
          payload: undefined,
        },
        bytesHex: toHex(detachedDeviceResult),
        expected: expectedDetachedDevice,
      },
      {
        id: "request-device-detached-admitted-object-result",
        kind: "result",
        carrierProjection: requestDeviceCarrierProjection(1, "7", 2),
        event: {
          ...detachedAdmittedEvent,
          payload: undefined,
        },
        bytesHex: toHex(detachedDeviceResult),
        expected: expectedDetachedDevice,
      },
      {
        id: "request-adapter-live-object-result",
        kind: "result",
        carrierProjection: resultCarrierProjection(3),
        event: {
          kind: 1,
          operationId: route.wireId,
          resultKind: 3,
          status: 0,
          providerAdmission: 1,
          physicalSequence: "5",
          deviceTransition: 0,
          ingressLogicalDeviceId: "0",
          ingressLogicalDeviceGeneration: "0",
          ingressProviderGeneration: "0",
          logicalDeviceId: "0",
          logicalDeviceGeneration: "0",
          providerGeneration: "0",
          operationProviderGeneration: "9",
        },
        bytesHex: toHex(liveObjectResult),
        expected: {
          kind: "object",
          object: {
            kind: "GPUAdapter",
            objectId: "41",
            objectGeneration: "2",
            providerGeneration: "9",
            serviceDetachedExpired: false,
            features: [
              "core-features-and-limits",
              "texture-compression-bc",
              "timestamp-query",
            ],
          },
        },
      },
      {
        id: "request-adapter-detached-expired-object-result",
        kind: "result",
        carrierProjection: resultCarrierProjection(3),
        event: {
          kind: 1,
          operationId: route.wireId,
          resultKind: 3,
          status: 0,
          providerAdmission: 1,
          physicalSequence: "5",
          deviceTransition: 0,
          ingressLogicalDeviceId: "0",
          ingressLogicalDeviceGeneration: "0",
          ingressProviderGeneration: "0",
          logicalDeviceId: "0",
          logicalDeviceGeneration: "0",
          providerGeneration: "0",
          operationProviderGeneration: "9",
        },
        bytesHex: toHex(detachedExpiredObjectResult),
        expected: {
          kind: "object",
          object: {
            kind: "GPUAdapter",
            objectId: "42",
            objectGeneration: "3",
            providerGeneration: "9",
            serviceDetachedExpired: true,
            features: ["core-features-and-limits"],
          },
        },
      },
      {
        id: "request-adapter-null-result",
        kind: "result",
        carrierProjection: resultCarrierProjection(2),
        event: {
          kind: 1,
          operationId: route.wireId,
          resultKind: 2,
          status: 0,
          providerAdmission: 1,
          physicalSequence: "5",
          deviceTransition: 0,
          ingressLogicalDeviceId: "0",
          ingressLogicalDeviceGeneration: "0",
          ingressProviderGeneration: "0",
          logicalDeviceId: "0",
          logicalDeviceGeneration: "0",
          providerGeneration: "0",
          operationProviderGeneration: "9",
        },
        bytesHex: toHex(nullResult),
        expected: { kind: "null" },
      },
      {
        id: "request-adapter-not-admitted-null-result",
        kind: "result",
        carrierProjection: resultCarrierProjection(2, 0, "0", "0"),
        event: {
          kind: 1,
          operationId: route.wireId,
          resultKind: 2,
          status: 0,
          providerAdmission: 0,
          physicalSequence: "0",
          deviceTransition: 0,
          ingressLogicalDeviceId: "0",
          ingressLogicalDeviceGeneration: "0",
          ingressProviderGeneration: "0",
          logicalDeviceId: "0",
          logicalDeviceGeneration: "0",
          providerGeneration: "0",
          operationProviderGeneration: "0",
        },
        bytesHex: toHex(nullResult),
        expected: { kind: "null" },
      },
      {
        id: "canonical-dictionary-utf8-byte-order",
        kind: "canonical-value",
        bytesHex: toHex(canonicalUtf8Dictionary),
        expected: {
          orderedKeys: ["\ue000", "\u{10000}"],
          rule: "unsigned-utf8-bytes-shorter-prefix-first",
        },
      },
      ...createBindGroupWorkloadVectors,
      {
        id: "create-bind-group-operation-success-result",
        kind: "result",
        operationId: createBindGroupOperationId,
        semanticTerminalId: "operation-success",
        bytesHex: toHex(createBindGroupCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...createBindGroupStructuralRejections,
      ...createBindGroupSemanticRejections,
      {
        id: "create-bind-group-layout-request",
        kind: "request",
        carrierProjection: createBindGroupLayoutRequestCarrier,
        trust:
          "untrusted-wrapper-record-prefix-and-descriptor-join-only-never-authority",
        semanticOwner:
          "native-semantic-service-before-provider-admission",
        bytesHex: toHex(createBindGroupLayoutBytes),
        expected: expectedCreateBindGroupLayoutRequest,
      },
      {
        id: "create-bind-group-layout-operation-success-result",
        kind: "result",
        semanticTerminalId: "operation-success",
        carrierProjection: createBindGroupLayoutCompletionCarrier,
        bytesHex: toHex(createBindGroupLayoutCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...bindGroupLayoutRejectionVectors,
      ...createBufferWorkloadVectors,
      {
        id: "create-buffer-operation-success-result",
        kind: "result",
        semanticTerminalId: "operation-success",
        carrierProjection: createBufferCompletionCarrier,
        bytesHex: toHex(createBufferCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...createBufferAdversarialVectors,
      ...samplerCorpus.requestVectors,
      samplerCorpus.successVector,
      ...samplerCorpus.semanticRejections,
      ...textureCorpus.requestVectors,
      textureCorpus.successVector,
      ...textureCorpus.semanticRejections,
      ...textureViewWorkloadVectors,
      textureViewSuccessVector,
      ...textureViewStructuralRejections,
      ...textureViewSemanticRejections,
      {
        id: "create-pipeline-layout-request",
        kind: "request",
        carrierProjection: createPipelineLayoutRequestCarrier,
        trust:
          "untrusted-wrapper-record-prefix-and-descriptor-join-only-never-authority",
        semanticOwner:
          "native-semantic-service-before-provider-admission",
        bytesHex: toHex(createPipelineLayoutBytes),
        expected: expectedCreatePipelineLayoutRequest,
      },
      {
        id: "create-pipeline-layout-operation-success-result",
        kind: "result",
        semanticTerminalId: "operation-success",
        carrierProjection: createPipelineLayoutCompletionCarrier,
        bytesHex: toHex(createPipelineLayoutCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...pipelineLayoutRejectionVectors,
      ...computePipelineCohortVectors,
      computePipelinePresentVector,
      {
        id: "create-compute-pipeline-operation-success-result",
        kind: "result",
        operationId: createComputePipelineOperationId,
        semanticTerminalId: "operation-success",
        carrierProjection: computePipelineSuccessCarrier,
        bytesHex: toHex(createComputePipelineCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...computePipelineStructuralRejections,
      ...computePipelineSemanticRejections,
      ...renderPipelineCohortVectors,
      renderPipelineAutoVector,
      renderPipelineFullStateVector,
      {
        id: "create-render-pipeline-operation-success-result",
        kind: "result",
        operationId: createRenderPipelineOperationId,
        semanticTerminalId: "operation-success",
        carrierProjection: renderPipelineSuccessCarrier,
        bytesHex: toHex(createRenderPipelineCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...renderPipelineStructuralRejections,
      ...renderPipelineSemanticRejections,
      {
        id: "create-command-encoder-request",
        kind: "request",
        carrierProjection: createCommandEncoderRequestCarrier,
        trust:
          "untrusted-wrapper-record-prefix-and-descriptor-join-only-never-authority",
        semanticOwner:
          "native-semantic-service-before-provider-admission",
        bytesHex: toHex(createCommandEncoderBytes),
        expected: expectedCreateCommandEncoderRequest,
      },
      {
        id: "create-command-encoder-operation-success-result",
        kind: "result",
        semanticTerminalId: "operation-success",
        carrierProjection: createCommandEncoderCompletionCarrier,
        bytesHex: toHex(createCommandEncoderCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      {
        id: "create-shader-module-request",
        kind: "request",
        carrierProjection: createShaderModuleRequestCarrier,
        trust:
          "untrusted-wrapper-record-prefix-and-descriptor-join-only-never-authority",
        semanticOwner:
          "native-semantic-service-before-provider-admission",
        bytesHex: toHex(createShaderModuleBytes),
        expected: expectedCreateShaderModuleRequest,
      },
      {
        id: "create-shader-module-operation-success-result",
        kind: "result",
        semanticTerminalId: "operation-success",
        carrierProjection: createShaderModuleCompletionCarrier,
        bytesHex: toHex(createShaderModuleCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      {
        id: "device-destroy-sealed-timeline-request",
        kind: "request",
        carrierProjection: deviceDestroyRequestCarrier,
        trust:
          "untrusted-wrapper-record-prefix-join-only-never-authority",
        semanticOwner:
          "native-semantic-service-before-provider-admission",
        bytesHex: toHex(deviceDestroyBytes),
        expected: expectedDeviceDestroyRequest,
      },
      {
        id: "device-destroy-repeat-cleanup-noop-result",
        kind: "result",
        semanticTerminalId: "repeat-cleanup-noop",
        carrierProjection: deviceDestroyCompletionCarrier(0, "0"),
        bytesHex: toHex(deviceDestroyCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      {
        id: "device-destroy-first-cleanup-provider-result",
        kind: "result",
        semanticTerminalId: "first-cleanup-provider",
        carrierProjection: deviceDestroyCompletionCarrier(1, "8"),
        bytesHex: toHex(deviceDestroyCompletion),
        expected: { kind: "terminal-receipt", value: "undefined" },
      },
      ...lifecycleRequests.map((entry) => ({
        id: entry.id,
        operationId: entry.operationId,
        kind: "request",
        carrierProjection: lifecycleRequestCarrier(
          entry,
          entry.operationId === bufferMapAsyncOperationId ? "41" : "0",
        ),
        trust:
          "source-affine-wrapper-generation-and-owned-byte-comparison-input-only-never-authority",
        semanticOwner:
          "native-buffer-lifecycle-semantic-service-before-provider-admission",
        bytesHex: toHex(entry.bytes),
        expected: entry.inspected,
      })),
      ...["repeat-cleanup-noop", "first-cleanup-rejection", "first-cleanup-provider"]
        .map((terminal) => {
          const entry = requestById.get("buffer-destroy-map-write-request");
          const admitted = terminal === "first-cleanup-provider";
          return {
            id: `buffer-destroy-${terminal}-result`,
            operationId: bufferDestroyOperationId,
            kind: "result",
            semanticTerminalId: terminal,
            carrierProjection: lifecycleCompletionCarrier(
              entry,
              0,
              "0",
              admitted ? 1 : 0,
              admitted ? "51" : "0",
            ),
            bytesHex: toHex(cleanupTerminalBytes.get(
              `${bufferDestroyOperationId}:${terminal}`,
            )),
            expected: { kind: "terminal-receipt", value: "undefined" },
          };
        }),
      ...["unmapped-noop", "cleanup-rejection", "cleanup-provider"]
        .map((terminal) => {
          const entry = requestById.get("buffer-unmap-map-write-request");
          const admitted = terminal === "cleanup-provider";
          return {
            id: `buffer-unmap-${terminal}-result`,
            operationId: bufferUnmapOperationId,
            kind: "result",
            semanticTerminalId: terminal,
            carrierProjection: lifecycleCompletionCarrier(
              entry,
              0,
              "0",
              admitted ? 1 : 0,
              admitted ? "52" : "0",
            ),
            bytesHex: toHex(cleanupTerminalBytes.get(
              `${bufferUnmapOperationId}:${terminal}`,
            )),
            expected: { kind: "terminal-receipt", value: "undefined" },
          };
        }),
      ...mapCompletions.map(({ result, bytes }) => {
        const entry = requestById.get(
          result.variant === "mapped-bytes"
            ? "buffer-map-async-read-omitted-size-request"
            : "buffer-map-async-write-present-size-request",
        );
        return {
          id: `buffer-map-async-${result.variant}-result`,
          operationId: bufferMapAsyncOperationId,
          kind: "result",
          semanticTerminalId: result.variant === "mapped-bytes"
            ? "operation-success"
            : result.variant === "late-cancelled-cleanup"
            ? "late-cancelled-cleanup"
            : "provider-map-rejection",
          carrierProjection: lifecycleCompletionCarrier(
            entry,
            4,
            "41",
            1,
            "53",
          ),
          bytesHex: toHex(bytes),
          expected: {
            ...result,
            ownedBytes: Array.from(result.ownedBytes),
          },
        };
      }),
      ...lifecycleBinaryRejections.map((rejection) => ({
        id: rejection.id,
        operationId: rejection.operationId,
        kind: "binary-rejection",
        direction: rejection.direction,
        mutation: rejection.mutation,
        bytesHex: toHex(rejection.bytes),
        expected: { rejection: "fail-closed-before-provider-or-wrapper-exposure" },
      })),
      {
        id: "buffer-map-async-source-generation-mismatch-rejected",
        operationId: bufferMapAsyncOperationId,
        kind: "semantic-rejection",
        carrierProjection: lifecycleRequestCarrier(
          requestById.get("buffer-map-async-read-omitted-size-request"),
          "41",
        ),
        authenticatedStateMutation: {
          currentPendingMapGeneration: "9",
          payloadPendingMapGeneration: "8",
        },
        expected: {
          rejection: "source-affine-generation-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      ...canvasLifecycleRequests.map((entry) => ({
        id: entry.id,
        operationId: entry.operationId,
        kind: "request",
        carrierProjection: canvasRequestCarrier(entry),
        trust:
          "source-affine-wrapper-generation-origin-and-surface-account-comparison-input-only-never-authority",
        semanticOwner:
          "native-canvas-lifecycle-semantic-service-before-provider-admission",
        bytesHex: toHex(entry.encoded.bytes),
        expected: entry.encoded.inspected,
      })),
      ...canvasCarrierRejections,
      ...[
        {
          entry: canvasRequestById.get(
            "canvas-configure-next-generation-request",
          ),
          terminal: "operation-success",
          providerAdmission: 1,
          physicalSequence: "63",
        },
        {
          entry: canvasRequestById.get(
            "canvas-unconfigure-retiring-generation-request",
          ),
          terminal: "first-cleanup-provider",
          providerAdmission: 1,
          physicalSequence: "64",
        },
        {
          entry: canvasRequestById.get(
            "texture-destroy-repeat-cleanup-noop-request",
          ),
          terminal: "repeat-cleanup-noop",
          providerAdmission: 0,
          physicalSequence: "0",
        },
        {
          id: "gputexture-destroy-expired-repeat-cleanup-noop-result",
          entry: canvasRequestById.get(
            "texture-destroy-expired-canvas-current-request",
          ),
          terminal: "repeat-cleanup-noop",
          providerAdmission: 0,
          physicalSequence: "0",
        },
      ].map(({ id, entry, terminal, providerAdmission, physicalSequence }) => {
        assertSemanticTerminalCounts(
          entry.operationId,
          terminal,
          providerAdmission,
          physicalSequence,
        );
        return {
          id: id ??
            `${entry.operationId.replaceAll(".", "-").toLowerCase()}-${terminal}-result`,
          operationId: entry.operationId,
          kind: "result",
          semanticTerminalId: terminal,
          carrierProjection: canvasCompletionCarrier(
            entry,
            providerAdmission,
            physicalSequence,
          ),
          bytesHex: toHex(canvasTerminalBytes.get(
            `${entry.operationId}:${terminal}`,
          )),
          expected: { kind: "terminal-receipt", value: "undefined" },
        };
      }),
      ...canvasBinaryRejections.map((rejection) => ({
        id: rejection.id,
        operationId: rejection.operationId,
        kind: "binary-rejection",
        direction: "request",
        mutation: rejection.mutation,
        bytesHex: toHex(rejection.bytes),
        expected: {
          rejection: "fail-closed-before-provider-or-wrapper-exposure",
        },
      })),
      {
        id: "canvas-configure-extended-tone-mapping-content-rejected",
        operationId: canvasConfigureOperationId,
        kind: "content-timeline-rejection",
        convertedArguments: convertedCanvasExtendedToneMapping,
        observedDictionaryGetOrder: [
          "alphaMode",
          "colorSpace",
          "device",
          "format",
          "toneMapping",
          "toneMapping.mode",
          "usage",
          "viewFormats",
        ],
        expected: {
          rejection: "phase-1a-tone-mapping-mode-is-standard",
          configurationPublicationCount: 0,
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "canvas-configure-candidate-generation-mismatch-rejected",
        operationId: canvasConfigureOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "canvas-configure-next-generation-request",
        )),
        authenticatedStateMutation: {
          currentConfigurationGeneration: "8",
          requiredCandidateConfigurationGeneration: "9",
          payloadConfigurationGeneration: "8",
        },
        expected: {
          rejection: "source-affine-generation-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "canvas-unconfigure-retiring-generation-mismatch-rejected",
        operationId: canvasUnconfigureOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "canvas-unconfigure-retiring-generation-request",
        )),
        authenticatedStateMutation: {
          currentConfigurationGeneration: "9",
          payloadConfigurationGeneration: "8",
        },
        expected: {
          rejection: "source-affine-generation-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "texture-destroy-current-epoch-mismatch-rejected",
        operationId: textureDestroyOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "texture-destroy-expired-canvas-current-request",
        )),
        authenticatedStateMutation: {
          currentTextureEpoch: "14",
          payloadCurrentEpoch: "13",
        },
        expected: {
          rejection: "source-affine-generation-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "canvas-configure-authenticated-snapshot-mismatch-rejected",
        operationId: canvasConfigureOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "canvas-configure-next-generation-request",
        )),
        bytesHex: toHex(configureBytes),
        authenticatedStateMutation: {
          installedConfigurationGeneration: "8",
          installedFormat: "bgra8unorm",
          installedUsage: 17,
          installedViewFormats: ["rgba16float"],
          installedToneMappingMode: "standard",
          payloadViewFormats: ["rgba8unorm", "rgba8unorm"],
        },
        expected: {
          rejection:
            "source-affine-configured-state-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "canvas-configure-surface-account-state-mismatch-rejected",
        operationId: canvasConfigureOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "canvas-configure-next-generation-request",
        )),
        bytesHex: toHex(configureBytes),
        authenticatedStateMutation: {
          currentSurfaceAccountToken: "20",
          payloadSurfaceAccountToken: "19",
          currentSurfaceAccountGeneration: "23",
          payloadSurfaceAccountGeneration: "23",
        },
        expected: {
          rejection: "source-affine-surface-account-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "texture-destroy-origin-digest-state-mismatch-rejected",
        operationId: textureDestroyOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "texture-destroy-expired-canvas-current-request",
        )),
        bytesHex: toHex(expiredTextureDestroyBytes),
        authenticatedStateMutation: {
          authenticatedTextureOriginDigest: "cd".repeat(32),
          payloadTextureOriginDigest: canvasTextureOriginDigest,
        },
        expected: {
          rejection: "source-affine-texture-origin-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "texture-destroy-materialization-state-mismatch-rejected",
        operationId: textureDestroyOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "texture-destroy-expired-canvas-current-request",
        )),
        bytesHex: toHex(expiredTextureDestroyBytes),
        authenticatedStateMutation: {
          authenticatedMaterializationState: "unmaterialized",
          payloadMaterializationState: "materialized",
        },
        expected: {
          rejection: "texture-materialization-state-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "texture-destroy-terminal-state-mismatch-rejected",
        operationId: textureDestroyOperationId,
        kind: "semantic-rejection",
        carrierProjection: canvasRequestCarrier(canvasRequestById.get(
          "texture-destroy-expired-canvas-current-request",
        )),
        bytesHex: toHex(expiredTextureDestroyBytes),
        authenticatedStateMutation: {
          authenticatedTextureTerminalState: "already-destroyed",
          requiredTerminalIntent: "repeat-cleanup-noop",
          payloadTerminalIntent: "first-expired-cleanup",
        },
        expected: {
          rejection: "texture-terminal-intent-mismatch-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      {
        id: "canvas-current-same-epoch-wrapper-reuse",
        operationId: "GPUCanvasContext.getCurrentTexture",
        kind: "wrapper-local-invariant",
        configuredGeneration: "8",
        callsWithinSameEpoch: 2,
        expected: {
          sameWrapperIdentity: true,
          currentEpochIncrementCount: 1,
          nativeCodecRouteCount: 0,
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      },
      ...queueWriteBufferRequests.map((entry) => ({
        id: entry.id,
        operationId: queueWriteBufferOperationId,
        kind: "request",
        carrierProjection: queueWriteBufferCarrier,
        trust:
          "source-affine-queue-and-destination-generation-joins-plus-one-owned-snapshot-never-authority",
        semanticOwner:
          "native-queue-write-semantic-service-before-provider-admission",
        bytesHex: toHex(entry.bytes),
        expected: entry.inspected,
      })),
      ...[
        ["later-predicate-rejection", 0, "0"],
        ["operation-success", 1, "71"],
      ].map(([terminal, providerAdmission, physicalSequence]) => ({
        id: `queue-write-buffer-${terminal}-result`,
        operationId: queueWriteBufferOperationId,
        kind: "result",
        semanticTerminalId: terminal,
        carrierProjection: queueWriteBufferCompletionCarrier(
          providerAdmission,
          physicalSequence,
        ),
        bytesHex: toHex(queueWriteBufferCompletionBytes.get(terminal)),
        expected: { kind: "terminal-receipt", value: "undefined" },
      })),
      ...queueWriteBufferBinaryRejections.map((rejection) => ({
        id: rejection.id,
        operationId: queueWriteBufferOperationId,
        kind: "binary-rejection",
        direction: "request",
        mutation: rejection.mutation,
        bytesHex: toHex(rejection.bytes),
        expected: {
          rejection: "fail-closed-before-provider-or-wrapper-exposure",
        },
      })),
      ...queueWriteTextureRequests.map((entry) => ({
        id: entry.id,
        operationId: queueWriteTextureOperationId,
        kind: "request",
        carrierProjection: queueWriteTextureCarrier,
        trust:
          "source-affine-queue-plus-full-untrusted-texture-provenance-and-one-whole-owned-snapshot-never-authority",
        semanticOwner:
          "native-queue-write-texture-semantic-service-before-provider-admission",
        bytesHex: toHex(entry.bytes),
        expected: entry.inspected,
      })),
      ...queueWriteTextureSemanticRejections.map((entry) => ({
        id: entry.id,
        operationId: queueWriteTextureOperationId,
        kind: "semantic-rejection",
        direction: "request",
        mutation: entry.mutation,
        carrierProjection: queueWriteTextureCarrier,
        semanticTerminalId: "later-predicate-rejection",
        firstFailingPredicate:
          "queue.write-texture.destination-current-same-device",
        bytesHex: toHex(entry.bytes),
        expected: {
          convertedArguments: entry.inspected.convertedArguments,
          rejection: "device-timeline-validation-before-provider-admission",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      })),
      ...[
        ["later-predicate-rejection", 0, "0"],
        ["operation-success", 1, "72"],
      ].map(([terminal, providerAdmission, physicalSequence]) => ({
        id: `queue-write-texture-${terminal}-result`,
        operationId: queueWriteTextureOperationId,
        kind: "result",
        semanticTerminalId: terminal,
        carrierProjection: queueWriteTextureCompletionCarrier(
          providerAdmission,
          physicalSequence,
        ),
        bytesHex: toHex(queueWriteTextureCompletionBytes.get(terminal)),
        expected: { kind: "terminal-receipt", value: "undefined" },
      })),
      ...queueWriteTextureBinaryRejections.map((rejection) => ({
        id: rejection.id,
        operationId: queueWriteTextureOperationId,
        kind: "binary-rejection",
        direction: "request",
        mutation: rejection.mutation,
        bytesHex: toHex(rejection.bytes),
        expected: {
          rejection: "fail-closed-before-provider-or-wrapper-exposure",
        },
      })),
      ...queueSubmitRequests.map((entry) => ({
        id: entry.id,
        operationId: queueSubmitOperationId,
        kind: "request",
        carrierProjection: queueSubmitCarrier,
        trust:
          "sealed-record-table-and-command-program-indices-plus-digest-are-comparison-input-only-never-authority",
        semanticOwner:
          "native-queue-submit-semantic-service-before-provider-admission",
        bytesHex: toHex(entry.bytes),
        expected: entry.inspected,
      })),
      ...queueSubmitBinaryRejections.map((rejection) => ({
        id: rejection.id,
        operationId: queueSubmitOperationId,
        kind: "binary-rejection",
        direction: "request",
        mutation: rejection.mutation,
        bytesHex: toHex(rejection.bytes),
        expected: {
          rejection: "fail-closed-before-provider-or-wrapper-exposure",
        },
      })),
      ...[
        ["captured-scope", { captured_scope_id: "2" }],
        ["device-ingress", { device_ingress_ordinal: "31" }],
        ["queue-ingress", { queue_ingress_ordinal: "32" }],
        ["receiver-generation", {
          receiver: { ...queueSubmitCarrier.receiver, object_generation: "6" },
        }],
        ["provider-generation", { provider_generation: "10" }],
      ].map(([join, carrierMutation]) => ({
        id: `queue-submit-${join}-carrier-mismatch-rejected`,
        operationId: queueSubmitOperationId,
        kind: "carrier-join-rejection",
        carrierProjection: queueSubmitCarrier,
        carrierMutation,
        expected: {
          rejection: "authenticated-carrier-payload-join-mismatch",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      })),
      ...[
        ["captured-scope", { captured_scope_id: "3" }],
        ["device-ingress", { device_ingress_ordinal: "4" }],
        ["queue-ingress", { queue_ingress_ordinal: "5" }],
        ["receiver-generation", {
          receiver: { ...queueWriteBufferCarrier.receiver, object_generation: "6" },
        }],
        ["provider-generation", { provider_generation: "10" }],
      ].map(([join, carrierMutation]) => ({
        id: `queue-write-buffer-${join}-carrier-mismatch-rejected`,
        operationId: queueWriteBufferOperationId,
        kind: "carrier-join-rejection",
        carrierProjection: queueWriteBufferCarrier,
        carrierMutation,
        expected: {
          rejection: "authenticated-carrier-payload-join-mismatch",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      })),
      ...[
        ["captured-scope", { captured_scope_id: "3" }],
        ["device-ingress", { device_ingress_ordinal: "4" }],
        ["queue-ingress", { queue_ingress_ordinal: "6" }],
        ["receiver-generation", {
          receiver: { ...queueWriteTextureCarrier.receiver, object_generation: "6" },
        }],
        ["provider-generation", { provider_generation: "10" }],
      ].map(([join, carrierMutation]) => ({
        id: `queue-write-texture-${join}-carrier-mismatch-rejected`,
        operationId: queueWriteTextureOperationId,
        kind: "carrier-join-rejection",
        carrierProjection: queueWriteTextureCarrier,
        carrierMutation,
        expected: {
          rejection: "authenticated-carrier-payload-join-mismatch",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        },
      })),
    ],
  };
}

function main() {
  const rendered = `${JSON.stringify(buildCorpus(), null, 2)}\n`;
  if (process.argv.includes("--check")) {
    const output = assertConfinedGeneratedFile(
      repositoryRoot,
      outputPath,
      "WebGPU language-neutral codec corpus",
    );
    if (fs.readFileSync(output.path, "utf8") !== rendered) {
      fail(
        "WebGPU codec corpus is stale; run bun run generate:webgpu-production-codec-corpus",
      );
    }
    console.log(
      "webgpu-production-codec-corpus: requestAdapter, requestDevice unknown-limit/live/detached, createBindGroup 18-call/full-provenance-witness/structural/adversarial, createBindGroupLayout, createBuffer 21-call/accounting/adversarial, createPipelineLayout, createSampler four-call/accounting/adversarial, createTexture five-call/accounting/adversarial, createTextureView 25-call/8-class/device-and-canvas/origin-ordering/adversarial, createCommandEncoder, createShaderModule, device-destroy, GPUBuffer destroy/mapAsync/unmap, canvas configure/unconfigure/texture-destroy generation-and-origin/adversarial, GPUQueue.writeBuffer/writeTexture, and GPUQueue.submit 15-command-record/timeline/digest/adversarial payload-codegen vectors are fresh",
    );
    return;
  }
  writeGeneratedFilesTransactionally(repositoryRoot, [
    {
      path: outputPath,
      content: rendered,
      label: "WebGPU language-neutral codec corpus",
    },
  ]);
  console.log(
    `webgpu-production-codec-corpus: wrote ${outputPath}`,
  );
}

try {
  main();
} catch (error) {
  console.error(
    "webgpu-production-codec-corpus: " +
      (error instanceof Error ? error.message : String(error)),
  );
  process.exitCode = 1;
}
