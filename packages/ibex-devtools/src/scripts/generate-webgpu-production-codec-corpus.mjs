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
const outputPath =
  "tests/fixtures/webgpu-production-codec-corpus-v1.generated.json";
const operationId = "GPU.requestAdapter";
const requestDeviceOperationId = "GPUAdapter.requestDevice";
const createBindGroupLayoutOperationId = "GPUDevice.createBindGroupLayout";
const createBufferOperationId = "GPUDevice.createBuffer";
const createPipelineLayoutOperationId = "GPUDevice.createPipelineLayout";
const createSamplerOperationId = "GPUDevice.createSampler";
const createTextureOperationId = "GPUDevice.createTexture";
const createCommandEncoderOperationId = "GPUDevice.createCommandEncoder";
const createShaderModuleOperationId = "GPUDevice.createShaderModule";
const deviceDestroyOperationId = "GPUDevice.destroy";

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
    });
  const detachedExpiredObjectResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(operationId, {
      kind: "adapter",
      objectId: "42",
      objectGeneration: "3",
      providerGeneration: "9",
      serviceDetachedExpired: true,
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
    "validate-buffer-mapped-at-creation-alignment",
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
    ["sealed-timeline-gap", { sealedLocalTimelinePrefixContiguous: false }],
    ["stale-device-generation", { deviceGeneration: "stale" }],
    ["coverage-absent", { operationCoverageInstalled: false }],
    ["aggregate-envelope-not-live", { aggregateEnvelopeState: "CLOSED" }],
    ["unreviewed-workload-size", { descriptor: { size: 8 } }],
    ["logical-max-below-size", { logicalMaxBufferSize: 64 }],
    ["closed-usage-mask-mismatch", { allowedBufferUsageMask: 12 }],
    ["illegal-map-usage-combination", { reviewedUsageSetAdds: 3, usage: 3 }],
    ["mapped-size-misaligned", { reviewedSizeSetAdds: 6, size: 6 }],
    ["foreign-target-provenance", { targetLogicalDeviceId: "56" }],
    ["stale-target-generation", { targetSlotGeneration: "2" }],
    ["dual-ledger-capacity-exhausted", { aggregateEnvelopeResourceCredit: 0 }],
    ["provider-completion-credit-exhausted", { completionCredit: 0 }],
    ["overlong-label", { label: "x".repeat(44) }],
  ]);
  const createBufferAdversarialVectors = Object.freeze(
    createBufferAdversarialMutations.map(([suffix, mutation], index) =>
      Object.freeze({
        id: `create-buffer-${suffix}-rejected`,
        kind: "semantic-rejection",
        operationId: createBufferOperationId,
        semanticTerminalId: "later-predicate-rejection",
        semanticStepIndex: index + 1,
        firstFailingSemanticStep: createBufferSemanticSteps[index],
        earlierSemanticStepsMustPass: createBufferSemanticSteps.slice(0, index),
        mutation,
        bytesHex: positiveBufferVector.bytesHex,
        expected: Object.freeze({
          codegenDisposition: "encoded-for-post-decode-semantic-validation",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
        }),
      })),
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
    { dimension: "2d", format: "rgba8unorm", label: "texture", mipLevelCount: 1, sampleCount: 1, size: [32, 32], usage: 23, viewFormats: [] },
    { format: "rgba8unorm", size: [64, 64], usage: 22 },
    { format: "rgba8unorm", size: [32, 32], usage: 17 },
    { dimension: "2d", format: "rgba8unorm", label: "trackTexture", mipLevelCount: 1, sampleCount: 1, size: [512, 512], usage: 23, viewFormats: [] },
    { dimension: "2d", format: "rgba16float", label: "bezierTexture", mipLevelCount: 1, sampleCount: 1, size: [256, 128], usage: 31, viewFormats: [] },
  ]);
  const textureExpectedDescriptors = Object.freeze([
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "texture", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 32, width: 32 }), usage: 23, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 64, width: 64 }), usage: 22, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 32, width: 32 }), usage: 17, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba8unorm", label: "trackTexture", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 512, width: 512 }), usage: 23, viewFormats: Object.freeze([]) }),
    Object.freeze({ dimension: "2d", format: "rgba16float", label: "bezierTexture", mipLevelCount: 1, sampleCount: 1, size: Object.freeze({ depthOrArrayLayers: 1, height: 128, width: 256 }), usage: 31, viewFormats: Object.freeze([]) }),
  ]);
  const textureBytes = Object.freeze([4_096, 16_384, 4_096, 1_048_576, 262_144]);
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
      ["mip-sample-bounds", { mipLevelCount: 7 }],
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
  if (textureBytes.reduce((sum, value) => sum + value, 0) !== 1_335_296) {
    fail("GPUDevice.createTexture checked workload byte evidence drifted");
  }

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
      "generated-language-neutral-request-adapter-request-device-create-bind-group-layout-create-buffer-create-pipeline-layout-create-sampler-create-texture-create-command-encoder-create-shader-module-device-destroy-payload-codegen-positive-and-adversarial-interoperability-vectors-no-native-install-claim",
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
          totalResourceBytes: 1_335_296,
          extents: [[32, 32, 1], [64, 64, 1], [32, 32, 1], [512, 512, 1], [256, 128, 1]],
          formats: ["rgba8unorm", "rgba16float"],
          usages: [17, 22, 23, 31],
          mipLevelCounts: [1],
          sampleCounts: [1],
          maximumLabelUtf8Bytes: 13,
        },
        semanticStepOrder: textureCorpus.semanticSteps,
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
      "webgpu-production-codec-corpus: requestAdapter, requestDevice unknown-limit/live/detached, createBindGroupLayout, createBuffer 21-call/accounting/adversarial, createPipelineLayout, createSampler four-call/accounting/adversarial, createTexture five-call/accounting/adversarial, createCommandEncoder, createShaderModule, and device-destroy payload-codegen vectors are fresh",
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
