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
      "create-bind-group-layout-overlong-label-rejected",
      {
        label: "💡".repeat(15),
        entries: [{ binding: 0, visibility: 7, buffer: {} }],
      },
      "exceeds the reviewed workload bounds",
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
      "generated-language-neutral-request-adapter-request-device-create-bind-group-layout-create-command-encoder-create-shader-module-device-destroy-payload-codegen-positive-and-adversarial-interoperability-vectors-no-native-install-claim",
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
      "webgpu-production-codec-corpus: requestAdapter, requestDevice unknown-limit/live/detached, createBindGroupLayout positive/adversarial, createCommandEncoder, createShaderModule, and device-destroy payload-codegen vectors are fresh",
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
