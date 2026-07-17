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
const outputPath =
  "tests/fixtures/webgpu-production-codec-corpus-v1.generated.json";
const operationId = "GPU.requestAdapter";

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
      "generated-language-neutral-request-adapter-payload-codegen-positive-interoperability-vectors-no-native-install-claim",
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
    vectors: [
      defaultRequest,
      highPerformanceRequest,
      compatibilityRequest,
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
      "webgpu-production-codec-corpus: requestAdapter request/live-object/detached-object/null and UTF-8 ordering vectors are fresh",
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
