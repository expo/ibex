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

  const convertedArguments =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [
        Object.freeze({
          powerPreference: "high-performance",
          forceFallbackAdapter: false,
        }),
      ],
      Object.freeze({
        reference() {
          fail("requestAdapter conversion must not inspect a wrapper reference");
        },
      }),
    );
  const expectedConvertedArguments = Object.freeze({
    forceFallbackAdapter: false,
    featureLevel: "core",
    xrCompatible: false,
    powerPreference: "high-performance",
  });
  if (
    canonicalJson(convertedArguments) !==
    canonicalJson(expectedConvertedArguments)
  ) {
    fail("requestAdapter WebIDL default projection drifted");
  }

  const request = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
    Object.freeze({
      operationId,
      wireId: route.wireId,
      convertedArguments,
      receiver: Object.freeze({
        kind: "GPU",
        objectId: "23",
        objectGeneration: "4",
        logicalDeviceId: "0",
        logicalDeviceGeneration: "0",
        providerGeneration: "0",
      }),
      capturedScopeId: "0",
      adapterOrdinal: "0",
      deviceIngressOrdinal: "0",
      queueIngressOrdinal: "0",
      sealedLocalTimeline: Object.freeze([]),
    }),
  );
  const inspected =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(request);
  const expectedInspected = {
    operationId,
    codec: requestCodec.tag,
    receiver: {
      kind: "GPU",
      objectId: "23",
      objectGeneration: "4",
      logicalDeviceId: "0",
      logicalDeviceGeneration: "0",
      providerGeneration: "0",
    },
    target: null,
    capturedScopeId: "0",
    adapterOrdinal: "0",
    deviceIngressOrdinal: "0",
    queueIngressOrdinal: "0",
    sealedLocalTimeline: [],
    convertedArguments: expectedConvertedArguments,
  };
  if (canonicalJson(inspected) !== canonicalJson(expectedInspected)) {
    fail("requestAdapter generated request does not round-trip through inspection");
  }

  const objectResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(operationId, {
      kind: "adapter",
      objectId: "41",
      objectGeneration: "2",
      providerGeneration: "9",
    });
  const nullResult =
    WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(operationId, {
      kind: "null",
    });
  const objectResultEvent = Object.freeze({
    operationId: route.wireId,
    resultKind: 3,
    providerAdmission: 1,
    physicalSequence: "5",
    deviceTransition: 0,
    logicalDeviceId: "0",
    logicalDeviceGeneration: "0",
    providerGeneration: "0",
    operationProviderGeneration: "9",
    payload: objectResult,
  });
  const nullResultEvent = Object.freeze({
    operationId: route.wireId,
    resultKind: 2,
    providerAdmission: 1,
    physicalSequence: "5",
    deviceTransition: 0,
    logicalDeviceId: "0",
    logicalDeviceGeneration: "0",
    providerGeneration: "0",
    operationProviderGeneration: "9",
    payload: nullResult,
  });
  const decodedObject =
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      operationId,
      objectResultEvent,
    );
  const decodedNull = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
    operationId,
    nullResultEvent,
  );
  if (
    canonicalJson(decodedObject) !==
      canonicalJson({
        kind: "object",
        object: {
          kind: "GPUAdapter",
          objectId: "41",
          objectGeneration: "2",
          providerGeneration: "9",
        },
      }) ||
    canonicalJson(decodedNull) !== canonicalJson({ kind: "null" })
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
    schema: "ibex/webgpu-production-codec-corpus/1",
    disposition:
      "generated-language-neutral-request-adapter-conformance-no-native-install-claim",
    supportClaim: "none",
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
      requestCodec: requestCodec.tag,
      requestCodecTag: requestCodec.wireTag,
      completionCodec: completionCodec.tag,
      completionCodecTag: completionCodec.wireTag,
    },
    vectors: [
      {
        id: "request-adapter-high-performance",
        kind: "request",
        bytesHex: toHex(request),
        expected: {
          receiver: {
            kind: "GPU",
            objectId: "23",
            objectGeneration: "4",
            logicalDeviceId: "0",
            logicalDeviceGeneration: "0",
            providerGeneration: "0",
          },
          target: null,
          capturedScopeId: "0",
          adapterOrdinal: "0",
          deviceIngressOrdinal: "0",
          queueIngressOrdinal: "0",
          sealedLocalTimeline: [],
          convertedArguments: expectedConvertedArguments,
        },
      },
      {
        id: "request-adapter-object-result",
        kind: "result",
        event: {
          operationId: route.wireId,
          resultKind: 3,
          providerAdmission: 1,
          physicalSequence: "5",
          deviceTransition: 0,
          logicalDeviceId: "0",
          logicalDeviceGeneration: "0",
          providerGeneration: "0",
          operationProviderGeneration: "9",
        },
        bytesHex: toHex(objectResult),
        expected: {
          kind: "object",
          object: {
            kind: "GPUAdapter",
            objectId: "41",
            objectGeneration: "2",
            providerGeneration: "9",
          },
        },
      },
      {
        id: "request-adapter-null-result",
        kind: "result",
        event: {
          operationId: route.wireId,
          resultKind: 2,
          providerAdmission: 1,
          physicalSequence: "5",
          deviceTransition: 0,
          logicalDeviceId: "0",
          logicalDeviceGeneration: "0",
          providerGeneration: "0",
          operationProviderGeneration: "9",
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
      "webgpu-production-codec-corpus: requestAdapter request/object/null and UTF-8 ordering vectors are fresh",
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
