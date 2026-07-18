#!/usr/bin/env bun
/**
 * Generate the construction-private production wrapper routing table from the
 * reviewed Exact projection already pinned in this repository.
 *
 * The source projection still classifies its payload/result codecs as
 * descriptive. This generator emits both routing data and a reviewed
 * injection-only codec manifest whose missing authenticated inputs remain
 * explicit. It cannot enable navigator.gpu or create a support claim.
 *
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 * @ref LLP 0017#2-add-one-regenerate-command-and-one-drift-check
 */

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertConfinedGeneratedFile,
  writeGeneratedFilesTransactionally,
} from "./generated-output-io.mjs";
import {
  REVIEWED_DIGESTS,
  validateWebGpuWrapperSemantics,
  validateWebGpuWrapperAuthority,
} from "./webgpu-test-wrapper-generator.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../../../..");
const authorityPath = "tests/fixtures/webgpu-test-wrapper-authority-v1.json";
const semanticsPath = "tests/fixtures/webgpu-test-wrapper-semantics-v1.json";
const workloadStagingPath =
  "tests/fixtures/webgpu-typegpu-workload-staging-v1.json";
const outputPath =
  "packages/ibex-runtime-js/src/webgpu/production-plan.generated.ts";
const codecOutputPath =
  "packages/ibex-runtime-js/src/webgpu/production-codecs.generated.ts";
const codecManifestOutputPath =
  "tests/fixtures/webgpu-production-codec-manifest-v1.generated.json";
const runtimeHeaderPath = "include/exact_runtime.h";
const webGpuTypesPackagePath = "node_modules/@webgpu/types/package.json";
const webGpuTypesDeclarationPath =
  "node_modules/@webgpu/types/dist/index.d.ts";
const webGpuTypesVersion = "0.1.71";

function readJson(sourcePath, label) {
  const confined = assertConfinedGeneratedFile(
    repositoryRoot,
    sourcePath,
    label,
  );
  return JSON.parse(fs.readFileSync(confined.path, "utf8"));
}

const REQUIRED_WORKLOAD_BLOCKERS = Object.freeze([
  "ordered-logical-semantic-program",
  "executable-public-and-service-codecs",
  "matching-native-service-decoder-and-provider-method",
  "generated-capsec-edge-and-supported-target-cell",
  "native-conformance-and-platform-evidence",
]);
const WRAPPER_LOCAL_METADATA_OPERATION_IDS = Object.freeze([
  "GPUBuffer.mapState",
  "GPUBuffer.usage",
  "GPUTexture.dimension",
  "GPUTexture.format",
  "GPUTexture.height",
  "GPUTexture.width",
]);
const IMMUTABLE_TRIANGLE_ROUTE_IDS = Object.freeze([
  "GPU.getPreferredCanvasFormat",
  "GPU.requestAdapter",
  "GPUAdapter.requestDevice",
  "GPUCanvasContext.configure",
  "GPUCanvasContext.getConfiguration",
  "GPUCanvasContext.getCurrentTexture",
  "GPUCanvasContext.unconfigure",
  "GPUCommandEncoder.beginRenderPass",
  "GPUCommandEncoder.finish",
  "GPUDevice.createCommandEncoder",
  "GPUDevice.createRenderPipeline",
  "GPUDevice.createShaderModule",
  "GPUDevice.destroy",
  "GPUDevice.features",
  "GPUDevice.limits",
  "GPUDevice.lost",
  "GPUDevice.popErrorScope",
  "GPUDevice.pushErrorScope",
  "GPUDevice.queue",
  "GPUQueue.submit",
  "GPURenderPassEncoder.draw",
  "GPURenderPassEncoder.end",
  "GPURenderPassEncoder.setPipeline",
  "GPUTexture.createView",
  "GPUTexture.destroy",
]);

function exactSet(actual, expected, label) {
  if (
    !Array.isArray(actual) ||
    !Array.isArray(expected) ||
    new Set(actual).size !== actual.length ||
    new Set(expected).size !== expected.length
  ) {
    throw new Error(`${label} must contain unique arrays`);
  }
  const canonical = (values) => [...new Set(values)].sort();
  if (JSON.stringify(canonical(actual)) !== JSON.stringify(canonical(expected))) {
    throw new Error(`${label} drifted`);
  }
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

function readPinnedWebIdlVocabulary() {
  const packageMetadata = JSON.parse(
    fs.readFileSync(path.join(repositoryRoot, webGpuTypesPackagePath), "utf8"),
  );
  if (
    packageMetadata.name !== "@webgpu/types" ||
    packageMetadata.version !== webGpuTypesVersion
  ) {
    throw new Error(
      `WebGPU Web IDL vocabulary requires @webgpu/types@${webGpuTypesVersion}`,
    );
  }

  const declarationBytes = fs.readFileSync(
    path.join(repositoryRoot, webGpuTypesDeclarationPath),
  );
  const declaration = declarationBytes.toString("utf8");
  const stringUnion = (name, expectedCount) => {
    const match = new RegExp(`\\btype\\s+${name}\\s*=\\s*([\\s\\S]*?);`, "u")
      .exec(declaration);
    if (!match) throw new Error(`pinned @webgpu/types omits ${name}`);
    const body = match[1];
    const values = [...body.matchAll(/\|\s*"([^"]+)"/gu)]
      .map((entry) => entry[1]);
    const unparsed = body.replace(/\|\s*"[^"]+"/gu, "").replace(/\s/gu, "");
    if (
      unparsed !== "" ||
      values.length !== expectedCount ||
      new Set(values).size !== values.length
    ) {
      throw new Error(`pinned ${name} vocabulary drifted`);
    }
    return Object.freeze(values);
  };
  const gpuTextureFormats = stringUnion("GPUTextureFormat", 101);
  if (
    !gpuTextureFormats.includes("r16unorm") ||
    !gpuTextureFormats.includes("bc7-rgba-unorm") ||
    !gpuTextureFormats.includes("astc-12x12-unorm-srgb")
  ) {
    throw new Error("pinned GPUTextureFormat vocabulary drifted");
  }

  return Object.freeze({
    bindingPackage: "@webgpu/types",
    bindingPackageVersion: webGpuTypesVersion,
    declarationPath: webGpuTypesDeclarationPath,
    declarationSha256: crypto
      .createHash("sha256")
      .update(declarationBytes)
      .digest("hex"),
    gpuTextureFormats: Object.freeze(gpuTextureFormats),
    gpuAddressModes: stringUnion("GPUAddressMode", 3),
    gpuFilterModes: stringUnion("GPUFilterMode", 2),
    gpuMipmapFilterModes: stringUnion("GPUMipmapFilterMode", 2),
    gpuCompareFunctions: stringUnion("GPUCompareFunction", 8),
    gpuTextureDimensions: stringUnion("GPUTextureDimension", 3),
    gpuTextureViewDimensions: stringUnion("GPUTextureViewDimension", 6),
  });
}

function stagingProjectionSha256(staging) {
  const projection = { ...staging };
  delete projection.source;
  return crypto
    .createHash("sha256")
    .update(
      `exact/typegpu-workload-closure/ibex-staging-projection/v1\n${canonicalJson(projection)}\n`,
      "utf8",
    )
    .digest("hex");
}

function validateWorkloadStaging(staging, routeIds, activeScopeId) {
  if (
    staging?.schema !== "ibex/webgpu-typegpu-workload-staging/1" ||
    staging.artifactVersion !== 1 ||
    staging.status !== "audited-not-routable-not-installed" ||
    staging.supportClaim !== "none" ||
    staging.nativeExecutionEvidence !==
      "none-recording-provider-is-inventory-only" ||
    staging.typegpuVersion !== "0.11.9" ||
    staging.publicSurfaceRule !==
      "members-remain-absent-until-all-blockers-close-no-throwing-stubs" ||
    staging.embeddedCodecRule !==
      "EMBEDDED_EXECUTABLE_WEBGPU_CODECS-remains-undefined"
  ) {
    throw new Error("invalid TypeGPU workload staging authority");
  }
  if (
    staging.source?.path !== "tests/gpu/typegpu-workload-closure-v1.json" ||
    staging.source.fullArtifactSha256Disposition !==
      "provenance-only-excluded-to-avoid-outer-submodule-recursion" ||
    staging.source.normalizedProjectionSha256 !==
      stagingProjectionSha256(staging)
  ) {
    throw new Error("invalid TypeGPU normalized staging projection identity");
  }
  exactSet(staging.blockers, REQUIRED_WORKLOAD_BLOCKERS, "TypeGPU staging blockers");
  if (
    staging.activeRouteSubset.scopeId !== activeScopeId ||
    staging.activeRouteSubset.operationCount !== routeIds.length ||
    staging.activeRouteSubset.operationIds.length !== routeIds.length
  ) {
    throw new Error("TypeGPU active route subset scope or count drifted");
  }
  exactSet(
    staging.activeRouteSubset.operationIds,
    routeIds,
    "TypeGPU active route subset",
  );
  const operations = staging.workloadClosure?.operations;
  if (!Array.isArray(operations)) {
    throw new Error("TypeGPU workload operation closure is missing");
  }
  const operationIds = operations.map((operation) => operation.operationId);
  if (
    !Array.isArray(operations) ||
    new Set(operationIds).size !== operations.length ||
    staging.workloadClosure.operationCount !== operations.length
  ) {
    throw new Error("TypeGPU workload operation closure is not bijective");
  }
  const routeSet = new Set(routeIds);
  const triangleSet = new Set(IMMUTABLE_TRIANGLE_ROUTE_IDS);
  const wrapperLocalMetadataSet = new Set(WRAPPER_LOCAL_METADATA_OPERATION_IDS);
  if (triangleSet.size !== 25) {
    throw new Error("immutable TypeGPU triangle route set drifted");
  }
  exactSet(
    routeIds.filter((operationId) => triangleSet.has(operationId)),
    IMMUTABLE_TRIANGLE_ROUTE_IDS,
    "immutable TypeGPU active triangle routes",
  );
  const graduatedRouteSet = new Set(
    routeIds.filter((operationId) => !triangleSet.has(operationId)),
  );
  const workloadOperationSet = new Set(operationIds);
  exactSet(
    operations
      .filter(
        (operation) =>
          operation.disposition === "active-private-triangle-route",
      )
      .map((operation) => operation.operationId),
    IMMUTABLE_TRIANGLE_ROUTE_IDS.filter((operationId) =>
      workloadOperationSet.has(operationId),
    ),
    "TypeGPU workload triangle disposition rows",
  );
  exactSet(
    operations
      .filter(
        (operation) =>
          operation.disposition === "active-private-graduated-route",
      )
      .map((operation) => operation.operationId),
    [...graduatedRouteSet].filter((operationId) =>
      workloadOperationSet.has(operationId),
    ),
    "TypeGPU workload graduated disposition rows",
  );
  const additional = operations.filter(
    (operation) => !routeSet.has(operation.operationId),
  );
  if (staging.workloadClosure.additionalOperationCount !== additional.length) {
    throw new Error("TypeGPU additional operation count drifted");
  }
  for (const operation of operations) {
    const expectedDisposition = triangleSet.has(operation.operationId)
      ? "active-private-triangle-route"
      : graduatedRouteSet.has(operation.operationId)
        ? "active-private-graduated-route"
        : wrapperLocalMetadataSet.has(operation.operationId)
          ? "private-wrapper-local-metadata-read-no-dispatch"
        : "staged-unroutable-no-prototype-member";
    if (
      !["method", "property"].includes(operation.memberKind) ||
      operation.disposition !== expectedDisposition
    ) {
      throw new Error(`invalid TypeGPU staging disposition for ${operation.operationId}`);
    }
  }
  return Object.freeze({
    scopeId: staging.scopeId,
    status: staging.status,
    supportClaim: staging.supportClaim,
    nativeExecutionEvidence: staging.nativeExecutionEvidence,
    source: staging.source,
    typegpuVersion: staging.typegpuVersion,
    operationCount: operations.length,
    additionalOperationCount: additional.length,
    additionalOperations: additional,
    properties: staging.workloadClosure.properties,
    constants: staging.workloadClosure.constants,
    hostExtensions: staging.workloadClosure.hostExtensions,
    blockers: staging.blockers,
    publicSurfaceRule: staging.publicSurfaceRule,
    embeddedCodecRule: staging.embeddedCodecRule,
  });
}

function renderPlan(authority, workloadStaging, webIdlVocabulary) {
  const { payload, computed } = validateWebGpuWrapperAuthority(authority);
  const routes = payload.operations.map((operation) => ({
    operationId: operation.operationId,
    wireId: operation.wireId,
    interfaceName: operation.operationId.slice(
      0,
      operation.operationId.indexOf("."),
    ),
    memberName: operation.operationId.slice(
      operation.operationId.indexOf(".") + 1,
    ),
    memberKind: operation.memberKind,
    dispatchClass: operation.dispatchClass,
    logicalExecutionKind: operation.logicalExecutionKind,
    resultTiming: operation.resultTiming,
    providerSubmission: operation.providerSubmission,
    receiverHandleKind: operation.receiverHandleKind,
    wrapperAllocatedTargetHandleKind:
      operation.wrapperAllocatedTargetHandleKind,
    resultHandleKind: operation.resultHandleKind,
    serviceReceiverProjection: operation.serviceReceiverProjection,
    publicArgumentCodec: operation.publicArgumentCodec,
    serviceArgumentCodec: operation.serviceArgumentCodec,
    serviceCompletionCodec: operation.serviceCompletionCodec,
    publicResultCodec: operation.publicResultCodec,
    operationInstanceIdentity: operation.operationInstanceIdentity,
    promiseIdentity: operation.promiseIdentity,
  }));
  if (routes.length === 0 || new Set(routes.map((route) => route.operationId)).size !== routes.length) {
    throw new Error("production WebGPU plan must contain a nonempty unique route set");
  }
  const stagedWorkloadClosure = validateWorkloadStaging(
    workloadStaging,
    routes.map((route) => route.operationId),
    payload.scopeId,
  );
  const plan = {
    schema: "ibex/webgpu-production-wrapper-plan/1",
    profileId: payload.profileId,
    scopeId: payload.scopeId,
    maxPayloadBytes: payload.wireEnvelope.maxPayloadBytes,
    codecReadiness:
      "generated-injection-and-request-adapter-request-device-create-bind-group-layout-create-buffer-create-pipeline-layout-create-command-encoder-create-shader-module-device-destroy-payload-codegen-input-native-codec-not-installed",
    digests: computed,
    webIdlVocabulary,
    activeRouteSubset: {
      scopeId: payload.scopeId,
      operationCount: routes.length,
      operationIds: routes.map((route) => route.operationId),
    },
    stagedWorkloadClosure,
    routes,
  };
  return (
    "// Generated by generate-webgpu-production-plan.mjs; do not edit.\n" +
    "// The route table is production input, but navigator.gpu remains gated\n" +
    "// until a separately generated executable codec bundle validates it.\n" +
    "export const WEBGPU_PRODUCTION_PLAN = " +
    JSON.stringify(plan, null, 2) +
    " as const;\n"
  );
}

function serviceCodecBlockers(codec) {
  if (codec.tag === "none-service-request-v1") return ["no-service-call"];
  const blockers = [...(codec.requiredSemanticFields || [])];
  if (codec.tag === "gpu-request-device-service-request-v1") {
    blockers.push(
      "generatedLogicalProviderDescriptor",
      "authenticatedResultSelectionIdentity",
    );
  }
  return blockers;
}

function numberedCatalog(rows, additions = () => ({})) {
  return rows.map((row, index) => ({
    wireTag: index + 1,
    ...row,
    ...additions(row),
  }));
}

function exactGpuHeaderVocabulary() {
  const header = fs.readFileSync(path.resolve(repositoryRoot, runtimeHeaderPath), "utf8");
  const enumBlock = header.match(
    /typedef enum ExactGpuObjectKindV2 \{([\s\S]*?)\} ExactGpuObjectKindV2;/u,
  )?.[1];
  if (!enumBlock) throw new Error("ExactGpuObjectKindV2 is absent from exact_runtime.h");
  const rows = [
    ...enumBlock.matchAll(
      /\b(EXACT_GPU_OBJECT_[A-Z0-9_]+_V2)\s*=\s*([0-9]+)\s*,/gu,
    ),
  ].map((match) => [match[1], Number(match[2])]);
  if (
    rows.length !== 23 ||
    new Set(rows.map(([name]) => name)).size !== rows.length ||
    rows.some(([, value], index) => value !== index)
  ) {
    throw new Error("ExactGpuObjectKindV2 must remain the complete contiguous 0..22 table");
  }
  const publicTags = rows.map(([name, value]) => {
    const stem = name
      .slice("EXACT_GPU_OBJECT_".length, -"_V2".length);
    const publicName = stem === "NONE"
      ? "None"
      : stem === "GPU"
        ? "GPU"
        : `GPU${stem
            .split("_")
            .map((part) => part[0] + part.slice(1).toLowerCase())
            .join("")}`;
    return [publicName, value];
  });
  if (new Set(publicTags.map(([name]) => name)).size !== publicTags.length) {
    throw new Error("ExactGpuObjectKindV2 public-name projection is not bijective");
  }
  const requiredCarrierConstantNames = [
    "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
    "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
    "EXACT_GPU_DEVICE_UNCHANGED_V2",
    "EXACT_GPU_DEVICE_ASSIGNED_V2",
    "EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2",
    "EXACT_GPU_PROVIDER_NOT_ADMITTED_V2",
    "EXACT_GPU_PROVIDER_ADMITTED_V2",
    "EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2",
    "EXACT_GPU_BACKEND_NONE_V2",
    "EXACT_GPU_RESULT_NONE_V2",
    "EXACT_GPU_RESULT_NULL_V2",
    "EXACT_GPU_RESULT_OBJECT_V2",
  ];
  const carrierConstants = Object.fromEntries(
    requiredCarrierConstantNames.map((name) => {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
      const match = header.match(
        new RegExp(`\\b${escaped}\\s*=\\s*([0-9]+)\\s*,`, "u"),
      );
      if (!match) throw new Error(`${name} is absent from exact_runtime.h`);
      return [name, Number(match[1])];
    }),
  );
  return {
    authority: {
      path: runtimeHeaderPath,
      sha256: crypto.createHash("sha256").update(header, "utf8").digest("hex"),
    },
    tags: Object.fromEntries(publicTags),
    carrierConstants,
  };
}

function buildCodecManifest(authority, semantics, webIdlVocabulary) {
  const { payload, computed } = validateWebGpuWrapperAuthority(authority);
  const semantic = validateWebGpuWrapperSemantics(semantics);
  const headerVocabulary = exactGpuHeaderVocabulary();
  const nativeCodecPrograms = payload.wireEnvelope.nativeCodecPrograms;
  const requestAdapterProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPU.requestAdapter",
  );
  const requestDeviceProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUAdapter.requestDevice",
  );
  const createBindGroupLayoutProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUDevice.createBindGroupLayout",
  );
  const createBufferProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUDevice.createBuffer",
  );
  const createPipelineLayoutProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUDevice.createPipelineLayout",
  );
  const createCommandEncoderProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUDevice.createCommandEncoder",
  );
  const createShaderModuleProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUDevice.createShaderModule",
  );
  const deviceDestroyProgram = nativeCodecPrograms.routes.find(
    (route) => route.operationId === "GPUDevice.destroy",
  );
  const deviceDestroySemanticProgram =
    semantic.semanticProjection.providerRoutingPrograms.find(
      (program) => program.operationId === "GPUDevice.destroy",
    );
  const createCommandEncoderSemanticProgram =
    semantic.semanticProjection.providerRoutingPrograms.find(
      (program) => program.operationId === "GPUDevice.createCommandEncoder",
    );
  const createBindGroupLayoutSemanticProgram =
    semantic.semanticProjection.providerRoutingPrograms.find(
      (program) => program.operationId === "GPUDevice.createBindGroupLayout",
    );
  const createBufferSemanticProgram =
    semantic.semanticProjection.providerRoutingPrograms.find(
      (program) => program.operationId === "GPUDevice.createBuffer",
    );
  const createPipelineLayoutSemanticProgram =
    semantic.semanticProjection.providerRoutingPrograms.find(
      (program) => program.operationId === "GPUDevice.createPipelineLayout",
    );
  const createShaderModuleSemanticProgram =
    semantic.semanticProjection.providerRoutingPrograms.find(
      (program) => program.operationId === "GPUDevice.createShaderModule",
    );
  const objectCompletion = requestAdapterProgram?.completion.variants.find(
    (variant) => variant.name === "object",
  );
  const nullCompletion = requestAdapterProgram?.completion.variants.find(
    (variant) => variant.name === "null",
  );
  if (
    !requestAdapterProgram ||
    !requestDeviceProgram ||
    !createBindGroupLayoutProgram ||
    !createBufferProgram ||
    !createPipelineLayoutProgram ||
    !createCommandEncoderProgram ||
    !createShaderModuleProgram ||
    !deviceDestroyProgram ||
    !createBindGroupLayoutSemanticProgram ||
    !createBufferSemanticProgram ||
    !createPipelineLayoutSemanticProgram ||
    !createCommandEncoderSemanticProgram ||
    !createShaderModuleSemanticProgram ||
    !deviceDestroySemanticProgram ||
    headerVocabulary.tags.GPU !== 1 ||
    headerVocabulary.tags.GPUAdapter !== 2 ||
    headerVocabulary.tags.GPUDevice !== 3 ||
    headerVocabulary.tags.GPUBuffer !== 5 ||
    headerVocabulary.tags.GPUBindGroupLayout !== 9 ||
    headerVocabulary.tags.GPUPipelineLayout !== 11 ||
    headerVocabulary.tags.GPUShaderModule !== 12 ||
    headerVocabulary.tags.GPUCommandEncoder !== 15 ||
    headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2 !==
      requestAdapterProgram.completion.commonCarrierConstraints[0].value ||
    headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2 !== 2 ||
    headerVocabulary.carrierConstants.EXACT_GPU_DEVICE_UNCHANGED_V2 !==
      requestAdapterProgram.completion.commonCarrierConstraints[3].value ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NULL_V2 !==
      nullCompletion?.resultKind ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_OBJECT_V2 !==
      objectCompletion?.resultKind ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2 !==
      deviceDestroyProgram.completion.commonCarrierConstraints.at(-1)?.value ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2 !==
      createCommandEncoderProgram.completion.commonCarrierConstraints.at(-1)?.value ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2 !==
      createBindGroupLayoutProgram.completion.commonCarrierConstraints.at(-1)?.value ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2 !==
      createBufferProgram.completion.commonCarrierConstraints.at(-1)?.value ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2 !==
      createPipelineLayoutProgram.completion.commonCarrierConstraints.at(-1)?.value ||
    headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2 !==
      createShaderModuleProgram.completion.commonCarrierConstraints.at(-1)?.value ||
    headerVocabulary.carrierConstants.EXACT_GPU_DEVICE_ASSIGNED_V2 !== 1 ||
    headerVocabulary.carrierConstants.EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2 !== 2 ||
    headerVocabulary.carrierConstants.EXACT_GPU_PROVIDER_NOT_ADMITTED_V2 !== 0 ||
    headerVocabulary.carrierConstants.EXACT_GPU_PROVIDER_ADMITTED_V2 !== 1 ||
    headerVocabulary.carrierConstants.EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2 !== 1 ||
    headerVocabulary.carrierConstants.EXACT_GPU_BACKEND_NONE_V2 !== 0 ||
    requestDeviceProgram.request.executablePrerequisites.join(",") !==
      "generatedLogicalProviderDescriptor,authenticatedResultSelectionIdentity" ||
    createBindGroupLayoutProgram.request.executablePrerequisites.length !== 0 ||
    createBufferProgram.request.executablePrerequisites.length !== 0 ||
    createPipelineLayoutProgram.request.executablePrerequisites.length !== 0 ||
    createCommandEncoderProgram.request.executablePrerequisites.length !== 0 ||
    createShaderModuleProgram.request.executablePrerequisites.length !== 0 ||
    deviceDestroyProgram.request.executablePrerequisites.length !== 0
  ) {
    throw new Error("native WebGPU codec program C vocabulary drifted");
  }
  const destroyCompletionEvents = {
    "repeat-cleanup-noop": {
      kind: "operation-result",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      resultKind: headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2,
      resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
      status: 0,
      completionVariant: "repeat-cleanup-noop",
    },
    "first-cleanup-rejection": {
      kind: "device-error",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
      completionPayloadEncoderEligibility:
        "excluded-not-an-operation-result",
    },
    "first-cleanup-provider": {
      kind: "operation-result",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      resultKind: headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2,
      resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
      status: 0,
      completionVariant: "first-cleanup-provider",
    },
  };
  const expectedDestroyTerminalMapping = {
    authorityPath:
      "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.destroy]",
    terminals: deviceDestroySemanticProgram.terminals.map((terminal) => ({
      terminalId: terminal.terminalId,
      errorTiming: terminal.errorTiming,
      resultDisposition: terminal.resultDisposition,
      providerTokenCount: terminal.providerTokenCount,
      physicalSequenceCount: terminal.physicalSequenceCount,
      event: destroyCompletionEvents[terminal.terminalId],
    })),
  };
  if (
    canonicalJson(deviceDestroyProgram.completion.semanticTerminalMapping) !==
      canonicalJson(expectedDestroyTerminalMapping) ||
    expectedDestroyTerminalMapping.terminals.some((terminal) => !terminal.event)
  ) {
    throw new Error(
      "GPUDevice.destroy native completion mapping differs from semantic terminals",
    );
  }
  const createCommandEncoderCompletionEvents = {
    "webidl-rejection": {
      kind: "no-service-call",
      completionPayloadEncoderEligibility: "excluded-before-service-ingress",
    },
    "later-predicate-rejection": {
      kind: "device-error",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
      completionPayloadEncoderEligibility:
        "excluded-not-an-operation-result",
    },
    "operation-success": {
      kind: "operation-result",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      resultKind: headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2,
      resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
      status: 0,
      completionVariant: "operation-success",
    },
  };
  const expectedCreateBindGroupLayoutTerminalMapping = {
    authorityPath:
      "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createBindGroupLayout]",
    terminals: createBindGroupLayoutSemanticProgram.terminals.map((terminal) => ({
      terminalId: terminal.terminalId,
      errorTiming: terminal.errorTiming,
      resultDisposition: terminal.resultDisposition,
      providerTokenCount: terminal.providerTokenCount,
      physicalSequenceCount: terminal.physicalSequenceCount,
      event: createCommandEncoderCompletionEvents[terminal.terminalId],
    })),
  };
  if (
    canonicalJson(createBindGroupLayoutProgram.completion.semanticTerminalMapping) !==
      canonicalJson(expectedCreateBindGroupLayoutTerminalMapping) ||
    expectedCreateBindGroupLayoutTerminalMapping.terminals.some(
      (terminal) => !terminal.event,
    )
  ) {
    throw new Error(
      "GPUDevice.createBindGroupLayout native completion mapping differs from semantic terminals",
    );
  }
  const expectedCreateBufferTerminalMapping = {
    authorityPath:
      "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createBuffer]",
    terminals: createBufferSemanticProgram.terminals.map((terminal) => ({
      terminalId: terminal.terminalId,
      errorTiming: terminal.errorTiming,
      resultDisposition: terminal.resultDisposition,
      providerTokenCount: terminal.providerTokenCount,
      physicalSequenceCount: terminal.physicalSequenceCount,
      event: createCommandEncoderCompletionEvents[terminal.terminalId],
    })),
  };
  if (
    canonicalJson(createBufferProgram.completion.semanticTerminalMapping) !==
      canonicalJson(expectedCreateBufferTerminalMapping) ||
    expectedCreateBufferTerminalMapping.terminals.some(
      (terminal) => !terminal.event,
    )
  ) {
    throw new Error(
      "GPUDevice.createBuffer native completion mapping differs from semantic terminals",
    );
  }
  const expectedCreatePipelineLayoutTerminalMapping = {
    authorityPath:
      "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createPipelineLayout]",
    terminals: createPipelineLayoutSemanticProgram.terminals.map((terminal) => ({
      terminalId: terminal.terminalId,
      errorTiming: terminal.errorTiming,
      resultDisposition: terminal.resultDisposition,
      providerTokenCount: terminal.providerTokenCount,
      physicalSequenceCount: terminal.physicalSequenceCount,
      event: createCommandEncoderCompletionEvents[terminal.terminalId],
    })),
  };
  if (
    canonicalJson(createPipelineLayoutProgram.completion.semanticTerminalMapping) !==
      canonicalJson(expectedCreatePipelineLayoutTerminalMapping) ||
    expectedCreatePipelineLayoutTerminalMapping.terminals.some(
      (terminal) => !terminal.event,
    )
  ) {
    throw new Error(
      "GPUDevice.createPipelineLayout native completion mapping differs from semantic terminals",
    );
  }
  const expectedCreateCommandEncoderTerminalMapping = {
    authorityPath:
      "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createCommandEncoder]",
    terminals: createCommandEncoderSemanticProgram.terminals.map((terminal) => ({
      terminalId: terminal.terminalId,
      errorTiming: terminal.errorTiming,
      resultDisposition: terminal.resultDisposition,
      providerTokenCount: terminal.providerTokenCount,
      physicalSequenceCount: terminal.physicalSequenceCount,
      event: createCommandEncoderCompletionEvents[terminal.terminalId],
    })),
  };
  if (
    canonicalJson(createCommandEncoderProgram.completion.semanticTerminalMapping) !==
      canonicalJson(expectedCreateCommandEncoderTerminalMapping) ||
    expectedCreateCommandEncoderTerminalMapping.terminals.some(
      (terminal) => !terminal.event,
    )
  ) {
    throw new Error(
      "GPUDevice.createCommandEncoder native completion mapping differs from semantic terminals",
    );
  }
  const createShaderModuleCompletionEvents = {
    "webidl-rejection": {
      kind: "no-service-call",
      completionPayloadEncoderEligibility: "excluded-before-service-ingress",
    },
    "later-predicate-rejection": {
      kind: "device-error",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
      completionPayloadEncoderEligibility:
        "excluded-not-an-operation-result",
    },
    "operation-success": {
      kind: "operation-result",
      kindValue:
        headerVocabulary.carrierConstants.EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2,
      kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      resultKind: headerVocabulary.carrierConstants.EXACT_GPU_RESULT_NONE_V2,
      resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
      status: 0,
      completionVariant: "operation-success",
    },
  };
  const expectedCreateShaderModuleTerminalMapping = {
    authorityPath:
      "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createShaderModule]",
    terminals: createShaderModuleSemanticProgram.terminals.map((terminal) => ({
      terminalId: terminal.terminalId,
      errorTiming: terminal.errorTiming,
      resultDisposition: terminal.resultDisposition,
      providerTokenCount: terminal.providerTokenCount,
      physicalSequenceCount: terminal.physicalSequenceCount,
      event: createShaderModuleCompletionEvents[terminal.terminalId],
    })),
  };
  if (
    canonicalJson(createShaderModuleProgram.completion.semanticTerminalMapping) !==
      canonicalJson(expectedCreateShaderModuleTerminalMapping) ||
    expectedCreateShaderModuleTerminalMapping.terminals.some(
      (terminal) => !terminal.event,
    )
  ) {
    throw new Error(
      "GPUDevice.createShaderModule native completion mapping differs from semantic terminals",
    );
  }
  const manifest = {
    schema: "ibex/webgpu-executable-codec-manifest/2",
    disposition:
      "reviewed-generated-injection-and-request-adapter-request-device-create-bind-group-layout-create-buffer-create-pipeline-layout-create-command-encoder-create-shader-module-device-destroy-payload-codegen-input-native-codec-not-installed-no-support-claim",
    profileId: payload.profileId,
    scopeId: payload.scopeId,
    operationCount: payload.operations.length,
    operationIds: payload.operations.map((operation) => operation.operationId),
    maxPayloadBytes: payload.wireEnvelope.maxPayloadBytes,
    byteOrder: payload.wireEnvelope.byteOrder,
    scalarRules: payload.wireEnvelope.scalarRules,
    digests: computed,
    layout: payload.wireEnvelope.codecLayout,
    nativeCodecPrograms,
    objectKindAuthority: headerVocabulary.authority,
    objectKindTags: headerVocabulary.tags,
    carrierConstants: headerVocabulary.carrierConstants,
    webIdlVocabulary,
    publicArguments: numberedCatalog(payload.codecCatalog.publicArguments),
    serviceArguments: numberedCatalog(
      payload.codecCatalog.serviceArguments,
      (codec) => {
        const blockers = serviceCodecBlockers(codec);
        const nativeProgramPrerequisitesRepresented =
          codec.tag !== "gpu-request-device-service-request-v1" ||
          requestDeviceProgram.request.executablePrerequisites.join(",") ===
            "generatedLogicalProviderDescriptor,authenticatedResultSelectionIdentity";
        return {
          nativeProgramPrerequisitesRepresented,
          executableFromCurrentAuthenticatedInputs:
            nativeProgramPrerequisitesRepresented && blockers.length === 0,
          unavailableSemanticFields: blockers,
        };
      },
    ),
    serviceCompletions: numberedCatalog(
      payload.codecCatalog.serviceCompletions,
    ),
    completeLimitNames: semantic.semanticProjection.limitPolicy.limits.map(
      (limit) => limit.name,
    ),
  };
  if (
    manifest.operationCount === 0 ||
    new Set(manifest.operationIds).size !== manifest.operationCount
  ) {
    throw new Error("executable WebGPU codec manifest must contain a nonempty unique operation set");
  }
  if (manifest.completeLimitNames.length !== 36) {
    throw new Error("executable WebGPU codec manifest must contain 36 limits");
  }
  return manifest;
}

function renderCodecs(manifest) {
  return (
    "// Generated by generate-webgpu-production-plan.mjs; do not edit.\n" +
    "// This artifact is reviewed for explicit private injection only. The\n" +
    "// matching native payload codec and several authenticated semantic inputs are\n" +
    "// absent, so it neither enables navigator.gpu nor makes a support claim.\n" +
    "import { createExecutableWebGpuCodecs } from './production-codec-runtime';\n\n" +
    "export const WEBGPU_OBJECT_KIND_TAGS = " +
    JSON.stringify(manifest.objectKindTags, null, 2) +
    " as const;\n\n" +
    "export const WEBGPU_EXECUTABLE_CODEC_MANIFEST = " +
    JSON.stringify(manifest, null, 2) +
    " as const;\n\n" +
    "const generated = createExecutableWebGpuCodecs(\n" +
    "  WEBGPU_EXECUTABLE_CODEC_MANIFEST,\n" +
    "  WEBGPU_OBJECT_KIND_TAGS,\n" +
    ");\n\n" +
    "export const WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION = generated.bundle;\n" +
    "export const WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT = generated.testSupport;\n"
  );
}

function main() {
  const authority = readJson(
    authorityPath,
    "WebGPU normalized routing authority",
  );
  const semantics = readJson(
    semanticsPath,
    "WebGPU normalized semantic authority",
  );
  const workloadStaging = readJson(
    workloadStagingPath,
    "TypeGPU workload staging authority",
  );
  const webIdlVocabulary = readPinnedWebIdlVocabulary();
  const renderedPlan = renderPlan(
    authority,
    workloadStaging,
    webIdlVocabulary,
  );
  const codecManifest = buildCodecManifest(
    authority,
    semantics,
    webIdlVocabulary,
  );
  const renderedCodecs = renderCodecs(codecManifest);
  const renderedCodecManifest = `${JSON.stringify(codecManifest, null, 2)}\n`;
  if (process.argv.includes("--check")) {
    for (const generated of [
      {
        path: outputPath,
        content: renderedPlan,
        label: "WebGPU production routing plan",
      },
      {
        path: codecOutputPath,
        content: renderedCodecs,
        label: "WebGPU executable codec manifest",
      },
      {
        path: codecManifestOutputPath,
        content: renderedCodecManifest,
        label: "WebGPU language-neutral codec manifest",
      },
    ]) {
      const confined = assertConfinedGeneratedFile(
        repositoryRoot,
        generated.path,
        generated.label,
      );
      if (fs.readFileSync(confined.path, "utf8") !== generated.content) {
        throw new Error(
          generated.label +
            " is stale; run bun run generate:webgpu-production-plan",
        );
      }
    }
    console.log(
      `webgpu-production-plan: ${authority.payload.operations.length} active routes, ` +
        `${workloadStaging.workloadClosure.additionalOperationCount} staged unroutable operations, ` +
        "and injection codecs fresh at normalized projection " +
        REVIEWED_DIGESTS.projection,
    );
    return;
  }
  writeGeneratedFilesTransactionally(repositoryRoot, [
    {
      path: outputPath,
      content: renderedPlan,
      label: "WebGPU production routing plan",
    },
    {
      path: codecOutputPath,
      content: renderedCodecs,
      label: "WebGPU executable codec manifest",
    },
    {
      path: codecManifestOutputPath,
      content: renderedCodecManifest,
      label: "WebGPU language-neutral codec manifest",
    },
  ]);
  console.log(
    "webgpu-production-plan: wrote routing plan, TypeGPU staging inventory, and injection codecs" +
      " at normalized projection " +
      REVIEWED_DIGESTS.projection,
  );
}

try {
  main();
} catch (error) {
  console.error(
    "webgpu-production-plan: " +
      (error instanceof Error ? error.message : String(error)),
  );
  process.exitCode = 1;
}
