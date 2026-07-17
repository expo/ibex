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

function validateWorkloadStaging(staging, routeIds) {
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
  exactSet(staging.blockers, REQUIRED_WORKLOAD_BLOCKERS, "TypeGPU staging blockers");
  if (
    staging.activeRouteSubset.operationCount !== routeIds.length ||
    staging.activeRouteSubset.operationIds.length !== routeIds.length
  ) {
    throw new Error("TypeGPU active route subset count drifted");
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
  const additional = operations.filter(
    (operation) => !routeSet.has(operation.operationId),
  );
  if (staging.workloadClosure.additionalOperationCount !== additional.length) {
    throw new Error("TypeGPU additional operation count drifted");
  }
  for (const operation of operations) {
    const isRoute = routeSet.has(operation.operationId);
    if (
      !["method", "property"].includes(operation.memberKind) ||
      operation.disposition !==
        (isRoute
          ? "active-private-triangle-route"
          : "staged-unroutable-no-prototype-member")
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

function renderPlan(authority, workloadStaging) {
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
    promiseIdentity: operation.promiseIdentity,
  }));
  if (routes.length === 0 || new Set(routes.map((route) => route.operationId)).size !== routes.length) {
    throw new Error("production WebGPU plan must contain a nonempty unique route set");
  }
  const stagedWorkloadClosure = validateWorkloadStaging(
    workloadStaging,
    routes.map((route) => route.operationId),
  );
  const plan = {
    schema: "ibex/webgpu-production-wrapper-plan/1",
    profileId: payload.profileId,
    scopeId: payload.scopeId,
    maxPayloadBytes: payload.wireEnvelope.maxPayloadBytes,
    codecReadiness: "unavailable-descriptive-tags-only",
    digests: computed,
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

function renderCodecs(authority, semantics) {
  const { payload, computed } = validateWebGpuWrapperAuthority(authority);
  const semantic = validateWebGpuWrapperSemantics(semantics);
  const manifest = {
    schema: "ibex/webgpu-executable-codec-manifest/1",
    disposition:
      "reviewed-generated-injection-only-native-decoder-absent-no-support-claim",
    profileId: payload.profileId,
    scopeId: payload.scopeId,
    operationCount: payload.operations.length,
    operationIds: payload.operations.map((operation) => operation.operationId),
    maxPayloadBytes: payload.wireEnvelope.maxPayloadBytes,
    byteOrder: payload.wireEnvelope.byteOrder,
    scalarRules: payload.wireEnvelope.scalarRules,
    digests: computed,
    layout: {
      requestMagic: "IBGQ",
      resultMagic: "IBGR",
      lossMagic: "IBGL",
      version: 1,
      diagnosticMaxBytes: 4096,
      sequenceMaxCount: 1024,
      dictionaryMaxFields: 128,
      nestingMaxDepth: 16,
    },
    publicArguments: numberedCatalog(payload.codecCatalog.publicArguments),
    serviceArguments: numberedCatalog(
      payload.codecCatalog.serviceArguments,
      (codec) => {
        const blockers = serviceCodecBlockers(codec);
        return {
          executableFromCurrentAuthenticatedInputs: blockers.length === 0,
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
  return (
    "// Generated by generate-webgpu-production-plan.mjs; do not edit.\n" +
    "// This artifact is reviewed for explicit private injection only. The\n" +
    "// matching native decoder and several authenticated semantic inputs are\n" +
    "// absent, so it neither enables navigator.gpu nor makes a support claim.\n" +
    "import { createExecutableWebGpuCodecs } from './production-codec-runtime';\n\n" +
    "export const WEBGPU_EXECUTABLE_CODEC_MANIFEST = " +
    JSON.stringify(manifest, null, 2) +
    " as const;\n\n" +
    "const generated = createExecutableWebGpuCodecs(\n" +
    "  WEBGPU_EXECUTABLE_CODEC_MANIFEST,\n" +
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
  const renderedPlan = renderPlan(authority, workloadStaging);
  const renderedCodecs = renderCodecs(authority, semantics);
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
