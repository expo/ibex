/**
 * Generate a portable, test-only WebGPU wrapper factory from the reviewed
 * Exact runtime-wire projection. This module is deliberately outside the
 * runtime bundle and builtin manifest.
 *
 * Outer integration must compare its current normalized projection to
 * REVIEWED_DIGESTS.projection after repinning Ibex. It must not compare the
 * recursive full-artifact bytes or historical source commit.
 *
 * @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
 * @ref LLP 0019#the-enforced-conformance-seam
 * @ref LLP 0026#compatibility-contract-and-conformance-corpus
 */

import crypto from "node:crypto";

import { portableWebGpuTestWrapperFactory } from "./webgpu-test-wrapper-portable.mjs";
import {
  CONDITIONAL_PROVIDER_OPERATION_IDS,
  CONDITIONAL_PROVIDER_ROUTE_COUNT,
  NATIVE_CODEC_ROUTE_IDS,
  REVIEWED_DIGESTS,
  REVIEWED_SEMANTIC_DIGESTS,
  WRAPPER_ROUTE_ASSIGNMENTS,
  WRAPPER_ROUTE_COUNT,
} from "./webgpu-wrapper-pins.generated.mjs";

export {
  CONDITIONAL_PROVIDER_OPERATION_IDS,
  CONDITIONAL_PROVIDER_ROUTE_COUNT,
  NATIVE_CODEC_ROUTE_IDS,
  REVIEWED_DIGESTS,
  REVIEWED_SEMANTIC_DIGESTS,
  WRAPPER_ROUTE_ASSIGNMENTS,
  WRAPPER_ROUTE_COUNT,
};

const EXPECTED_QUEUE_SUBMIT_COMMAND_RECORD_TYPE_SHA256 =
  "432138a1cc45bccd3a7ffce4a53e391a3bd0a321ce7393e7a097410a9206d758";
const EXPECTED_QUEUE_SUBMIT_REQUEST_BODY_TYPE_SHA256 =
  "db9e3537ef359719593b74e73ebbe670c35a4a9e4235cbd3bdecc3ce57cf5683";
const EXPECTED_QUEUE_SUBMIT_NATIVE_ROUTE_SHA256 =
  "1a75cadd6062c5194e9c6ef5da0abbe022e6ef0418c91be25dc0560121e11322";

function assert(condition, message) {
  if (!condition) throw new Error("webgpu test-wrapper authority: " + message);
}

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return "[" + value.map((entry) => canonicalJson(entry)).join(",") + "]";
  }
  if (value !== null && typeof value === "object") {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

export function canonicalDigest(domain, value) {
  return crypto
    .createHash("sha256")
    .update(domain + "\n" + canonicalJson(value) + "\n", "utf8")
    .digest("hex");
}

function assertDigest(actual, expected, label) {
  assert(actual === expected, label + " digest drifted (got " + actual + ")");
}

function assertCanonical(actual, expected, label) {
  assert(canonicalJson(actual) === canonicalJson(expected), label + " drifted");
}

function buildExpectedCreateBindGroupLayoutNativeRoute({
  templateRoute,
  operation,
  requestCatalogIndex,
  completionCatalogIndex,
}) {
  const route = structuredClone(templateRoute);
  route.operationId = operation.operationId;
  route.wireId = operation.wireId;
  route.request.catalog.tag = operation.serviceArgumentCodec;
  route.request.catalog.wireTag = requestCatalogIndex + 1;
  const header = route.request.payload.fields.find(
    (field) => field.name === "header",
  );
  header.constants.codecTag = requestCatalogIndex + 1;
  header.constants.operationWireId = operation.wireId;
  route.request.payload.fields.find(
    (field) => field.name === "convertedArguments",
  ).constraintType = "bindGroupLayoutDescriptorV1";
  for (const constraint of route.request.carrierConstraints) {
    if (constraint.carrierPath === "operation_id") {
      constraint.value = operation.wireId;
    }
    if (constraint.carrierPath === "target.kind") {
      constraint.valueFrom = "objectKindTags.GPUBindGroupLayout";
    }
  }
  route.request.valueConstraints.find(
    (constraint) => constraint.payloadPath === "convertedArguments",
  ).type = "bindGroupLayoutDescriptorV1";
  route.request.semanticServiceBoundary.requiredAfterDecode = [
    "authenticate-contiguous-sealed-local-timeline-prefix",
    "validate-current-live-device-generation",
    "validate-operation-coverage",
    "validate-authorized-live-account",
    "validate-bind-group-layout-descriptor-under-logical-device-capabilities",
    "reserve-bind-group-layout-handle-and-aggregate-envelope",
    "authenticate-wrapper-allocated-bind-group-layout-target",
    "select-provider-admission-and-physical-sequence",
  ];
  route.completion.catalog.wireTag = completionCatalogIndex + 1;
  for (const constraint of route.completion.commonCarrierConstraints) {
    if (
      constraint.carrierPath ===
      "record.operation_result.operation.operation_id"
    ) {
      constraint.value = operation.wireId;
    }
    if (
      constraint.carrierPath ===
      "record.operation_result.operation.target.kind"
    ) {
      constraint.valueFrom = "objectKindTags.GPUBindGroupLayout";
    }
  }
  route.completion.semanticTerminalMapping.authorityPath =
    `semanticProjection.providerRoutingPrograms[operationId=${operation.operationId}]`;
  return route;
}

function buildExpectedCreatePipelineLayoutNativeRoute({
  templateRoute,
  operation,
  requestCatalogIndex,
  completionCatalogIndex,
}) {
  const route = structuredClone(templateRoute);
  route.operationId = operation.operationId;
  route.wireId = operation.wireId;
  route.request.catalog.tag = operation.serviceArgumentCodec;
  route.request.catalog.wireTag = requestCatalogIndex + 1;
  const header = route.request.payload.fields.find(
    (field) => field.name === "header",
  );
  header.constants.codecTag = requestCatalogIndex + 1;
  header.constants.operationWireId = operation.wireId;
  route.request.payload.fields.find(
    (field) => field.name === "convertedArguments",
  ).constraintType = "pipelineLayoutDescriptorV1";
  for (const constraint of route.request.carrierConstraints) {
    if (constraint.carrierPath === "operation_id") {
      constraint.value = operation.wireId;
    }
    if (constraint.carrierPath === "target.kind") {
      constraint.valueFrom = "objectKindTags.GPUPipelineLayout";
    }
  }
  route.request.valueConstraints.find(
    (constraint) => constraint.payloadPath === "convertedArguments",
  ).type = "pipelineLayoutDescriptorV1";
  route.request.semanticServiceBoundary.requiredAfterDecode = [
    "authenticate-contiguous-sealed-local-timeline-prefix",
    "validate-current-live-device-generation",
    "validate-operation-coverage",
    "validate-authorized-live-account",
    "validate-pipeline-layout-group-count-under-reviewed-workload",
    "validate-pipeline-layout-count-under-logical-max-bind-groups",
    "validate-pipeline-layout-non-null-group-positions",
    "authenticate-pipeline-layout-bind-group-layout-full-references",
    "validate-current-live-nonexclusive-bind-group-layout-generations",
    "validate-pipeline-layout-aggregate-binding-slots-under-logical-limits",
    "validate-pipeline-layout-immediate-alignment",
    "validate-pipeline-layout-immediate-size-under-logical-limit",
    "validate-pipeline-layout-label-under-reviewed-workload",
    "reserve-pipeline-layout-handle-and-aggregate-envelope",
    "authenticate-wrapper-allocated-pipeline-layout-target",
    "select-provider-admission-and-physical-sequence",
  ];
  route.completion.catalog.wireTag = completionCatalogIndex + 1;
  for (const constraint of route.completion.commonCarrierConstraints) {
    if (
      constraint.carrierPath ===
      "record.operation_result.operation.operation_id"
    ) {
      constraint.value = operation.wireId;
    }
    if (
      constraint.carrierPath ===
      "record.operation_result.operation.target.kind"
    ) {
      constraint.valueFrom = "objectKindTags.GPUPipelineLayout";
    }
  }
  route.completion.semanticTerminalMapping.authorityPath =
    `semanticProjection.providerRoutingPrograms[operationId=${operation.operationId}]`;
  return route;
}

function buildExpectedCreateBufferNativeRoute({
  templateRoute,
  operation,
  requestCatalogIndex,
  completionCatalogIndex,
}) {
  const route = structuredClone(templateRoute);
  route.operationId = operation.operationId;
  route.wireId = operation.wireId;
  route.request.catalog.tag = operation.serviceArgumentCodec;
  route.request.catalog.wireTag = requestCatalogIndex + 1;
  const header = route.request.payload.fields.find(
    (field) => field.name === "header",
  );
  header.constants.codecTag = requestCatalogIndex + 1;
  header.constants.operationWireId = operation.wireId;
  route.request.payload.fields.find(
    (field) => field.name === "convertedArguments",
  ).constraintType = "bufferDescriptorV1";
  for (const constraint of route.request.carrierConstraints) {
    if (constraint.carrierPath === "operation_id") {
      constraint.value = operation.wireId;
    }
    if (constraint.carrierPath === "target.kind") {
      constraint.valueFrom = "objectKindTags.GPUBuffer";
    }
  }
  route.request.valueConstraints.find(
    (constraint) => constraint.payloadPath === "convertedArguments",
  ).type = "bufferDescriptorV1";
  route.request.semanticServiceBoundary.requiredAfterDecode = [
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
  ];
  route.completion.catalog.wireTag = completionCatalogIndex + 1;
  for (const constraint of route.completion.commonCarrierConstraints) {
    if (
      constraint.carrierPath ===
      "record.operation_result.operation.operation_id"
    ) {
      constraint.value = operation.wireId;
    }
    if (
      constraint.carrierPath ===
      "record.operation_result.operation.target.kind"
    ) {
      constraint.valueFrom = "objectKindTags.GPUBuffer";
    }
  }
  route.completion.semanticTerminalMapping.authorityPath =
    `semanticProjection.providerRoutingPrograms[operationId=${operation.operationId}]`;
  route.completion.semanticTerminalMapping.terminals.splice(1, 0, {
    terminalId: "content-rejection",
    errorTiming: "content-timeline",
    resultDisposition: "throw",
    providerTokenCount: 0,
    physicalSequenceCount: 0,
    event: {
      kind: "no-service-call",
      completionPayloadEncoderEligibility: "excluded-before-service-ingress",
    },
  });
  return route;
}

function buildExpectedResourceNativeRoute({
  templateRoute,
  operation,
  requestCatalogIndex,
  completionCatalogIndex,
  descriptorType,
  receiverKind = "GPUDevice",
  targetKind,
  semanticSteps,
  contentRejection = false,
}) {
  const route = buildExpectedCreateBufferNativeRoute({
    templateRoute,
    operation,
    requestCatalogIndex,
    completionCatalogIndex,
  });
  if (!contentRejection) {
    route.completion.semanticTerminalMapping.terminals =
      route.completion.semanticTerminalMapping.terminals.filter(
        (terminal) => terminal.terminalId !== "content-rejection",
      );
  }
  route.request.payload.fields.find(
    (field) => field.name === "convertedArguments",
  ).constraintType = descriptorType;
  route.request.valueConstraints.find(
    (constraint) => constraint.payloadPath === "convertedArguments",
  ).type = descriptorType;
  route.request.carrierConstraints.find(
    (constraint) => constraint.carrierPath === "receiver.kind",
  ).valueFrom = `objectKindTags.${receiverKind}`;
  route.request.carrierConstraints.find(
    (constraint) => constraint.carrierPath === "target.kind",
  ).valueFrom = `objectKindTags.${targetKind}`;
  route.request.semanticServiceBoundary.requiredAfterDecode = semanticSteps;
  route.completion.commonCarrierConstraints.find(
    (constraint) =>
      constraint.carrierPath ===
      "record.operation_result.operation.receiver.kind",
  ).valueFrom = `objectKindTags.${receiverKind}`;
  route.completion.commonCarrierConstraints.find(
    (constraint) =>
      constraint.carrierPath ===
      "record.operation_result.operation.target.kind",
  ).valueFrom = `objectKindTags.${targetKind}`;
  return route;
}

function validateNativeCodecPrograms(payload) {
  const envelope = payload.wireEnvelope;
  const program = envelope?.nativeCodecPrograms;
  assert(
    program?.schema === "ibex/webgpu-native-codec-programs/2" &&
      program.disposition ===
        "request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-queue-write-buffer-queue-submit-payload-codegen-input-only-native-codec-not-installed-no-support-claim",
    "native codec program identity or disposition drifted",
  );
  assertCanonical(
    program.dispatch,
    {
      carrierPath: "ExactGpuSemanticCallV2.operation_id",
      payloadOperationWireIdRole:
        "constant-and-equality-check-only-never-dispatch",
      payloadCodecTagRole:
        "route-selected-constant-and-equality-check-only-never-dispatch",
    },
    "native codec dispatch authority",
  );
  assertCanonical(
    program.scope,
    {
      request:
        "service-request-payload-decoder-plus-operation-specific-call-joins",
      completion:
        "service-completion-payload-codec-plus-operation-specific-event-joins",
      excluded:
        "full-call-or-event-construction-and-global-v2-carrier-validation",
    },
    "native codec program scope",
  );
  assertCanonical(
    program.carrierValidationDependency,
    {
      authority: "ExactGpuSemanticCallV2-and-ExactGpuServiceEventV2",
      requestStructuralValidationMustPrecede:
        "native-request-payload-decode",
      requestStatefulValidationMustPrecede:
        "semantic-execution-and-provider-admission",
      completionEncoderRequires:
        "authenticated-retained-call-plus-service-owned-operation-result",
      completionValidationMustPrecede:
        "completion-payload-decode-and-wrapper-exposure",
      globallyOwnedCarrierInvariants: [
        "exact-struct-size-abi-version-flags-reserved-and-payload-bounds",
        "valid-realm-account-topology-and-authority-context",
        "retained-operation-instance-promise-scope-ordinals-receiver-target-correlation",
        "valid-provider-admission-physical-sequence-and-device-transition-provenance",
        "result-kind-record-size-status-and-payload-shape",
      ],
      programOwns:
        "selected-payload-layout-plus-operation-specific-carrier-joins-and-constraints-only",
    },
    "native codec carrier-validation dependency",
  );
  assertCanonical(
    program.constants,
    { providerTopologyId: payload.providerDescriptor.topologyId },
    "native codec constants",
  );
  assertCanonical(
    program.primitiveEncodings,
    {
      ascii4: { widthBytes: 4, encoding: "ascii" },
      u8: { widthBytes: 1, encoding: "unsigned-integer" },
      u16le: {
        widthBytes: 2,
        encoding: "unsigned-integer",
        byteOrder: "little-endian",
      },
      u32le: {
        widthBytes: 4,
        encoding: "unsigned-integer",
        byteOrder: "little-endian",
      },
      u64le: {
        widthBytes: 8,
        encoding: "unsigned-integer",
        byteOrder: "little-endian",
      },
      f64le: {
        widthBytes: 8,
        encoding: "ieee754-binary64",
        byteOrder: "little-endian",
        constraints: ["finite"],
      },
      utf8: {
        kind: "length-prefixed-bytes",
        lengthType: "u32le",
        encoding: "utf8",
        constraints: ["well-formed"],
      },
    },
    "native codec primitive encodings",
  );

  const types = program.types;
  assertCanonical(
    Object.keys(types || {}).sort(),
    [
      "bindGroupDescriptorV1",
      "bindGroupLayoutDescriptorV1",
      "bufferCleanupRequestBodyV1",
      "bufferDescriptorV1",
      "bufferMapAsyncCompletionBodyV1",
      "bufferMapAsyncRequestBodyV1",
      "canonicalValueV1",
      "commandEncoderDescriptorV1",
      "commandRecordV1",
      "completeDeviceLimitsV1",
      "gpuDeviceCompletionBodyV1",
      "headerV1",
      "objectReferenceV1",
      "optionalReferenceV1",
      "ownedBytesV1",
      "pipelineLayoutDescriptorV1",
      "queueSubmitRequestBodyV1",
      "queueWriteBufferRequestBodyV1",
      "requestAdapterOptionsV1",
      "requestDeviceDescriptorV1",
      "samplerDescriptorV1",
      "shaderModuleDescriptorV1",
      "sortedUniqueFeatureSequenceV1",
      "textureDescriptorV1",
      "textureViewRequestV1",
    ],
    "native codec type inventory",
  );
  assertCanonical(
    types.ownedBytesV1,
    {
      kind: "length-prefixed-owned-bytes",
      lengthType: "u64le",
      maxBytesFrom: "wireEnvelope.maxPayloadBytes",
      ownership: "affine-transfer-consumed-at-most-once",
    },
    "native owned byte block type",
  );
  assertCanonical(
    types.bufferCleanupRequestBodyV1,
    {
      kind: "struct",
      fields: [
        { name: "cleanupAction", type: "u8" },
        { name: "cleanupGeneration", type: "u64le" },
        { name: "cancelledMapGeneration", type: "u64le" },
        { name: "activeMapGeneration", type: "u64le" },
        { name: "activeMapMode", type: "u32le" },
        { name: "mappedOffset", type: "u64le" },
        { name: "mappedSize", type: "u64le" },
        { name: "writeback", type: "ownedBytesV1" },
      ],
      invariants: [
        "cleanupAction-zero-requires-all-generation-range-mode-and-writeback-fields-empty",
        "cleanupAction-nonzero-requires-positive-cleanupGeneration",
        "activeMapGeneration-zero-iff-activeMapMode-offset-size-and-writeback-are-empty",
        "activeMapMode-one-read-requires-empty-writeback",
        "activeMapMode-two-write-requires-writeback-byte-length-equal-mappedSize",
        "cancelledMapGeneration-and-activeMapGeneration-are-source-affine-wrapper-generations",
        "writeback-is-affine-owned-and-consumed-at-most-once-by-cleanupGeneration",
      ],
    },
    "native buffer cleanup request body type",
  );
  assertCanonical(
    types.bufferMapAsyncRequestBodyV1,
    {
      kind: "struct",
      fields: [
        { name: "pendingMapGeneration", type: "u64le" },
        { name: "mode", type: "u32le" },
        { name: "offset", type: "u64le" },
        { name: "requestedSizePresent", type: "u8" },
        { name: "requestedSize", type: "u64le" },
      ],
      invariants: [
        "pendingMapGeneration-positive-and-source-affine-to-receiver-wrapper",
        "mode-exactly-GPUMapMode-READ-one-or-WRITE-two",
        "requestedSizePresent-zero-requires-requestedSize-zero",
        "offset-and-present-size-preserve-WebIDL-safe-u64-values-without-normalization",
      ],
    },
    "native buffer mapAsync request body type",
  );
  assertCanonical(
    types.bufferMapAsyncCompletionBodyV1,
    {
      kind: "tagged-union",
      tag: { name: "variant", type: "u8" },
      commonFields: [
        { name: "pendingMapGeneration", type: "u64le" },
        { name: "mode", type: "u32le" },
        { name: "offset", type: "u64le" },
        { name: "size", type: "u64le" },
      ],
      variants: [
        { name: "mapped-bytes", tag: 1, payload: "ownedBytesV1" },
        { name: "provider-operation-error", tag: 2, payload: "empty" },
        { name: "allocation-range-error", tag: 3, payload: "empty" },
        { name: "late-cancelled-cleanup", tag: 4, payload: "empty" },
      ],
      invariants: [
        "pendingMapGeneration-mode-offset-and-size-join-the-service-owned-accepted-map-result",
        "mapped-bytes-payload-length-equals-size-and-transfers-one-owned-byte-block",
        "failure-and-late-cancelled-variants-carry-zero-owned-bytes",
        "late-cancelled-cleanup-never-settles-the-public-promise-again",
      ],
    },
    "native buffer mapAsync completion body type",
  );
  assertCanonical(
    types.queueWriteBufferRequestBodyV1,
    {
      kind: "struct",
      fields: [
        { name: "destination", type: "objectReferenceV1" },
        { name: "destinationOffset", type: "u64le" },
        { name: "bytes", type: "ownedBytesV1" },
      ],
      invariants: [
        "destination-is-the-exact-post-WebIDL-GPUBuffer-full-reference",
        "destination-logical-device-and-provider-generations-equal-the-source-queue",
        "destinationOffset-preserves-the-WebIDL-safe-u64-without-alignment-normalization",
        "bytes-are-the-complete-synchronously-selected-source-snapshot",
        "bytes-length-is-a-multiple-of-four-including-zero",
        "bytes-are-affine-owned-by-one-operation-instance-until-terminal-settlement",
        "maximum-bytes-subtract-the-exact-fixed-envelope-and-body-overhead-from-maxPayloadBytes",
      ],
    },
    "native queue writeBuffer request body type",
  );
  assertDigest(
    canonicalDigest(
      "ibex/webgpu-native-codec-program/command-record-v1",
      types.commandRecordV1,
    ),
    EXPECTED_QUEUE_SUBMIT_COMMAND_RECORD_TYPE_SHA256,
    "native queue submit command-record type",
  );
  assertCanonical(
    types.commandRecordV1.identityClasses,
    [
      {
        name: "active-route",
        tag: 1,
        operationIdSource: "productionPlan.routes[operationId].wireId",
        operationIdentitySha256: "32-zero-bytes",
      },
      {
        name: "staged-local",
        tag: 2,
        operationIdSource:
          "productionPlan.stagedWorkloadClosure.localRecordingSubset.operations[operationId].localRecordId",
        operationIdentitySha256Source:
          "productionPlan.stagedWorkloadClosure.localRecordingSubset.operations[operationId].recordIdentitySha256",
      },
    ],
    "native queue submit record identity authority",
  );
  assertCanonical(
    types.commandRecordV1.operationVariants.map(
      ({ name, tag, identityClass, recordRole }) => ({
        name,
        tag,
        identityClass,
        recordRole,
      }),
    ),
    [
      { name: "GPUCanvasContext.getCurrentTexture", tag: 0, identityClass: "active-route", recordRole: "timeline-only" },
      { name: "GPUCommandEncoder.beginComputePass", tag: 1, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUCommandEncoder.beginRenderPass", tag: 2, identityClass: "active-route", recordRole: "command-program" },
      { name: "GPUCommandEncoder.clearBuffer", tag: 3, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUCommandEncoder.copyBufferToBuffer", tag: 4, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUCommandEncoder.copyTextureToTexture", tag: 5, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUComputePassEncoder.setPipeline", tag: 6, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUComputePassEncoder.setBindGroup", tag: 7, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUComputePassEncoder.dispatchWorkgroups", tag: 8, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPUComputePassEncoder.end", tag: 9, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPURenderPassEncoder.setPipeline", tag: 10, identityClass: "active-route", recordRole: "command-program" },
      { name: "GPURenderPassEncoder.setBindGroup", tag: 11, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPURenderPassEncoder.setVertexBuffer", tag: 12, identityClass: "staged-local", recordRole: "command-program" },
      { name: "GPURenderPassEncoder.draw", tag: 13, identityClass: "active-route", recordRole: "command-program" },
      { name: "GPURenderPassEncoder.end", tag: 14, identityClass: "active-route", recordRole: "command-program" },
      { name: "GPUCommandEncoder.finish", tag: 15, identityClass: "active-route", recordRole: "command-program" },
    ],
    "native queue submit operation-variant table",
  );
  assertDigest(
    canonicalDigest(
      "ibex/webgpu-native-codec-program/queue-submit-request-body-v1",
      types.queueSubmitRequestBodyV1,
    ),
    EXPECTED_QUEUE_SUBMIT_REQUEST_BODY_TYPE_SHA256,
    "native queue submit request-body type",
  );
  assertCanonical(
    types.queueSubmitRequestBodyV1.programDigest,
    {
      algorithm: "sha256",
      domainUtf8WithTrailingNul: "exact/webgpu-command-program/v1\0",
      inputOrder: [
        "domain-utf8-bytes-without-length-prefix",
        "commandBufferRef-objectReferenceV1",
        "invalid-u8",
        "finishRecordPosition-u32le",
        "recordIndexCount-u32le",
        "for-each-index-in-program-order-recordByteLength-u32le-plus-exact-commandRecordV1-bytes",
      ],
    },
    "native queue submit program digest",
  );
  assertCanonical(
    types.headerV1,
    {
      kind: "struct",
      fields: [
        { name: "magic", type: "ascii4" },
        { name: "version", type: "u16le" },
        { name: "codecTag", type: "u16le" },
        { name: "operationWireId", type: "u32le" },
      ],
    },
    "native codec header type",
  );
  assertCanonical(
    types.objectReferenceV1,
    {
      kind: "struct",
      fields: [
        { name: "kind", type: "u8", catalog: "objectKindTags" },
        { name: "objectId", type: "u64le" },
        { name: "objectGeneration", type: "u64le" },
        { name: "logicalDeviceId", type: "u64le" },
        { name: "logicalDeviceGeneration", type: "u64le" },
        { name: "providerGeneration", type: "u64le" },
      ],
    },
    "native codec object-reference type",
  );
  assertCanonical(
    types.optionalReferenceV1,
    {
      kind: "optional",
      discriminantType: "u8",
      absentTag: 0,
      presentTag: 1,
      valueType: "objectReferenceV1",
    },
    "native codec optional-reference type",
  );
  assertCanonical(
    types.canonicalValueV1,
    {
      kind: "recursive-tagged-union",
      tagType: "u8",
      maxDepthFrom: "codecLayout.nestingMaxDepth",
      rootDepth: 0,
      depthLimitOperator: "less-than-or-equal",
      variants: [
        { name: "null", tag: envelope.codecLayout.valueTags.null, payload: { kind: "empty" } },
        { name: "false", tag: envelope.codecLayout.valueTags.false, payload: { kind: "empty" } },
        { name: "true", tag: envelope.codecLayout.valueTags.true, payload: { kind: "empty" } },
        { name: "u32", tag: envelope.codecLayout.valueTags.u32, payload: { kind: "scalar", type: "u32le" } },
        { name: "f64", tag: envelope.codecLayout.valueTags.f64, payload: { kind: "scalar", type: "f64le" } },
        { name: "string", tag: envelope.codecLayout.valueTags.string, payload: { kind: "scalar", type: "utf8" } },
        {
          name: "sequence",
          tag: envelope.codecLayout.valueTags.sequence,
          payload: {
            kind: "sequence",
            countType: "u32le",
            elementType: "canonicalValueV1",
            maxCountFrom: "codecLayout.sequenceMaxCount",
            countLimitOperator: "less-than-or-equal",
          },
        },
        {
          name: "dictionary",
          tag: envelope.codecLayout.valueTags.dictionary,
          payload: {
            kind: "dictionary",
            countType: "u32le",
            keyType: "utf8",
            valueType: "canonicalValueV1",
            maxCountFrom: "codecLayout.dictionaryMaxFields",
            countLimitOperator: "less-than-or-equal",
            keyConstraints: [
              "unique",
              "strictly-increasing-unsigned-utf8-bytes-shorter-prefix-first",
            ],
          },
        },
      ],
    },
    "native canonical-value type",
  );
  assertCanonical(
    types.requestAdapterOptionsV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      unknownFields: "reject",
      fields: [
        {
          name: "featureLevel",
          required: true,
          value: { kind: "string-enum", values: ["core", "compatibility"] },
        },
        {
          name: "forceFallbackAdapter",
          required: true,
          value: { kind: "boolean" },
        },
        {
          name: "powerPreference",
          required: false,
          value: {
            kind: "string-enum",
            values: ["low-power", "high-performance"],
          },
        },
        {
          name: "xrCompatible",
          required: true,
          value: { kind: "boolean" },
        },
      ],
      preEncodingBranches: [
        {
          condition: "featureLevel-not-core-or-compatibility",
          disposition: "wrapper-local-null-no-service-call",
        },
      ],
    },
    "native requestAdapter option type",
  );
  assertCanonical(
    types.requestDeviceDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: { kind: "string" },
        },
        {
          name: "requiredFeatures",
          required: true,
          value: {
            kind: "sequence",
            element: "string",
            maxCountFrom: "codecLayout.sequenceMaxCount",
          },
        },
        {
          name: "requiredLimits",
          required: true,
          value: {
            kind: "dictionary",
            key: "string",
            value: "nonnegative-js-safe-integer",
            maxCountFrom: "codecLayout.dictionaryMaxFields",
          },
        },
        {
          name: "defaultQueue",
          required: true,
          value: {
            kind: "closed-dictionary",
            unknownFields: "reject",
            fields: [{
              name: "label",
              required: true,
              value: { kind: "string" },
            }],
          },
        },
      ],
    },
    "native requestDevice untrusted descriptor ingress type",
  );
  assertCanonical(
    types.bindGroupDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: { kind: "string" },
        },
        {
          name: "entries",
          required: true,
          value: {
            kind: "sequence",
            minCount: 0,
            maxCountFrom: "codecLayout.sequenceMaxCount",
            element: {
              kind: "closed-dictionary",
              unknownFields: "reject",
              fields: [
                { name: "binding", required: true, value: { kind: "u32" } },
                {
                  name: "resource",
                  required: true,
                  value: {
                    kind: "closed-dictionary",
                    unknownFields: "reject",
                    fields: [
                      {
                        name: "resourceKind",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: [
                            "GPUBufferBinding",
                            "GPUSampler",
                            "GPUTextureView",
                            "GPUBuffer",
                            "GPUTexture",
                            "GPUExternalTexture",
                          ],
                        },
                      },
                      {
                        name: "buffer",
                        required: false,
                        value: {
                          kind: "full-object-reference",
                          referenceType: "objectReferenceV1",
                          requiredObjectKind: "GPUBuffer",
                        },
                      },
                      { name: "offset", required: false, value: { kind: "u64" } },
                      { name: "size", required: false, value: { kind: "u64" } },
                      {
                        name: "reference",
                        required: false,
                        value: {
                          kind: "full-object-reference",
                          referenceType: "objectReferenceV1",
                          permittedObjectKinds: [
                            "GPUSampler",
                            "GPUTextureView",
                            "GPUBuffer",
                            "GPUTexture",
                            "GPUExternalTexture",
                          ],
                        },
                      },
                    ],
                  },
                },
              ],
            },
          },
        },
        {
          name: "layout",
          required: true,
          value: {
            kind: "full-object-reference",
            referenceType: "objectReferenceV1",
            requiredObjectKind: "GPUBindGroupLayout",
          },
        },
      ],
    },
    "native createBindGroup untrusted descriptor ingress type",
  );
  assertCanonical(
    types.bindGroupLayoutDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: { kind: "string" },
        },
        {
          name: "entries",
          required: true,
          value: {
            kind: "sequence",
            minCount: 0,
            maxCountFrom: "codecLayout.sequenceMaxCount",
            element: {
              kind: "closed-dictionary",
              unknownFields: "reject",
              fields: [
                {
                  name: "binding",
                  required: true,
                  value: { kind: "u32" },
                },
                {
                  name: "buffer",
                  required: false,
                  value: {
                    kind: "closed-dictionary",
                    unknownFields: "reject",
                    fields: [
                      {
                        name: "hasDynamicOffset",
                        required: true,
                        value: { kind: "boolean" },
                      },
                      {
                        name: "minBindingSize",
                        required: true,
                        value: {
                          kind: "u64",
                          constraints: ["js-safe-integer"],
                        },
                      },
                      {
                        name: "type",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: ["uniform", "storage", "read-only-storage"],
                        },
                      },
                    ],
                  },
                },
                {
                  name: "externalTexture",
                  required: false,
                  value: {
                    kind: "closed-dictionary",
                    unknownFields: "reject",
                    fields: [],
                  },
                },
                {
                  name: "sampler",
                  required: false,
                  value: {
                    kind: "closed-dictionary",
                    unknownFields: "reject",
                    fields: [
                      {
                        name: "type",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: ["filtering", "non-filtering", "comparison"],
                        },
                      },
                    ],
                  },
                },
                {
                  name: "storageTexture",
                  required: false,
                  value: {
                    kind: "closed-dictionary",
                    unknownFields: "reject",
                    fields: [
                      {
                        name: "access",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: ["write-only", "read-only", "read-write"],
                        },
                      },
                      {
                        name: "format",
                        required: true,
                        value: {
                          kind: "string-enum",
                          valuesFrom: "webIdlVocabulary.gpuTextureFormats",
                        },
                      },
                      {
                        name: "viewDimension",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: [
                            "1d",
                            "2d",
                            "2d-array",
                            "cube",
                            "cube-array",
                            "3d",
                          ],
                        },
                      },
                    ],
                  },
                },
                {
                  name: "texture",
                  required: false,
                  value: {
                    kind: "closed-dictionary",
                    unknownFields: "reject",
                    fields: [
                      {
                        name: "multisampled",
                        required: true,
                        value: { kind: "boolean" },
                      },
                      {
                        name: "sampleType",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: [
                            "float",
                            "unfilterable-float",
                            "depth",
                            "sint",
                            "uint",
                          ],
                        },
                      },
                      {
                        name: "viewDimension",
                        required: true,
                        value: {
                          kind: "string-enum",
                          values: [
                            "1d",
                            "2d",
                            "2d-array",
                            "cube",
                            "cube-array",
                            "3d",
                          ],
                        },
                      },
                    ],
                  },
                },
                {
                  name: "visibility",
                  required: true,
                  value: { kind: "u32" },
                },
              ],
            },
          },
        },
      ],
    },
    "native createBindGroupLayout post-WebIDL structural descriptor type",
  );
  assertCanonical(
    types.bufferDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: {
            kind: "string",
            constraints: [
              "maximum-utf8-bytes-16777017",
              "shares-total-payload-budget-with-sealed-local-timeline",
            ],
          },
        },
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
    },
    "native createBuffer post-WebIDL structural descriptor type",
  );
  assertCanonical(
    types.pipelineLayoutDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: { kind: "string" },
        },
        {
          name: "bindGroupLayouts",
          required: true,
          value: {
            kind: "sequence",
            minCount: 0,
            maxCountFrom: "codecLayout.sequenceMaxCount",
            element: {
              kind: "nullable-full-object-reference",
              nullValue: "null",
              referenceType: "objectReferenceV1",
              requiredObjectKind: "GPUBindGroupLayout",
            },
          },
        },
        {
          name: "immediateSize",
          required: true,
          value: { kind: "u32" },
        },
      ],
    },
    "native createPipelineLayout post-WebIDL structural descriptor type",
  );
  assertCanonical(
    types.samplerDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        { name: "addressModeU", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuAddressModes" } },
        { name: "addressModeV", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuAddressModes" } },
        { name: "addressModeW", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuAddressModes" } },
        { name: "compare", required: false, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuCompareFunctions" } },
        { name: "label", required: true, value: { kind: "string" } },
        { name: "lodMaxClamp", required: true, value: { kind: "f64", constraints: ["finite"] } },
        { name: "lodMinClamp", required: true, value: { kind: "f64", constraints: ["finite"] } },
        { name: "magFilter", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuFilterModes" } },
        { name: "maxAnisotropy", required: true, value: { kind: "u32", constraints: ["maximum-65535"] } },
        { name: "minFilter", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuFilterModes" } },
        { name: "mipmapFilter", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuMipmapFilterModes" } },
      ],
    },
    "native createSampler post-WebIDL structural descriptor type",
  );
  assertCanonical(
    types.textureDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        { name: "dimension", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureDimensions" } },
        { name: "format", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureFormats" } },
        { name: "label", required: true, value: { kind: "string" } },
        { name: "mipLevelCount", required: true, value: { kind: "u32" } },
        { name: "sampleCount", required: true, value: { kind: "u32" } },
        {
          name: "size",
          required: true,
          value: {
            kind: "closed-dictionary",
            unknownFields: "reject",
            fields: [
              { name: "depthOrArrayLayers", required: true, value: { kind: "u32" } },
              { name: "height", required: true, value: { kind: "u32" } },
              { name: "width", required: true, value: { kind: "u32" } },
            ],
          },
        },
        { name: "textureBindingViewDimension", required: false, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureViewDimensions" } },
        { name: "usage", required: true, value: { kind: "u32" } },
        {
          name: "viewFormats",
          required: true,
          value: {
            kind: "sequence",
            maxCountFrom: "codecLayout.sequenceMaxCount",
            element: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureFormats" },
          },
        },
      ],
    },
    "native createTexture post-WebIDL structural descriptor type",
  );
  assertCanonical(
    types.textureViewRequestV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      trust: "untrusted-webidl-converted-semantic-service-ingress-only",
      providerBoundary: "forbidden-raw-descriptor-or-origin-must-not-reach-provider",
      unknownFields: "reject",
      fields: [
        {
          name: "converted",
          required: true,
          value: {
            kind: "closed-dictionary",
            unknownFields: "reject",
            fields: [
              { name: "arrayLayerCount", required: false, value: { kind: "u32" } },
              { name: "aspect", required: true, value: { kind: "string-enum", values: ["all", "stencil-only", "depth-only"] } },
              { name: "baseArrayLayer", required: true, value: { kind: "u32" } },
              { name: "baseMipLevel", required: true, value: { kind: "u32" } },
              { name: "dimension", required: false, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureViewDimensions" } },
              { name: "format", required: false, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureFormats" } },
              { name: "label", required: true, value: { kind: "string" } },
              { name: "mipLevelCount", required: false, value: { kind: "u32" } },
              { name: "swizzle", required: true, value: { kind: "string", constraints: ["texture-component-swizzle-syntax"] } },
              { name: "usage", required: true, value: { kind: "u32" } },
            ],
          },
        },
        {
          name: "currentOrigin",
          required: false,
          value: {
            kind: "closed-dictionary",
            unknownFields: "reject",
            fields: [
              { name: "originClass", required: true, value: { kind: "string-enum", values: ["canvas-current"] } },
              { name: "contextRef", required: true, value: { kind: "full-object-reference" } },
              { name: "attachmentGeneration", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
              { name: "contextGeneration", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
              { name: "configurationGeneration", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
              { name: "currentEpoch", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
              {
                name: "mintOperationProvenance",
                required: true,
                value: {
                  kind: "closed-dictionary",
                  unknownFields: "reject",
                  fields: [
                    { name: "operationInstanceId", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
                    { name: "deviceIngressOrdinal", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
                  ],
                },
              },
              { name: "textureOriginDigest", required: true, value: { kind: "string", constraints: ["sha256-hex"] } },
              { name: "configuredDeviceRef", required: true, value: { kind: "full-object-reference" } },
              { name: "format", required: true, value: { kind: "string-enum", valuesFrom: "webIdlVocabulary.gpuTextureFormats" } },
              { name: "usage", required: true, value: { kind: "u32" } },
              { name: "alphaMode", required: true, value: { kind: "string-enum", values: ["opaque", "premultiplied"] } },
              { name: "colorSpace", required: true, value: { kind: "string-enum", values: ["srgb", "display-p3"] } },
              { name: "targetAuthorityDigest", required: true, value: { kind: "string", constraints: ["sha256-hex"] } },
              { name: "surfaceAccountToken", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
              { name: "surfaceAccountGeneration", required: true, value: { kind: "string", constraints: ["positive-u64-canonical-decimal"] } },
            ],
          },
        },
      ],
    },
    "native createTextureView post-WebIDL structural request type",
  );
  assertCanonical(
    types.commandEncoderDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: { kind: "string" },
        },
      ],
    },
    "native createCommandEncoder descriptor type",
  );
  assertCanonical(
    types.shaderModuleDescriptorV1,
    {
      kind: "closed-dictionary",
      encodingType: "canonicalValueV1",
      unknownFields: "reject",
      fields: [
        {
          name: "label",
          required: true,
          value: { kind: "string" },
        },
        {
          name: "code",
          required: true,
          value: { kind: "string" },
        },
      ],
    },
    "native createShaderModule descriptor type",
  );
  assertCanonical(
    types.sortedUniqueFeatureSequenceV1,
    {
      kind: "sequence",
      countType: "u32le",
      elementType: "utf8",
      maxCountFrom: "codecLayout.sequenceMaxCount",
      constraints: ["strictly-increasing-utf8-strings"],
    },
    "native requestDevice feature result type",
  );
  assertCanonical(
    types.completeDeviceLimitsV1,
    {
      kind: "ordered-record",
      fieldNamesFrom: "semanticProjection.limitPolicy.limits",
      requiredFieldCount: 36,
      valueType: "u64le",
      constraints: ["js-safe-integer"],
    },
    "native requestDevice complete limits result type",
  );
  assertCanonical(
    types.gpuDeviceCompletionBodyV1,
    {
      kind: "struct",
      fields: [
        { name: "objectId", type: "u64le", constraint: "positive" },
        { name: "objectGeneration", type: "u64le", constraint: "positive" },
        { name: "logicalDeviceId", type: "u64le", constraint: "positive" },
        {
          name: "logicalDeviceGeneration",
          type: "u64le",
          constraint: "positive",
        },
        { name: "providerGeneration", type: "u64le", constraint: "positive" },
        { name: "queueObjectId", type: "u64le", constraint: "positive" },
        {
          name: "queueObjectGeneration",
          type: "u64le",
          constraint: "positive",
        },
        { name: "features", type: "sortedUniqueFeatureSequenceV1" },
        { name: "limits", type: "completeDeviceLimitsV1" },
        {
          name: "diagnosticMessage",
          type: "utf8",
          maxBytesFrom: "codecLayout.diagnosticMaxBytes",
        },
      ],
    },
    "native requestDevice completion body type",
  );

  assert(
    Array.isArray(program.routes) &&
      program.routes.length === NATIVE_CODEC_ROUTE_IDS.length &&
      program.routes.map((route) => route.operationId).join("|") ===
        NATIVE_CODEC_ROUTE_IDS.join("|"),
    "native codec program route order or inventory drifted: expected " +
      NATIVE_CODEC_ROUTE_IDS.join(", "),
  );
  const route = program.routes.find(
    (candidate) => candidate.operationId === "GPU.requestAdapter",
  );
  const operation = payload.operations.find(
    (candidate) => candidate.operationId === "GPU.requestAdapter",
  );
  assert(
    operation && route.operationId === operation.operationId &&
      route.wireId === operation.wireId,
    "native requestAdapter operation identity drifted",
  );
  const requestCatalogIndex = payload.codecCatalog.serviceArguments.findIndex(
    (codec) => codec.tag === operation.serviceArgumentCodec,
  );
  const completionCatalogIndex = payload.codecCatalog.serviceCompletions.findIndex(
    (codec) => codec.tag === operation.serviceCompletionCodec,
  );
  assertCanonical(
    route.request.catalog,
    {
      name: "serviceArguments",
      tag: operation.serviceArgumentCodec,
      wireTag: requestCatalogIndex + 1,
    },
    "native requestAdapter request catalog selection",
  );
  assert(
    route.request.payloadRole ===
      "service-request-payload-decoder-plus-operation-specific-call-joins",
    "native requestAdapter request payload role drifted",
  );
  assertCanonical(
    route.completion.catalog,
    {
      name: "serviceCompletions",
      tag: operation.serviceCompletionCodec,
      wireTag: completionCatalogIndex + 1,
    },
    "native requestAdapter completion catalog selection",
  );
  assert(
    route.completion.payloadRole ===
      "service-completion-payload-codec-plus-operation-specific-event-joins",
    "native requestAdapter completion payload role drifted",
  );
  assertCanonical(
    route.request.payload,
    {
      kind: "struct",
      fields: [
        {
          name: "header",
          type: "headerV1",
          constants: {
            magic: envelope.codecLayout.requestMagic,
            version: envelope.codecLayout.version,
            codecTag: requestCatalogIndex + 1,
            operationWireId: operation.wireId,
          },
        },
        { name: "receiver", type: "objectReferenceV1" },
        { name: "target", type: "optionalReferenceV1" },
        { name: "capturedScopeId", type: "u64le" },
        { name: "adapterOrdinal", type: "u64le" },
        { name: "deviceIngressOrdinal", type: "u64le" },
        { name: "queueIngressOrdinal", type: "u64le" },
        { name: "sealedLocalTimeline", type: "canonicalValueV1" },
        {
          name: "convertedArguments",
          type: "canonicalValueV1",
          constraintType: "requestAdapterOptionsV1",
        },
      ],
    },
    "native requestAdapter request layout",
  );
  assertCanonical(
    route.request.carrierJoins,
    [
      ["header.operationWireId", "operation_id", "equal"],
      ["receiver.kind", "receiver.kind", "equal"],
      ["receiver.objectId", "receiver.object_id", "equal"],
      ["receiver.objectGeneration", "receiver.object_generation", "equal"],
      ["receiver.logicalDeviceId", "ingress_device.logical_device_id", "equal"],
      ["receiver.logicalDeviceGeneration", "ingress_device.logical_device_generation", "equal"],
      ["receiver.providerGeneration", "ingress_device.provider_generation", "equal"],
      ["receiver.providerGeneration", "provider_generation", "equal"],
      ["target", "target", "absent-iff-all-zero-reference"],
      ["capturedScopeId", "captured_scope_id", "equal"],
      ["adapterOrdinal", "adapter_ordinal", "equal"],
      ["deviceIngressOrdinal", "device_ingress_ordinal", "equal"],
      ["queueIngressOrdinal", "queue_ingress_ordinal", "equal"],
    ].map(([payloadPath, carrierPath, operator]) => ({
      payloadPath,
      carrierPath,
      operator,
    })),
    "native requestAdapter carrier joins",
  );
  assertCanonical(
    route.request.carrierConstraints,
    [
      { carrierPath: "operation_id", operator: "equal", value: operation.wireId },
      { carrierPath: "flags", operator: "equal", value: 0 },
      {
        carrierPath: "topology_id",
        operator: "equal",
        valueFrom: "constants.providerTopologyId",
      },
      { carrierPath: "ingress_device", operator: "all-zero" },
      { carrierPath: "provider_generation", operator: "equal", value: "0" },
      { carrierPath: "operation_instance_id", operator: "positive" },
      { carrierPath: "promise_id", operator: "positive" },
      { carrierPath: "receiver.kind", operator: "equal", valueFrom: "objectKindTags.GPU" },
      { carrierPath: "receiver.flags", operator: "equal", value: 0 },
      { carrierPath: "receiver.object_id", operator: "positive" },
      { carrierPath: "receiver.object_generation", operator: "positive" },
      { carrierPath: "target", operator: "all-zero" },
      { carrierPath: "captured_scope_id", operator: "equal", value: "0" },
      { carrierPath: "adapter_ordinal", operator: "equal", value: "0" },
      { carrierPath: "device_ingress_ordinal", operator: "equal", value: "0" },
      { carrierPath: "queue_ingress_ordinal", operator: "equal", value: "0" },
    ],
    "native requestAdapter carrier constraints",
  );
  assertCanonical(
    route.request.valueConstraints,
    [
      { payloadPath: "sealedLocalTimeline", operator: "exact-empty-sequence" },
      {
        payloadPath: "convertedArguments",
        operator: "conforms-to-type",
        type: "requestAdapterOptionsV1",
      },
    ],
    "native requestAdapter value constraints",
  );
  assert(route.request.noTrailingBytes === true,
    "native requestAdapter request must reject trailing bytes");
  assertCanonical(
    route.completion.commonCarrierConstraints,
    [
      {
        carrierPath: "kind",
        operator: "equal",
        value: 1,
        symbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      },
      {
        carrierPath: "record.operation_result.status",
        operator: "equal",
        value: 0,
      },
      {
        carrierPath: "record.operation_result.operation.operation_id",
        operator: "equal",
        value: operation.wireId,
      },
      {
        carrierPath: "record.operation_result.operation.device_transition",
        operator: "equal",
        value: 0,
        symbol: "EXACT_GPU_DEVICE_UNCHANGED_V2",
      },
      {
        carrierPath: "record.operation_result.operation.ingress_device",
        operator: "all-zero",
      },
      {
        carrierPath: "record.operation_result.operation.result_device",
        operator: "all-zero",
      },
    ],
    "native requestAdapter completion carrier constraints",
  );
  assertCanonical(
    route.completion.variants,
    [
      {
        name: "null",
        resultKind: 2,
        resultKindSymbol: "EXACT_GPU_RESULT_NULL_V2",
        payload: { kind: "empty", exactLengthBytes: 0 },
      },
      {
        name: "object",
        resultKind: 3,
        resultKindSymbol: "EXACT_GPU_RESULT_OBJECT_V2",
        objectKind: "GPUAdapter",
        payload: {
          kind: "struct",
          fields: [
            {
              name: "header",
              type: "headerV1",
              constants: {
                magic: envelope.codecLayout.resultMagic,
                version: envelope.codecLayout.version,
                codecTag: completionCatalogIndex + 1,
                operationWireId: operation.wireId,
              },
            },
            { name: "present", type: "u8", constant: 1 },
            { name: "objectId", type: "u64le", constraint: "positive" },
            { name: "objectGeneration", type: "u64le", constraint: "positive" },
            { name: "providerGeneration", type: "u64le", constraint: "positive" },
            {
              name: "serviceDetachedExpired",
              type: "u8",
              constraint: "boolean-zero-or-one",
            },
            { name: "features", type: "sortedUniqueFeatureSequenceV1" },
          ],
        },
        carrierJoins: [
          {
            payloadPath: "providerGeneration",
            carrierPath:
              "record.operation_result.operation.provider_generation",
            operator: "equal",
          },
        ],
        noTrailingBytes: true,
      },
    ],
    "native requestAdapter completion variants",
  );

  const requestDeviceRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUAdapter.requestDevice",
  );
  const requestDeviceOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUAdapter.requestDevice",
  );
  assert(
    requestDeviceRoute && requestDeviceOperation &&
      requestDeviceRoute.wireId === requestDeviceOperation.wireId,
    "native requestDevice operation identity drifted",
  );
  const requestDeviceRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === requestDeviceOperation.serviceArgumentCodec,
    );
  const requestDeviceCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === requestDeviceOperation.serviceCompletionCodec,
    );
  assertCanonical(
    requestDeviceRoute.request.catalog,
    {
      name: "serviceArguments",
      tag: "gpu-request-device-service-request-v1",
      wireTag: requestDeviceRequestCatalogIndex + 1,
    },
    "native requestDevice request catalog selection",
  );
  assertCanonical(
    requestDeviceRoute.request.payload,
    {
      kind: "struct",
      fields: [
        {
          name: "header",
          type: "headerV1",
          constants: {
            magic: envelope.codecLayout.requestMagic,
            version: envelope.codecLayout.version,
            codecTag: requestDeviceRequestCatalogIndex + 1,
            operationWireId: requestDeviceOperation.wireId,
          },
        },
        { name: "receiver", type: "objectReferenceV1" },
        { name: "target", type: "optionalReferenceV1" },
        { name: "capturedScopeId", type: "u64le" },
        { name: "adapterOrdinal", type: "u64le" },
        { name: "deviceIngressOrdinal", type: "u64le" },
        { name: "queueIngressOrdinal", type: "u64le" },
        { name: "sealedLocalTimeline", type: "canonicalValueV1" },
        {
          name: "convertedArguments",
          type: "canonicalValueV1",
          constraintType: "requestDeviceDescriptorV1",
        },
      ],
    },
    "native requestDevice request layout",
  );
  assertCanonical(
    requestDeviceRoute.request.carrierJoins,
    [
      ["header.operationWireId", "operation_id", "equal"],
      ["receiver.kind", "receiver.kind", "equal"],
      ["receiver.objectId", "receiver.object_id", "equal"],
      ["receiver.objectGeneration", "receiver.object_generation", "equal"],
      ["receiver.logicalDeviceId", "ingress_device.logical_device_id", "equal"],
      ["receiver.logicalDeviceGeneration", "ingress_device.logical_device_generation", "equal"],
      ["receiver.providerGeneration", "provider_generation", "equal"],
      ["target", "target", "absent-iff-all-zero-reference"],
      ["capturedScopeId", "captured_scope_id", "equal"],
      ["adapterOrdinal", "adapter_ordinal", "equal"],
      ["deviceIngressOrdinal", "device_ingress_ordinal", "equal"],
      ["queueIngressOrdinal", "queue_ingress_ordinal", "equal"],
    ].map(([payloadPath, carrierPath, operator]) => ({
      payloadPath,
      carrierPath,
      operator,
    })),
    "native requestDevice carrier joins",
  );
  assertCanonical(
    requestDeviceRoute.request.carrierConstraints,
    [
      {
        carrierPath: "operation_id",
        operator: "equal",
        value: requestDeviceOperation.wireId,
      },
      { carrierPath: "flags", operator: "equal", value: 0 },
      {
        carrierPath: "topology_id",
        operator: "equal",
        valueFrom: "constants.providerTopologyId",
      },
      { carrierPath: "ingress_device", operator: "all-zero" },
      { carrierPath: "provider_generation", operator: "positive" },
      { carrierPath: "operation_instance_id", operator: "positive" },
      { carrierPath: "promise_id", operator: "positive" },
      {
        carrierPath: "receiver.kind",
        operator: "equal",
        valueFrom: "objectKindTags.GPUAdapter",
      },
      { carrierPath: "receiver.flags", operator: "equal", value: 0 },
      { carrierPath: "receiver.object_id", operator: "positive" },
      { carrierPath: "receiver.object_generation", operator: "positive" },
      { carrierPath: "target", operator: "all-zero" },
      { carrierPath: "captured_scope_id", operator: "equal", value: "0" },
      { carrierPath: "adapter_ordinal", operator: "positive" },
      { carrierPath: "device_ingress_ordinal", operator: "equal", value: "0" },
      { carrierPath: "queue_ingress_ordinal", operator: "equal", value: "0" },
    ],
    "native requestDevice carrier constraints",
  );
  assertCanonical(
    requestDeviceRoute.request.valueConstraints,
    [
      { payloadPath: "sealedLocalTimeline", operator: "exact-empty-sequence" },
      {
        payloadPath: "convertedArguments",
        operator: "conforms-to-type",
        type: "requestDeviceDescriptorV1",
      },
      {
        payloadPath: "convertedArguments",
        operator: "untrusted-semantic-service-ingress-only-never-provider-input",
      },
    ],
    "native requestDevice value constraints",
  );
  assertCanonical(
    requestDeviceRoute.request.semanticServiceDerivations,
    [
      {
        name: "generatedLogicalProviderDescriptor",
        ownership: "native-semantic-service-derived-never-payload-or-wrapper-supplied",
        inputs: [
          "untrusted-convertedArguments",
          "authenticated-adapter-state",
          "authenticated-feature-level-profile",
          "authenticated-capability-grant",
          "versioned-service-internal-requirements",
        ],
        output:
          "exact-logical-features-limits-plus-versioned-service-internal-requirements-only",
        forbiddenProviderInputs: ["convertedArguments", "raw-GPUDeviceDescriptor"],
        requiredBefore: ["provider-admission"],
        authenticatedCrossLinks: [
          {
            derivedPath: "providerGeneration",
            carrierPath: "provider_generation",
            operator: "equal",
          },
          {
            derivedPath: "adapterIdentity",
            carrierPath: "receiver",
            operator: "derived-from-authenticated-reference",
          },
        ],
      },
      {
        name: "authenticatedResultSelectionIdentity",
        ownership: "native-semantic-service-allocated-never-payload-or-wrapper-supplied",
        inputs: [
          "authenticated-retained-call",
          "live-device-reservation",
          "authenticated-adapter-publication-credit",
          "authenticated-account-capacity-state",
        ],
        output: "fresh-device-object-logical-device-and-queue-identities",
        requiredBefore: ["provider-admission", "completion-encoding"],
        authenticatedCrossLinks: [
          {
            derivedPath: "logicalDeviceId",
            carrierPath:
              "record.operation_result.operation.result_device.logical_device_id",
            operator: "equal",
          },
          {
            derivedPath: "logicalDeviceGeneration",
            carrierPath:
              "record.operation_result.operation.result_device.logical_device_generation",
            operator: "equal",
          },
          {
            derivedPath: "providerGeneration",
            carrierPath:
              "record.operation_result.operation.result_device.provider_generation",
            operator: "equal",
          },
          {
            derivedPath: "retainedOperationIdentity",
            carrierPath: "record.operation_result.operation.operation_instance_id",
            operator: "bound-to-authenticated-retained-call",
          },
          {
            derivedPath: "retainedPromiseIdentity",
            carrierPath: "record.operation_result.operation.promise_id",
            operator: "bound-to-authenticated-retained-call",
          },
        ],
      },
    ],
    "native requestDevice semantic-service derivations",
  );
  assertCanonical(
    requestDeviceRoute.request.executablePrerequisites,
    ["generatedLogicalProviderDescriptor", "authenticatedResultSelectionIdentity"],
    "native requestDevice executable prerequisites",
  );
  assert(requestDeviceRoute.request.noTrailingBytes === true,
    "native requestDevice request must reject trailing bytes");

  assertCanonical(
    requestDeviceRoute.completion.catalog,
    {
      name: "serviceCompletions",
      tag: "gpu-device-service-completion-v1",
      wireTag: requestDeviceCompletionCatalogIndex + 1,
    },
    "native requestDevice completion catalog selection",
  );
  assertCanonical(
    requestDeviceRoute.completion.payload,
    {
      kind: "struct",
      fields: [
        {
          name: "header",
          type: "headerV1",
          constants: {
            magic: envelope.codecLayout.resultMagic,
            version: envelope.codecLayout.version,
            codecTag: requestDeviceCompletionCatalogIndex + 1,
            operationWireId: requestDeviceOperation.wireId,
          },
        },
        { name: "body", type: "gpuDeviceCompletionBodyV1" },
      ],
    },
    "native requestDevice completion layout",
  );
  assertCanonical(
    requestDeviceRoute.completion.commonCarrierConstraints,
    [
      {
        carrierPath: "kind",
        operator: "equal",
        value: 1,
        symbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      },
      { carrierPath: "record.operation_result.status", operator: "equal", value: 0 },
      {
        carrierPath: "record.operation_result.operation.operation_id",
        operator: "equal",
        value: requestDeviceOperation.wireId,
      },
      {
        carrierPath: "record.operation_result.operation.ingress_device",
        operator: "all-zero",
      },
      {
        carrierPath: "record.operation_result.operation.result_device",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.provider_generation",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.receiver.kind",
        operator: "equal",
        valueFrom: "objectKindTags.GPUAdapter",
      },
      {
        carrierPath: "record.operation_result.operation.target",
        operator: "all-zero",
      },
      {
        carrierPath: "record.operation_result.operation.adapter_ordinal",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.device_ingress_ordinal",
        operator: "equal",
        value: "0",
      },
      {
        carrierPath: "record.operation_result.operation.queue_ingress_ordinal",
        operator: "equal",
        value: "0",
      },
      {
        carrierPath: "record.operation_result.result_kind",
        operator: "equal",
        value: 3,
        symbol: "EXACT_GPU_RESULT_OBJECT_V2",
      },
    ],
    "native requestDevice completion carrier constraints",
  );
  assertCanonical(
    requestDeviceRoute.completion.carrierJoins,
    [
      ["body.logicalDeviceId", "record.operation_result.operation.result_device.logical_device_id"],
      ["body.logicalDeviceGeneration", "record.operation_result.operation.result_device.logical_device_generation"],
      ["body.providerGeneration", "record.operation_result.operation.result_device.provider_generation"],
      ["body.providerGeneration", "record.operation_result.operation.provider_generation"],
    ].map(([payloadPath, carrierPath]) => ({ payloadPath, carrierPath, operator: "equal" })),
    "native requestDevice completion carrier joins",
  );
  assertCanonical(
    requestDeviceRoute.completion.serviceResultJoins,
    [
      ["body.objectId", "authenticatedResultSelectionIdentity.deviceObjectId"],
      ["body.objectGeneration", "authenticatedResultSelectionIdentity.deviceObjectGeneration"],
      ["body.queueObjectId", "authenticatedResultSelectionIdentity.queueObjectId"],
      ["body.queueObjectGeneration", "authenticatedResultSelectionIdentity.queueObjectGeneration"],
      ["body.features", "generatedLogicalProviderDescriptor.logicalFeatures"],
      ["body.limits", "generatedLogicalProviderDescriptor.logicalLimits"],
      [
        "body.diagnosticMessage",
        "nativeSemanticServiceResult.diagnosticMessage",
        "equal-never-caller-selected",
      ],
    ].map(([payloadPath, serviceResultPath, operator = "equal"]) => ({
      payloadPath, serviceResultPath, operator,
    })),
    "native requestDevice completion semantic-result joins",
  );
  const [liveVariant, detachedNotAdmittedVariant, detachedAdmittedVariant] =
    requestDeviceRoute.completion.variants;
  assertCanonical(
    requestDeviceRoute.completion.variants.map((variant) => variant.name),
    ["live-object", "detached-not-admitted-object", "detached-admitted-object"],
    "native requestDevice completion variant inventory",
  );
  assertCanonical(
    liveVariant.carrierConstraints,
    [
      {
        carrierPath: "record.operation_result.operation.device_transition",
        operator: "equal",
        value: 1,
        symbol: "EXACT_GPU_DEVICE_ASSIGNED_V2",
      },
      {
        carrierPath: "record.operation_result.operation.provider_admission",
        operator: "equal",
        value: 1,
        symbol: "EXACT_GPU_PROVIDER_ADMITTED_V2",
      },
      {
        carrierPath: "record.operation_result.operation.physical_sequence",
        operator: "positive",
      },
      { carrierPath: "detachedAlreadyLost", operator: "equal", value: false },
      { carrierPath: "lossReason-and-backendClass", operator: "absent" },
    ],
    "native requestDevice live completion variant",
  );
  assertCanonical(
    liveVariant.payloadConstraints,
    [{
      payloadPath: "body.diagnosticMessage",
      operator: "exact-empty-string",
    }],
    "native requestDevice live completion diagnostic",
  );
  const expectedDetachedTail = [
    { carrierPath: "detachedAlreadyLost", operator: "equal", value: true },
    {
      carrierPath: "lossReason",
      operator: "equal",
      value: 1,
      symbol: "EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2",
    },
    {
      carrierPath: "backendClass",
      operator: "equal",
      value: 0,
      symbol: "EXACT_GPU_BACKEND_NONE_V2",
    },
  ];
  for (const [variant, admitted] of [
    [detachedNotAdmittedVariant, false],
    [detachedAdmittedVariant, true],
  ]) {
    assertCanonical(
      variant.carrierConstraints,
      [
        {
          carrierPath: "record.operation_result.operation.device_transition",
          operator: "equal",
          value: 2,
          symbol: "EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2",
        },
        {
          carrierPath: "record.operation_result.operation.provider_admission",
          operator: "equal",
          value: admitted ? 1 : 0,
          symbol: admitted
            ? "EXACT_GPU_PROVIDER_ADMITTED_V2"
            : "EXACT_GPU_PROVIDER_NOT_ADMITTED_V2",
        },
        admitted
          ? {
            carrierPath: "record.operation_result.operation.physical_sequence",
            operator: "positive",
          }
          : {
            carrierPath: "record.operation_result.operation.physical_sequence",
            operator: "equal",
            value: "0",
          },
        ...expectedDetachedTail,
      ],
      `native requestDevice detached ${admitted ? "admitted" : "not-admitted"} variant`,
    );
    assertCanonical(
      variant.payloadConstraints,
      [{
        payloadPath: "body.diagnosticMessage",
        operator:
          "native-semantic-service-owned-stable-utf8-within-reviewed-bound",
      }],
      `native requestDevice detached ${admitted ? "admitted" : "not-admitted"} diagnostic`,
    );
  }
  assert(requestDeviceRoute.completion.noTrailingBytes === true,
    "native requestDevice completion must reject trailing bytes");

  const createCommandEncoderRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUDevice.createCommandEncoder",
  );
  const createCommandEncoderOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUDevice.createCommandEncoder",
  );
  assert(
    createCommandEncoderRoute && createCommandEncoderOperation &&
      createCommandEncoderRoute.wireId === createCommandEncoderOperation.wireId,
    "native createCommandEncoder operation identity drifted",
  );
  const createCommandEncoderRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === createCommandEncoderOperation.serviceArgumentCodec,
    );
  const createCommandEncoderCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === createCommandEncoderOperation.serviceCompletionCodec,
    );
  assertCanonical(
    createCommandEncoderRoute,
    {
      operationId: "GPUDevice.createCommandEncoder",
      wireId: createCommandEncoderOperation.wireId,
      request: {
        payloadRole:
          "service-request-payload-decoder-plus-operation-specific-call-joins",
        catalog: {
          name: "serviceArguments",
          tag: "gpu-create-command-encoder-service-request-v1",
          wireTag: createCommandEncoderRequestCatalogIndex + 1,
        },
        payload: {
          kind: "struct",
          fields: [
            {
              name: "header",
              type: "headerV1",
              constants: {
                magic: envelope.codecLayout.requestMagic,
                version: envelope.codecLayout.version,
                codecTag: createCommandEncoderRequestCatalogIndex + 1,
                operationWireId: createCommandEncoderOperation.wireId,
              },
            },
            { name: "receiver", type: "objectReferenceV1" },
            { name: "target", type: "optionalReferenceV1" },
            { name: "capturedScopeId", type: "u64le" },
            { name: "adapterOrdinal", type: "u64le" },
            { name: "deviceIngressOrdinal", type: "u64le" },
            { name: "queueIngressOrdinal", type: "u64le" },
            { name: "sealedLocalTimeline", type: "canonicalValueV1" },
            {
              name: "convertedArguments",
              type: "canonicalValueV1",
              constraintType: "commandEncoderDescriptorV1",
            },
          ],
        },
        carrierJoins: [
          ["header.operationWireId", "operation_id"],
          ["receiver.kind", "receiver.kind"],
          ["receiver.objectId", "receiver.object_id"],
          ["receiver.objectGeneration", "receiver.object_generation"],
          ["receiver.logicalDeviceId", "ingress_device.logical_device_id"],
          ["receiver.logicalDeviceGeneration", "ingress_device.logical_device_generation"],
          ["receiver.providerGeneration", "ingress_device.provider_generation"],
          ["receiver.providerGeneration", "provider_generation"],
          ["target.kind", "target.kind"],
          ["target.objectId", "target.object_id"],
          ["target.objectGeneration", "target.object_generation"],
          ["target.logicalDeviceId", "ingress_device.logical_device_id"],
          ["target.logicalDeviceGeneration", "ingress_device.logical_device_generation"],
          ["target.providerGeneration", "ingress_device.provider_generation"],
          ["target.providerGeneration", "provider_generation"],
          ["capturedScopeId", "captured_scope_id"],
          ["adapterOrdinal", "adapter_ordinal"],
          ["deviceIngressOrdinal", "device_ingress_ordinal"],
          ["queueIngressOrdinal", "queue_ingress_ordinal"],
        ].map(([payloadPath, carrierPath]) => ({
          payloadPath,
          carrierPath,
          operator: "equal",
        })),
        carrierConstraints: [
          {
            carrierPath: "operation_id",
            operator: "equal",
            value: createCommandEncoderOperation.wireId,
          },
          { carrierPath: "flags", operator: "equal", value: 0 },
          {
            carrierPath: "topology_id",
            operator: "equal",
            valueFrom: "constants.providerTopologyId",
          },
          { carrierPath: "ingress_device", operator: "positive" },
          { carrierPath: "provider_generation", operator: "positive" },
          { carrierPath: "operation_instance_id", operator: "positive" },
          { carrierPath: "promise_id", operator: "equal", value: "0" },
          {
            carrierPath: "receiver.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUDevice",
          },
          { carrierPath: "receiver.flags", operator: "equal", value: 0 },
          { carrierPath: "receiver.object_id", operator: "positive" },
          { carrierPath: "receiver.object_generation", operator: "positive" },
          {
            carrierPath: "target.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUCommandEncoder",
          },
          { carrierPath: "target.flags", operator: "equal", value: 0 },
          { carrierPath: "target.object_id", operator: "positive" },
          { carrierPath: "target.object_generation", operator: "positive" },
          { carrierPath: "adapter_ordinal", operator: "equal", value: "0" },
          { carrierPath: "device_ingress_ordinal", operator: "positive" },
          { carrierPath: "queue_ingress_ordinal", operator: "equal", value: "0" },
        ],
        valueConstraints: [
          {
            payloadPath: "sealedLocalTimeline",
            operator: "canonical-sequence-within-layout-bounds",
          },
          {
            payloadPath: "sealedLocalTimeline",
            operator: "untrusted-wrapper-record-prefix-join-only-never-authority",
          },
          {
            payloadPath: "convertedArguments",
            operator: "conforms-to-type",
            type: "commandEncoderDescriptorV1",
          },
        ],
        semanticServiceBoundary: {
          stateAuthority:
            "authenticated-device-object-account-coverage-and-reservation-tables",
          payloadRole: "comparison-input-only-never-authority",
          requiredAfterDecode: [
            "authenticate-contiguous-sealed-local-timeline-prefix",
            "validate-current-live-device-generation",
            "validate-operation-coverage",
            "validate-authorized-live-account",
            "reserve-command-encoder-handle-and-aggregate-envelope",
            "authenticate-wrapper-allocated-command-encoder-target",
            "select-provider-admission-and-physical-sequence",
          ],
          completionEncodingRequires: [
            "authenticated-retained-call",
            "service-owned-operation-result",
          ],
        },
        executablePrerequisites: [],
        noTrailingBytes: true,
      },
      completion: {
        payloadRole:
          "service-completion-payload-codec-plus-operation-specific-event-joins",
        catalog: {
          name: "serviceCompletions",
          tag: "terminal-receipt-service-completion-v1",
          wireTag: createCommandEncoderCompletionCatalogIndex + 1,
        },
        commonCarrierConstraints: [
          {
            carrierPath: "kind",
            operator: "equal",
            value: 1,
            symbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
          },
          { carrierPath: "record.operation_result.status", operator: "equal", value: 0 },
          {
            carrierPath: "record.operation_result.operation.operation_id",
            operator: "equal",
            value: createCommandEncoderOperation.wireId,
          },
          {
            carrierPath: "record.operation_result.operation.device_transition",
            operator: "equal",
            value: 0,
            symbol: "EXACT_GPU_DEVICE_UNCHANGED_V2",
          },
          {
            carrierPath: "record.operation_result.operation.ingress_device",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.result_device",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.provider_generation",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.promise_id",
            operator: "equal",
            value: "0",
          },
          {
            carrierPath: "record.operation_result.operation.receiver.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUDevice",
          },
          {
            carrierPath: "record.operation_result.operation.target.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUCommandEncoder",
          },
          {
            carrierPath: "record.operation_result.operation.adapter_ordinal",
            operator: "equal",
            value: "0",
          },
          {
            carrierPath: "record.operation_result.operation.device_ingress_ordinal",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.queue_ingress_ordinal",
            operator: "equal",
            value: "0",
          },
          {
            carrierPath: "record.operation_result.result_kind",
            operator: "equal",
            value: 0,
            symbol: "EXACT_GPU_RESULT_NONE_V2",
          },
        ],
        payload: { kind: "empty", exactLengthBytes: 0 },
        semanticTerminalMapping: {
          authorityPath:
            "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createCommandEncoder]",
          terminals: [
            {
              terminalId: "webidl-rejection",
              errorTiming: "synchronous-webidl",
              resultDisposition: "throw",
              providerTokenCount: 0,
              physicalSequenceCount: 0,
              event: {
                kind: "no-service-call",
                completionPayloadEncoderEligibility:
                  "excluded-before-service-ingress",
              },
            },
            {
              terminalId: "later-predicate-rejection",
              errorTiming: "device-timeline",
              resultDisposition: "return-invalid-object-and-report-error",
              providerTokenCount: 0,
              physicalSequenceCount: 0,
              event: {
                kind: "device-error",
                kindValue: 2,
                kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
                completionPayloadEncoderEligibility:
                  "excluded-not-an-operation-result",
              },
            },
            {
              terminalId: "operation-success",
              errorTiming: "none",
              resultDisposition: "return-object",
              providerTokenCount: 1,
              physicalSequenceCount: 1,
              event: {
                kind: "operation-result",
                kindValue: 1,
                kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
                resultKind: 0,
                resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
                status: 0,
                completionVariant: "operation-success",
              },
            },
          ],
        },
        variants: [
          {
            name: "operation-success",
            carrierConstraints: [
              {
                carrierPath: "record.operation_result.operation.provider_admission",
                operator: "equal",
                value: 1,
                symbol: "EXACT_GPU_PROVIDER_ADMITTED_V2",
              },
              {
                carrierPath: "record.operation_result.operation.physical_sequence",
                operator: "positive",
              },
            ],
          },
        ],
        noTrailingBytes: true,
      },
    },
    "native createCommandEncoder codec route",
  );

  const createShaderModuleRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUDevice.createShaderModule",
  );
  const createShaderModuleOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUDevice.createShaderModule",
  );
  assert(
    createShaderModuleRoute && createShaderModuleOperation &&
      createShaderModuleRoute.wireId === createShaderModuleOperation.wireId,
    "native createShaderModule operation identity drifted",
  );
  const createShaderModuleRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === createShaderModuleOperation.serviceArgumentCodec,
    );
  const createShaderModuleCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === createShaderModuleOperation.serviceCompletionCodec,
    );
  assertCanonical(
    createShaderModuleRoute,
    {
      operationId: "GPUDevice.createShaderModule",
      wireId: createShaderModuleOperation.wireId,
      request: {
        payloadRole:
          "service-request-payload-decoder-plus-operation-specific-call-joins",
        catalog: {
          name: "serviceArguments",
          tag: "gpu-create-shader-module-service-request-v1",
          wireTag: createShaderModuleRequestCatalogIndex + 1,
        },
        payload: {
          kind: "struct",
          fields: [
            {
              name: "header",
              type: "headerV1",
              constants: {
                magic: envelope.codecLayout.requestMagic,
                version: envelope.codecLayout.version,
                codecTag: createShaderModuleRequestCatalogIndex + 1,
                operationWireId: createShaderModuleOperation.wireId,
              },
            },
            { name: "receiver", type: "objectReferenceV1" },
            { name: "target", type: "optionalReferenceV1" },
            { name: "capturedScopeId", type: "u64le" },
            { name: "adapterOrdinal", type: "u64le" },
            { name: "deviceIngressOrdinal", type: "u64le" },
            { name: "queueIngressOrdinal", type: "u64le" },
            { name: "sealedLocalTimeline", type: "canonicalValueV1" },
            {
              name: "convertedArguments",
              type: "canonicalValueV1",
              constraintType: "shaderModuleDescriptorV1",
            },
          ],
        },
        carrierJoins: [
          ["header.operationWireId", "operation_id"],
          ["receiver.kind", "receiver.kind"],
          ["receiver.objectId", "receiver.object_id"],
          ["receiver.objectGeneration", "receiver.object_generation"],
          ["receiver.logicalDeviceId", "ingress_device.logical_device_id"],
          ["receiver.logicalDeviceGeneration", "ingress_device.logical_device_generation"],
          ["receiver.providerGeneration", "ingress_device.provider_generation"],
          ["receiver.providerGeneration", "provider_generation"],
          ["target.kind", "target.kind"],
          ["target.objectId", "target.object_id"],
          ["target.objectGeneration", "target.object_generation"],
          ["target.logicalDeviceId", "ingress_device.logical_device_id"],
          ["target.logicalDeviceGeneration", "ingress_device.logical_device_generation"],
          ["target.providerGeneration", "ingress_device.provider_generation"],
          ["target.providerGeneration", "provider_generation"],
          ["capturedScopeId", "captured_scope_id"],
          ["adapterOrdinal", "adapter_ordinal"],
          ["deviceIngressOrdinal", "device_ingress_ordinal"],
          ["queueIngressOrdinal", "queue_ingress_ordinal"],
        ].map(([payloadPath, carrierPath]) => ({
          payloadPath,
          carrierPath,
          operator: "equal",
        })),
        carrierConstraints: [
          {
            carrierPath: "operation_id",
            operator: "equal",
            value: createShaderModuleOperation.wireId,
          },
          { carrierPath: "flags", operator: "equal", value: 0 },
          {
            carrierPath: "topology_id",
            operator: "equal",
            valueFrom: "constants.providerTopologyId",
          },
          { carrierPath: "ingress_device", operator: "positive" },
          { carrierPath: "provider_generation", operator: "positive" },
          { carrierPath: "operation_instance_id", operator: "positive" },
          { carrierPath: "promise_id", operator: "equal", value: "0" },
          {
            carrierPath: "receiver.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUDevice",
          },
          { carrierPath: "receiver.flags", operator: "equal", value: 0 },
          { carrierPath: "receiver.object_id", operator: "positive" },
          { carrierPath: "receiver.object_generation", operator: "positive" },
          {
            carrierPath: "target.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUShaderModule",
          },
          { carrierPath: "target.flags", operator: "equal", value: 0 },
          { carrierPath: "target.object_id", operator: "positive" },
          { carrierPath: "target.object_generation", operator: "positive" },
          { carrierPath: "adapter_ordinal", operator: "equal", value: "0" },
          { carrierPath: "device_ingress_ordinal", operator: "positive" },
          { carrierPath: "queue_ingress_ordinal", operator: "equal", value: "0" },
        ],
        valueConstraints: [
          {
            payloadPath: "sealedLocalTimeline",
            operator: "canonical-sequence-within-layout-bounds",
          },
          {
            payloadPath: "sealedLocalTimeline",
            operator: "untrusted-wrapper-record-prefix-join-only-never-authority",
          },
          {
            payloadPath: "convertedArguments",
            operator: "conforms-to-type",
            type: "shaderModuleDescriptorV1",
          },
        ],
        semanticServiceBoundary: {
          stateAuthority:
            "authenticated-device-object-account-coverage-and-reservation-tables",
          payloadRole: "comparison-input-only-never-authority",
          requiredAfterDecode: [
            "authenticate-contiguous-sealed-local-timeline-prefix",
            "validate-current-live-device-generation",
            "validate-operation-coverage",
            "validate-authorized-live-account",
            "validate-wgsl-with-naga-under-logical-capabilities",
            "reserve-shader-module-handle-and-aggregate-envelope",
            "authenticate-wrapper-allocated-shader-module-target",
            "select-provider-admission-and-physical-sequence",
          ],
          completionEncodingRequires: [
            "authenticated-retained-call",
            "service-owned-operation-result",
          ],
        },
        executablePrerequisites: [],
        noTrailingBytes: true,
      },
      completion: {
        payloadRole:
          "service-completion-payload-codec-plus-operation-specific-event-joins",
        catalog: {
          name: "serviceCompletions",
          tag: "terminal-receipt-service-completion-v1",
          wireTag: createShaderModuleCompletionCatalogIndex + 1,
        },
        commonCarrierConstraints: [
          {
            carrierPath: "kind",
            operator: "equal",
            value: 1,
            symbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
          },
          { carrierPath: "record.operation_result.status", operator: "equal", value: 0 },
          {
            carrierPath: "record.operation_result.operation.operation_id",
            operator: "equal",
            value: createShaderModuleOperation.wireId,
          },
          {
            carrierPath: "record.operation_result.operation.device_transition",
            operator: "equal",
            value: 0,
            symbol: "EXACT_GPU_DEVICE_UNCHANGED_V2",
          },
          {
            carrierPath: "record.operation_result.operation.ingress_device",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.result_device",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.provider_generation",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.promise_id",
            operator: "equal",
            value: "0",
          },
          {
            carrierPath: "record.operation_result.operation.receiver.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUDevice",
          },
          {
            carrierPath: "record.operation_result.operation.target.kind",
            operator: "equal",
            valueFrom: "objectKindTags.GPUShaderModule",
          },
          {
            carrierPath: "record.operation_result.operation.adapter_ordinal",
            operator: "equal",
            value: "0",
          },
          {
            carrierPath: "record.operation_result.operation.device_ingress_ordinal",
            operator: "positive",
          },
          {
            carrierPath: "record.operation_result.operation.queue_ingress_ordinal",
            operator: "equal",
            value: "0",
          },
          {
            carrierPath: "record.operation_result.result_kind",
            operator: "equal",
            value: 0,
            symbol: "EXACT_GPU_RESULT_NONE_V2",
          },
        ],
        payload: { kind: "empty", exactLengthBytes: 0 },
        semanticTerminalMapping: {
          authorityPath:
            "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createShaderModule]",
          terminals: [
            {
              terminalId: "webidl-rejection",
              errorTiming: "synchronous-webidl",
              resultDisposition: "throw",
              providerTokenCount: 0,
              physicalSequenceCount: 0,
              event: {
                kind: "no-service-call",
                completionPayloadEncoderEligibility:
                  "excluded-before-service-ingress",
              },
            },
            {
              terminalId: "later-predicate-rejection",
              errorTiming: "device-timeline",
              resultDisposition: "return-invalid-object-and-report-error",
              providerTokenCount: 0,
              physicalSequenceCount: 0,
              event: {
                kind: "device-error",
                kindValue: 2,
                kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
                completionPayloadEncoderEligibility:
                  "excluded-not-an-operation-result",
              },
            },
            {
              terminalId: "operation-success",
              errorTiming: "none",
              resultDisposition: "return-object",
              providerTokenCount: 1,
              physicalSequenceCount: 1,
              event: {
                kind: "operation-result",
                kindValue: 1,
                kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
                resultKind: 0,
                resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
                status: 0,
                completionVariant: "operation-success",
              },
            },
          ],
        },
        variants: [
          {
            name: "operation-success",
            carrierConstraints: [
              {
                carrierPath: "record.operation_result.operation.provider_admission",
                operator: "equal",
                value: 1,
                symbol: "EXACT_GPU_PROVIDER_ADMITTED_V2",
              },
              {
                carrierPath: "record.operation_result.operation.physical_sequence",
                operator: "positive",
              },
            ],
          },
        ],
        noTrailingBytes: true,
      },
    },
    "native createShaderModule codec route",
  );

  const createBindGroupLayoutRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUDevice.createBindGroupLayout",
  );
  const createBindGroupLayoutOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUDevice.createBindGroupLayout",
  );
  assert(
    createBindGroupLayoutRoute && createBindGroupLayoutOperation &&
      createBindGroupLayoutRoute.wireId === createBindGroupLayoutOperation.wireId,
    "native createBindGroupLayout operation identity drifted",
  );
  const createBindGroupLayoutRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === createBindGroupLayoutOperation.serviceArgumentCodec,
    );
  const createBindGroupLayoutCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === createBindGroupLayoutOperation.serviceCompletionCodec,
    );
  const expectedCreateBindGroupLayoutRoute =
    buildExpectedCreateBindGroupLayoutNativeRoute({
      templateRoute: createShaderModuleRoute,
      operation: createBindGroupLayoutOperation,
      requestCatalogIndex: createBindGroupLayoutRequestCatalogIndex,
      completionCatalogIndex: createBindGroupLayoutCompletionCatalogIndex,
    });
  assertCanonical(
    createBindGroupLayoutRoute,
    expectedCreateBindGroupLayoutRoute,
    "native createBindGroupLayout codec route",
  );

  const createBufferRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUDevice.createBuffer",
  );
  const createBufferOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUDevice.createBuffer",
  );
  assert(
    createBufferRoute && createBufferOperation &&
      createBufferRoute.wireId === createBufferOperation.wireId,
    "native createBuffer operation identity drifted",
  );
  const createBufferRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === createBufferOperation.serviceArgumentCodec,
    );
  const createBufferCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === createBufferOperation.serviceCompletionCodec,
    );
  assertCanonical(
    createBufferRoute,
    buildExpectedCreateBufferNativeRoute({
      templateRoute: expectedCreateBindGroupLayoutRoute,
      operation: createBufferOperation,
      requestCatalogIndex: createBufferRequestCatalogIndex,
      completionCatalogIndex: createBufferCompletionCatalogIndex,
    }),
    "native createBuffer codec route",
  );

  const createPipelineLayoutRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUDevice.createPipelineLayout",
  );
  const createPipelineLayoutOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUDevice.createPipelineLayout",
  );
  assert(
    createPipelineLayoutRoute && createPipelineLayoutOperation &&
      createPipelineLayoutRoute.wireId === createPipelineLayoutOperation.wireId,
    "native createPipelineLayout operation identity drifted",
  );
  const createPipelineLayoutRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === createPipelineLayoutOperation.serviceArgumentCodec,
    );
  const createPipelineLayoutCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === createPipelineLayoutOperation.serviceCompletionCodec,
    );
  assertCanonical(
    createPipelineLayoutRoute,
    buildExpectedCreatePipelineLayoutNativeRoute({
      templateRoute: expectedCreateBindGroupLayoutRoute,
      operation: createPipelineLayoutOperation,
      requestCatalogIndex: createPipelineLayoutRequestCatalogIndex,
      completionCatalogIndex: createPipelineLayoutCompletionCatalogIndex,
    }),
    "native createPipelineLayout codec route",
  );

  for (const resource of [
    {
      operationId: "GPUDevice.createBindGroup",
      descriptorType: "bindGroupDescriptorV1",
      targetKind: "GPUBindGroup",
      semanticSteps: [
        "authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table",
        "authenticate-contiguous-sealed-local-timeline-prefix",
        "validate-current-live-device-generation",
        "validate-operation-coverage",
        "validate-authorized-live-account-and-aggregate-envelope",
        "validate-exact-generated-typegpu-bind-group-full-provenance-witness",
        "authenticate-current-same-device-bind-group-layout-full-reference-and-joined-descriptor",
        "validate-bind-group-entry-layout-cardinality-and-exact-binding-join",
        "authenticate-current-same-device-resource-full-references-and-creator-order",
        "validate-buffer-sampler-texture-view-and-external-resource-compatibility",
        "authenticate-wrapper-allocated-bind-group-target-provenance",
        "validate-wrapper-allocated-bind-group-target-generation",
        "reserve-bind-group-table-and-dual-ledger-capacity",
        "commit-bind-group-layout-and-resource-dependency-retention-before-provider-admission",
        "arm-exactly-once-terminal-unwind-for-bind-group-dependency-retention",
        "reserve-bind-group-provider-request-completion-and-physical-sequence",
        "validate-bind-group-label-under-reviewed-workload",
      ],
    },
    {
      operationId: "GPUDevice.createSampler",
      descriptorType: "samplerDescriptorV1",
      targetKind: "GPUSampler",
      semanticSteps: [
        "authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table",
        "authenticate-contiguous-sealed-local-timeline-prefix",
        "validate-current-live-device-generation",
        "validate-operation-coverage",
        "validate-authorized-live-account-and-aggregate-envelope",
        "validate-sampler-lod-order-and-range",
        "validate-sampler-anisotropy-and-filter-combination",
        "validate-sampler-label-under-reviewed-workload",
        "validate-sampler-descriptor-under-reviewed-workload",
        "authenticate-wrapper-allocated-sampler-target-provenance",
        "validate-wrapper-allocated-sampler-target-generation",
        "reserve-sampler-table-and-resource-ledger-capacity",
        "reserve-sampler-provider-request-completion-and-physical-sequence",
      ],
    },
    {
      operationId: "GPUDevice.createTexture",
      descriptorType: "textureDescriptorV1",
      targetKind: "GPUTexture",
      contentRejection: true,
      semanticSteps: [
        "authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table",
        "authenticate-contiguous-sealed-local-timeline-prefix",
        "validate-current-live-device-generation",
        "validate-operation-coverage",
        "validate-authorized-live-account-and-aggregate-envelope",
        "validate-texture-extent-under-logical-limits-and-structural-bounds",
        "validate-texture-format-under-logical-capabilities",
        "validate-texture-usage-closed-bits-and-format-compatibility",
        "validate-texture-mip-level-and-sample-count-bounds",
        "validate-texture-view-formats-compatibility",
        "validate-texture-binding-view-dimension-compatibility",
        "validate-texture-label-under-reviewed-workload",
        "validate-texture-descriptor-under-reviewed-workload",
        "authenticate-wrapper-allocated-texture-target-provenance",
        "validate-wrapper-allocated-texture-target-generation",
        "compute-checked-texture-resource-bytes-and-reserve-dual-ledger-capacity",
        "reserve-texture-provider-request-completion-and-physical-sequence",
      ],
    },
    {
      operationId: "GPUTexture.createView",
      descriptorType: "textureViewRequestV1",
      receiverKind: "GPUTexture",
      targetKind: "GPUTextureView",
      semanticSteps: [
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
      ],
    },
  ]) {
    const resourceRoute = program.routes.find(
      (candidate) => candidate.operationId === resource.operationId,
    );
    const resourceOperation = payload.operations.find(
      (candidate) => candidate.operationId === resource.operationId,
    );
    assert(
      resourceRoute && resourceOperation &&
        resourceRoute.wireId === resourceOperation.wireId,
      `native ${resource.operationId} operation identity drifted`,
    );
    const resourceRequestCatalogIndex =
      payload.codecCatalog.serviceArguments.findIndex(
        (codec) => codec.tag === resourceOperation.serviceArgumentCodec,
      );
    const resourceCompletionCatalogIndex =
      payload.codecCatalog.serviceCompletions.findIndex(
        (codec) => codec.tag === resourceOperation.serviceCompletionCodec,
      );
    assertCanonical(
      resourceRoute,
      buildExpectedResourceNativeRoute({
        templateRoute: expectedCreateBindGroupLayoutRoute,
        operation: resourceOperation,
        requestCatalogIndex: resourceRequestCatalogIndex,
        completionCatalogIndex: resourceCompletionCatalogIndex,
        descriptorType: resource.descriptorType,
        receiverKind: resource.receiverKind,
        targetKind: resource.targetKind,
        semanticSteps: resource.semanticSteps,
        contentRejection: resource.contentRejection,
      }),
      `native ${resource.operationId} codec route`,
    );
  }

  const deviceDestroyRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUDevice.destroy",
  );
  const deviceDestroyOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUDevice.destroy",
  );
  assert(
    deviceDestroyRoute && deviceDestroyOperation &&
      deviceDestroyRoute.wireId === deviceDestroyOperation.wireId,
    "native device destroy operation identity drifted",
  );
  const deviceDestroyRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === deviceDestroyOperation.serviceArgumentCodec,
    );
  const deviceDestroyCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === deviceDestroyOperation.serviceCompletionCodec,
    );
  assertCanonical(
    deviceDestroyRoute.request.catalog,
    {
      name: "serviceArguments",
      tag: "gpu-device-cleanup-service-request-v1",
      wireTag: deviceDestroyRequestCatalogIndex + 1,
    },
    "native device destroy request catalog selection",
  );
  assertCanonical(
    deviceDestroyRoute.request.payload,
    {
      kind: "struct",
      fields: [
        {
          name: "header",
          type: "headerV1",
          constants: {
            magic: envelope.codecLayout.requestMagic,
            version: envelope.codecLayout.version,
            codecTag: deviceDestroyRequestCatalogIndex + 1,
            operationWireId: deviceDestroyOperation.wireId,
          },
        },
        { name: "receiver", type: "objectReferenceV1" },
        { name: "target", type: "optionalReferenceV1" },
        { name: "capturedScopeId", type: "u64le" },
        { name: "adapterOrdinal", type: "u64le" },
        { name: "deviceIngressOrdinal", type: "u64le" },
        { name: "queueIngressOrdinal", type: "u64le" },
        { name: "sealedLocalTimeline", type: "canonicalValueV1" },
        { name: "convertedArguments", type: "canonicalValueV1" },
      ],
    },
    "native device destroy request layout",
  );
  assertCanonical(
    deviceDestroyRoute.request.carrierJoins,
    [
      ["header.operationWireId", "operation_id", "equal"],
      ["receiver.kind", "receiver.kind", "equal"],
      ["receiver.objectId", "receiver.object_id", "equal"],
      ["receiver.objectGeneration", "receiver.object_generation", "equal"],
      ["receiver.logicalDeviceId", "ingress_device.logical_device_id", "equal"],
      ["receiver.logicalDeviceGeneration", "ingress_device.logical_device_generation", "equal"],
      ["receiver.providerGeneration", "ingress_device.provider_generation", "equal"],
      ["receiver.providerGeneration", "provider_generation", "equal"],
      ["target", "target", "absent-iff-all-zero-reference"],
      ["capturedScopeId", "captured_scope_id", "equal"],
      ["adapterOrdinal", "adapter_ordinal", "equal"],
      ["deviceIngressOrdinal", "device_ingress_ordinal", "equal"],
      ["queueIngressOrdinal", "queue_ingress_ordinal", "equal"],
    ].map(([payloadPath, carrierPath, operator]) => ({
      payloadPath, carrierPath, operator,
    })),
    "native device destroy carrier joins",
  );
  assertCanonical(
    deviceDestroyRoute.request.carrierConstraints,
    [
      {
        carrierPath: "operation_id",
        operator: "equal",
        value: deviceDestroyOperation.wireId,
      },
      { carrierPath: "flags", operator: "equal", value: 0 },
      {
        carrierPath: "topology_id",
        operator: "equal",
        valueFrom: "constants.providerTopologyId",
      },
      { carrierPath: "ingress_device", operator: "positive" },
      { carrierPath: "provider_generation", operator: "positive" },
      { carrierPath: "operation_instance_id", operator: "positive" },
      { carrierPath: "promise_id", operator: "equal", value: "0" },
      {
        carrierPath: "receiver.kind",
        operator: "equal",
        valueFrom: "objectKindTags.GPUDevice",
      },
      { carrierPath: "receiver.flags", operator: "equal", value: 0 },
      { carrierPath: "receiver.object_id", operator: "positive" },
      { carrierPath: "receiver.object_generation", operator: "positive" },
      { carrierPath: "target", operator: "all-zero" },
      { carrierPath: "adapter_ordinal", operator: "equal", value: "0" },
      { carrierPath: "device_ingress_ordinal", operator: "positive" },
      { carrierPath: "queue_ingress_ordinal", operator: "equal", value: "0" },
    ],
    "native device destroy carrier constraints",
  );
  assertCanonical(
    deviceDestroyRoute.request.valueConstraints,
    [
      {
        payloadPath: "sealedLocalTimeline",
        operator: "canonical-sequence-within-layout-bounds",
      },
      {
        payloadPath: "sealedLocalTimeline",
        operator: "untrusted-wrapper-record-prefix-join-only-never-authority",
      },
      {
        payloadPath: "convertedArguments",
        operator: "exact-null",
      },
    ],
    "native device destroy value constraints",
  );
  assertCanonical(
    deviceDestroyRoute.request.semanticServiceBoundary,
    {
      stateAuthority:
        "authenticated-device-lifecycle-operation-and-provider-tables",
      payloadRole: "comparison-input-only-never-authority",
      requiredAfterDecode: [
        "authenticate-contiguous-sealed-local-timeline-prefix",
        "validate-idempotent-device-terminal-state",
        "validate-cleanup-predicates",
        "select-provider-admission-and-physical-sequence",
      ],
      completionEncodingRequires: [
        "authenticated-retained-call",
        "service-owned-operation-result",
      ],
    },
    "native device destroy semantic-service boundary",
  );
  assertCanonical(
    deviceDestroyRoute.request.executablePrerequisites,
    [],
    "native device destroy executable prerequisites",
  );
  assert(deviceDestroyRoute.request.noTrailingBytes === true,
    "native device destroy request must reject trailing bytes");

  assertCanonical(
    deviceDestroyRoute.completion.catalog,
    {
      name: "serviceCompletions",
      tag: "terminal-receipt-service-completion-v1",
      wireTag: deviceDestroyCompletionCatalogIndex + 1,
    },
    "native device destroy completion catalog selection",
  );
  assertCanonical(
    deviceDestroyRoute.completion.commonCarrierConstraints,
    [
      {
        carrierPath: "kind",
        operator: "equal",
        value: 1,
        symbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
      },
      { carrierPath: "record.operation_result.status", operator: "equal", value: 0 },
      {
        carrierPath: "record.operation_result.operation.operation_id",
        operator: "equal",
        value: deviceDestroyOperation.wireId,
      },
      {
        carrierPath: "record.operation_result.operation.device_transition",
        operator: "equal",
        value: 0,
        symbol: "EXACT_GPU_DEVICE_UNCHANGED_V2",
      },
      {
        carrierPath: "record.operation_result.operation.ingress_device",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.result_device",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.provider_generation",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.promise_id",
        operator: "equal",
        value: "0",
      },
      {
        carrierPath: "record.operation_result.operation.receiver.kind",
        operator: "equal",
        valueFrom: "objectKindTags.GPUDevice",
      },
      {
        carrierPath: "record.operation_result.operation.target",
        operator: "all-zero",
      },
      {
        carrierPath: "record.operation_result.operation.adapter_ordinal",
        operator: "equal",
        value: "0",
      },
      {
        carrierPath: "record.operation_result.operation.device_ingress_ordinal",
        operator: "positive",
      },
      {
        carrierPath: "record.operation_result.operation.queue_ingress_ordinal",
        operator: "equal",
        value: "0",
      },
      {
        carrierPath: "record.operation_result.result_kind",
        operator: "equal",
        value: 0,
        symbol: "EXACT_GPU_RESULT_NONE_V2",
      },
    ],
    "native device destroy completion carrier constraints",
  );
  assertCanonical(
    deviceDestroyRoute.completion.payload,
    { kind: "empty", exactLengthBytes: 0 },
    "native device destroy completion payload",
  );
  assertCanonical(
    deviceDestroyRoute.completion.semanticTerminalMapping,
    {
      authorityPath:
        "semanticProjection.providerRoutingPrograms[operationId=GPUDevice.destroy]",
      terminals: [
        {
          terminalId: "repeat-cleanup-noop",
          errorTiming: "none",
          resultDisposition: "return-undefined",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "operation-result",
            kindValue: 1,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
            resultKind: 0,
            resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
            status: 0,
            completionVariant: "repeat-cleanup-noop",
          },
        },
        {
          terminalId: "first-cleanup-rejection",
          errorTiming: "device-timeline",
          resultDisposition: "return-undefined-and-report-error",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "device-error",
            kindValue: 2,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2",
            completionPayloadEncoderEligibility:
              "excluded-not-an-operation-result",
          },
        },
        {
          terminalId: "first-cleanup-provider",
          errorTiming: "none",
          resultDisposition: "return-undefined",
          providerTokenCount: 1,
          physicalSequenceCount: 1,
          event: {
            kind: "operation-result",
            kindValue: 1,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
            resultKind: 0,
            resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
            status: 0,
            completionVariant: "first-cleanup-provider",
          },
        },
      ],
    },
    "native device destroy semantic terminal mapping",
  );
  assertCanonical(
    deviceDestroyRoute.completion.variants,
    [
      {
        name: "repeat-cleanup-noop",
        carrierConstraints: [
          {
            carrierPath: "record.operation_result.operation.provider_admission",
            operator: "equal",
            value: 0,
            symbol: "EXACT_GPU_PROVIDER_NOT_ADMITTED_V2",
          },
          {
            carrierPath: "record.operation_result.operation.physical_sequence",
            operator: "equal",
            value: "0",
          },
        ],
      },
      {
        name: "first-cleanup-provider",
        carrierConstraints: [
          {
            carrierPath: "record.operation_result.operation.provider_admission",
            operator: "equal",
            value: 1,
            symbol: "EXACT_GPU_PROVIDER_ADMITTED_V2",
          },
          {
            carrierPath: "record.operation_result.operation.physical_sequence",
            operator: "positive",
          },
        ],
      },
    ],
    "native device destroy completion variants",
  );
  assert(deviceDestroyRoute.completion.noTrailingBytes === true,
    "native device destroy completion must reject trailing bytes");

  const queueWriteBufferRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUQueue.writeBuffer",
  );
  const queueWriteBufferOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUQueue.writeBuffer",
  );
  assert(
    queueWriteBufferRoute && queueWriteBufferOperation &&
      queueWriteBufferRoute.wireId === queueWriteBufferOperation.wireId,
    "native queue writeBuffer operation identity drifted",
  );
  const queueWriteBufferRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === queueWriteBufferOperation.serviceArgumentCodec,
    );
  const queueWriteBufferCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === queueWriteBufferOperation.serviceCompletionCodec,
    );
  assertCanonical(
    queueWriteBufferRoute.request.catalog,
    {
      name: "serviceArguments",
      tag: "gpu-queue-write-buffer-service-request-v1",
      wireTag: queueWriteBufferRequestCatalogIndex + 1,
    },
    "native queue writeBuffer request catalog selection",
  );
  assertCanonical(
    queueWriteBufferRoute.request.payload,
    {
      kind: "struct",
      fields: [
        {
          name: "header",
          type: "headerV1",
          constants: {
            magic: envelope.codecLayout.requestMagic,
            version: envelope.codecLayout.version,
            codecTag: queueWriteBufferRequestCatalogIndex + 1,
            operationWireId: queueWriteBufferOperation.wireId,
          },
        },
        { name: "receiver", type: "objectReferenceV1" },
        { name: "target", type: "optionalReferenceV1" },
        { name: "capturedScopeId", type: "u64le" },
        { name: "adapterOrdinal", type: "u64le" },
        { name: "deviceIngressOrdinal", type: "u64le" },
        { name: "queueIngressOrdinal", type: "u64le" },
        { name: "body", type: "queueWriteBufferRequestBodyV1" },
      ],
    },
    "native queue writeBuffer request layout",
  );
  assertCanonical(
    queueWriteBufferRoute.request.carrierJoins,
    [
      ["header.operationWireId", "operation_id", "equal"],
      ["receiver.kind", "receiver.kind", "equal"],
      ["receiver.objectId", "receiver.object_id", "equal"],
      ["receiver.objectGeneration", "receiver.object_generation", "equal"],
      ["receiver.logicalDeviceId", "ingress_device.logical_device_id", "equal"],
      ["receiver.logicalDeviceGeneration", "ingress_device.logical_device_generation", "equal"],
      ["receiver.providerGeneration", "ingress_device.provider_generation", "equal"],
      ["receiver.providerGeneration", "provider_generation", "equal"],
      ["target", "target", "absent-iff-all-zero-reference"],
      ["capturedScopeId", "captured_scope_id", "equal"],
      ["adapterOrdinal", "adapter_ordinal", "equal"],
      ["deviceIngressOrdinal", "device_ingress_ordinal", "equal"],
      ["queueIngressOrdinal", "queue_ingress_ordinal", "equal"],
    ].map(([payloadPath, carrierPath, operator]) => ({
      payloadPath, carrierPath, operator,
    })),
    "native queue writeBuffer carrier joins",
  );
  assertCanonical(
    queueWriteBufferRoute.request.carrierConstraints,
    [
      { carrierPath: "operation_id", operator: "equal", value: queueWriteBufferOperation.wireId },
      { carrierPath: "flags", operator: "equal", value: 0 },
      { carrierPath: "topology_id", operator: "equal", valueFrom: "constants.providerTopologyId" },
      { carrierPath: "ingress_device", operator: "positive" },
      { carrierPath: "provider_generation", operator: "positive" },
      { carrierPath: "operation_instance_id", operator: "positive" },
      { carrierPath: "promise_id", operator: "equal", value: "0" },
      { carrierPath: "receiver.kind", operator: "equal", valueFrom: "objectKindTags.GPUQueue" },
      { carrierPath: "receiver.flags", operator: "equal", value: 0 },
      { carrierPath: "receiver.object_id", operator: "positive" },
      { carrierPath: "receiver.object_generation", operator: "positive" },
      { carrierPath: "target", operator: "all-zero" },
      { carrierPath: "adapter_ordinal", operator: "equal", value: "0" },
      { carrierPath: "device_ingress_ordinal", operator: "positive" },
      { carrierPath: "queue_ingress_ordinal", operator: "positive" },
    ],
    "native queue writeBuffer carrier constraints",
  );
  assertCanonical(
    queueWriteBufferRoute.request.valueConstraints,
    [
      { payloadPath: "body", operator: "conforms-to-type", type: "queueWriteBufferRequestBodyV1" },
      {
        payloadPath: "body.destination",
        operator: "exact-GPUBuffer-full-reference-same-logical-device-and-provider-as-receiver",
      },
      {
        payloadPath: "body.destinationOffset",
        operator: "WebIDL-safe-u64-comparison-input-without-normalization",
      },
      {
        payloadPath: "body.bytes",
        operator: "complete-four-byte-aligned-affine-owned-source-snapshot-within-exact-payload-bound",
      },
    ],
    "native queue writeBuffer value constraints",
  );
  assertCanonical(
    queueWriteBufferRoute.request.semanticServiceBoundary,
    {
      stateAuthority:
        "authenticated-queue-buffer-object-account-ledger-and-provider-tables",
      payloadRole:
        "source-affine-destination-and-owned-byte-snapshot-comparison-input-only-never-authority",
      requiredAfterDecode: [
        "authenticate-source-affine-queue-receiver-and-reconstruct-device-account-and-authority",
        "validate-current-live-queue-device-and-provider-generations",
        "validate-operation-coverage",
        "authenticate-current-same-device-destination-buffer-full-reference-and-creation-key",
        "validate-destination-buffer-live-unmapped-copy-dst-offset-and-checked-range",
        "validate-queue-fixed-live-account-and-aggregate-envelope",
        "reserve-the-complete-owned-snapshot-in-both-ledgers-before-chunking",
        "reserve-provider-request-terminal-completion-and-realm-physical-sequence",
      ],
      completionEncodingRequires: [
        "authenticated-retained-call",
        "service-owned-queue-write-terminal",
      ],
    },
    "native queue writeBuffer semantic-service boundary",
  );
  assertCanonical(
    queueWriteBufferRoute.request.executablePrerequisites,
    [],
    "native queue writeBuffer executable prerequisites",
  );
  assert(queueWriteBufferRoute.request.noTrailingBytes === true,
    "native queue writeBuffer request must reject trailing bytes");
  assertCanonical(
    queueWriteBufferRoute.completion.catalog,
    {
      name: "serviceCompletions",
      tag: "terminal-receipt-service-completion-v1",
      wireTag: queueWriteBufferCompletionCatalogIndex + 1,
    },
    "native queue writeBuffer completion catalog selection",
  );
  assertCanonical(
    queueWriteBufferRoute.completion.commonCarrierConstraints,
    [
      { carrierPath: "kind", operator: "equal", value: 1, symbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2" },
      { carrierPath: "record.operation_result.status", operator: "equal", value: 0 },
      { carrierPath: "record.operation_result.operation.operation_id", operator: "equal", value: queueWriteBufferOperation.wireId },
      { carrierPath: "record.operation_result.operation.device_transition", operator: "equal", value: 0, symbol: "EXACT_GPU_DEVICE_UNCHANGED_V2" },
      { carrierPath: "record.operation_result.operation.ingress_device", operator: "positive" },
      { carrierPath: "record.operation_result.operation.result_device", operator: "positive" },
      { carrierPath: "record.operation_result.operation.provider_generation", operator: "positive" },
      { carrierPath: "record.operation_result.operation.promise_id", operator: "equal", value: "0" },
      { carrierPath: "record.operation_result.operation.receiver.kind", operator: "equal", valueFrom: "objectKindTags.GPUQueue" },
      { carrierPath: "record.operation_result.operation.target", operator: "all-zero" },
      { carrierPath: "record.operation_result.operation.adapter_ordinal", operator: "equal", value: "0" },
      { carrierPath: "record.operation_result.operation.device_ingress_ordinal", operator: "positive" },
      { carrierPath: "record.operation_result.operation.queue_ingress_ordinal", operator: "positive" },
      { carrierPath: "record.operation_result.result_kind", operator: "equal", value: 0, symbol: "EXACT_GPU_RESULT_NONE_V2" },
    ],
    "native queue writeBuffer completion carrier constraints",
  );
  assertCanonical(
    queueWriteBufferRoute.completion.payload,
    { kind: "empty", exactLengthBytes: 0 },
    "native queue writeBuffer completion payload",
  );
  assertCanonical(
    queueWriteBufferRoute.completion.semanticTerminalMapping,
    {
      authorityPath:
        "semanticProjection.providerRoutingPrograms[operationId=GPUQueue.writeBuffer]",
      terminals: [
        {
          terminalId: "webidl-rejection",
          errorTiming: "synchronous-webidl",
          resultDisposition: "throw",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "no-service-call",
            completionPayloadEncoderEligibility: "excluded-before-service-ingress",
          },
        },
        {
          terminalId: "source-range-rejection",
          errorTiming: "synchronous-operation-state",
          resultDisposition: "throw",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "no-service-call",
            completionPayloadEncoderEligibility:
              "excluded-before-owned-snapshot-service-ingress",
          },
        },
        {
          terminalId: "later-predicate-rejection",
          errorTiming: "device-timeline",
          resultDisposition: "return-undefined-and-report-error",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "operation-result",
            kindValue: 1,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
            resultKind: 0,
            resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
            status: 0,
            completionVariant: "later-predicate-rejection",
            publicExposure:
              "none-wrapper-already-returned-device-error-delivered-separately",
          },
        },
        {
          terminalId: "operation-success",
          errorTiming: "none",
          resultDisposition: "return-undefined",
          providerTokenCount: 1,
          physicalSequenceCount: 1,
          event: {
            kind: "operation-result",
            kindValue: 1,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
            resultKind: 0,
            resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
            status: 0,
            completionVariant: "operation-success",
            publicExposure: "none-wrapper-already-returned",
          },
        },
      ],
    },
    "native queue writeBuffer semantic terminal mapping",
  );
  assertCanonical(
    queueWriteBufferRoute.completion.variants,
    [
      {
        name: "later-predicate-rejection",
        carrierConstraints: [
          { carrierPath: "record.operation_result.operation.provider_admission", operator: "equal", value: 0, symbol: "EXACT_GPU_PROVIDER_NOT_ADMITTED_V2" },
          { carrierPath: "record.operation_result.operation.physical_sequence", operator: "equal", value: "0" },
        ],
        serviceResultConstraints: [
          { serviceResultPath: "queueWriteTerminal", operator: "equal", value: "later-predicate-rejection" },
        ],
      },
      {
        name: "operation-success",
        carrierConstraints: [
          { carrierPath: "record.operation_result.operation.provider_admission", operator: "equal", value: 1, symbol: "EXACT_GPU_PROVIDER_ADMITTED_V2" },
          { carrierPath: "record.operation_result.operation.physical_sequence", operator: "positive" },
        ],
        serviceResultConstraints: [
          { serviceResultPath: "queueWriteTerminal", operator: "equal", value: "operation-success" },
        ],
      },
    ],
    "native queue writeBuffer completion variants",
  );
  assertCanonical(
    queueWriteBufferRoute.completion.serviceResultJoins,
    [{
      payloadPath: "empty-payload-selected-variant",
      serviceResultPath: "queueWriteTerminal",
      operator: "selects-exact-completion-variant",
    }],
    "native queue writeBuffer service-result joins",
  );
  assert(queueWriteBufferRoute.completion.noTrailingBytes === true,
    "native queue writeBuffer completion must reject trailing bytes");

  const queueSubmitRoute = program.routes.find(
    (candidate) => candidate.operationId === "GPUQueue.submit",
  );
  const queueSubmitOperation = payload.operations.find(
    (candidate) => candidate.operationId === "GPUQueue.submit",
  );
  assert(
    queueSubmitRoute && queueSubmitOperation &&
      queueSubmitRoute.wireId === 308839175 &&
      queueSubmitRoute.wireId === queueSubmitOperation.wireId,
    "native queue submit operation identity drifted",
  );
  assertDigest(
    canonicalDigest(
      "ibex/webgpu-native-codec-program/queue-submit-route-v1",
      queueSubmitRoute,
    ),
    EXPECTED_QUEUE_SUBMIT_NATIVE_ROUTE_SHA256,
    "native queue submit route",
  );
  const queueSubmitRequestCatalogIndex =
    payload.codecCatalog.serviceArguments.findIndex(
      (codec) => codec.tag === queueSubmitOperation.serviceArgumentCodec,
    );
  const queueSubmitCompletionCatalogIndex =
    payload.codecCatalog.serviceCompletions.findIndex(
      (codec) => codec.tag === queueSubmitOperation.serviceCompletionCodec,
    );
  assertCanonical(
    queueSubmitRoute.request.catalog,
    {
      name: "serviceArguments",
      tag: "gpu-sealed-command-program-sequence-service-request-v1",
      wireTag: queueSubmitRequestCatalogIndex + 1,
    },
    "native queue submit request catalog selection",
  );
  assertCanonical(
    queueSubmitRoute.request.payload.fields,
    [
      {
        name: "header",
        type: "headerV1",
        constants: {
          magic: envelope.codecLayout.requestMagic,
          version: envelope.codecLayout.version,
          codecTag: queueSubmitRequestCatalogIndex + 1,
          operationWireId: queueSubmitOperation.wireId,
        },
      },
      { name: "receiver", type: "objectReferenceV1" },
      { name: "target", type: "optionalReferenceV1" },
      { name: "capturedScopeId", type: "u64le" },
      { name: "adapterOrdinal", type: "u64le" },
      { name: "deviceIngressOrdinal", type: "u64le" },
      { name: "queueIngressOrdinal", type: "u64le" },
      { name: "body", type: "queueSubmitRequestBodyV1" },
    ],
    "native queue submit request layout",
  );
  assertCanonical(
    queueSubmitRoute.request.executablePrerequisites,
    [],
    "native queue submit executable prerequisites",
  );
  assert(
    queueSubmitRoute.request.noTrailingBytes === true &&
      queueSubmitRoute.completion.noTrailingBytes === true,
    "native queue submit codec must reject trailing bytes",
  );
  assertCanonical(
    queueSubmitRoute.completion.catalog,
    {
      name: "serviceCompletions",
      tag: "terminal-receipt-service-completion-v1",
      wireTag: queueSubmitCompletionCatalogIndex + 1,
    },
    "native queue submit completion catalog selection",
  );
  assertCanonical(
    queueSubmitRoute.completion.payload,
    { kind: "empty", exactLengthBytes: 0 },
    "native queue submit completion payload",
  );
  assertCanonical(
    queueSubmitRoute.completion.semanticTerminalMapping,
    {
      authorityPath:
        "semanticProjection.providerRoutingPrograms[operationId=GPUQueue.submit]",
      terminals: [
        {
          terminalId: "webidl-rejection",
          errorTiming: "synchronous-webidl",
          resultDisposition: "throw",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "no-service-call",
            completionPayloadEncoderEligibility:
              "excluded-before-service-ingress",
          },
        },
        {
          terminalId: "later-predicate-rejection",
          errorTiming: "device-timeline",
          resultDisposition: "return-undefined-and-report-error",
          providerTokenCount: 0,
          physicalSequenceCount: 0,
          event: {
            kind: "operation-result",
            kindValue: 1,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
            resultKind: 0,
            resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
            status: 0,
            completionVariant: "later-predicate-rejection",
            publicExposure:
              "none-wrapper-already-returned-device-error-delivered-separately",
          },
        },
        {
          terminalId: "operation-success",
          errorTiming: "none",
          resultDisposition: "return-undefined",
          providerTokenCount: 1,
          physicalSequenceCount: 1,
          event: {
            kind: "operation-result",
            kindValue: 1,
            kindSymbol: "EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2",
            resultKind: 0,
            resultKindSymbol: "EXACT_GPU_RESULT_NONE_V2",
            status: 0,
            completionVariant: "operation-success",
            publicExposure: "none-wrapper-already-returned",
          },
        },
      ],
    },
    "native queue submit semantic terminal mapping",
  );
  assertCanonical(
    queueSubmitRoute.completion.variants.map((variant) => variant.name),
    ["later-predicate-rejection", "operation-success"],
    "native queue submit completion variants",
  );
  assertCanonical(
    queueSubmitRoute.completion.serviceResultJoins,
    [{
      payloadPath: "empty-payload-selected-variant",
      serviceResultPath: "queueSubmitTerminal",
      operator: "selects-exact-completion-variant",
    }],
    "native queue submit service-result joins",
  );
}

export function validateWebGpuWrapperAuthority(authority) {
  assert(authority?.schema === "ibex/webgpu-test-wrapper-authority/1", "unknown schema");
  assert(authority.status === "test-only-no-runtime-install", "fixture must remain test-only");
  assert(
    authority.provenance?.sourceCommitAndArtifactSha256Disposition ===
      "provenance-only-not-executable-acceptance",
    "source commit/full-artifact SHA must remain provenance-only",
  );
  assert(
    authority.provenance?.normalizedProjectionComparison ===
      "required-across-outer-ibex-repins",
    "outer normalized-projection comparison expectation is missing",
  );
  assert(
    authority.provenance?.excludedRecursiveFields?.length === 1 &&
      authority.provenance.excludedRecursiveFields[0] === "generatedFrom",
    "recursive generatedFrom fields must be excluded from the projection",
  );
  assert(
    /^[0-9a-f]{40}$/u.test(authority.provenance.sourceCommit) &&
      /^[0-9a-f]{64}$/u.test(authority.provenance.sourceArtifactSha256),
    "historical source provenance is malformed",
  );

  const payload = authority.payload;
  assert(payload && typeof payload === "object", "payload is missing");
  assert(payload.claims?.supportClaim === "none", "support claim must remain none");
  assert(payload.claims?.actualRuntimeInstall === "not-installed", "runtime install claim changed");
  assert(payload.claims?.publicGlobalStatus === "not-installed", "public global claim changed");
  assert(payload.claims?.nativeBindingStatus === "not-installed", "native binding claim changed");
  assert(
    payload.claims?.wireCodecStatus ===
      "generated-injection-and-request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-queue-write-buffer-queue-submit-payload-codegen-input-only-native-codec-not-installed",
    "wire codec readiness claim drifted",
  );
  assert(
    payload.claims?.nativeServiceDecoderStatus === "not-installed" &&
      payload.claims?.semanticServiceStatus === "not-installed" &&
      payload.claims?.embeddedCodecStatus === "undefined",
    "native decoder, semantic service, or embedded codec claim changed",
  );
  assert(
    payload.installInventory?.actualInstalledOperationCount === 0,
    "fixture claims installed operations",
  );
  assert(
    payload.wireEnvelope?.scalarRules?.dictionary ===
      "u8-value-tag-plus-u32-count-plus-unique-well-formed-utf8-key-and-canonical-value-pairs-sorted-by-unsigned-utf8-bytes-shorter-prefix-first",
    "wire dictionary rule differs from the executable generic-value codec",
  );
  assert(
    canonicalJson(payload.wireEnvelope?.codecLayout) ===
      canonicalJson({
        requestMagic: "IBGQ",
        resultMagic: "IBGR",
        lossMagic: "IBGL",
        version: 1,
        header:
          "ascii4-magic-plus-u16-le-version-plus-u16-le-codec-tag-plus-u32-le-operation-wire-id",
        reference: "u8-object-kind-plus-five-u64-le-identity-fields",
        target: "u8-zero-or-one-presence-plus-optional-reference",
        requestTail:
          "four-u64-le-ordinals-plus-generic-sealed-local-timeline-plus-generic-converted-arguments",
        nullableNullResult:
          "authenticated-result-kind-null-plus-zero-payload-bytes",
        catalogWireTagRule: "one-based-index-in-authority-catalog-order",
        objectKindTagRule:
          "ExactGpuObjectKindV2-numeric-values-from-include-exact_runtime.h",
        valueTags: {
          null: 0,
          false: 1,
          true: 2,
          u32: 3,
          f64: 4,
          string: 5,
          sequence: 6,
          dictionary: 7,
        },
        diagnosticMaxBytes: 4096,
        sequenceMaxCount: 1024,
        dictionaryMaxFields: 128,
        nestingMaxDepth: 16,
      }),
    "authenticated executable codec layout drifted",
  );
  validateNativeCodecPrograms(payload);

  const operations = payload.operations;
  assert(
    Array.isArray(operations) && operations.length === WRAPPER_ROUTE_COUNT,
    `operation inventory must have ${WRAPPER_ROUTE_COUNT} rows`,
  );
  const operationIds = operations.map((entry) => entry.operationId);
  const wireIds = operations.map((entry) => entry.wireId);
  assert(
    new Set(operationIds).size === WRAPPER_ROUTE_COUNT,
    "operation IDs are not unique",
  );
  assert(
    wireIds.every((wireId) => Number.isSafeInteger(wireId) && wireId > 0) &&
      new Set(wireIds).size === WRAPPER_ROUTE_COUNT,
    "wire IDs must be unique nonzero safe integers",
  );
  assert(
    operations.every((entry) => /^[0-9a-f]{64}$/u.test(entry.semanticSha256)),
    "operation semantic digests are malformed",
  );

  const assignments = new Map(WRAPPER_ROUTE_ASSIGNMENTS.map((row) => [row[0], row]));
  assert(
    assignments.size === WRAPPER_ROUTE_COUNT,
    "wrapper assignment table is not bijective",
  );
  assert(
    operationIds.slice().sort().join("\n") === [...assignments.keys()].sort().join("\n"),
    "operation inventory and wrapper assignment table differ",
  );
  for (const operation of operations) {
    const assignment = assignments.get(operation.operationId);
    assert(operation.memberKind === assignment[3], operation.operationId + " member kind drifted");
    assert(
      operation.operationId === assignment[1] + "." + assignment[2],
      operation.operationId + " wrapper member assignment drifted",
    );
  }

  const identities = operations
    .map(({ wireId, operationId, semanticSha256 }) => ({ wireId, operationId, semanticSha256 }))
    .sort((left, right) => left.wireId - right.wireId);
  const operationSet = canonicalDigest(
    "exact/webgpu-runtime-wire/operation-set/v1",
    identities.map(({ wireId, operationId }) => ({ wireId, operationId })),
  );
  const semanticProgramSet = canonicalDigest(
    "exact/webgpu-runtime-wire/semantic-program-set/v1",
    identities,
  );
  const runtimeRouting = canonicalDigest(
    "exact/webgpu-runtime-wire/runtime-routing/v1",
    operations.slice().sort((left, right) => left.wireId - right.wireId),
  );
  const webgpuCVocabulary = canonicalDigest("exact/webgpu-runtime-wire/c-vocabulary/v1", {
    wireEnvelope: payload.wireEnvelope,
    codecCatalog: payload.codecCatalog,
    handleModel: payload.handleModel,
    errorModel: payload.errorModel,
    eventModel: payload.eventModel,
    interfaceObjects: payload.installInventory.interfaceObjects,
    constantObjects: payload.installInventory.constantObjects,
  });
  const projection = canonicalDigest("exact/webgpu-runtime-wire/projection/v1", payload);
  const computed = {
    operationSet,
    semanticProgramSet,
    runtimeRouting,
    webgpuCVocabulary,
    projection,
  };

  for (const [name, expected] of Object.entries(REVIEWED_DIGESTS)) {
    assertDigest(computed[name], expected, name);
  }
  assertDigest(authority.authentication.operationSetSha256, operationSet, "embedded operation-set");
  assertDigest(
    authority.authentication.semanticProgramSetSha256,
    semanticProgramSet,
    "embedded semantic-program",
  );
  assertDigest(authority.authentication.runtimeRoutingSha256, runtimeRouting, "embedded routing");
  assertDigest(
    authority.authentication.webgpuCVocabularySha256,
    webgpuCVocabulary,
    "embedded C vocabulary",
  );
  assertDigest(authority.authentication.projectionPayloadSha256, projection, "embedded projection");

  const descriptor = payload.providerDescriptor;
  assertCanonical(
    descriptor.serviceShutdownPolicy,
    {
      deadlineMs: 10000,
      clock: "monotonic",
      wedgedProviderDisposition: "force-loss-and-quarantine-generation",
      redactedDiagnostic: "gpu-provider-shutdown-deadline-exceeded-v1",
    },
    "provider service shutdown policy",
  );
  assertDigest(descriptor.operationSetDigest, operationSet, "provider operation-set");
  assertDigest(descriptor.semanticProgramDigest, semanticProgramSet, "provider semantic-program");
  assertDigest(descriptor.runtimeRoutingDigest, runtimeRouting, "provider routing");
  assertDigest(descriptor.webgpuCVocabularyDigest, webgpuCVocabulary, "provider C vocabulary");
  assert(
    canonicalJson(descriptor.sortedOperationIds) ===
      canonicalJson(identities.map((entry) => entry.wireId)),
    "provider sorted operation IDs drifted",
  );
  assert(
    payload.eventModel.variants.map((entry) => entry.kind).join("|") ===
      "operation-complete|physical-error-record|provider-loss-record|device-loss|account-close|realm-close",
    "typed service-event inventory drifted",
  );
  assert(
    Object.keys(payload.wireEnvelope.lifecycleRequests).sort().join("|") ===
      "accountClose|cancel|realmClose|retire",
    "typed lifecycle-request inventory drifted",
  );
  assert(
    payload.codecCatalog.publicResults.some(
      (entry) =>
        entry.tag === "gpu-supported-limits-snapshot-v1" &&
        entry.wireShape === "complete-36-member-limit-record",
    ),
    "authenticated limit result shape drifted",
  );
  return { payload, computed };
}

export function validateWebGpuWrapperSemantics(semantics) {
  assert(semantics?.schema === "ibex/webgpu-test-wrapper-semantics/1", "unknown semantic schema");
  assert(semantics.status === "test-only-no-runtime-install", "semantic fixture must remain test-only");
  assert(
    semantics.provenance?.normalizedSemanticComparison ===
      "required-across-outer-ibex-repins",
    "outer normalized-semantic comparison expectation is missing",
  );
  const semanticProjection = semantics.semanticProjection;
  const fakeClientData = semantics.fakeClientData;
  const computed = {
    semanticProjection: canonicalDigest(
      "ibex/webgpu-test-wrapper/semantic-projection/v1",
      semanticProjection,
    ),
    fakeClientData: canonicalDigest(
      "ibex/webgpu-test-wrapper/fake-client-data/v1",
      fakeClientData,
    ),
  };
  assertDigest(
    computed.semanticProjection,
    REVIEWED_SEMANTIC_DIGESTS.semanticProjection,
    "reviewed semantic projection",
  );
  assertDigest(
    computed.fakeClientData,
    REVIEWED_SEMANTIC_DIGESTS.fakeClientData,
    "reviewed fake-client data",
  );
  assertDigest(
    semantics.authentication.semanticProjectionSha256,
    computed.semanticProjection,
    "embedded semantic projection",
  );
  assertDigest(
    semantics.authentication.fakeClientDataSha256,
    computed.fakeClientData,
    "embedded fake-client data",
  );

  const limitPolicy = semanticProjection.limitPolicy;
  const featurePolicy = semanticProjection.featurePolicy;
  assert(
    Object.keys(featurePolicy ?? {}).sort().join("|") ===
      "adapterFeatureImplications|adapterRequiredFeatureAlternatives|defaultFeatures|deviceProjection|features|newDeviceFeatureImplications|requiredFeatureValidation",
    "wrapper feature-policy projection drifted",
  );
  assert(
    featurePolicy.requiredFeatureValidation ===
      "webidl-known-then-subset-of-adapter-profile-and-capability-grant" &&
      featurePolicy.deviceProjection ===
        "requested-plus-pinned-default-and-implied-features",
    "wrapper feature-policy algorithms drifted",
  );
  assert(
    Array.isArray(featurePolicy.features) &&
      featurePolicy.features.length > 0 &&
      new Set(featurePolicy.features.map((row) => row.name)).size ===
        featurePolicy.features.length,
    "feature policy vocabulary is malformed",
  );
  const admittedFeatureNames = new Set();
  for (const row of featurePolicy.features) {
    assert(
      typeof row.name === "string" &&
        ((row.classification === "standard" &&
          row.profileAdmission === "admitted") ||
          (row.classification === "disabled-extension" &&
            row.profileAdmission === "denied")),
      "feature policy row is malformed: " + row.name,
    );
    if (row.profileAdmission === "admitted") admittedFeatureNames.add(row.name);
  }
  assert(
    Object.keys(featurePolicy.defaultFeatures ?? {}).sort().join("|") ===
      "compatibility|core",
    "feature-level default inventory drifted",
  );
  for (const featureLevel of ["core", "compatibility"]) {
    const defaults = featurePolicy.defaultFeatures[featureLevel];
    assert(
      Array.isArray(defaults) &&
        new Set(defaults).size === defaults.length &&
        defaults.every((name) => admittedFeatureNames.has(name)),
      featureLevel + " default features are malformed",
    );
  }
  function validateFeatureImplications(rows, label) {
    assert(Array.isArray(rows), label + " are missing");
    const pairs = new Set();
    for (const row of rows) {
      const pair = row?.feature + "\0" + row?.implies;
      assert(
        admittedFeatureNames.has(row?.feature) &&
          admittedFeatureNames.has(row?.implies) &&
          row.feature !== row.implies &&
          !pairs.has(pair),
        label + " contain an invalid row",
      );
      pairs.add(pair);
    }
  }
  validateFeatureImplications(
    featurePolicy.adapterFeatureImplications,
    "adapter feature implications",
  );
  validateFeatureImplications(
    featurePolicy.newDeviceFeatureImplications,
    "new-device feature implications",
  );
  assert(
    Array.isArray(featurePolicy.adapterRequiredFeatureAlternatives) &&
      featurePolicy.adapterRequiredFeatureAlternatives.length > 0 &&
      featurePolicy.adapterRequiredFeatureAlternatives.every(
        (alternative) =>
          Array.isArray(alternative) &&
          alternative.length > 0 &&
          new Set(alternative).size === alternative.length &&
          alternative.every((name) => admittedFeatureNames.has(name)),
      ),
    "adapter required-feature alternatives are malformed",
  );
  assert(
    limitPolicy.requestValidation.undefinedValue ===
      "skip-key-validation-and-projection",
    "undefined limit rule drifted",
  );
  assert(
    limitPolicy.requestValidation.unknownNonUndefined ===
      "operation-error-promise-rejection",
    "unknown non-undefined limit rule drifted",
  );
  assert(Array.isArray(limitPolicy.limits) && limitPolicy.limits.length === 36, "limit program must have 36 rows");
  assert(
    new Set(limitPolicy.limits.map((row) => row.name)).size === 36,
    "limit names are not unique",
  );
  for (const row of limitPolicy.limits) {
    assert(row.class === "maximum" || row.class === "alignment", row.name + " class drifted");
    assert(
      (row.class === "maximum" && row.betterDirection === "higher") ||
        (row.class === "alignment" && row.betterDirection === "lower"),
      row.name + " direction disagrees with its class",
    );
    assert(
      Number.isSafeInteger(row.coreDefault) &&
        row.coreDefault >= 0 &&
        Number.isSafeInteger(row.compatibilityDefault) &&
        row.compatibilityDefault >= 0,
      row.name + " feature-level defaults are invalid",
    );
    for (const featureLevel of ["core", "compatibility"]) {
      assert(
        Number.isSafeInteger(row.profileBucket?.[featureLevel]) &&
          row.profileBucket[featureLevel] >= 0 &&
          Number.isSafeInteger(row.capabilityGrantBoundary?.[featureLevel]) &&
          row.capabilityGrantBoundary[featureLevel] >= 0,
        row.name + " " + featureLevel + " request boundary is invalid",
      );
    }
    assert(
      row.class !== "alignment" ||
        ([
          row.coreDefault,
          row.compatibilityDefault,
          row.profileBucket.core,
          row.profileBucket.compatibility,
          row.capabilityGrantBoundary.core,
          row.capabilityGrantBoundary.compatibility,
        ].every(
          (value) =>
            value > 0 &&
            value < 2 ** 32 &&
            Number.isInteger(Math.log2(value)),
        )),
      row.name + " alignment metadata is invalid",
    );
  }
  const providerDescriptor = semanticProjection.requestDeviceProviderDescriptor;
  assert(
    providerDescriptor?.policy ===
      "generated-logical-limits-plus-versioned-service-internal-requirements-only" &&
      providerDescriptor.projectionRule === limitPolicy.projectionRule,
    "requestDevice provider-descriptor policy drifted",
  );
  assert(
    Object.keys(providerDescriptor).sort().join("|") ===
      "capabilityProjectionPredicate|policy|projectionRule|providerReadyPredicate",
    "requestDevice provider-descriptor projection must remain outer-derivable",
  );
  const capabilityProjectionPredicate =
    providerDescriptor.capabilityProjectionPredicate;
  assert(
    capabilityProjectionPredicate?.predicateId ===
      "adapter.request-device.capability-projection" &&
      capabilityProjectionPredicate.predicateType === "profile-feature-limit" &&
      capabilityProjectionPredicate.predicateIndex === 2 &&
      capabilityProjectionPredicate.predicateWireId === 1496584302 &&
      capabilityProjectionPredicate.failureClass === "none" &&
      capabilityProjectionPredicate.failureTiming === "none" &&
      capabilityProjectionPredicate.inputs.join("|") ===
        "requiredFeatures|requiredLimits|featureLevel|profileFeaturePolicy|profileLimitTable|capabilityGrant|serviceInternalRequirements" &&
      capabilityProjectionPredicate.relation.includes(
        "generated logical provider descriptor containing only that logical set plus versioned service-internal requirements",
      ),
    "requestDevice capability-projection predicate drifted",
  );
  const providerReadyPredicate = providerDescriptor.providerReadyPredicate;
  assert(
    providerReadyPredicate?.predicateId ===
      "adapter.request-device.provider-ready" &&
      providerReadyPredicate.predicateType === "provider-request-readiness" &&
      providerReadyPredicate.predicateIndex === 1 &&
      providerReadyPredicate.predicateWireId === 1494113071 &&
      providerReadyPredicate.failureClass === "none" &&
      providerReadyPredicate.failureTiming === "none" &&
      providerReadyPredicate.inputs.join("|") ===
        "liveDeviceReservationId|generatedLogicalProviderDescriptor" &&
      providerReadyPredicate.relation.includes(
        "raw request descriptor is unavailable at this boundary",
      ),
    "requestDevice provider-ready predicate drifted",
  );
  const failureProgram = semanticProjection.requestDeviceFailureProgram;
  const expectedBranchIds = [
    "webidl",
    "required-features-check",
    "adapter-validation",
    "live-admission",
    "expiry-result-selection-commit",
    "live-device-capacity",
    "capacity-result-selection-commit",
    "live-device-commit",
    "provider-request",
    "provider-settlement",
  ];
  assert(
    failureProgram?.operationId === "GPUAdapter.requestDevice" &&
      Number.isSafeInteger(failureProgram.operationWireId) &&
      failureProgram.operationWireId > 0,
    "requestDevice failure program identity drifted",
  );
  assert(
    Array.isArray(failureProgram.branches) &&
      failureProgram.branches.map((branch) => branch.branchId).join("|") ===
        expectedBranchIds.join("|"),
    "requestDevice failure branch order or inventory drifted",
  );
  const failureBranches = new Map();
  const branchWireIds = new Set();
  const predicateWireIds = new Set();
  for (const branch of failureProgram.branches) {
    assert(
      Number.isSafeInteger(branch.branchWireId) &&
        branch.branchWireId > 0 &&
        !branchWireIds.has(branch.branchWireId),
      "requestDevice failure branch wire ID is invalid: " + branch.branchId,
    );
    branchWireIds.add(branch.branchWireId);
    assert(
      Array.isArray(branch.orderedPredicates) && branch.orderedPredicates.length > 0,
      "requestDevice failure branch has no predicates: " + branch.branchId,
    );
    const predicateIds = new Set();
    for (let index = 0; index < branch.orderedPredicates.length; index += 1) {
      const predicate = branch.orderedPredicates[index];
      assert(
        typeof predicate.predicateId === "string" &&
          predicate.predicateId.length > 0 &&
          !predicateIds.has(predicate.predicateId) &&
          predicate.predicateIndex === index + 1 &&
          Number.isSafeInteger(predicate.predicateWireId) &&
          predicate.predicateWireId > 0 &&
          !predicateWireIds.has(predicate.predicateWireId),
        "requestDevice failure predicate identity is invalid: " + branch.branchId,
      );
      assert(
        ["none", "type-error", "operation-error", "security-error"].includes(
          predicate.failureClass,
        ) &&
          ["none", "promise-rejection"].includes(predicate.failureTiming) &&
          ((predicate.failureClass === "none") ===
            (predicate.failureTiming === "none")),
        "requestDevice failure predicate class/timing is invalid: " +
          predicate.predicateId,
      );
      predicateIds.add(predicate.predicateId);
      predicateWireIds.add(predicate.predicateWireId);
    }
    failureBranches.set(branch.branchId, branch);
  }
  const routing = semanticProjection.requestDeviceRouting;
  assert(
    routing.operationId === "GPUAdapter.requestDevice" &&
      routing.exhaustive === true &&
      routing.disjoint === true,
    "requestDevice routing program drifted",
  );
  const expectedFacts = [
    "webidlValid",
    "requiredFeaturesSupported",
    "adapterRequestValid",
    "deviceAdmissionValid",
    "adapterExpired",
    "deviceExpiryResultCommitLive",
    "deviceReservationCapacityAvailable",
    "deviceCapacityResultCommitLive",
    "deviceReservationCommitLive",
    "providerFulfilled",
    "deviceAccountLiveAtProviderCompletion",
    "deviceAccountLiveAtSettlementCommit",
    "providerInabilityWonLossRace",
  ];
  assert(
    Array.isArray(routing.facts) &&
      routing.facts.join("|") === expectedFacts.join("|") &&
      Array.isArray(routing.precedence) &&
      routing.precedence.join("|") === expectedFacts.join("|"),
    "requestDevice fact inventory or precedence drifted",
  );
  assert(
    Array.isArray(routing.factBindings) &&
      routing.factBindings.length === expectedFacts.length &&
      routing.factBindings.map((binding) => binding.fact).join("|") ===
        expectedFacts.join("|"),
    "requestDevice fact bindings drifted",
  );
  for (const binding of routing.factBindings) {
    assert(
      (binding.kind === "branch-predicates" &&
        failureBranches.has(binding.branchId) &&
        binding.passWhen === true) ||
        (binding.kind === "external-outcome" &&
          typeof binding.source === "string" &&
          binding.source.length > 0 &&
          (!binding.requiredBranchId ||
            failureBranches.has(binding.requiredBranchId))),
      "requestDevice fact binding is malformed: " + binding.fact,
    );
  }
  const expectedTerminalIds = [
    "webidl-rejection",
    "unsupported-required-features",
    "invalid-adapter-request",
    "live-admission-rejection",
    "expiry-lost-selection-close-rejection",
    "expired-adapter-lost-device",
    "pre-capacity-close-rejection",
    "capacity-lost-selection-close-rejection",
    "live-device-capacity-unavailable",
    "post-capacity-close-rejection",
    "live-device-commit-close-rejection",
    "provider-unfulfilled-provider-inability-won",
    "provider-unfulfilled-provider-inability-won-before-close",
    "provider-unfulfilled-account-close-won",
    "lost-device-returned-close-before-provider-completion",
    "lost-device-returned-close-after-provider-completion",
    "live-device-returned",
  ];
  assert(
    Array.isArray(routing.terminals) &&
      routing.terminals.length === expectedTerminalIds.length,
    "requestDevice terminal inventory must have 17 rows",
  );
  const terminals = new Map(routing.terminals.map((terminal) => [terminal.terminalId, terminal]));
  assert(terminals.size === 17, "requestDevice terminal IDs are not unique");
  assert(
    routing.terminals.map((terminal) => terminal.terminalId).join("|") ===
      expectedTerminalIds.join("|"),
    "requestDevice terminal order or inventory drifted",
  );
  for (const terminalId of expectedTerminalIds) {
    const terminal = terminals.get(terminalId);
    assert(
      terminal &&
        terminal.conditions &&
        Object.keys(terminal.conditions).length > 0 &&
        Array.isArray(terminal.branchPath) &&
        terminal.branchPath.length > 0,
      "requestDevice terminal is structurally incomplete: " + terminalId,
    );
    assert(
      Object.entries(terminal.conditions).every(
        ([fact, value]) => expectedFacts.includes(fact) && typeof value === "boolean",
      ) &&
        terminal.branchPath.every((branchId) => failureBranches.has(branchId)),
      "requestDevice terminal names an unknown fact or branch: " + terminalId,
    );
    assert(
      (terminal.providerTokenCount === 0 || terminal.providerTokenCount === 1) &&
        terminal.physicalSequenceCount === terminal.providerTokenCount,
      "requestDevice provider/physical count drifted: " + terminalId,
    );
    assert(
      terminal.resultDisposition === "promise-reject" ||
        terminal.resultDisposition === "promise-resolve-object" ||
        terminal.resultDisposition === "promise-resolve-lost-object",
      "requestDevice result disposition drifted: " + terminalId,
    );
    assert(
      typeof terminal.adapterStateAfterSettlement === "string" &&
        typeof terminal.publicationCreditDisposition === "string" &&
        typeof terminal.liveDeviceCreditDisposition === "string",
      "requestDevice ownership disposition is incomplete: " + terminalId,
    );
    if (terminal.errorSource?.kind === "first-failing-predicate") {
      const branch = failureBranches.get(terminal.errorSource.branchId);
      assert(
        branch &&
          branch.orderedPredicates.some(
            (predicate) =>
              predicate.failureClass !== "none" &&
              predicate.failureTiming === terminal.errorTiming,
          ),
        "requestDevice terminal lacks an authenticated failing predicate: " +
          terminalId,
      );
    }
  }
  assert(
    terminals.get("expired-adapter-lost-device").providerTokenCount === 0 &&
      terminals.get("expired-adapter-lost-device").physicalSequenceCount === 0 &&
      terminals.get("expired-adapter-lost-device").lostSettlement.settlementOrder ===
        "device-lost-before-request-device-promise",
    "expired-adapter terminal semantics drifted",
  );
  assert(
    terminals.get("live-device-returned").providerTokenCount === 1 &&
      terminals.get("live-device-returned").physicalSequenceCount === 1,
    "live requestDevice provider admission semantics drifted",
  );
  const providerRoutingPrograms = semanticProjection.providerRoutingPrograms;
  assert(
    Array.isArray(providerRoutingPrograms) &&
      providerRoutingPrograms.length === CONDITIONAL_PROVIDER_ROUTE_COUNT &&
      providerRoutingPrograms.map((program) => program.operationId).join("|") ===
        CONDITIONAL_PROVIDER_OPERATION_IDS.join("|"),
    "conditional provider-routing program order or inventory drifted",
  );
  for (const program of providerRoutingPrograms) {
    assert(
      program.exhaustive === true &&
        program.disjoint === true &&
        Array.isArray(program.facts) &&
        program.facts.join("|") === program.precedence.join("|") &&
        Array.isArray(program.factBindings) &&
        program.factBindings.map((binding) => binding.fact).join("|") ===
          program.facts.join("|"),
      "conditional provider-routing program is malformed: " + program.operationId,
    );
    const providerCounts = new Set();
    for (const terminal of program.terminals) {
      assert(
        (terminal.providerTokenCount === 0 || terminal.providerTokenCount === 1) &&
          terminal.physicalSequenceCount === terminal.providerTokenCount,
        "conditional provider terminal count drifted: " +
          program.operationId +
          "/" +
          terminal.terminalId,
      );
      providerCounts.add(terminal.providerTokenCount);
    }
    assert(
      providerCounts.size === 2 && providerCounts.has(0) && providerCounts.has(1),
      "conditional provider-routing program no longer varies admission: " +
        program.operationId,
    );
  }
  assert(
    canonicalJson(
      providerRoutingPrograms.find(
        (program) => program.operationId === "GPUAdapter.requestDevice",
      ),
    ) === canonicalJson(routing),
    "requestDevice routing differs from the conditional provider-routing projection",
  );
  assert(
    fakeClientData.disposition ===
      "deterministic-test-data-not-exact-profile-authority",
    "fake-client data disposition drifted",
  );
  assert(
    Array.isArray(fakeClientData.adapterFeatures) &&
      new Set(fakeClientData.adapterFeatures).size ===
        fakeClientData.adapterFeatures.length &&
      fakeClientData.adapterFeatures.every((name) =>
        admittedFeatureNames.has(name),
      ),
    "fake adapter features are malformed",
  );
  const projectedFakeFeatures = new Set(fakeClientData.adapterFeatures);
  for (const implication of featurePolicy.adapterFeatureImplications) {
    if (projectedFakeFeatures.has(implication.feature)) {
      assert(
        projectedFakeFeatures.has(implication.implies),
        "fake adapter omits an adapter-implied feature",
      );
    }
  }
  for (const implication of featurePolicy.newDeviceFeatureImplications) {
    if (projectedFakeFeatures.has(implication.feature)) {
      assert(
        projectedFakeFeatures.has(implication.implies),
        "fake adapter cannot support an ordered new-device feature addition",
      );
    }
  }
  assert(
    ["core", "compatibility"].every((featureLevel) =>
      featurePolicy.defaultFeatures[featureLevel].every((name) =>
        projectedFakeFeatures.has(name),
      ),
    ),
    "fake adapter does not support every feature-level default",
  );
  assert(
    featurePolicy.adapterRequiredFeatureAlternatives.some((alternative) =>
      alternative.every((name) => projectedFakeFeatures.has(name)),
    ),
    "fake adapter satisfies no required feature alternative",
  );
  const fakeAdapterLimitNames = Object.keys(
    fakeClientData.adapterLimits ?? {},
  ).sort();
  const limitNames = limitPolicy.limits.map((row) => row.name).sort();
  assert(
    canonicalJson(fakeAdapterLimitNames) === canonicalJson(limitNames),
    "fake adapter limits are not the complete limit policy",
  );
  for (const row of limitPolicy.limits) {
    const value = fakeClientData.adapterLimits[row.name];
    assert(
      Number.isSafeInteger(value) &&
        value >= 0 &&
        (row.class === "maximum"
          ? value >= Math.max(row.coreDefault, row.compatibilityDefault)
          : value <= Math.min(row.coreDefault, row.compatibilityDefault) &&
            value > 0 &&
            value < 2 ** 32 &&
            Number.isInteger(Math.log2(value))),
      "fake adapter limit is inconsistent with device defaults: " + row.name,
    );
  }
  assert(
    Array.isArray(fakeClientData.providerEntryOperationIds) &&
      new Set(fakeClientData.providerEntryOperationIds).size ===
        fakeClientData.providerEntryOperationIds.length,
    "fake provider-entry operation set is malformed",
  );
  return { semanticProjection, fakeClientData, computed };
}

export function buildWebGpuWrapperPlan(authority, semantics) {
  const { payload, computed } = validateWebGpuWrapperAuthority(authority);
  const semantic = validateWebGpuWrapperSemantics(semantics);
  const assignments = new Map(WRAPPER_ROUTE_ASSIGNMENTS.map((row) => [row[0], row]));
  const operationIds = new Set(payload.operations.map((operation) => operation.operationId));
  const requestDeviceOperation = payload.operations.find(
    (operation) => operation.operationId === "GPUAdapter.requestDevice",
  );
  assert(
    requestDeviceOperation.wireId ===
      semantic.semanticProjection.requestDeviceFailureProgram.operationWireId,
    "requestDevice failure-program wire identity differs from runtime authority",
  );
  assert(
    semantic.fakeClientData.providerEntryOperationIds.every((operationId) =>
      operationIds.has(operationId),
    ),
    "fake provider-entry set names an operation outside the authenticated inventory",
  );
  return {
    schema: "ibex/webgpu-test-wrapper-plan/1",
    profileId: payload.profileId,
    scopeId: payload.scopeId,
    digests: computed,
    maxPayloadBytes: payload.wireEnvelope.maxPayloadBytes,
    semantic: {
      digest: semantic.computed.semanticProjection,
      featurePolicy: semantic.semanticProjection.featurePolicy,
      limitPolicy: semantic.semanticProjection.limitPolicy,
      requestDeviceFailureProgram:
        semantic.semanticProjection.requestDeviceFailureProgram,
      requestDeviceRouting: semantic.semanticProjection.requestDeviceRouting,
      requestDeviceProviderDescriptor:
        semantic.semanticProjection.requestDeviceProviderDescriptor,
      providerRoutingPrograms:
        semantic.semanticProjection.providerRoutingPrograms,
    },
    fakeClientData: semantic.fakeClientData,
    routes: payload.operations.map((operation) => {
      const assignment = assignments.get(operation.operationId);
      return {
        ...operation,
        interfaceName: assignment[1],
        memberName: assignment[2],
        fakeProviderEntry:
          semantic.fakeClientData.providerEntryOperationIds.includes(
            operation.operationId,
          ),
      };
    }),
  };
}

export function renderWebGpuTestWrapper(authority, semantics) {
  const plan = buildWebGpuWrapperPlan(authority, semantics);
  return (
    "(" +
    portableWebGpuTestWrapperFactory.toString() +
    ")(" +
    JSON.stringify(plan) +
    ")\n"
  );
}
