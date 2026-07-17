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

export const REVIEWED_DIGESTS = Object.freeze({
  projection: "8650c9faa794ac34c4b881804a8dd210f34abe3b1833deb7f3f09876cc408651",
  operationSet: "ba939cdb05e89cb5243317e6836465e3612b25d8e02f49a94187064b972830e7",
  semanticProgramSet: "ecb999ed815c17184598f83bf3f64702bf050ff31fbd4c2326b68cac74f09058",
  runtimeRouting: "519b32708751fc7357e5e9f76f9b1e76bda491972ae0f7141279b2df7be4cb94",
  webgpuCVocabulary: "6ea4da1993483fee17a87bb7e09918bfd51a02ca61ddf72bd5b0289866695f1b",
});

export const REVIEWED_SEMANTIC_DIGESTS = Object.freeze({
  semanticProjection:
    "374dc0348ec585fbfe3829df3602a52e054aed2fa36b635c12357e5bd28f0746",
  fakeClientData:
    "16952a4a4b487fb567d7e68b5f893d6ca51e3b994677aea05c02c8469094ff0d",
});

export const WRAPPER_ROUTE_ASSIGNMENTS = Object.freeze([
  ["GPU.getPreferredCanvasFormat", "GPU", "getPreferredCanvasFormat", "method"],
  ["GPU.requestAdapter", "GPU", "requestAdapter", "method"],
  ["GPUAdapter.requestDevice", "GPUAdapter", "requestDevice", "method"],
  ["GPUCanvasContext.configure", "GPUCanvasContext", "configure", "method"],
  ["GPUCanvasContext.getConfiguration", "GPUCanvasContext", "getConfiguration", "method"],
  ["GPUCanvasContext.getCurrentTexture", "GPUCanvasContext", "getCurrentTexture", "method"],
  ["GPUCanvasContext.unconfigure", "GPUCanvasContext", "unconfigure", "method"],
  ["GPUCommandEncoder.beginRenderPass", "GPUCommandEncoder", "beginRenderPass", "method"],
  ["GPUCommandEncoder.finish", "GPUCommandEncoder", "finish", "method"],
  ["GPUDevice.createCommandEncoder", "GPUDevice", "createCommandEncoder", "method"],
  ["GPUDevice.createRenderPipeline", "GPUDevice", "createRenderPipeline", "method"],
  ["GPUDevice.createShaderModule", "GPUDevice", "createShaderModule", "method"],
  ["GPUDevice.destroy", "GPUDevice", "destroy", "method"],
  ["GPUDevice.features", "GPUDevice", "features", "property"],
  ["GPUDevice.limits", "GPUDevice", "limits", "property"],
  ["GPUDevice.lost", "GPUDevice", "lost", "property"],
  ["GPUDevice.popErrorScope", "GPUDevice", "popErrorScope", "method"],
  ["GPUDevice.pushErrorScope", "GPUDevice", "pushErrorScope", "method"],
  ["GPUDevice.queue", "GPUDevice", "queue", "property"],
  ["GPUQueue.submit", "GPUQueue", "submit", "method"],
  ["GPURenderPassEncoder.draw", "GPURenderPassEncoder", "draw", "method"],
  ["GPURenderPassEncoder.end", "GPURenderPassEncoder", "end", "method"],
  ["GPURenderPassEncoder.setPipeline", "GPURenderPassEncoder", "setPipeline", "method"],
  ["GPUTexture.createView", "GPUTexture", "createView", "method"],
  ["GPUTexture.destroy", "GPUTexture", "destroy", "method"],
]);

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

function validateNativeCodecPrograms(payload) {
  const envelope = payload.wireEnvelope;
  const program = envelope?.nativeCodecPrograms;
  assert(
    program?.schema === "ibex/webgpu-native-codec-programs/2" &&
      program.disposition ===
        "request-adapter-payload-codegen-input-only-native-codec-not-installed-no-support-claim",
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
      "canonicalValueV1",
      "headerV1",
      "objectReferenceV1",
      "optionalReferenceV1",
      "requestAdapterOptionsV1",
    ],
    "native codec type inventory",
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

  assert(Array.isArray(program.routes) && program.routes.length === 1,
    "native codec program must contain exactly one route");
  const route = program.routes[0];
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
      "generated-injection-and-request-adapter-payload-codegen-input-only-native-codec-not-installed",
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
  assert(Array.isArray(operations) && operations.length === 25, "operation inventory must have 25 rows");
  const operationIds = operations.map((entry) => entry.operationId);
  const wireIds = operations.map((entry) => entry.wireId);
  assert(new Set(operationIds).size === 25, "operation IDs are not unique");
  assert(
    wireIds.every((wireId) => Number.isSafeInteger(wireId) && wireId > 0) &&
      new Set(wireIds).size === 25,
    "wire IDs must be unique nonzero safe integers",
  );
  assert(
    operations.every((entry) => /^[0-9a-f]{64}$/u.test(entry.semanticSha256)),
    "operation semantic digests are malformed",
  );

  const assignments = new Map(WRAPPER_ROUTE_ASSIGNMENTS.map((row) => [row[0], row]));
  assert(assignments.size === 25, "wrapper assignment table is not bijective");
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
  assert(
    limitPolicy.requestValidation.undefinedValue ===
      "skip-key-validation-and-projection",
    "undefined limit rule drifted",
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
      Number.isSafeInteger(row.profileBucket.core) && row.profileBucket.core >= 0,
      row.name + " core profile bucket is invalid",
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
      capabilityProjectionPredicate.predicateWireId === 436961075 &&
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
  const expectedProviderRoutingIds = [
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
  ];
  const providerRoutingPrograms = semanticProjection.providerRoutingPrograms;
  assert(
    Array.isArray(providerRoutingPrograms) &&
      providerRoutingPrograms.map((program) => program.operationId).join("|") ===
        expectedProviderRoutingIds.join("|"),
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
      new Set(fakeClientData.adapterFeatures).size === fakeClientData.adapterFeatures.length,
    "fake adapter features are malformed",
  );
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
