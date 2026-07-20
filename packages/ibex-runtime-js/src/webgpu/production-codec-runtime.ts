// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// The normalized operation/catalog artifact selects every codec. This module
// implements those selected conversions and the private injection-only binary
// layout without introducing a second hand-authored operation registry.

import type { NativeGpuEventV2 } from './native-bridge';
import { DOMException as RuntimeDOMException } from '../events/DOMException';
import type {
  ExecutableWebGpuCodecBundle,
  ProductionGpuCanvasServiceEncoding,
  ProductionGpuFullObjectReference,
  ProductionGpuTextureOriginDigestInput,
  ProductionGpuCodecWrapperAccess,
  ProductionGpuDecodedResult,
  ProductionGpuServiceEncodingInput,
  ProductionGpuWrapperKind,
} from './production-codecs';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';

const WebGpuDOMException =
  typeof globalThis.DOMException === 'function'
    ? globalThis.DOMException
    : RuntimeDOMException;

interface CodecCatalogRow {
  readonly wireTag: number;
  readonly tag: string;
  readonly wireShape: string;
}

interface ServiceCodecCatalogRow extends CodecCatalogRow {
  readonly nativeProgramPrerequisitesRepresented: boolean;
  readonly executableFromCurrentAuthenticatedInputs: boolean;
  readonly unavailableSemanticFields: readonly string[];
}

type NativeCodecPrimitiveName =
  | 'ascii4'
  | 'u8'
  | 'u16le'
  | 'u32le'
  | 'u64le'
  | 'f64le'
  | 'utf8';

interface NativeCodecPrimitiveEncoding {
  readonly widthBytes?: number;
  readonly kind?: 'length-prefixed-bytes';
  readonly lengthType?: 'u32le';
  readonly encoding: 'ascii' | 'unsigned-integer' | 'ieee754-binary64' | 'utf8';
  readonly byteOrder?: 'little-endian';
  readonly constraints?: readonly ('finite' | 'well-formed')[];
}

interface NativeCodecField {
  readonly name: string;
  readonly type: NativeCodecPrimitiveName |
    'headerV1' |
    'objectReferenceV1' |
    'optionalReferenceV1' |
    'canonicalValueV1' |
    'sortedUniqueFeatureSequenceV1' |
    'completeDeviceLimitsV1' |
    'gpuDeviceCompletionBodyV1' |
    'bufferCleanupRequestBodyV1' |
    'bufferMapAsyncRequestBodyV1' |
    'bufferMapAsyncCompletionBodyV1' |
    'queueWriteBufferRequestBodyV1' |
    'queueSubmitRequestBodyV1' |
    'canvasConfigureRequestBodyV1' |
    'canvasViewFormatSequenceV1' |
    'canvasUnconfigureRequestBodyV1' |
    'textureDestroyRequestBodyV1' |
    'canvasCurrentTextureOriginV1' |
    'sha256DigestV1' |
    'ownedBytesV1';
  readonly catalog?: 'objectKindTags';
  readonly constraintType?:
    | 'requestAdapterOptionsV1'
    | 'requestDeviceDescriptorV1'
    | 'bindGroupDescriptorV1'
    | 'bindGroupLayoutDescriptorV1'
    | 'bufferDescriptorV1'
    | 'pipelineLayoutDescriptorV1'
    | 'computePipelineDescriptorV1'
    | 'renderPipelineDescriptorV1'
    | 'samplerDescriptorV1'
    | 'textureDescriptorV1'
    | 'textureViewRequestV1'
    | 'commandEncoderDescriptorV1'
    | 'shaderModuleDescriptorV1';
  readonly constants?: Readonly<{
    magic: 'IBGQ' | 'IBGR';
    version: 1;
    codecTag: 2 | 3 | 4 | 5 | 6 | 7 | 9 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25;
    operationWireId:
      | 1660448199
      | 194635792
      | 206890944
      | 1869756926
      | 2544948076
      | 3373402978
      | 2342501516
      | 2407151159
      | 3285037552
      | 4177957718
      | 1853125118
      | 599085487
      | 4055478657
      | 1199806466
      | 3314731466
      | 1760273919
      | 1228615721
      | 56177326
      | 935342475
      | 2933046788
      | 404589710
      | 308839175;
  }>;
  readonly constant?: 1;
  readonly constraint?: 'positive' | 'boolean-zero-or-one';
  readonly maxBytesFrom?: 'codecLayout.diagnosticMaxBytes';
}

interface NativeCodecCanonicalVariant {
  readonly name:
    | 'null'
    | 'false'
    | 'true'
    | 'u32'
    | 'f64'
    | 'string'
    | 'sequence'
    | 'dictionary';
  readonly tag: number;
  readonly payload: Readonly<{
    kind: 'empty' | 'scalar' | 'sequence' | 'dictionary';
    type?: 'u32le' | 'f64le' | 'utf8';
    countType?: 'u32le';
    elementType?: 'canonicalValueV1';
    keyType?: 'utf8';
    valueType?: 'canonicalValueV1';
    maxCountFrom?:
      | 'codecLayout.sequenceMaxCount'
      | 'codecLayout.dictionaryMaxFields';
    countLimitOperator?: 'less-than-or-equal';
    keyConstraints?: readonly (
      | 'unique'
      | 'strictly-increasing-unsigned-utf8-bytes-shorter-prefix-first'
    )[];
  }>;
}

interface NativeCodecRequestAdapterOptionField {
  readonly name:
    | 'featureLevel'
    | 'forceFallbackAdapter'
    | 'powerPreference'
    | 'xrCompatible';
  readonly required: boolean;
  readonly value: Readonly<{
    kind: 'boolean' | 'string-enum';
    values?: readonly (
      | 'core'
      | 'compatibility'
      | 'low-power'
      | 'high-performance'
    )[];
  }>;
}

interface NativeCodecJoin {
  readonly payloadPath: string;
  readonly carrierPath: string;
  readonly operator: 'equal' | 'absent-iff-all-zero-reference';
}

interface NativeCodecCarrierConstraint {
  readonly carrierPath: string;
  readonly operator: 'equal' | 'all-zero' | 'positive' | 'absent';
  readonly value?: number | boolean | '0';
  readonly valueFrom?:
    | 'objectKindTags.GPU'
    | 'objectKindTags.GPUAdapter'
    | 'objectKindTags.GPUDevice'
    | 'objectKindTags.GPUQueue'
    | 'objectKindTags.GPUBuffer'
    | 'objectKindTags.GPUSampler'
    | 'objectKindTags.GPUTexture'
    | 'objectKindTags.GPUTextureView'
    | 'objectKindTags.GPUCanvasContext'
    | 'objectKindTags.GPUBindGroup'
    | 'objectKindTags.GPUBindGroupLayout'
    | 'objectKindTags.GPUPipelineLayout'
    | 'objectKindTags.GPUComputePipeline'
    | 'objectKindTags.GPURenderPipeline'
    | 'objectKindTags.GPUCommandEncoder'
    | 'objectKindTags.GPUShaderModule'
    | 'constants.providerTopologyId';
  readonly symbol?:
    | 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2'
    | 'EXACT_GPU_DEVICE_UNCHANGED_V2'
    | 'EXACT_GPU_DEVICE_ASSIGNED_V2'
    | 'EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2'
    | 'EXACT_GPU_PROVIDER_NOT_ADMITTED_V2'
    | 'EXACT_GPU_PROVIDER_ADMITTED_V2'
    | 'EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2'
    | 'EXACT_GPU_BACKEND_NONE_V2'
    | 'EXACT_GPU_RESULT_NONE_V2'
    | 'EXACT_GPU_RESULT_OBJECT_V2'
    | 'EXACT_GPU_RESULT_BYTES_V2';
}

interface NativeCodecCatalogReference {
  readonly name: 'serviceArguments' | 'serviceCompletions';
  readonly tag:
    | 'gpu-request-adapter-service-request-v1'
    | 'nullable-gpu-adapter-service-completion-v2'
    | 'gpu-request-device-service-request-v1'
    | 'gpu-device-service-completion-v1'
    | 'gpu-create-bind-group-service-request-v1'
    | 'gpu-create-bind-group-layout-service-request-v1'
    | 'gpu-create-buffer-service-request-v1'
    | 'gpu-create-sampler-service-request-v1'
    | 'gpu-create-texture-service-request-v1'
    | 'gpu-create-texture-view-service-request-v1'
    | 'gpu-create-pipeline-layout-service-request-v1'
    | 'gpu-create-compute-pipeline-service-request-v1'
    | 'gpu-create-render-pipeline-service-request-v1'
    | 'gpu-create-command-encoder-service-request-v1'
    | 'gpu-create-shader-module-service-request-v1'
    | 'gpu-device-cleanup-service-request-v1'
    | 'gpu-buffer-destroy-service-request-v1'
    | 'gpu-buffer-map-async-service-request-v1'
    | 'gpu-buffer-unmap-service-request-v1'
    | 'gpu-canvas-configure-service-request-v1'
    | 'gpu-canvas-unconfigure-service-request-v1'
    | 'gpu-texture-cleanup-service-request-v1'
    | 'gpu-queue-write-buffer-service-request-v1'
    | 'gpu-sealed-command-program-sequence-service-request-v1'
    | 'gpu-buffer-map-async-service-completion-v1'
    | 'terminal-receipt-service-completion-v1';
  readonly wireTag: 2 | 3 | 4 | 5 | 6 | 7 | 9 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25;
}

interface NativeCodecCompletionVariant {
  readonly name: 'null' | 'object';
  readonly resultKind: 2 | 3;
  readonly resultKindSymbol:
    | 'EXACT_GPU_RESULT_NULL_V2'
    | 'EXACT_GPU_RESULT_OBJECT_V2';
  readonly objectKind?: 'GPUAdapter';
  readonly payload: Readonly<{
    kind: 'empty' | 'struct';
    exactLengthBytes?: 0;
    fields?: readonly NativeCodecField[];
  }>;
  readonly carrierJoins?: readonly NativeCodecJoin[];
  readonly noTrailingBytes?: true;
}

interface NativeCodecRequestAdapterRoute {
  readonly operationId: 'GPU.requestAdapter';
  readonly wireId: 1660448199;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<{
      payloadPath: 'sealedLocalTimeline' | 'convertedArguments';
      operator: 'exact-empty-sequence' | 'conforms-to-type';
      type?: 'requestAdapterOptionsV1';
    }>[];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    variants: readonly NativeCodecCompletionVariant[];
  }>;
}

interface NativeCodecRequestDeviceRoute {
  readonly operationId: 'GPUAdapter.requestDevice';
  readonly wireId: 194635792;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<Record<string, unknown>>[];
    semanticServiceDerivations: readonly Readonly<Record<string, unknown>>[];
    executablePrerequisites: readonly [
      'generatedLogicalProviderDescriptor',
      'authenticatedResultSelectionIdentity',
    ];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    serviceResultJoins: readonly Readonly<Record<string, unknown>>[];
    variants: readonly Readonly<{
      name:
        | 'live-object'
        | 'detached-not-admitted-object'
        | 'detached-admitted-object';
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
      payloadConstraints: readonly Readonly<Record<string, unknown>>[];
    }>[];
    noTrailingBytes: true;
  }>;
}

interface NativeCodecCreateCommandEncoderRoute {
  readonly operationId: 'GPUDevice.createCommandEncoder';
  readonly wireId: 4055478657;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<Record<string, unknown>>[];
    semanticServiceBoundary: Readonly<Record<string, unknown>>;
    executablePrerequisites: readonly [];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<{ kind: 'empty'; exactLengthBytes: 0 }>;
    semanticTerminalMapping: Readonly<Record<string, unknown>>;
    variants: readonly Readonly<{
      name: 'operation-success';
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
    }>[];
    noTrailingBytes: true;
  }>;
}

interface NativeCodecCreateBindGroupLayoutRoute {
  readonly operationId: 'GPUDevice.createBindGroupLayout';
  readonly wireId: 2544948076;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<Record<string, unknown>>[];
    semanticServiceBoundary: Readonly<Record<string, unknown>>;
    executablePrerequisites: readonly [];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<{ kind: 'empty'; exactLengthBytes: 0 }>;
    semanticTerminalMapping: Readonly<Record<string, unknown>>;
    variants: readonly Readonly<{
      name: 'operation-success';
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
    }>[];
    noTrailingBytes: true;
  }>;
}

interface NativeCodecCreateBindGroupRoute {
  readonly operationId: 'GPUDevice.createBindGroup';
  readonly wireId: 1199806466;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreatePipelineLayoutRoute {
  readonly operationId: 'GPUDevice.createPipelineLayout';
  readonly wireId: 3373402978;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateComputePipelineRoute {
  readonly operationId: 'GPUDevice.createComputePipeline';
  readonly wireId: 2342501516;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateRenderPipelineRoute {
  readonly operationId: 'GPUDevice.createRenderPipeline';
  readonly wireId: 2407151159;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateBufferRoute {
  readonly operationId: 'GPUDevice.createBuffer';
  readonly wireId: 1869756926;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateSamplerRoute {
  readonly operationId: 'GPUDevice.createSampler';
  readonly wireId: 3285037552;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateTextureRoute {
  readonly operationId: 'GPUDevice.createTexture';
  readonly wireId: 4177957718;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateTextureViewRoute {
  readonly operationId: 'GPUTexture.createView';
  readonly wireId: 1853125118;
  readonly request: NativeCodecCreateBindGroupLayoutRoute['request'];
  readonly completion: NativeCodecCreateBindGroupLayoutRoute['completion'];
}

interface NativeCodecCreateShaderModuleRoute {
  readonly operationId: 'GPUDevice.createShaderModule';
  readonly wireId: 599085487;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<Record<string, unknown>>[];
    semanticServiceBoundary: Readonly<Record<string, unknown>>;
    executablePrerequisites: readonly [];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<{ kind: 'empty'; exactLengthBytes: 0 }>;
    semanticTerminalMapping: Readonly<Record<string, unknown>>;
    variants: readonly Readonly<{
      name: 'operation-success';
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
    }>[];
    noTrailingBytes: true;
  }>;
}

interface NativeCodecDeviceDestroyRoute {
  readonly operationId: 'GPUDevice.destroy';
  readonly wireId: 206890944;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<Record<string, unknown>>[];
    semanticServiceBoundary: Readonly<Record<string, unknown>>;
    executablePrerequisites: readonly [];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<{ kind: 'empty'; exactLengthBytes: 0 }>;
    semanticTerminalMapping: Readonly<Record<string, unknown>>;
    variants: readonly Readonly<{
      name: 'repeat-cleanup-noop' | 'first-cleanup-provider';
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
    }>[];
    noTrailingBytes: true;
  }>;
}

interface NativeCodecBufferLifecycleRoute {
  readonly operationId: 'GPUBuffer.destroy' | 'GPUBuffer.mapAsync' | 'GPUBuffer.unmap';
  readonly wireId: 3314731466 | 1760273919 | 1228615721;
  readonly request: Readonly<{
    payloadRole:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    catalog: NativeCodecCatalogReference;
    payload: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    carrierJoins: readonly NativeCodecJoin[];
    carrierConstraints: readonly NativeCodecCarrierConstraint[];
    valueConstraints: readonly Readonly<Record<string, unknown>>[];
    semanticServiceBoundary: Readonly<Record<string, unknown>>;
    executablePrerequisites: readonly [];
    noTrailingBytes: true;
  }>;
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<Record<string, unknown>>;
    semanticTerminalMapping: Readonly<Record<string, unknown>>;
    variants: readonly Readonly<{
      name: string;
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
      serviceResultConstraints?: readonly Readonly<Record<string, unknown>>[];
    }>[];
    carrierJoins?: readonly NativeCodecJoin[];
    serviceResultJoins: readonly Readonly<Record<string, unknown>>[];
    noTrailingBytes: true;
  }>;
}

interface NativeCodecQueueWriteBufferRoute {
  readonly operationId: 'GPUQueue.writeBuffer';
  readonly wireId: 404589710;
  readonly request: NativeCodecBufferLifecycleRoute['request'];
  readonly completion: NativeCodecBufferLifecycleRoute['completion'];
}

interface NativeCodecQueueSubmitRoute {
  readonly operationId: 'GPUQueue.submit';
  readonly wireId: 308839175;
  readonly request: NativeCodecBufferLifecycleRoute['request'];
  readonly completion: NativeCodecBufferLifecycleRoute['completion'];
}

interface NativeCodecCanvasServiceRoute {
  readonly operationId:
    | 'GPUCanvasContext.configure'
    | 'GPUCanvasContext.unconfigure'
    | 'GPUTexture.destroy';
  readonly wireId: 56177326 | 935342475 | 2933046788;
  readonly request: NativeCodecBufferLifecycleRoute['request'];
  readonly completion: Readonly<{
    payloadRole:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    catalog: NativeCodecCatalogReference;
    commonCarrierConstraints: readonly NativeCodecCarrierConstraint[];
    payload: Readonly<Record<string, unknown>>;
    semanticTerminalMapping: Readonly<Record<string, unknown>>;
    variants: readonly Readonly<{
      name: string;
      carrierConstraints: readonly NativeCodecCarrierConstraint[];
      serviceResultConstraints?: readonly Readonly<Record<string, unknown>>[];
    }>[];
    serviceResultJoins?: readonly Readonly<Record<string, unknown>>[];
    noTrailingBytes: true;
  }>;
}

export interface NativeCodecProgramsV2 {
  readonly schema: 'ibex/webgpu-native-codec-programs/2';
  readonly disposition:
    'request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-compute-pipeline-create-render-pipeline-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-canvas-configure-canvas-unconfigure-texture-destroy-queue-write-buffer-queue-submit-native-codec-not-installed-no-support-claim';
  readonly dispatch: Readonly<{
    carrierPath: 'ExactGpuSemanticCallV2.operation_id';
    payloadOperationWireIdRole:
      'constant-and-equality-check-only-never-dispatch';
    payloadCodecTagRole:
      'route-selected-constant-and-equality-check-only-never-dispatch';
  }>;
  readonly scope: Readonly<{
    request:
      'service-request-payload-decoder-plus-operation-specific-call-joins';
    completion:
      'service-completion-payload-codec-plus-operation-specific-event-joins';
    excluded:
      'full-call-or-event-construction-and-global-v2-carrier-validation';
  }>;
  readonly carrierValidationDependency: Readonly<{
    authority: 'ExactGpuSemanticCallV2-and-ExactGpuServiceEventV2';
    requestStructuralValidationMustPrecede:
      'native-request-payload-decode';
    requestStatefulValidationMustPrecede:
      'semantic-execution-and-provider-admission';
    completionEncoderRequires:
      'authenticated-retained-call-plus-service-owned-operation-result';
    completionValidationMustPrecede:
      'completion-payload-decode-and-wrapper-exposure';
    globallyOwnedCarrierInvariants: readonly [
      'exact-struct-size-abi-version-flags-reserved-and-payload-bounds',
      'valid-realm-account-topology-and-authority-context',
      'retained-operation-instance-promise-scope-ordinals-receiver-target-correlation',
      'valid-provider-admission-physical-sequence-and-device-transition-provenance',
      'result-kind-record-size-status-and-payload-shape',
    ];
    programOwns:
      'selected-payload-layout-plus-operation-specific-carrier-joins-and-constraints-only';
  }>;
  readonly constants: Readonly<{
    providerTopologyId: 1;
  }>;
  readonly primitiveEncodings: Readonly<
    Record<NativeCodecPrimitiveName, NativeCodecPrimitiveEncoding>
  >;
  readonly types: Readonly<{
    headerV1: Readonly<{ kind: 'struct'; fields: readonly NativeCodecField[] }>;
    objectReferenceV1: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
    optionalReferenceV1: Readonly<{
      kind: 'optional';
      discriminantType: 'u8';
      absentTag: 0;
      presentTag: 1;
      valueType: 'objectReferenceV1';
    }>;
    canonicalValueV1: Readonly<{
      kind: 'recursive-tagged-union';
      tagType: 'u8';
      maxDepthFrom: 'codecLayout.nestingMaxDepth';
      rootDepth: 0;
      depthLimitOperator: 'less-than-or-equal';
      variants: readonly NativeCodecCanonicalVariant[];
    }>;
    requestAdapterOptionsV1: Readonly<{
      kind: 'closed-dictionary';
      encodingType: 'canonicalValueV1';
      unknownFields: 'reject';
      fields: readonly NativeCodecRequestAdapterOptionField[];
      preEncodingBranches: readonly Readonly<{
        condition: 'featureLevel-not-core-or-compatibility';
        disposition: 'wrapper-local-null-no-service-call';
      }>[];
    }>;
    requestDeviceDescriptorV1: Readonly<Record<string, unknown>>;
    bindGroupDescriptorV1: Readonly<Record<string, unknown>>;
    bindGroupLayoutDescriptorV1: Readonly<Record<string, unknown>>;
    bufferDescriptorV1: Readonly<Record<string, unknown>>;
    pipelineLayoutDescriptorV1: Readonly<Record<string, unknown>>;
    computePipelineDescriptorV1: Readonly<Record<string, unknown>>;
    renderPipelineDescriptorV1: Readonly<Record<string, unknown>>;
    samplerDescriptorV1: Readonly<Record<string, unknown>>;
    textureDescriptorV1: Readonly<Record<string, unknown>>;
    textureViewRequestV1: Readonly<Record<string, unknown>>;
    ownedBytesV1: Readonly<Record<string, unknown>>;
    bufferCleanupRequestBodyV1: Readonly<Record<string, unknown>>;
    bufferMapAsyncRequestBodyV1: Readonly<Record<string, unknown>>;
    bufferMapAsyncCompletionBodyV1: Readonly<Record<string, unknown>>;
    sha256DigestV1: Readonly<Record<string, unknown>>;
    canvasConfigureRequestBodyV1: Readonly<Record<string, unknown>>;
    canvasViewFormatSequenceV1: Readonly<Record<string, unknown>>;
    canvasUnconfigureRequestBodyV1: Readonly<Record<string, unknown>>;
    canvasCurrentTextureOriginV1: Readonly<Record<string, unknown>>;
    textureDestroyRequestBodyV1: Readonly<Record<string, unknown>>;
    queueWriteBufferRequestBodyV1: Readonly<Record<string, unknown>>;
    commandRecordV1: Readonly<Record<string, unknown>>;
    queueSubmitRequestBodyV1: Readonly<Record<string, unknown>>;
    commandEncoderDescriptorV1: Readonly<Record<string, unknown>>;
    shaderModuleDescriptorV1: Readonly<Record<string, unknown>>;
    sortedUniqueFeatureSequenceV1: Readonly<Record<string, unknown>>;
    completeDeviceLimitsV1: Readonly<Record<string, unknown>>;
    gpuDeviceCompletionBodyV1: Readonly<{
      kind: 'struct';
      fields: readonly NativeCodecField[];
    }>;
  }>;
  readonly routes: readonly (
    | NativeCodecRequestAdapterRoute
    | NativeCodecRequestDeviceRoute
    | NativeCodecCreateBindGroupRoute
    | NativeCodecCreateBindGroupLayoutRoute
    | NativeCodecCreateBufferRoute
    | NativeCodecCreatePipelineLayoutRoute
    | NativeCodecCreateComputePipelineRoute
    | NativeCodecCreateRenderPipelineRoute
    | NativeCodecCreateSamplerRoute
    | NativeCodecCreateTextureRoute
    | NativeCodecCreateTextureViewRoute
    | NativeCodecCreateCommandEncoderRoute
    | NativeCodecCreateShaderModuleRoute
    | NativeCodecDeviceDestroyRoute
    | NativeCodecBufferLifecycleRoute
    | NativeCodecCanvasServiceRoute
    | NativeCodecQueueWriteBufferRoute
    | NativeCodecQueueSubmitRoute
  )[];
}

export interface WebGpuCarrierConstants {
  readonly EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2: 1;
  readonly EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2: 2;
  readonly EXACT_GPU_DEVICE_UNCHANGED_V2: 0;
  readonly EXACT_GPU_DEVICE_ASSIGNED_V2: 1;
  readonly EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2: 2;
  readonly EXACT_GPU_PROVIDER_NOT_ADMITTED_V2: 0;
  readonly EXACT_GPU_PROVIDER_ADMITTED_V2: 1;
  readonly EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2: 1;
  readonly EXACT_GPU_BACKEND_NONE_V2: 0;
  readonly EXACT_GPU_RESULT_NONE_V2: 0;
  readonly EXACT_GPU_RESULT_NULL_V2: 2;
  readonly EXACT_GPU_RESULT_OBJECT_V2: 3;
  readonly EXACT_GPU_RESULT_BYTES_V2: 4;
}

export interface ExecutableWebGpuCodecManifest {
  readonly schema: 'ibex/webgpu-executable-codec-manifest/2';
  readonly disposition: string;
  readonly profileId: string;
  readonly scopeId: string;
  readonly operationCount: number;
  readonly operationIds: readonly string[];
  readonly maxPayloadBytes: number;
  readonly byteOrder: string;
  readonly scalarRules: Readonly<Record<string, string>>;
  readonly digests: Readonly<{
    operationSet: string;
    semanticProgramSet: string;
    runtimeRouting: string;
    webgpuCVocabulary: string;
    projection: string;
  }>;
  readonly layout: Readonly<{
    requestMagic: string;
    resultMagic: string;
    lossMagic: string;
    version: number;
    header: string;
    reference: string;
    target: string;
    requestTail: string;
    nullableNullResult: string;
    catalogWireTagRule: string;
    objectKindTagRule: string;
    valueTags: Readonly<{
      null: number;
      false: number;
      true: number;
      u32: number;
      f64: number;
      string: number;
      sequence: number;
      dictionary: number;
    }>;
    diagnosticMaxBytes: number;
    sequenceMaxCount: number;
    dictionaryMaxFields: number;
    nestingMaxDepth: number;
  }>;
  readonly nativeCodecPrograms: NativeCodecProgramsV2;
  readonly objectKindAuthority: Readonly<{
    path: string;
    sha256: string;
  }>;
  readonly objectKindTags: Readonly<Record<string, number>>;
  readonly carrierConstants: WebGpuCarrierConstants;
  readonly webIdlVocabulary: Readonly<{
    bindingPackage: '@webgpu/types';
    bindingPackageVersion: '0.1.71';
    declarationPath: 'node_modules/@webgpu/types/dist/index.d.ts';
    declarationSha256: string;
    gpuFeatureNames: readonly string[];
    gpuTextureFormats: readonly string[];
    gpuTextureFormatCapabilityRowsSha256: string;
    gpuTextureFormatRequiredFeatures: Readonly<Record<string, string | null>>;
    gpuAddressModes: readonly string[];
    gpuFilterModes: readonly string[];
    gpuMipmapFilterModes: readonly string[];
    gpuCompareFunctions: readonly string[];
    gpuTextureDimensions: readonly string[];
    gpuTextureViewDimensions: readonly string[];
  }>;
  readonly publicArguments: readonly CodecCatalogRow[];
  readonly serviceArguments: readonly ServiceCodecCatalogRow[];
  readonly serviceCompletions: readonly CodecCatalogRow[];
  readonly authenticatedPromotions: readonly Readonly<{
    readonly operationId: string;
    readonly sourceDisposition:
      | 'staged-unroutable-no-prototype-member'
      | 'private-wrapper-local-recording-no-dispatch';
    readonly activeDisposition: 'active-private-graduated-route';
    readonly sourceOperationWireId: number;
    readonly sourceOperationSemanticSha256: string;
    readonly sourceWorkloadCohortSha256: string;
    readonly disposition:
      | 'construction-private-route-and-native-codec-public-install-and-support-absent'
      | 'construction-private-command-program-route-and-queue-submit-codec-public-install-and-support-absent';
  }>[];
  readonly postWebIdlPayloadCodegenInputs: readonly [];
  readonly completeLimitNames: readonly string[];
  readonly typeGpuBindGroupWorkloadEvidence: Readonly<{
    readonly corpusSha256: string;
    readonly callCount: 18;
    readonly distinctLayoutCount: 16;
    readonly entryCount: 47;
    readonly resourceKindCounts: Readonly<{
      readonly GPUBufferBinding: 36;
      readonly GPUSampler: 5;
      readonly GPUTextureView: 6;
    }>;
    readonly maximumEntriesPerDescriptor: 5;
    readonly maximumLabelUtf8Bytes: 57;
    readonly workloadCallCounts: Readonly<{
      readonly 'typegpu-genetic-racing': 16;
      readonly 'typegpu-jelly-slider': 2;
    }>;
    readonly workloadDigests: Readonly<Record<string, string>>;
    readonly acceptedWitnesses: readonly Readonly<{
      readonly id: string;
      readonly evidenceSequence: number;
      readonly evidenceTraceOrdinal: number;
      readonly convertedDescriptorCanonicalJson: string;
      readonly convertedDescriptorSha256: string;
      readonly joinedCanonicalJson: string;
      readonly joinedSha256: string;
      readonly witnessCanonicalJson: string;
      readonly witnessSha256: string;
      readonly workloadId: string;
    }>[];
  }>;
}

type ProductionRoute = (typeof WEBGPU_PRODUCTION_PLAN.routes)[number];
type OperationResultEvent = Extract<NativeGpuEventV2, { kind: 1 }>;

type DetachedOperationResultEvent = OperationResultEvent & Readonly<{
  detachedAlreadyLost?: unknown;
  lossReason?: unknown;
  backendClass?: unknown;
}>;

const PRODUCTION_WRAPPER_KINDS = Object.freeze([
  'GPU',
  'GPUAdapter',
  'GPUBindGroup',
  'GPUBindGroupLayout',
  'GPUBuffer',
  'GPUPipelineLayout',
  'GPUSampler',
  'GPUDevice',
  'GPUQueue',
  'GPUTexture',
  'GPUTextureView',
  'GPUShaderModule',
  'GPURenderPipeline',
  'GPUCommandEncoder',
  'GPUComputePipeline',
  'GPUComputePassEncoder',
  'GPURenderPassEncoder',
  'GPUCommandBuffer',
  'GPUQuerySet',
  'GPUCanvasContext',
] as const satisfies readonly ProductionGpuWrapperKind[]);

const REQUEST_ADAPTER_OPERATION_ID = 'GPU.requestAdapter';
const REQUEST_ADAPTER_WIRE_ID = 1660448199;
const REQUEST_ADAPTER_REQUEST_CODEC =
  'gpu-request-adapter-service-request-v1';
const REQUEST_ADAPTER_COMPLETION_CODEC =
  'nullable-gpu-adapter-service-completion-v2';
const REQUEST_DEVICE_OPERATION_ID = 'GPUAdapter.requestDevice';
const REQUEST_DEVICE_WIRE_ID = 194635792;
const REQUEST_DEVICE_REQUEST_CODEC = 'gpu-request-device-service-request-v1';
const REQUEST_DEVICE_COMPLETION_CODEC = 'gpu-device-service-completion-v1';
const CREATE_BIND_GROUP_OPERATION_ID = 'GPUDevice.createBindGroup';
const CREATE_BIND_GROUP_WIRE_ID = 1199806466;
const CREATE_BIND_GROUP_REQUEST_CODEC =
  'gpu-create-bind-group-service-request-v1';
const CREATE_BIND_GROUP_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_BIND_GROUP_LAYOUT_OPERATION_ID =
  'GPUDevice.createBindGroupLayout';
const CREATE_BIND_GROUP_LAYOUT_WIRE_ID = 2544948076;
const CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC =
  'gpu-create-bind-group-layout-service-request-v1';
const CREATE_BIND_GROUP_LAYOUT_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_BUFFER_OPERATION_ID = 'GPUDevice.createBuffer';
const CREATE_BUFFER_WIRE_ID = 1869756926;
const CREATE_BUFFER_MAX_LABEL_UTF8_BYTES = 16_777_017;
const CREATE_BUFFER_REQUEST_CODEC = 'gpu-create-buffer-service-request-v1';
const CREATE_BUFFER_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_SAMPLER_OPERATION_ID = 'GPUDevice.createSampler';
const CREATE_SAMPLER_WIRE_ID = 3285037552;
const CREATE_SAMPLER_REQUEST_CODEC = 'gpu-create-sampler-service-request-v1';
const CREATE_SAMPLER_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_TEXTURE_OPERATION_ID = 'GPUDevice.createTexture';
const CREATE_TEXTURE_WIRE_ID = 4177957718;
const CREATE_TEXTURE_REQUEST_CODEC = 'gpu-create-texture-service-request-v1';
const CREATE_TEXTURE_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_TEXTURE_VIEW_OPERATION_ID = 'GPUTexture.createView';
const CREATE_TEXTURE_VIEW_WIRE_ID = 1853125118;
const CREATE_TEXTURE_VIEW_REQUEST_CODEC =
  'gpu-create-texture-view-service-request-v1';
const CREATE_TEXTURE_VIEW_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_PIPELINE_LAYOUT_OPERATION_ID =
  'GPUDevice.createPipelineLayout';
const CREATE_PIPELINE_LAYOUT_WIRE_ID = 3373402978;
const CREATE_PIPELINE_LAYOUT_REQUEST_CODEC =
  'gpu-create-pipeline-layout-service-request-v1';
const CREATE_PIPELINE_LAYOUT_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_COMPUTE_PIPELINE_OPERATION_ID =
  'GPUDevice.createComputePipeline';
const CREATE_COMPUTE_PIPELINE_WIRE_ID = 2342501516;
const CREATE_COMPUTE_PIPELINE_REQUEST_CODEC =
  'gpu-create-compute-pipeline-service-request-v1';
const CREATE_COMPUTE_PIPELINE_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_RENDER_PIPELINE_OPERATION_ID =
  'GPUDevice.createRenderPipeline';
const CREATE_RENDER_PIPELINE_WIRE_ID = 2407151159;
const CREATE_RENDER_PIPELINE_REQUEST_CODEC =
  'gpu-create-render-pipeline-service-request-v1';
const CREATE_RENDER_PIPELINE_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_COMMAND_ENCODER_OPERATION_ID = 'GPUDevice.createCommandEncoder';
const CREATE_COMMAND_ENCODER_WIRE_ID = 4055478657;
const CREATE_COMMAND_ENCODER_REQUEST_CODEC =
  'gpu-create-command-encoder-service-request-v1';
const CREATE_COMMAND_ENCODER_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CREATE_SHADER_MODULE_OPERATION_ID = 'GPUDevice.createShaderModule';
const CREATE_SHADER_MODULE_WIRE_ID = 599085487;
const CREATE_SHADER_MODULE_REQUEST_CODEC =
  'gpu-create-shader-module-service-request-v1';
const CREATE_SHADER_MODULE_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const DEVICE_DESTROY_OPERATION_ID = 'GPUDevice.destroy';
const DEVICE_DESTROY_WIRE_ID = 206890944;
const DEVICE_DESTROY_REQUEST_CODEC = 'gpu-device-cleanup-service-request-v1';
const DEVICE_DESTROY_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const BUFFER_DESTROY_OPERATION_ID = 'GPUBuffer.destroy';
const BUFFER_DESTROY_WIRE_ID = 3314731466;
const BUFFER_DESTROY_REQUEST_CODEC = 'gpu-buffer-destroy-service-request-v1';
const BUFFER_MAP_ASYNC_OPERATION_ID = 'GPUBuffer.mapAsync';
const BUFFER_MAP_ASYNC_WIRE_ID = 1760273919;
const BUFFER_MAP_ASYNC_REQUEST_CODEC =
  'gpu-buffer-map-async-service-request-v1';
const BUFFER_MAP_ASYNC_COMPLETION_CODEC =
  'gpu-buffer-map-async-service-completion-v1';
const BUFFER_UNMAP_OPERATION_ID = 'GPUBuffer.unmap';
const BUFFER_UNMAP_WIRE_ID = 1228615721;
const BUFFER_UNMAP_REQUEST_CODEC = 'gpu-buffer-unmap-service-request-v1';
const BUFFER_CLEANUP_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const CANVAS_CONFIGURE_OPERATION_ID = 'GPUCanvasContext.configure';
const CANVAS_CONFIGURE_WIRE_ID = 56177326;
const CANVAS_CONFIGURE_REQUEST_CODEC =
  'gpu-canvas-configure-service-request-v1';
const CANVAS_UNCONFIGURE_OPERATION_ID = 'GPUCanvasContext.unconfigure';
const CANVAS_UNCONFIGURE_WIRE_ID = 935342475;
const CANVAS_UNCONFIGURE_REQUEST_CODEC =
  'gpu-canvas-unconfigure-service-request-v1';
const TEXTURE_DESTROY_OPERATION_ID = 'GPUTexture.destroy';
const TEXTURE_DESTROY_WIRE_ID = 2933046788;
const TEXTURE_DESTROY_REQUEST_CODEC = 'gpu-texture-cleanup-service-request-v1';
const CANVAS_CLEANUP_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const QUEUE_WRITE_BUFFER_OPERATION_ID = 'GPUQueue.writeBuffer';
const QUEUE_WRITE_BUFFER_WIRE_ID = 404589710;
const QUEUE_WRITE_BUFFER_REQUEST_CODEC =
  'gpu-queue-write-buffer-service-request-v1';
const QUEUE_WRITE_BUFFER_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const QUEUE_WRITE_BUFFER_FIXED_PAYLOAD_BYTES = 143;
const QUEUE_SUBMIT_OPERATION_ID = 'GPUQueue.submit';
const QUEUE_SUBMIT_WIRE_ID = 308839175;
const QUEUE_SUBMIT_REQUEST_CODEC =
  'gpu-sealed-command-program-sequence-service-request-v1';
const QUEUE_SUBMIT_COMPLETION_CODEC =
  'terminal-receipt-service-completion-v1';
const QUEUE_SUBMIT_RECORD_TABLE_MAX_COUNT = 2_048;
const QUEUE_SUBMIT_PROGRAM_MAX_COUNT = 1_024;
const QUEUE_SUBMIT_PROGRAM_RECORD_MAX_COUNT = 1_024;
const QUEUE_SUBMIT_LOGICAL_ERROR_MAX_BYTES = 4_096;
const QUEUE_SUBMIT_PROGRAM_DIGEST_DOMAIN =
  'exact/webgpu-command-program/v1\0';

const EXPECTED_WEBGPU_CARRIER_CONSTANTS = Object.freeze({
  EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2: 1,
  EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2: 2,
  EXACT_GPU_DEVICE_UNCHANGED_V2: 0,
  EXACT_GPU_DEVICE_ASSIGNED_V2: 1,
  EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2: 2,
  EXACT_GPU_PROVIDER_NOT_ADMITTED_V2: 0,
  EXACT_GPU_PROVIDER_ADMITTED_V2: 1,
  EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2: 1,
  EXACT_GPU_BACKEND_NONE_V2: 0,
  EXACT_GPU_RESULT_NONE_V2: 0,
  EXACT_GPU_RESULT_NULL_V2: 2,
  EXACT_GPU_RESULT_OBJECT_V2: 3,
  EXACT_GPU_RESULT_BYTES_V2: 4,
} as const satisfies WebGpuCarrierConstants);
const EXPECTED_BUFFER_LIFECYCLE_NATIVE_CODEC_SHA256 =
  '371b04e7963c5e5c62c110134573aa4dae3a804389ea0df021c636ea1ec27063';
const EXPECTED_QUEUE_WRITE_BUFFER_NATIVE_CODEC_SHA256 =
  'a04a12cd84364bc18fd85f4aa9d786aa89d1a06abb4110c7b794b2d9404cc104';
const EXPECTED_QUEUE_SUBMIT_NATIVE_CODEC_SHA256 =
  '7384eadbb32ba1bdbf6986661155b6fc5ce91804d78c90c85b491c05e5ce1bf6';
const EXPECTED_CANVAS_NATIVE_CODEC_SHA256 =
  'b23a205fa68b269ecb40b854ebda2a5a91958f1fdfc2d8dfbb6ddeedc3b53068';
const EXPECTED_CREATE_RENDER_PIPELINE_NATIVE_ROUTE_SHA256 =
  '0f1af44238843ba1edc0ca1513c8b732cb72733a3680006be94a3322602919ee';
const EXPECTED_CREATE_COMPUTE_PIPELINE_DESCRIPTOR_SHA256 =
  '1c6145dd069e31da8d4eca2cf765fd40c410d0bde08cdf92b98a3f4a05301943';
const EXPECTED_CREATE_COMPUTE_PIPELINE_NATIVE_ROUTE_SHA256 =
  '9ef551467a581cb5cb10e41e5a6c97e6bb64b3e452cfc5905fdd6ec85c283bdb';

type NativeCodecProgramsWithoutQueueSubmitTypes = Omit<
  NativeCodecProgramsV2,
  'types'
> & {
  readonly types: Omit<
    NativeCodecProgramsV2['types'],
    'commandRecordV1' | 'queueSubmitRequestBodyV1' |
    'computePipelineDescriptorV1' | 'renderPipelineDescriptorV1' |
    'sha256DigestV1' | 'canvasConfigureRequestBodyV1' |
    'canvasViewFormatSequenceV1' |
    'canvasUnconfigureRequestBodyV1' | 'canvasCurrentTextureOriginV1' |
    'textureDestroyRequestBodyV1'
  >;
};

const EXPECTED_COMPLETE_LIMIT_NAMES = Object.freeze([
  'maxTextureDimension1D',
  'maxTextureDimension2D',
  'maxTextureDimension3D',
  'maxTextureArrayLayers',
  'maxBindGroups',
  'maxBindGroupsPlusVertexBuffers',
  'maxBindingsPerBindGroup',
  'maxDynamicUniformBuffersPerPipelineLayout',
  'maxDynamicStorageBuffersPerPipelineLayout',
  'maxSampledTexturesPerShaderStage',
  'maxSamplersPerShaderStage',
  'maxStorageBuffersPerShaderStage',
  'maxStorageBuffersInVertexStage',
  'maxStorageBuffersInFragmentStage',
  'maxStorageTexturesPerShaderStage',
  'maxStorageTexturesInVertexStage',
  'maxStorageTexturesInFragmentStage',
  'maxUniformBuffersPerShaderStage',
  'maxUniformBufferBindingSize',
  'maxStorageBufferBindingSize',
  'minUniformBufferOffsetAlignment',
  'minStorageBufferOffsetAlignment',
  'maxVertexBuffers',
  'maxBufferSize',
  'maxVertexAttributes',
  'maxVertexBufferArrayStride',
  'maxInterStageShaderVariables',
  'maxColorAttachments',
  'maxColorAttachmentBytesPerSample',
  'maxComputeWorkgroupStorageSize',
  'maxComputeInvocationsPerWorkgroup',
  'maxComputeWorkgroupSizeX',
  'maxComputeWorkgroupSizeY',
  'maxComputeWorkgroupSizeZ',
  'maxComputeWorkgroupsPerDimension',
  'maxImmediateSize',
] as const);

const BIND_GROUP_LAYOUT_VIEW_DIMENSIONS = Object.freeze([
  '1d',
  '2d',
  '2d-array',
  'cube',
  'cube-array',
  '3d',
] as const);

const EXPECTED_NATIVE_CODEC_PROGRAM = Object.freeze({
  schema: 'ibex/webgpu-native-codec-programs/2',
  disposition:
    'request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-compute-pipeline-create-render-pipeline-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-canvas-configure-canvas-unconfigure-texture-destroy-queue-write-buffer-queue-submit-native-codec-not-installed-no-support-claim',
  dispatch: {
    carrierPath: 'ExactGpuSemanticCallV2.operation_id',
    payloadOperationWireIdRole:
      'constant-and-equality-check-only-never-dispatch',
    payloadCodecTagRole:
      'route-selected-constant-and-equality-check-only-never-dispatch',
  },
  scope: {
    request:
      'service-request-payload-decoder-plus-operation-specific-call-joins',
    completion:
      'service-completion-payload-codec-plus-operation-specific-event-joins',
    excluded:
      'full-call-or-event-construction-and-global-v2-carrier-validation',
  },
  carrierValidationDependency: {
    authority: 'ExactGpuSemanticCallV2-and-ExactGpuServiceEventV2',
    requestStructuralValidationMustPrecede:
      'native-request-payload-decode',
    requestStatefulValidationMustPrecede:
      'semantic-execution-and-provider-admission',
    completionEncoderRequires:
      'authenticated-retained-call-plus-service-owned-operation-result',
    completionValidationMustPrecede:
      'completion-payload-decode-and-wrapper-exposure',
    globallyOwnedCarrierInvariants: [
      'exact-struct-size-abi-version-flags-reserved-and-payload-bounds',
      'valid-realm-account-topology-and-authority-context',
      'retained-operation-instance-promise-scope-ordinals-receiver-target-correlation',
      'valid-provider-admission-physical-sequence-and-device-transition-provenance',
      'result-kind-record-size-status-and-payload-shape',
    ],
    programOwns:
      'selected-payload-layout-plus-operation-specific-carrier-joins-and-constraints-only',
  },
  constants: {
    providerTopologyId: 1,
  },
  primitiveEncodings: {
    ascii4: { widthBytes: 4, encoding: 'ascii' },
    u8: { widthBytes: 1, encoding: 'unsigned-integer' },
    u16le: {
      widthBytes: 2,
      encoding: 'unsigned-integer',
      byteOrder: 'little-endian',
    },
    u32le: {
      widthBytes: 4,
      encoding: 'unsigned-integer',
      byteOrder: 'little-endian',
    },
    u64le: {
      widthBytes: 8,
      encoding: 'unsigned-integer',
      byteOrder: 'little-endian',
    },
    f64le: {
      widthBytes: 8,
      encoding: 'ieee754-binary64',
      byteOrder: 'little-endian',
      constraints: ['finite'],
    },
    utf8: {
      kind: 'length-prefixed-bytes',
      lengthType: 'u32le',
      encoding: 'utf8',
      constraints: ['well-formed'],
    },
  },
  types: {
    headerV1: {
      kind: 'struct',
      fields: [
        { name: 'magic', type: 'ascii4' },
        { name: 'version', type: 'u16le' },
        { name: 'codecTag', type: 'u16le' },
        { name: 'operationWireId', type: 'u32le' },
      ],
    },
    objectReferenceV1: {
      kind: 'struct',
      fields: [
        { name: 'kind', type: 'u8', catalog: 'objectKindTags' },
        { name: 'objectId', type: 'u64le' },
        { name: 'objectGeneration', type: 'u64le' },
        { name: 'logicalDeviceId', type: 'u64le' },
        { name: 'logicalDeviceGeneration', type: 'u64le' },
        { name: 'providerGeneration', type: 'u64le' },
      ],
    },
    optionalReferenceV1: {
      kind: 'optional',
      discriminantType: 'u8',
      absentTag: 0,
      presentTag: 1,
      valueType: 'objectReferenceV1',
    },
    canonicalValueV1: {
      kind: 'recursive-tagged-union',
      tagType: 'u8',
      maxDepthFrom: 'codecLayout.nestingMaxDepth',
      rootDepth: 0,
      depthLimitOperator: 'less-than-or-equal',
      variants: [
        { name: 'null', tag: 0, payload: { kind: 'empty' } },
        { name: 'false', tag: 1, payload: { kind: 'empty' } },
        { name: 'true', tag: 2, payload: { kind: 'empty' } },
        {
          name: 'u32',
          tag: 3,
          payload: { kind: 'scalar', type: 'u32le' },
        },
        {
          name: 'f64',
          tag: 4,
          payload: { kind: 'scalar', type: 'f64le' },
        },
        {
          name: 'string',
          tag: 5,
          payload: { kind: 'scalar', type: 'utf8' },
        },
        {
          name: 'sequence',
          tag: 6,
          payload: {
            kind: 'sequence',
            countType: 'u32le',
            elementType: 'canonicalValueV1',
            maxCountFrom: 'codecLayout.sequenceMaxCount',
            countLimitOperator: 'less-than-or-equal',
          },
        },
        {
          name: 'dictionary',
          tag: 7,
          payload: {
            kind: 'dictionary',
            countType: 'u32le',
            keyType: 'utf8',
            valueType: 'canonicalValueV1',
            maxCountFrom: 'codecLayout.dictionaryMaxFields',
            countLimitOperator: 'less-than-or-equal',
            keyConstraints: [
              'unique',
              'strictly-increasing-unsigned-utf8-bytes-shorter-prefix-first',
            ],
          },
        },
      ],
    },
    requestAdapterOptionsV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      unknownFields: 'reject',
      fields: [
        {
          name: 'featureLevel',
          required: true,
          value: {
            kind: 'string-enum',
            values: ['core', 'compatibility'],
          },
        },
        {
          name: 'forceFallbackAdapter',
          required: true,
          value: { kind: 'boolean' },
        },
        {
          name: 'powerPreference',
          required: false,
          value: {
            kind: 'string-enum',
            values: ['low-power', 'high-performance'],
          },
        },
        {
          name: 'xrCompatible',
          required: true,
          value: { kind: 'boolean' },
        },
      ],
      preEncodingBranches: [{
        condition: 'featureLevel-not-core-or-compatibility',
        disposition: 'wrapper-local-null-no-service-call',
      }],
    },
    requestDeviceDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        { name: 'label', required: true, value: { kind: 'string' } },
        {
          name: 'requiredFeatures',
          required: true,
          value: {
            kind: 'sequence',
            element: 'string',
            maxCountFrom: 'codecLayout.sequenceMaxCount',
          },
        },
        {
          name: 'requiredLimits',
          required: true,
          value: {
            kind: 'dictionary',
            key: 'string',
            value: 'nonnegative-js-safe-integer',
            maxCountFrom: 'codecLayout.dictionaryMaxFields',
          },
        },
        {
          name: 'defaultQueue',
          required: true,
          value: {
            kind: 'closed-dictionary',
            unknownFields: 'reject',
            fields: [{
              name: 'label',
              required: true,
              value: { kind: 'string' },
            }],
          },
        },
      ],
    },
    bindGroupDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        {
          name: 'label',
          required: true,
          value: { kind: 'string' },
        },
        {
          name: 'entries',
          required: true,
          value: {
            kind: 'sequence',
            minCount: 0,
            maxCountFrom: 'codecLayout.sequenceMaxCount',
            element: {
              kind: 'closed-dictionary',
              unknownFields: 'reject',
              fields: [
                {
                  name: 'binding',
                  required: true,
                  value: { kind: 'u32' },
                },
                {
                  name: 'resource',
                  required: true,
                  value: {
                    kind: 'closed-dictionary',
                    unknownFields: 'reject',
                    fields: [
                      {
                        name: 'resourceKind',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: [
                            'GPUBufferBinding',
                            'GPUSampler',
                            'GPUTextureView',
                            'GPUBuffer',
                            'GPUTexture',
                            'GPUExternalTexture',
                          ],
                        },
                      },
                      {
                        name: 'buffer',
                        required: false,
                        value: {
                          kind: 'full-object-reference',
                          referenceType: 'objectReferenceV1',
                          requiredObjectKind: 'GPUBuffer',
                        },
                      },
                      {
                        name: 'offset',
                        required: false,
                        value: { kind: 'u64' },
                      },
                      {
                        name: 'size',
                        required: false,
                        value: { kind: 'u64' },
                      },
                      {
                        name: 'reference',
                        required: false,
                        value: {
                          kind: 'full-object-reference',
                          referenceType: 'objectReferenceV1',
                          permittedObjectKinds: [
                            'GPUSampler',
                            'GPUTextureView',
                            'GPUBuffer',
                            'GPUTexture',
                            'GPUExternalTexture',
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
          name: 'layout',
          required: true,
          value: {
            kind: 'full-object-reference',
            referenceType: 'objectReferenceV1',
            requiredObjectKind: 'GPUBindGroupLayout',
          },
        },
      ],
    },
    bindGroupLayoutDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        {
          name: 'label',
          required: true,
          value: { kind: 'string' },
        },
        {
          name: 'entries',
          required: true,
          value: {
            kind: 'sequence',
            minCount: 0,
            maxCountFrom: 'codecLayout.sequenceMaxCount',
            element: {
              kind: 'closed-dictionary',
              unknownFields: 'reject',
              fields: [
                {
                  name: 'binding',
                  required: true,
                  value: { kind: 'u32' },
                },
                {
                  name: 'buffer',
                  required: false,
                  value: {
                    kind: 'closed-dictionary',
                    unknownFields: 'reject',
                    fields: [
                      {
                        name: 'hasDynamicOffset',
                        required: true,
                        value: { kind: 'boolean' },
                      },
                      {
                        name: 'minBindingSize',
                        required: true,
                        value: {
                          kind: 'u64',
                          constraints: ['js-safe-integer'],
                        },
                      },
                      {
                        name: 'type',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: ['uniform', 'storage', 'read-only-storage'],
                        },
                      },
                    ],
                  },
                },
                {
                  name: 'externalTexture',
                  required: false,
                  value: {
                    kind: 'closed-dictionary',
                    unknownFields: 'reject',
                    fields: [],
                  },
                },
                {
                  name: 'sampler',
                  required: false,
                  value: {
                    kind: 'closed-dictionary',
                    unknownFields: 'reject',
                    fields: [
                      {
                        name: 'type',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: ['filtering', 'non-filtering', 'comparison'],
                        },
                      },
                    ],
                  },
                },
                {
                  name: 'storageTexture',
                  required: false,
                  value: {
                    kind: 'closed-dictionary',
                    unknownFields: 'reject',
                    fields: [
                      {
                        name: 'access',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: ['write-only', 'read-only', 'read-write'],
                        },
                      },
                      {
                        name: 'format',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          valuesFrom: 'webIdlVocabulary.gpuTextureFormats',
                        },
                      },
                      {
                        name: 'viewDimension',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: BIND_GROUP_LAYOUT_VIEW_DIMENSIONS,
                        },
                      },
                    ],
                  },
                },
                {
                  name: 'texture',
                  required: false,
                  value: {
                    kind: 'closed-dictionary',
                    unknownFields: 'reject',
                    fields: [
                      {
                        name: 'multisampled',
                        required: true,
                        value: { kind: 'boolean' },
                      },
                      {
                        name: 'sampleType',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: [
                            'float',
                            'unfilterable-float',
                            'depth',
                            'sint',
                            'uint',
                          ],
                        },
                      },
                      {
                        name: 'viewDimension',
                        required: true,
                        value: {
                          kind: 'string-enum',
                          values: BIND_GROUP_LAYOUT_VIEW_DIMENSIONS,
                        },
                      },
                    ],
                  },
                },
                {
                  name: 'visibility',
                  required: true,
                  value: { kind: 'u32' },
                },
              ],
            },
          },
        },
      ],
    },
    bufferDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        {
          name: 'label',
          required: true,
          value: {
            kind: 'string',
            constraints: [
              'maximum-utf8-bytes-16777017',
              'shares-total-payload-budget-with-sealed-local-timeline',
            ],
          },
        },
        {
          name: 'mappedAtCreation',
          required: true,
          value: { kind: 'boolean' },
        },
        {
          name: 'size',
          required: true,
          value: {
            kind: 'u64',
            constraints: ['js-safe-integer', 'maximum-268435456'],
          },
        },
        { name: 'usage', required: true, value: { kind: 'u32' } },
      ],
    },
    pipelineLayoutDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        {
          name: 'label',
          required: true,
          value: { kind: 'string' },
        },
        {
          name: 'bindGroupLayouts',
          required: true,
          value: {
            kind: 'sequence',
            minCount: 0,
            maxCountFrom: 'codecLayout.sequenceMaxCount',
            element: {
              kind: 'nullable-full-object-reference',
              nullValue: 'null',
              referenceType: 'objectReferenceV1',
              requiredObjectKind: 'GPUBindGroupLayout',
            },
          },
        },
        {
          name: 'immediateSize',
          required: true,
          value: { kind: 'u32' },
        },
      ],
    },
    samplerDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        { name: 'addressModeU', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuAddressModes' } },
        { name: 'addressModeV', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuAddressModes' } },
        { name: 'addressModeW', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuAddressModes' } },
        { name: 'compare', required: false, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuCompareFunctions' } },
        { name: 'label', required: true, value: { kind: 'string' } },
        { name: 'lodMaxClamp', required: true, value: { kind: 'f64', constraints: ['finite'] } },
        { name: 'lodMinClamp', required: true, value: { kind: 'f64', constraints: ['finite'] } },
        { name: 'magFilter', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuFilterModes' } },
        { name: 'maxAnisotropy', required: true, value: { kind: 'u32', constraints: ['maximum-65535'] } },
        { name: 'minFilter', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuFilterModes' } },
        { name: 'mipmapFilter', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuMipmapFilterModes' } },
      ],
    },
    textureDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        { name: 'dimension', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureDimensions' } },
        { name: 'format', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureFormats' } },
        { name: 'label', required: true, value: { kind: 'string' } },
        { name: 'mipLevelCount', required: true, value: { kind: 'u32' } },
        { name: 'sampleCount', required: true, value: { kind: 'u32' } },
        {
          name: 'size',
          required: true,
          value: {
            kind: 'closed-dictionary',
            unknownFields: 'reject',
            fields: [
              { name: 'depthOrArrayLayers', required: true, value: { kind: 'u32' } },
              { name: 'height', required: true, value: { kind: 'u32' } },
              { name: 'width', required: true, value: { kind: 'u32' } },
            ],
          },
        },
        { name: 'textureBindingViewDimension', required: false, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureViewDimensions' } },
        { name: 'usage', required: true, value: { kind: 'u32' } },
        {
          name: 'viewFormats',
          required: true,
          value: {
            kind: 'sequence',
            maxCountFrom: 'codecLayout.sequenceMaxCount',
            element: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureFormats' },
          },
        },
      ],
    },
    textureViewRequestV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      trust: 'untrusted-webidl-converted-semantic-service-ingress-only',
      providerBoundary: 'forbidden-raw-descriptor-or-origin-must-not-reach-provider',
      unknownFields: 'reject',
      fields: [
        {
          name: 'converted',
          required: true,
          value: {
            kind: 'closed-dictionary',
            unknownFields: 'reject',
            fields: [
              { name: 'arrayLayerCount', required: false, value: { kind: 'u32' } },
              { name: 'aspect', required: true, value: { kind: 'string-enum', values: ['all', 'stencil-only', 'depth-only'] } },
              { name: 'baseArrayLayer', required: true, value: { kind: 'u32' } },
              { name: 'baseMipLevel', required: true, value: { kind: 'u32' } },
              { name: 'dimension', required: false, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureViewDimensions' } },
              { name: 'format', required: false, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureFormats' } },
              { name: 'label', required: true, value: { kind: 'string' } },
              { name: 'mipLevelCount', required: false, value: { kind: 'u32' } },
              { name: 'swizzle', required: true, value: { kind: 'string', constraints: ['texture-component-swizzle-syntax'] } },
              { name: 'usage', required: true, value: { kind: 'u32' } },
            ],
          },
        },
        {
          name: 'currentOrigin',
          required: false,
          value: {
            kind: 'closed-dictionary',
            unknownFields: 'reject',
            fields: [
              { name: 'originClass', required: true, value: { kind: 'string-enum', values: ['canvas-current'] } },
              { name: 'contextRef', required: true, value: { kind: 'full-object-reference' } },
              { name: 'attachmentGeneration', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
              { name: 'contextGeneration', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
              { name: 'configurationGeneration', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
              { name: 'currentEpoch', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
              {
                name: 'mintOperationProvenance',
                required: true,
                value: {
                  kind: 'closed-dictionary',
                  unknownFields: 'reject',
                  fields: [
                    { name: 'operationInstanceId', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
                    { name: 'deviceIngressOrdinal', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
                  ],
                },
              },
              { name: 'textureOriginDigest', required: true, value: { kind: 'string', constraints: ['sha256-hex'] } },
              { name: 'configuredDeviceRef', required: true, value: { kind: 'full-object-reference' } },
              { name: 'format', required: true, value: { kind: 'string-enum', valuesFrom: 'webIdlVocabulary.gpuTextureFormats' } },
              { name: 'usage', required: true, value: { kind: 'u32' } },
              { name: 'alphaMode', required: true, value: { kind: 'string-enum', values: ['opaque', 'premultiplied'] } },
              { name: 'colorSpace', required: true, value: { kind: 'string-enum', values: ['srgb', 'display-p3'] } },
              { name: 'targetAuthorityDigest', required: true, value: { kind: 'string', constraints: ['sha256-hex'] } },
              { name: 'surfaceAccountToken', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
              { name: 'surfaceAccountGeneration', required: true, value: { kind: 'string', constraints: ['positive-u64-canonical-decimal'] } },
            ],
          },
        },
      ],
    },
    commandEncoderDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      unknownFields: 'reject',
      fields: [
        { name: 'label', required: true, value: { kind: 'string' } },
      ],
    },
    shaderModuleDescriptorV1: {
      kind: 'closed-dictionary',
      encodingType: 'canonicalValueV1',
      unknownFields: 'reject',
      fields: [
        { name: 'label', required: true, value: { kind: 'string' } },
        { name: 'code', required: true, value: { kind: 'string' } },
      ],
    },
    sortedUniqueFeatureSequenceV1: {
      kind: 'sequence',
      countType: 'u32le',
      elementType: 'utf8',
      maxCountFrom: 'codecLayout.sequenceMaxCount',
      constraints: ['strictly-increasing-utf8-strings'],
    },
    completeDeviceLimitsV1: {
      kind: 'ordered-record',
      fieldNamesFrom: 'semanticProjection.limitPolicy.limits',
      requiredFieldCount: 36,
      valueType: 'u64le',
      constraints: ['js-safe-integer'],
    },
    gpuDeviceCompletionBodyV1: {
      kind: 'struct',
      fields: [
        { name: 'objectId', type: 'u64le', constraint: 'positive' },
        { name: 'objectGeneration', type: 'u64le', constraint: 'positive' },
        { name: 'logicalDeviceId', type: 'u64le', constraint: 'positive' },
        {
          name: 'logicalDeviceGeneration',
          type: 'u64le',
          constraint: 'positive',
        },
        { name: 'providerGeneration', type: 'u64le', constraint: 'positive' },
        { name: 'queueObjectId', type: 'u64le', constraint: 'positive' },
        {
          name: 'queueObjectGeneration',
          type: 'u64le',
          constraint: 'positive',
        },
        { name: 'features', type: 'sortedUniqueFeatureSequenceV1' },
        { name: 'limits', type: 'completeDeviceLimitsV1' },
        {
          name: 'diagnosticMessage',
          type: 'utf8',
          maxBytesFrom: 'codecLayout.diagnosticMaxBytes',
        },
      ],
    },
    ownedBytesV1: {
      kind: 'length-prefixed-owned-bytes',
      lengthType: 'u64le',
      maxBytesFrom: 'wireEnvelope.maxPayloadBytes',
      ownership: 'affine-transfer-consumed-at-most-once',
    },
    bufferCleanupRequestBodyV1: {
      kind: 'struct',
      fields: [
        { name: 'cleanupAction', type: 'u8' },
        { name: 'cleanupGeneration', type: 'u64le' },
        { name: 'cancelledMapGeneration', type: 'u64le' },
        { name: 'activeMapGeneration', type: 'u64le' },
        { name: 'activeMapMode', type: 'u32le' },
        { name: 'mappedOffset', type: 'u64le' },
        { name: 'mappedSize', type: 'u64le' },
        { name: 'writeback', type: 'ownedBytesV1' },
      ],
      invariants: [
        'cleanupAction-zero-requires-all-generation-range-mode-and-writeback-fields-empty',
        'cleanupAction-nonzero-requires-positive-cleanupGeneration',
        'activeMapGeneration-zero-iff-activeMapMode-offset-size-and-writeback-are-empty',
        'activeMapMode-one-read-requires-empty-writeback',
        'activeMapMode-two-write-requires-writeback-byte-length-equal-mappedSize',
        'cancelledMapGeneration-and-activeMapGeneration-are-source-affine-wrapper-generations',
        'writeback-is-affine-owned-and-consumed-at-most-once-by-cleanupGeneration',
      ],
    },
    bufferMapAsyncRequestBodyV1: {
      kind: 'struct',
      fields: [
        { name: 'pendingMapGeneration', type: 'u64le' },
        { name: 'mode', type: 'u32le' },
        { name: 'offset', type: 'u64le' },
        { name: 'requestedSizePresent', type: 'u8' },
        { name: 'requestedSize', type: 'u64le' },
      ],
      invariants: [
        'pendingMapGeneration-positive-and-source-affine-to-receiver-wrapper',
        'mode-exactly-GPUMapMode-READ-one-or-WRITE-two',
        'requestedSizePresent-zero-requires-requestedSize-zero',
        'offset-and-present-size-preserve-WebIDL-safe-u64-values-without-normalization',
      ],
    },
    bufferMapAsyncCompletionBodyV1: {
      kind: 'tagged-union',
      tag: { name: 'variant', type: 'u8' },
      commonFields: [
        { name: 'pendingMapGeneration', type: 'u64le' },
        { name: 'mode', type: 'u32le' },
        { name: 'offset', type: 'u64le' },
        { name: 'size', type: 'u64le' },
      ],
      variants: [
        { name: 'mapped-bytes', tag: 1, payload: 'ownedBytesV1' },
        { name: 'provider-operation-error', tag: 2, payload: 'empty' },
        { name: 'allocation-range-error', tag: 3, payload: 'empty' },
        { name: 'late-cancelled-cleanup', tag: 4, payload: 'empty' },
      ],
      invariants: [
        'pendingMapGeneration-mode-offset-and-size-join-the-service-owned-accepted-map-result',
        'mapped-bytes-payload-length-equals-size-and-transfers-one-owned-byte-block',
        'failure-and-late-cancelled-variants-carry-zero-owned-bytes',
        'late-cancelled-cleanup-never-settles-the-public-promise-again',
      ],
    },
    queueWriteBufferRequestBodyV1: {
      kind: 'struct',
      fields: [
        { name: 'destination', type: 'objectReferenceV1' },
        { name: 'destinationOffset', type: 'u64le' },
        { name: 'bytes', type: 'ownedBytesV1' },
      ],
      invariants: [
        'destination-is-the-exact-post-WebIDL-GPUBuffer-full-reference',
        'destination-logical-device-and-provider-generations-equal-the-source-queue',
        'destinationOffset-preserves-the-WebIDL-safe-u64-without-alignment-normalization',
        'bytes-are-the-complete-synchronously-selected-source-snapshot',
        'bytes-length-is-a-multiple-of-four-including-zero',
        'bytes-are-affine-owned-by-one-operation-instance-until-terminal-settlement',
        'maximum-bytes-subtract-the-exact-fixed-envelope-and-body-overhead-from-maxPayloadBytes',
      ],
    },
  },
  routes: [{
    operationId: REQUEST_ADAPTER_OPERATION_ID,
    wireId: REQUEST_ADAPTER_WIRE_ID,
    request: {
      payloadRole:
        'service-request-payload-decoder-plus-operation-specific-call-joins',
      catalog: {
        name: 'serviceArguments',
        tag: REQUEST_ADAPTER_REQUEST_CODEC,
        wireTag: 2,
      },
      payload: {
        kind: 'struct',
        fields: [
          {
            name: 'header',
            type: 'headerV1',
            constants: {
              magic: 'IBGQ',
              version: 1,
              codecTag: 2,
              operationWireId: REQUEST_ADAPTER_WIRE_ID,
            },
          },
          { name: 'receiver', type: 'objectReferenceV1' },
          { name: 'target', type: 'optionalReferenceV1' },
          { name: 'capturedScopeId', type: 'u64le' },
          { name: 'adapterOrdinal', type: 'u64le' },
          { name: 'deviceIngressOrdinal', type: 'u64le' },
          { name: 'queueIngressOrdinal', type: 'u64le' },
          { name: 'sealedLocalTimeline', type: 'canonicalValueV1' },
          {
            name: 'convertedArguments',
            type: 'canonicalValueV1',
            constraintType: 'requestAdapterOptionsV1',
          },
        ],
      },
      carrierJoins: [
        {
          payloadPath: 'header.operationWireId',
          carrierPath: 'operation_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.kind',
          carrierPath: 'receiver.kind',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.objectId',
          carrierPath: 'receiver.object_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.objectGeneration',
          carrierPath: 'receiver.object_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.logicalDeviceId',
          carrierPath: 'ingress_device.logical_device_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.logicalDeviceGeneration',
          carrierPath: 'ingress_device.logical_device_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.providerGeneration',
          carrierPath: 'ingress_device.provider_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.providerGeneration',
          carrierPath: 'provider_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'target',
          carrierPath: 'target',
          operator: 'absent-iff-all-zero-reference',
        },
        {
          payloadPath: 'capturedScopeId',
          carrierPath: 'captured_scope_id',
          operator: 'equal',
        },
        {
          payloadPath: 'adapterOrdinal',
          carrierPath: 'adapter_ordinal',
          operator: 'equal',
        },
        {
          payloadPath: 'deviceIngressOrdinal',
          carrierPath: 'device_ingress_ordinal',
          operator: 'equal',
        },
        {
          payloadPath: 'queueIngressOrdinal',
          carrierPath: 'queue_ingress_ordinal',
          operator: 'equal',
        },
      ],
      carrierConstraints: [
        {
          carrierPath: 'operation_id',
          operator: 'equal',
          value: REQUEST_ADAPTER_WIRE_ID,
        },
        { carrierPath: 'flags', operator: 'equal', value: 0 },
        {
          carrierPath: 'topology_id',
          operator: 'equal',
          valueFrom: 'constants.providerTopologyId',
        },
        { carrierPath: 'ingress_device', operator: 'all-zero' },
        {
          carrierPath: 'provider_generation',
          operator: 'equal',
          value: '0',
        },
        { carrierPath: 'operation_instance_id', operator: 'positive' },
        { carrierPath: 'promise_id', operator: 'positive' },
        {
          carrierPath: 'receiver.kind',
          operator: 'equal',
          valueFrom: 'objectKindTags.GPU',
        },
        { carrierPath: 'receiver.flags', operator: 'equal', value: 0 },
        { carrierPath: 'receiver.object_id', operator: 'positive' },
        { carrierPath: 'receiver.object_generation', operator: 'positive' },
        { carrierPath: 'target', operator: 'all-zero' },
        {
          carrierPath: 'captured_scope_id',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'adapter_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'device_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'queue_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
      ],
      valueConstraints: [
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'exact-empty-sequence',
        },
        {
          payloadPath: 'convertedArguments',
          operator: 'conforms-to-type',
          type: 'requestAdapterOptionsV1',
        },
      ],
      noTrailingBytes: true,
    },
    completion: {
      payloadRole:
        'service-completion-payload-codec-plus-operation-specific-event-joins',
      catalog: {
        name: 'serviceCompletions',
        tag: REQUEST_ADAPTER_COMPLETION_CODEC,
        wireTag: 6,
      },
      commonCarrierConstraints: [
        {
          carrierPath: 'kind',
          operator: 'equal',
          value: 1,
          symbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
        },
        {
          carrierPath: 'record.operation_result.status',
          operator: 'equal',
          value: 0,
        },
        {
          carrierPath: 'record.operation_result.operation.operation_id',
          operator: 'equal',
          value: REQUEST_ADAPTER_WIRE_ID,
        },
        {
          carrierPath:
            'record.operation_result.operation.device_transition',
          operator: 'equal',
          value: 0,
          symbol: 'EXACT_GPU_DEVICE_UNCHANGED_V2',
        },
        {
          carrierPath: 'record.operation_result.operation.ingress_device',
          operator: 'all-zero',
        },
        {
          carrierPath: 'record.operation_result.operation.result_device',
          operator: 'all-zero',
        },
      ],
      variants: [
        {
          name: 'null',
          resultKind: 2,
          resultKindSymbol: 'EXACT_GPU_RESULT_NULL_V2',
          payload: { kind: 'empty', exactLengthBytes: 0 },
        },
        {
          name: 'object',
          resultKind: 3,
          resultKindSymbol: 'EXACT_GPU_RESULT_OBJECT_V2',
          objectKind: 'GPUAdapter',
          payload: {
            kind: 'struct',
            fields: [
              {
                name: 'header',
                type: 'headerV1',
                constants: {
                  magic: 'IBGR',
                  version: 1,
                  codecTag: 6,
                  operationWireId: REQUEST_ADAPTER_WIRE_ID,
                },
              },
              { name: 'present', type: 'u8', constant: 1 },
              {
                name: 'objectId',
                type: 'u64le',
                constraint: 'positive',
              },
              {
                name: 'objectGeneration',
                type: 'u64le',
                constraint: 'positive',
              },
              {
                name: 'providerGeneration',
                type: 'u64le',
                constraint: 'positive',
              },
              {
                name: 'serviceDetachedExpired',
                type: 'u8',
                constraint: 'boolean-zero-or-one',
              },
              { name: 'features', type: 'sortedUniqueFeatureSequenceV1' },
            ],
          },
          carrierJoins: [{
            payloadPath: 'providerGeneration',
            carrierPath:
              'record.operation_result.operation.provider_generation',
            operator: 'equal',
          }],
          noTrailingBytes: true,
        },
      ],
    },
  }, {
    operationId: REQUEST_DEVICE_OPERATION_ID,
    wireId: REQUEST_DEVICE_WIRE_ID,
    request: {
      payloadRole:
        'service-request-payload-decoder-plus-operation-specific-call-joins',
      catalog: {
        name: 'serviceArguments',
        tag: REQUEST_DEVICE_REQUEST_CODEC,
        wireTag: 3,
      },
      payload: {
        kind: 'struct',
        fields: [
          {
            name: 'header',
            type: 'headerV1',
            constants: {
              magic: 'IBGQ',
              version: 1,
              codecTag: 3,
              operationWireId: REQUEST_DEVICE_WIRE_ID,
            },
          },
          { name: 'receiver', type: 'objectReferenceV1' },
          { name: 'target', type: 'optionalReferenceV1' },
          { name: 'capturedScopeId', type: 'u64le' },
          { name: 'adapterOrdinal', type: 'u64le' },
          { name: 'deviceIngressOrdinal', type: 'u64le' },
          { name: 'queueIngressOrdinal', type: 'u64le' },
          { name: 'sealedLocalTimeline', type: 'canonicalValueV1' },
          {
            name: 'convertedArguments',
            type: 'canonicalValueV1',
            constraintType: 'requestDeviceDescriptorV1',
          },
        ],
      },
      carrierJoins: [
        {
          payloadPath: 'header.operationWireId',
          carrierPath: 'operation_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.kind',
          carrierPath: 'receiver.kind',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.objectId',
          carrierPath: 'receiver.object_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.objectGeneration',
          carrierPath: 'receiver.object_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.logicalDeviceId',
          carrierPath: 'ingress_device.logical_device_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.logicalDeviceGeneration',
          carrierPath: 'ingress_device.logical_device_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.providerGeneration',
          carrierPath: 'provider_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'target',
          carrierPath: 'target',
          operator: 'absent-iff-all-zero-reference',
        },
        {
          payloadPath: 'capturedScopeId',
          carrierPath: 'captured_scope_id',
          operator: 'equal',
        },
        {
          payloadPath: 'adapterOrdinal',
          carrierPath: 'adapter_ordinal',
          operator: 'equal',
        },
        {
          payloadPath: 'deviceIngressOrdinal',
          carrierPath: 'device_ingress_ordinal',
          operator: 'equal',
        },
        {
          payloadPath: 'queueIngressOrdinal',
          carrierPath: 'queue_ingress_ordinal',
          operator: 'equal',
        },
      ],
      carrierConstraints: [
        {
          carrierPath: 'operation_id',
          operator: 'equal',
          value: REQUEST_DEVICE_WIRE_ID,
        },
        { carrierPath: 'flags', operator: 'equal', value: 0 },
        {
          carrierPath: 'topology_id',
          operator: 'equal',
          valueFrom: 'constants.providerTopologyId',
        },
        { carrierPath: 'ingress_device', operator: 'all-zero' },
        { carrierPath: 'provider_generation', operator: 'positive' },
        { carrierPath: 'operation_instance_id', operator: 'positive' },
        { carrierPath: 'promise_id', operator: 'positive' },
        {
          carrierPath: 'receiver.kind',
          operator: 'equal',
          valueFrom: 'objectKindTags.GPUAdapter',
        },
        { carrierPath: 'receiver.flags', operator: 'equal', value: 0 },
        { carrierPath: 'receiver.object_id', operator: 'positive' },
        { carrierPath: 'receiver.object_generation', operator: 'positive' },
        { carrierPath: 'target', operator: 'all-zero' },
        { carrierPath: 'captured_scope_id', operator: 'equal', value: '0' },
        { carrierPath: 'adapter_ordinal', operator: 'positive' },
        {
          carrierPath: 'device_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'queue_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
      ],
      valueConstraints: [
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'exact-empty-sequence',
        },
        {
          payloadPath: 'convertedArguments',
          operator: 'conforms-to-type',
          type: 'requestDeviceDescriptorV1',
        },
        {
          payloadPath: 'convertedArguments',
          operator:
            'untrusted-semantic-service-ingress-only-never-provider-input',
        },
      ],
      semanticServiceDerivations: [
        {
          name: 'generatedLogicalProviderDescriptor',
          ownership:
            'native-semantic-service-derived-never-payload-or-wrapper-supplied',
          inputs: [
            'untrusted-convertedArguments',
            'authenticated-adapter-state',
            'authenticated-feature-level-profile',
            'authenticated-capability-grant',
            'versioned-service-internal-requirements',
          ],
          output:
            'exact-logical-features-limits-plus-versioned-service-internal-requirements-only',
          forbiddenProviderInputs: [
            'convertedArguments',
            'raw-GPUDeviceDescriptor',
          ],
          requiredBefore: ['provider-admission'],
          authenticatedCrossLinks: [
            {
              derivedPath: 'providerGeneration',
              carrierPath: 'provider_generation',
              operator: 'equal',
            },
            {
              derivedPath: 'adapterIdentity',
              carrierPath: 'receiver',
              operator: 'derived-from-authenticated-reference',
            },
          ],
        },
        {
          name: 'authenticatedResultSelectionIdentity',
          ownership:
            'native-semantic-service-allocated-never-payload-or-wrapper-supplied',
          inputs: [
            'authenticated-retained-call',
            'live-device-reservation',
            'authenticated-adapter-publication-credit',
            'authenticated-account-capacity-state',
          ],
          output: 'fresh-device-object-logical-device-and-queue-identities',
          requiredBefore: ['provider-admission', 'completion-encoding'],
          authenticatedCrossLinks: [
            {
              derivedPath: 'logicalDeviceId',
              carrierPath:
                'record.operation_result.operation.result_device.logical_device_id',
              operator: 'equal',
            },
            {
              derivedPath: 'logicalDeviceGeneration',
              carrierPath:
                'record.operation_result.operation.result_device.logical_device_generation',
              operator: 'equal',
            },
            {
              derivedPath: 'providerGeneration',
              carrierPath:
                'record.operation_result.operation.result_device.provider_generation',
              operator: 'equal',
            },
            {
              derivedPath: 'retainedOperationIdentity',
              carrierPath:
                'record.operation_result.operation.operation_instance_id',
              operator: 'bound-to-authenticated-retained-call',
            },
            {
              derivedPath: 'retainedPromiseIdentity',
              carrierPath: 'record.operation_result.operation.promise_id',
              operator: 'bound-to-authenticated-retained-call',
            },
          ],
        },
      ],
      executablePrerequisites: [
        'generatedLogicalProviderDescriptor',
        'authenticatedResultSelectionIdentity',
      ],
      noTrailingBytes: true,
    },
    completion: {
      payloadRole:
        'service-completion-payload-codec-plus-operation-specific-event-joins',
      catalog: {
        name: 'serviceCompletions',
        tag: REQUEST_DEVICE_COMPLETION_CODEC,
        wireTag: 4,
      },
      commonCarrierConstraints: [
        {
          carrierPath: 'kind',
          operator: 'equal',
          value: 1,
          symbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
        },
        {
          carrierPath: 'record.operation_result.status',
          operator: 'equal',
          value: 0,
        },
        {
          carrierPath: 'record.operation_result.operation.operation_id',
          operator: 'equal',
          value: REQUEST_DEVICE_WIRE_ID,
        },
        {
          carrierPath: 'record.operation_result.operation.ingress_device',
          operator: 'all-zero',
        },
        {
          carrierPath: 'record.operation_result.operation.result_device',
          operator: 'positive',
        },
        {
          carrierPath:
            'record.operation_result.operation.provider_generation',
          operator: 'positive',
        },
        {
          carrierPath: 'record.operation_result.operation.receiver.kind',
          operator: 'equal',
          valueFrom: 'objectKindTags.GPUAdapter',
        },
        {
          carrierPath: 'record.operation_result.operation.target',
          operator: 'all-zero',
        },
        {
          carrierPath: 'record.operation_result.operation.adapter_ordinal',
          operator: 'positive',
        },
        {
          carrierPath:
            'record.operation_result.operation.device_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath:
            'record.operation_result.operation.queue_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'record.operation_result.result_kind',
          operator: 'equal',
          value: 3,
          symbol: 'EXACT_GPU_RESULT_OBJECT_V2',
        },
      ],
      payload: {
        kind: 'struct',
        fields: [
          {
            name: 'header',
            type: 'headerV1',
            constants: {
              magic: 'IBGR',
              version: 1,
              codecTag: 4,
              operationWireId: REQUEST_DEVICE_WIRE_ID,
            },
          },
          { name: 'body', type: 'gpuDeviceCompletionBodyV1' },
        ],
      },
      carrierJoins: [
        {
          payloadPath: 'body.logicalDeviceId',
          carrierPath:
            'record.operation_result.operation.result_device.logical_device_id',
          operator: 'equal',
        },
        {
          payloadPath: 'body.logicalDeviceGeneration',
          carrierPath:
            'record.operation_result.operation.result_device.logical_device_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'body.providerGeneration',
          carrierPath:
            'record.operation_result.operation.result_device.provider_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'body.providerGeneration',
          carrierPath:
            'record.operation_result.operation.provider_generation',
          operator: 'equal',
        },
      ],
      serviceResultJoins: [
        {
          payloadPath: 'body.objectId',
          serviceResultPath:
            'authenticatedResultSelectionIdentity.deviceObjectId',
          operator: 'equal',
        },
        {
          payloadPath: 'body.objectGeneration',
          serviceResultPath:
            'authenticatedResultSelectionIdentity.deviceObjectGeneration',
          operator: 'equal',
        },
        {
          payloadPath: 'body.queueObjectId',
          serviceResultPath:
            'authenticatedResultSelectionIdentity.queueObjectId',
          operator: 'equal',
        },
        {
          payloadPath: 'body.queueObjectGeneration',
          serviceResultPath:
            'authenticatedResultSelectionIdentity.queueObjectGeneration',
          operator: 'equal',
        },
        {
          payloadPath: 'body.features',
          serviceResultPath:
            'generatedLogicalProviderDescriptor.logicalFeatures',
          operator: 'equal',
        },
        {
          payloadPath: 'body.limits',
          serviceResultPath: 'generatedLogicalProviderDescriptor.logicalLimits',
          operator: 'equal',
        },
        {
          payloadPath: 'body.diagnosticMessage',
          serviceResultPath: 'nativeSemanticServiceResult.diagnosticMessage',
          operator: 'equal-never-caller-selected',
        },
      ],
      variants: [
        {
          name: 'live-object',
          carrierConstraints: [
            {
              carrierPath:
                'record.operation_result.operation.device_transition',
              operator: 'equal',
              value: 1,
              symbol: 'EXACT_GPU_DEVICE_ASSIGNED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.provider_admission',
              operator: 'equal',
              value: 1,
              symbol: 'EXACT_GPU_PROVIDER_ADMITTED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.physical_sequence',
              operator: 'positive',
            },
            {
              carrierPath: 'detachedAlreadyLost',
              operator: 'equal',
              value: false,
            },
            {
              carrierPath: 'lossReason-and-backendClass',
              operator: 'absent',
            },
          ],
          payloadConstraints: [{
            payloadPath: 'body.diagnosticMessage',
            operator: 'exact-empty-string',
          }],
        },
        {
          name: 'detached-not-admitted-object',
          carrierConstraints: [
            {
              carrierPath:
                'record.operation_result.operation.device_transition',
              operator: 'equal',
              value: 2,
              symbol: 'EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.provider_admission',
              operator: 'equal',
              value: 0,
              symbol: 'EXACT_GPU_PROVIDER_NOT_ADMITTED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.physical_sequence',
              operator: 'equal',
              value: '0',
            },
            {
              carrierPath: 'detachedAlreadyLost',
              operator: 'equal',
              value: true,
            },
            {
              carrierPath: 'lossReason',
              operator: 'equal',
              value: 1,
              symbol: 'EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2',
            },
            {
              carrierPath: 'backendClass',
              operator: 'equal',
              value: 0,
              symbol: 'EXACT_GPU_BACKEND_NONE_V2',
            },
          ],
          payloadConstraints: [{
            payloadPath: 'body.diagnosticMessage',
            operator:
              'native-semantic-service-owned-stable-utf8-within-reviewed-bound',
          }],
        },
        {
          name: 'detached-admitted-object',
          carrierConstraints: [
            {
              carrierPath:
                'record.operation_result.operation.device_transition',
              operator: 'equal',
              value: 2,
              symbol: 'EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.provider_admission',
              operator: 'equal',
              value: 1,
              symbol: 'EXACT_GPU_PROVIDER_ADMITTED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.physical_sequence',
              operator: 'positive',
            },
            {
              carrierPath: 'detachedAlreadyLost',
              operator: 'equal',
              value: true,
            },
            {
              carrierPath: 'lossReason',
              operator: 'equal',
              value: 1,
              symbol: 'EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2',
            },
            {
              carrierPath: 'backendClass',
              operator: 'equal',
              value: 0,
              symbol: 'EXACT_GPU_BACKEND_NONE_V2',
            },
          ],
          payloadConstraints: [{
            payloadPath: 'body.diagnosticMessage',
            operator:
              'native-semantic-service-owned-stable-utf8-within-reviewed-bound',
          }],
        },
      ],
      noTrailingBytes: true,
    },
  }, {
    operationId: DEVICE_DESTROY_OPERATION_ID,
    wireId: DEVICE_DESTROY_WIRE_ID,
    request: {
      payloadRole:
        'service-request-payload-decoder-plus-operation-specific-call-joins',
      catalog: {
        name: 'serviceArguments',
        tag: DEVICE_DESTROY_REQUEST_CODEC,
        wireTag: 12,
      },
      payload: {
        kind: 'struct',
        fields: [
          {
            name: 'header',
            type: 'headerV1',
            constants: {
              magic: 'IBGQ',
              version: 1,
              codecTag: 12,
              operationWireId: DEVICE_DESTROY_WIRE_ID,
            },
          },
          { name: 'receiver', type: 'objectReferenceV1' },
          { name: 'target', type: 'optionalReferenceV1' },
          { name: 'capturedScopeId', type: 'u64le' },
          { name: 'adapterOrdinal', type: 'u64le' },
          { name: 'deviceIngressOrdinal', type: 'u64le' },
          { name: 'queueIngressOrdinal', type: 'u64le' },
          { name: 'sealedLocalTimeline', type: 'canonicalValueV1' },
          { name: 'convertedArguments', type: 'canonicalValueV1' },
        ],
      },
      carrierJoins: [
        {
          payloadPath: 'header.operationWireId',
          carrierPath: 'operation_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.kind',
          carrierPath: 'receiver.kind',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.objectId',
          carrierPath: 'receiver.object_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.objectGeneration',
          carrierPath: 'receiver.object_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.logicalDeviceId',
          carrierPath: 'ingress_device.logical_device_id',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.logicalDeviceGeneration',
          carrierPath: 'ingress_device.logical_device_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.providerGeneration',
          carrierPath: 'ingress_device.provider_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'receiver.providerGeneration',
          carrierPath: 'provider_generation',
          operator: 'equal',
        },
        {
          payloadPath: 'target',
          carrierPath: 'target',
          operator: 'absent-iff-all-zero-reference',
        },
        {
          payloadPath: 'capturedScopeId',
          carrierPath: 'captured_scope_id',
          operator: 'equal',
        },
        {
          payloadPath: 'adapterOrdinal',
          carrierPath: 'adapter_ordinal',
          operator: 'equal',
        },
        {
          payloadPath: 'deviceIngressOrdinal',
          carrierPath: 'device_ingress_ordinal',
          operator: 'equal',
        },
        {
          payloadPath: 'queueIngressOrdinal',
          carrierPath: 'queue_ingress_ordinal',
          operator: 'equal',
        },
      ],
      carrierConstraints: [
        {
          carrierPath: 'operation_id',
          operator: 'equal',
          value: DEVICE_DESTROY_WIRE_ID,
        },
        { carrierPath: 'flags', operator: 'equal', value: 0 },
        {
          carrierPath: 'topology_id',
          operator: 'equal',
          valueFrom: 'constants.providerTopologyId',
        },
        { carrierPath: 'ingress_device', operator: 'positive' },
        { carrierPath: 'provider_generation', operator: 'positive' },
        { carrierPath: 'operation_instance_id', operator: 'positive' },
        { carrierPath: 'promise_id', operator: 'equal', value: '0' },
        {
          carrierPath: 'receiver.kind',
          operator: 'equal',
          valueFrom: 'objectKindTags.GPUDevice',
        },
        { carrierPath: 'receiver.flags', operator: 'equal', value: 0 },
        { carrierPath: 'receiver.object_id', operator: 'positive' },
        { carrierPath: 'receiver.object_generation', operator: 'positive' },
        { carrierPath: 'target', operator: 'all-zero' },
        { carrierPath: 'adapter_ordinal', operator: 'equal', value: '0' },
        { carrierPath: 'device_ingress_ordinal', operator: 'positive' },
        {
          carrierPath: 'queue_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
      ],
      valueConstraints: [
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'canonical-sequence-within-layout-bounds',
        },
        {
          payloadPath: 'sealedLocalTimeline',
          operator:
            'untrusted-wrapper-record-prefix-join-only-never-authority',
        },
        {
          payloadPath: 'convertedArguments',
          operator: 'exact-null',
        },
      ],
      semanticServiceBoundary: {
        stateAuthority:
          'authenticated-device-lifecycle-operation-and-provider-tables',
        payloadRole: 'comparison-input-only-never-authority',
        requiredAfterDecode: [
          'authenticate-contiguous-sealed-local-timeline-prefix',
          'validate-idempotent-device-terminal-state',
          'validate-cleanup-predicates',
          'select-provider-admission-and-physical-sequence',
        ],
        completionEncodingRequires: [
          'authenticated-retained-call',
          'service-owned-operation-result',
        ],
      },
      executablePrerequisites: [],
      noTrailingBytes: true,
    },
    completion: {
      payloadRole:
        'service-completion-payload-codec-plus-operation-specific-event-joins',
      catalog: {
        name: 'serviceCompletions',
        tag: DEVICE_DESTROY_COMPLETION_CODEC,
        wireTag: 2,
      },
      commonCarrierConstraints: [
        {
          carrierPath: 'kind',
          operator: 'equal',
          value: 1,
          symbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
        },
        {
          carrierPath: 'record.operation_result.status',
          operator: 'equal',
          value: 0,
        },
        {
          carrierPath: 'record.operation_result.operation.operation_id',
          operator: 'equal',
          value: DEVICE_DESTROY_WIRE_ID,
        },
        {
          carrierPath: 'record.operation_result.operation.device_transition',
          operator: 'equal',
          value: 0,
          symbol: 'EXACT_GPU_DEVICE_UNCHANGED_V2',
        },
        {
          carrierPath: 'record.operation_result.operation.ingress_device',
          operator: 'positive',
        },
        {
          carrierPath: 'record.operation_result.operation.result_device',
          operator: 'positive',
        },
        {
          carrierPath:
            'record.operation_result.operation.provider_generation',
          operator: 'positive',
        },
        {
          carrierPath: 'record.operation_result.operation.promise_id',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'record.operation_result.operation.receiver.kind',
          operator: 'equal',
          valueFrom: 'objectKindTags.GPUDevice',
        },
        {
          carrierPath: 'record.operation_result.operation.target',
          operator: 'all-zero',
        },
        {
          carrierPath: 'record.operation_result.operation.adapter_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath:
            'record.operation_result.operation.device_ingress_ordinal',
          operator: 'positive',
        },
        {
          carrierPath:
            'record.operation_result.operation.queue_ingress_ordinal',
          operator: 'equal',
          value: '0',
        },
        {
          carrierPath: 'record.operation_result.result_kind',
          operator: 'equal',
          value: 0,
          symbol: 'EXACT_GPU_RESULT_NONE_V2',
        },
      ],
      payload: { kind: 'empty', exactLengthBytes: 0 },
      semanticTerminalMapping: {
        authorityPath:
          'semanticProjection.providerRoutingPrograms[operationId=GPUDevice.destroy]',
        terminals: [
          {
            terminalId: 'repeat-cleanup-noop',
            errorTiming: 'none',
            resultDisposition: 'return-undefined',
            providerTokenCount: 0,
            physicalSequenceCount: 0,
            event: {
              kind: 'operation-result',
              kindValue: 1,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
              resultKind: 0,
              resultKindSymbol: 'EXACT_GPU_RESULT_NONE_V2',
              status: 0,
              completionVariant: 'repeat-cleanup-noop',
            },
          },
          {
            terminalId: 'first-cleanup-rejection',
            errorTiming: 'device-timeline',
            resultDisposition: 'return-undefined-and-report-error',
            providerTokenCount: 0,
            physicalSequenceCount: 0,
            event: {
              kind: 'device-error',
              kindValue: 2,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2',
              completionPayloadEncoderEligibility:
                'excluded-not-an-operation-result',
            },
          },
          {
            terminalId: 'first-cleanup-provider',
            errorTiming: 'none',
            resultDisposition: 'return-undefined',
            providerTokenCount: 1,
            physicalSequenceCount: 1,
            event: {
              kind: 'operation-result',
              kindValue: 1,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
              resultKind: 0,
              resultKindSymbol: 'EXACT_GPU_RESULT_NONE_V2',
              status: 0,
              completionVariant: 'first-cleanup-provider',
            },
          },
        ],
      },
      variants: [
        {
          name: 'repeat-cleanup-noop',
          carrierConstraints: [
            {
              carrierPath:
                'record.operation_result.operation.provider_admission',
              operator: 'equal',
              value: 0,
              symbol: 'EXACT_GPU_PROVIDER_NOT_ADMITTED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.physical_sequence',
              operator: 'equal',
              value: '0',
            },
          ],
        },
        {
          name: 'first-cleanup-provider',
          carrierConstraints: [
            {
              carrierPath:
                'record.operation_result.operation.provider_admission',
              operator: 'equal',
              value: 1,
              symbol: 'EXACT_GPU_PROVIDER_ADMITTED_V2',
            },
            {
              carrierPath:
                'record.operation_result.operation.physical_sequence',
              operator: 'positive',
            },
          ],
        },
      ],
      noTrailingBytes: true,
    },
  }],
} as const satisfies NativeCodecProgramsWithoutQueueSubmitTypes);

const VERTEX_FORMATS = Object.freeze([
  'uint8',
  'uint8x2',
  'uint8x4',
  'sint8',
  'sint8x2',
  'sint8x4',
  'unorm8',
  'unorm8x2',
  'unorm8x4',
  'snorm8',
  'snorm8x2',
  'snorm8x4',
  'uint16',
  'uint16x2',
  'uint16x4',
  'sint16',
  'sint16x2',
  'sint16x4',
  'unorm16',
  'unorm16x2',
  'unorm16x4',
  'snorm16',
  'snorm16x2',
  'snorm16x4',
  'float16',
  'float16x2',
  'float16x4',
  'float32',
  'float32x2',
  'float32x3',
  'float32x4',
  'uint32',
  'uint32x2',
  'uint32x3',
  'uint32x4',
  'sint32',
  'sint32x2',
  'sint32x3',
  'sint32x4',
  'unorm10-10-10-2',
  'unorm8x4-bgra',
]);

const BLEND_FACTORS = Object.freeze([
  'zero',
  'one',
  'src',
  'one-minus-src',
  'src-alpha',
  'one-minus-src-alpha',
  'dst',
  'one-minus-dst',
  'dst-alpha',
  'one-minus-dst-alpha',
  'src-alpha-saturated',
  'constant',
  'one-minus-constant',
  'src1',
  'one-minus-src1',
  'src1-alpha',
  'one-minus-src1-alpha',
]);

const COMPARE_FUNCTIONS = Object.freeze([
  'never',
  'less',
  'equal',
  'less-equal',
  'greater',
  'not-equal',
  'greater-equal',
  'always',
]);

const STENCIL_OPERATIONS = Object.freeze([
  'keep',
  'zero',
  'replace',
  'invert',
  'increment-clamp',
  'decrement-clamp',
  'increment-wrap',
  'decrement-wrap',
]);

function isObjectLike(value: unknown): value is Record<PropertyKey, unknown> {
  return (typeof value === 'object' && value !== null) ||
    typeof value === 'function';
}

function canonicalManifestJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalManifestJson(entry)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) =>
        `${JSON.stringify(key)}:${canonicalManifestJson(
          (value as Readonly<Record<string, unknown>>)[key],
        )}`)
      .join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) {
    throw new TypeError('Generated WebGPU codec manifest is not JSON-safe');
  }
  return encoded;
}

const SHA256_INITIAL_STATE = Object.freeze([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const SHA256_ROUND_CONSTANTS = Object.freeze([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotateRight32(value: number, count: number): number {
  return ((value >>> count) | (value << (32 - count))) >>> 0;
}

function sha256Bytes(input: Uint8Array): Uint8Array {
  const bitLength = input.length * 8;
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(input);
  padded[input.length] = 0x80;
  const paddedView = new DataView(padded.buffer);
  paddedView.setUint32(paddedLength - 8, Math.floor(bitLength / 0x1_0000_0000), false);
  paddedView.setUint32(paddedLength - 4, bitLength >>> 0, false);

  const state = SHA256_INITIAL_STATE.slice();
  const words = new Uint32Array(64);
  for (let offset = 0; offset < paddedLength; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      words[index] = paddedView.getUint32(offset + index * 4, false);
    }
    for (let index = 16; index < 64; index += 1) {
      const left = words[index - 15];
      const right = words[index - 2];
      const sigma0 = rotateRight32(left, 7) ^ rotateRight32(left, 18) ^
        (left >>> 3);
      const sigma1 = rotateRight32(right, 17) ^ rotateRight32(right, 19) ^
        (right >>> 10);
      words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let index = 0; index < 64; index += 1) {
      const sum1 = rotateRight32(e, 6) ^ rotateRight32(e, 11) ^
        rotateRight32(e, 25);
      const choose = (e & f) ^ (~e & g);
      const temporary1 = (h + sum1 + choose + SHA256_ROUND_CONSTANTS[index] +
        words[index]) >>> 0;
      const sum0 = rotateRight32(a, 2) ^ rotateRight32(a, 13) ^
        rotateRight32(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temporary2 = (sum0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temporary1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temporary1 + temporary2) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
  }
  const digest = new Uint8Array(32);
  const digestView = new DataView(digest.buffer);
  for (let index = 0; index < state.length; index += 1) {
    digestView.setUint32(index * 4, state[index], false);
  }
  return digest;
}

function bytesHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function sha256HexUtf8(value: string): string {
  return bytesHex(sha256Bytes(encodeUtf8(value)));
}

interface ValidatedNativeCodecProgram {
  readonly route: NativeCodecRequestAdapterRoute;
  readonly requestDeviceRoute: NativeCodecRequestDeviceRoute;
  readonly createBindGroupRoute: NativeCodecCreateBindGroupRoute;
  readonly createBindGroupLayoutRoute: NativeCodecCreateBindGroupLayoutRoute;
  readonly createBufferRoute: NativeCodecCreateBufferRoute;
  readonly createPipelineLayoutRoute: NativeCodecCreatePipelineLayoutRoute;
  readonly createComputePipelineRoute: NativeCodecCreateComputePipelineRoute;
  readonly createRenderPipelineRoute: NativeCodecCreateRenderPipelineRoute;
  readonly createSamplerRoute: NativeCodecCreateSamplerRoute;
  readonly createTextureRoute: NativeCodecCreateTextureRoute;
  readonly createTextureViewRoute: NativeCodecCreateTextureViewRoute;
  readonly createCommandEncoderRoute: NativeCodecCreateCommandEncoderRoute;
  readonly createShaderModuleRoute: NativeCodecCreateShaderModuleRoute;
  readonly deviceDestroyRoute: NativeCodecDeviceDestroyRoute;
  readonly bufferDestroyRoute: NativeCodecBufferLifecycleRoute;
  readonly bufferMapAsyncRoute: NativeCodecBufferLifecycleRoute;
  readonly bufferUnmapRoute: NativeCodecBufferLifecycleRoute;
  readonly canvasConfigureRoute: NativeCodecCanvasServiceRoute;
  readonly canvasUnconfigureRoute: NativeCodecCanvasServiceRoute;
  readonly textureDestroyRoute: NativeCodecCanvasServiceRoute;
  readonly queueWriteBufferRoute: NativeCodecQueueWriteBufferRoute;
  readonly queueSubmitRoute: NativeCodecQueueSubmitRoute;
  readonly noneResultKind: 0;
  readonly nullResultKind: 2;
  readonly objectResultKind: 3;
  readonly bytesResultKind: 4;
  readonly operationResultEventKind: 1;
  readonly unchangedDeviceTransition: 0;
  readonly assignedDeviceTransition: 1;
  readonly assignedDetachedDeviceTransition: 2;
  readonly providerNotAdmitted: 0;
  readonly providerAdmitted: 1;
}

function validateTypeGpuBindGroupWorkloadEvidence(
  manifest: ExecutableWebGpuCodecManifest,
): void {
  const evidence = manifest.typeGpuBindGroupWorkloadEvidence;
  if (
    evidence?.callCount !== 18 ||
    evidence.distinctLayoutCount !== 16 ||
    evidence.entryCount !== 47 ||
    evidence.maximumEntriesPerDescriptor !== 5 ||
    evidence.maximumLabelUtf8Bytes !== 57 ||
    evidence.resourceKindCounts.GPUBufferBinding !== 36 ||
    evidence.resourceKindCounts.GPUSampler !== 5 ||
    evidence.resourceKindCounts.GPUTextureView !== 6 ||
    evidence.workloadCallCounts['typegpu-genetic-racing'] !== 16 ||
    evidence.workloadCallCounts['typegpu-jelly-slider'] !== 2 ||
    !/^[0-9a-f]{64}$/u.test(evidence.corpusSha256) ||
    !Object.values(evidence.workloadDigests).every(
      (digest) => /^[0-9a-f]{64}$/u.test(digest),
    ) ||
    evidence.acceptedWitnesses.length !== 18
  ) {
    throw new Error('Invalid generated TypeGPU bind-group workload evidence');
  }
  const resourceCounts = new Map<string, number>();
  const workloadCounts = new Map<string, number>();
  const layoutDescriptors = new Set<string>();
  let entryCount = 0;
  let maximumEntries = 0;
  let maximumLabelBytes = 0;
  for (const witness of evidence.acceptedWitnesses) {
    if (
      !/^[0-9a-f]{64}$/u.test(witness.convertedDescriptorSha256) ||
      !/^[0-9a-f]{64}$/u.test(witness.joinedSha256) ||
      !/^[0-9a-f]{64}$/u.test(witness.witnessSha256) ||
      sha256HexUtf8(witness.convertedDescriptorCanonicalJson) !==
        witness.convertedDescriptorSha256 ||
      sha256HexUtf8(witness.joinedCanonicalJson) !== witness.joinedSha256 ||
      sha256HexUtf8(witness.witnessCanonicalJson) !== witness.witnessSha256
    ) {
      throw new Error('Invalid generated TypeGPU bind-group full witness digest');
    }
    let convertedParsed: unknown;
    let joinedParsed: unknown;
    let witnessParsed: unknown;
    try {
      convertedParsed = JSON.parse(witness.convertedDescriptorCanonicalJson);
      joinedParsed = JSON.parse(witness.joinedCanonicalJson);
      witnessParsed = JSON.parse(witness.witnessCanonicalJson);
    } catch {
      throw new Error('Invalid generated TypeGPU bind-group full witness JSON');
    }
    if (
      canonicalManifestJson(convertedParsed) !==
        witness.convertedDescriptorCanonicalJson ||
      canonicalManifestJson(joinedParsed) !== witness.joinedCanonicalJson ||
      canonicalManifestJson(witnessParsed) !== witness.witnessCanonicalJson ||
      canonicalManifestJson({
        convertedDescriptor: convertedParsed,
        joined: joinedParsed,
      }) !== witness.witnessCanonicalJson ||
      typeof convertedParsed !== 'object' ||
      convertedParsed === null ||
      Array.isArray(convertedParsed) ||
      typeof joinedParsed !== 'object' ||
      joinedParsed === null ||
      Array.isArray(joinedParsed)
    ) {
      throw new Error('Noncanonical generated TypeGPU bind-group full witness');
    }
    const converted = convertedParsed as Readonly<Record<string, unknown>>;
    const joined = joinedParsed as Readonly<Record<string, unknown>>;
    const convertedLayout = converted.layout as
      | Readonly<Record<string, unknown>>
      | undefined;
    const joinedEntries = joined.entries;
    const convertedEntries = converted.entries;
    if (
      typeof joined.label !== 'string' ||
      converted.label !== joined.label ||
      joined.sequence !== witness.evidenceSequence ||
      joined.traceOrdinal !== witness.evidenceTraceOrdinal ||
      joined.workloadId !== witness.workloadId ||
      !Array.isArray(joinedEntries) ||
      joinedEntries.length < 1 ||
      joinedEntries.length > 5 ||
      !Array.isArray(convertedEntries) ||
      convertedEntries.length !== joinedEntries.length ||
      convertedLayout?.kind !== 'GPUBindGroupLayout' ||
      convertedLayout.creationSequence !== joined.layoutCreationSequence ||
      typeof joined.layoutDescriptor !== 'object' ||
      joined.layoutDescriptor === null
    ) {
      throw new Error('Invalid generated TypeGPU bind-group full witness shape');
    }
    entryCount += joinedEntries.length;
    maximumEntries = Math.max(maximumEntries, joinedEntries.length);
    maximumLabelBytes = Math.max(
      maximumLabelBytes,
      encodeUtf8(joined.label).byteLength,
    );
    layoutDescriptors.add(canonicalManifestJson(joined.layoutDescriptor));
    workloadCounts.set(
      witness.workloadId,
      (workloadCounts.get(witness.workloadId) ?? 0) + 1,
    );
    for (const [index, entry] of joinedEntries.entries()) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
        throw new Error('Invalid generated TypeGPU bind-group entry witness');
      }
      const joinedEntry = entry as Readonly<Record<string, unknown>>;
      const convertedEntryValue = convertedEntries[index];
      if (
        typeof convertedEntryValue !== 'object' ||
        convertedEntryValue === null ||
        Array.isArray(convertedEntryValue)
      ) {
        throw new Error('Invalid converted TypeGPU bind-group entry witness');
      }
      const convertedEntry = convertedEntryValue as Readonly<Record<string, unknown>>;
      const convertedResource = convertedEntry.resource as
        | Readonly<Record<string, unknown>>
        | undefined;
      const resourceKind = joinedEntry.resourceKind;
      if (typeof resourceKind !== 'string') {
        throw new Error('Invalid generated TypeGPU bind-group resource witness');
      }
      if (
        convertedEntry.binding !== joinedEntry.binding ||
        convertedResource?.resourceKind !== resourceKind
      ) {
        throw new Error('Cross-wired generated TypeGPU bind-group entry witness');
      }
      if (resourceKind === 'GPUBufferBinding') {
        const buffer = convertedResource.buffer as
          | Readonly<Record<string, unknown>>
          | undefined;
        if (
          buffer?.kind !== 'GPUBuffer' ||
          buffer.creationSequence !== joinedEntry.bufferCreationSequence ||
          convertedResource.offset !== joinedEntry.offset ||
          Object.hasOwn(convertedResource, 'size') !==
            Object.hasOwn(joinedEntry, 'size') ||
          convertedResource.size !== joinedEntry.size
        ) {
          throw new Error('Buffer witness lost creator sequence or optional size presence');
        }
      } else {
        const reference = convertedResource.reference as
          | Readonly<Record<string, unknown>>
          | undefined;
        const creationSequence = resourceKind === 'GPUSampler'
          ? joinedEntry.samplerCreationSequence
          : joinedEntry.viewCreationSequence;
        if (
          reference?.kind !== resourceKind ||
          reference.creationSequence !== creationSequence ||
          (resourceKind === 'GPUTextureView' &&
            (reference.textureCreationSequence !==
              (joinedEntry.textureOrigin as Readonly<Record<string, unknown>> | undefined)
                ?.creationSequence ||
              canonicalManifestJson(reference.textureOrigin) !==
                canonicalManifestJson(joinedEntry.textureOrigin)))
        ) {
          throw new Error('Resource witness lost creator, parent, or origin provenance');
        }
      }
      resourceCounts.set(
        resourceKind,
        (resourceCounts.get(resourceKind) ?? 0) + 1,
      );
    }
  }
  if (
    entryCount !== evidence.entryCount ||
    maximumEntries !== evidence.maximumEntriesPerDescriptor ||
    maximumLabelBytes !== evidence.maximumLabelUtf8Bytes ||
    layoutDescriptors.size !== evidence.distinctLayoutCount ||
    resourceCounts.get('GPUBufferBinding') !== 36 ||
    resourceCounts.get('GPUSampler') !== 5 ||
    resourceCounts.get('GPUTextureView') !== 6 ||
    resourceCounts.size !== 3 ||
    workloadCounts.get('typegpu-genetic-racing') !== 16 ||
    workloadCounts.get('typegpu-jelly-slider') !== 2 ||
    workloadCounts.size !== 2
  ) {
    throw new Error('Generated TypeGPU bind-group evidence aggregate drifted');
  }
}

function validateNativeCodecProgram(
  manifest: ExecutableWebGpuCodecManifest,
  expectedObjectKindTags: Readonly<Record<string, number>>,
): ValidatedNativeCodecProgram {
  const {
    commandRecordV1,
    queueSubmitRequestBodyV1,
    computePipelineDescriptorV1,
    renderPipelineDescriptorV1,
    sha256DigestV1,
    canvasConfigureRequestBodyV1,
    canvasViewFormatSequenceV1,
    canvasUnconfigureRequestBodyV1,
    canvasCurrentTextureOriginV1,
    textureDestroyRequestBodyV1,
    ...nativeTypesWithoutQueueSubmit
  } = manifest.nativeCodecPrograms.types;
  void commandRecordV1;
  void queueSubmitRequestBodyV1;
  void sha256DigestV1;
  void canvasConfigureRequestBodyV1;
  void canvasViewFormatSequenceV1;
  void canvasUnconfigureRequestBodyV1;
  void canvasCurrentTextureOriginV1;
  void textureDestroyRequestBodyV1;
  if (
    sha256HexUtf8(canonicalManifestJson(computePipelineDescriptorV1)) !==
      EXPECTED_CREATE_COMPUTE_PIPELINE_DESCRIPTOR_SHA256
  ) {
    throw new Error('Invalid authenticated GPUDevice.createComputePipeline descriptor type');
  }
  if (
    sha256HexUtf8(canonicalManifestJson(renderPipelineDescriptorV1)) !==
      '9a597fe88d4b7d91edfdf927df1429f8762b3cf3d0ed47ed1645bc12f8f7f2b7'
  ) {
    throw new Error('Invalid authenticated GPUDevice.createRenderPipeline descriptor type');
  }
  const programWithoutDeviceObjectCreationRoutes = {
    ...manifest.nativeCodecPrograms,
    types: nativeTypesWithoutQueueSubmit,
    routes: manifest.nativeCodecPrograms.routes.filter(
      (candidate) =>
        candidate.operationId !== CREATE_BIND_GROUP_OPERATION_ID &&
        candidate.operationId !== CREATE_BIND_GROUP_LAYOUT_OPERATION_ID &&
        candidate.operationId !== CREATE_BUFFER_OPERATION_ID &&
        candidate.operationId !== CREATE_PIPELINE_LAYOUT_OPERATION_ID &&
        candidate.operationId !== CREATE_COMPUTE_PIPELINE_OPERATION_ID &&
        candidate.operationId !== CREATE_RENDER_PIPELINE_OPERATION_ID &&
        candidate.operationId !== CREATE_SAMPLER_OPERATION_ID &&
        candidate.operationId !== CREATE_TEXTURE_OPERATION_ID &&
        candidate.operationId !== CREATE_TEXTURE_VIEW_OPERATION_ID &&
        candidate.operationId !== CREATE_COMMAND_ENCODER_OPERATION_ID &&
        candidate.operationId !== CREATE_SHADER_MODULE_OPERATION_ID &&
        candidate.operationId !== BUFFER_DESTROY_OPERATION_ID &&
        candidate.operationId !== BUFFER_MAP_ASYNC_OPERATION_ID &&
        candidate.operationId !== BUFFER_UNMAP_OPERATION_ID &&
        candidate.operationId !== CANVAS_CONFIGURE_OPERATION_ID &&
        candidate.operationId !== CANVAS_UNCONFIGURE_OPERATION_ID &&
        candidate.operationId !== TEXTURE_DESTROY_OPERATION_ID &&
        candidate.operationId !== QUEUE_WRITE_BUFFER_OPERATION_ID &&
        candidate.operationId !== QUEUE_SUBMIT_OPERATION_ID,
    ),
  };
  if (
    canonicalManifestJson(programWithoutDeviceObjectCreationRoutes) !==
      canonicalManifestJson(EXPECTED_NATIVE_CODEC_PROGRAM) ||
    canonicalManifestJson(manifest.carrierConstants) !==
      canonicalManifestJson(EXPECTED_WEBGPU_CARRIER_CONSTANTS)
  ) {
    throw new Error('Invalid generated WebGPU native codec program');
  }
  const lifecycleProgram = {
    types: {
      ownedBytesV1: manifest.nativeCodecPrograms.types.ownedBytesV1,
      bufferCleanupRequestBodyV1:
        manifest.nativeCodecPrograms.types.bufferCleanupRequestBodyV1,
      bufferMapAsyncRequestBodyV1:
        manifest.nativeCodecPrograms.types.bufferMapAsyncRequestBodyV1,
      bufferMapAsyncCompletionBodyV1:
        manifest.nativeCodecPrograms.types.bufferMapAsyncCompletionBodyV1,
    },
    routes: manifest.nativeCodecPrograms.routes.filter((candidate) =>
      candidate.operationId === BUFFER_DESTROY_OPERATION_ID ||
      candidate.operationId === BUFFER_MAP_ASYNC_OPERATION_ID ||
      candidate.operationId === BUFFER_UNMAP_OPERATION_ID
    ),
  };
  if (
    sha256HexUtf8(canonicalManifestJson(lifecycleProgram)) !==
      EXPECTED_BUFFER_LIFECYCLE_NATIVE_CODEC_SHA256
  ) {
    throw new Error('Invalid authenticated GPUBuffer lifecycle codec program');
  }
  const queueWriteBufferProgram = {
    types: {
      ownedBytesV1: manifest.nativeCodecPrograms.types.ownedBytesV1,
      queueWriteBufferRequestBodyV1:
        manifest.nativeCodecPrograms.types.queueWriteBufferRequestBodyV1,
    },
    routes: manifest.nativeCodecPrograms.routes.filter(
      (candidate) =>
        candidate.operationId === QUEUE_WRITE_BUFFER_OPERATION_ID,
    ),
  };
  if (
    sha256HexUtf8(canonicalManifestJson(queueWriteBufferProgram)) !==
      EXPECTED_QUEUE_WRITE_BUFFER_NATIVE_CODEC_SHA256
  ) {
    throw new Error('Invalid authenticated GPUQueue.writeBuffer codec program');
  }
  const queueSubmitProgram = {
    types: {
      commandRecordV1: manifest.nativeCodecPrograms.types.commandRecordV1,
      queueSubmitRequestBodyV1:
        manifest.nativeCodecPrograms.types.queueSubmitRequestBodyV1,
    },
    routes: manifest.nativeCodecPrograms.routes.filter(
      (candidate) => candidate.operationId === QUEUE_SUBMIT_OPERATION_ID,
    ),
  };
  if (
    sha256HexUtf8(canonicalManifestJson(queueSubmitProgram)) !==
      EXPECTED_QUEUE_SUBMIT_NATIVE_CODEC_SHA256
  ) {
    throw new Error('Invalid authenticated GPUQueue.submit codec program');
  }
  const canvasProgram = {
    types: {
      sha256DigestV1: manifest.nativeCodecPrograms.types.sha256DigestV1,
      canvasConfigureRequestBodyV1:
        manifest.nativeCodecPrograms.types.canvasConfigureRequestBodyV1,
      canvasViewFormatSequenceV1:
        manifest.nativeCodecPrograms.types.canvasViewFormatSequenceV1,
      canvasUnconfigureRequestBodyV1:
        manifest.nativeCodecPrograms.types.canvasUnconfigureRequestBodyV1,
      canvasCurrentTextureOriginV1:
        manifest.nativeCodecPrograms.types.canvasCurrentTextureOriginV1,
      textureDestroyRequestBodyV1:
        manifest.nativeCodecPrograms.types.textureDestroyRequestBodyV1,
    },
    routes: manifest.nativeCodecPrograms.routes.filter((candidate) =>
      candidate.operationId === CANVAS_CONFIGURE_OPERATION_ID ||
      candidate.operationId === CANVAS_UNCONFIGURE_OPERATION_ID ||
      candidate.operationId === TEXTURE_DESTROY_OPERATION_ID
    ),
  };
  const canvasProgramSha256 = sha256HexUtf8(
    canonicalManifestJson(canvasProgram),
  );
  if (canvasProgramSha256 !== EXPECTED_CANVAS_NATIVE_CODEC_SHA256) {
    throw new Error(
      `Invalid authenticated canvas service codec program (${canvasProgramSha256})`,
    );
  }
  const route = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecRequestAdapterRoute =>
      candidate.operationId === REQUEST_ADAPTER_OPERATION_ID,
  );
  const requestDeviceRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecRequestDeviceRoute =>
      candidate.operationId === REQUEST_DEVICE_OPERATION_ID,
  );
  const createBindGroupRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateBindGroupRoute =>
      candidate.operationId === CREATE_BIND_GROUP_OPERATION_ID,
  );
  const createBindGroupLayoutRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateBindGroupLayoutRoute =>
      candidate.operationId === CREATE_BIND_GROUP_LAYOUT_OPERATION_ID,
  );
  const createBufferRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateBufferRoute =>
      candidate.operationId === CREATE_BUFFER_OPERATION_ID,
  );
  const createPipelineLayoutRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreatePipelineLayoutRoute =>
      candidate.operationId === CREATE_PIPELINE_LAYOUT_OPERATION_ID,
  );
  const createComputePipelineRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateComputePipelineRoute =>
      candidate.operationId === CREATE_COMPUTE_PIPELINE_OPERATION_ID,
  );
  const createRenderPipelineRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateRenderPipelineRoute =>
      candidate.operationId === CREATE_RENDER_PIPELINE_OPERATION_ID,
  );
  const createSamplerRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateSamplerRoute =>
      candidate.operationId === CREATE_SAMPLER_OPERATION_ID,
  );
  const createTextureRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateTextureRoute =>
      candidate.operationId === CREATE_TEXTURE_OPERATION_ID,
  );
  const createTextureViewRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateTextureViewRoute =>
      candidate.operationId === CREATE_TEXTURE_VIEW_OPERATION_ID,
  );
  const createCommandEncoderRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateCommandEncoderRoute =>
      candidate.operationId === CREATE_COMMAND_ENCODER_OPERATION_ID,
  );
  const createShaderModuleRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCreateShaderModuleRoute =>
      candidate.operationId === CREATE_SHADER_MODULE_OPERATION_ID,
  );
  const deviceDestroyRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecDeviceDestroyRoute =>
      candidate.operationId === DEVICE_DESTROY_OPERATION_ID,
  );
  const bufferDestroyRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecBufferLifecycleRoute =>
      candidate.operationId === BUFFER_DESTROY_OPERATION_ID,
  );
  const bufferMapAsyncRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecBufferLifecycleRoute =>
      candidate.operationId === BUFFER_MAP_ASYNC_OPERATION_ID,
  );
  const bufferUnmapRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecBufferLifecycleRoute =>
      candidate.operationId === BUFFER_UNMAP_OPERATION_ID,
  );
  const canvasConfigureRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCanvasServiceRoute =>
      candidate.operationId === CANVAS_CONFIGURE_OPERATION_ID,
  );
  const canvasUnconfigureRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCanvasServiceRoute =>
      candidate.operationId === CANVAS_UNCONFIGURE_OPERATION_ID,
  );
  const textureDestroyRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecCanvasServiceRoute =>
      candidate.operationId === TEXTURE_DESTROY_OPERATION_ID,
  );
  const queueWriteBufferRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecQueueWriteBufferRoute =>
      candidate.operationId === QUEUE_WRITE_BUFFER_OPERATION_ID,
  );
  const queueSubmitRoute = manifest.nativeCodecPrograms.routes.find(
    (candidate): candidate is NativeCodecQueueSubmitRoute =>
      candidate.operationId === QUEUE_SUBMIT_OPERATION_ID,
  );
  const planRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === REQUEST_ADAPTER_OPERATION_ID,
  );
  const requestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === REQUEST_ADAPTER_REQUEST_CODEC,
  );
  const completionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === REQUEST_ADAPTER_COMPLETION_CODEC,
  );
  const requestDevicePlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === REQUEST_DEVICE_OPERATION_ID,
  );
  const requestDeviceRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === REQUEST_DEVICE_REQUEST_CODEC,
  );
  const requestDeviceCompletionCodec = manifest.serviceCompletions.find(
      (candidate) => candidate.tag === REQUEST_DEVICE_COMPLETION_CODEC,
  );
  const createBindGroupPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_BIND_GROUP_OPERATION_ID,
  );
  const createBindGroupRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_BIND_GROUP_REQUEST_CODEC,
  );
  const createBindGroupCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_BIND_GROUP_COMPLETION_CODEC,
  );
  const createBindGroupLayoutPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_BIND_GROUP_LAYOUT_OPERATION_ID,
  );
  const createBindGroupLayoutRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC,
  );
  const createBindGroupLayoutCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_BIND_GROUP_LAYOUT_COMPLETION_CODEC,
  );
  const createBufferPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_BUFFER_OPERATION_ID,
  );
  const createBufferRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_BUFFER_REQUEST_CODEC,
  );
  const createBufferCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_BUFFER_COMPLETION_CODEC,
  );
  const createPipelineLayoutPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_PIPELINE_LAYOUT_OPERATION_ID,
  );
  const createPipelineLayoutRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_PIPELINE_LAYOUT_REQUEST_CODEC,
  );
  const createPipelineLayoutCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_PIPELINE_LAYOUT_COMPLETION_CODEC,
  );
  const createComputePipelinePlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_COMPUTE_PIPELINE_OPERATION_ID,
  );
  const createComputePipelineRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_COMPUTE_PIPELINE_REQUEST_CODEC,
  );
  const createComputePipelineCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_COMPUTE_PIPELINE_COMPLETION_CODEC,
  );
  const createRenderPipelinePlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_RENDER_PIPELINE_OPERATION_ID,
  );
  const createRenderPipelineRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_RENDER_PIPELINE_REQUEST_CODEC,
  );
  const createRenderPipelineCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_RENDER_PIPELINE_COMPLETION_CODEC,
  );
  const createSamplerPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_SAMPLER_OPERATION_ID,
  );
  const createSamplerRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_SAMPLER_REQUEST_CODEC,
  );
  const createSamplerCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_SAMPLER_COMPLETION_CODEC,
  );
  const createTexturePlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_TEXTURE_OPERATION_ID,
  );
  const createTextureRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_TEXTURE_REQUEST_CODEC,
  );
  const createTextureCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_TEXTURE_COMPLETION_CODEC,
  );
  const createTextureViewPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_TEXTURE_VIEW_OPERATION_ID,
  );
  const createTextureViewRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_TEXTURE_VIEW_REQUEST_CODEC,
  );
  const createTextureViewCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_TEXTURE_VIEW_COMPLETION_CODEC,
  );
  const createCommandEncoderPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_COMMAND_ENCODER_OPERATION_ID,
  );
  const createCommandEncoderRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_COMMAND_ENCODER_REQUEST_CODEC,
  );
  const createCommandEncoderCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_COMMAND_ENCODER_COMPLETION_CODEC,
  );
  const createShaderModulePlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === CREATE_SHADER_MODULE_OPERATION_ID,
  );
  const createShaderModuleRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === CREATE_SHADER_MODULE_REQUEST_CODEC,
  );
  const createShaderModuleCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === CREATE_SHADER_MODULE_COMPLETION_CODEC,
  );
  const deviceDestroyPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === DEVICE_DESTROY_OPERATION_ID,
  );
  const deviceDestroyRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === DEVICE_DESTROY_REQUEST_CODEC,
  );
  const deviceDestroyCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === DEVICE_DESTROY_COMPLETION_CODEC,
  );
  const bufferDestroyPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === BUFFER_DESTROY_OPERATION_ID,
  );
  const bufferDestroyRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === BUFFER_DESTROY_REQUEST_CODEC,
  );
  const bufferMapAsyncPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === BUFFER_MAP_ASYNC_OPERATION_ID,
  );
  const bufferMapAsyncRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === BUFFER_MAP_ASYNC_REQUEST_CODEC,
  );
  const bufferMapAsyncCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === BUFFER_MAP_ASYNC_COMPLETION_CODEC,
  );
  const bufferUnmapPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === BUFFER_UNMAP_OPERATION_ID,
  );
  const bufferUnmapRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === BUFFER_UNMAP_REQUEST_CODEC,
  );
  const bufferCleanupCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === BUFFER_CLEANUP_COMPLETION_CODEC,
  );
  const queueWriteBufferPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === QUEUE_WRITE_BUFFER_OPERATION_ID,
  );
  const queueWriteBufferRequestCodec = manifest.serviceArguments.find(
    (candidate) => candidate.tag === QUEUE_WRITE_BUFFER_REQUEST_CODEC,
  );
  const queueWriteBufferCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === QUEUE_WRITE_BUFFER_COMPLETION_CODEC,
  );
  const queueSubmitRequestCodec = manifest.serviceArguments.find(
    (candidate) =>
      candidate.tag === QUEUE_SUBMIT_REQUEST_CODEC,
  );
  const queueSubmitPlanRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === QUEUE_SUBMIT_OPERATION_ID,
  );
  const queueSubmitCompletionCodec = manifest.serviceCompletions.find(
    (candidate) => candidate.tag === QUEUE_SUBMIT_COMPLETION_CODEC,
  );
  const nullVariant = route?.completion.variants.find(
    (variant) => variant.name === 'null',
  );
  const objectVariant = route?.completion.variants.find(
    (variant) => variant.name === 'object',
  );
  const createCommandEncoderRequestFields = [
    {
      name: 'header',
      type: 'headerV1',
      constants: {
        magic: 'IBGQ',
        version: 1,
        codecTag: 5,
        operationWireId: CREATE_COMMAND_ENCODER_WIRE_ID,
      },
    },
    { name: 'receiver', type: 'objectReferenceV1' },
    { name: 'target', type: 'optionalReferenceV1' },
    { name: 'capturedScopeId', type: 'u64le' },
    { name: 'adapterOrdinal', type: 'u64le' },
    { name: 'deviceIngressOrdinal', type: 'u64le' },
    { name: 'queueIngressOrdinal', type: 'u64le' },
    { name: 'sealedLocalTimeline', type: 'canonicalValueV1' },
    {
      name: 'convertedArguments',
      type: 'canonicalValueV1',
      constraintType: 'commandEncoderDescriptorV1',
    },
  ];
  const createCommandEncoderCarrierJoins = [
    ['header.operationWireId', 'operation_id'],
    ['receiver.kind', 'receiver.kind'],
    ['receiver.objectId', 'receiver.object_id'],
    ['receiver.objectGeneration', 'receiver.object_generation'],
    ['receiver.logicalDeviceId', 'ingress_device.logical_device_id'],
    ['receiver.logicalDeviceGeneration', 'ingress_device.logical_device_generation'],
    ['receiver.providerGeneration', 'ingress_device.provider_generation'],
    ['receiver.providerGeneration', 'provider_generation'],
    ['target.kind', 'target.kind'],
    ['target.objectId', 'target.object_id'],
    ['target.objectGeneration', 'target.object_generation'],
    ['target.logicalDeviceId', 'ingress_device.logical_device_id'],
    ['target.logicalDeviceGeneration', 'ingress_device.logical_device_generation'],
    ['target.providerGeneration', 'ingress_device.provider_generation'],
    ['target.providerGeneration', 'provider_generation'],
    ['capturedScopeId', 'captured_scope_id'],
    ['adapterOrdinal', 'adapter_ordinal'],
    ['deviceIngressOrdinal', 'device_ingress_ordinal'],
    ['queueIngressOrdinal', 'queue_ingress_ordinal'],
  ].map(([payloadPath, carrierPath]) => ({
    payloadPath,
    carrierPath,
    operator: 'equal',
  }));
  const createCommandEncoderCarrierConstraints = [
    {
      carrierPath: 'operation_id',
      operator: 'equal',
      value: CREATE_COMMAND_ENCODER_WIRE_ID,
    },
    { carrierPath: 'flags', operator: 'equal', value: 0 },
    {
      carrierPath: 'topology_id',
      operator: 'equal',
      valueFrom: 'constants.providerTopologyId',
    },
    { carrierPath: 'ingress_device', operator: 'positive' },
    { carrierPath: 'provider_generation', operator: 'positive' },
    { carrierPath: 'operation_instance_id', operator: 'positive' },
    { carrierPath: 'promise_id', operator: 'equal', value: '0' },
    {
      carrierPath: 'receiver.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUDevice',
    },
    { carrierPath: 'receiver.flags', operator: 'equal', value: 0 },
    { carrierPath: 'receiver.object_id', operator: 'positive' },
    { carrierPath: 'receiver.object_generation', operator: 'positive' },
    {
      carrierPath: 'target.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUCommandEncoder',
    },
    { carrierPath: 'target.flags', operator: 'equal', value: 0 },
    { carrierPath: 'target.object_id', operator: 'positive' },
    { carrierPath: 'target.object_generation', operator: 'positive' },
    { carrierPath: 'adapter_ordinal', operator: 'equal', value: '0' },
    { carrierPath: 'device_ingress_ordinal', operator: 'positive' },
    { carrierPath: 'queue_ingress_ordinal', operator: 'equal', value: '0' },
  ];
  const createCommandEncoderCompletionCarrierConstraints = [
    {
      carrierPath: 'kind',
      operator: 'equal',
      value: 1,
      symbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
    },
    { carrierPath: 'record.operation_result.status', operator: 'equal', value: 0 },
    {
      carrierPath: 'record.operation_result.operation.operation_id',
      operator: 'equal',
      value: CREATE_COMMAND_ENCODER_WIRE_ID,
    },
    {
      carrierPath: 'record.operation_result.operation.device_transition',
      operator: 'equal',
      value: 0,
      symbol: 'EXACT_GPU_DEVICE_UNCHANGED_V2',
    },
    {
      carrierPath: 'record.operation_result.operation.ingress_device',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.result_device',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.provider_generation',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.promise_id',
      operator: 'equal',
      value: '0',
    },
    {
      carrierPath: 'record.operation_result.operation.receiver.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUDevice',
    },
    {
      carrierPath: 'record.operation_result.operation.target.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUCommandEncoder',
    },
    {
      carrierPath: 'record.operation_result.operation.adapter_ordinal',
      operator: 'equal',
      value: '0',
    },
    {
      carrierPath: 'record.operation_result.operation.device_ingress_ordinal',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.queue_ingress_ordinal',
      operator: 'equal',
      value: '0',
    },
    {
      carrierPath: 'record.operation_result.result_kind',
      operator: 'equal',
      value: 0,
      symbol: 'EXACT_GPU_RESULT_NONE_V2',
    },
  ];
  const expectedCreateCommandEncoderRoute = {
    operationId: CREATE_COMMAND_ENCODER_OPERATION_ID,
    wireId: CREATE_COMMAND_ENCODER_WIRE_ID,
    request: {
      payloadRole:
        'service-request-payload-decoder-plus-operation-specific-call-joins',
      catalog: {
        name: 'serviceArguments',
        tag: CREATE_COMMAND_ENCODER_REQUEST_CODEC,
        wireTag: 5,
      },
      payload: { kind: 'struct', fields: createCommandEncoderRequestFields },
      carrierJoins: createCommandEncoderCarrierJoins,
      carrierConstraints: createCommandEncoderCarrierConstraints,
      valueConstraints: [
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'canonical-sequence-within-layout-bounds',
        },
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'untrusted-wrapper-record-prefix-join-only-never-authority',
        },
        {
          payloadPath: 'convertedArguments',
          operator: 'conforms-to-type',
          type: 'commandEncoderDescriptorV1',
        },
      ],
      semanticServiceBoundary: {
        stateAuthority:
          'authenticated-device-object-account-coverage-and-reservation-tables',
        payloadRole: 'comparison-input-only-never-authority',
        requiredAfterDecode: [
          'authenticate-contiguous-sealed-local-timeline-prefix',
          'validate-current-live-device-generation',
          'validate-operation-coverage',
          'validate-authorized-live-account',
          'reserve-command-encoder-handle-and-aggregate-envelope',
          'authenticate-wrapper-allocated-command-encoder-target',
          'select-provider-admission-and-physical-sequence',
        ],
        completionEncodingRequires: [
          'authenticated-retained-call',
          'service-owned-operation-result',
        ],
      },
      executablePrerequisites: [],
      noTrailingBytes: true,
    },
    completion: {
      payloadRole:
        'service-completion-payload-codec-plus-operation-specific-event-joins',
      catalog: {
        name: 'serviceCompletions',
        tag: CREATE_COMMAND_ENCODER_COMPLETION_CODEC,
        wireTag: 2,
      },
      commonCarrierConstraints:
        createCommandEncoderCompletionCarrierConstraints,
      payload: { kind: 'empty', exactLengthBytes: 0 },
      semanticTerminalMapping: {
        authorityPath:
          'semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createCommandEncoder]',
        terminals: [
          {
            terminalId: 'webidl-rejection',
            errorTiming: 'synchronous-webidl',
            resultDisposition: 'throw',
            providerTokenCount: 0,
            physicalSequenceCount: 0,
            event: {
              kind: 'no-service-call',
              completionPayloadEncoderEligibility:
                'excluded-before-service-ingress',
            },
          },
          {
            terminalId: 'later-predicate-rejection',
            errorTiming: 'device-timeline',
            resultDisposition: 'return-invalid-object-and-report-error',
            providerTokenCount: 0,
            physicalSequenceCount: 0,
            event: {
              kind: 'device-error',
              kindValue: 2,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2',
              completionPayloadEncoderEligibility:
                'excluded-not-an-operation-result',
            },
          },
          {
            terminalId: 'operation-success',
            errorTiming: 'none',
            resultDisposition: 'return-object',
            providerTokenCount: 1,
            physicalSequenceCount: 1,
            event: {
              kind: 'operation-result',
              kindValue: 1,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
              resultKind: 0,
              resultKindSymbol: 'EXACT_GPU_RESULT_NONE_V2',
              status: 0,
              completionVariant: 'operation-success',
            },
          },
        ],
      },
      variants: [{
        name: 'operation-success',
        carrierConstraints: [
          {
            carrierPath:
              'record.operation_result.operation.provider_admission',
            operator: 'equal',
            value: 1,
            symbol: 'EXACT_GPU_PROVIDER_ADMITTED_V2',
          },
          {
            carrierPath:
              'record.operation_result.operation.physical_sequence',
            operator: 'positive',
          },
        ],
      }],
      noTrailingBytes: true,
    },
  };
  const createShaderModuleRequestFields = [
    {
      name: 'header',
      type: 'headerV1',
      constants: {
        magic: 'IBGQ',
        version: 1,
        codecTag: 7,
        operationWireId: CREATE_SHADER_MODULE_WIRE_ID,
      },
    },
    { name: 'receiver', type: 'objectReferenceV1' },
    { name: 'target', type: 'optionalReferenceV1' },
    { name: 'capturedScopeId', type: 'u64le' },
    { name: 'adapterOrdinal', type: 'u64le' },
    { name: 'deviceIngressOrdinal', type: 'u64le' },
    { name: 'queueIngressOrdinal', type: 'u64le' },
    { name: 'sealedLocalTimeline', type: 'canonicalValueV1' },
    {
      name: 'convertedArguments',
      type: 'canonicalValueV1',
      constraintType: 'shaderModuleDescriptorV1',
    },
  ];
  const createShaderModuleCarrierJoins = [
    ['header.operationWireId', 'operation_id'],
    ['receiver.kind', 'receiver.kind'],
    ['receiver.objectId', 'receiver.object_id'],
    ['receiver.objectGeneration', 'receiver.object_generation'],
    ['receiver.logicalDeviceId', 'ingress_device.logical_device_id'],
    ['receiver.logicalDeviceGeneration', 'ingress_device.logical_device_generation'],
    ['receiver.providerGeneration', 'ingress_device.provider_generation'],
    ['receiver.providerGeneration', 'provider_generation'],
    ['target.kind', 'target.kind'],
    ['target.objectId', 'target.object_id'],
    ['target.objectGeneration', 'target.object_generation'],
    ['target.logicalDeviceId', 'ingress_device.logical_device_id'],
    ['target.logicalDeviceGeneration', 'ingress_device.logical_device_generation'],
    ['target.providerGeneration', 'ingress_device.provider_generation'],
    ['target.providerGeneration', 'provider_generation'],
    ['capturedScopeId', 'captured_scope_id'],
    ['adapterOrdinal', 'adapter_ordinal'],
    ['deviceIngressOrdinal', 'device_ingress_ordinal'],
    ['queueIngressOrdinal', 'queue_ingress_ordinal'],
  ].map(([payloadPath, carrierPath]) => ({
    payloadPath,
    carrierPath,
    operator: 'equal',
  }));
  const createShaderModuleCarrierConstraints = [
    {
      carrierPath: 'operation_id',
      operator: 'equal',
      value: CREATE_SHADER_MODULE_WIRE_ID,
    },
    { carrierPath: 'flags', operator: 'equal', value: 0 },
    {
      carrierPath: 'topology_id',
      operator: 'equal',
      valueFrom: 'constants.providerTopologyId',
    },
    { carrierPath: 'ingress_device', operator: 'positive' },
    { carrierPath: 'provider_generation', operator: 'positive' },
    { carrierPath: 'operation_instance_id', operator: 'positive' },
    { carrierPath: 'promise_id', operator: 'equal', value: '0' },
    {
      carrierPath: 'receiver.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUDevice',
    },
    { carrierPath: 'receiver.flags', operator: 'equal', value: 0 },
    { carrierPath: 'receiver.object_id', operator: 'positive' },
    { carrierPath: 'receiver.object_generation', operator: 'positive' },
    {
      carrierPath: 'target.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUShaderModule',
    },
    { carrierPath: 'target.flags', operator: 'equal', value: 0 },
    { carrierPath: 'target.object_id', operator: 'positive' },
    { carrierPath: 'target.object_generation', operator: 'positive' },
    { carrierPath: 'adapter_ordinal', operator: 'equal', value: '0' },
    { carrierPath: 'device_ingress_ordinal', operator: 'positive' },
    { carrierPath: 'queue_ingress_ordinal', operator: 'equal', value: '0' },
  ];
  const createShaderModuleCompletionCarrierConstraints = [
    {
      carrierPath: 'kind',
      operator: 'equal',
      value: 1,
      symbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
    },
    { carrierPath: 'record.operation_result.status', operator: 'equal', value: 0 },
    {
      carrierPath: 'record.operation_result.operation.operation_id',
      operator: 'equal',
      value: CREATE_SHADER_MODULE_WIRE_ID,
    },
    {
      carrierPath: 'record.operation_result.operation.device_transition',
      operator: 'equal',
      value: 0,
      symbol: 'EXACT_GPU_DEVICE_UNCHANGED_V2',
    },
    {
      carrierPath: 'record.operation_result.operation.ingress_device',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.result_device',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.provider_generation',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.promise_id',
      operator: 'equal',
      value: '0',
    },
    {
      carrierPath: 'record.operation_result.operation.receiver.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUDevice',
    },
    {
      carrierPath: 'record.operation_result.operation.target.kind',
      operator: 'equal',
      valueFrom: 'objectKindTags.GPUShaderModule',
    },
    {
      carrierPath: 'record.operation_result.operation.adapter_ordinal',
      operator: 'equal',
      value: '0',
    },
    {
      carrierPath: 'record.operation_result.operation.device_ingress_ordinal',
      operator: 'positive',
    },
    {
      carrierPath: 'record.operation_result.operation.queue_ingress_ordinal',
      operator: 'equal',
      value: '0',
    },
    {
      carrierPath: 'record.operation_result.result_kind',
      operator: 'equal',
      value: 0,
      symbol: 'EXACT_GPU_RESULT_NONE_V2',
    },
  ];
  const expectedCreateShaderModuleRoute = {
    operationId: CREATE_SHADER_MODULE_OPERATION_ID,
    wireId: CREATE_SHADER_MODULE_WIRE_ID,
    request: {
      payloadRole:
        'service-request-payload-decoder-plus-operation-specific-call-joins',
      catalog: {
        name: 'serviceArguments',
        tag: CREATE_SHADER_MODULE_REQUEST_CODEC,
        wireTag: 7,
      },
      payload: { kind: 'struct', fields: createShaderModuleRequestFields },
      carrierJoins: createShaderModuleCarrierJoins,
      carrierConstraints: createShaderModuleCarrierConstraints,
      valueConstraints: [
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'canonical-sequence-within-layout-bounds',
        },
        {
          payloadPath: 'sealedLocalTimeline',
          operator: 'untrusted-wrapper-record-prefix-join-only-never-authority',
        },
        {
          payloadPath: 'convertedArguments',
          operator: 'conforms-to-type',
          type: 'shaderModuleDescriptorV1',
        },
      ],
      semanticServiceBoundary: {
        stateAuthority:
          'authenticated-device-object-account-coverage-and-reservation-tables',
        payloadRole: 'comparison-input-only-never-authority',
        requiredAfterDecode: [
          'authenticate-contiguous-sealed-local-timeline-prefix',
          'validate-current-live-device-generation',
          'validate-operation-coverage',
          'validate-authorized-live-account',
          'validate-wgsl-with-naga-under-logical-capabilities',
          'reserve-shader-module-handle-and-aggregate-envelope',
          'authenticate-wrapper-allocated-shader-module-target',
          'select-provider-admission-and-physical-sequence',
        ],
        completionEncodingRequires: [
          'authenticated-retained-call',
          'service-owned-operation-result',
        ],
      },
      executablePrerequisites: [],
      noTrailingBytes: true,
    },
    completion: {
      payloadRole:
        'service-completion-payload-codec-plus-operation-specific-event-joins',
      catalog: {
        name: 'serviceCompletions',
        tag: CREATE_SHADER_MODULE_COMPLETION_CODEC,
        wireTag: 2,
      },
      commonCarrierConstraints:
        createShaderModuleCompletionCarrierConstraints,
      payload: { kind: 'empty', exactLengthBytes: 0 },
      semanticTerminalMapping: {
        authorityPath:
          'semanticProjection.providerRoutingPrograms[operationId=GPUDevice.createShaderModule]',
        terminals: [
          {
            terminalId: 'webidl-rejection',
            errorTiming: 'synchronous-webidl',
            resultDisposition: 'throw',
            providerTokenCount: 0,
            physicalSequenceCount: 0,
            event: {
              kind: 'no-service-call',
              completionPayloadEncoderEligibility:
                'excluded-before-service-ingress',
            },
          },
          {
            terminalId: 'later-predicate-rejection',
            errorTiming: 'device-timeline',
            resultDisposition: 'return-invalid-object-and-report-error',
            providerTokenCount: 0,
            physicalSequenceCount: 0,
            event: {
              kind: 'device-error',
              kindValue: 2,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2',
              completionPayloadEncoderEligibility:
                'excluded-not-an-operation-result',
            },
          },
          {
            terminalId: 'operation-success',
            errorTiming: 'none',
            resultDisposition: 'return-object',
            providerTokenCount: 1,
            physicalSequenceCount: 1,
            event: {
              kind: 'operation-result',
              kindValue: 1,
              kindSymbol: 'EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2',
              resultKind: 0,
              resultKindSymbol: 'EXACT_GPU_RESULT_NONE_V2',
              status: 0,
              completionVariant: 'operation-success',
            },
          },
        ],
      },
      variants: [{
        name: 'operation-success',
        carrierConstraints: [
          {
            carrierPath:
              'record.operation_result.operation.provider_admission',
            operator: 'equal',
            value: 1,
            symbol: 'EXACT_GPU_PROVIDER_ADMITTED_V2',
          },
          {
            carrierPath:
              'record.operation_result.operation.physical_sequence',
            operator: 'positive',
          },
        ],
      }],
      noTrailingBytes: true,
    },
  };
  const expectedCreateBindGroupLayoutCanonical = canonicalManifestJson(
    expectedCreateShaderModuleRoute,
  )
    .replaceAll('GPUDevice.createShaderModule', CREATE_BIND_GROUP_LAYOUT_OPERATION_ID)
    .replaceAll('gpu-create-shader-module-service-request-v1', CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC)
    .replaceAll('GPUShaderModule', 'GPUBindGroupLayout')
    .replaceAll('shaderModuleDescriptorV1', 'bindGroupLayoutDescriptorV1')
    .replaceAll('599085487', String(CREATE_BIND_GROUP_LAYOUT_WIRE_ID))
    .replaceAll('"codecTag":7', '"codecTag":15')
    .replaceAll('"wireTag":7', '"wireTag":15')
    .replaceAll(
      'validate-wgsl-with-naga-under-logical-capabilities',
      'validate-bind-group-layout-descriptor-under-logical-device-capabilities',
    )
    .replaceAll(
      'reserve-shader-module-handle-and-aggregate-envelope',
      'reserve-bind-group-layout-handle-and-aggregate-envelope',
    )
    .replaceAll(
      'authenticate-wrapper-allocated-shader-module-target',
      'authenticate-wrapper-allocated-bind-group-layout-target',
    );
  const expectedCreateBindGroupCanonical = expectedCreateBindGroupLayoutCanonical
    .replaceAll(CREATE_BIND_GROUP_LAYOUT_OPERATION_ID, CREATE_BIND_GROUP_OPERATION_ID)
    .replaceAll(CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC, CREATE_BIND_GROUP_REQUEST_CODEC)
    .replaceAll('GPUBindGroupLayout', 'GPUBindGroup')
    .replaceAll('bindGroupLayoutDescriptorV1', 'bindGroupDescriptorV1')
    .replaceAll(String(CREATE_BIND_GROUP_LAYOUT_WIRE_ID), String(CREATE_BIND_GROUP_WIRE_ID))
    .replaceAll('"codecTag":15', '"codecTag":24')
    .replaceAll('"wireTag":15', '"wireTag":24')
    .replace(
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account","validate-bind-group-layout-descriptor-under-logical-device-capabilities","reserve-bind-group-layout-handle-and-aggregate-envelope","authenticate-wrapper-allocated-bind-group-layout-target","select-provider-admission-and-physical-sequence"]',
      '"requiredAfterDecode":["authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table","authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-exact-generated-typegpu-bind-group-full-provenance-witness","authenticate-current-same-device-bind-group-layout-full-reference-and-joined-descriptor","validate-bind-group-entry-layout-cardinality-and-exact-binding-join","authenticate-current-same-device-resource-full-references-and-creator-order","validate-buffer-sampler-texture-view-and-external-resource-compatibility","authenticate-wrapper-allocated-bind-group-target-provenance","validate-wrapper-allocated-bind-group-target-generation","reserve-bind-group-table-and-dual-ledger-capacity","commit-bind-group-layout-and-resource-dependency-retention-before-provider-admission","arm-exactly-once-terminal-unwind-for-bind-group-dependency-retention","reserve-bind-group-provider-request-completion-and-physical-sequence","validate-bind-group-label-under-reviewed-workload"]',
    );
  const expectedCreatePipelineLayoutCanonical = expectedCreateBindGroupLayoutCanonical
    .replaceAll(CREATE_BIND_GROUP_LAYOUT_OPERATION_ID, CREATE_PIPELINE_LAYOUT_OPERATION_ID)
    .replaceAll(CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC, CREATE_PIPELINE_LAYOUT_REQUEST_CODEC)
    .replaceAll('GPUBindGroupLayout', 'GPUPipelineLayout')
    .replaceAll('bindGroupLayoutDescriptorV1', 'pipelineLayoutDescriptorV1')
    .replaceAll(String(CREATE_BIND_GROUP_LAYOUT_WIRE_ID), String(CREATE_PIPELINE_LAYOUT_WIRE_ID))
    .replaceAll('"codecTag":15', '"codecTag":16')
    .replaceAll('"wireTag":15', '"wireTag":16')
    .replace(
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account","validate-bind-group-layout-descriptor-under-logical-device-capabilities","reserve-bind-group-layout-handle-and-aggregate-envelope","authenticate-wrapper-allocated-bind-group-layout-target","select-provider-admission-and-physical-sequence"]',
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account","validate-pipeline-layout-group-count-under-reviewed-workload","validate-pipeline-layout-count-under-logical-max-bind-groups","validate-pipeline-layout-non-null-group-positions","authenticate-pipeline-layout-bind-group-layout-full-references","validate-current-live-nonexclusive-bind-group-layout-generations","validate-pipeline-layout-aggregate-binding-slots-under-logical-limits","validate-pipeline-layout-immediate-alignment","validate-pipeline-layout-immediate-size-under-logical-limit","validate-pipeline-layout-label-under-reviewed-workload","reserve-pipeline-layout-handle-and-aggregate-envelope","authenticate-wrapper-allocated-pipeline-layout-target","select-provider-admission-and-physical-sequence"]',
    );
  const contentRejectionTerminalCanonical = canonicalManifestJson({
    terminalId: 'content-rejection',
    errorTiming: 'content-timeline',
    resultDisposition: 'throw',
    providerTokenCount: 0,
    physicalSequenceCount: 0,
    event: {
      kind: 'no-service-call',
      completionPayloadEncoderEligibility: 'excluded-before-service-ingress',
    },
  });
  const expectedCreateBufferCanonical = expectedCreateBindGroupLayoutCanonical
    .replaceAll(CREATE_BIND_GROUP_LAYOUT_OPERATION_ID, CREATE_BUFFER_OPERATION_ID)
    .replaceAll(CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC, CREATE_BUFFER_REQUEST_CODEC)
    .replaceAll('GPUBindGroupLayout', 'GPUBuffer')
    .replaceAll('bindGroupLayoutDescriptorV1', 'bufferDescriptorV1')
    .replaceAll(String(CREATE_BIND_GROUP_LAYOUT_WIRE_ID), String(CREATE_BUFFER_WIRE_ID))
    .replaceAll('"codecTag":15', '"codecTag":17')
    .replaceAll('"wireTag":15', '"wireTag":17')
    .replace(
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account","validate-bind-group-layout-descriptor-under-logical-device-capabilities","reserve-bind-group-layout-handle-and-aggregate-envelope","authenticate-wrapper-allocated-bind-group-layout-target","select-provider-admission-and-physical-sequence"]',
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-buffer-descriptor-under-reviewed-workload","validate-buffer-size-under-logical-max-and-structural-ceiling","validate-buffer-usage-closed-bits","validate-buffer-map-usage-combination","authenticate-wrapper-allocated-buffer-target-provenance","validate-wrapper-allocated-buffer-target-generation","reserve-buffer-table-and-dual-ledger-capacity","reserve-buffer-provider-request-completion-and-physical-sequence","validate-buffer-label-under-reviewed-workload"]',
    )
    .replace(
      '"terminalId":"webidl-rejection"},{"errorTiming":"device-timeline"',
      `"terminalId":"webidl-rejection"},${contentRejectionTerminalCanonical},{"errorTiming":"device-timeline"`,
    );
  const expectedCreateSamplerCanonical = expectedCreateBufferCanonical
    .replaceAll(CREATE_BUFFER_OPERATION_ID, CREATE_SAMPLER_OPERATION_ID)
    .replaceAll(CREATE_BUFFER_REQUEST_CODEC, CREATE_SAMPLER_REQUEST_CODEC)
    .replaceAll('GPUBuffer', 'GPUSampler')
    .replaceAll('bufferDescriptorV1', 'samplerDescriptorV1')
    .replaceAll(String(CREATE_BUFFER_WIRE_ID), String(CREATE_SAMPLER_WIRE_ID))
    .replaceAll('"codecTag":17', '"codecTag":18')
    .replaceAll('"wireTag":17', '"wireTag":18')
    .replace(
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-buffer-descriptor-under-reviewed-workload","validate-buffer-size-under-logical-max-and-structural-ceiling","validate-buffer-usage-closed-bits","validate-buffer-map-usage-combination","authenticate-wrapper-allocated-buffer-target-provenance","validate-wrapper-allocated-buffer-target-generation","reserve-buffer-table-and-dual-ledger-capacity","reserve-buffer-provider-request-completion-and-physical-sequence","validate-buffer-label-under-reviewed-workload"]',
      '"requiredAfterDecode":["authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table","authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-sampler-lod-order-and-range","validate-sampler-anisotropy-and-filter-combination","validate-sampler-label-under-reviewed-workload","validate-sampler-descriptor-under-reviewed-workload","authenticate-wrapper-allocated-sampler-target-provenance","validate-wrapper-allocated-sampler-target-generation","reserve-sampler-table-and-resource-ledger-capacity","reserve-sampler-provider-request-completion-and-physical-sequence"]',
    )
    .replace(`,${contentRejectionTerminalCanonical}`, '');
  const expectedCreateTextureCanonical = expectedCreateBufferCanonical
    .replaceAll(CREATE_BUFFER_OPERATION_ID, CREATE_TEXTURE_OPERATION_ID)
    .replaceAll(CREATE_BUFFER_REQUEST_CODEC, CREATE_TEXTURE_REQUEST_CODEC)
    .replaceAll('GPUBuffer', 'GPUTexture')
    .replaceAll('bufferDescriptorV1', 'textureDescriptorV1')
    .replaceAll(String(CREATE_BUFFER_WIRE_ID), String(CREATE_TEXTURE_WIRE_ID))
    .replaceAll('"codecTag":17', '"codecTag":19')
    .replaceAll('"wireTag":17', '"wireTag":19')
    .replace(
      '"requiredAfterDecode":["authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-buffer-descriptor-under-reviewed-workload","validate-buffer-size-under-logical-max-and-structural-ceiling","validate-buffer-usage-closed-bits","validate-buffer-map-usage-combination","authenticate-wrapper-allocated-buffer-target-provenance","validate-wrapper-allocated-buffer-target-generation","reserve-buffer-table-and-dual-ledger-capacity","reserve-buffer-provider-request-completion-and-physical-sequence","validate-buffer-label-under-reviewed-workload"]',
      '"requiredAfterDecode":["authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table","authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-texture-extent-under-logical-limits-and-structural-bounds","validate-texture-format-under-logical-capabilities","validate-texture-usage-closed-bits-and-format-compatibility","validate-texture-mip-level-and-sample-count-bounds","validate-texture-view-formats-compatibility","validate-texture-binding-view-dimension-compatibility","validate-texture-label-under-reviewed-workload","validate-texture-descriptor-under-reviewed-workload","authenticate-wrapper-allocated-texture-target-provenance","validate-wrapper-allocated-texture-target-generation","compute-checked-texture-resource-bytes-and-reserve-dual-ledger-capacity","reserve-texture-provider-request-completion-and-physical-sequence"]',
    );
  const expectedCreateTextureViewCanonical = expectedCreateTextureCanonical
    .replaceAll(CREATE_TEXTURE_OPERATION_ID, '__CREATE_TEXTURE_VIEW_OPERATION__')
    .replaceAll(CREATE_TEXTURE_REQUEST_CODEC, CREATE_TEXTURE_VIEW_REQUEST_CODEC)
    .replaceAll('GPUTexture', 'GPUTextureView')
    .replaceAll('GPUDevice', 'GPUTexture')
    .replaceAll('textureDescriptorV1', 'textureViewRequestV1')
    .replaceAll(String(CREATE_TEXTURE_WIRE_ID), String(CREATE_TEXTURE_VIEW_WIRE_ID))
    .replaceAll('"codecTag":19', '"codecTag":9')
    .replaceAll('"wireTag":19', '"wireTag":9')
    .replaceAll('__CREATE_TEXTURE_VIEW_OPERATION__', CREATE_TEXTURE_VIEW_OPERATION_ID)
    .replace(
      '"requiredAfterDecode":["authenticate-source-affine-device-receiver-and-reconstruct-authority-from-device-table","authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-device-generation","validate-operation-coverage","validate-authorized-live-account-and-aggregate-envelope","validate-texture-extent-under-logical-limits-and-structural-bounds","validate-texture-format-under-logical-capabilities","validate-texture-usage-closed-bits-and-format-compatibility","validate-texture-mip-level-and-sample-count-bounds","validate-texture-view-formats-compatibility","validate-texture-binding-view-dimension-compatibility","validate-texture-label-under-reviewed-workload","validate-texture-descriptor-under-reviewed-workload","authenticate-wrapper-allocated-texture-target-provenance","validate-wrapper-allocated-texture-target-generation","compute-checked-texture-resource-bytes-and-reserve-dual-ledger-capacity","reserve-texture-provider-request-completion-and-physical-sequence"]',
      '"requiredAfterDecode":["authenticate-source-affine-texture-receiver-and-reconstruct-authority-from-texture-table","authenticate-contiguous-sealed-local-timeline-prefix","validate-current-live-undestroyed-texture-device-and-provider-generation","authenticate-current-texture-origin-provenance-and-epoch","validate-operation-coverage","validate-authorized-live-source-account-and-aggregate-envelope-with-alias-accounting","validate-texture-view-format-and-aspect-compatibility","validate-texture-view-dimension-compatibility","validate-texture-view-subresource-range","validate-texture-view-usage-and-swizzle-capability","validate-texture-view-label-under-reviewed-workload","validate-exact-texture-view-descriptor-parent-origin-workload-tuples","authenticate-wrapper-allocated-texture-view-target-provenance","validate-wrapper-allocated-texture-view-target-generation","reserve-texture-view-table-and-independent-cost-without-backing-double-charge","reserve-texture-view-provider-request-completion-and-physical-sequence"]',
    )
    .replace(`,${contentRejectionTerminalCanonical}`, '');
  if (
    manifest.nativeCodecPrograms.routes.length !== 22 ||
    new Set(
      manifest.nativeCodecPrograms.routes.map((candidate) => candidate.operationId),
    ).size !== 22 ||
    !route ||
    !requestDeviceRoute ||
    !createBindGroupRoute ||
    !createBindGroupLayoutRoute ||
    !createBufferRoute ||
    !createPipelineLayoutRoute ||
    !createComputePipelineRoute ||
    !createRenderPipelineRoute ||
    !createSamplerRoute ||
    !createTextureRoute ||
    !createTextureViewRoute ||
    !createCommandEncoderRoute ||
    !createShaderModuleRoute ||
    !deviceDestroyRoute ||
    !bufferDestroyRoute ||
    !bufferMapAsyncRoute ||
    !bufferUnmapRoute ||
    !canvasConfigureRoute ||
    !canvasUnconfigureRoute ||
    !textureDestroyRoute ||
    !queueWriteBufferRoute ||
    !queueSubmitRoute ||
    canonicalManifestJson(createCommandEncoderRoute) !==
      canonicalManifestJson(expectedCreateCommandEncoderRoute) ||
    canonicalManifestJson(createShaderModuleRoute) !==
      canonicalManifestJson(expectedCreateShaderModuleRoute) ||
    canonicalManifestJson(createBindGroupRoute) !==
      expectedCreateBindGroupCanonical ||
    canonicalManifestJson(createBindGroupLayoutRoute) !==
      expectedCreateBindGroupLayoutCanonical ||
    canonicalManifestJson(createBufferRoute) !==
      expectedCreateBufferCanonical ||
    canonicalManifestJson(createPipelineLayoutRoute) !==
      expectedCreatePipelineLayoutCanonical ||
    sha256HexUtf8(canonicalManifestJson(createComputePipelineRoute)) !==
      EXPECTED_CREATE_COMPUTE_PIPELINE_NATIVE_ROUTE_SHA256 ||
    sha256HexUtf8(canonicalManifestJson(createRenderPipelineRoute)) !==
      EXPECTED_CREATE_RENDER_PIPELINE_NATIVE_ROUTE_SHA256 ||
    canonicalManifestJson(createSamplerRoute) !==
      expectedCreateSamplerCanonical ||
    canonicalManifestJson(createTextureRoute) !==
      expectedCreateTextureCanonical ||
    canonicalManifestJson(createTextureViewRoute) !==
      expectedCreateTextureViewCanonical ||
    !planRoute ||
    planRoute.wireId !== REQUEST_ADAPTER_WIRE_ID ||
    planRoute.serviceArgumentCodec !== REQUEST_ADAPTER_REQUEST_CODEC ||
    planRoute.serviceCompletionCodec !== REQUEST_ADAPTER_COMPLETION_CODEC ||
    requestCodec?.wireTag !== route.request.catalog.wireTag ||
    completionCodec?.wireTag !== route.completion.catalog.wireTag ||
    !requestDevicePlanRoute ||
    requestDevicePlanRoute.wireId !== REQUEST_DEVICE_WIRE_ID ||
    requestDevicePlanRoute.serviceArgumentCodec !==
      REQUEST_DEVICE_REQUEST_CODEC ||
    requestDevicePlanRoute.serviceCompletionCodec !==
      REQUEST_DEVICE_COMPLETION_CODEC ||
    requestDeviceRequestCodec?.wireTag !==
      requestDeviceRoute.request.catalog.wireTag ||
    requestDeviceRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    requestDeviceRequestCodec?.executableFromCurrentAuthenticatedInputs !== false ||
    canonicalManifestJson(
      requestDeviceRequestCodec.unavailableSemanticFields,
    ) !== canonicalManifestJson([
      'generatedLogicalProviderDescriptor',
      'authenticatedResultSelectionIdentity',
    ]) ||
    requestDeviceCompletionCodec?.wireTag !==
      requestDeviceRoute.completion.catalog.wireTag ||
    !createBindGroupPlanRoute ||
    createBindGroupPlanRoute.wireId !== CREATE_BIND_GROUP_WIRE_ID ||
    createBindGroupPlanRoute.serviceArgumentCodec !==
      CREATE_BIND_GROUP_REQUEST_CODEC ||
    createBindGroupPlanRoute.serviceCompletionCodec !==
      CREATE_BIND_GROUP_COMPLETION_CODEC ||
    createBindGroupRequestCodec?.wireTag !==
      createBindGroupRoute.request.catalog.wireTag ||
    createBindGroupRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createBindGroupRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createBindGroupRequestCodec.unavailableSemanticFields.length !== 0 ||
    createBindGroupCompletionCodec?.wireTag !==
      createBindGroupRoute.completion.catalog.wireTag ||
    !createBindGroupLayoutPlanRoute ||
    createBindGroupLayoutPlanRoute.wireId !== CREATE_BIND_GROUP_LAYOUT_WIRE_ID ||
    createBindGroupLayoutPlanRoute.serviceArgumentCodec !==
      CREATE_BIND_GROUP_LAYOUT_REQUEST_CODEC ||
    createBindGroupLayoutPlanRoute.serviceCompletionCodec !==
      CREATE_BIND_GROUP_LAYOUT_COMPLETION_CODEC ||
    createBindGroupLayoutRequestCodec?.wireTag !==
      createBindGroupLayoutRoute.request.catalog.wireTag ||
    createBindGroupLayoutRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createBindGroupLayoutRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createBindGroupLayoutRequestCodec.unavailableSemanticFields.length !== 0 ||
    createBindGroupLayoutCompletionCodec?.wireTag !==
      createBindGroupLayoutRoute.completion.catalog.wireTag ||
    !createBufferPlanRoute ||
    createBufferPlanRoute.wireId !== CREATE_BUFFER_WIRE_ID ||
    createBufferPlanRoute.serviceArgumentCodec !== CREATE_BUFFER_REQUEST_CODEC ||
    createBufferPlanRoute.serviceCompletionCodec !==
      CREATE_BUFFER_COMPLETION_CODEC ||
    createBufferRequestCodec?.wireTag !== createBufferRoute.request.catalog.wireTag ||
    createBufferRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createBufferRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createBufferRequestCodec.unavailableSemanticFields.length !== 0 ||
    createBufferCompletionCodec?.wireTag !==
      createBufferRoute.completion.catalog.wireTag ||
    !createPipelineLayoutPlanRoute ||
    createPipelineLayoutPlanRoute.wireId !== CREATE_PIPELINE_LAYOUT_WIRE_ID ||
    createPipelineLayoutPlanRoute.serviceArgumentCodec !==
      CREATE_PIPELINE_LAYOUT_REQUEST_CODEC ||
    createPipelineLayoutPlanRoute.serviceCompletionCodec !==
      CREATE_PIPELINE_LAYOUT_COMPLETION_CODEC ||
    createPipelineLayoutRequestCodec?.wireTag !==
      createPipelineLayoutRoute.request.catalog.wireTag ||
    createPipelineLayoutRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createPipelineLayoutRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createPipelineLayoutRequestCodec.unavailableSemanticFields.length !== 0 ||
    createPipelineLayoutCompletionCodec?.wireTag !==
      createPipelineLayoutRoute.completion.catalog.wireTag ||
    !createComputePipelinePlanRoute ||
    createComputePipelinePlanRoute.wireId !== CREATE_COMPUTE_PIPELINE_WIRE_ID ||
    createComputePipelinePlanRoute.serviceArgumentCodec !==
      CREATE_COMPUTE_PIPELINE_REQUEST_CODEC ||
    createComputePipelinePlanRoute.serviceCompletionCodec !==
      CREATE_COMPUTE_PIPELINE_COMPLETION_CODEC ||
    createComputePipelineRequestCodec?.wireTag !==
      createComputePipelineRoute.request.catalog.wireTag ||
    createComputePipelineRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createComputePipelineRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createComputePipelineRequestCodec.unavailableSemanticFields.length !== 0 ||
    createComputePipelineCompletionCodec?.wireTag !==
      createComputePipelineRoute.completion.catalog.wireTag ||
    !createRenderPipelinePlanRoute ||
    createRenderPipelinePlanRoute.wireId !== CREATE_RENDER_PIPELINE_WIRE_ID ||
    createRenderPipelinePlanRoute.serviceArgumentCodec !==
      CREATE_RENDER_PIPELINE_REQUEST_CODEC ||
    createRenderPipelinePlanRoute.serviceCompletionCodec !==
      CREATE_RENDER_PIPELINE_COMPLETION_CODEC ||
    createRenderPipelineRequestCodec?.wireTag !==
      createRenderPipelineRoute.request.catalog.wireTag ||
    createRenderPipelineRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createRenderPipelineRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createRenderPipelineRequestCodec.unavailableSemanticFields.length !== 0 ||
    createRenderPipelineCompletionCodec?.wireTag !==
      createRenderPipelineRoute.completion.catalog.wireTag ||
    !createSamplerPlanRoute ||
    createSamplerPlanRoute.wireId !== CREATE_SAMPLER_WIRE_ID ||
    createSamplerPlanRoute.serviceArgumentCodec !== CREATE_SAMPLER_REQUEST_CODEC ||
    createSamplerPlanRoute.serviceCompletionCodec !==
      CREATE_SAMPLER_COMPLETION_CODEC ||
    createSamplerRequestCodec?.wireTag !== createSamplerRoute.request.catalog.wireTag ||
    createSamplerRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createSamplerRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createSamplerRequestCodec.unavailableSemanticFields.length !== 0 ||
    createSamplerCompletionCodec?.wireTag !==
      createSamplerRoute.completion.catalog.wireTag ||
    !createTexturePlanRoute ||
    createTexturePlanRoute.wireId !== CREATE_TEXTURE_WIRE_ID ||
    createTexturePlanRoute.serviceArgumentCodec !== CREATE_TEXTURE_REQUEST_CODEC ||
    createTexturePlanRoute.serviceCompletionCodec !==
      CREATE_TEXTURE_COMPLETION_CODEC ||
    createTextureRequestCodec?.wireTag !== createTextureRoute.request.catalog.wireTag ||
    createTextureRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createTextureRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createTextureRequestCodec.unavailableSemanticFields.length !== 0 ||
    createTextureCompletionCodec?.wireTag !==
      createTextureRoute.completion.catalog.wireTag ||
    !createTextureViewPlanRoute ||
    createTextureViewPlanRoute.wireId !== CREATE_TEXTURE_VIEW_WIRE_ID ||
    createTextureViewPlanRoute.serviceArgumentCodec !==
      CREATE_TEXTURE_VIEW_REQUEST_CODEC ||
    createTextureViewPlanRoute.serviceCompletionCodec !==
      CREATE_TEXTURE_VIEW_COMPLETION_CODEC ||
    createTextureViewRequestCodec?.wireTag !==
      createTextureViewRoute.request.catalog.wireTag ||
    createTextureViewRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createTextureViewRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createTextureViewRequestCodec.unavailableSemanticFields.length !== 0 ||
    createTextureViewCompletionCodec?.wireTag !==
      createTextureViewRoute.completion.catalog.wireTag ||
    !createCommandEncoderPlanRoute ||
    createCommandEncoderPlanRoute.wireId !== CREATE_COMMAND_ENCODER_WIRE_ID ||
    createCommandEncoderPlanRoute.serviceArgumentCodec !==
      CREATE_COMMAND_ENCODER_REQUEST_CODEC ||
    createCommandEncoderPlanRoute.serviceCompletionCodec !==
      CREATE_COMMAND_ENCODER_COMPLETION_CODEC ||
    createCommandEncoderRequestCodec?.wireTag !==
      createCommandEncoderRoute.request.catalog.wireTag ||
    createCommandEncoderRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createCommandEncoderRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createCommandEncoderRequestCodec.unavailableSemanticFields.length !== 0 ||
    createCommandEncoderCompletionCodec?.wireTag !==
      createCommandEncoderRoute.completion.catalog.wireTag ||
    !createShaderModulePlanRoute ||
    createShaderModulePlanRoute.wireId !== CREATE_SHADER_MODULE_WIRE_ID ||
    createShaderModulePlanRoute.serviceArgumentCodec !==
      CREATE_SHADER_MODULE_REQUEST_CODEC ||
    createShaderModulePlanRoute.serviceCompletionCodec !==
      CREATE_SHADER_MODULE_COMPLETION_CODEC ||
    createShaderModuleRequestCodec?.wireTag !==
      createShaderModuleRoute.request.catalog.wireTag ||
    createShaderModuleRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    createShaderModuleRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    createShaderModuleRequestCodec.unavailableSemanticFields.length !== 0 ||
    createShaderModuleCompletionCodec?.wireTag !==
      createShaderModuleRoute.completion.catalog.wireTag ||
    !deviceDestroyPlanRoute ||
    deviceDestroyPlanRoute.wireId !== DEVICE_DESTROY_WIRE_ID ||
    deviceDestroyPlanRoute.serviceArgumentCodec !==
      DEVICE_DESTROY_REQUEST_CODEC ||
    deviceDestroyPlanRoute.serviceCompletionCodec !==
      DEVICE_DESTROY_COMPLETION_CODEC ||
    deviceDestroyRequestCodec?.wireTag !==
      deviceDestroyRoute.request.catalog.wireTag ||
    deviceDestroyRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    deviceDestroyRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    deviceDestroyRequestCodec.unavailableSemanticFields.length !== 0 ||
    deviceDestroyCompletionCodec?.wireTag !==
      deviceDestroyRoute.completion.catalog.wireTag ||
    !bufferDestroyPlanRoute ||
    bufferDestroyPlanRoute.wireId !== BUFFER_DESTROY_WIRE_ID ||
    bufferDestroyPlanRoute.serviceArgumentCodec !== BUFFER_DESTROY_REQUEST_CODEC ||
    bufferDestroyPlanRoute.serviceCompletionCodec !== BUFFER_CLEANUP_COMPLETION_CODEC ||
    bufferDestroyRequestCodec?.wireTag !== bufferDestroyRoute.request.catalog.wireTag ||
    bufferDestroyRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    bufferDestroyRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    bufferDestroyRequestCodec.unavailableSemanticFields.length !== 0 ||
    bufferCleanupCompletionCodec?.wireTag !== bufferDestroyRoute.completion.catalog.wireTag ||
    !bufferMapAsyncPlanRoute ||
    bufferMapAsyncPlanRoute.wireId !== BUFFER_MAP_ASYNC_WIRE_ID ||
    bufferMapAsyncPlanRoute.serviceArgumentCodec !== BUFFER_MAP_ASYNC_REQUEST_CODEC ||
    bufferMapAsyncPlanRoute.serviceCompletionCodec !== BUFFER_MAP_ASYNC_COMPLETION_CODEC ||
    bufferMapAsyncRequestCodec?.wireTag !== bufferMapAsyncRoute.request.catalog.wireTag ||
    bufferMapAsyncRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    bufferMapAsyncRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    bufferMapAsyncRequestCodec.unavailableSemanticFields.length !== 0 ||
    bufferMapAsyncCompletionCodec?.wireTag !== bufferMapAsyncRoute.completion.catalog.wireTag ||
    !bufferUnmapPlanRoute ||
    bufferUnmapPlanRoute.wireId !== BUFFER_UNMAP_WIRE_ID ||
    bufferUnmapPlanRoute.serviceArgumentCodec !== BUFFER_UNMAP_REQUEST_CODEC ||
    bufferUnmapPlanRoute.serviceCompletionCodec !== BUFFER_CLEANUP_COMPLETION_CODEC ||
    bufferUnmapRequestCodec?.wireTag !== bufferUnmapRoute.request.catalog.wireTag ||
    bufferUnmapRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    bufferUnmapRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    bufferUnmapRequestCodec.unavailableSemanticFields.length !== 0 ||
    bufferCleanupCompletionCodec?.wireTag !== bufferUnmapRoute.completion.catalog.wireTag ||
    !queueWriteBufferPlanRoute ||
    queueWriteBufferPlanRoute.wireId !== QUEUE_WRITE_BUFFER_WIRE_ID ||
    queueWriteBufferPlanRoute.serviceArgumentCodec !==
      QUEUE_WRITE_BUFFER_REQUEST_CODEC ||
    queueWriteBufferPlanRoute.serviceCompletionCodec !==
      QUEUE_WRITE_BUFFER_COMPLETION_CODEC ||
    queueWriteBufferRequestCodec?.wireTag !==
      queueWriteBufferRoute.request.catalog.wireTag ||
    queueWriteBufferRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    queueWriteBufferRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    queueWriteBufferRequestCodec.unavailableSemanticFields.length !== 0 ||
    queueWriteBufferCompletionCodec?.wireTag !==
      queueWriteBufferRoute.completion.catalog.wireTag ||
    !queueSubmitPlanRoute ||
    queueSubmitPlanRoute.wireId !== QUEUE_SUBMIT_WIRE_ID ||
    queueSubmitPlanRoute.serviceArgumentCodec !== QUEUE_SUBMIT_REQUEST_CODEC ||
    queueSubmitPlanRoute.serviceCompletionCodec !== QUEUE_SUBMIT_COMPLETION_CODEC ||
    queueSubmitRequestCodec?.wireTag !== queueSubmitRoute.request.catalog.wireTag ||
    queueSubmitRequestCodec?.nativeProgramPrerequisitesRepresented !== true ||
    queueSubmitRequestCodec?.executableFromCurrentAuthenticatedInputs !== true ||
    queueSubmitRequestCodec.unavailableSemanticFields.length !== 0 ||
    queueSubmitCompletionCodec?.wireTag !==
      queueSubmitRoute.completion.catalog.wireTag ||
    manifest.layout.requestMagic !== 'IBGQ' ||
    manifest.layout.resultMagic !== 'IBGR' ||
    manifest.layout.version !== 1 ||
    manifest.objectKindTags.GPU !== 1 ||
    manifest.objectKindTags.GPUAdapter !== 2 ||
    manifest.objectKindTags.GPUDevice !== 3 ||
    manifest.objectKindTags.GPUQueue !== 4 ||
    manifest.objectKindTags.GPUBuffer !== 5 ||
    manifest.objectKindTags.GPUTexture !== 6 ||
    manifest.objectKindTags.GPUTextureView !== 7 ||
    manifest.objectKindTags.GPUSampler !== 8 ||
    manifest.objectKindTags.GPUBindGroupLayout !== 9 ||
    manifest.objectKindTags.GPUBindGroup !== 10 ||
    manifest.objectKindTags.GPUPipelineLayout !== 11 ||
    manifest.objectKindTags.GPUShaderModule !== 12 ||
    manifest.objectKindTags.GPUComputePipeline !== 13 ||
    manifest.objectKindTags.GPURenderPipeline !== 14 ||
    manifest.objectKindTags.GPUCommandEncoder !== 15 ||
    expectedObjectKindTags.GPU !== 1 ||
    expectedObjectKindTags.GPUAdapter !== 2 ||
    expectedObjectKindTags.GPUDevice !== 3 ||
    expectedObjectKindTags.GPUQueue !== 4 ||
    expectedObjectKindTags.GPUBuffer !== 5 ||
    expectedObjectKindTags.GPUTexture !== 6 ||
    expectedObjectKindTags.GPUTextureView !== 7 ||
    expectedObjectKindTags.GPUSampler !== 8 ||
    expectedObjectKindTags.GPUBindGroupLayout !== 9 ||
    expectedObjectKindTags.GPUBindGroup !== 10 ||
    expectedObjectKindTags.GPUPipelineLayout !== 11 ||
    expectedObjectKindTags.GPUShaderModule !== 12 ||
    expectedObjectKindTags.GPUComputePipeline !== 13 ||
    expectedObjectKindTags.GPURenderPipeline !== 14 ||
    expectedObjectKindTags.GPUCommandEncoder !== 15 ||
    nullVariant?.resultKind !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NULL_V2 ||
    objectVariant?.resultKind !==
      manifest.carrierConstants.EXACT_GPU_RESULT_OBJECT_V2 ||
    deviceDestroyRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createCommandEncoderRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createBindGroupRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createBindGroupLayoutRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createBufferRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createPipelineLayoutRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createComputePipelineRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createRenderPipelineRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createSamplerRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createTextureRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createTextureViewRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    createShaderModuleRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    bufferDestroyRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    bufferMapAsyncRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_BYTES_V2 ||
    bufferUnmapRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    canvasConfigureRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    canvasUnconfigureRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    textureDestroyRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    queueWriteBufferRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2 ||
    queueSubmitRoute.completion.commonCarrierConstraints.at(-1)?.value !==
      manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2
  ) {
    throw new Error('Generated WebGPU native codec program cross-link drifted');
  }
  return Object.freeze({
    route,
    requestDeviceRoute,
    createBindGroupRoute,
    createBindGroupLayoutRoute,
    createBufferRoute,
    createPipelineLayoutRoute,
    createComputePipelineRoute,
    createRenderPipelineRoute,
    createSamplerRoute,
    createTextureRoute,
    createTextureViewRoute,
    createCommandEncoderRoute,
    createShaderModuleRoute,
    deviceDestroyRoute,
    bufferDestroyRoute,
    bufferMapAsyncRoute,
    bufferUnmapRoute,
    canvasConfigureRoute,
    canvasUnconfigureRoute,
    textureDestroyRoute,
    queueWriteBufferRoute,
    queueSubmitRoute,
    noneResultKind: manifest.carrierConstants.EXACT_GPU_RESULT_NONE_V2,
    nullResultKind: manifest.carrierConstants.EXACT_GPU_RESULT_NULL_V2,
    objectResultKind: manifest.carrierConstants.EXACT_GPU_RESULT_OBJECT_V2,
    bytesResultKind: manifest.carrierConstants.EXACT_GPU_RESULT_BYTES_V2,
    operationResultEventKind:
      manifest.carrierConstants.EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2,
    unchangedDeviceTransition:
      manifest.carrierConstants.EXACT_GPU_DEVICE_UNCHANGED_V2,
    assignedDeviceTransition:
      manifest.carrierConstants.EXACT_GPU_DEVICE_ASSIGNED_V2,
    assignedDetachedDeviceTransition:
      manifest.carrierConstants.EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2,
    providerNotAdmitted:
      manifest.carrierConstants.EXACT_GPU_PROVIDER_NOT_ADMITTED_V2,
    providerAdmitted:
      manifest.carrierConstants.EXACT_GPU_PROVIDER_ADMITTED_V2,
  });
}

function dictionary(value: unknown, label: string): Record<PropertyKey, unknown> {
  if (value === undefined || value === null) return Object.create(null);
  if (!isObjectLike(value)) {
    throw new TypeError(`${label} must be a dictionary`);
  }
  return value;
}

function webIdlString(value: unknown, label: string): string {
  if (typeof value === 'symbol') throw new TypeError(`${label} cannot be a Symbol`);
  return String(value);
}

function webIdlUsvString(value: unknown, label: string): string {
  const converted = webIdlString(value, label);
  let result = '';
  for (let index = 0; index < converted.length; index += 1) {
    const codeUnit = converted.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = converted.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        result += converted[index] + converted[index + 1];
        index += 1;
      } else {
        result += '\ufffd';
      }
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      result += '\ufffd';
    } else {
      result += converted[index];
    }
  }
  return result;
}

function enumValue(
  value: unknown,
  values: readonly string[],
  label: string,
): string {
  const converted = webIdlString(value, label);
  if (!values.includes(converted)) {
    throw new TypeError(`${label} is not a supported enum value`);
  }
  return converted;
}

function u32(value: unknown, label: string, defaultValue?: number): number {
  if (value === undefined && defaultValue !== undefined) return defaultValue;
  // Web IDL [EnforceRange] uses ToNumber, not the Number constructor. Unary
  // plus preserves that distinction: primitive BigInts and objects whose
  // numeric primitive is a BigInt throw instead of being explicitly accepted
  // by Number(...).
  const converted = +(value as number);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be an unsigned 32-bit integer`);
  }
  const integer = Math.trunc(converted);
  if (integer < 0 || integer >= 0x1_0000_0000) {
    throw new TypeError(`${label} must be an unsigned 32-bit integer`);
  }
  return Object.is(integer, -0) ? 0 : integer;
}

function i32(value: unknown, label: string, defaultValue?: number): number {
  if (value === undefined && defaultValue !== undefined) return defaultValue;
  const converted = +(value as number);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be a signed 32-bit integer`);
  }
  const integer = Math.trunc(converted);
  if (integer < -0x8000_0000 || integer > 0x7fff_ffff) {
    throw new TypeError(`${label} must be a signed 32-bit integer`);
  }
  return Object.is(integer, -0) ? 0 : integer;
}

function u64Number(value: unknown, label: string): number {
  const converted = +(value as number);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be an unsigned 64-bit integer`);
  }
  const integer = Math.trunc(converted);
  // Web IDL narrows both signed and unsigned 64-bit conversions to the safe
  // integer interval so [EnforceRange] remains unambiguous in ECMAScript.
  if (integer < 0 || integer > Number.MAX_SAFE_INTEGER) {
    throw new TypeError(`${label} must be an unsigned 64-bit integer`);
  }
  return Object.is(integer, -0) ? 0 : integer;
}

function finiteNumber(value: unknown, label: string): number {
  // Web IDL's double conversion uses ToNumber, which rejects BigInt. The
  // Number constructor is observably different because it accepts BigInt.
  const converted = +(value as number);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be finite`);
  }
  return converted;
}

function restrictedFloat(value: unknown, label: string): number {
  const converted = +(value as number);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be a finite float`);
  }
  const rounded = Math.fround(converted);
  if (!Number.isFinite(rounded)) {
    throw new TypeError(`${label} is outside the finite float range`);
  }
  return rounded;
}

function clampUnsignedShort(value: unknown, label: string): number {
  const converted = +(value as number);
  if (Number.isNaN(converted) || converted <= 0) return 0;
  if (converted >= 0xffff) return 0xffff;
  const lower = Math.floor(converted);
  const fraction = converted - lower;
  if (fraction < 0.5) return lower;
  if (fraction > 0.5) return lower + 1;
  return lower % 2 === 0 ? lower : lower + 1;
}

function convertExtent3D(
  value: unknown,
  maximum: number,
): Readonly<{
  size: Readonly<{
    width: number;
    height: number;
    depthOrArrayLayers: number;
  }>;
  iterableLength: number | null;
}> {
  if (!isObjectLike(value)) {
    throw new TypeError('GPUTextureDescriptor.size must be an iterable or dictionary');
  }
  const iteratorMethod = value[Symbol.iterator];
  if (iteratorMethod !== undefined && iteratorMethod !== null) {
    if (typeof iteratorMethod !== 'function') {
      throw new TypeError('GPUTextureDescriptor.size @@iterator must be callable');
    }
    const sourceIterator = Reflect.apply(iteratorMethod, value, []);
    if (!isIteratorObjectForNativeForOf(sourceIterator)) {
      throw new TypeError('GPUTextureDescriptor.size iterator must be an object');
    }
    const converted: number[] = [];
    const iterable = {
      [Symbol.iterator]() {
        return sourceIterator;
      },
    };
    for (const member of iterable) {
      if (converted.length >= maximum) {
        throw new TypeError(
          'GPUTextureDescriptor.size sequence exceeds the structural transport bound',
        );
      }
      converted.push(
        u32(member, `GPUTextureDescriptor.size[${converted.length}]`),
      );
    }
    return frozenRecord({
      size: frozenRecord({
        // Invalid empty and overlong iterable shapes are rejected only after
        // the complete enclosing descriptor has been converted. These
        // placeholders can therefore never enter the service boundary.
        width: converted[0] ?? 0,
        height: converted[1] ?? 1,
        depthOrArrayLayers: converted[2] ?? 1,
      }),
      iterableLength: converted.length,
    });
  }

  // Web IDL dictionary conversion observes members lexicographically.
  const depthValue = value.depthOrArrayLayers;
  const depthOrArrayLayers = u32(
    depthValue,
    'GPUTextureDescriptor.size.depthOrArrayLayers',
    1,
  );
  const heightValue = value.height;
  const height = u32(heightValue, 'GPUTextureDescriptor.size.height', 1);
  const widthValue = value.width;
  if (widthValue === undefined) {
    throw new TypeError('GPUTextureDescriptor.size.width is required');
  }
  const width = u32(widthValue, 'GPUTextureDescriptor.size.width');
  return frozenRecord({
    size: frozenRecord({ width, height, depthOrArrayLayers }),
    iterableLength: null,
  });
}

function convertOrigin3DArgument(
  value: unknown,
  label: string,
): Readonly<{ x: number; y: number; z: number }> {
  if (!isObjectLike(value)) {
    throw new TypeError(`${label} must be an iterable or dictionary`);
  }
  const iteratorMethod = value[Symbol.iterator];
  if (iteratorMethod !== undefined && iteratorMethod !== null) {
    const members = sequence(value, label, 3, (member, index) =>
      u32(member, `${label}[${index}]`));
    return frozenRecord({
      x: (members[0] as number | undefined) ?? 0,
      y: (members[1] as number | undefined) ?? 0,
      z: (members[2] as number | undefined) ?? 0,
    });
  }
  const source = dictionary(value, label);
  const x = u32(source.x, `${label}.x`, 0);
  const y = u32(source.y, `${label}.y`, 0);
  const z = u32(source.z, `${label}.z`, 0);
  return frozenRecord({ x, y, z });
}

function convertCopyExtent3DArgument(
  value: unknown,
  label: string,
): Readonly<{ width: number; height: number; depthOrArrayLayers: number }> {
  if (!isObjectLike(value)) {
    throw new TypeError(`${label} must be an iterable or dictionary`);
  }
  const iteratorMethod = value[Symbol.iterator];
  if (iteratorMethod !== undefined && iteratorMethod !== null) {
    const members = sequence(value, label, 3, (member, index) =>
      u32(member, `${label}[${index}]`));
    if (members.length === 0) {
      throw new TypeError(`${label} must contain one to three members`);
    }
    return frozenRecord({
      width: members[0] as number,
      height: (members[1] as number | undefined) ?? 1,
      depthOrArrayLayers: (members[2] as number | undefined) ?? 1,
    });
  }
  const source = dictionary(value, label);
  const depthOrArrayLayers = u32(
    source.depthOrArrayLayers,
    `${label}.depthOrArrayLayers`,
    1,
  );
  const height = u32(source.height, `${label}.height`, 1);
  if (source.width === undefined) {
    throw new TypeError(`${label}.width is required`);
  }
  const width = u32(source.width, `${label}.width`);
  return frozenRecord({ width, height, depthOrArrayLayers });
}

function convertComputePassDescriptorArguments(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  const source = dictionary(value, 'GPUComputePassDescriptor');
  const label = optionalLabel(source);
  const timestampWritesValue = source.timestampWrites;
  if (timestampWritesValue === undefined) {
    return frozenRecord({ label, timestampWrites: null });
  }
  const timestampWrites = dictionary(
    timestampWritesValue,
    'GPUComputePassTimestampWrites',
  );
  const beginningOfPassWriteIndex = timestampWrites.beginningOfPassWriteIndex ===
      undefined
    ? null
    : u32(
      timestampWrites.beginningOfPassWriteIndex,
      'GPUComputePassTimestampWrites.beginningOfPassWriteIndex',
    );
  const endOfPassWriteIndex = timestampWrites.endOfPassWriteIndex === undefined
    ? null
    : u32(
      timestampWrites.endOfPassWriteIndex,
      'GPUComputePassTimestampWrites.endOfPassWriteIndex',
    );
  const querySet = wrappers.referenceIfBranded(
    timestampWrites.querySet,
    'GPUQuerySet',
  ) ?? null;
  return frozenRecord({
    label,
    timestampWrites: frozenRecord({
      beginningOfPassWriteIndex,
      endOfPassWriteIndex,
      querySet,
    }),
  });
}

function convertClearBufferArguments(
  args: readonly unknown[],
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  if (args.length < 1) throw new TypeError('clearBuffer requires a buffer');
  return frozenRecord({
    buffer: wrappers.reference(args[0], 'GPUBuffer'),
    offset: args[1] === undefined
      ? 0
      : u64Number(args[1], 'GPUCommandEncoder.clearBuffer offset'),
    size: args[2] === undefined
      ? null
      : u64Number(args[2], 'GPUCommandEncoder.clearBuffer size'),
  });
}

function convertCopyBufferToBufferArguments(
  args: readonly unknown[],
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  if (args.length < 2) {
    throw new TypeError('copyBufferToBuffer requires source and destination');
  }
  const source = wrappers.reference(args[0], 'GPUBuffer');
  const shortDestination = wrappers.referenceIfBranded(args[1], 'GPUBuffer');
  if (shortDestination !== undefined) {
    return frozenRecord({
      source,
      sourceOffset: 0,
      destination: shortDestination,
      destinationOffset: 0,
      size: args[2] === undefined
        ? null
        : u64Number(args[2], 'GPUCommandEncoder.copyBufferToBuffer size'),
      overload: 'short',
    });
  }
  if (args.length < 3) {
    throw new TypeError('copyBufferToBuffer full overload requires a destination');
  }
  return frozenRecord({
    source,
    sourceOffset: u64Number(
      args[1],
      'GPUCommandEncoder.copyBufferToBuffer sourceOffset',
    ),
    destination: wrappers.reference(args[2], 'GPUBuffer'),
    destinationOffset: u64Number(
      args[3],
      'GPUCommandEncoder.copyBufferToBuffer destinationOffset',
    ),
    size: args[4] === undefined
      ? null
      : u64Number(args[4], 'GPUCommandEncoder.copyBufferToBuffer size'),
    overload: 'full',
  });
}

function convertTextureCopyViewArgument(
  value: unknown,
  label: string,
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  const source = dictionary(value, label);
  const aspect = source.aspect === undefined
    ? 'all'
    : enumValue(
      source.aspect,
      ['all', 'stencil-only', 'depth-only'],
      `${label}.aspect`,
    );
  const mipLevel = u32(source.mipLevel, `${label}.mipLevel`, 0);
  const origin = source.origin === undefined
    ? frozenRecord({ x: 0, y: 0, z: 0 })
    : convertOrigin3DArgument(source.origin, `${label}.origin`);
  if (source.texture === undefined) {
    throw new TypeError(`${label}.texture is required`);
  }
  return frozenRecord({
    aspect,
    mipLevel,
    origin,
    texture: wrappers.reference(source.texture, 'GPUTexture'),
  });
}

function convertCopyTextureToTextureArguments(
  args: readonly unknown[],
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  return frozenRecord({
    source: convertTextureCopyViewArgument(
      args[0],
      'GPUCommandEncoder.copyTextureToTexture source',
      wrappers,
    ),
    destination: convertTextureCopyViewArgument(
      args[1],
      'GPUCommandEncoder.copyTextureToTexture destination',
      wrappers,
    ),
    copySize: convertCopyExtent3DArgument(
      args[2],
      'GPUCommandEncoder.copyTextureToTexture copySize',
    ),
  });
}

function convertSetBindGroupArguments(
  args: readonly unknown[],
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  if (args.length < 2) {
    throw new TypeError('setBindGroup requires index and bindGroup');
  }
  const index = u32(args[0], 'setBindGroup index');
  const bindGroup = args[1] === null || args[1] === undefined
    ? null
    : wrappers.reference(args[1], 'GPUBindGroup');
  if (args.length >= 5) {
    const start = u64Number(args[3], 'dynamicOffsetsDataStart');
    const length = u32(args[4], 'dynamicOffsetsDataLength');
    let tag: unknown;
    let byteLength: number;
    try {
      tag = Reflect.apply(TYPED_ARRAY_TAG_GETTER, args[2], []);
      byteLength = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH_GETTER, args[2], []);
    } catch {
      throw new TypeError('dynamicOffsetsData must be a Uint32Array');
    }
    if (tag !== 'Uint32Array') {
      throw new TypeError('dynamicOffsetsData must be a Uint32Array');
    }
    const sourceLength = byteLength / 4;
    if (start > sourceLength || length > sourceLength - start) {
      throw new RangeError('dynamicOffsetsData range exceeds the source Uint32Array');
    }
    if (length > maximum) {
      throw new RangeError('dynamicOffsetsData range exceeds the reviewed sequence bound');
    }
    const source = args[2] as Readonly<Record<number, number>>;
    const dynamicOffsets: number[] = [];
    for (let offsetIndex = 0; offsetIndex < length; offsetIndex += 1) {
      dynamicOffsets.push(source[start + offsetIndex]);
    }
    return frozenRecord({
      index,
      bindGroup,
      dynamicOffsets: Object.freeze(dynamicOffsets),
      overload: 'uint32-range',
    });
  }
  if (args.length === 4) {
    throw new TypeError('setBindGroup overload requires either three or five arguments');
  }
  const dynamicOffsets = args[2] === undefined
    ? []
    : sequence(
      args[2],
      'dynamicOffsets',
      maximum,
      (member, offsetIndex) =>
        u32(member, `dynamicOffsets[${offsetIndex}]`),
    );
  return frozenRecord({
    index,
    bindGroup,
    dynamicOffsets: Object.freeze(dynamicOffsets),
    overload: 'iterable',
  });
}

function convertSetVertexBufferArguments(
  args: readonly unknown[],
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  return frozenRecord({
    slot: u32(args[0], 'GPURenderPassEncoder.setVertexBuffer slot'),
    buffer: args[1] === null || args[1] === undefined
      ? null
      : wrappers.reference(args[1], 'GPUBuffer'),
    offset: args[2] === undefined
      ? 0
      : u64Number(args[2], 'GPURenderPassEncoder.setVertexBuffer offset'),
    size: args[3] === undefined
      ? null
      : u64Number(args[3], 'GPURenderPassEncoder.setVertexBuffer size'),
  });
}

function sequence(
  value: unknown,
  label: string,
  maximum: number,
  convertMember: (member: unknown, index: number) => unknown = (member) => member,
): readonly unknown[] {
  if (!isObjectLike(value)) {
    throw new TypeError(`${label} must be iterable`);
  }
  const iterator = value[Symbol.iterator];
  if (typeof iterator !== 'function') {
    throw new TypeError(`${label} must be iterable`);
  }
  const output: unknown[] = [];
  const sourceIterator = Reflect.apply(iterator, value, []);
  if (!isIteratorObjectForNativeForOf(sourceIterator)) {
    throw new TypeError(`${label} iterator must be an object`);
  }
  // The wrapper lets native for-of own IteratorStep and IteratorClose while
  // preserving the single observable Get/Call of the source @@iterator.
  const iterable = {
    [Symbol.iterator]() {
      return sourceIterator;
    },
  };
  for (const member of iterable) {
    if (output.length >= maximum) {
      throw new TypeError(`${label} exceeds the reviewed sequence bound`);
    }
    output.push(convertMember(member, output.length));
  }
  return output;
}

// The manual prefix of Web IDL's GetIterator has established only that the
// result is an object at this point. Native for-of must remain responsible for
// the observable Get of `next`, its callability check, IteratorStep, and
// IteratorClose. This guard therefore narrows the object for TypeScript
// without eagerly touching any of those user-observable properties.
function isIteratorObjectForNativeForOf(
  value: unknown,
): value is Iterator<unknown, unknown, unknown> {
  return isObjectLike(value);
}

function frozenRecord<const Entries extends Readonly<Record<string, unknown>>>(
  entries: Entries,
): Readonly<Entries> {
  return Object.freeze(entries);
}

function optionalLabel(value: Record<PropertyKey, unknown>): string {
  const label = value.label;
  return label === undefined
    ? ''
    : webIdlUsvString(label, 'label');
}

function convertConstants(
  value: unknown,
  label: string,
): Readonly<Record<string, number>> {
  const source = value === undefined ? Object.create(null) : value;
  if (!isObjectLike(source)) {
    throw new TypeError(`${label} must be an object`);
  }
  // Web IDL record conversion gets all own keys once, then interleaves each
  // descriptor check, key conversion, value Get, and value conversion. Using
  // Object.keys here would observe every descriptor before the first value
  // Get and would silently skip an enumerable Symbol instead of rejecting it.
  const convertedEntries = new Map<string, number>();
  for (const key of Reflect.ownKeys(source)) {
    const descriptor = Reflect.getOwnPropertyDescriptor(source, key);
    if (descriptor?.enumerable !== true) continue;
    const convertedKey = webIdlUsvString(key, `${label} key`);
    const convertedValue = finiteNumber(
      Reflect.get(source, key),
      `${label}.${convertedKey}`,
    );
    // USVString conversion can collapse distinct raw keys containing lone
    // surrogates. Ordered-map Set replaces the earlier value without moving
    // the key, exactly as Web IDL requires.
    convertedEntries.set(convertedKey, convertedValue);
  }
  const result: Record<string, number> = {};
  const canonicalEntries = [...convertedEntries].sort(([left], [right]) =>
    compareCanonicalUtf8(left, right));
  for (const [key, converted] of canonicalEntries) {
    // CreateDataProperty semantics preserve legal record keys such as
    // "__proto__" instead of invoking Object.prototype's legacy setter.
    Object.defineProperty(result, key, {
      configurable: false,
      enumerable: true,
      value: converted,
      writable: false,
    });
  }
  return Object.freeze(result);
}

function convertRequestAdapterOptions(value: unknown): unknown {
  const source = dictionary(value, 'GPURequestAdapterOptions');
  const featureLevelSource = source.featureLevel;
  const featureLevel = featureLevelSource === undefined
    ? 'core'
    : webIdlString(
      featureLevelSource,
      'GPURequestAdapterOptions.featureLevel',
    );
  const forceFallbackAdapter = Boolean(source.forceFallbackAdapter);
  const powerPreferenceSource = source.powerPreference;
  const powerPreference = powerPreferenceSource === undefined
    ? undefined
    : enumValue(
      powerPreferenceSource,
      ['low-power', 'high-performance'],
      'GPURequestAdapterOptions.powerPreference',
    );
  const xrCompatible = Boolean(source.xrCompatible);
  const result: Record<string, unknown> = {
    forceFallbackAdapter,
    featureLevel,
    xrCompatible,
  };
  if (powerPreference !== undefined) {
    result.powerPreference = powerPreference;
  }
  return frozenRecord(result);
}

function convertDeviceDescriptor(value: unknown, maximum: number): unknown {
  const source = dictionary(value, 'GPUDeviceDescriptor');
  const requestedFeatures = source.requiredFeatures === undefined
    ? []
    : sequence(source.requiredFeatures, 'requiredFeatures', maximum);
  const features = requestedFeatures.map((feature) =>
    webIdlString(feature, 'requiredFeatures member'));
  const requiredLimits = dictionary(
    source.requiredLimits,
    'GPUDeviceDescriptor.requiredLimits',
  );
  const limits = Object.create(null) as Record<string, number>;
  for (const key of Object.keys(requiredLimits).sort()) {
    const requested = requiredLimits[key];
    if (requested !== undefined) {
      limits[key] = u64Number(requested, `requiredLimits.${key}`);
    }
  }
  const defaultQueue = dictionary(
    source.defaultQueue,
    'GPUQueueDescriptor',
  );
  return frozenRecord({
    label: optionalLabel(source),
    requiredFeatures: Object.freeze(features),
    requiredLimits: Object.freeze(limits),
    defaultQueue: frozenRecord({ label: optionalLabel(defaultQueue) }),
  });
}

function convertCanvasConfiguration(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
  textureFormats: readonly string[],
): unknown {
  const source = dictionary(value, 'GPUCanvasConfiguration');
  // Web IDL dictionary members are observed in lexicographic order. Keep
  // every Get in a local so hostile accessors run exactly once and a failure
  // stops before every later member.
  const alphaModeValue = source.alphaMode;
  const alphaMode = alphaModeValue === undefined
    ? 'opaque'
    : enumValue(
      alphaModeValue,
      ['opaque', 'premultiplied'],
      'GPUCanvasConfiguration.alphaMode',
    );
  const colorSpaceValue = source.colorSpace;
  const colorSpace = colorSpaceValue === undefined
    ? 'srgb'
    : enumValue(
      colorSpaceValue,
      ['srgb', 'display-p3'],
      'GPUCanvasConfiguration.colorSpace',
    );
  const device = source.device;
  wrappers.reference(device, 'GPUDevice');
  const formatValue = source.format;
  if (formatValue === undefined) {
    throw new TypeError('GPUCanvasConfiguration.format is required');
  }
  const format = enumValue(
    formatValue,
    textureFormats,
    'GPUCanvasConfiguration.format',
  );
  const toneMappingValue = source.toneMapping;
  const toneMapping = dictionary(
    toneMappingValue,
    'GPUCanvasToneMapping',
  );
  const toneMappingModeValue = toneMapping.mode;
  const toneMappingMode = toneMappingModeValue === undefined
    ? 'standard'
    : enumValue(
      toneMappingModeValue,
      ['standard', 'extended'],
      'GPUCanvasToneMapping.mode',
    );
  const usageValue = source.usage;
  const usage = u32(
    usageValue,
    'GPUCanvasConfiguration.usage',
    0x10,
  );
  const viewFormatsValue = source.viewFormats;
  const viewFormats = Object.freeze(
    (viewFormatsValue === undefined
      ? []
      : sequence(
        viewFormatsValue,
        'GPUCanvasConfiguration.viewFormats',
        maximum,
      )
    ).map((candidate) =>
      enumValue(
        candidate,
        textureFormats,
        'GPUCanvasConfiguration.viewFormats member',
      )),
  );
  return frozenRecord({
    alphaMode,
    colorSpace,
    device,
    format,
    toneMapping: frozenRecord({ mode: toneMappingMode }),
    usage,
    viewFormats,
  });
}

function convertColor(value: unknown): Readonly<Record<string, number>> {
  if (Array.isArray(value)) {
    if (value.length !== 4) throw new TypeError('GPUColor sequence must have four members');
    return frozenRecord({
      r: finiteNumber(value[0], 'GPUColor.r'),
      g: finiteNumber(value[1], 'GPUColor.g'),
      b: finiteNumber(value[2], 'GPUColor.b'),
      a: finiteNumber(value[3], 'GPUColor.a'),
    }) as Readonly<Record<string, number>>;
  }
  const source = dictionary(value, 'GPUColor');
  return frozenRecord({
    r: finiteNumber(source.r, 'GPUColor.r'),
    g: finiteNumber(source.g, 'GPUColor.g'),
    b: finiteNumber(source.b, 'GPUColor.b'),
    a: finiteNumber(source.a, 'GPUColor.a'),
  }) as Readonly<Record<string, number>>;
}

function convertRenderPassDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const source = dictionary(value, 'GPURenderPassDescriptor');
  const sourceAttachments = source.colorAttachments === undefined
    ? []
    : sequence(source.colorAttachments, 'colorAttachments', maximum);
  const attachments = sourceAttachments.map((attachment, index) => {
    if (attachment === null) return null;
    const row = dictionary(attachment, `colorAttachments[${index}]`);
    const result: Record<string, unknown> = {
      view: wrappers.reference(row.view, 'GPUTextureView'),
      loadOp: row.loadOp === undefined
        ? 'load'
        : enumValue(row.loadOp, ['load', 'clear'], 'GPURenderPassColorAttachment.loadOp'),
      storeOp: row.storeOp === undefined
        ? 'store'
        : enumValue(
          row.storeOp,
          ['store', 'discard'],
          'GPURenderPassColorAttachment.storeOp',
        ),
    };
    if (row.resolveTarget !== undefined) {
      result.resolveTarget = wrappers.reference(
        row.resolveTarget,
        'GPUTextureView',
      );
    }
    if (row.clearValue !== undefined) result.clearValue = convertColor(row.clearValue);
    if (row.depthSlice !== undefined) {
      result.depthSlice = u32(row.depthSlice, 'GPURenderPassColorAttachment.depthSlice');
    }
    return frozenRecord(result);
  });
  return frozenRecord({
    label: optionalLabel(source),
    colorAttachments: Object.freeze(attachments),
  });
}

function convertObjectDescriptor(value: unknown, label: string): unknown {
  const source = dictionary(value, label);
  return frozenRecord({ label: optionalLabel(source) });
}

function convertBindGroupLayoutDescriptor(
  value: unknown,
  maximum: number,
  textureFormats: readonly string[],
): unknown {
  const source = dictionary(value, 'GPUBindGroupLayoutDescriptor');
  // GPUBindGroupLayoutDescriptor inherits label before its own entries member.
  // Convert each Get immediately so observable mutations affect later members
  // exactly as Web IDL specifies.
  const label = optionalLabel(source);
  const entriesValue = source.entries;
  if (entriesValue === undefined) {
    throw new TypeError('GPUBindGroupLayoutDescriptor.entries is required');
  }
  const entries = sequence(
    entriesValue,
    'GPUBindGroupLayoutDescriptor.entries',
    maximum,
    (entry, index) => {
      const row = dictionary(entry, `GPUBindGroupLayoutEntry[${index}]`);
      const bindingValue = row.binding;
      if (bindingValue === undefined) {
        throw new TypeError(
          `GPUBindGroupLayoutEntry[${index}].binding is required`,
        );
      }
      const converted: Record<string, unknown> = {
        binding: u32(
          bindingValue,
          `GPUBindGroupLayoutEntry[${index}].binding`,
        ),
      };

      const bufferValue = row.buffer;
      if (bufferValue !== undefined) {
        const buffer = dictionary(
          bufferValue,
          `GPUBufferBindingLayout[${index}]`,
        );
        const hasDynamicOffset = Boolean(buffer.hasDynamicOffset);
        const minBindingSizeValue = buffer.minBindingSize;
        const minBindingSize = minBindingSizeValue === undefined
          ? 0
          : u64Number(
            minBindingSizeValue,
            `GPUBufferBindingLayout[${index}].minBindingSize`,
          );
        const typeValue = buffer.type;
        const type = typeValue === undefined
          ? 'uniform'
          : enumValue(
            typeValue,
            ['uniform', 'storage', 'read-only-storage'],
            `GPUBufferBindingLayout[${index}].type`,
          );
        converted.buffer = frozenRecord({ hasDynamicOffset, minBindingSize, type });
      }

      const externalTextureValue = row.externalTexture;
      if (externalTextureValue !== undefined) {
        dictionary(
          externalTextureValue,
          `GPUExternalTextureBindingLayout[${index}]`,
        );
        converted.externalTexture = frozenRecord({});
      }

      const samplerValue = row.sampler;
      if (samplerValue !== undefined) {
        const sampler = dictionary(
          samplerValue,
          `GPUSamplerBindingLayout[${index}]`,
        );
        const typeValue = sampler.type;
        converted.sampler = frozenRecord({
          type: typeValue === undefined
            ? 'filtering'
            : enumValue(
              typeValue,
              ['filtering', 'non-filtering', 'comparison'],
              `GPUSamplerBindingLayout[${index}].type`,
            ),
        });
      }

      const storageTextureValue = row.storageTexture;
      if (storageTextureValue !== undefined) {
        const storageTexture = dictionary(
          storageTextureValue,
          `GPUStorageTextureBindingLayout[${index}]`,
        );
        const accessValue = storageTexture.access;
        const access = accessValue === undefined
          ? 'write-only'
          : enumValue(
            accessValue,
            ['write-only', 'read-only', 'read-write'],
            `GPUStorageTextureBindingLayout[${index}].access`,
          );
        const formatValue = storageTexture.format;
        if (formatValue === undefined) {
          throw new TypeError(
            `GPUStorageTextureBindingLayout[${index}].format is required`,
          );
        }
        const format = enumValue(
          formatValue,
          textureFormats,
          `GPUStorageTextureBindingLayout[${index}].format`,
        );
        const viewDimensionValue = storageTexture.viewDimension;
        const viewDimension = viewDimensionValue === undefined
          ? '2d'
          : enumValue(
            viewDimensionValue,
            BIND_GROUP_LAYOUT_VIEW_DIMENSIONS,
            `GPUStorageTextureBindingLayout[${index}].viewDimension`,
          );
        converted.storageTexture = frozenRecord({
          access,
          format,
          viewDimension,
        });
      }

      const textureValue = row.texture;
      if (textureValue !== undefined) {
        const texture = dictionary(
          textureValue,
          `GPUTextureBindingLayout[${index}]`,
        );
        const multisampled = Boolean(texture.multisampled);
        const sampleTypeValue = texture.sampleType;
        const sampleType = sampleTypeValue === undefined
          ? 'float'
          : enumValue(
            sampleTypeValue,
            ['float', 'unfilterable-float', 'depth', 'sint', 'uint'],
            `GPUTextureBindingLayout[${index}].sampleType`,
          );
        const viewDimensionValue = texture.viewDimension;
        const viewDimension = viewDimensionValue === undefined
          ? '2d'
          : enumValue(
            viewDimensionValue,
            BIND_GROUP_LAYOUT_VIEW_DIMENSIONS,
            `GPUTextureBindingLayout[${index}].viewDimension`,
          );
        converted.texture = frozenRecord({
          multisampled,
          sampleType,
          viewDimension,
        });
      }

      const visibilityValue = row.visibility;
      if (visibilityValue === undefined) {
        throw new TypeError(
          `GPUBindGroupLayoutEntry[${index}].visibility is required`,
        );
      }
      converted.visibility = u32(
        visibilityValue,
        `GPUBindGroupLayoutEntry[${index}].visibility`,
      );
      return frozenRecord(converted);
    },
  );
  return frozenRecord({
    label,
    entries: Object.freeze(entries),
  });
}

function convertBindGroupDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const source = dictionary(value, 'GPUBindGroupDescriptor');
  // GPUObjectDescriptorBase is inherited before entries and layout. Every
  // conversion immediately follows its single Get to preserve observable
  // Web IDL dictionary order.
  const label = optionalLabel(source);
  const entriesValue = source.entries;
  if (entriesValue === undefined) {
    throw new TypeError('GPUBindGroupDescriptor.entries is required');
  }
  const entries = sequence(
    entriesValue,
    'GPUBindGroupDescriptor.entries',
    maximum,
    (entry, index) => {
      const row = dictionary(entry, `GPUBindGroupEntry[${index}]`);
      const bindingValue = row.binding;
      if (bindingValue === undefined) {
        throw new TypeError(`GPUBindGroupEntry[${index}].binding is required`);
      }
      const binding = u32(bindingValue, `GPUBindGroupEntry[${index}].binding`);
      const resourceValue = row.resource;
      if (resourceValue === undefined) {
        throw new TypeError(`GPUBindGroupEntry[${index}].resource is required`);
      }

      let resource: Readonly<Record<string, unknown>>;
      try {
        const reference = wrappers.reference(resourceValue);
        if (
          reference.kind !== 'GPUSampler' &&
          reference.kind !== 'GPUTextureView' &&
          reference.kind !== 'GPUBuffer' &&
          reference.kind !== 'GPUTexture' &&
          reference.kind !== 'GPUExternalTexture'
        ) {
          throw new TypeError(
            `GPUBindGroupEntry[${index}].resource has an unsupported wrapper brand`,
          );
        }
        resource = frozenRecord({
          resourceKind: reference.kind,
          reference,
        });
      } catch (error) {
        if (!(error instanceof TypeError)) throw error;
        const bindingResource = dictionary(
          resourceValue,
          `GPUBufferBinding[${index}]`,
        );
        const bufferValue = bindingResource.buffer;
        if (bufferValue === undefined) {
          throw error;
        }
        const buffer = wrappers.reference(bufferValue, 'GPUBuffer');
        const offsetValue = bindingResource.offset;
        const offset = offsetValue === undefined
          ? 0
          : u64Number(offsetValue, `GPUBufferBinding[${index}].offset`);
        const sizeValue = bindingResource.size;
        resource = frozenRecord({
          resourceKind: 'GPUBufferBinding',
          buffer,
          offset,
          ...(sizeValue === undefined
            ? {}
            : { size: u64Number(sizeValue, `GPUBufferBinding[${index}].size`) }),
        });
      }
      return frozenRecord({ binding, resource });
    },
  );
  const layoutValue = source.layout;
  if (layoutValue === undefined) {
    throw new TypeError('GPUBindGroupDescriptor.layout is required');
  }
  const layout = wrappers.reference(layoutValue, 'GPUBindGroupLayout');
  return frozenRecord({ label, entries: Object.freeze(entries), layout });
}

function convertBufferDescriptor(value: unknown): unknown {
  const source = dictionary(value, 'GPUBufferDescriptor');
  // GPUObjectDescriptorBase is inherited before the own dictionary members.
  // Convert immediately after each single Get so user code cannot reorder the
  // pinned label -> mappedAtCreation -> size -> usage observation sequence.
  const label = optionalLabel(source);
  const mappedAtCreation = Boolean(source.mappedAtCreation);
  const sizeValue = source.size;
  if (sizeValue === undefined) {
    throw new TypeError('GPUBufferDescriptor.size is required');
  }
  const size = u64Number(sizeValue, 'GPUBufferDescriptor.size');
  const usageValue = source.usage;
  if (usageValue === undefined) {
    throw new TypeError('GPUBufferDescriptor.usage is required');
  }
  const usage = u32(usageValue, 'GPUBufferDescriptor.usage');
  if (size > 268_435_456) {
    throw new TypeError('GPUBufferDescriptor.size exceeds the structural ceiling');
  }
  return frozenRecord({ label, mappedAtCreation, size, usage });
}

function convertBufferMappedRangeArguments(
  args: readonly unknown[],
): Readonly<Record<string, unknown>> {
  const offset = args[0] === undefined
    ? 0
    : u64Number(args[0], 'GPUBuffer.getMappedRange offset');
  const size = args[1] === undefined
    ? undefined
    : u64Number(args[1], 'GPUBuffer.getMappedRange size');
  return frozenRecord({
    offset,
    ...(size === undefined ? {} : { size }),
  });
}

function convertBufferMapAsyncArguments(
  args: readonly unknown[],
): Readonly<Record<string, unknown>> {
  const mode = u32(args[0], 'GPUBuffer.mapAsync mode');
  const offset = args[1] === undefined
    ? 0
    : u64Number(args[1], 'GPUBuffer.mapAsync offset');
  const size = args[2] === undefined
    ? undefined
    : u64Number(args[2], 'GPUBuffer.mapAsync size');
  return frozenRecord({
    mode,
    offset,
    ...(size === undefined ? {} : { size }),
  });
}

function requiredIntrinsicGetter(
  prototype: object,
  key: PropertyKey,
): (this: unknown) => unknown {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (getter === undefined) {
    throw new Error(`Missing required ECMAScript intrinsic getter: ${String(key)}`);
  }
  return getter;
}

const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(
  Uint8Array.prototype,
) as object;
const TYPED_ARRAY_BUFFER_GETTER = requiredIntrinsicGetter(
  TYPED_ARRAY_PROTOTYPE,
  'buffer',
);
const TYPED_ARRAY_BYTE_OFFSET_GETTER = requiredIntrinsicGetter(
  TYPED_ARRAY_PROTOTYPE,
  'byteOffset',
);
const TYPED_ARRAY_BYTE_LENGTH_GETTER = requiredIntrinsicGetter(
  TYPED_ARRAY_PROTOTYPE,
  'byteLength',
);
const TYPED_ARRAY_TAG_GETTER = requiredIntrinsicGetter(
  TYPED_ARRAY_PROTOTYPE,
  Symbol.toStringTag,
);
const DATA_VIEW_BUFFER_GETTER = requiredIntrinsicGetter(
  DataView.prototype,
  'buffer',
);
const DATA_VIEW_BYTE_OFFSET_GETTER = requiredIntrinsicGetter(
  DataView.prototype,
  'byteOffset',
);
const DATA_VIEW_BYTE_LENGTH_GETTER = requiredIntrinsicGetter(
  DataView.prototype,
  'byteLength',
);
const ARRAY_BUFFER_BYTE_LENGTH_GETTER = requiredIntrinsicGetter(
  ArrayBuffer.prototype,
  'byteLength',
);
const SHARED_ARRAY_BUFFER_BYTE_LENGTH_GETTER =
  typeof SharedArrayBuffer === 'undefined'
    ? undefined
    : requiredIntrinsicGetter(SharedArrayBuffer.prototype, 'byteLength');
const TYPED_ARRAY_ELEMENT_SIZES: Readonly<Record<string, number>> =
  Object.freeze({
    Int8Array: 1,
    Uint8Array: 1,
    Uint8ClampedArray: 1,
    Int16Array: 2,
    Uint16Array: 2,
    Float16Array: 2,
    Int32Array: 4,
    Uint32Array: 4,
    Float32Array: 4,
    Float64Array: 8,
    BigInt64Array: 8,
    BigUint64Array: 8,
  });

function convertedAllowSharedBufferSource(value: unknown): Readonly<{
  source: ArrayBufferLike;
  byteOffset: number;
  byteLength: number;
  elementSize: number;
}> {
  if (ArrayBuffer.isView(value)) {
    try {
      return Object.freeze({
        source: Reflect.apply(DATA_VIEW_BUFFER_GETTER, value, []) as ArrayBufferLike,
        byteOffset: Reflect.apply(DATA_VIEW_BYTE_OFFSET_GETTER, value, []) as number,
        byteLength: Reflect.apply(DATA_VIEW_BYTE_LENGTH_GETTER, value, []) as number,
        elementSize: 1,
      });
    } catch {
      const tag = Reflect.apply(TYPED_ARRAY_TAG_GETTER, value, []);
      const elementSize = typeof tag === 'string'
        ? TYPED_ARRAY_ELEMENT_SIZES[tag]
        : undefined;
      if (elementSize === undefined) {
        throw new TypeError(
          'GPUQueue.writeBuffer data has an unknown typed-array brand',
        );
      }
      return Object.freeze({
        source: Reflect.apply(
          TYPED_ARRAY_BUFFER_GETTER,
          value,
          [],
        ) as ArrayBufferLike,
        byteOffset: Reflect.apply(
          TYPED_ARRAY_BYTE_OFFSET_GETTER,
          value,
          [],
        ) as number,
        byteLength: Reflect.apply(
          TYPED_ARRAY_BYTE_LENGTH_GETTER,
          value,
          [],
        ) as number,
        elementSize,
      });
    }
  }
  let byteLength: number | undefined;
  try {
    byteLength = Reflect.apply(
      ARRAY_BUFFER_BYTE_LENGTH_GETTER,
      value,
      [],
    ) as number;
  } catch {
    if (SHARED_ARRAY_BUFFER_BYTE_LENGTH_GETTER !== undefined) {
      try {
        byteLength = Reflect.apply(
          SHARED_ARRAY_BUFFER_BYTE_LENGTH_GETTER,
          value,
          [],
        ) as number;
      } catch {
        // The public error below covers values without an ArrayBuffer slot.
      }
    }
  }
  if (byteLength === undefined) {
    throw new TypeError(
      'GPUQueue.writeBuffer data must be an AllowSharedBufferSource',
    );
  }
  const source = value as ArrayBufferLike;
  return Object.freeze({
    source,
    byteOffset: 0,
    byteLength,
    elementSize: 1,
  });
}

function convertQueueWriteBufferArguments(
  args: readonly unknown[],
  wrappers: ProductionGpuCodecWrapperAccess,
): Readonly<Record<string, unknown>> {
  const buffer = wrappers.reference(args[0], 'GPUBuffer');
  const bufferOffset = u64Number(
    args[1],
    'GPUQueue.writeBuffer bufferOffset',
  );
  const data = convertedAllowSharedBufferSource(args[2]);
  const dataOffset = args[3] === undefined
    ? 0
    : u64Number(args[3], 'GPUQueue.writeBuffer dataOffset');
  const size = args[4] === undefined
    ? undefined
    : u64Number(args[4], 'GPUQueue.writeBuffer size');
  const availableElements = data.byteLength / data.elementSize;
  if (
    !Number.isSafeInteger(availableElements) ||
    dataOffset > availableElements ||
    (size !== undefined && size > availableElements - dataOffset)
  ) {
    throw new WebGpuDOMException(
      'GPUQueue.writeBuffer source range is out of bounds',
      'OperationError',
    );
  }
  const selectedElements = size ?? availableElements - dataOffset;
  const selectedByteLength = selectedElements * data.elementSize;
  const selectedByteOffset = data.byteOffset + dataOffset * data.elementSize;
  if (
    !Number.isSafeInteger(selectedByteLength) ||
    !Number.isSafeInteger(selectedByteOffset) ||
    selectedByteLength % 4 !== 0
  ) {
    throw new WebGpuDOMException(
      'GPUQueue.writeBuffer selected source byte length must be a multiple of 4',
      'OperationError',
    );
  }
  const bytes = new Uint8Array(
    new Uint8Array(data.source, selectedByteOffset, selectedByteLength),
  );
  return frozenRecord({
    buffer,
    bufferOffset,
    bytes,
  });
}

function convertSamplerDescriptor(
  value: unknown,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): unknown {
  const source = dictionary(value, 'GPUSamplerDescriptor');
  const addressModeUValue = source.addressModeU;
  const addressModeU = addressModeUValue === undefined
    ? 'clamp-to-edge'
    : enumValue(addressModeUValue, vocabulary.gpuAddressModes, 'GPUSamplerDescriptor.addressModeU');
  const addressModeVValue = source.addressModeV;
  const addressModeV = addressModeVValue === undefined
    ? 'clamp-to-edge'
    : enumValue(addressModeVValue, vocabulary.gpuAddressModes, 'GPUSamplerDescriptor.addressModeV');
  const addressModeWValue = source.addressModeW;
  const addressModeW = addressModeWValue === undefined
    ? 'clamp-to-edge'
    : enumValue(addressModeWValue, vocabulary.gpuAddressModes, 'GPUSamplerDescriptor.addressModeW');
  const compareValue = source.compare;
  const compare = compareValue === undefined
    ? undefined
    : enumValue(compareValue, vocabulary.gpuCompareFunctions, 'GPUSamplerDescriptor.compare');
  const labelValue = source.label;
  const label = labelValue === undefined
    ? ''
    : webIdlUsvString(labelValue, 'GPUSamplerDescriptor.label');
  const lodMaxClampValue = source.lodMaxClamp;
  const lodMaxClamp = lodMaxClampValue === undefined
    ? 32
    : restrictedFloat(lodMaxClampValue, 'GPUSamplerDescriptor.lodMaxClamp');
  const lodMinClampValue = source.lodMinClamp;
  const lodMinClamp = lodMinClampValue === undefined
    ? 0
    : restrictedFloat(lodMinClampValue, 'GPUSamplerDescriptor.lodMinClamp');
  const magFilterValue = source.magFilter;
  const magFilter = magFilterValue === undefined
    ? 'nearest'
    : enumValue(magFilterValue, vocabulary.gpuFilterModes, 'GPUSamplerDescriptor.magFilter');
  const maxAnisotropyValue = source.maxAnisotropy;
  const maxAnisotropy = maxAnisotropyValue === undefined
    ? 1
    : clampUnsignedShort(maxAnisotropyValue, 'GPUSamplerDescriptor.maxAnisotropy');
  const minFilterValue = source.minFilter;
  const minFilter = minFilterValue === undefined
    ? 'nearest'
    : enumValue(minFilterValue, vocabulary.gpuFilterModes, 'GPUSamplerDescriptor.minFilter');
  const mipmapFilterValue = source.mipmapFilter;
  const mipmapFilter = mipmapFilterValue === undefined
    ? 'nearest'
    : enumValue(
      mipmapFilterValue,
      vocabulary.gpuMipmapFilterModes,
      'GPUSamplerDescriptor.mipmapFilter',
    );
  return frozenRecord({
    addressModeU,
    addressModeV,
    addressModeW,
    ...(compare === undefined ? {} : { compare }),
    label,
    lodMaxClamp,
    lodMinClamp,
    magFilter,
    maxAnisotropy,
    minFilter,
    mipmapFilter,
  });
}

function convertTextureDescriptor(
  value: unknown,
  maximum: number,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): unknown {
  const source = dictionary(value, 'GPUTextureDescriptor');
  const dimensionValue = source.dimension;
  const dimension = dimensionValue === undefined
    ? '2d'
    : enumValue(
      dimensionValue,
      vocabulary.gpuTextureDimensions,
      'GPUTextureDescriptor.dimension',
    );
  const formatValue = source.format;
  if (formatValue === undefined) {
    throw new TypeError('GPUTextureDescriptor.format is required');
  }
  const format = enumValue(
    formatValue,
    vocabulary.gpuTextureFormats,
    'GPUTextureDescriptor.format',
  );
  const labelValue = source.label;
  const label = labelValue === undefined
    ? ''
    : webIdlUsvString(labelValue, 'GPUTextureDescriptor.label');
  const mipLevelCountValue = source.mipLevelCount;
  const mipLevelCount = u32(
    mipLevelCountValue,
    'GPUTextureDescriptor.mipLevelCount',
    1,
  );
  const sampleCountValue = source.sampleCount;
  const sampleCount = u32(sampleCountValue, 'GPUTextureDescriptor.sampleCount', 1);
  const sizeValue = source.size;
  if (sizeValue === undefined) {
    throw new TypeError('GPUTextureDescriptor.size is required');
  }
  const convertedSize = convertExtent3D(sizeValue, maximum);
  const textureBindingViewDimensionValue = source.textureBindingViewDimension;
  const textureBindingViewDimension = textureBindingViewDimensionValue === undefined
    ? undefined
    : enumValue(
      textureBindingViewDimensionValue,
      vocabulary.gpuTextureViewDimensions,
      'GPUTextureDescriptor.textureBindingViewDimension',
    );
  const usageValue = source.usage;
  if (usageValue === undefined) {
    throw new TypeError('GPUTextureDescriptor.usage is required');
  }
  const usage = u32(usageValue, 'GPUTextureDescriptor.usage');
  const viewFormatsValue = source.viewFormats;
  const viewFormats = viewFormatsValue === undefined
    ? []
    : sequence(
      viewFormatsValue,
      'GPUTextureDescriptor.viewFormats',
      maximum,
      (viewFormat) => enumValue(
        viewFormat,
        vocabulary.gpuTextureFormats,
        'GPUTextureDescriptor.viewFormats member',
      ),
    );
  if (
    convertedSize.iterableLength !== null &&
    (convertedSize.iterableLength < 1 || convertedSize.iterableLength > 3)
  ) {
    throw new TypeError(
      'GPUTextureDescriptor.size sequence must contain one to three members',
    );
  }
  return frozenRecord({
    dimension,
    format,
    label,
    mipLevelCount,
    sampleCount,
    size: convertedSize.size,
    ...(textureBindingViewDimension === undefined
      ? {}
      : { textureBindingViewDimension }),
    usage,
    viewFormats: Object.freeze(viewFormats),
  });
}

function convertPipelineLayoutDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const source = dictionary(value, 'GPUPipelineLayoutDescriptor');
  // GPUObjectDescriptor is inherited first. Each conversion follows its Get
  // immediately so observable mutations preserve Web IDL dictionary order.
  const label = optionalLabel(source);
  const bindGroupLayoutsValue = source.bindGroupLayouts;
  if (bindGroupLayoutsValue === undefined) {
    throw new TypeError(
      'GPUPipelineLayoutDescriptor.bindGroupLayouts is required',
    );
  }
  const bindGroupLayouts = sequence(
    bindGroupLayoutsValue,
    'GPUPipelineLayoutDescriptor.bindGroupLayouts',
    maximum,
    (layout) => layout === null || layout === undefined
      ? null
      : wrappers.reference(layout, 'GPUBindGroupLayout'),
  );
  const immediateSizeValue = source.immediateSize;
  const immediateSize = u32(
    immediateSizeValue,
    'GPUPipelineLayoutDescriptor.immediateSize',
    0,
  );
  return frozenRecord({
    label,
    bindGroupLayouts: Object.freeze(bindGroupLayouts),
    immediateSize,
  });
}

function convertVertexBuffers(value: unknown, maximum: number): readonly unknown[] {
  const buffers = sequence(
    value,
    'GPUVertexState.buffers',
    maximum,
    (buffer, bufferIndex) => {
      if (buffer === null || buffer === undefined) return null;
      const source = dictionary(
        buffer,
        `GPUVertexBufferLayout[${bufferIndex}]`,
      );
      // Dictionary members are observed and converted in lexicographic order.
      const arrayStrideValue = source.arrayStride;
      if (arrayStrideValue === undefined) {
        throw new TypeError('GPUVertexBufferLayout.arrayStride is required');
      }
      const arrayStride = u64Number(
        arrayStrideValue,
        'GPUVertexBufferLayout.arrayStride',
      );
      const attributesValue = source.attributes;
      if (attributesValue === undefined) {
        throw new TypeError('GPUVertexBufferLayout.attributes is required');
      }
      const attributes = sequence(
        attributesValue,
        `GPUVertexBufferLayout[${bufferIndex}].attributes`,
        maximum,
        (attribute) => {
          const row = dictionary(attribute, 'GPUVertexAttribute');
          const formatValue = row.format;
          if (formatValue === undefined) {
            throw new TypeError('GPUVertexAttribute.format is required');
          }
          const format = enumValue(
            formatValue,
            VERTEX_FORMATS,
            'GPUVertexAttribute.format',
          );
          const offsetValue = row.offset;
          if (offsetValue === undefined) {
            throw new TypeError('GPUVertexAttribute.offset is required');
          }
          const offset = u64Number(offsetValue, 'GPUVertexAttribute.offset');
          const shaderLocationValue = row.shaderLocation;
          if (shaderLocationValue === undefined) {
            throw new TypeError('GPUVertexAttribute.shaderLocation is required');
          }
          const shaderLocation = u32(
            shaderLocationValue,
            'GPUVertexAttribute.shaderLocation',
          );
          return frozenRecord({ format, offset, shaderLocation });
        },
      );
      const stepModeValue = source.stepMode;
      const stepMode = stepModeValue === undefined
        ? 'vertex'
        : enumValue(
          stepModeValue,
          ['vertex', 'instance'],
          'GPUVertexBufferLayout.stepMode',
        );
      return frozenRecord({
        arrayStride,
        attributes: Object.freeze(attributes),
        stepMode,
      });
    },
  );
  return Object.freeze(buffers);
}

function convertProgrammableStage(
  value: unknown,
  label: string,
  wrappers: ProductionGpuCodecWrapperAccess,
): Record<string, unknown> {
  const source = dictionary(value, label);
  const result: Record<string, unknown> = {};
  const constantsValue = source.constants;
  result.constants = convertConstants(constantsValue, `${label}.constants`);
  const entryPointValue = source.entryPoint;
  if (entryPointValue !== undefined) {
    result.entryPoint = webIdlUsvString(entryPointValue, `${label}.entryPoint`);
  }
  const moduleValue = source.module;
  if (moduleValue === undefined) {
    throw new TypeError(`${label}.module is required`);
  }
  result.module = wrappers.reference(moduleValue, 'GPUShaderModule');
  return result;
}

function convertBlendComponent(
  value: unknown,
  label: string,
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, label);
  const dstFactorValue = source.dstFactor;
  const dstFactor = dstFactorValue === undefined
    ? 'zero'
    : enumValue(dstFactorValue, BLEND_FACTORS, `${label}.dstFactor`);
  const operationValue = source.operation;
  const operation = operationValue === undefined
    ? 'add'
    : enumValue(
      operationValue,
      ['add', 'subtract', 'reverse-subtract', 'min', 'max'],
      `${label}.operation`,
    );
  const srcFactorValue = source.srcFactor;
  const srcFactor = srcFactorValue === undefined
    ? 'one'
    : enumValue(srcFactorValue, BLEND_FACTORS, `${label}.srcFactor`);
  return frozenRecord({
    dstFactor,
    operation,
    srcFactor,
  });
}

function convertBlendState(value: unknown): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUBlendState');
  const alphaValue = source.alpha;
  if (alphaValue === undefined) {
    throw new TypeError('GPUBlendState.alpha is required');
  }
  const alpha = convertBlendComponent(alphaValue, 'GPUBlendState.alpha');
  const colorValue = source.color;
  if (colorValue === undefined) {
    throw new TypeError('GPUBlendState.color is required');
  }
  const color = convertBlendComponent(colorValue, 'GPUBlendState.color');
  return frozenRecord({ alpha, color });
}

function convertColorTargetState(
  value: unknown,
  textureFormats: readonly string[],
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUColorTargetState');
  const result: Record<string, unknown> = {};
  const blendValue = source.blend;
  if (blendValue !== undefined) {
    result.blend = convertBlendState(blendValue);
  }
  const formatValue = source.format;
  if (formatValue === undefined) {
    throw new TypeError('GPUColorTargetState.format is required');
  }
  result.format = enumValue(
    formatValue,
    textureFormats,
    'GPUColorTargetState.format',
  );
  const writeMaskValue = source.writeMask;
  result.writeMask = u32(
    writeMaskValue,
    'GPUColorTargetState.writeMask',
    0x0f,
  );
  return frozenRecord(result);
}

function convertFragmentState(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
  textureFormats: readonly string[],
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUFragmentState');
  const fragment = convertProgrammableStage(
    source,
    'GPUFragmentState',
    wrappers,
  );
  const targetsValue = source.targets;
  if (targetsValue === undefined) {
    throw new TypeError('GPUFragmentState.targets is required');
  }
  fragment.targets = Object.freeze(sequence(
    targetsValue,
    'GPUFragmentState.targets',
    maximum,
    (target) => target === null || target === undefined
      ? null
      : convertColorTargetState(target, textureFormats),
  ));
  return frozenRecord(fragment);
}

function convertMultisampleState(value: unknown): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUMultisampleState');
  const alphaToCoverageEnabled = Boolean(source.alphaToCoverageEnabled);
  const countValue = source.count;
  const count = u32(countValue, 'GPUMultisampleState.count', 1);
  const maskValue = source.mask;
  const mask = u32(maskValue, 'GPUMultisampleState.mask', 0xffff_ffff);
  return frozenRecord({ alphaToCoverageEnabled, count, mask });
}

function convertPrimitiveState(value: unknown): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUPrimitiveState');
  const cullModeValue = source.cullMode;
  const cullMode = cullModeValue === undefined
    ? 'none'
    : enumValue(cullModeValue, ['none', 'front', 'back'], 'GPUPrimitiveState.cullMode');
  const frontFaceValue = source.frontFace;
  const frontFace = frontFaceValue === undefined
    ? 'ccw'
    : enumValue(frontFaceValue, ['ccw', 'cw'], 'GPUPrimitiveState.frontFace');
  const stripIndexFormatValue = source.stripIndexFormat;
  const stripIndexFormat = stripIndexFormatValue === undefined
    ? undefined
    : enumValue(
      stripIndexFormatValue,
      ['uint16', 'uint32'],
      'GPUPrimitiveState.stripIndexFormat',
    );
  const topologyValue = source.topology;
  const topology = topologyValue === undefined
    ? 'triangle-list'
    : enumValue(
      topologyValue,
      ['point-list', 'line-list', 'line-strip', 'triangle-list', 'triangle-strip'],
      'GPUPrimitiveState.topology',
    );
  const unclippedDepth = Boolean(source.unclippedDepth);
  return frozenRecord({
    cullMode,
    frontFace,
    ...(stripIndexFormat === undefined ? {} : { stripIndexFormat }),
    topology,
    unclippedDepth,
  });
}

function convertStencilFaceState(
  value: unknown,
  label: string,
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, label);
  const compareValue = source.compare;
  const compare = compareValue === undefined
    ? 'always'
    : enumValue(compareValue, COMPARE_FUNCTIONS, `${label}.compare`);
  const depthFailOpValue = source.depthFailOp;
  const depthFailOp = depthFailOpValue === undefined
    ? 'keep'
    : enumValue(depthFailOpValue, STENCIL_OPERATIONS, `${label}.depthFailOp`);
  const failOpValue = source.failOp;
  const failOp = failOpValue === undefined
    ? 'keep'
    : enumValue(failOpValue, STENCIL_OPERATIONS, `${label}.failOp`);
  const passOpValue = source.passOp;
  const passOp = passOpValue === undefined
    ? 'keep'
    : enumValue(passOpValue, STENCIL_OPERATIONS, `${label}.passOp`);
  return frozenRecord({ compare, depthFailOp, failOp, passOp });
}

function convertDepthStencilState(
  value: unknown,
  textureFormats: readonly string[],
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUDepthStencilState');
  const depthBiasValue = source.depthBias;
  const depthBias = i32(depthBiasValue, 'GPUDepthStencilState.depthBias', 0);
  const depthBiasClampValue = source.depthBiasClamp;
  const depthBiasClamp = depthBiasClampValue === undefined
    ? 0
    : restrictedFloat(
      depthBiasClampValue,
      'GPUDepthStencilState.depthBiasClamp',
    );
  const depthBiasSlopeScaleValue = source.depthBiasSlopeScale;
  const depthBiasSlopeScale = depthBiasSlopeScaleValue === undefined
    ? 0
    : restrictedFloat(
      depthBiasSlopeScaleValue,
      'GPUDepthStencilState.depthBiasSlopeScale',
    );
  const depthCompareValue = source.depthCompare;
  const depthCompare = depthCompareValue === undefined
    ? undefined
    : enumValue(
      depthCompareValue,
      COMPARE_FUNCTIONS,
      'GPUDepthStencilState.depthCompare',
    );
  const depthWriteEnabledValue = source.depthWriteEnabled;
  const depthWriteEnabled = depthWriteEnabledValue === undefined
    ? undefined
    : Boolean(depthWriteEnabledValue);
  const formatValue = source.format;
  if (formatValue === undefined) {
    throw new TypeError('GPUDepthStencilState.format is required');
  }
  const format = enumValue(
    formatValue,
    textureFormats,
    'GPUDepthStencilState.format',
  );
  const stencilBack = convertStencilFaceState(
    source.stencilBack,
    'GPUDepthStencilState.stencilBack',
  );
  const stencilFront = convertStencilFaceState(
    source.stencilFront,
    'GPUDepthStencilState.stencilFront',
  );
  const stencilReadMaskValue = source.stencilReadMask;
  const stencilReadMask = u32(
    stencilReadMaskValue,
    'GPUDepthStencilState.stencilReadMask',
    0xffff_ffff,
  );
  const stencilWriteMaskValue = source.stencilWriteMask;
  const stencilWriteMask = u32(
    stencilWriteMaskValue,
    'GPUDepthStencilState.stencilWriteMask',
    0xffff_ffff,
  );
  return frozenRecord({
    depthBias,
    depthBiasClamp,
    depthBiasSlopeScale,
    ...(depthCompare === undefined ? {} : { depthCompare }),
    ...(depthWriteEnabled === undefined ? {} : { depthWriteEnabled }),
    format,
    stencilBack,
    stencilFront,
    stencilReadMask,
    stencilWriteMask,
  });
}

function convertVertexState(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, 'GPUVertexState');
  const vertex = convertProgrammableStage(source, 'GPUVertexState', wrappers);
  const buffersValue = source.buffers;
  vertex.buffers = convertVertexBuffers(
    buffersValue === undefined ? [] : buffersValue,
    maximum,
  );
  return frozenRecord(vertex);
}

function convertPipelineLayoutUnion(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
): string | Readonly<ProductionGpuFullObjectReference> {
  // Web IDL selects the interface member only for a platform object that
  // implements GPUPipelineLayout. Every other value, including an ordinary
  // object, falls through to GPUAutoLayoutMode's string conversion. Exact
  // additionally keeps known wrong-kind and foreign private wrappers on its
  // fail-closed brand path instead of invoking app-controlled stringification.
  const reference = wrappers.referenceIfBranded(value, 'GPUPipelineLayout');
  if (reference !== undefined) return reference;
  return enumValue(value, ['auto'], 'GPUPipelineDescriptorBase.layout');
}

function convertRenderPipelineDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
  textureFormats: readonly string[],
): unknown {
  const source = dictionary(value, 'GPURenderPipelineDescriptor');
  // Inherited dictionary members are observed first, followed by the derived
  // members in lexicographic order. Conversion immediately follows each Get.
  const label = optionalLabel(source);
  const layoutValue = source.layout;
  if (layoutValue === undefined) {
    throw new TypeError('GPUPipelineDescriptorBase.layout is required');
  }
  const layout = convertPipelineLayoutUnion(layoutValue, wrappers);
  const result: Record<string, unknown> = {
    label,
    layout,
  };
  const depthStencilValue = source.depthStencil;
  if (depthStencilValue !== undefined) {
    result.depthStencil = convertDepthStencilState(
      depthStencilValue,
      textureFormats,
    );
  }
  const fragmentValue = source.fragment;
  if (fragmentValue !== undefined) {
    result.fragment = convertFragmentState(
      fragmentValue,
      wrappers,
      maximum,
      textureFormats,
    );
  }
  const multisampleValue = source.multisample;
  result.multisample = convertMultisampleState(multisampleValue);
  const primitiveValue = source.primitive;
  result.primitive = convertPrimitiveState(primitiveValue);
  const vertexValue = source.vertex;
  if (vertexValue === undefined) {
    throw new TypeError('GPURenderPipelineDescriptor.vertex is required');
  }
  result.vertex = convertVertexState(vertexValue, wrappers, maximum);
  return frozenRecord(result);
}

function convertComputePipelineDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
): unknown {
  const source = dictionary(value, 'GPUComputePipelineDescriptor');
  // Web IDL observes inherited dictionary members before the derived member:
  // label, layout, then compute. Each conversion immediately follows its Get.
  const label = optionalLabel(source);
  const layoutValue = source.layout;
  if (layoutValue === undefined) {
    throw new TypeError('GPUPipelineDescriptorBase.layout is required');
  }
  const layout = convertPipelineLayoutUnion(layoutValue, wrappers);
  const computeValue = source.compute;
  if (computeValue === undefined) {
    throw new TypeError('GPUComputePipelineDescriptor.compute is required');
  }
  const compute = convertProgrammableStage(
    computeValue,
    'GPUProgrammableStage',
    wrappers,
  );
  return frozenRecord({ label, layout, compute: frozenRecord(compute) });
}

function convertShaderModuleDescriptor(value: unknown): unknown {
  const source = dictionary(value, 'GPUShaderModuleDescriptor');
  if (source.code === undefined) {
    throw new TypeError('GPUShaderModuleDescriptor.code is required');
  }
  return frozenRecord({
    label: optionalLabel(source),
    code: webIdlUsvString(source.code, 'GPUShaderModuleDescriptor.code'),
  });
}

function convertErrorFilter(value: unknown): unknown {
  return enumValue(
    value,
    ['validation', 'out-of-memory', 'internal'],
    'GPUErrorFilter',
  );
}

function convertCommandBufferSequence(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const values = sequence(value, 'GPUQueue.submit commandBuffers', maximum);
  for (const buffer of values) wrappers.reference(buffer, 'GPUCommandBuffer');
  // The wrapper needs the branded values to seal their private command records.
  return Object.freeze(values.slice());
}

function convertDrawArguments(args: readonly unknown[]): unknown {
  return Object.freeze([
    u32(args[0], 'vertexCount'),
    u32(args[1], 'instanceCount', 1),
    u32(args[2], 'firstVertex', 0),
    u32(args[3], 'firstInstance', 0),
  ]);
}

function convertTextureViewDescriptor(
  value: unknown,
  textureFormats: readonly string[],
): unknown {
  const source = dictionary(value, 'GPUTextureViewDescriptor');
  // Web IDL dictionary members, including inherited GPUObjectDescriptor.label,
  // are observed and converted once in lexicographic order. Keep each Get
  // adjacent to its conversion so a throwing conversion prevents every later
  // getter from running.
  const arrayLayerCountValue = source.arrayLayerCount;
  const arrayLayerCount = arrayLayerCountValue === undefined
    ? undefined
    : u32(arrayLayerCountValue, 'GPUTextureViewDescriptor.arrayLayerCount');
  const aspectValue = source.aspect;
  const aspect = aspectValue === undefined
    ? 'all'
    : enumValue(
      aspectValue,
      ['all', 'stencil-only', 'depth-only'],
      'GPUTextureViewDescriptor.aspect',
    );
  const baseArrayLayerValue = source.baseArrayLayer;
  const baseArrayLayer = u32(
    baseArrayLayerValue,
    'GPUTextureViewDescriptor.baseArrayLayer',
    0,
  );
  const baseMipLevelValue = source.baseMipLevel;
  const baseMipLevel = u32(
    baseMipLevelValue,
    'GPUTextureViewDescriptor.baseMipLevel',
    0,
  );
  const dimensionValue = source.dimension;
  const dimension = dimensionValue === undefined
    ? undefined
    : enumValue(
      dimensionValue,
      ['1d', '2d', '2d-array', 'cube', 'cube-array', '3d'],
      'GPUTextureViewDescriptor.dimension',
    );
  const formatValue = source.format;
  const format = formatValue === undefined
    ? undefined
    : enumValue(
      formatValue,
      textureFormats,
      'GPUTextureViewDescriptor.format',
    );
  const labelValue = source.label;
  const label = labelValue === undefined
    ? ''
    : webIdlUsvString(labelValue, 'GPUTextureViewDescriptor.label');
  const mipLevelCountValue = source.mipLevelCount;
  const mipLevelCount = mipLevelCountValue === undefined
    ? undefined
    : u32(
      mipLevelCountValue,
      'GPUTextureViewDescriptor.mipLevelCount',
    );
  const swizzleValue = source.swizzle;
  const swizzle = swizzleValue === undefined
    ? 'rgba'
    : webIdlString(swizzleValue, 'GPUTextureViewDescriptor.swizzle');
  if (!/^[rgba01]{4}$/.test(swizzle)) {
    throw new TypeError(
      'GPUTextureViewDescriptor.swizzle must contain exactly four r, g, b, a, 0, or 1 components',
    );
  }
  const usageValue = source.usage;
  const usage = u32(usageValue, 'GPUTextureViewDescriptor.usage', 0);
  return frozenRecord({
    ...(arrayLayerCount === undefined ? {} : { arrayLayerCount }),
    aspect,
    baseArrayLayer,
    baseMipLevel,
    ...(dimension === undefined ? {} : { dimension }),
    ...(format === undefined ? {} : { format }),
    label,
    ...(mipLevelCount === undefined ? {} : { mipLevelCount }),
    swizzle,
    usage,
  });
}

function encodeUtf8(value: string): Uint8Array {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    let codePoint = value.charCodeAt(index);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      if (index + 1 >= value.length) throw new TypeError('String is not well-formed UTF-16');
      const trail = value.charCodeAt(++index);
      if (trail < 0xdc00 || trail > 0xdfff) {
        throw new TypeError('String is not well-formed UTF-16');
      }
      codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (trail - 0xdc00);
    } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
      throw new TypeError('String is not well-formed UTF-16');
    }
    if (codePoint <= 0x7f) {
      bytes.push(codePoint);
    } else if (codePoint <= 0x7ff) {
      bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint <= 0xffff) {
      bytes.push(
        0xe0 | (codePoint >> 12),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    } else {
      bytes.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    }
  }
  return Uint8Array.from(bytes);
}

function compareCanonicalUtf8(left: string, right: string): number {
  const leftBytes = encodeUtf8(left);
  const rightBytes = encodeUtf8(right);
  const sharedLength = Math.min(leftBytes.byteLength, rightBytes.byteLength);
  for (let index = 0; index < sharedLength; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) {
      return leftBytes[index] - rightBytes[index];
    }
  }
  return leftBytes.byteLength - rightBytes.byteLength;
}

function decodeUtf8(bytes: Uint8Array): string {
  const codeUnits: number[] = [];
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index++];
    let codePoint: number;
    let remaining: number;
    let minimum: number;
    if (first <= 0x7f) {
      codePoint = first;
      remaining = 0;
      minimum = 0;
    } else if (first >= 0xc2 && first <= 0xdf) {
      codePoint = first & 0x1f;
      remaining = 1;
      minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
      codePoint = first & 0x0f;
      remaining = 2;
      minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codePoint = first & 0x07;
      remaining = 3;
      minimum = 0x10000;
    } else {
      throw new TypeError('Malformed UTF-8 in WebGPU payload');
    }
    for (let part = 0; part < remaining; part += 1) {
      if (index >= bytes.length) throw new TypeError('Truncated UTF-8 in WebGPU payload');
      const continuation = bytes[index++];
      if ((continuation & 0xc0) !== 0x80) {
        throw new TypeError('Malformed UTF-8 in WebGPU payload');
      }
      codePoint = (codePoint << 6) | (continuation & 0x3f);
    }
    if (
      codePoint < minimum ||
      codePoint > 0x10ffff ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    ) {
      throw new TypeError('Non-canonical UTF-8 in WebGPU payload');
    }
    if (codePoint <= 0xffff) {
      codeUnits.push(codePoint);
    } else {
      const scalar = codePoint - 0x10000;
      codeUnits.push(0xd800 + (scalar >> 10), 0xdc00 + (scalar & 0x3ff));
    }
  }
  let result = '';
  for (let offset = 0; offset < codeUnits.length; offset += 4096) {
    result += String.fromCharCode(...codeUnits.slice(offset, offset + 4096));
  }
  return result;
}

function parseU64Decimal(value: string): readonly [number, number] {
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new TypeError('WebGPU u64 value must be canonical decimal');
  }
  let high = 0;
  let low = 0;
  for (const character of value) {
    const digit = character.charCodeAt(0) - 48;
    const lowProduct = low * 10 + digit;
    const nextLow = lowProduct % 0x1_0000_0000;
    const carry = Math.floor(lowProduct / 0x1_0000_0000);
    const highProduct = high * 10 + carry;
    if (highProduct >= 0x1_0000_0000) {
      throw new TypeError('WebGPU u64 value exceeds the binary range');
    }
    low = nextLow;
    high = highProduct;
  }
  return [low, high];
}

function u64Decimal(high: number, low: number): string {
  const digits = [0];
  for (let bit = 63; bit >= 0; bit -= 1) {
    let carry = bit >= 32
      ? (high >>> (bit - 32)) & 1
      : (low >>> bit) & 1;
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      const value = digits[index] * 2 + carry;
      digits[index] = value % 10;
      carry = Math.floor(value / 10);
    }
    if (carry) digits.unshift(carry);
  }
  return digits.join('');
}

class Writer {
  private bytes = new Uint8Array(256);
  private view = new DataView(this.bytes.buffer);
  private offset = 0;

  constructor(private readonly maximum: number) {}

  private reserve(count: number): void {
    const required = this.offset + count;
    if (required > this.maximum) {
      throw new TypeError('WebGPU payload exceeds the reviewed byte bound');
    }
    if (required <= this.bytes.length) return;
    let capacity = this.bytes.length;
    while (capacity < required) capacity = Math.min(this.maximum, capacity * 2);
    const replacement = new Uint8Array(capacity);
    replacement.set(this.bytes);
    this.bytes = replacement;
    this.view = new DataView(replacement.buffer);
  }

  u8(value: number): void {
    this.reserve(1);
    this.view.setUint8(this.offset, value);
    this.offset += 1;
  }

  u16(value: number): void {
    this.reserve(2);
    this.view.setUint16(this.offset, value, true);
    this.offset += 2;
  }

  u32(value: number): void {
    this.reserve(4);
    this.view.setUint32(this.offset, value, true);
    this.offset += 4;
  }

  f64(value: number): void {
    this.reserve(8);
    this.view.setFloat64(this.offset, value, true);
    this.offset += 8;
  }

  u64(value: string): void {
    const [low, high] = parseU64Decimal(value);
    this.u32(low);
    this.u32(high);
  }

  raw(value: Uint8Array): void {
    this.reserve(value.byteLength);
    this.bytes.set(value, this.offset);
    this.offset += value.byteLength;
  }

  ascii4(value: string): void {
    if (!/^[\x20-\x7e]{4}$/u.test(value)) throw new Error('Codec magic must be four ASCII bytes');
    for (let index = 0; index < value.length; index += 1) {
      this.u8(value.charCodeAt(index));
    }
  }

  string(value: string, maximumBytes = this.maximum): void {
    const encoded = encodeUtf8(value);
    if (encoded.byteLength > maximumBytes) {
      throw new TypeError('WebGPU string exceeds its reviewed byte bound');
    }
    this.u32(encoded.byteLength);
    this.raw(encoded);
  }

  value(
    value: unknown,
    limits: ExecutableWebGpuCodecManifest['layout'],
    depth = 0,
    seen = new WeakSet<object>(),
  ): void {
    if (depth > limits.nestingMaxDepth) {
      throw new TypeError('WebGPU value exceeds the reviewed nesting bound');
    }
    if (value === null) {
      this.u8(limits.valueTags.null);
      return;
    }
    if (value === false) {
      this.u8(limits.valueTags.false);
      return;
    }
    if (value === true) {
      this.u8(limits.valueTags.true);
      return;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new TypeError('WebGPU numbers must be finite');
      if (Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff) {
        this.u8(limits.valueTags.u32);
        this.u32(value);
      } else {
        this.u8(limits.valueTags.f64);
        this.f64(value);
      }
      return;
    }
    if (typeof value === 'string') {
      this.u8(limits.valueTags.string);
      this.string(value);
      return;
    }
    if (typeof value !== 'object' || value === null) {
      throw new TypeError('WebGPU payload contains a non-canonical value');
    }
    if (seen.has(value)) throw new TypeError('WebGPU payload contains a cycle');
    seen.add(value);
    if (Array.isArray(value)) {
      if (value.length > limits.sequenceMaxCount) {
        throw new TypeError('WebGPU sequence exceeds the reviewed count bound');
      }
      this.u8(limits.valueTags.sequence);
      this.u32(value.length);
      for (const item of value) this.value(item, limits, depth + 1, seen);
    } else {
      const keys = Object.keys(value)
        .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
        .sort(compareCanonicalUtf8);
      if (keys.length > limits.dictionaryMaxFields) {
        throw new TypeError('WebGPU dictionary exceeds the reviewed field bound');
      }
      this.u8(limits.valueTags.dictionary);
      this.u32(keys.length);
      for (const key of keys) {
        this.string(key);
        this.value(
          (value as Record<string, unknown>)[key],
          limits,
          depth + 1,
          seen,
        );
      }
    }
    seen.delete(value);
  }

  finish(): Uint8Array {
    return this.bytes.slice(0, this.offset);
  }
}

class Reader {
  private readonly bytes: Uint8Array;
  private readonly view: DataView;
  private offset = 0;

  constructor(value: ArrayBufferView, maximum: number) {
    if (value.byteLength > maximum) {
      throw new TypeError('WebGPU payload exceeds the reviewed byte bound');
    }
    this.bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    this.view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  }

  private require(count: number): void {
    if (count < 0 || this.offset + count > this.bytes.byteLength) {
      throw new TypeError('Truncated WebGPU payload');
    }
  }

  u8(): number {
    this.require(1);
    return this.view.getUint8(this.offset++);
  }

  u16(): number {
    this.require(2);
    const value = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return value;
  }

  u32(): number {
    this.require(4);
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  f64(): number {
    this.require(8);
    const value = this.view.getFloat64(this.offset, true);
    this.offset += 8;
    if (!Number.isFinite(value)) throw new TypeError('Non-finite WebGPU payload number');
    return value;
  }

  u64(): string {
    const low = this.u32();
    const high = this.u32();
    return u64Decimal(high, low);
  }

  ascii4(): string {
    return String.fromCharCode(this.u8(), this.u8(), this.u8(), this.u8());
  }

  string(maximumBytes: number): string {
    const length = this.u32();
    if (length > maximumBytes) {
      throw new TypeError('WebGPU string exceeds its reviewed byte bound');
    }
    this.require(length);
    const result = decodeUtf8(this.bytes.subarray(this.offset, this.offset + length));
    this.offset += length;
    return result;
  }

  raw(count: number): Uint8Array {
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new TypeError('Invalid WebGPU owned byte length');
    }
    this.require(count);
    const result = this.bytes.slice(this.offset, this.offset + count);
    this.offset += count;
    return result;
  }

  /**
   * Retain an affine view into the already-owned native completion payload.
   * GPUBuffer mapping uses this path so the construction-private engine bridge
   * can mint true keyed aliases without a second byte-block allocation.
   */
  mappedBytes(count: number): Uint8Array {
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new TypeError('Invalid WebGPU mapped byte length');
    }
    this.require(count);
    const result = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return result;
  }

  value(
    limits: ExecutableWebGpuCodecManifest['layout'],
    depth = 0,
  ): unknown {
    if (depth > limits.nestingMaxDepth) {
      throw new TypeError('WebGPU value exceeds the reviewed nesting bound');
    }
    const tag = this.u8();
    if (tag === limits.valueTags.null) return null;
    if (tag === limits.valueTags.false) return false;
    if (tag === limits.valueTags.true) return true;
    if (tag === limits.valueTags.u32) return this.u32();
    if (tag === limits.valueTags.f64) return this.f64();
    if (tag === limits.valueTags.string) return this.string(this.bytes.byteLength);
    if (tag === limits.valueTags.sequence) {
      const count = this.u32();
      if (count > limits.sequenceMaxCount) {
        throw new TypeError('WebGPU sequence exceeds the reviewed count bound');
      }
      const result: unknown[] = [];
      for (let index = 0; index < count; index += 1) {
        result.push(this.value(limits, depth + 1));
      }
      return result;
    }
    if (tag === limits.valueTags.dictionary) {
      const count = this.u32();
      if (count > limits.dictionaryMaxFields) {
        throw new TypeError('WebGPU dictionary exceeds the reviewed field bound');
      }
      const result = Object.create(null) as Record<string, unknown>;
      let previous = '';
      for (let index = 0; index < count; index += 1) {
        const key = this.string(this.bytes.byteLength);
        if (
          (index > 0 && compareCanonicalUtf8(key, previous) <= 0) ||
          Object.prototype.hasOwnProperty.call(result, key)
        ) {
          throw new TypeError('WebGPU dictionary keys are not canonical');
        }
        previous = key;
        result[key] = this.value(limits, depth + 1);
      }
      return result;
    }
    throw new TypeError(`Unknown WebGPU value tag: ${tag}`);
  }

  done(): void {
    if (this.offset !== this.bytes.byteLength) {
      throw new TypeError('Trailing bytes in WebGPU payload');
    }
  }
}

type BufferLifecycleBody = NonNullable<
  ProductionGpuServiceEncodingInput['bufferLifecycle']
>;

type QueueWriteBufferBody = Readonly<{
  destination: ProductionGpuServiceEncodingInput['receiver'];
  destinationOffset: string;
  bytes: Uint8Array;
}>;

function arrayBufferViewBytes(value: ArrayBufferView, label: string): Uint8Array {
  if (!ArrayBuffer.isView(value)) {
    throw new TypeError(`${label} must be an owned byte view`);
  }
  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

function writeOwnedBytes(
  writer: Writer,
  value: ArrayBufferView,
  maximum: number,
  label: string,
): void {
  const bytes = arrayBufferViewBytes(value, label);
  if (bytes.byteLength > maximum) {
    throw new TypeError(`${label} exceeds the reviewed byte bound`);
  }
  writer.u64(String(bytes.byteLength));
  writer.raw(bytes);
}

function readOwnedBytes(
  reader: Reader,
  maximum: number,
  label: string,
): Uint8Array {
  const length = u64Number(reader.u64(), `${label} length`);
  if (length > maximum) {
    throw new TypeError(`${label} exceeds the reviewed byte bound`);
  }
  return reader.raw(length);
}

function readOwnedMappedBytes(
  reader: Reader,
  maximum: number,
  label: string,
): Uint8Array {
  const length = u64Number(reader.u64(), `${label} length`);
  if (length > maximum) {
    throw new TypeError(`${label} exceeds the reviewed byte bound`);
  }
  return reader.mappedBytes(length);
}

function exactLifecycleKeys(
  value: object,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.join('|') !== sortedExpected.join('|')) {
    throw new TypeError(`${label} is not a closed lifecycle body`);
  }
}

function validateBufferLifecycleBody(
  operationId: string,
  body: BufferLifecycleBody,
  maximum: number,
): void {
  if (operationId === BUFFER_MAP_ASYNC_OPERATION_ID) {
    if (body.kind !== 'map-async-v1') {
      throw new TypeError('GPUBuffer.mapAsync requires the map-async-v1 body');
    }
    exactLifecycleKeys(body, [
      'kind',
      'pendingMapGeneration',
      'mode',
      'offset',
      'requestedSizePresent',
      'requestedSize',
    ], 'GPUBuffer.mapAsync body');
    positiveIdentity(body.pendingMapGeneration, 'pendingMapGeneration');
    u64Number(body.offset, 'GPUBuffer.mapAsync offset');
    u64Number(body.requestedSize, 'GPUBuffer.mapAsync requested size');
    if (
      (body.mode !== 1 && body.mode !== 2) ||
      (body.requestedSizePresent !== 0 && body.requestedSizePresent !== 1) ||
      (body.requestedSizePresent === 0 && body.requestedSize !== '0')
    ) {
      throw new TypeError('GPUBuffer.mapAsync body violates its closed mode/range form');
    }
    return;
  }
  if (body.kind !== 'cleanup-v1') {
    throw new TypeError(`${operationId} requires the cleanup-v1 body`);
  }
  exactLifecycleKeys(body, [
    'kind',
    'cleanupAction',
    'cleanupGeneration',
    'cancelledMapGeneration',
    'activeMapGeneration',
    'activeMapMode',
    'mappedOffset',
    'mappedSize',
    'writeback',
  ], `${operationId} body`);
  for (const [name, value] of [
    ['cleanupGeneration', body.cleanupGeneration],
    ['cancelledMapGeneration', body.cancelledMapGeneration],
    ['activeMapGeneration', body.activeMapGeneration],
    ['mappedOffset', body.mappedOffset],
    ['mappedSize', body.mappedSize],
  ] as const) {
    parseU64Decimal(value);
  }
  const writeback = arrayBufferViewBytes(body.writeback, 'GPUBuffer cleanup writeback');
  if (writeback.byteLength > maximum) {
    throw new TypeError('GPUBuffer cleanup writeback exceeds the reviewed byte bound');
  }
  const allowedAction = operationId === BUFFER_DESTROY_OPERATION_ID
    ? body.cleanupAction === 0 || body.cleanupAction === 2
    : operationId === BUFFER_UNMAP_OPERATION_ID
    ? body.cleanupAction === 0 || body.cleanupAction === 1
    : false;
  if (!allowedAction) {
    throw new TypeError(`${operationId} cleanup action is invalid`);
  }
  if (body.cleanupAction === 0) {
    if (
      body.cleanupGeneration !== '0' ||
      body.cancelledMapGeneration !== '0' ||
      body.activeMapGeneration !== '0' ||
      body.activeMapMode !== 0 ||
      body.mappedOffset !== '0' ||
      body.mappedSize !== '0' ||
      writeback.byteLength !== 0
    ) {
      throw new TypeError('GPUBuffer cleanup no-op body is not empty');
    }
    return;
  }
  positiveIdentity(body.cleanupGeneration, 'cleanupGeneration');
  if (body.activeMapGeneration === '0') {
    if (
      body.activeMapMode !== 0 ||
      body.mappedOffset !== '0' ||
      body.mappedSize !== '0' ||
      writeback.byteLength !== 0
    ) {
      throw new TypeError('GPUBuffer cleanup empty active-map state is inconsistent');
    }
    return;
  }
  if (body.activeMapMode !== 1 && body.activeMapMode !== 2) {
    throw new TypeError('GPUBuffer cleanup active map mode is invalid');
  }
  if (body.activeMapMode === 1 && writeback.byteLength !== 0) {
    throw new TypeError('GPUBuffer MAP_READ cleanup may not carry writeback bytes');
  }
  if (
    body.activeMapMode === 2 &&
    String(writeback.byteLength) !== body.mappedSize
  ) {
    throw new TypeError('GPUBuffer MAP_WRITE cleanup must own the exact mapped extent');
  }
}

function writeBufferLifecycleBody(
  writer: Writer,
  operationId: string,
  body: BufferLifecycleBody,
  maximum: number,
): void {
  validateBufferLifecycleBody(operationId, body, maximum);
  if (body.kind === 'map-async-v1') {
    writer.u64(body.pendingMapGeneration);
    writer.u32(body.mode);
    writer.u64(body.offset);
    writer.u8(body.requestedSizePresent);
    writer.u64(body.requestedSize);
    return;
  }
  writer.u8(body.cleanupAction);
  writer.u64(body.cleanupGeneration);
  writer.u64(body.cancelledMapGeneration);
  writer.u64(body.activeMapGeneration);
  writer.u32(body.activeMapMode);
  writer.u64(body.mappedOffset);
  writer.u64(body.mappedSize);
  writeOwnedBytes(writer, body.writeback, maximum, 'GPUBuffer cleanup writeback');
}

function readBufferLifecycleBody(
  reader: Reader,
  operationId: string,
  maximum: number,
): BufferLifecycleBody {
  if (operationId === BUFFER_MAP_ASYNC_OPERATION_ID) {
    const body = {
      kind: 'map-async-v1',
      pendingMapGeneration: reader.u64(),
      mode: reader.u32(),
      offset: reader.u64(),
      requestedSizePresent: reader.u8(),
      requestedSize: reader.u64(),
    } as const as BufferLifecycleBody;
    validateBufferLifecycleBody(operationId, body, maximum);
    return body;
  }
  const body = {
    kind: 'cleanup-v1',
    cleanupAction: reader.u8(),
    cleanupGeneration: reader.u64(),
    cancelledMapGeneration: reader.u64(),
    activeMapGeneration: reader.u64(),
    activeMapMode: reader.u32(),
    mappedOffset: reader.u64(),
    mappedSize: reader.u64(),
    writeback: readOwnedBytes(
      reader,
      maximum,
      'GPUBuffer cleanup writeback',
    ),
  } as const as BufferLifecycleBody;
  validateBufferLifecycleBody(operationId, body, maximum);
  return body;
}

type CanvasServiceBody = NonNullable<
  ProductionGpuServiceEncodingInput['canvasService']
>;

function digestBytes(value: string, label: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
  const result = new Uint8Array(32);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function readDigest(reader: Reader): string {
  return bytesHex(reader.raw(32));
}

function validateCanvasServiceBody(
  operationId: string,
  body: CanvasServiceBody,
  receiver: ProductionGpuServiceEncodingInput['receiver'],
  convertedArguments: unknown,
  textureFormats: readonly string[],
  sequenceMaximum: number,
): void {
  if (operationId === CANVAS_CONFIGURE_OPERATION_ID) {
    if (body.kind !== 'canvas-configure-v1') {
      throw new TypeError('GPUCanvasContext.configure requires its closed authority body');
    }
    exactLifecycleKeys(body, [
      'kind',
      'receiverContextRef',
      'attachmentGeneration',
      'contextGeneration',
      'configurationGeneration',
      'configuredDeviceRef',
      'format',
      'usage',
      'viewFormats',
      'alphaMode',
      'colorSpace',
      'toneMappingMode',
      'targetAuthorityDigest',
      'surfaceAccountToken',
      'surfaceAccountGeneration',
    ], 'GPUCanvasContext.configure authority');
    const receiverContextRef = submitReference(
      body.receiverContextRef,
      'GPUCanvasContext.configure receiverContextRef',
      'GPUCanvasContext',
    );
    const configuredDeviceRef = submitReference(
      body.configuredDeviceRef,
      'GPUCanvasContext.configure configuredDeviceRef',
      'GPUDevice',
    );
    if (
      !sameReference(receiverContextRef, receiver) ||
      !sameDeviceReference(configuredDeviceRef, receiver)
    ) {
      throw new TypeError('GPUCanvasContext.configure authority was retargeted');
    }
    for (const [name, value] of [
      ['attachmentGeneration', body.attachmentGeneration],
      ['contextGeneration', body.contextGeneration],
      ['configurationGeneration', body.configurationGeneration],
      ['surfaceAccountToken', body.surfaceAccountToken],
      ['surfaceAccountGeneration', body.surfaceAccountGeneration],
    ] as const) {
      positiveIdentity(value, `GPUCanvasContext.configure ${name}`);
    }
    const converted = submitRecord(
      convertedArguments,
      'GPUCanvasContext.configure converted arguments',
    );
    const convertedToneMapping = submitRecord(
      converted.toneMapping,
      'GPUCanvasContext.configure converted toneMapping',
    );
    const convertedViewFormats = converted.viewFormats;
    if (body.toneMappingMode !== 'standard') {
      throw new TypeError(
        'GPUCanvasContext.configure toneMappingMode must be standard',
      );
    }
    if (
      !textureFormats.includes(body.format) ||
      !Number.isInteger(body.usage) ||
      body.usage < 0 ||
      body.usage > 0xffff_ffff ||
      !Array.isArray(body.viewFormats) ||
      body.viewFormats.length > sequenceMaximum ||
      body.viewFormats.some((format) => !textureFormats.includes(format)) ||
      (body.alphaMode !== 'opaque' && body.alphaMode !== 'premultiplied') ||
      (body.colorSpace !== 'srgb' && body.colorSpace !== 'display-p3') ||
      !Array.isArray(convertedViewFormats) ||
      convertedViewFormats.length !== body.viewFormats.length ||
      body.viewFormats.some(
        (format, index) => convertedViewFormats[index] !== format,
      ) ||
      converted.format !== body.format ||
      converted.usage !== body.usage ||
      converted.alphaMode !== body.alphaMode ||
      converted.colorSpace !== body.colorSpace ||
      convertedToneMapping.mode !== body.toneMappingMode
    ) {
      throw new TypeError(
        'GPUCanvasContext.configure authority disagrees with converted configuration',
      );
    }
    digestBytes(body.targetAuthorityDigest, 'canvas target authority digest');
    return;
  }

  if (operationId === CANVAS_UNCONFIGURE_OPERATION_ID) {
    if (body.kind !== 'canvas-unconfigure-v1') {
      throw new TypeError('GPUCanvasContext.unconfigure requires its closed authority body');
    }
    exactLifecycleKeys(body, [
      'kind',
      'receiverContextRef',
      'attachmentGeneration',
      'contextGeneration',
      'configurationGeneration',
      'terminalIntent',
      'targetAuthorityDigest',
      'surfaceAccountToken',
      'surfaceAccountGeneration',
    ], 'GPUCanvasContext.unconfigure authority');
    const receiverContextRef = submitReference(
      body.receiverContextRef,
      'GPUCanvasContext.unconfigure receiverContextRef',
      'GPUCanvasContext',
    );
    if (
      !sameReference(receiverContextRef, receiver) ||
      body.terminalIntent !== 'first-cleanup' ||
      convertedArguments !== null
    ) {
      throw new TypeError('GPUCanvasContext.unconfigure authority was retargeted');
    }
    for (const [name, value] of [
      ['attachmentGeneration', body.attachmentGeneration],
      ['contextGeneration', body.contextGeneration],
      ['configurationGeneration', body.configurationGeneration],
      ['surfaceAccountToken', body.surfaceAccountToken],
      ['surfaceAccountGeneration', body.surfaceAccountGeneration],
    ] as const) {
      positiveIdentity(value, `GPUCanvasContext.unconfigure ${name}`);
    }
    digestBytes(body.targetAuthorityDigest, 'canvas target authority digest');
    return;
  }

  if (operationId !== TEXTURE_DESTROY_OPERATION_ID ||
      body.kind !== 'texture-destroy-v1') {
    throw new TypeError(`${operationId} has the wrong canvas service body`);
  }
  exactLifecycleKeys(body, [
    'kind',
    'receiverTextureRef',
    'terminalIntent',
    'materializationState',
    'origin',
  ], 'GPUTexture.destroy authority');
  const receiverTextureRef = submitReference(
    body.receiverTextureRef,
    'GPUTexture.destroy receiverTextureRef',
    'GPUTexture',
  );
  if (
    !sameReference(receiverTextureRef, receiver) ||
    convertedArguments !== null ||
    ![
      'first-cleanup',
      'first-expired-cleanup',
      'repeat-cleanup-noop',
    ].includes(body.terminalIntent) ||
    (body.materializationState !== 'unmaterialized' &&
      body.materializationState !== 'materialized')
  ) {
    throw new TypeError('GPUTexture.destroy authority was retargeted');
  }
  if (body.origin.kind === 'device-created-v1') {
    exactLifecycleKeys(body.origin, ['kind'], 'GPUTexture.destroy device origin');
    if (body.terminalIntent === 'first-expired-cleanup') {
      throw new TypeError('A device-created texture cannot carry canvas expiry');
    }
    return;
  }
  if (body.origin.kind !== 'canvas-current-v1') {
    throw new TypeError('GPUTexture.destroy has an unknown origin class');
  }
  exactLifecycleKeys(body.origin, [
    'kind',
    'contextRef',
    'attachmentGeneration',
    'contextGeneration',
    'configurationGeneration',
    'currentEpoch',
    'mintOperationProvenance',
    'textureOriginDigest',
  ], 'GPUTexture.destroy canvas-current origin');
  const contextRef = submitReference(
    body.origin.contextRef,
    'GPUTexture.destroy contextRef',
    'GPUCanvasContext',
  );
  if (!sameDeviceReference(contextRef, receiver)) {
    throw new TypeError('GPUTexture.destroy canvas origin has foreign device provenance');
  }
  exactLifecycleKeys(body.origin.mintOperationProvenance, [
    'operationInstanceId',
    'deviceIngressOrdinal',
  ], 'GPUTexture.destroy mint provenance');
  for (const [name, value] of [
    ['attachmentGeneration', body.origin.attachmentGeneration],
    ['contextGeneration', body.origin.contextGeneration],
    ['configurationGeneration', body.origin.configurationGeneration],
    ['currentEpoch', body.origin.currentEpoch],
    [
      'mintOperationInstanceId',
      body.origin.mintOperationProvenance.operationInstanceId,
    ],
    [
      'mintDeviceIngressOrdinal',
      body.origin.mintOperationProvenance.deviceIngressOrdinal,
    ],
  ] as const) {
    positiveIdentity(value, `GPUTexture.destroy ${name}`);
  }
  digestBytes(body.origin.textureOriginDigest, 'canvas texture origin digest');
}

function writeCanvasServiceBody(
  writer: Writer,
  operationId: string,
  body: CanvasServiceBody,
  receiver: ProductionGpuServiceEncodingInput['receiver'],
  convertedArguments: unknown,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
  textureFormats: readonly string[],
  sequenceMaximum: number,
): void {
  validateCanvasServiceBody(
    operationId,
    body,
    receiver,
    convertedArguments,
    textureFormats,
    sequenceMaximum,
  );
  if (body.kind === 'canvas-configure-v1') {
    writeReference(writer, body.receiverContextRef, objectKinds);
    writer.u64(body.attachmentGeneration);
    writer.u64(body.contextGeneration);
    writer.u64(body.configurationGeneration);
    writeReference(writer, body.configuredDeviceRef, objectKinds);
    writer.string(body.format);
    writer.u32(body.usage);
    writer.u32(body.viewFormats.length);
    for (const viewFormat of body.viewFormats) writer.string(viewFormat);
    writer.u8(body.alphaMode === 'opaque' ? 1 : 2);
    writer.u8(body.colorSpace === 'srgb' ? 1 : 2);
    writer.u8(body.toneMappingMode === 'standard' ? 1 : 2);
    writer.raw(digestBytes(body.targetAuthorityDigest, 'canvas target authority digest'));
    writer.u64(body.surfaceAccountToken);
    writer.u64(body.surfaceAccountGeneration);
    return;
  }
  if (body.kind === 'canvas-unconfigure-v1') {
    writeReference(writer, body.receiverContextRef, objectKinds);
    writer.u64(body.attachmentGeneration);
    writer.u64(body.contextGeneration);
    writer.u64(body.configurationGeneration);
    writer.u8(1);
    writer.raw(digestBytes(body.targetAuthorityDigest, 'canvas target authority digest'));
    writer.u64(body.surfaceAccountToken);
    writer.u64(body.surfaceAccountGeneration);
    return;
  }
  writeReference(writer, body.receiverTextureRef, objectKinds);
  writer.u8({
    'repeat-cleanup-noop': 0,
    'first-cleanup': 1,
    'first-expired-cleanup': 2,
  }[body.terminalIntent]);
  writer.u8(body.materializationState === 'materialized' ? 1 : 0);
  writer.u8(body.origin.kind === 'device-created-v1' ? 1 : 2);
  if (body.origin.kind === 'canvas-current-v1') {
    writeReference(writer, body.origin.contextRef, objectKinds);
    writer.u64(body.origin.attachmentGeneration);
    writer.u64(body.origin.contextGeneration);
    writer.u64(body.origin.configurationGeneration);
    writer.u64(body.origin.currentEpoch);
    writer.u64(body.origin.mintOperationProvenance.operationInstanceId);
    writer.u64(body.origin.mintOperationProvenance.deviceIngressOrdinal);
    writer.raw(digestBytes(body.origin.textureOriginDigest, 'canvas texture origin digest'));
  }
}

function readCanvasServiceBody(
  reader: Reader,
  operationId: string,
  receiver: ProductionGpuServiceEncodingInput['receiver'],
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
  textureFormats: readonly string[],
  sequenceMaximum: number,
): CanvasServiceBody {
  let body: CanvasServiceBody;
  let convertedArguments: unknown = null;
  if (operationId === CANVAS_CONFIGURE_OPERATION_ID) {
    const receiverContextRef = readReference(reader, objectKindsByTag);
    const attachmentGeneration = reader.u64();
    const contextGeneration = reader.u64();
    const configurationGeneration = reader.u64();
    const configuredDeviceRef = readReference(reader, objectKindsByTag);
    const format = reader.string(256);
    const usage = reader.u32();
    const viewFormatCount = reader.u32();
    if (viewFormatCount > sequenceMaximum) {
      throw new TypeError('GPUCanvasContext.configure viewFormats exceeds its bound');
    }
    const viewFormats = Object.freeze(
      Array.from({ length: viewFormatCount }, () => reader.string(256)),
    );
    const alphaModeTag = reader.u8();
    const colorSpaceTag = reader.u8();
    const toneMappingModeTag = reader.u8();
    const alphaMode = alphaModeTag === 1
      ? 'opaque'
      : alphaModeTag === 2
        ? 'premultiplied'
        : undefined;
    const colorSpace = colorSpaceTag === 1
      ? 'srgb'
      : colorSpaceTag === 2
        ? 'display-p3'
        : undefined;
    const toneMappingMode = toneMappingModeTag === 1
      ? 'standard'
      : toneMappingModeTag === 2
        ? 'extended'
        : undefined;
    if (!alphaMode || !colorSpace || !toneMappingMode) {
      throw new TypeError('GPUCanvasContext.configure enum tag is unknown');
    }
    body = Object.freeze({
      kind: 'canvas-configure-v1',
      receiverContextRef,
      attachmentGeneration,
      contextGeneration,
      configurationGeneration,
      configuredDeviceRef,
      format,
      usage,
      viewFormats,
      alphaMode,
      colorSpace,
      toneMappingMode,
      targetAuthorityDigest: readDigest(reader),
      surfaceAccountToken: reader.u64(),
      surfaceAccountGeneration: reader.u64(),
    });
    convertedArguments = Object.freeze({
      format,
      usage,
      viewFormats,
      alphaMode,
      colorSpace,
      toneMapping: Object.freeze({ mode: toneMappingMode }),
    });
  } else if (operationId === CANVAS_UNCONFIGURE_OPERATION_ID) {
    const terminalIntentTag = (() => {
      const receiverContextRef = readReference(reader, objectKindsByTag);
      const attachmentGeneration = reader.u64();
      const contextGeneration = reader.u64();
      const configurationGeneration = reader.u64();
      const tag = reader.u8();
      body = Object.freeze({
        kind: 'canvas-unconfigure-v1',
        receiverContextRef,
        attachmentGeneration,
        contextGeneration,
        configurationGeneration,
        terminalIntent: 'first-cleanup',
        targetAuthorityDigest: readDigest(reader),
        surfaceAccountToken: reader.u64(),
        surfaceAccountGeneration: reader.u64(),
      });
      return tag;
    })();
    if (terminalIntentTag !== 1) {
      throw new TypeError('GPUCanvasContext.unconfigure terminal intent is unknown');
    }
  } else {
    const receiverTextureRef = readReference(reader, objectKindsByTag);
    const terminalIntentTag = reader.u8();
    const materializationTag = reader.u8();
    const originTag = reader.u8();
    const terminalIntent = terminalIntentTag === 0
      ? 'repeat-cleanup-noop'
      : terminalIntentTag === 1
        ? 'first-cleanup'
        : terminalIntentTag === 2
          ? 'first-expired-cleanup'
          : undefined;
    const materializationState = materializationTag === 0
      ? 'unmaterialized'
      : materializationTag === 1
        ? 'materialized'
        : undefined;
    if (!terminalIntent || !materializationState || (originTag !== 1 && originTag !== 2)) {
      throw new TypeError('GPUTexture.destroy body tag is unknown');
    }
    const origin = originTag === 1
      ? Object.freeze({ kind: 'device-created-v1' as const })
      : Object.freeze({
          kind: 'canvas-current-v1' as const,
          contextRef: readReference(reader, objectKindsByTag),
          attachmentGeneration: reader.u64(),
          contextGeneration: reader.u64(),
          configurationGeneration: reader.u64(),
          currentEpoch: reader.u64(),
          mintOperationProvenance: Object.freeze({
            operationInstanceId: reader.u64(),
            deviceIngressOrdinal: reader.u64(),
          }),
          textureOriginDigest: readDigest(reader),
        });
    body = Object.freeze({
      kind: 'texture-destroy-v1',
      receiverTextureRef,
      terminalIntent,
      materializationState,
      origin,
    });
  }
  validateCanvasServiceBody(
    operationId,
    body,
    receiver,
    convertedArguments,
    textureFormats,
    sequenceMaximum,
  );
  return body;
}

function validateCanvasServiceRequestFields(
  input: ProductionGpuServiceEncodingInput,
  textureFormats: readonly string[],
  sequenceMaximum: number,
): CanvasServiceBody {
  const expectedReceiverKind = input.operationId === TEXTURE_DESTROY_OPERATION_ID
    ? 'GPUTexture'
    : 'GPUCanvasContext';
  submitReference(input.receiver, `${input.operationId} receiver`, expectedReceiverKind);
  if (
    input.target !== undefined ||
    input.adapterOrdinal !== '0' ||
    input.queueIngressOrdinal !== '0' ||
    !Array.isArray(input.sealedLocalTimeline) ||
    input.sealedLocalTimeline.length !== 0
  ) {
    throw new TypeError(`${input.operationId} violates its canvas carrier projection`);
  }
  parseU64Decimal(input.capturedScopeId);
  positiveIdentity(input.deviceIngressOrdinal, `${input.operationId} device ingress`);
  if (!input.canvasService) {
    throw new TypeError(`${input.operationId} wrapper authority is missing`);
  }
  validateCanvasServiceBody(
    input.operationId,
    input.canvasService,
    input.receiver,
    input.convertedArguments,
    textureFormats,
    sequenceMaximum,
  );
  return input.canvasService;
}

function validateBufferLifecycleRequestFields(
  input: ProductionGpuServiceEncodingInput,
  maximum: number,
): BufferLifecycleBody {
  if (
    input.receiver.kind !== 'GPUBuffer' ||
    input.target !== undefined ||
    input.adapterOrdinal !== '0' ||
    input.queueIngressOrdinal !== '0' ||
    !Array.isArray(input.sealedLocalTimeline) ||
    input.sealedLocalTimeline.length !== 0
  ) {
    throw new TypeError(
      `${input.operationId} lifecycle request violates its carrier projection`,
    );
  }
  positiveIdentity(input.receiver.objectId, 'GPUBuffer.objectId');
  positiveIdentity(input.receiver.objectGeneration, 'GPUBuffer.objectGeneration');
  positiveIdentity(input.receiver.logicalDeviceId, 'GPUBuffer.logicalDeviceId');
  positiveIdentity(
    input.receiver.logicalDeviceGeneration,
    'GPUBuffer.logicalDeviceGeneration',
  );
  positiveIdentity(input.receiver.providerGeneration, 'GPUBuffer.providerGeneration');
  parseU64Decimal(input.capturedScopeId);
  positiveIdentity(input.deviceIngressOrdinal, 'GPUBuffer.deviceIngressOrdinal');
  if (!input.bufferLifecycle) {
    throw new TypeError(`${input.operationId} lifecycle body is missing`);
  }
  validateBufferLifecycleBody(input.operationId, input.bufferLifecycle, maximum);
  if (input.bufferLifecycle.kind === 'map-async-v1') {
    if (
      typeof input.convertedArguments !== 'object' ||
      input.convertedArguments === null ||
      Array.isArray(input.convertedArguments)
    ) {
      throw new TypeError('GPUBuffer.mapAsync converted arguments are missing');
    }
    const converted = input.convertedArguments as Readonly<Record<string, unknown>>;
    const expectedKeys = input.bufferLifecycle.requestedSizePresent === 1
      ? ['mode', 'offset', 'size']
      : ['mode', 'offset'];
    exactLifecycleKeys(converted, expectedKeys, 'GPUBuffer.mapAsync converted arguments');
    if (
      converted.mode !== input.bufferLifecycle.mode ||
      String(converted.offset) !== input.bufferLifecycle.offset ||
      (input.bufferLifecycle.requestedSizePresent === 1 &&
        String(converted.size) !== input.bufferLifecycle.requestedSize)
    ) {
      throw new TypeError(
        'GPUBuffer.mapAsync lifecycle body disagrees with converted arguments',
      );
    }
  } else if (input.convertedArguments !== null) {
    throw new TypeError(`${input.operationId} cleanup arguments must be null`);
  }
  return input.bufferLifecycle;
}

function validateQueueWriteBufferRequestFields(
  input: ProductionGpuServiceEncodingInput,
  maximum: number,
): QueueWriteBufferBody {
  if (
    input.receiver.kind !== 'GPUQueue' ||
    input.target !== undefined ||
    input.adapterOrdinal !== '0' ||
    !Array.isArray(input.sealedLocalTimeline) ||
    input.sealedLocalTimeline.length !== 0 ||
    input.bufferLifecycle !== undefined
  ) {
    throw new TypeError(
      'GPUQueue.writeBuffer request violates its carrier projection',
    );
  }
  positiveIdentity(input.receiver.objectId, 'GPUQueue.objectId');
  positiveIdentity(input.receiver.objectGeneration, 'GPUQueue.objectGeneration');
  positiveIdentity(input.receiver.logicalDeviceId, 'GPUQueue.logicalDeviceId');
  positiveIdentity(
    input.receiver.logicalDeviceGeneration,
    'GPUQueue.logicalDeviceGeneration',
  );
  positiveIdentity(input.receiver.providerGeneration, 'GPUQueue.providerGeneration');
  parseU64Decimal(input.capturedScopeId);
  positiveIdentity(input.deviceIngressOrdinal, 'GPUQueue.deviceIngressOrdinal');
  positiveIdentity(input.queueIngressOrdinal, 'GPUQueue.queueIngressOrdinal');
  if (
    typeof input.convertedArguments !== 'object' ||
    input.convertedArguments === null ||
    Array.isArray(input.convertedArguments)
  ) {
    throw new TypeError('GPUQueue.writeBuffer converted arguments are missing');
  }
  const converted = input.convertedArguments as Readonly<Record<string, unknown>>;
  exactLifecycleKeys(
    converted,
    ['buffer', 'bufferOffset', 'bytes'],
    'GPUQueue.writeBuffer converted arguments',
  );
  const destinationValue = converted.buffer;
  if (
    typeof destinationValue !== 'object' ||
    destinationValue === null ||
    Array.isArray(destinationValue)
  ) {
    throw new TypeError('GPUQueue.writeBuffer destination reference is missing');
  }
  const destination = destinationValue as Readonly<Record<string, unknown>>;
  exactLifecycleKeys(
    destination,
    [
      'kind',
      'objectId',
      'objectGeneration',
      'logicalDeviceId',
      'logicalDeviceGeneration',
      'providerGeneration',
    ],
    'GPUQueue.writeBuffer destination reference',
  );
  if (
    destination.kind !== 'GPUBuffer' ||
    typeof destination.objectId !== 'string' ||
    typeof destination.objectGeneration !== 'string' ||
    typeof destination.logicalDeviceId !== 'string' ||
    typeof destination.logicalDeviceGeneration !== 'string' ||
    typeof destination.providerGeneration !== 'string'
  ) {
    throw new TypeError('GPUQueue.writeBuffer destination is not a full GPUBuffer reference');
  }
  positiveIdentity(destination.objectId, 'GPUBuffer.objectId');
  positiveIdentity(destination.objectGeneration, 'GPUBuffer.objectGeneration');
  positiveIdentity(destination.logicalDeviceId, 'GPUBuffer.logicalDeviceId');
  positiveIdentity(
    destination.logicalDeviceGeneration,
    'GPUBuffer.logicalDeviceGeneration',
  );
  positiveIdentity(destination.providerGeneration, 'GPUBuffer.providerGeneration');
  if (
    destination.logicalDeviceId !== input.receiver.logicalDeviceId ||
    destination.logicalDeviceGeneration !==
      input.receiver.logicalDeviceGeneration ||
    destination.providerGeneration !== input.receiver.providerGeneration
  ) {
    throw new TypeError(
      'GPUQueue.writeBuffer destination does not join the receiver device generation',
    );
  }
  const destinationOffset = u64Number(
    converted.bufferOffset,
    'GPUQueue.writeBuffer destination offset',
  );
  if (!(converted.bytes instanceof Uint8Array)) {
    throw new TypeError('GPUQueue.writeBuffer source snapshot must be owned bytes');
  }
  const maximumBytes = maximum - QUEUE_WRITE_BUFFER_FIXED_PAYLOAD_BYTES;
  if (
    converted.bytes.byteLength > maximumBytes ||
    converted.bytes.byteLength % 4 !== 0
  ) {
    throw new TypeError(
      'GPUQueue.writeBuffer source snapshot violates its exact payload bound',
    );
  }
  return Object.freeze({
    destination: destination as QueueWriteBufferBody['destination'],
    destinationOffset: String(destinationOffset),
    bytes: converted.bytes,
  });
}

function writeQueueWriteBufferBody(
  writer: Writer,
  body: QueueWriteBufferBody,
  maximum: number,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
): void {
  writeReference(writer, body.destination, objectKinds);
  writer.u64(body.destinationOffset);
  writeOwnedBytes(
    writer,
    body.bytes,
    maximum - QUEUE_WRITE_BUFFER_FIXED_PAYLOAD_BYTES,
    'GPUQueue.writeBuffer source snapshot',
  );
}

function readQueueWriteBufferBody(
  reader: Reader,
  maximum: number,
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
): QueueWriteBufferBody {
  const destination = readReference(reader, objectKindsByTag);
  if (destination.kind !== 'GPUBuffer') {
    throw new TypeError('GPUQueue.writeBuffer destination kind is not GPUBuffer');
  }
  positiveIdentity(destination.objectId, 'GPUBuffer.objectId');
  positiveIdentity(destination.objectGeneration, 'GPUBuffer.objectGeneration');
  positiveIdentity(destination.logicalDeviceId, 'GPUBuffer.logicalDeviceId');
  positiveIdentity(
    destination.logicalDeviceGeneration,
    'GPUBuffer.logicalDeviceGeneration',
  );
  positiveIdentity(destination.providerGeneration, 'GPUBuffer.providerGeneration');
  const destinationOffset = reader.u64();
  u64Number(destinationOffset, 'GPUQueue.writeBuffer destination offset');
  const bytes = readOwnedBytes(
    reader,
    maximum - QUEUE_WRITE_BUFFER_FIXED_PAYLOAD_BYTES,
    'GPUQueue.writeBuffer source snapshot',
  );
  if (bytes.byteLength % 4 !== 0) {
    throw new TypeError(
      'GPUQueue.writeBuffer source snapshot byte length is not a multiple of 4',
    );
  }
  return Object.freeze({ destination, destinationOffset, bytes });
}

function writeReference(
  writer: Writer,
  reference: ProductionGpuServiceEncodingInput['receiver'],
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
): void {
  const kind = objectKinds[reference.kind];
  if (!kind) throw new TypeError(`Unknown WebGPU object kind: ${reference.kind}`);
  writer.u8(kind);
  writer.u64(reference.objectId);
  writer.u64(reference.objectGeneration);
  writer.u64(reference.logicalDeviceId);
  writer.u64(reference.logicalDeviceGeneration);
  writer.u64(reference.providerGeneration);
}

function readReference(
  reader: Reader,
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
): ProductionGpuServiceEncodingInput['receiver'] {
  const kindTag = reader.u8();
  const kind = objectKindsByTag.get(kindTag);
  if (!kind) throw new TypeError(`Unknown WebGPU object kind tag: ${kindTag}`);
  return Object.freeze({
    kind,
    objectId: reader.u64(),
    objectGeneration: reader.u64(),
    logicalDeviceId: reader.u64(),
    logicalDeviceGeneration: reader.u64(),
    providerGeneration: reader.u64(),
  });
}

function writeHeader(
  writer: Writer,
  magic: string,
  version: number,
  codecTag: number,
  wireId: number,
): void {
  writer.ascii4(magic);
  writer.u16(version);
  writer.u16(codecTag);
  writer.u32(wireId);
}

function readHeader(
  reader: Reader,
  magic: string,
  version: number,
  expectedCodecTag: number,
  expectedWireId: number,
): void {
  if (reader.ascii4() !== magic) throw new TypeError('Unknown WebGPU payload magic');
  if (reader.u16() !== version) throw new TypeError('Unknown WebGPU codec version');
  const codecTag = reader.u16();
  if (codecTag !== expectedCodecTag) {
    throw new TypeError(`Unexpected WebGPU codec tag: ${codecTag}`);
  }
  if (reader.u32() !== expectedWireId) {
    throw new TypeError('WebGPU payload operation identity mismatch');
  }
}

function positiveIdentity(value: string, label: string): string {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new TypeError(`${label} must be a positive identity`);
  }
  return value;
}

interface QueueSubmitRecordSpec {
  readonly tag: number;
  readonly operationName: string;
  readonly identityClass: 'active-route' | 'staged-local';
  readonly operationId: number;
  readonly operationIdentitySha256: string | null;
  readonly commandRecord: boolean;
}

const QUEUE_SUBMIT_RECORD_VARIANTS = Object.freeze([
  ['GPUCanvasContext.getCurrentTexture', 0, false],
  ['GPUCommandEncoder.beginComputePass', 1, true],
  ['GPUCommandEncoder.beginRenderPass', 2, true],
  ['GPUCommandEncoder.clearBuffer', 3, true],
  ['GPUCommandEncoder.copyBufferToBuffer', 4, true],
  ['GPUCommandEncoder.copyTextureToTexture', 5, true],
  ['GPUComputePassEncoder.setPipeline', 6, true],
  ['GPUComputePassEncoder.setBindGroup', 7, true],
  ['GPUComputePassEncoder.dispatchWorkgroups', 8, true],
  ['GPUComputePassEncoder.end', 9, true],
  ['GPURenderPassEncoder.setPipeline', 10, true],
  ['GPURenderPassEncoder.setBindGroup', 11, true],
  ['GPURenderPassEncoder.setVertexBuffer', 12, true],
  ['GPURenderPassEncoder.draw', 13, true],
  ['GPURenderPassEncoder.end', 14, true],
  ['GPUCommandEncoder.finish', 15, true],
] as const);

function buildQueueSubmitRecordSpecs(): Readonly<{
  byName: ReadonlyMap<string, QueueSubmitRecordSpec>;
  byTag: ReadonlyMap<number, QueueSubmitRecordSpec>;
}> {
  const staged = new Map<
    string,
    (typeof WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.operations)[number]
  >(
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.operations
      .map((entry) => [entry.operationId, entry] as const),
  );
  const active = new Map<
    string,
    (typeof WEBGPU_PRODUCTION_PLAN.routes)[number]
  >(
    WEBGPU_PRODUCTION_PLAN.routes.map((entry) => [entry.operationId, entry] as const),
  );
  const promoted = new Set(
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.authenticatedPromotions.map(
      (entry) => entry.operationId,
    ),
  );
  const specs = QUEUE_SUBMIT_RECORD_VARIANTS.map(
    ([operationName, tag, commandRecord]): QueueSubmitRecordSpec => {
      const stagedEntry = staged.get(operationName);
      const activeEntry = active.get(operationName);
      const authenticatedPromotion =
        stagedEntry !== undefined &&
        activeEntry !== undefined &&
        promoted.has(operationName);
      if (
        (stagedEntry === undefined && activeEntry === undefined) ||
        (stagedEntry !== undefined &&
          activeEntry !== undefined &&
          !authenticatedPromotion)
      ) {
        throw new Error(`Queue-submit record identity is ambiguous: ${operationName}`);
      }
      if (stagedEntry && !authenticatedPromotion) {
        if (
          stagedEntry.logicalExecutionKind !== 'wrapper-local-recording' ||
          stagedEntry.terminalDisposition !==
            'sealed-logical-record-no-provider-submit' ||
          stagedEntry.routingDisposition !==
            'construction-private-non-installing-non-routing' ||
          !/^[0-9a-f]{64}$/u.test(stagedEntry.recordIdentitySha256)
        ) {
          throw new Error(`Invalid staged queue-submit identity: ${operationName}`);
        }
        return Object.freeze({
          tag,
          operationName,
          identityClass: 'staged-local',
          operationId: stagedEntry.localRecordId,
          operationIdentitySha256: stagedEntry.recordIdentitySha256,
          commandRecord,
        });
      }
      if (
        activeEntry?.providerSubmission !== 'none' ||
        activeEntry.operationInstanceIdentity !==
          'wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record'
      ) {
        throw new Error(`Invalid active queue-submit identity: ${operationName}`);
      }
      return Object.freeze({
        tag,
        operationName,
        identityClass: 'active-route',
        operationId: activeEntry.wireId,
        operationIdentitySha256: null,
        commandRecord,
      });
    },
  );
  return Object.freeze({
    byName: new Map(specs.map((spec) => [spec.operationName, spec])),
    byTag: new Map(specs.map((spec) => [spec.tag, spec])),
  });
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) ||
    keys.some((key) => !allowed.has(key))
  ) {
    throw new TypeError(`${label} is not a closed record`);
  }
}

function submitRecord(value: unknown, label: string): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be a record`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function submitU32(value: unknown, label: string): number {
  if (!Number.isInteger(value) || (value as number) < 0 ||
      (value as number) > 0xffff_ffff) {
    throw new TypeError(`${label} must be a u32`);
  }
  return value as number;
}

function submitU64(value: unknown, label: string): number {
  return u64Number(value, label);
}

function submitString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string`);
  encodeUtf8(value);
  return value;
}

function submitReference(
  value: unknown,
  label: string,
  expectedKind?: ProductionGpuWrapperKind,
  permitDeviceLessWrapper = false,
): ProductionGpuServiceEncodingInput['receiver'] {
  const record = submitRecord(value, label);
  exactKeys(record, [
    'kind',
    'objectId',
    'objectGeneration',
    'logicalDeviceId',
    'logicalDeviceGeneration',
    'providerGeneration',
  ], [], label);
  const kind = record.kind;
  if (
    typeof kind !== 'string' ||
    !(PRODUCTION_WRAPPER_KINDS as readonly string[]).includes(kind) ||
    (expectedKind !== undefined && kind !== expectedKind)
  ) {
    throw new TypeError(`${label} has the wrong object kind`);
  }
  for (const field of [
    'objectId',
    'objectGeneration',
    'logicalDeviceId',
    'logicalDeviceGeneration',
    'providerGeneration',
  ] as const) {
    if (typeof record[field] !== 'string') {
      throw new TypeError(`${label}.${field} must be a canonical u64 string`);
    }
    parseU64Decimal(record[field] as string);
  }
  positiveIdentity(record.objectId as string, `${label}.objectId`);
  positiveIdentity(record.objectGeneration as string, `${label}.objectGeneration`);
  if (permitDeviceLessWrapper && (kind === 'GPU' || kind === 'GPUAdapter')) {
    if (
      record.logicalDeviceId !== '0' ||
      record.logicalDeviceGeneration !== '0' ||
      (kind === 'GPU'
        ? record.providerGeneration !== '0'
        : record.providerGeneration === '0')
    ) {
      throw new TypeError(`${label} has invalid device-less provenance`);
    }
  } else {
    positiveIdentity(record.logicalDeviceId as string, `${label}.logicalDeviceId`);
    positiveIdentity(
      record.logicalDeviceGeneration as string,
      `${label}.logicalDeviceGeneration`,
    );
    positiveIdentity(
      record.providerGeneration as string,
      `${label}.providerGeneration`,
    );
  }
  return Object.freeze(record) as ProductionGpuServiceEncodingInput['receiver'];
}

function sameReference(
  left: ProductionGpuServiceEncodingInput['receiver'],
  right: ProductionGpuServiceEncodingInput['receiver'],
): boolean {
  return left.kind === right.kind &&
    left.objectId === right.objectId &&
    left.objectGeneration === right.objectGeneration &&
    left.logicalDeviceId === right.logicalDeviceId &&
    left.logicalDeviceGeneration === right.logicalDeviceGeneration &&
    left.providerGeneration === right.providerGeneration;
}

function sameDeviceReference(
  value: ProductionGpuServiceEncodingInput['receiver'],
  device: ProductionGpuServiceEncodingInput['receiver'],
): boolean {
  return value.logicalDeviceId === device.logicalDeviceId &&
    value.logicalDeviceGeneration === device.logicalDeviceGeneration &&
    value.providerGeneration === device.providerGeneration;
}

function submitOptionalReference(
  value: unknown,
  label: string,
  device: ProductionGpuServiceEncodingInput['receiver'],
  expectedKind?: ProductionGpuWrapperKind,
): ProductionGpuServiceEncodingInput['receiver'] | null {
  if (value === null) return null;
  const reference = submitReference(value, label, expectedKind);
  if (!sameDeviceReference(reference, device)) {
    throw new TypeError(`${label} has foreign device provenance`);
  }
  return reference;
}

function validateReferenceSequence(
  value: unknown,
  label: string,
  kind: ProductionGpuWrapperKind,
  maximum: number,
): readonly ProductionGpuServiceEncodingInput['receiver'][] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new TypeError(`${label} must be a bounded reference sequence`);
  }
  const references = value.map((entry, index) =>
    submitReference(entry, `${label}[${index}]`, kind));
  for (let index = 1; index < references.length; index += 1) {
    const left = references[index - 1]!;
    const right = references[index]!;
    const leftKey = `${left.objectId}/${left.objectGeneration}`;
    const rightKey = `${right.objectId}/${right.objectGeneration}`;
    if (leftKey >= rightKey) {
      throw new TypeError(`${label} is not strictly sorted and unique`);
    }
  }
  return references as readonly ProductionGpuServiceEncodingInput['receiver'][];
}

function validateQueueSubmitArgument(
  spec: QueueSubmitRecordSpec,
  value: unknown,
  _device: ProductionGpuServiceEncodingInput['receiver'],
  maximum: number,
): void {
  const record = value === null || Array.isArray(value)
    ? null
    : submitRecord(value, `${spec.operationName} arguments`);
  const ref = (
    candidate: unknown,
    label: string,
    kind?: ProductionGpuWrapperKind,
  ) => submitReference(candidate, label, kind, true);
  const optionalU64 = (candidate: unknown, label: string) => {
    if (candidate !== null) submitU64(candidate, label);
  };
  const bindGroupArguments = () => {
    if (!record) throw new TypeError(`${spec.operationName} arguments are missing`);
    exactKeys(record, ['index', 'bindGroup', 'dynamicOffsets', 'overload'], [], spec.operationName);
    submitU32(record.index, `${spec.operationName}.index`);
    if (record.bindGroup !== null) ref(record.bindGroup, `${spec.operationName}.bindGroup`, 'GPUBindGroup');
    if (!Array.isArray(record.dynamicOffsets) || record.dynamicOffsets.length > maximum) {
      throw new TypeError(`${spec.operationName}.dynamicOffsets is not bounded`);
    }
    record.dynamicOffsets.forEach((entry, index) =>
      submitU32(entry, `${spec.operationName}.dynamicOffsets[${index}]`));
    if (record.overload !== 'iterable' && record.overload !== 'uint32-range') {
      throw new TypeError(`${spec.operationName}.overload is invalid`);
    }
  };

  switch (spec.operationName) {
    case 'GPUCanvasContext.getCurrentTexture':
      if (!record) {
        throw new TypeError('GPUCanvasContext.getCurrentTexture arguments are missing');
      }
      exactKeys(record, ['currentOrigin'], [], spec.operationName);
      validateCanvasCurrentTextureOrigin(
        record.currentOrigin,
        WEBGPU_PRODUCTION_PLAN.webIdlVocabulary,
        'GPUCanvasContext.getCurrentTexture currentOrigin',
      );
      return;
    case 'GPURenderPassEncoder.end':
      if (value !== null) throw new TypeError(`${spec.operationName} arguments must be null`);
      return;
    case 'GPUCommandEncoder.beginComputePass': {
      if (!record) throw new TypeError('beginComputePass arguments are missing');
      exactKeys(record, ['label', 'timestampWrites'], [], spec.operationName);
      submitString(record.label, `${spec.operationName}.label`);
      if (record.timestampWrites !== null) {
        const timestamp = submitRecord(record.timestampWrites, 'timestampWrites');
        exactKeys(timestamp, [
          'beginningOfPassWriteIndex',
          'endOfPassWriteIndex',
          'querySet',
        ], [], 'timestampWrites');
        if (timestamp.beginningOfPassWriteIndex !== null) {
          submitU32(timestamp.beginningOfPassWriteIndex, 'beginningOfPassWriteIndex');
        }
        if (timestamp.endOfPassWriteIndex !== null) {
          submitU32(timestamp.endOfPassWriteIndex, 'endOfPassWriteIndex');
        }
        if (timestamp.querySet !== null) {
          // The wrapper intentionally records any branded wrapper here and
          // carries a logical validation error for a non-query-set brand.
          ref(timestamp.querySet, 'timestampWrites.querySet');
        }
      }
      return;
    }
    case 'GPUCommandEncoder.beginRenderPass': {
      if (!record) throw new TypeError('beginRenderPass arguments are missing');
      exactKeys(record, ['label', 'colorAttachments'], [], spec.operationName);
      submitString(record.label, `${spec.operationName}.label`);
      if (!Array.isArray(record.colorAttachments) ||
          record.colorAttachments.length > maximum) {
        throw new TypeError('beginRenderPass color attachments are not bounded');
      }
      record.colorAttachments.forEach((attachment, index) => {
        if (attachment === null) return;
        const row = submitRecord(attachment, `colorAttachments[${index}]`);
        exactKeys(row, ['view', 'loadOp', 'storeOp'], [
          'resolveTarget', 'clearValue', 'depthSlice',
        ], `colorAttachments[${index}]`);
        ref(row.view, `colorAttachments[${index}].view`, 'GPUTextureView');
        if (row.resolveTarget !== undefined) {
          ref(row.resolveTarget, `colorAttachments[${index}].resolveTarget`, 'GPUTextureView');
        }
        if (row.loadOp !== 'load' && row.loadOp !== 'clear') {
          throw new TypeError('Invalid render-pass loadOp');
        }
        if (row.storeOp !== 'store' && row.storeOp !== 'discard') {
          throw new TypeError('Invalid render-pass storeOp');
        }
        if (row.clearValue !== undefined) {
          const color = submitRecord(row.clearValue, 'clearValue');
          exactKeys(color, ['r', 'g', 'b', 'a'], [], 'clearValue');
          for (const channel of ['r', 'g', 'b', 'a'] as const) {
            if (typeof color[channel] !== 'number' || !Number.isFinite(color[channel])) {
              throw new TypeError(`clearValue.${channel} must be finite`);
            }
          }
        }
        if (row.depthSlice !== undefined) submitU32(row.depthSlice, 'depthSlice');
      });
      return;
    }
    case 'GPUCommandEncoder.clearBuffer':
      if (!record) throw new TypeError('clearBuffer arguments are missing');
      exactKeys(record, ['buffer', 'offset', 'size'], [], spec.operationName);
      ref(record.buffer, 'clearBuffer.buffer', 'GPUBuffer');
      submitU64(record.offset, 'clearBuffer.offset');
      optionalU64(record.size, 'clearBuffer.size');
      return;
    case 'GPUCommandEncoder.copyBufferToBuffer':
      if (!record) throw new TypeError('copyBufferToBuffer arguments are missing');
      exactKeys(record, [
        'source', 'sourceOffset', 'destination', 'destinationOffset', 'size', 'overload',
      ], [], spec.operationName);
      ref(record.source, 'copyBufferToBuffer.source', 'GPUBuffer');
      ref(record.destination, 'copyBufferToBuffer.destination', 'GPUBuffer');
      submitU64(record.sourceOffset, 'copyBufferToBuffer.sourceOffset');
      submitU64(record.destinationOffset, 'copyBufferToBuffer.destinationOffset');
      optionalU64(record.size, 'copyBufferToBuffer.size');
      if (record.overload !== 'short' && record.overload !== 'full') {
        throw new TypeError('copyBufferToBuffer overload is invalid');
      }
      return;
    case 'GPUCommandEncoder.copyTextureToTexture': {
      if (!record) throw new TypeError('copyTextureToTexture arguments are missing');
      exactKeys(record, ['source', 'destination', 'copySize'], [], spec.operationName);
      for (const name of ['source', 'destination'] as const) {
        const side = submitRecord(record[name], `copyTextureToTexture.${name}`);
        exactKeys(side, ['aspect', 'mipLevel', 'origin', 'texture'], [], name);
        if (side.aspect !== 'all' && side.aspect !== 'stencil-only' &&
            side.aspect !== 'depth-only') throw new TypeError('Invalid texture aspect');
        submitU32(side.mipLevel, `${name}.mipLevel`);
        ref(side.texture, `${name}.texture`, 'GPUTexture');
        const origin = submitRecord(side.origin, `${name}.origin`);
        exactKeys(origin, ['x', 'y', 'z'], [], `${name}.origin`);
        for (const axis of ['x', 'y', 'z'] as const) submitU32(origin[axis], `${name}.${axis}`);
      }
      const extent = submitRecord(record.copySize, 'copyTextureToTexture.copySize');
      exactKeys(extent, ['width', 'height', 'depthOrArrayLayers'], [], 'copySize');
      submitU32(extent.width, 'copySize.width');
      submitU32(extent.height, 'copySize.height');
      submitU32(extent.depthOrArrayLayers, 'copySize.depthOrArrayLayers');
      return;
    }
    case 'GPUComputePassEncoder.setPipeline':
      if (!record) throw new TypeError('compute setPipeline arguments are missing');
      exactKeys(record, ['pipeline'], [], spec.operationName);
      // The staged wrapper records an arbitrary branded wrapper and marks a
      // non-compute pipeline as a device-timeline validation error.
      ref(record.pipeline, 'compute setPipeline.pipeline');
      return;
    case 'GPUComputePassEncoder.setBindGroup':
    case 'GPURenderPassEncoder.setBindGroup':
      bindGroupArguments();
      return;
    case 'GPUComputePassEncoder.dispatchWorkgroups':
      if (!record) throw new TypeError('dispatchWorkgroups arguments are missing');
      exactKeys(record, [
        'workgroupCountX', 'workgroupCountY', 'workgroupCountZ',
      ], [], spec.operationName);
      submitU32(record.workgroupCountX, 'workgroupCountX');
      submitU32(record.workgroupCountY, 'workgroupCountY');
      submitU32(record.workgroupCountZ, 'workgroupCountZ');
      return;
    case 'GPUComputePassEncoder.end':
      if (!record) throw new TypeError('compute end arguments are missing');
      exactKeys(record, ['usedBindGroups'], [], spec.operationName);
      validateReferenceSequence(
        record.usedBindGroups,
        'compute end usedBindGroups',
        'GPUBindGroup',
        maximum,
      );
      return;
    case 'GPURenderPassEncoder.setPipeline':
      ref(value, 'render setPipeline.pipeline', 'GPURenderPipeline');
      return;
    case 'GPURenderPassEncoder.setVertexBuffer':
      if (!record) throw new TypeError('setVertexBuffer arguments are missing');
      exactKeys(record, ['slot', 'buffer', 'offset', 'size'], [], spec.operationName);
      submitU32(record.slot, 'setVertexBuffer.slot');
      if (record.buffer !== null) ref(record.buffer, 'setVertexBuffer.buffer', 'GPUBuffer');
      submitU64(record.offset, 'setVertexBuffer.offset');
      optionalU64(record.size, 'setVertexBuffer.size');
      return;
    case 'GPURenderPassEncoder.draw':
      if (!Array.isArray(value) || value.length !== 4) {
        throw new TypeError('draw arguments must contain four u32 values');
      }
      value.forEach((entry, index) => submitU32(entry, `draw[${index}]`));
      return;
    case 'GPUCommandEncoder.finish':
      if (!record) throw new TypeError('finish arguments are missing');
      exactKeys(record, ['descriptor', 'usedBindGroups'], [], spec.operationName);
      {
        const descriptor = submitRecord(record.descriptor, 'finish.descriptor');
        exactKeys(descriptor, ['label'], [], 'finish.descriptor');
        submitString(descriptor.label, 'finish.descriptor.label');
      }
      validateReferenceSequence(
        record.usedBindGroups,
        'finish.usedBindGroups',
        'GPUBindGroup',
        maximum,
      );
      return;
  }
}

function hexDigestBytes(value: string, label: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function constantTimeBytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

interface ValidatedQueueSubmitRecord {
  readonly source: Readonly<Record<string, unknown>>;
  readonly spec: QueueSubmitRecordSpec;
  readonly operationInstanceId: string;
  readonly deviceIngressOrdinal: string;
  readonly capturedScopeId: string;
  readonly receiver: ProductionGpuServiceEncodingInput['receiver'];
  readonly commandEncoder: ProductionGpuServiceEncodingInput['receiver'] | null;
  readonly pass: ProductionGpuServiceEncodingInput['receiver'] | null;
  readonly target: ProductionGpuServiceEncodingInput['receiver'] | null;
  readonly argumentBody: unknown;
  readonly logicalError: Readonly<{ name: string; message: string }> | null;
}

function compareU64(left: string, right: string): number {
  parseU64Decimal(left);
  parseU64Decimal(right);
  return left.length - right.length || (left < right ? -1 : left > right ? 1 : 0);
}

function queueSubmitLogicalError(
  value: unknown,
  label: string,
): Readonly<{ name: string; message: string }> | null {
  if (value === null || value === undefined) return null;
  const record = submitRecord(value, label);
  exactKeys(record, ['name', 'message'], [], label);
  if (
    record.name !== 'GPUValidationError' &&
    record.name !== 'GPUOutOfMemoryError' &&
    record.name !== 'GPUInternalError'
  ) {
    throw new TypeError(`${label}.name is not a closed WebGPU error kind`);
  }
  const message = submitString(record.message, `${label}.message`);
  if (encodeUtf8(message).byteLength > QUEUE_SUBMIT_LOGICAL_ERROR_MAX_BYTES) {
    throw new TypeError(`${label}.message exceeds its reviewed byte bound`);
  }
  return Object.freeze({ name: record.name, message });
}

function validateQueueSubmitRecord(
  value: unknown,
  specs: ReadonlyMap<string, QueueSubmitRecordSpec>,
  device: ProductionGpuServiceEncodingInput['receiver'],
  maximum: number,
): ValidatedQueueSubmitRecord {
  const source = submitRecord(value, 'GPUQueue.submit record');
  exactKeys(source, [
    'recordIdentityClass',
    'operationId',
    'operationName',
    'operationIdentitySha256',
    'operationInstanceId',
    'deviceIngressOrdinal',
    'capturedScopeId',
    'receiverRef',
    'commandEncoderRef',
    'passRef',
    'wrapperAllocatedTargetRef',
    'argumentBody',
    'logicalError',
  ], [], 'GPUQueue.submit record');
  if (typeof source.operationName !== 'string') {
    throw new TypeError('GPUQueue.submit record operation name is missing');
  }
  const spec = specs.get(source.operationName);
  if (
    !spec ||
    source.recordIdentityClass !== spec.identityClass ||
    source.operationId !== spec.operationId ||
    source.operationIdentitySha256 !== spec.operationIdentitySha256
  ) {
    throw new TypeError('GPUQueue.submit record operation provenance is invalid');
  }
  if (typeof source.operationInstanceId !== 'string' ||
      typeof source.deviceIngressOrdinal !== 'string' ||
      typeof source.capturedScopeId !== 'string') {
    throw new TypeError('GPUQueue.submit record ordinals are not canonical u64 strings');
  }
  const operationInstanceId = positiveIdentity(
    source.operationInstanceId,
    'GPUQueue.submit record operationInstanceId',
  );
  const deviceIngressOrdinal = positiveIdentity(
    source.deviceIngressOrdinal,
    'GPUQueue.submit record deviceIngressOrdinal',
  );
  parseU64Decimal(operationInstanceId);
  parseU64Decimal(deviceIngressOrdinal);
  parseU64Decimal(source.capturedScopeId);
  const receiver = submitReference(source.receiverRef, 'record.receiverRef');
  if (!sameDeviceReference(receiver, device)) {
    throw new TypeError('GPUQueue.submit record receiver has foreign device provenance');
  }
  const commandEncoder = submitOptionalReference(
    source.commandEncoderRef,
    'record.commandEncoderRef',
    device,
    'GPUCommandEncoder',
  );
  const pass = submitOptionalReference(
    source.passRef,
    'record.passRef',
    device,
  );
  const target = submitOptionalReference(
    source.wrapperAllocatedTargetRef,
    'record.wrapperAllocatedTargetRef',
    device,
  );
  const requireEncoderReceiver = (
    allocatedPassKind?: 'GPUComputePassEncoder' | 'GPURenderPassEncoder',
  ) => {
    const passProjectionIsValid = allocatedPassKind === undefined
      ? pass === null
      : pass?.kind === allocatedPassKind && target !== null &&
        sameReference(pass, target);
    if (receiver.kind !== 'GPUCommandEncoder' || !commandEncoder ||
        !sameReference(receiver, commandEncoder) || !passProjectionIsValid) {
      throw new TypeError(`${spec.operationName} encoder provenance is invalid`);
    }
  };
  const requirePassReceiver = (kind: 'GPUComputePassEncoder' | 'GPURenderPassEncoder') => {
    if (receiver.kind !== kind || pass === null || pass.kind !== kind ||
        !sameReference(receiver, pass) || commandEncoder === null || target !== null) {
      throw new TypeError(`${spec.operationName} pass provenance is invalid`);
    }
  };
  switch (spec.operationName) {
    case 'GPUCanvasContext.getCurrentTexture':
      if (receiver.kind !== 'GPUCanvasContext' || commandEncoder !== null ||
          pass !== null || target?.kind !== 'GPUTexture') {
        throw new TypeError('Timeline-only canvas-current provenance is invalid');
      }
      {
        const argument = submitRecord(
          source.argumentBody,
          'GPUCanvasContext.getCurrentTexture arguments',
        );
        exactKeys(argument, ['currentOrigin'], [], 'GPUCanvasContext.getCurrentTexture');
        const origin = validateCanvasCurrentTextureOrigin(
          argument.currentOrigin,
          WEBGPU_PRODUCTION_PLAN.webIdlVocabulary,
          'GPUCanvasContext.getCurrentTexture currentOrigin',
        );
        if (
          !sameReference(origin.contextRef, receiver) ||
          !sameDeviceReference(origin.configuredDeviceRef, device) ||
          compareU64(origin.mintOperationInstanceId, operationInstanceId) > 0 ||
          compareU64(origin.mintDeviceIngressOrdinal, deviceIngressOrdinal) > 0
        ) {
          throw new TypeError(
            'Timeline-only canvas-current origin does not match its source-affine record',
          );
        }
        validateCanvasCurrentTextureOriginDigest(
          origin,
          target,
          WEBGPU_PRODUCTION_PLAN.webIdlVocabulary,
          'GPUCanvasContext.getCurrentTexture currentOrigin',
        );
      }
      break;
    case 'GPUCommandEncoder.beginComputePass':
      requireEncoderReceiver('GPUComputePassEncoder');
      if (target?.kind !== 'GPUComputePassEncoder') {
        throw new TypeError('beginComputePass target provenance is invalid');
      }
      break;
    case 'GPUCommandEncoder.beginRenderPass':
      requireEncoderReceiver('GPURenderPassEncoder');
      if (target?.kind !== 'GPURenderPassEncoder') {
        throw new TypeError('beginRenderPass target provenance is invalid');
      }
      break;
    case 'GPUCommandEncoder.finish':
      requireEncoderReceiver();
      if (target?.kind !== 'GPUCommandBuffer') {
        throw new TypeError('finish target provenance is invalid');
      }
      break;
    case 'GPUCommandEncoder.clearBuffer':
    case 'GPUCommandEncoder.copyBufferToBuffer':
    case 'GPUCommandEncoder.copyTextureToTexture':
      requireEncoderReceiver();
      if (target !== null) {
        throw new TypeError(`${spec.operationName} may not allocate a target`);
      }
      break;
    case 'GPUComputePassEncoder.setPipeline':
    case 'GPUComputePassEncoder.setBindGroup':
    case 'GPUComputePassEncoder.dispatchWorkgroups':
    case 'GPUComputePassEncoder.end':
      requirePassReceiver('GPUComputePassEncoder');
      break;
    case 'GPURenderPassEncoder.setPipeline':
    case 'GPURenderPassEncoder.setBindGroup':
    case 'GPURenderPassEncoder.setVertexBuffer':
    case 'GPURenderPassEncoder.draw':
    case 'GPURenderPassEncoder.end':
      requirePassReceiver('GPURenderPassEncoder');
      break;
  }
  validateQueueSubmitArgument(
    spec,
    source.argumentBody,
    device,
    maximum,
  );
  return Object.freeze({
    source,
    spec,
    operationInstanceId,
    deviceIngressOrdinal,
    capturedScopeId: source.capturedScopeId,
    receiver,
    commandEncoder,
    pass,
    target,
    argumentBody: source.argumentBody,
    logicalError: queueSubmitLogicalError(source.logicalError, 'record.logicalError'),
  });
}

function writeOptionalSubmitReference(
  writer: Writer,
  value: ProductionGpuServiceEncodingInput['receiver'] | null,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
): void {
  writer.u8(value === null ? 0 : 1);
  if (value !== null) writeReference(writer, value, objectKinds);
}

function readOptionalSubmitReference(
  reader: Reader,
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
): ProductionGpuServiceEncodingInput['receiver'] | null {
  const presence = reader.u8();
  if (presence !== 0 && presence !== 1) {
    throw new TypeError('Invalid queue-submit optional-reference tag');
  }
  return presence === 0 ? null : readReference(reader, objectKindsByTag);
}

function queueSubmitLogicalErrorTag(name: string): number {
  if (name === 'GPUValidationError') return 1;
  if (name === 'GPUOutOfMemoryError') return 2;
  if (name === 'GPUInternalError') return 3;
  throw new TypeError('Unknown queue-submit logical error kind');
}

function writeQueueSubmitLogicalError(
  writer: Writer,
  value: Readonly<{ name: string; message: string }> | null,
): void {
  if (value === null) {
    writer.u8(0);
    return;
  }
  writer.u8(queueSubmitLogicalErrorTag(value.name));
  writer.string(value.message, QUEUE_SUBMIT_LOGICAL_ERROR_MAX_BYTES);
}

function readQueueSubmitLogicalError(
  reader: Reader,
): Readonly<{ name: string; message: string }> | null {
  const tag = reader.u8();
  if (tag === 0) return null;
  const names = [
    '',
    'GPUValidationError',
    'GPUOutOfMemoryError',
    'GPUInternalError',
  ] as const;
  const name = names[tag];
  if (!name) throw new TypeError('Unknown queue-submit logical error tag');
  return Object.freeze({
    name,
    message: reader.string(QUEUE_SUBMIT_LOGICAL_ERROR_MAX_BYTES),
  });
}

function encodeQueueSubmitRecord(
  record: ValidatedQueueSubmitRecord,
  maximum: number,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
  layout: ExecutableWebGpuCodecManifest['layout'],
): Uint8Array {
  const writer = new Writer(maximum);
  writer.u8(record.spec.identityClass === 'active-route' ? 1 : 2);
  writer.u8(record.spec.tag);
  writer.u16(0);
  writer.u32(record.spec.operationId);
  writer.raw(record.spec.operationIdentitySha256 === null
    ? new Uint8Array(32)
    : hexDigestBytes(record.spec.operationIdentitySha256, 'record identity'));
  writer.u64(record.operationInstanceId);
  writer.u64(record.deviceIngressOrdinal);
  writer.u64(record.capturedScopeId);
  writeReference(writer, record.receiver, objectKinds);
  writeOptionalSubmitReference(writer, record.commandEncoder, objectKinds);
  writeOptionalSubmitReference(writer, record.pass, objectKinds);
  writeOptionalSubmitReference(writer, record.target, objectKinds);
  writeQueueSubmitLogicalError(writer, record.logicalError);
  writer.value(record.argumentBody, layout);
  return writer.finish();
}

function readQueueSubmitRecord(
  bytes: Uint8Array,
  specs: ReadonlyMap<number, QueueSubmitRecordSpec>,
  device: ProductionGpuServiceEncodingInput['receiver'],
  maximum: number,
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
  layout: ExecutableWebGpuCodecManifest['layout'],
): Readonly<Record<string, unknown>> {
  const reader = new Reader(bytes, maximum);
  const identityClassTag = reader.u8();
  const spec = specs.get(reader.u8());
  if (!spec || (identityClassTag !== 1 && identityClassTag !== 2) ||
      (identityClassTag === 1) !== (spec.identityClass === 'active-route')) {
    throw new TypeError('Queue-submit record identity class/tag mismatch');
  }
  if (reader.u16() !== 0 || reader.u32() !== spec.operationId) {
    throw new TypeError('Queue-submit record identity header mismatch');
  }
  const identityDigest = reader.raw(32);
  const expectedDigest = spec.operationIdentitySha256 === null
    ? new Uint8Array(32)
    : hexDigestBytes(spec.operationIdentitySha256, 'record identity');
  if (!constantTimeBytesEqual(identityDigest, expectedDigest)) {
    throw new TypeError('Queue-submit record identity digest mismatch');
  }
  const operationInstanceId = reader.u64();
  const deviceIngressOrdinal = reader.u64();
  const capturedScopeId = reader.u64();
  const receiverRef = readReference(reader, objectKindsByTag);
  const commandEncoderRef = readOptionalSubmitReference(reader, objectKindsByTag);
  const passRef = readOptionalSubmitReference(reader, objectKindsByTag);
  const wrapperAllocatedTargetRef = readOptionalSubmitReference(
    reader,
    objectKindsByTag,
  );
  const logicalError = readQueueSubmitLogicalError(reader);
  const argumentBody = reader.value(layout);
  reader.done();
  const decoded = Object.freeze({
    recordIdentityClass: spec.identityClass,
    operationId: spec.operationId,
    operationName: spec.operationName,
    operationIdentitySha256: spec.operationIdentitySha256,
    operationInstanceId,
    deviceIngressOrdinal,
    capturedScopeId,
    receiverRef,
    commandEncoderRef,
    passRef,
    wrapperAllocatedTargetRef,
    argumentBody,
    logicalError,
  });
  validateQueueSubmitRecord(decoded, new Map([[spec.operationName, spec]]), device, maximum);
  return decoded;
}

interface QueueSubmitEncodedProgram {
  readonly commandBuffer: ProductionGpuServiceEncodingInput['receiver'];
  readonly invalid: boolean;
  readonly finishRecordPosition: number;
  readonly recordIndices: readonly number[];
  readonly digest: Uint8Array;
}

interface QueueSubmitEncodedBody {
  readonly recordBytes: readonly Uint8Array[];
  readonly pendingTimelineIndices: readonly number[];
  readonly programs: readonly QueueSubmitEncodedProgram[];
  readonly wrapperValidationError: Readonly<{ name: string; message: string }> | null;
}

function queueSubmitProgramDigest(
  commandBuffer: ProductionGpuServiceEncodingInput['receiver'],
  invalid: boolean,
  finishRecordPosition: number,
  recordIndices: readonly number[],
  recordBytes: readonly Uint8Array[],
  maximum: number,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
): Uint8Array {
  const writer = new Writer(maximum);
  writer.raw(encodeUtf8(QUEUE_SUBMIT_PROGRAM_DIGEST_DOMAIN));
  writeReference(writer, commandBuffer, objectKinds);
  writer.u8(invalid ? 1 : 0);
  writer.u32(finishRecordPosition);
  writer.u32(recordIndices.length);
  for (const recordIndex of recordIndices) {
    const bytes = recordBytes[recordIndex];
    if (!bytes) throw new TypeError('Queue-submit program index is out of range');
    writer.u32(bytes.byteLength);
    writer.raw(bytes);
  }
  return sha256Bytes(writer.finish());
}

function validateQueueSubmitRequestFields(
  input: ProductionGpuServiceEncodingInput,
  specs: Readonly<{
    byName: ReadonlyMap<string, QueueSubmitRecordSpec>;
    byTag: ReadonlyMap<number, QueueSubmitRecordSpec>;
  }>,
  maximum: number,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
  layout: ExecutableWebGpuCodecManifest['layout'],
): QueueSubmitEncodedBody {
  if (
    input.receiver.kind !== 'GPUQueue' ||
    input.target !== undefined ||
    input.adapterOrdinal !== '0'
  ) {
    throw new TypeError('GPUQueue.submit violates its receiver/target projection');
  }
  for (const [name, value] of [
    ['objectId', input.receiver.objectId],
    ['objectGeneration', input.receiver.objectGeneration],
    ['logicalDeviceId', input.receiver.logicalDeviceId],
    ['logicalDeviceGeneration', input.receiver.logicalDeviceGeneration],
    ['providerGeneration', input.receiver.providerGeneration],
    ['deviceIngressOrdinal', input.deviceIngressOrdinal],
    ['queueIngressOrdinal', input.queueIngressOrdinal],
  ] as const) positiveIdentity(value, `GPUQueue.submit ${name}`);
  parseU64Decimal(input.capturedScopeId);
  if (!Array.isArray(input.sealedLocalTimeline) ||
      input.sealedLocalTimeline.length > QUEUE_SUBMIT_PROGRAM_RECORD_MAX_COUNT) {
    throw new TypeError('GPUQueue.submit pending timeline exceeds its bound');
  }
  const converted = submitRecord(
    input.convertedArguments,
    'GPUQueue.submit converted arguments',
  );
  exactKeys(converted, ['commandBuffers'], ['wrapperValidationError'],
    'GPUQueue.submit converted arguments');
  if (!Array.isArray(converted.commandBuffers) ||
      converted.commandBuffers.length > QUEUE_SUBMIT_PROGRAM_MAX_COUNT) {
    throw new TypeError('GPUQueue.submit command buffer sequence exceeds its bound');
  }
  const wrapperValidationError = queueSubmitLogicalError(
    converted.wrapperValidationError,
    'GPUQueue.submit wrapperValidationError',
  );
  const allSources = new Set<object>();
  for (const record of input.sealedLocalTimeline) {
    if (typeof record !== 'object' || record === null || Array.isArray(record)) {
      throw new TypeError('GPUQueue.submit pending timeline contains a non-record');
    }
    allSources.add(record);
  }
  let aggregateProgramRecordCount = 0;
  const sourcePrograms = converted.commandBuffers.map((entry, programIndex) => {
    const program = submitRecord(entry, `GPUQueue.submit program[${programIndex}]`);
    exactKeys(program, ['commandBuffer', 'invalid', 'records'], [],
      `GPUQueue.submit program[${programIndex}]`);
    const commandBuffer = submitReference(
      program.commandBuffer,
      `GPUQueue.submit program[${programIndex}].commandBuffer`,
      'GPUCommandBuffer',
    );
    if (!sameDeviceReference(commandBuffer, input.receiver)) {
      throw new TypeError('GPUQueue.submit command buffer has foreign device provenance');
    }
    if (typeof program.invalid !== 'boolean' || !Array.isArray(program.records) ||
        program.records.length > QUEUE_SUBMIT_PROGRAM_RECORD_MAX_COUNT) {
      throw new TypeError('GPUQueue.submit command program has an invalid shape');
    }
    if (
      program.records.length >
        QUEUE_SUBMIT_PROGRAM_RECORD_MAX_COUNT - aggregateProgramRecordCount
    ) {
      throw new TypeError('GPUQueue.submit aggregate command records exceed their bound');
    }
    aggregateProgramRecordCount += program.records.length;
    const seen = new Set<object>();
    for (const record of program.records) {
      if (typeof record !== 'object' || record === null || Array.isArray(record)) {
        throw new TypeError('GPUQueue.submit command program contains a non-record');
      }
      if (seen.has(record)) {
        throw new TypeError('GPUQueue.submit command program reuses one record index');
      }
      seen.add(record);
      allSources.add(record);
    }
    return Object.freeze({
      commandBuffer,
      invalid: program.invalid,
      records: program.records as readonly object[],
    });
  });
  if (allSources.size > QUEUE_SUBMIT_RECORD_TABLE_MAX_COUNT) {
    throw new TypeError('GPUQueue.submit unique record table exceeds its bound');
  }
  const validated = [...allSources].map((source) =>
    validateQueueSubmitRecord(source, specs.byName, input.receiver, maximum));
  validated.sort((left, right) =>
    compareU64(left.deviceIngressOrdinal, right.deviceIngressOrdinal));
  const operationInstances = new Set<string>();
  const ingressOrdinals = new Set<string>();
  for (const record of validated) {
    if (operationInstances.has(record.operationInstanceId) ||
        ingressOrdinals.has(record.deviceIngressOrdinal) ||
        compareU64(record.deviceIngressOrdinal, input.deviceIngressOrdinal) >= 0) {
      throw new TypeError(
        'GPUQueue.submit record identities must be unique and precede submit ingress',
      );
    }
    operationInstances.add(record.operationInstanceId);
    ingressOrdinals.add(record.deviceIngressOrdinal);
  }
  const sourceToIndex = new Map<object, number>(
    validated.map((record, index) => [record.source, index]),
  );
  const pendingTimelineIndices = input.sealedLocalTimeline.map((record) =>
    sourceToIndex.get(record as object)!);
  for (let index = 1; index < pendingTimelineIndices.length; index += 1) {
    if (pendingTimelineIndices[index - 1] >= pendingTimelineIndices[index]) {
      throw new TypeError('GPUQueue.submit pending timeline indices are not ordered');
    }
  }
  const recordBytes = validated.map((record) =>
    encodeQueueSubmitRecord(record, maximum, objectKinds, layout));
  const programs = sourcePrograms.map((program, programIndex) => {
    const recordIndices = program.records.map((record) => sourceToIndex.get(record)!);
    for (let index = 1; index < recordIndices.length; index += 1) {
      if (recordIndices[index - 1] >= recordIndices[index]) {
        throw new TypeError(`GPUQueue.submit program[${programIndex}] indices are not ordered`);
      }
    }
    let finishRecordPosition = -1;
    for (let index = 0; index < recordIndices.length; index += 1) {
      const record = validated[recordIndices[index]];
      if (record.spec.operationName === 'GPUCommandEncoder.finish' &&
          record.target !== null && sameReference(record.target, program.commandBuffer)) {
        if (finishRecordPosition !== -1) {
          throw new TypeError('GPUQueue.submit program has duplicate matching finish records');
        }
        finishRecordPosition = index;
      }
      if (!record.spec.commandRecord) {
        throw new TypeError('GPUQueue.submit program references a timeline-only record');
      }
    }
    if (finishRecordPosition < 0) {
      throw new TypeError('GPUQueue.submit program lacks its exact finish target');
    }
    return Object.freeze({
      commandBuffer: program.commandBuffer,
      invalid: program.invalid,
      finishRecordPosition,
      recordIndices: Object.freeze(recordIndices),
      digest: queueSubmitProgramDigest(
        program.commandBuffer,
        program.invalid,
        finishRecordPosition,
        recordIndices,
        recordBytes,
        maximum,
        objectKinds,
      ),
    });
  });
  return Object.freeze({
    recordBytes: Object.freeze(recordBytes),
    pendingTimelineIndices: Object.freeze(pendingTimelineIndices),
    programs: Object.freeze(programs),
    wrapperValidationError,
  });
}

function writeQueueSubmitBody(
  writer: Writer,
  body: QueueSubmitEncodedBody,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
): void {
  writer.u32(body.recordBytes.length);
  for (const record of body.recordBytes) {
    writer.u32(record.byteLength);
    writer.raw(record);
  }
  writer.u32(body.pendingTimelineIndices.length);
  for (const recordIndex of body.pendingTimelineIndices) writer.u32(recordIndex);
  writer.u32(body.programs.length);
  for (const program of body.programs) {
    writeReference(writer, program.commandBuffer, objectKinds);
    writer.u8(program.invalid ? 1 : 0);
    writer.u32(program.finishRecordPosition);
    writer.u32(program.recordIndices.length);
    for (const recordIndex of program.recordIndices) writer.u32(recordIndex);
    writer.raw(program.digest);
  }
  writeQueueSubmitLogicalError(writer, body.wrapperValidationError);
}

function readQueueSubmitBody(
  reader: Reader,
  specs: Readonly<{
    byName: ReadonlyMap<string, QueueSubmitRecordSpec>;
    byTag: ReadonlyMap<number, QueueSubmitRecordSpec>;
  }>,
  device: ProductionGpuServiceEncodingInput['receiver'],
  submitDeviceIngressOrdinal: string,
  maximum: number,
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
  layout: ExecutableWebGpuCodecManifest['layout'],
): Readonly<{
  recordTable: readonly Readonly<Record<string, unknown>>[];
  pendingTimeline: readonly Readonly<Record<string, unknown>>[];
  commandBuffers: readonly Readonly<Record<string, unknown>>[];
  wrapperValidationError: Readonly<{ name: string; message: string }> | null;
}> {
  const recordCount = reader.u32();
  if (recordCount > QUEUE_SUBMIT_RECORD_TABLE_MAX_COUNT) {
    throw new TypeError('GPUQueue.submit record table exceeds its bound');
  }
  const rawRecords: Uint8Array[] = [];
  const recordTable: Readonly<Record<string, unknown>>[] = [];
  const operationInstances = new Set<string>();
  const ingressOrdinals = new Set<string>();
  for (let index = 0; index < recordCount; index += 1) {
    const length = reader.u32();
    if (length === 0 || length > maximum) {
      throw new TypeError('GPUQueue.submit record length is invalid');
    }
    const bytes = reader.raw(length);
    const record = readQueueSubmitRecord(
      bytes,
      specs.byTag,
      device,
      maximum,
      objectKindsByTag,
      layout,
    );
    const operationInstanceId = record.operationInstanceId as string;
    const ingress = record.deviceIngressOrdinal as string;
    if (
      operationInstances.has(operationInstanceId) ||
      ingressOrdinals.has(ingress) ||
      compareU64(ingress, submitDeviceIngressOrdinal) >= 0 ||
      (index > 0 && compareU64(
        recordTable[index - 1].deviceIngressOrdinal as string,
        ingress,
      ) >= 0)
    ) {
      throw new TypeError('GPUQueue.submit record table identities/order are invalid');
    }
    operationInstances.add(operationInstanceId);
    ingressOrdinals.add(ingress);
    rawRecords.push(bytes);
    recordTable.push(record);
  }
  const readIndices = (count: number, label: string): readonly number[] => {
    if (count > QUEUE_SUBMIT_PROGRAM_RECORD_MAX_COUNT) {
      throw new TypeError(`${label} exceeds its bound`);
    }
    const indices: number[] = [];
    for (let index = 0; index < count; index += 1) {
      const recordIndex = reader.u32();
      if (recordIndex >= recordCount ||
          (index > 0 && indices[index - 1] >= recordIndex)) {
        throw new TypeError(`${label} indices are out of range, reused, or unordered`);
      }
      indices.push(recordIndex);
    }
    return Object.freeze(indices);
  };
  const pendingIndices = readIndices(reader.u32(), 'GPUQueue.submit pending timeline');
  const referencedRecordIndices = new Set(pendingIndices);
  const programCount = reader.u32();
  if (programCount > QUEUE_SUBMIT_PROGRAM_MAX_COUNT) {
    throw new TypeError('GPUQueue.submit command buffer count exceeds its bound');
  }
  const commandBuffers: Readonly<Record<string, unknown>>[] = [];
  let aggregateProgramRecordCount = 0;
  for (let programIndex = 0; programIndex < programCount; programIndex += 1) {
    const commandBuffer = readReference(reader, objectKindsByTag);
    if (commandBuffer.kind !== 'GPUCommandBuffer' ||
        !sameDeviceReference(commandBuffer, device)) {
      throw new TypeError('GPUQueue.submit command buffer provenance is invalid');
    }
    const invalidTag = reader.u8();
    if (invalidTag !== 0 && invalidTag !== 1) {
      throw new TypeError('GPUQueue.submit command buffer invalid tag is not boolean');
    }
    const finishRecordPosition = reader.u32();
    const recordIndices = readIndices(
      reader.u32(),
      `GPUQueue.submit program[${programIndex}]`,
    );
    if (
      recordIndices.length >
        QUEUE_SUBMIT_PROGRAM_RECORD_MAX_COUNT - aggregateProgramRecordCount
    ) {
      throw new TypeError('GPUQueue.submit aggregate command records exceed their bound');
    }
    aggregateProgramRecordCount += recordIndices.length;
    for (const recordIndex of recordIndices) referencedRecordIndices.add(recordIndex);
    if (finishRecordPosition >= recordIndices.length) {
      throw new TypeError('GPUQueue.submit finish position is out of range');
    }
    for (const recordIndex of recordIndices) {
      const spec = specs.byName.get(recordTable[recordIndex].operationName as string);
      if (!spec?.commandRecord) {
        throw new TypeError('GPUQueue.submit program references a timeline-only record');
      }
    }
    const finish = recordTable[recordIndices[finishRecordPosition]];
    if (
      finish.operationName !== 'GPUCommandEncoder.finish' ||
      !sameReference(
        finish.wrapperAllocatedTargetRef as ProductionGpuServiceEncodingInput['receiver'],
        commandBuffer,
      )
    ) {
      throw new TypeError('GPUQueue.submit finish target/position mismatch');
    }
    const digest = reader.raw(32);
    const expectedDigest = queueSubmitProgramDigest(
      commandBuffer,
      invalidTag === 1,
      finishRecordPosition,
      recordIndices,
      rawRecords,
      maximum,
      objectKinds,
    );
    if (!constantTimeBytesEqual(digest, expectedDigest)) {
      throw new TypeError('GPUQueue.submit command program digest mismatch');
    }
    commandBuffers.push(Object.freeze({
      commandBuffer,
      invalid: invalidTag === 1,
      records: Object.freeze(recordIndices.map((index) => recordTable[index])),
      recordIndices,
      finishRecordPosition,
      commandProgramDigest: bytesHex(digest),
    }));
  }
  const wrapperValidationError = readQueueSubmitLogicalError(reader);
  if (referencedRecordIndices.size !== recordCount) {
    throw new TypeError('GPUQueue.submit record table is not the exact index union');
  }
  return Object.freeze({
    recordTable: Object.freeze(recordTable),
    pendingTimeline: Object.freeze(pendingIndices.map((index) => recordTable[index])),
    commandBuffers: Object.freeze(commandBuffers),
    wrapperValidationError,
  });
}

interface RequestAdapterReferenceLike {
  readonly kind?: unknown;
  readonly objectId?: unknown;
  readonly objectGeneration?: unknown;
  readonly logicalDeviceId?: unknown;
  readonly logicalDeviceGeneration?: unknown;
  readonly providerGeneration?: unknown;
}

function validateRequestAdapterOptionsForService(value: unknown): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      'GPU.requestAdapter converted arguments must be a closed dictionary',
    );
  }
  const source = value as Readonly<Record<PropertyKey, unknown>>;
  const keys = Reflect.ownKeys(source);
  const allowed = new Set<PropertyKey>([
    'featureLevel',
    'forceFallbackAdapter',
    'powerPreference',
    'xrCompatible',
  ]);
  if (
    keys.some((key) => !allowed.has(key)) ||
    !Object.prototype.hasOwnProperty.call(source, 'featureLevel') ||
    !Object.prototype.hasOwnProperty.call(source, 'forceFallbackAdapter') ||
    !Object.prototype.hasOwnProperty.call(source, 'xrCompatible')
  ) {
    throw new TypeError(
      'GPU.requestAdapter converted arguments violate the closed dictionary',
    );
  }
  if (source.featureLevel !== 'core' && source.featureLevel !== 'compatibility') {
    throw new TypeError(
      'GPU.requestAdapter featureLevel must be core or compatibility before encoding',
    );
  }
  if (
    typeof source.forceFallbackAdapter !== 'boolean' ||
    typeof source.xrCompatible !== 'boolean'
  ) {
    throw new TypeError(
      'GPU.requestAdapter converted boolean fields have the wrong type',
    );
  }
  if (
    Object.prototype.hasOwnProperty.call(source, 'powerPreference') &&
    source.powerPreference !== 'low-power' &&
    source.powerPreference !== 'high-performance'
  ) {
    throw new TypeError(
      'GPU.requestAdapter powerPreference has the wrong encoded value',
    );
  }
}

function validateRequestAdapterRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  capturedScopeId: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
): void {
  if (
    receiver.kind !== 'GPU' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string'
  ) {
    throw new TypeError('GPU.requestAdapter requires the typed GPU singleton');
  }
  positiveIdentity(receiver.objectId, 'GPU.requestAdapter receiver.objectId');
  positiveIdentity(
    receiver.objectGeneration,
    'GPU.requestAdapter receiver.objectGeneration',
  );
  if (
    receiver.logicalDeviceId !== '0' ||
    receiver.logicalDeviceGeneration !== '0' ||
    receiver.providerGeneration !== '0'
  ) {
    throw new TypeError(
      'GPU.requestAdapter receiver must carry zero device/provider provenance',
    );
  }
  if (target !== undefined && target !== null) {
    throw new TypeError('GPU.requestAdapter must not carry a target');
  }
  if (
    capturedScopeId !== '0' ||
    adapterOrdinal !== '0' ||
    deviceIngressOrdinal !== '0' ||
    queueIngressOrdinal !== '0'
  ) {
    throw new TypeError(
      'GPU.requestAdapter scope and ingress ordinals must be zero',
    );
  }
  if (!Array.isArray(sealedLocalTimeline) || sealedLocalTimeline.length !== 0) {
    throw new TypeError(
      'GPU.requestAdapter sealed local timeline must be exactly empty',
    );
  }
  validateRequestAdapterOptionsForService(convertedArguments);
}

function validateRequestDeviceDescriptorForService(
  value: unknown,
  sequenceMaximum: number,
  dictionaryMaximum: number,
): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      'GPUAdapter.requestDevice converted arguments must be a closed dictionary',
    );
  }
  const source = value as Readonly<Record<PropertyKey, unknown>>;
  const allowed = new Set<PropertyKey>([
    'label',
    'requiredFeatures',
    'requiredLimits',
    'defaultQueue',
  ]);
  if (
    Reflect.ownKeys(source).some((key) => !allowed.has(key)) ||
    [...allowed].some((key) => !Object.prototype.hasOwnProperty.call(source, key)) ||
    typeof source.label !== 'string' ||
    !Array.isArray(source.requiredFeatures) ||
    source.requiredFeatures.length > sequenceMaximum ||
    source.requiredFeatures.some((feature) => typeof feature !== 'string')
  ) {
    throw new TypeError(
      'GPUAdapter.requestDevice converted arguments violate the reviewed descriptor shape',
    );
  }
  const limits = source.requiredLimits;
  if (
    typeof limits !== 'object' || limits === null || Array.isArray(limits) ||
    Reflect.ownKeys(limits).some((key) => typeof key !== 'string') ||
    Reflect.ownKeys(limits).length > dictionaryMaximum ||
    Object.values(limits).some(
      (limit) =>
        typeof limit !== 'number' ||
        !Number.isSafeInteger(limit) ||
        limit < 0,
    )
  ) {
    throw new TypeError(
      'GPUAdapter.requestDevice requiredLimits violate the reviewed descriptor shape',
    );
  }
  const defaultQueue = source.defaultQueue;
  if (
    typeof defaultQueue !== 'object' ||
    defaultQueue === null ||
    Array.isArray(defaultQueue) ||
    Reflect.ownKeys(defaultQueue).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(defaultQueue, 'label') ||
    typeof (defaultQueue as Readonly<Record<string, unknown>>).label !== 'string'
  ) {
    throw new TypeError(
      'GPUAdapter.requestDevice defaultQueue violates the reviewed descriptor shape',
    );
  }
}

function validateRequestDeviceRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  capturedScopeId: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  dictionaryMaximum: number,
): void {
  if (
    receiver.kind !== 'GPUAdapter' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUAdapter.requestDevice requires an authenticated GPUAdapter receiver',
    );
  }
  positiveIdentity(receiver.objectId, 'GPUAdapter.requestDevice receiver.objectId');
  positiveIdentity(
    receiver.objectGeneration,
    'GPUAdapter.requestDevice receiver.objectGeneration',
  );
  positiveIdentity(
    receiver.providerGeneration,
    'GPUAdapter.requestDevice receiver.providerGeneration',
  );
  if (
    receiver.logicalDeviceId !== '0' ||
    receiver.logicalDeviceGeneration !== '0'
  ) {
    throw new TypeError(
      'GPUAdapter.requestDevice receiver must not carry an ingress device',
    );
  }
  if (target !== undefined && target !== null) {
    throw new TypeError('GPUAdapter.requestDevice must not carry a target');
  }
  positiveIdentity(String(adapterOrdinal), 'GPUAdapter.requestDevice adapterOrdinal');
  if (
    capturedScopeId !== '0' ||
    deviceIngressOrdinal !== '0' ||
    queueIngressOrdinal !== '0'
  ) {
    throw new TypeError(
      'GPUAdapter.requestDevice scope and device/queue ingress ordinals must be zero',
    );
  }
  if (!Array.isArray(sealedLocalTimeline) || sealedLocalTimeline.length !== 0) {
    throw new TypeError(
      'GPUAdapter.requestDevice sealed local timeline must be exactly empty',
    );
  }
  validateRequestDeviceDescriptorForService(
    convertedArguments,
    sequenceMaximum,
    dictionaryMaximum,
  );
}

function validateDeviceDestroyRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
): void {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.destroy requires an authenticated GPUDevice receiver',
    );
  }
  positiveIdentity(receiver.objectId, 'GPUDevice.destroy receiver.objectId');
  positiveIdentity(
    receiver.objectGeneration,
    'GPUDevice.destroy receiver.objectGeneration',
  );
  positiveIdentity(
    receiver.logicalDeviceId,
    'GPUDevice.destroy receiver.logicalDeviceId',
  );
  positiveIdentity(
    receiver.logicalDeviceGeneration,
    'GPUDevice.destroy receiver.logicalDeviceGeneration',
  );
  positiveIdentity(
    receiver.providerGeneration,
    'GPUDevice.destroy receiver.providerGeneration',
  );
  if (target !== undefined && target !== null) {
    throw new TypeError('GPUDevice.destroy must not carry a target');
  }
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUDevice.destroy adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUDevice.destroy deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.destroy sealed local timeline must be a bounded sequence',
    );
  }
  if (convertedArguments !== null) {
    throw new TypeError(
      'GPUDevice.destroy converted arguments must be exactly null',
    );
  }
}

function validateCreateCommandEncoderDescriptorForService(
  value: unknown,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(value, 'label') ||
    typeof (value as Readonly<Record<string, unknown>>).label !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createCommandEncoder converted arguments violate the reviewed descriptor shape',
    );
  }
}

function hasExactOwnProperties(
  value: Readonly<Record<string, unknown>>,
  names: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === names.length &&
    names.every((name) => Object.prototype.hasOwnProperty.call(value, name));
}

function isConvertedU32(value: unknown): value is number {
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    value < 0x1_0000_0000;
}

function isConvertedU64(value: unknown): value is number {
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= Number.MAX_SAFE_INTEGER;
}

function isPositiveCanonicalDecimalU64(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) {
    return false;
  }
  const maximum = '18446744073709551615';
  return value.length < maximum.length ||
    (value.length === maximum.length && value <= maximum);
}

function validateBindGroupFullReference(
  value: unknown,
  expectedKinds: readonly string[],
  label: string,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      [
        'kind',
        'objectId',
        'objectGeneration',
        'logicalDeviceId',
        'logicalDeviceGeneration',
        'providerGeneration',
      ],
    )
  ) {
    throw new TypeError(`${label} must be a full object reference`);
  }
  const reference = value as RequestAdapterReferenceLike;
  if (
    typeof reference.kind !== 'string' ||
    !expectedKinds.includes(reference.kind) ||
    typeof reference.objectId !== 'string' ||
    typeof reference.objectGeneration !== 'string' ||
    typeof reference.logicalDeviceId !== 'string' ||
    typeof reference.logicalDeviceGeneration !== 'string' ||
    typeof reference.providerGeneration !== 'string'
  ) {
    throw new TypeError(`${label} has an invalid object-reference shape`);
  }
  for (const [identity, field] of [
    [reference.objectId, 'objectId'],
    [reference.objectGeneration, 'objectGeneration'],
    [reference.logicalDeviceId, 'logicalDeviceId'],
    [reference.logicalDeviceGeneration, 'logicalDeviceGeneration'],
    [reference.providerGeneration, 'providerGeneration'],
  ] as const) {
    positiveIdentity(identity, `${label}.${field}`);
  }
}

function validateCreateBindGroupDescriptorForService(
  value: unknown,
  sequenceMaximum: number,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      ['label', 'entries', 'layout'],
    )
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroup converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  if (
    typeof descriptor.label !== 'string' ||
    !Array.isArray(descriptor.entries) ||
    descriptor.entries.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroup converted descriptor exceeds structural transport bounds',
    );
  }
  validateBindGroupFullReference(
    descriptor.layout,
    ['GPUBindGroupLayout'],
    'GPUDevice.createBindGroup layout',
  );
  descriptor.entries.forEach((entry, index) => {
    if (
      typeof entry !== 'object' ||
      entry === null ||
      Array.isArray(entry) ||
      !hasExactOwnProperties(
        entry as Readonly<Record<string, unknown>>,
        ['binding', 'resource'],
      )
    ) {
      throw new TypeError(
        `GPUDevice.createBindGroup entry ${index} must be a closed dictionary`,
      );
    }
    const row = entry as Readonly<Record<string, unknown>>;
    if (
      !isConvertedU32(row.binding) ||
      typeof row.resource !== 'object' ||
      row.resource === null ||
      Array.isArray(row.resource)
    ) {
      throw new TypeError(
        `GPUDevice.createBindGroup entry ${index} is not a canonical WebIDL dictionary`,
      );
    }
    const resource = row.resource as Readonly<Record<string, unknown>>;
    if (resource.resourceKind === 'GPUBufferBinding') {
      const names = Object.prototype.hasOwnProperty.call(resource, 'size')
        ? ['resourceKind', 'buffer', 'offset', 'size']
        : ['resourceKind', 'buffer', 'offset'];
      if (
        !hasExactOwnProperties(resource, names) ||
        !isConvertedU64(resource.offset) ||
        (Object.prototype.hasOwnProperty.call(resource, 'size') &&
          !isConvertedU64(resource.size))
      ) {
        throw new TypeError(
          `GPUDevice.createBindGroup buffer entry ${index} is not canonical`,
        );
      }
      validateBindGroupFullReference(
        resource.buffer,
        ['GPUBuffer'],
        `GPUDevice.createBindGroup entry ${index}.buffer`,
      );
      return;
    }
    const resourceKinds = [
      'GPUSampler',
      'GPUTextureView',
      'GPUBuffer',
      'GPUTexture',
      'GPUExternalTexture',
    ];
    if (
      typeof resource.resourceKind !== 'string' ||
      !resourceKinds.includes(resource.resourceKind) ||
      !hasExactOwnProperties(resource, ['resourceKind', 'reference'])
    ) {
      throw new TypeError(
        `GPUDevice.createBindGroup resource entry ${index} is not canonical`,
      );
    }
    validateBindGroupFullReference(
      resource.reference,
      [resource.resourceKind],
      `GPUDevice.createBindGroup entry ${index}.reference`,
    );
  });
}

function validateCreateBindGroupLayoutDescriptorForService(
  value: unknown,
  sequenceMaximum: number,
  textureFormats: readonly string[],
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      ['label', 'entries'],
    )
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  if (
    typeof descriptor.label !== 'string' ||
    !Array.isArray(descriptor.entries) ||
    descriptor.entries.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout converted descriptor exceeds structural transport bounds',
    );
  }
  const bufferTypes = new Set(['uniform', 'storage', 'read-only-storage']);
  const samplerTypes = new Set(['filtering', 'non-filtering', 'comparison']);
  const textureSampleTypes = new Set([
    'float',
    'unfilterable-float',
    'depth',
    'sint',
    'uint',
  ]);
  const textureViewDimensions = new Set<string>(
    BIND_GROUP_LAYOUT_VIEW_DIMENSIONS,
  );
  const storageAccessValues = new Set(['write-only', 'read-only', 'read-write']);
  const storageViewDimensions = new Set<string>(
    BIND_GROUP_LAYOUT_VIEW_DIMENSIONS,
  );
  const resourceNames = [
    'buffer',
    'externalTexture',
    'sampler',
    'storageTexture',
    'texture',
  ] as const;
  const entryNames = new Set<string>(['binding', 'visibility', ...resourceNames]);
  descriptor.entries.forEach((entry, index) => {
    if (
      typeof entry !== 'object' ||
      entry === null ||
      Array.isArray(entry)
    ) {
      throw new TypeError(
        `GPUDevice.createBindGroupLayout entry ${index} must be a closed dictionary`,
      );
    }
    const row = entry as Readonly<Record<string, unknown>>;
    const keys = Reflect.ownKeys(row);
    if (
      keys.some((key) => typeof key !== 'string' || !entryNames.has(key)) ||
      !Object.prototype.hasOwnProperty.call(row, 'binding') ||
      !Object.prototype.hasOwnProperty.call(row, 'visibility') ||
      !isConvertedU32(row.binding) ||
      !isConvertedU32(row.visibility)
    ) {
      throw new TypeError(
        `GPUDevice.createBindGroupLayout entry ${index} is not a canonical WebIDL dictionary`,
      );
    }

    for (const resourceName of resourceNames) {
      if (!Object.prototype.hasOwnProperty.call(row, resourceName)) continue;
      const resource = row[resourceName];
      if (
        typeof resource !== 'object' ||
        resource === null ||
        Array.isArray(resource)
      ) {
        throw new TypeError(
          `GPUDevice.createBindGroupLayout entry ${index} resource must be a closed dictionary`,
        );
      }
      const layout = resource as Readonly<Record<string, unknown>>;
      const valid = resourceName === 'buffer'
        ? hasExactOwnProperties(
          layout,
          ['hasDynamicOffset', 'minBindingSize', 'type'],
        ) &&
          typeof layout.hasDynamicOffset === 'boolean' &&
          isConvertedU64(layout.minBindingSize) &&
          typeof layout.type === 'string' &&
          bufferTypes.has(layout.type)
        : resourceName === 'externalTexture'
          ? Reflect.ownKeys(layout).length === 0
          : resourceName === 'sampler'
            ? hasExactOwnProperties(layout, ['type']) &&
              typeof layout.type === 'string' &&
              samplerTypes.has(layout.type)
            : resourceName === 'storageTexture'
              ? hasExactOwnProperties(
                layout,
                ['access', 'format', 'viewDimension'],
              ) &&
                typeof layout.access === 'string' &&
                storageAccessValues.has(layout.access) &&
                typeof layout.format === 'string' &&
                textureFormats.includes(layout.format) &&
                typeof layout.viewDimension === 'string' &&
                storageViewDimensions.has(layout.viewDimension)
              : hasExactOwnProperties(
                layout,
                ['multisampled', 'sampleType', 'viewDimension'],
              ) &&
                typeof layout.multisampled === 'boolean' &&
                typeof layout.sampleType === 'string' &&
                textureSampleTypes.has(layout.sampleType) &&
                typeof layout.viewDimension === 'string' &&
                textureViewDimensions.has(layout.viewDimension);
      if (!valid) {
        throw new TypeError(
          `GPUDevice.createBindGroupLayout entry ${index} resource is not a canonical WebIDL dictionary`,
        );
      }
    }
  });
}

function validateCreatePipelineLayoutDescriptorForService(
  value: unknown,
  sequenceMaximum: number,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      ['label', 'bindGroupLayouts', 'immediateSize'],
    )
  ) {
    throw new TypeError(
      'GPUDevice.createPipelineLayout converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  if (
    typeof descriptor.label !== 'string' ||
    !Array.isArray(descriptor.bindGroupLayouts) ||
    descriptor.bindGroupLayouts.length > sequenceMaximum ||
    !isConvertedU32(descriptor.immediateSize)
  ) {
    throw new TypeError(
      'GPUDevice.createPipelineLayout converted descriptor exceeds structural transport bounds',
    );
  }
  descriptor.bindGroupLayouts.forEach((entry, index) => {
    if (entry === null) return;
    if (
      typeof entry !== 'object' ||
      Array.isArray(entry) ||
      !hasExactOwnProperties(
        entry as Readonly<Record<string, unknown>>,
        [
          'kind',
          'objectId',
          'objectGeneration',
          'logicalDeviceId',
          'logicalDeviceGeneration',
          'providerGeneration',
        ],
      )
    ) {
      throw new TypeError(
        `GPUDevice.createPipelineLayout bindGroupLayouts[${index}] must be null or a full object reference`,
      );
    }
    const reference = entry as RequestAdapterReferenceLike;
    if (
      reference.kind !== 'GPUBindGroupLayout' ||
      typeof reference.objectId !== 'string' ||
      typeof reference.objectGeneration !== 'string' ||
      typeof reference.logicalDeviceId !== 'string' ||
      typeof reference.logicalDeviceGeneration !== 'string' ||
      typeof reference.providerGeneration !== 'string'
    ) {
      throw new TypeError(
        `GPUDevice.createPipelineLayout bindGroupLayouts[${index}] has an invalid full object reference`,
      );
    }
    for (const [identity, label] of [
      [reference.objectId, 'objectId'],
      [reference.objectGeneration, 'objectGeneration'],
      [reference.logicalDeviceId, 'logicalDeviceId'],
      [reference.logicalDeviceGeneration, 'logicalDeviceGeneration'],
      [reference.providerGeneration, 'providerGeneration'],
    ] as const) {
      positiveIdentity(
        identity,
        `GPUDevice.createPipelineLayout bindGroupLayouts[${index}].${label}`,
      );
    }
  });
}

function validatePipelineConstantsForService(
  value: unknown,
  dictionaryMaximum: number,
  label: string,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new TypeError(`${label} must be a canonical constants dictionary`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length > dictionaryMaximum ||
    keys.some(
      (key) =>
        typeof key !== 'string' ||
        typeof (value as Readonly<Record<string, unknown>>)[key] !== 'number' ||
        !Number.isFinite((value as Readonly<Record<string, number>>)[key]),
    )
  ) {
    throw new TypeError(`${label} exceeds structural transport bounds`);
  }
}

function validateRenderPipelineStageForService(
  value: unknown,
  kind: 'vertex' | 'fragment',
  sequenceMaximum: number,
  dictionaryMaximum: number,
  textureFormats: readonly string[],
): void {
  const label = `GPUDevice.createRenderPipeline ${kind}`;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be a canonical stage dictionary`);
  }
  const stage = value as Readonly<Record<string, unknown>>;
  const hasEntryPoint = Object.prototype.hasOwnProperty.call(stage, 'entryPoint');
  const required = kind === 'vertex'
    ? ['buffers', 'constants', 'module']
    : ['constants', 'module', 'targets'];
  if (
    !hasExactOwnProperties(
      stage,
      hasEntryPoint ? [...required, 'entryPoint'] : required,
    ) ||
    (hasEntryPoint && typeof stage.entryPoint !== 'string')
  ) {
    throw new TypeError(`${label} has an invalid closed dictionary shape`);
  }
  validatePipelineConstantsForService(
    stage.constants,
    dictionaryMaximum,
    `${label}.constants`,
  );
  validateBindGroupFullReference(stage.module, ['GPUShaderModule'], `${label}.module`);

  if (kind === 'vertex') {
    if (!Array.isArray(stage.buffers) || stage.buffers.length > sequenceMaximum) {
      throw new TypeError(`${label}.buffers must be a bounded sequence`);
    }
    stage.buffers.forEach((buffer, bufferIndex) => {
      if (buffer === null) return;
      if (
        typeof buffer !== 'object' ||
        Array.isArray(buffer) ||
        !hasExactOwnProperties(
          buffer as Readonly<Record<string, unknown>>,
          ['arrayStride', 'attributes', 'stepMode'],
        )
      ) {
        throw new TypeError(`${label}.buffers[${bufferIndex}] is not canonical`);
      }
      const layout = buffer as Readonly<Record<string, unknown>>;
      if (
        !isConvertedU64(layout.arrayStride) ||
        !Array.isArray(layout.attributes) ||
        layout.attributes.length > sequenceMaximum ||
        (layout.stepMode !== 'vertex' && layout.stepMode !== 'instance')
      ) {
        throw new TypeError(`${label}.buffers[${bufferIndex}] exceeds structural bounds`);
      }
      layout.attributes.forEach((attribute, attributeIndex) => {
        if (
          typeof attribute !== 'object' ||
          attribute === null ||
          Array.isArray(attribute) ||
          !hasExactOwnProperties(
            attribute as Readonly<Record<string, unknown>>,
            ['format', 'offset', 'shaderLocation'],
          )
        ) {
          throw new TypeError(
            `${label}.buffers[${bufferIndex}].attributes[${attributeIndex}] is not canonical`,
          );
        }
        const row = attribute as Readonly<Record<string, unknown>>;
        if (
          typeof row.format !== 'string' ||
          !VERTEX_FORMATS.includes(row.format as (typeof VERTEX_FORMATS)[number]) ||
          !isConvertedU64(row.offset) ||
          !isConvertedU32(row.shaderLocation)
        ) {
          throw new TypeError(
            `${label}.buffers[${bufferIndex}].attributes[${attributeIndex}] exceeds structural bounds`,
          );
        }
      });
    });
    return;
  }

  if (!Array.isArray(stage.targets) || stage.targets.length > sequenceMaximum) {
    throw new TypeError(`${label}.targets must be a bounded sequence`);
  }
  const blendOperations = ['add', 'subtract', 'reverse-subtract', 'min', 'max'];
  stage.targets.forEach((target, targetIndex) => {
    if (target === null) return;
    if (typeof target !== 'object' || Array.isArray(target)) {
      throw new TypeError(`${label}.targets[${targetIndex}] is not canonical`);
    }
    const row = target as Readonly<Record<string, unknown>>;
    const hasBlend = Object.prototype.hasOwnProperty.call(row, 'blend');
    if (
      !hasExactOwnProperties(row, hasBlend ? ['blend', 'format', 'writeMask'] : ['format', 'writeMask']) ||
      typeof row.format !== 'string' ||
      !textureFormats.includes(row.format) ||
      !isConvertedU32(row.writeMask)
    ) {
      throw new TypeError(`${label}.targets[${targetIndex}] exceeds structural bounds`);
    }
    if (!hasBlend) return;
    if (
      typeof row.blend !== 'object' ||
      row.blend === null ||
      Array.isArray(row.blend) ||
      !hasExactOwnProperties(
        row.blend as Readonly<Record<string, unknown>>,
        ['alpha', 'color'],
      )
    ) {
      throw new TypeError(`${label}.targets[${targetIndex}].blend is not canonical`);
    }
    const blend = row.blend as Readonly<Record<string, unknown>>;
    for (const componentName of ['alpha', 'color'] as const) {
      const component = blend[componentName];
      if (
        typeof component !== 'object' ||
        component === null ||
        Array.isArray(component) ||
        !hasExactOwnProperties(
          component as Readonly<Record<string, unknown>>,
          ['dstFactor', 'operation', 'srcFactor'],
        )
      ) {
        throw new TypeError(
          `${label}.targets[${targetIndex}].blend.${componentName} is not canonical`,
        );
      }
      const values = component as Readonly<Record<string, unknown>>;
      if (
        typeof values.dstFactor !== 'string' ||
        !BLEND_FACTORS.includes(values.dstFactor as (typeof BLEND_FACTORS)[number]) ||
        typeof values.operation !== 'string' ||
        !blendOperations.includes(values.operation) ||
        typeof values.srcFactor !== 'string' ||
        !BLEND_FACTORS.includes(values.srcFactor as (typeof BLEND_FACTORS)[number])
      ) {
        throw new TypeError(
          `${label}.targets[${targetIndex}].blend.${componentName} exceeds structural bounds`,
        );
      }
    }
  });
}

function validateCreateComputePipelineDescriptorForService(
  value: unknown,
  dictionaryMaximum: number,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      ['compute', 'label', 'layout'],
    )
  ) {
    throw new TypeError(
      'GPUDevice.createComputePipeline converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  if (typeof descriptor.label !== 'string') {
    throw new TypeError(
      'GPUDevice.createComputePipeline descriptor has an invalid label',
    );
  }
  if (descriptor.layout !== 'auto') {
    validateBindGroupFullReference(
      descriptor.layout,
      ['GPUPipelineLayout'],
      'GPUDevice.createComputePipeline layout',
    );
  }
  if (
    typeof descriptor.compute !== 'object' ||
    descriptor.compute === null ||
    Array.isArray(descriptor.compute)
  ) {
    throw new TypeError(
      'GPUDevice.createComputePipeline compute must be a canonical stage dictionary',
    );
  }
  const compute = descriptor.compute as Readonly<Record<string, unknown>>;
  const hasEntryPoint = Object.prototype.hasOwnProperty.call(
    compute,
    'entryPoint',
  );
  if (
    !hasExactOwnProperties(
      compute,
      hasEntryPoint
        ? ['constants', 'entryPoint', 'module']
        : ['constants', 'module'],
    ) ||
    (hasEntryPoint && typeof compute.entryPoint !== 'string')
  ) {
    throw new TypeError(
      'GPUDevice.createComputePipeline compute has an invalid closed dictionary shape',
    );
  }
  validatePipelineConstantsForService(
    compute.constants,
    dictionaryMaximum,
    'GPUDevice.createComputePipeline compute.constants',
  );
  validateBindGroupFullReference(
    compute.module,
    ['GPUShaderModule'],
    'GPUDevice.createComputePipeline compute.module',
  );
}

function validateCreateRenderPipelineDescriptorForService(
  value: unknown,
  sequenceMaximum: number,
  dictionaryMaximum: number,
  textureFormats: readonly string[],
): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      'GPUDevice.createRenderPipeline converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  const optional = ['depthStencil', 'fragment'].filter((field) =>
    Object.prototype.hasOwnProperty.call(descriptor, field)
  );
  if (
    !hasExactOwnProperties(
      descriptor,
      ['label', 'layout', ...optional, 'multisample', 'primitive', 'vertex'],
    ) ||
    typeof descriptor.label !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createRenderPipeline descriptor has an invalid closed dictionary shape',
    );
  }
  if (descriptor.layout !== 'auto') {
    validateBindGroupFullReference(
      descriptor.layout,
      ['GPUPipelineLayout'],
      'GPUDevice.createRenderPipeline layout',
    );
  }

  const multisample = descriptor.multisample;
  if (
    typeof multisample !== 'object' ||
    multisample === null ||
    Array.isArray(multisample) ||
    !hasExactOwnProperties(
      multisample as Readonly<Record<string, unknown>>,
      ['alphaToCoverageEnabled', 'count', 'mask'],
    )
  ) {
    throw new TypeError('GPUDevice.createRenderPipeline multisample is not canonical');
  }
  const multisampleState = multisample as Readonly<Record<string, unknown>>;
  if (
    typeof multisampleState.alphaToCoverageEnabled !== 'boolean' ||
    !isConvertedU32(multisampleState.count) ||
    !isConvertedU32(multisampleState.mask)
  ) {
    throw new TypeError('GPUDevice.createRenderPipeline multisample exceeds structural bounds');
  }

  const primitive = descriptor.primitive;
  if (typeof primitive !== 'object' || primitive === null || Array.isArray(primitive)) {
    throw new TypeError('GPUDevice.createRenderPipeline primitive is not canonical');
  }
  const primitiveState = primitive as Readonly<Record<string, unknown>>;
  const hasStripIndexFormat = Object.prototype.hasOwnProperty.call(
    primitiveState,
    'stripIndexFormat',
  );
  if (
    !hasExactOwnProperties(
      primitiveState,
      hasStripIndexFormat
        ? ['cullMode', 'frontFace', 'stripIndexFormat', 'topology', 'unclippedDepth']
        : ['cullMode', 'frontFace', 'topology', 'unclippedDepth'],
    ) ||
    !['none', 'front', 'back'].includes(String(primitiveState.cullMode)) ||
    !['ccw', 'cw'].includes(String(primitiveState.frontFace)) ||
    (hasStripIndexFormat &&
      primitiveState.stripIndexFormat !== 'uint16' &&
      primitiveState.stripIndexFormat !== 'uint32') ||
    !['point-list', 'line-list', 'line-strip', 'triangle-list', 'triangle-strip'].includes(
      String(primitiveState.topology),
    ) ||
    typeof primitiveState.unclippedDepth !== 'boolean'
  ) {
    throw new TypeError('GPUDevice.createRenderPipeline primitive exceeds structural bounds');
  }

  if (Object.prototype.hasOwnProperty.call(descriptor, 'depthStencil')) {
    const depthStencil = descriptor.depthStencil;
    if (
      typeof depthStencil !== 'object' ||
      depthStencil === null ||
      Array.isArray(depthStencil)
    ) {
      throw new TypeError('GPUDevice.createRenderPipeline depthStencil is not canonical');
    }
    const state = depthStencil as Readonly<Record<string, unknown>>;
    const optionals = ['depthCompare', 'depthWriteEnabled'].filter((field) =>
      Object.prototype.hasOwnProperty.call(state, field)
    );
    if (
      !hasExactOwnProperties(
        state,
        [
          'depthBias', 'depthBiasClamp', 'depthBiasSlopeScale', ...optionals,
          'format', 'stencilBack', 'stencilFront', 'stencilReadMask',
          'stencilWriteMask',
        ],
      ) ||
      typeof state.depthBias !== 'number' ||
      !Number.isInteger(state.depthBias) ||
      state.depthBias < -0x8000_0000 ||
      state.depthBias > 0x7fff_ffff ||
      typeof state.depthBiasClamp !== 'number' ||
      !Number.isFinite(state.depthBiasClamp) ||
      typeof state.depthBiasSlopeScale !== 'number' ||
      !Number.isFinite(state.depthBiasSlopeScale) ||
      (Object.prototype.hasOwnProperty.call(state, 'depthCompare') &&
        (typeof state.depthCompare !== 'string' ||
          !COMPARE_FUNCTIONS.includes(
            state.depthCompare as (typeof COMPARE_FUNCTIONS)[number],
          ))) ||
      (Object.prototype.hasOwnProperty.call(state, 'depthWriteEnabled') &&
        typeof state.depthWriteEnabled !== 'boolean') ||
      typeof state.format !== 'string' ||
      !textureFormats.includes(state.format) ||
      !isConvertedU32(state.stencilReadMask) ||
      !isConvertedU32(state.stencilWriteMask)
    ) {
      throw new TypeError('GPUDevice.createRenderPipeline depthStencil exceeds structural bounds');
    }
    for (const faceName of ['stencilBack', 'stencilFront'] as const) {
      const face = state[faceName];
      if (
        typeof face !== 'object' ||
        face === null ||
        Array.isArray(face) ||
        !hasExactOwnProperties(
          face as Readonly<Record<string, unknown>>,
          ['compare', 'depthFailOp', 'failOp', 'passOp'],
        )
      ) {
        throw new TypeError(`GPUDevice.createRenderPipeline ${faceName} is not canonical`);
      }
      const values = face as Readonly<Record<string, unknown>>;
      if (
        typeof values.compare !== 'string' ||
        !COMPARE_FUNCTIONS.includes(values.compare as (typeof COMPARE_FUNCTIONS)[number]) ||
        [values.depthFailOp, values.failOp, values.passOp].some(
          (entry) =>
            typeof entry !== 'string' ||
            !STENCIL_OPERATIONS.includes(entry as (typeof STENCIL_OPERATIONS)[number]),
        )
      ) {
        throw new TypeError(`GPUDevice.createRenderPipeline ${faceName} exceeds structural bounds`);
      }
    }
  }

  validateRenderPipelineStageForService(
    descriptor.vertex,
    'vertex',
    sequenceMaximum,
    dictionaryMaximum,
    textureFormats,
  );
  if (Object.prototype.hasOwnProperty.call(descriptor, 'fragment')) {
    validateRenderPipelineStageForService(
      descriptor.fragment,
      'fragment',
      sequenceMaximum,
      dictionaryMaximum,
      textureFormats,
    );
  }
}

function validateCreateBufferDescriptorForService(value: unknown): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      ['label', 'mappedAtCreation', 'size', 'usage'],
    )
  ) {
    throw new TypeError(
      'GPUDevice.createBuffer converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  if (
    typeof descriptor.label !== 'string' ||
    encodeUtf8(descriptor.label).byteLength >
      CREATE_BUFFER_MAX_LABEL_UTF8_BYTES ||
    typeof descriptor.mappedAtCreation !== 'boolean' ||
    !isConvertedU64(descriptor.size) ||
    descriptor.size > 268_435_456 ||
    !isConvertedU32(descriptor.usage)
  ) {
    throw new TypeError(
      'GPUDevice.createBuffer converted descriptor exceeds structural transport bounds',
    );
  }
}

function validateCreateSamplerDescriptorForService(
  value: unknown,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      'GPUDevice.createSampler converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  const fields = [
    'addressModeU', 'addressModeV', 'addressModeW', 'label', 'lodMaxClamp',
    'lodMinClamp', 'magFilter', 'maxAnisotropy', 'minFilter', 'mipmapFilter',
  ];
  const exactFields = Object.prototype.hasOwnProperty.call(descriptor, 'compare')
    ? [...fields.slice(0, 3), 'compare', ...fields.slice(3)]
    : fields;
  const validEnum = (candidate: unknown, values: readonly string[]) =>
    typeof candidate === 'string' && values.includes(candidate);
  if (
    !hasExactOwnProperties(descriptor, exactFields) ||
    !validEnum(descriptor.addressModeU, vocabulary.gpuAddressModes) ||
    !validEnum(descriptor.addressModeV, vocabulary.gpuAddressModes) ||
    !validEnum(descriptor.addressModeW, vocabulary.gpuAddressModes) ||
    (Object.prototype.hasOwnProperty.call(descriptor, 'compare') &&
      !validEnum(descriptor.compare, vocabulary.gpuCompareFunctions)) ||
    typeof descriptor.label !== 'string' ||
    typeof descriptor.lodMaxClamp !== 'number' ||
    !Number.isFinite(descriptor.lodMaxClamp) ||
    typeof descriptor.lodMinClamp !== 'number' ||
    !Number.isFinite(descriptor.lodMinClamp) ||
    !validEnum(descriptor.magFilter, vocabulary.gpuFilterModes) ||
    !isConvertedU32(descriptor.maxAnisotropy) ||
    descriptor.maxAnisotropy > 65_535 ||
    !validEnum(descriptor.minFilter, vocabulary.gpuFilterModes) ||
    !validEnum(descriptor.mipmapFilter, vocabulary.gpuMipmapFilterModes)
  ) {
    throw new TypeError(
      'GPUDevice.createSampler converted descriptor exceeds structural transport bounds',
    );
  }
}

function validateCreateTextureDescriptorForService(
  value: unknown,
  sequenceMaximum: number,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(
      'GPUDevice.createTexture converted arguments must be a canonical descriptor',
    );
  }
  const descriptor = value as Readonly<Record<string, unknown>>;
  const fields = [
    'dimension', 'format', 'label', 'mipLevelCount', 'sampleCount', 'size',
    'usage', 'viewFormats',
  ];
  const exactFields = Object.prototype.hasOwnProperty.call(
    descriptor,
    'textureBindingViewDimension',
  )
    ? [...fields.slice(0, 6), 'textureBindingViewDimension', ...fields.slice(6)]
    : fields;
  const size = descriptor.size as Readonly<Record<string, unknown>> | null;
  const viewFormats = descriptor.viewFormats;
  if (
    !hasExactOwnProperties(descriptor, exactFields) ||
    typeof descriptor.dimension !== 'string' ||
    !vocabulary.gpuTextureDimensions.includes(descriptor.dimension) ||
    typeof descriptor.format !== 'string' ||
    !vocabulary.gpuTextureFormats.includes(descriptor.format) ||
    typeof descriptor.label !== 'string' ||
    !isConvertedU32(descriptor.mipLevelCount) ||
    !isConvertedU32(descriptor.sampleCount) ||
    typeof size !== 'object' || size === null || Array.isArray(size) ||
    !hasExactOwnProperties(size, ['depthOrArrayLayers', 'height', 'width']) ||
    !isConvertedU32(size.depthOrArrayLayers) ||
    !isConvertedU32(size.height) ||
    !isConvertedU32(size.width) ||
    (Object.prototype.hasOwnProperty.call(
      descriptor,
      'textureBindingViewDimension',
    ) &&
      (typeof descriptor.textureBindingViewDimension !== 'string' ||
        !vocabulary.gpuTextureViewDimensions.includes(
          descriptor.textureBindingViewDimension,
        ))) ||
    !isConvertedU32(descriptor.usage) ||
    !Array.isArray(viewFormats) ||
    viewFormats.length > sequenceMaximum ||
    viewFormats.some(
      (entry) =>
        typeof entry !== 'string' ||
        !vocabulary.gpuTextureFormats.includes(entry),
    )
  ) {
    throw new TypeError(
      'GPUDevice.createTexture converted descriptor exceeds structural transport bounds',
    );
  }
}

function validateTextureViewFullReference(
  value: unknown,
  expectedKind: 'GPUCanvasContext' | 'GPUDevice' | 'GPUTexture',
  label: string,
): ProductionGpuServiceEncodingInput['receiver'] {
  return submitReference(value, label, expectedKind);
}

interface ValidatedCanvasCurrentTextureOrigin {
  readonly currentOrigin: Readonly<Record<string, unknown>>;
  readonly contextRef: ProductionGpuServiceEncodingInput['receiver'];
  readonly configuredDeviceRef: ProductionGpuServiceEncodingInput['receiver'];
  readonly mintOperationInstanceId: string;
  readonly mintDeviceIngressOrdinal: string;
}

function validateCanvasCurrentTextureOrigin(
  value: unknown,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
  label: string,
): ValidatedCanvasCurrentTextureOrigin {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactOwnProperties(
      value as Readonly<Record<string, unknown>>,
      [
        'originClass',
        'contextRef',
        'attachmentGeneration',
        'contextGeneration',
        'configurationGeneration',
        'currentEpoch',
        'mintOperationProvenance',
        'textureOriginDigest',
        'configuredDeviceRef',
        'format',
        'usage',
        'alphaMode',
        'colorSpace',
        'targetAuthorityDigest',
        'surfaceAccountToken',
        'surfaceAccountGeneration',
      ],
    )
  ) {
    throw new TypeError(`${label} must be a complete closed dictionary`);
  }
  const currentOrigin = value as Readonly<Record<string, unknown>>;
  const contextRef = validateTextureViewFullReference(
    currentOrigin.contextRef,
    'GPUCanvasContext',
    `${label}.contextRef`,
  );
  const configuredDeviceRef = validateTextureViewFullReference(
    currentOrigin.configuredDeviceRef,
    'GPUDevice',
    `${label}.configuredDeviceRef`,
  );
  const mint = currentOrigin.mintOperationProvenance;
  if (
    typeof mint !== 'object' ||
    mint === null ||
    Array.isArray(mint) ||
    !hasExactOwnProperties(
      mint as Readonly<Record<string, unknown>>,
      ['operationInstanceId', 'deviceIngressOrdinal'],
    )
  ) {
    throw new TypeError(`${label} mint provenance is incomplete`);
  }
  const mintRecord = mint as Readonly<Record<string, unknown>>;
  const positiveU64 = isPositiveCanonicalDecimalU64;
  if (
    currentOrigin.originClass !== 'canvas-current' ||
    !positiveU64(currentOrigin.attachmentGeneration) ||
    !positiveU64(currentOrigin.contextGeneration) ||
    !positiveU64(currentOrigin.configurationGeneration) ||
    !positiveU64(currentOrigin.currentEpoch) ||
    !positiveU64(mintRecord.operationInstanceId) ||
    !positiveU64(mintRecord.deviceIngressOrdinal) ||
    typeof currentOrigin.textureOriginDigest !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(currentOrigin.textureOriginDigest) ||
    typeof currentOrigin.format !== 'string' ||
    !vocabulary.gpuTextureFormats.includes(currentOrigin.format) ||
    !isConvertedU32(currentOrigin.usage) ||
    typeof currentOrigin.alphaMode !== 'string' ||
    !['opaque', 'premultiplied'].includes(currentOrigin.alphaMode) ||
    typeof currentOrigin.colorSpace !== 'string' ||
    !['srgb', 'display-p3'].includes(currentOrigin.colorSpace) ||
    typeof currentOrigin.targetAuthorityDigest !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(currentOrigin.targetAuthorityDigest) ||
    !positiveU64(currentOrigin.surfaceAccountToken) ||
    !positiveU64(currentOrigin.surfaceAccountGeneration)
  ) {
    throw new TypeError(`${label} violates structural bounds`);
  }
  return Object.freeze({
    currentOrigin,
    contextRef,
    configuredDeviceRef,
    mintOperationInstanceId: mintRecord.operationInstanceId as string,
    mintDeviceIngressOrdinal: mintRecord.deviceIngressOrdinal as string,
  });
}

function validateCanvasCurrentTextureOriginDigest(
  origin: ValidatedCanvasCurrentTextureOrigin,
  receiverTextureRef: ProductionGpuServiceEncodingInput['receiver'],
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
  label: string,
): void {
  if (
    receiverTextureRef.kind !== 'GPUTexture' ||
    !sameDeviceReference(origin.contextRef, receiverTextureRef) ||
    !sameDeviceReference(origin.configuredDeviceRef, receiverTextureRef)
  ) {
    throw new TypeError(`${label} has foreign source-affine device provenance`);
  }
  const source = origin.currentOrigin;
  const digestInput: ProductionGpuTextureOriginDigestInput = Object.freeze({
    originClass: 'canvas-current',
    receiverTextureRef,
    contextRef: origin.contextRef,
    attachmentGeneration: source.attachmentGeneration as string,
    contextGeneration: source.contextGeneration as string,
    configurationGeneration: source.configurationGeneration as string,
    currentEpoch: source.currentEpoch as string,
    mintOperationProvenance: Object.freeze({
      operationInstanceId: origin.mintOperationInstanceId,
      deviceIngressOrdinal: origin.mintDeviceIngressOrdinal,
    }),
    configuredDeviceRef: origin.configuredDeviceRef,
    format: source.format as string,
    usage: source.usage as number,
    alphaMode: source.alphaMode as 'opaque' | 'premultiplied',
    colorSpace: source.colorSpace as 'srgb' | 'display-p3',
    targetAuthorityDigest: source.targetAuthorityDigest as string,
    surfaceAccountToken: source.surfaceAccountToken as string,
    surfaceAccountGeneration: source.surfaceAccountGeneration as string,
  });
  const expectedDigest = sha256HexUtf8(
    canonicalTextureOriginDigestInput(digestInput, vocabulary),
  );
  if (source.textureOriginDigest !== expectedDigest) {
    throw new TypeError(`${label} digest does not bind the source texture`);
  }
}

function validateCreateTextureViewRequestForService(
  value: unknown,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
  receiverTextureRef?: ProductionGpuServiceEncodingInput['receiver'],
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value)
  ) {
    throw new TypeError(
      'GPUTexture.createView converted request must be a canonical dictionary',
    );
  }
  const request = value as Readonly<Record<string, unknown>>;
  const hasCurrentOrigin = Object.prototype.hasOwnProperty.call(
    request,
    'currentOrigin',
  );
  if (
    !hasExactOwnProperties(
      request,
      hasCurrentOrigin ? ['converted', 'currentOrigin'] : ['converted'],
    ) ||
    typeof request.converted !== 'object' ||
    request.converted === null ||
    Array.isArray(request.converted)
  ) {
    throw new TypeError(
      'GPUTexture.createView request must contain only converted descriptor and optional origin',
    );
  }

  const descriptor = request.converted as Readonly<Record<string, unknown>>;
  const descriptorFields = [
    'aspect',
    'baseArrayLayer',
    'baseMipLevel',
    'label',
    'swizzle',
    'usage',
  ];
  const optionalDescriptorFields = [
    'arrayLayerCount',
    'dimension',
    'format',
    'mipLevelCount',
  ];
  const expectedDescriptorFields = [
    ...descriptorFields,
    ...optionalDescriptorFields.filter((field) =>
      Object.prototype.hasOwnProperty.call(descriptor, field)
    ),
  ];
  if (
    !hasExactOwnProperties(descriptor, expectedDescriptorFields) ||
    typeof descriptor.aspect !== 'string' ||
    !['all', 'stencil-only', 'depth-only'].includes(descriptor.aspect) ||
    !isConvertedU32(descriptor.baseArrayLayer) ||
    !isConvertedU32(descriptor.baseMipLevel) ||
    typeof descriptor.label !== 'string' ||
    typeof descriptor.swizzle !== 'string' ||
    !/^[rgba01]{4}$/u.test(descriptor.swizzle) ||
    !isConvertedU32(descriptor.usage) ||
    (Object.prototype.hasOwnProperty.call(descriptor, 'arrayLayerCount') &&
      !isConvertedU32(descriptor.arrayLayerCount)) ||
    (Object.prototype.hasOwnProperty.call(descriptor, 'dimension') &&
      (typeof descriptor.dimension !== 'string' ||
        !vocabulary.gpuTextureViewDimensions.includes(descriptor.dimension))) ||
    (Object.prototype.hasOwnProperty.call(descriptor, 'format') &&
      (typeof descriptor.format !== 'string' ||
        !vocabulary.gpuTextureFormats.includes(descriptor.format))) ||
    (Object.prototype.hasOwnProperty.call(descriptor, 'mipLevelCount') &&
      !isConvertedU32(descriptor.mipLevelCount))
  ) {
    throw new TypeError(
      'GPUTexture.createView converted descriptor violates the structural transport contract',
    );
  }

  if (!hasCurrentOrigin) return;
  const origin = validateCanvasCurrentTextureOrigin(
    request.currentOrigin,
    vocabulary,
    'GPUTexture.createView canvas-current origin',
  );
  if (receiverTextureRef !== undefined) {
    validateCanvasCurrentTextureOriginDigest(
      origin,
      receiverTextureRef,
      vocabulary,
      'GPUTexture.createView canvas-current origin',
    );
  }
}

function canonicalTextureOriginDigestInput(
  input: ProductionGpuTextureOriginDigestInput,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): string {
  if (
    typeof input !== 'object' ||
    input === null ||
    Array.isArray(input) ||
    !hasExactOwnProperties(
      input as unknown as Readonly<Record<string, unknown>>,
      [
        'originClass',
        'receiverTextureRef',
        'contextRef',
        'attachmentGeneration',
        'contextGeneration',
        'configurationGeneration',
        'currentEpoch',
        'mintOperationProvenance',
        'configuredDeviceRef',
        'format',
        'usage',
        'alphaMode',
        'colorSpace',
        'targetAuthorityDigest',
        'surfaceAccountToken',
        'surfaceAccountGeneration',
      ],
    )
  ) {
    throw new TypeError(
      'GPUTexture.createView texture-origin digest input must be a closed dictionary',
    );
  }
  validateTextureViewFullReference(
    input.receiverTextureRef,
    'GPUTexture',
    'GPUTexture.createView texture-origin digest receiverTextureRef',
  );
  validateTextureViewFullReference(
    input.contextRef,
    'GPUCanvasContext',
    'GPUTexture.createView texture-origin digest contextRef',
  );
  validateTextureViewFullReference(
    input.configuredDeviceRef,
    'GPUDevice',
    'GPUTexture.createView texture-origin digest configuredDeviceRef',
  );
  const mint = input.mintOperationProvenance;
  if (
    input.originClass !== 'canvas-current' ||
    !isPositiveCanonicalDecimalU64(input.attachmentGeneration) ||
    !isPositiveCanonicalDecimalU64(input.contextGeneration) ||
    !isPositiveCanonicalDecimalU64(input.configurationGeneration) ||
    !isPositiveCanonicalDecimalU64(input.currentEpoch) ||
    typeof mint !== 'object' ||
    mint === null ||
    Array.isArray(mint) ||
    !hasExactOwnProperties(
      mint as unknown as Readonly<Record<string, unknown>>,
      ['operationInstanceId', 'deviceIngressOrdinal'],
    ) ||
    !isPositiveCanonicalDecimalU64(mint.operationInstanceId) ||
    !isPositiveCanonicalDecimalU64(mint.deviceIngressOrdinal) ||
    !vocabulary.gpuTextureFormats.includes(input.format) ||
    !isConvertedU32(input.usage) ||
    !['opaque', 'premultiplied'].includes(input.alphaMode) ||
    !['srgb', 'display-p3'].includes(input.colorSpace) ||
    !/^[0-9a-f]{64}$/u.test(input.targetAuthorityDigest) ||
    !isPositiveCanonicalDecimalU64(input.surfaceAccountToken) ||
    !isPositiveCanonicalDecimalU64(input.surfaceAccountGeneration)
  ) {
    throw new TypeError(
      'GPUTexture.createView texture-origin digest input violates structural bounds',
    );
  }
  return `exact.webgpu.texture-origin.v1\0${canonicalManifestJson(input)}`;
}

function validateCreateBindGroupLayoutRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  textureFormats: readonly string[],
): void {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout requires an authenticated GPUDevice receiver',
    );
  }
  for (const [identity, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(identity, `GPUDevice.createBindGroupLayout ${label}`);
  }
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout requires a wrapper-allocated target',
    );
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== 'GPUBindGroupLayout' ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiver.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiver.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiver.providerGeneration
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout target must share the authenticated device provenance',
    );
  }
  positiveIdentity(
    targetReference.objectId,
    'GPUDevice.createBindGroupLayout target.objectId',
  );
  positiveIdentity(
    targetReference.objectGeneration,
    'GPUDevice.createBindGroupLayout target.objectGeneration',
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUDevice.createBindGroupLayout deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createBindGroupLayout sealed local timeline must be a bounded sequence',
    );
  }
  validateCreateBindGroupLayoutDescriptorForService(
    convertedArguments,
    sequenceMaximum,
    textureFormats,
  );
}

function validateCreatePipelineLayoutRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
): void {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createPipelineLayout requires an authenticated GPUDevice receiver',
    );
  }
  for (const [identity, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(identity, `GPUDevice.createPipelineLayout ${label}`);
  }
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(
      'GPUDevice.createPipelineLayout requires a wrapper-allocated target',
    );
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== 'GPUPipelineLayout' ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiver.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiver.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiver.providerGeneration
  ) {
    throw new TypeError(
      'GPUDevice.createPipelineLayout target must share the authenticated device provenance',
    );
  }
  positiveIdentity(
    targetReference.objectId,
    'GPUDevice.createPipelineLayout target.objectId',
  );
  positiveIdentity(
    targetReference.objectGeneration,
    'GPUDevice.createPipelineLayout target.objectGeneration',
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUDevice.createPipelineLayout adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUDevice.createPipelineLayout deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createPipelineLayout sealed local timeline must be a bounded sequence',
    );
  }
  validateCreatePipelineLayoutDescriptorForService(
    convertedArguments,
    sequenceMaximum,
  );
}

function validateCreateBufferRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
): void {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createBuffer requires an authenticated GPUDevice receiver',
    );
  }
  for (const [identity, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(identity, `GPUDevice.createBuffer ${label}`);
  }
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(
      'GPUDevice.createBuffer requires a wrapper-allocated target',
    );
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== 'GPUBuffer' ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiver.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiver.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiver.providerGeneration
  ) {
    throw new TypeError(
      'GPUDevice.createBuffer target must share the authenticated device provenance',
    );
  }
  positiveIdentity(
    targetReference.objectId,
    'GPUDevice.createBuffer target.objectId',
  );
  positiveIdentity(
    targetReference.objectGeneration,
    'GPUDevice.createBuffer target.objectGeneration',
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUDevice.createBuffer adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUDevice.createBuffer deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createBuffer sealed local timeline must be a bounded sequence',
    );
  }
  validateCreateBufferDescriptorForService(convertedArguments);
}

function validateCreateResourceRequestFields(
  operationId:
    | 'GPUDevice.createBindGroup'
    | 'GPUDevice.createComputePipeline'
    | 'GPUDevice.createRenderPipeline'
    | 'GPUDevice.createSampler'
    | 'GPUDevice.createTexture',
  targetKind:
    | 'GPUBindGroup'
    | 'GPUComputePipeline'
    | 'GPURenderPipeline'
    | 'GPUSampler'
    | 'GPUTexture',
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  sequenceMaximum: number,
): RequestAdapterReferenceLike {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(`${operationId} requires an authenticated GPUDevice receiver`);
  }
  for (const [identity, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(identity, `${operationId} ${label}`);
  }
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(`${operationId} requires a wrapper-allocated target`);
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== targetKind ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiver.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiver.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiver.providerGeneration
  ) {
    throw new TypeError(
      `${operationId} target must share the authenticated device provenance`,
    );
  }
  positiveIdentity(targetReference.objectId, `${operationId} target.objectId`);
  positiveIdentity(
    targetReference.objectGeneration,
    `${operationId} target.objectGeneration`,
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(`${operationId} adapter and queue ingress ordinals must be zero`);
  }
  positiveIdentity(String(deviceIngressOrdinal), `${operationId} deviceIngressOrdinal`);
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(`${operationId} sealed local timeline must be a bounded sequence`);
  }
  return targetReference;
}

function validateCreateBindGroupRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
): void {
  validateCreateResourceRequestFields(
    CREATE_BIND_GROUP_OPERATION_ID,
    'GPUBindGroup',
    receiver,
    target,
    adapterOrdinal,
    deviceIngressOrdinal,
    queueIngressOrdinal,
    sealedLocalTimeline,
    sequenceMaximum,
  );
  validateCreateBindGroupDescriptorForService(
    convertedArguments,
    sequenceMaximum,
  );
}

function validateCreateComputePipelineRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  dictionaryMaximum: number,
): void {
  validateCreateResourceRequestFields(
    CREATE_COMPUTE_PIPELINE_OPERATION_ID,
    'GPUComputePipeline',
    receiver,
    target,
    adapterOrdinal,
    deviceIngressOrdinal,
    queueIngressOrdinal,
    sealedLocalTimeline,
    sequenceMaximum,
  );
  validateCreateComputePipelineDescriptorForService(
    convertedArguments,
    dictionaryMaximum,
  );
}

function validateCreateRenderPipelineRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  dictionaryMaximum: number,
  textureFormats: readonly string[],
): void {
  validateCreateResourceRequestFields(
    CREATE_RENDER_PIPELINE_OPERATION_ID,
    'GPURenderPipeline',
    receiver,
    target,
    adapterOrdinal,
    deviceIngressOrdinal,
    queueIngressOrdinal,
    sealedLocalTimeline,
    sequenceMaximum,
  );
  validateCreateRenderPipelineDescriptorForService(
    convertedArguments,
    sequenceMaximum,
    dictionaryMaximum,
    textureFormats,
  );
}

function validateCreateSamplerRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): void {
  validateCreateResourceRequestFields(
    CREATE_SAMPLER_OPERATION_ID,
    'GPUSampler',
    receiver,
    target,
    adapterOrdinal,
    deviceIngressOrdinal,
    queueIngressOrdinal,
    sealedLocalTimeline,
    sequenceMaximum,
  );
  validateCreateSamplerDescriptorForService(convertedArguments, vocabulary);
}

function validateCreateTextureRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): void {
  validateCreateResourceRequestFields(
    CREATE_TEXTURE_OPERATION_ID,
    'GPUTexture',
    receiver,
    target,
    adapterOrdinal,
    deviceIngressOrdinal,
    queueIngressOrdinal,
    sealedLocalTimeline,
    sequenceMaximum,
  );
  validateCreateTextureDescriptorForService(
    convertedArguments,
    sequenceMaximum,
    vocabulary,
  );
}

function validateCreateTextureViewRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
  vocabulary: ExecutableWebGpuCodecManifest['webIdlVocabulary'],
): void {
  if (
    receiver.kind !== 'GPUTexture' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUTexture.createView requires an authenticated GPUTexture receiver',
    );
  }
  for (const [identity, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(identity, `GPUTexture.createView ${label}`);
  }
  const receiverTextureRef = submitReference(
    receiver,
    'GPUTexture.createView receiver',
    'GPUTexture',
  );
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(
      'GPUTexture.createView requires a wrapper-allocated GPUTextureView target',
    );
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== 'GPUTextureView' ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiverTextureRef.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiverTextureRef.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiverTextureRef.providerGeneration
  ) {
    throw new TypeError(
      'GPUTexture.createView target must share the source texture device provenance',
    );
  }
  positiveIdentity(
    targetReference.objectId,
    'GPUTexture.createView target.objectId',
  );
  positiveIdentity(
    targetReference.objectGeneration,
    'GPUTexture.createView target.objectGeneration',
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUTexture.createView adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUTexture.createView deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUTexture.createView sealed local timeline must be a bounded sequence',
    );
  }
  validateCreateTextureViewRequestForService(
    convertedArguments,
    vocabulary,
    receiverTextureRef,
  );
}

function validateCreateCommandEncoderRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
): void {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createCommandEncoder requires an authenticated GPUDevice receiver',
    );
  }
  for (const [value, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(value, `GPUDevice.createCommandEncoder ${label}`);
  }
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(
      'GPUDevice.createCommandEncoder requires a wrapper-allocated target',
    );
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== 'GPUCommandEncoder' ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiver.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiver.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiver.providerGeneration
  ) {
    throw new TypeError(
      'GPUDevice.createCommandEncoder target must share the authenticated device provenance',
    );
  }
  positiveIdentity(
    targetReference.objectId,
    'GPUDevice.createCommandEncoder target.objectId',
  );
  positiveIdentity(
    targetReference.objectGeneration,
    'GPUDevice.createCommandEncoder target.objectGeneration',
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUDevice.createCommandEncoder adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUDevice.createCommandEncoder deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createCommandEncoder sealed local timeline must be a bounded sequence',
    );
  }
  validateCreateCommandEncoderDescriptorForService(convertedArguments);
}

function validateCreateShaderModuleDescriptorForService(
  value: unknown,
): void {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 2 ||
    !Object.prototype.hasOwnProperty.call(value, 'label') ||
    !Object.prototype.hasOwnProperty.call(value, 'code') ||
    typeof (value as Readonly<Record<string, unknown>>).label !== 'string' ||
    typeof (value as Readonly<Record<string, unknown>>).code !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createShaderModule converted arguments violate the reviewed descriptor shape',
    );
  }
}

function validateCreateShaderModuleRequestFields(
  receiver: RequestAdapterReferenceLike,
  target: unknown,
  adapterOrdinal: unknown,
  deviceIngressOrdinal: unknown,
  queueIngressOrdinal: unknown,
  sealedLocalTimeline: unknown,
  convertedArguments: unknown,
  sequenceMaximum: number,
): void {
  if (
    receiver.kind !== 'GPUDevice' ||
    typeof receiver.objectId !== 'string' ||
    typeof receiver.objectGeneration !== 'string' ||
    typeof receiver.logicalDeviceId !== 'string' ||
    typeof receiver.logicalDeviceGeneration !== 'string' ||
    typeof receiver.providerGeneration !== 'string'
  ) {
    throw new TypeError(
      'GPUDevice.createShaderModule requires an authenticated GPUDevice receiver',
    );
  }
  for (const [value, label] of [
    [receiver.objectId, 'receiver.objectId'],
    [receiver.objectGeneration, 'receiver.objectGeneration'],
    [receiver.logicalDeviceId, 'receiver.logicalDeviceId'],
    [receiver.logicalDeviceGeneration, 'receiver.logicalDeviceGeneration'],
    [receiver.providerGeneration, 'receiver.providerGeneration'],
  ] as const) {
    positiveIdentity(value, `GPUDevice.createShaderModule ${label}`);
  }
  if (typeof target !== 'object' || target === null || Array.isArray(target)) {
    throw new TypeError(
      'GPUDevice.createShaderModule requires a wrapper-allocated target',
    );
  }
  const targetReference = target as RequestAdapterReferenceLike;
  if (
    targetReference.kind !== 'GPUShaderModule' ||
    typeof targetReference.objectId !== 'string' ||
    typeof targetReference.objectGeneration !== 'string' ||
    targetReference.logicalDeviceId !== receiver.logicalDeviceId ||
    targetReference.logicalDeviceGeneration !== receiver.logicalDeviceGeneration ||
    targetReference.providerGeneration !== receiver.providerGeneration
  ) {
    throw new TypeError(
      'GPUDevice.createShaderModule target must share the authenticated device provenance',
    );
  }
  positiveIdentity(
    targetReference.objectId,
    'GPUDevice.createShaderModule target.objectId',
  );
  positiveIdentity(
    targetReference.objectGeneration,
    'GPUDevice.createShaderModule target.objectGeneration',
  );
  if (adapterOrdinal !== '0' || queueIngressOrdinal !== '0') {
    throw new TypeError(
      'GPUDevice.createShaderModule adapter and queue ingress ordinals must be zero',
    );
  }
  positiveIdentity(
    String(deviceIngressOrdinal),
    'GPUDevice.createShaderModule deviceIngressOrdinal',
  );
  if (
    !Array.isArray(sealedLocalTimeline) ||
    sealedLocalTimeline.length > sequenceMaximum
  ) {
    throw new TypeError(
      'GPUDevice.createShaderModule sealed local timeline must be a bounded sequence',
    );
  }
  validateCreateShaderModuleDescriptorForService(convertedArguments);
}

function validateRequestDeviceCompletionCarrier(
  event: DetachedOperationResultEvent,
  program: ValidatedNativeCodecProgram,
): boolean {
  if (
    event.kind !== program.operationResultEventKind ||
    event.status !== 0 ||
    event.operationId !== REQUEST_DEVICE_WIRE_ID ||
    event.resultKind !== program.objectResultKind ||
    event.ingressLogicalDeviceId !== '0' ||
    event.ingressLogicalDeviceGeneration !== '0' ||
    event.ingressProviderGeneration !== '0' ||
    event.receiverKind !== 2 ||
    event.receiverFlags !== 0 ||
    event.targetKind !== 0 ||
    event.targetFlags !== 0 ||
    event.targetId !== '0' ||
    event.targetGeneration !== '0' ||
    event.capturedScopeId !== '0' ||
    event.deviceIngressOrdinal !== '0' ||
    event.queueIngressOrdinal !== '0'
  ) {
    throw new TypeError(
      'GPUDevice result carries an invalid requestDevice authenticated carrier',
    );
  }
  positiveIdentity(event.receiverId, 'requestDevice carrier receiverId');
  positiveIdentity(
    event.receiverGeneration,
    'requestDevice carrier receiverGeneration',
  );
  positiveIdentity(event.adapterOrdinal, 'requestDevice carrier adapterOrdinal');
  positiveIdentity(
    event.operationProviderGeneration,
    'requestDevice carrier providerGeneration',
  );
  positiveIdentity(event.logicalDeviceId, 'requestDevice result logicalDeviceId');
  positiveIdentity(
    event.logicalDeviceGeneration,
    'requestDevice result logicalDeviceGeneration',
  );
  positiveIdentity(event.providerGeneration, 'requestDevice result providerGeneration');
  if (event.providerGeneration !== event.operationProviderGeneration) {
    throw new TypeError('GPUDevice result provider provenance mismatch');
  }

  const admitted = event.providerAdmission === program.providerAdmitted;
  if (
    (admitted && !/^[1-9][0-9]*$/u.test(event.physicalSequence)) ||
    (!admitted &&
      (event.providerAdmission !== program.providerNotAdmitted ||
        event.physicalSequence !== '0'))
  ) {
    throw new TypeError(
      'GPUDevice result admission/physical-sequence provenance mismatch',
    );
  }
  if (event.deviceTransition === program.assignedDeviceTransition) {
    if (
      !admitted ||
      event.detachedAlreadyLost !== false ||
      event.lossReason !== undefined ||
      event.backendClass !== undefined
    ) {
      throw new TypeError('Live GPUDevice result has invalid transition fields');
    }
    return false;
  }
  if (event.deviceTransition === program.assignedDetachedDeviceTransition) {
    if (
      event.detachedAlreadyLost !== true ||
      event.lossReason !== 1 ||
      event.backendClass !== 0
    ) {
      throw new TypeError('Detached GPUDevice result has invalid transition fields');
    }
    return true;
  }
  throw new TypeError('GPUDevice result has an invalid device transition');
}

function makeGpuError(kind: number, message: string): Error {
  const names: Readonly<Record<number, string>> = Object.freeze({
    1: 'GPUValidationError',
    2: 'GPUOutOfMemoryError',
    3: 'GPUInternalError',
  });
  const name = names[kind];
  if (!name) throw new TypeError(`Unknown GPU error kind: ${kind}`);
  const error = new Error(message);
  Object.defineProperty(error, 'name', {
    value: name,
    writable: false,
    enumerable: false,
    configurable: true,
  });
  return Object.freeze(error);
}

export interface WebGpuCodecTestAdapterResult {
  readonly kind: 'adapter';
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly providerGeneration: string;
  readonly serviceDetachedExpired: boolean;
  readonly features: readonly string[];
}

export interface WebGpuCodecTestDeviceResult {
  readonly kind: 'device';
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
  readonly queueObjectId: string;
  readonly queueObjectGeneration: string;
  readonly features: readonly string[];
  readonly limits: Readonly<Record<string, number>>;
  readonly diagnosticMessage?: string;
}

export interface WebGpuCodecTestErrorResult {
  readonly kind: 'error';
  readonly errorKind: 1 | 2 | 3;
  readonly message: string;
}

export interface WebGpuCodecTestBufferCleanupResult {
  readonly kind: 'buffer-cleanup';
  readonly terminal:
    | 'repeat-cleanup-noop'
    | 'first-cleanup-rejection'
    | 'first-cleanup-provider'
    | 'unmapped-noop'
    | 'cleanup-rejection'
    | 'cleanup-provider';
}

export interface WebGpuCodecTestBufferMapResult {
  readonly kind: 'buffer-map';
  readonly variant:
    | 'mapped-bytes'
    | 'provider-operation-error'
    | 'allocation-range-error'
    | 'late-cancelled-cleanup';
  readonly pendingMapGeneration: string;
  readonly mode: 1 | 2;
  readonly offset: string;
  readonly size: string;
  readonly ownedBytes: ArrayBufferView;
}

export interface WebGpuCodecTestQueueWriteBufferResult {
  readonly kind: 'queue-write-buffer';
  readonly terminal: 'later-predicate-rejection' | 'operation-success';
}

export interface WebGpuCodecTestCanvasTerminalResult {
  readonly kind: 'canvas-terminal';
  readonly terminal:
    | 'operation-success'
    | 'repeat-cleanup-noop'
    | 'first-cleanup-provider';
}

export type WebGpuCodecTestServiceResult =
  | Readonly<{ kind: 'none' }>
  | Readonly<{ kind: 'null' }>
  | WebGpuCodecTestAdapterResult
  | WebGpuCodecTestDeviceResult
  | WebGpuCodecTestErrorResult
  | WebGpuCodecTestBufferCleanupResult
  | WebGpuCodecTestBufferMapResult
  | WebGpuCodecTestCanvasTerminalResult
  | WebGpuCodecTestQueueWriteBufferResult;

export function createExecutableWebGpuCodecs(
  manifest: ExecutableWebGpuCodecManifest,
  expectedObjectKindTags: Readonly<Record<string, number>>,
): Readonly<{
  bundle: ExecutableWebGpuCodecBundle;
  testSupport: Readonly<{
    inspectServiceRequest: (payload: ArrayBufferView) => unknown;
    encodeNativeCodegenRequest: (
      input: ProductionGpuServiceEncodingInput,
    ) => Uint8Array;
    encodeServiceResult: (
      operationId: string,
      result: WebGpuCodecTestServiceResult,
    ) => Uint8Array;
    encodeDeviceLoss: (message: string) => Uint8Array;
    encodeCanonicalValue: (value: unknown) => Uint8Array;
  }>;
}> {
  validateTypeGpuBindGroupWorkloadEvidence(manifest);
  const requestAdapterNativeProgram = validateNativeCodecProgram(
    manifest,
    expectedObjectKindTags,
  );
  const textureFormatRequiredFeatureEntries = Object.entries(
    manifest.webIdlVocabulary.gpuTextureFormatRequiredFeatures,
  );
  if (
    manifest.schema !== 'ibex/webgpu-executable-codec-manifest/2' ||
    manifest.disposition !==
      'reviewed-generated-injection-and-request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-compute-pipeline-create-render-pipeline-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-canvas-configure-canvas-unconfigure-texture-destroy-queue-write-buffer-queue-submit-native-codec-not-installed-no-support-claim' ||
    manifest.operationCount !== WEBGPU_PRODUCTION_PLAN.routes.length ||
    manifest.byteOrder !== 'little-endian' ||
    manifest.digests.operationSet !==
      WEBGPU_PRODUCTION_PLAN.digests.operationSet ||
    manifest.digests.semanticProgramSet !==
      WEBGPU_PRODUCTION_PLAN.digests.semanticProgramSet ||
    manifest.digests.runtimeRouting !==
      WEBGPU_PRODUCTION_PLAN.digests.runtimeRouting ||
    manifest.digests.webgpuCVocabulary !==
      WEBGPU_PRODUCTION_PLAN.digests.webgpuCVocabulary ||
    manifest.digests.projection !== WEBGPU_PRODUCTION_PLAN.digests.projection ||
    canonicalManifestJson(manifest.completeLimitNames) !==
      canonicalManifestJson(EXPECTED_COMPLETE_LIMIT_NAMES) ||
    canonicalManifestJson(manifest.webIdlVocabulary) !==
      canonicalManifestJson(WEBGPU_PRODUCTION_PLAN.webIdlVocabulary) ||
    !Array.isArray(manifest.authenticatedPromotions) ||
    canonicalManifestJson(manifest.authenticatedPromotions) !==
      canonicalManifestJson(
        WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.authenticatedPromotions,
      ) ||
    !Array.isArray(manifest.postWebIdlPayloadCodegenInputs) ||
    canonicalManifestJson(manifest.postWebIdlPayloadCodegenInputs) !==
      canonicalManifestJson(
        WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure
          .postWebIdlPayloadCodegenInputs,
      ) ||
    new Set(manifest.completeLimitNames).size !==
      EXPECTED_COMPLETE_LIMIT_NAMES.length ||
    manifest.layout.requestMagic !== 'IBGQ' ||
    manifest.layout.resultMagic !== 'IBGR' ||
    manifest.layout.lossMagic !== 'IBGL' ||
    manifest.layout.version !== 1 ||
    manifest.layout.catalogWireTagRule !==
      'one-based-index-in-authority-catalog-order' ||
    manifest.layout.objectKindTagRule !==
      'ExactGpuObjectKindV2-numeric-values-from-include-exact_runtime.h' ||
    manifest.layout.header !==
      'ascii4-magic-plus-u16-le-version-plus-u16-le-codec-tag-plus-u32-le-operation-wire-id' ||
    manifest.layout.reference !==
      'u8-object-kind-plus-five-u64-le-identity-fields' ||
    manifest.layout.target !==
      'u8-zero-or-one-presence-plus-optional-reference' ||
    manifest.layout.requestTail !==
      'four-u64-le-ordinals-plus-generic-sealed-local-timeline-plus-generic-converted-arguments' ||
    manifest.layout.nullableNullResult !==
      'authenticated-result-kind-null-plus-zero-payload-bytes' ||
    manifest.maxPayloadBytes !== 16_777_216 ||
    manifest.layout.diagnosticMaxBytes !== 4_096 ||
    manifest.layout.sequenceMaxCount !== 1_024 ||
    manifest.layout.dictionaryMaxFields !== 128 ||
    manifest.layout.nestingMaxDepth !== 16 ||
    JSON.stringify(manifest.layout.valueTags) !==
      JSON.stringify({
        null: 0,
        false: 1,
        true: 2,
        u32: 3,
        f64: 4,
        string: 5,
        sequence: 6,
        dictionary: 7,
      }) ||
    manifest.objectKindAuthority.path !== 'include/exact_runtime.h' ||
    !/^[0-9a-f]{64}$/u.test(manifest.objectKindAuthority.sha256) ||
    manifest.webIdlVocabulary.bindingPackage !== '@webgpu/types' ||
    manifest.webIdlVocabulary.bindingPackageVersion !== '0.1.71' ||
    manifest.webIdlVocabulary.gpuFeatureNames.length !== 23 ||
    new Set(manifest.webIdlVocabulary.gpuFeatureNames).size !== 23 ||
    manifest.webIdlVocabulary.declarationPath !==
      'node_modules/@webgpu/types/dist/index.d.ts' ||
    !/^[0-9a-f]{64}$/u.test(manifest.webIdlVocabulary.declarationSha256) ||
    manifest.webIdlVocabulary.gpuTextureFormats.length !== 101 ||
    new Set(manifest.webIdlVocabulary.gpuTextureFormats).size !== 101 ||
    manifest.webIdlVocabulary.gpuTextureFormats[0] !== 'r8unorm' ||
    manifest.webIdlVocabulary.gpuTextureFormats.at(-1) !==
      'astc-12x12-unorm-srgb' ||
    !/^[0-9a-f]{64}$/u.test(
      manifest.webIdlVocabulary.gpuTextureFormatCapabilityRowsSha256,
    ) ||
    textureFormatRequiredFeatureEntries.length !== 101 ||
    textureFormatRequiredFeatureEntries.some(
      ([format, requiredFeature], index) =>
        format !== manifest.webIdlVocabulary.gpuTextureFormats[index] ||
        (requiredFeature !== null && typeof requiredFeature !== 'string'),
    ) ||
    JSON.stringify(manifest.webIdlVocabulary.gpuAddressModes) !==
      JSON.stringify(['clamp-to-edge', 'repeat', 'mirror-repeat']) ||
    JSON.stringify(manifest.webIdlVocabulary.gpuFilterModes) !==
      JSON.stringify(['nearest', 'linear']) ||
    JSON.stringify(manifest.webIdlVocabulary.gpuMipmapFilterModes) !==
      JSON.stringify(['nearest', 'linear']) ||
    JSON.stringify(manifest.webIdlVocabulary.gpuCompareFunctions) !==
      JSON.stringify([
        'never',
        'less',
        'equal',
        'less-equal',
        'greater',
        'not-equal',
        'greater-equal',
        'always',
      ]) ||
    JSON.stringify(manifest.webIdlVocabulary.gpuTextureDimensions) !==
      JSON.stringify(['1d', '2d', '3d']) ||
    JSON.stringify(manifest.webIdlVocabulary.gpuTextureViewDimensions) !==
      JSON.stringify(['1d', '2d', '2d-array', 'cube', 'cube-array', '3d']) ||
    manifest.publicArguments.some((row, index) => row.wireTag !== index + 1) ||
    manifest.serviceArguments.some((row, index) => row.wireTag !== index + 1) ||
    manifest.serviceCompletions.some((row, index) => row.wireTag !== index + 1)
  ) {
    throw new Error('Invalid generated WebGPU executable codec manifest');
  }
  const objectKindEntries = Object.entries(manifest.objectKindTags);
  const expectedObjectKindEntries = Object.entries(expectedObjectKindTags);
  if (
    objectKindEntries.length !== 23 ||
    expectedObjectKindEntries.length !== 23 ||
    manifest.objectKindTags.None !== 0 ||
    expectedObjectKindEntries.some(
      ([name, tag]) => manifest.objectKindTags[name] !== tag,
    ) ||
    objectKindEntries.some(
      ([name, tag]) => expectedObjectKindTags[name] !== tag,
    )
  ) {
    throw new Error('Invalid generated WebGPU object-kind table');
  }
  const objectKinds = Object.fromEntries(
    PRODUCTION_WRAPPER_KINDS.map((kind) => [kind, manifest.objectKindTags[kind]]),
  ) as Record<ProductionGpuWrapperKind, number>;
  if (
    Object.values(objectKinds).some(
      (tag) => !Number.isInteger(tag) || tag <= 0 || tag > 0xff,
    ) ||
    new Set(Object.values(objectKinds)).size !== PRODUCTION_WRAPPER_KINDS.length
  ) {
    throw new Error('Generated WebGPU wrapper object kinds are incomplete');
  }
  const objectKindsByTag = new Map<number, ProductionGpuWrapperKind>(
    Object.entries(objectKinds).map(([kind, tag]) => [
      tag,
      kind as ProductionGpuWrapperKind,
    ]),
  );
  const queueSubmitRecordSpecs = buildQueueSubmitRecordSpecs();
  const routes = new Map<string, ProductionRoute>(
    WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.operationId, route]),
  );
  const publicCodecs = new Map(
    manifest.publicArguments.map((codec) => [codec.tag, codec]),
  );
  const serviceCodecs = new Map(
    manifest.serviceArguments.map((codec) => [codec.tag, codec]),
  );
  const completionCodecs = new Map(
    manifest.serviceCompletions.map((codec) => [codec.tag, codec]),
  );
  const consumedQueueWriteBufferSnapshots = new WeakSet<Uint8Array>();
  if (
    routes.size !== WEBGPU_PRODUCTION_PLAN.routes.length ||
    manifest.authenticatedPromotions.length !==
      WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.authenticatedPromotions.length ||
    manifest.postWebIdlPayloadCodegenInputs.length !== 0 ||
    !routes.has(CREATE_COMPUTE_PIPELINE_OPERATION_ID) ||
    manifest.operationIds.length !== WEBGPU_PRODUCTION_PLAN.routes.length ||
    manifest.operationIds.some((operationId, index) =>
      WEBGPU_PRODUCTION_PLAN.routes[index]?.operationId !== operationId)
  ) {
    throw new Error('Generated WebGPU codec operation inventory drifted');
  }
  for (const route of routes.values()) {
    if (
      !publicCodecs.has(route.publicArgumentCodec) ||
      !serviceCodecs.has(route.serviceArgumentCodec) ||
      !completionCodecs.has(route.serviceCompletionCodec)
    ) {
      throw new Error(`Generated WebGPU codec catalog omits ${route.operationId}`);
    }
  }

  const selectedRoute = (operationId: string): ProductionRoute => {
    const route = routes.get(operationId);
    if (!route) throw new TypeError(`Unreviewed WebGPU operation: ${operationId}`);
    return route;
  };

  const convertPublicArguments = (
    operationId: string,
    args: readonly unknown[],
    wrappers: ProductionGpuCodecWrapperAccess,
  ): unknown => {
    const codec = routes.get(operationId)?.publicArgumentCodec;
    if (codec === undefined) {
      throw new TypeError(`Unreviewed WebGPU operation: ${operationId}`);
    }
    switch (codec) {
      case 'none-v1':
        return null;
      case 'gpu-request-adapter-options-v1':
        return convertRequestAdapterOptions(args[0]);
      case 'gpu-device-descriptor-v1':
        return convertDeviceDescriptor(args[0], manifest.layout.sequenceMaxCount);
      case 'gpu-canvas-configuration-v1':
        return convertCanvasConfiguration(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
          manifest.webIdlVocabulary.gpuTextureFormats,
        );
      case 'gpu-render-pass-descriptor-v1':
        return convertRenderPassDescriptor(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-compute-pass-descriptor-v1':
        return convertComputePassDescriptorArguments(args[0], wrappers);
      case 'gpu-clear-buffer-arguments-v1':
        return convertClearBufferArguments(args, wrappers);
      case 'gpu-copy-buffer-to-buffer-arguments-v1':
        return convertCopyBufferToBufferArguments(args, wrappers);
      case 'gpu-copy-texture-to-texture-arguments-v1':
        return convertCopyTextureToTextureArguments(args, wrappers);
      case 'gpu-command-buffer-descriptor-v1':
        return convertObjectDescriptor(args[0], 'GPUCommandBufferDescriptor');
      case 'gpu-command-encoder-descriptor-v1':
        return convertObjectDescriptor(args[0], 'GPUCommandEncoderDescriptor');
      case 'gpu-bind-group-descriptor-v1':
        return convertBindGroupDescriptor(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-bind-group-layout-descriptor-v1':
        return convertBindGroupLayoutDescriptor(
          args[0],
          manifest.layout.sequenceMaxCount,
          manifest.webIdlVocabulary.gpuTextureFormats,
        );
      case 'gpu-buffer-descriptor-v1':
        return convertBufferDescriptor(args[0]);
      case 'gpu-buffer-mapped-range-arguments-v1':
        return convertBufferMappedRangeArguments(args);
      case 'gpu-buffer-map-async-arguments-v1':
        return convertBufferMapAsyncArguments(args);
      case 'gpu-queue-write-buffer-arguments-v1':
        return convertQueueWriteBufferArguments(args, wrappers);
      case 'gpu-sampler-descriptor-v1':
        return convertSamplerDescriptor(args[0], manifest.webIdlVocabulary);
      case 'gpu-texture-descriptor-v1':
        return convertTextureDescriptor(
          args[0],
          manifest.layout.sequenceMaxCount,
          manifest.webIdlVocabulary,
        );
      case 'gpu-pipeline-layout-descriptor-v1':
        return convertPipelineLayoutDescriptor(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-render-pipeline-descriptor-v1':
        return convertRenderPipelineDescriptor(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
          manifest.webIdlVocabulary.gpuTextureFormats,
        );
      case 'gpu-compute-pipeline-descriptor-v1':
        return convertComputePipelineDescriptor(args[0], wrappers);
      case 'gpu-shader-module-descriptor-v1':
        return convertShaderModuleDescriptor(args[0]);
      case 'gpu-error-filter-v1':
        return convertErrorFilter(args[0]);
      case 'gpu-command-buffer-handle-sequence-v1':
        return convertCommandBufferSequence(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-dispatch-workgroups-arguments-v1':
        return frozenRecord({
          workgroupCountX: u32(
            args[0],
            'GPUComputePassEncoder.dispatchWorkgroups workgroupCountX',
          ),
          workgroupCountY: u32(
            args[1],
            'GPUComputePassEncoder.dispatchWorkgroups workgroupCountY',
            1,
          ),
          workgroupCountZ: u32(
            args[2],
            'GPUComputePassEncoder.dispatchWorkgroups workgroupCountZ',
            1,
          ),
        });
      case 'gpu-set-bind-group-arguments-v1':
        return convertSetBindGroupArguments(
          args,
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-draw-arguments-v1':
        return convertDrawArguments(args);
      case 'gpu-compute-pipeline-handle-v1':
        return wrappers.reference(args[0], 'GPUComputePipeline');
      case 'gpu-render-pipeline-handle-v1':
        return wrappers.reference(args[0], 'GPURenderPipeline');
      case 'gpu-set-vertex-buffer-arguments-v1':
        return convertSetVertexBufferArguments(args, wrappers);
      case 'gpu-texture-view-descriptor-v1':
        return convertTextureViewDescriptor(
          args[0],
          manifest.webIdlVocabulary.gpuTextureFormats,
        );
      default:
        throw new TypeError(`Unknown WebGPU public argument codec: ${codec}`);
    }
  };

  const encodeReviewedNativeRequestPayload = (
    input: ProductionGpuServiceEncodingInput,
  ): Uint8Array => {
    const route = selectedRoute(input.operationId);
    if (input.wireId !== route.wireId) {
      throw new TypeError('WebGPU request wire identity mismatch');
    }
    if (route.providerSubmission === 'none') {
      throw new TypeError(`${input.operationId} has no service request codec`);
    }
    const codec = serviceCodecs.get(route.serviceArgumentCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service request codec');
    let bufferLifecycleBody: BufferLifecycleBody | undefined;
    let canvasServiceBody: CanvasServiceBody | undefined;
    let queueWriteBufferBody: QueueWriteBufferBody | undefined;
    let queueSubmitBody: QueueSubmitEncodedBody | undefined;
    if (route.operationId === requestAdapterNativeProgram.route.operationId) {
      validateRequestAdapterRequestFields(
        input.receiver,
        input.target,
        input.capturedScopeId,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.requestDeviceRoute.operationId
    ) {
      if (!codec.nativeProgramPrerequisitesRepresented) {
        throw new TypeError(
          'GPUAdapter.requestDevice native derivation prerequisites are absent',
        );
      }
      validateRequestDeviceRequestFields(
        input.receiver,
        input.target,
        input.capturedScopeId,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.layout.dictionaryMaxFields,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createBindGroupRoute.operationId
    ) {
      validateCreateBindGroupRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createBindGroupLayoutRoute.operationId
    ) {
      validateCreateBindGroupLayoutRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary.gpuTextureFormats,
      );
    } else if (
      route.operationId === requestAdapterNativeProgram.createBufferRoute.operationId
    ) {
      validateCreateBufferRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createPipelineLayoutRoute.operationId
    ) {
      validateCreatePipelineLayoutRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createComputePipelineRoute.operationId
    ) {
      validateCreateComputePipelineRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.layout.dictionaryMaxFields,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createRenderPipelineRoute.operationId
    ) {
      validateCreateRenderPipelineRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.layout.dictionaryMaxFields,
        manifest.webIdlVocabulary.gpuTextureFormats,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createSamplerRoute.operationId
    ) {
      validateCreateSamplerRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createTextureRoute.operationId
    ) {
      validateCreateTextureRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createTextureViewRoute.operationId
    ) {
      validateCreateTextureViewRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createCommandEncoderRoute.operationId
    ) {
      validateCreateCommandEncoderRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createShaderModuleRoute.operationId
    ) {
      validateCreateShaderModuleRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.deviceDestroyRoute.operationId
    ) {
      validateDeviceDestroyRequestFields(
        input.receiver,
        input.target,
        input.adapterOrdinal,
        input.deviceIngressOrdinal,
        input.queueIngressOrdinal,
        input.sealedLocalTimeline,
        input.convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.bufferDestroyRoute.operationId ||
      route.operationId ===
        requestAdapterNativeProgram.bufferMapAsyncRoute.operationId ||
      route.operationId === requestAdapterNativeProgram.bufferUnmapRoute.operationId
    ) {
      bufferLifecycleBody = validateBufferLifecycleRequestFields(
        input,
        manifest.maxPayloadBytes,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.queueWriteBufferRoute.operationId
    ) {
      queueWriteBufferBody = validateQueueWriteBufferRequestFields(
        input,
        manifest.maxPayloadBytes,
      );
      if (consumedQueueWriteBufferSnapshots.has(queueWriteBufferBody.bytes)) {
        throw new TypeError(
          'GPUQueue.writeBuffer source snapshot was already consumed',
        );
      }
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.queueSubmitRoute.operationId
    ) {
      queueSubmitBody = validateQueueSubmitRequestFields(
        input,
        queueSubmitRecordSpecs,
        manifest.maxPayloadBytes,
        objectKinds,
        manifest.layout,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.canvasConfigureRoute.operationId ||
      route.operationId ===
        requestAdapterNativeProgram.canvasUnconfigureRoute.operationId ||
      route.operationId ===
        requestAdapterNativeProgram.textureDestroyRoute.operationId
    ) {
      canvasServiceBody = validateCanvasServiceRequestFields(
        input,
        manifest.webIdlVocabulary.gpuTextureFormats,
        manifest.layout.sequenceMaxCount,
      );
    }
    const writer = new Writer(manifest.maxPayloadBytes);
    writeHeader(
      writer,
      manifest.layout.requestMagic,
      manifest.layout.version,
      codec.wireTag,
      route.wireId,
    );
    writeReference(writer, input.receiver, objectKinds);
    writer.u8(input.target ? 1 : 0);
    if (input.target) writeReference(writer, input.target, objectKinds);
    writer.u64(input.capturedScopeId);
    writer.u64(input.adapterOrdinal);
    writer.u64(input.deviceIngressOrdinal);
    writer.u64(input.queueIngressOrdinal);
    if (bufferLifecycleBody) {
      writeBufferLifecycleBody(
        writer,
        route.operationId,
        bufferLifecycleBody,
        manifest.maxPayloadBytes,
      );
      return writer.finish();
    }
    if (queueWriteBufferBody) {
      writeQueueWriteBufferBody(
        writer,
        queueWriteBufferBody,
        manifest.maxPayloadBytes,
        objectKinds,
      );
      const payload = writer.finish();
      consumedQueueWriteBufferSnapshots.add(queueWriteBufferBody.bytes);
      return payload;
    }
    if (queueSubmitBody) {
      writeQueueSubmitBody(writer, queueSubmitBody, objectKinds);
      return writer.finish();
    }
    writer.value(input.sealedLocalTimeline, manifest.layout);
    if (canvasServiceBody) {
      writeCanvasServiceBody(
        writer,
        route.operationId,
        canvasServiceBody,
        input.receiver,
        input.convertedArguments,
        objectKinds,
        manifest.webIdlVocabulary.gpuTextureFormats,
        manifest.layout.sequenceMaxCount,
      );
      return writer.finish();
    }
    writer.value(input.convertedArguments, manifest.layout);
    return writer.finish();
  };

  const encodeServiceRequest = (
    input: ProductionGpuServiceEncodingInput,
  ): Uint8Array => {
    const route = selectedRoute(input.operationId);
    if (input.wireId !== route.wireId) {
      throw new TypeError('WebGPU request wire identity mismatch');
    }
    if (route.providerSubmission === 'none') {
      throw new TypeError(`${input.operationId} has no service request codec`);
    }
    const codec = serviceCodecs.get(route.serviceArgumentCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service request codec');
    if (!codec.executableFromCurrentAuthenticatedInputs) {
      throw new TypeError(
        `${route.serviceArgumentCodec} is injection-incomplete; missing authenticated semantic fields: ` +
          codec.unavailableSemanticFields.join(', '),
      );
    }
    return encodeReviewedNativeRequestPayload(input);
  };

  const encodeNativeCodegenRequest = (
    input: ProductionGpuServiceEncodingInput,
  ): Uint8Array => {
    if (
      input.operationId !== requestAdapterNativeProgram.route.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.requestDeviceRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createBindGroupRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createBindGroupLayoutRoute.operationId &&
      input.operationId !== requestAdapterNativeProgram.createBufferRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createPipelineLayoutRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createComputePipelineRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createRenderPipelineRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createSamplerRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createTextureRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createTextureViewRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createCommandEncoderRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.createShaderModuleRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.deviceDestroyRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.bufferDestroyRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.bufferMapAsyncRoute.operationId &&
      input.operationId !== requestAdapterNativeProgram.bufferUnmapRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.queueWriteBufferRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.canvasConfigureRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.canvasUnconfigureRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.textureDestroyRoute.operationId &&
      input.operationId !==
        requestAdapterNativeProgram.queueSubmitRoute.operationId
    ) {
      throw new TypeError(
        `${input.operationId} has no reviewed native codegen request program`,
      );
    }
    return encodeReviewedNativeRequestPayload(input);
  };

  const decodeServiceResult = (
    operationId: string,
    event: OperationResultEvent,
  ): ProductionGpuDecodedResult => {
    const route = selectedRoute(operationId);
    if (event.operationId !== route.wireId) {
      throw new TypeError('WebGPU result operation identity mismatch');
    }
    const codec = completionCodecs.get(route.serviceCompletionCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service completion codec');
    const adapterCompletion = route.operationId ===
        requestAdapterNativeProgram.route.operationId &&
      route.serviceCompletionCodec === REQUEST_ADAPTER_COMPLETION_CODEC;
    if (
      adapterCompletion &&
      (event.kind !== requestAdapterNativeProgram.operationResultEventKind ||
        event.status !== 0 ||
        event.deviceTransition !==
          requestAdapterNativeProgram.unchangedDeviceTransition ||
        event.ingressLogicalDeviceId !== '0' ||
        event.ingressLogicalDeviceGeneration !== '0' ||
        event.ingressProviderGeneration !== '0' ||
        event.logicalDeviceId !== '0' ||
        event.logicalDeviceGeneration !== '0' ||
        event.providerGeneration !== '0')
    ) {
      throw new TypeError(
        'GPUAdapter result carries an invalid authenticated carrier',
      );
    }
    const nullableCompletion =
      adapterCompletion ||
      route.serviceCompletionCodec ===
        'nullable-gpu-error-service-completion-v1';
    const nullResultKind = adapterCompletion
      ? requestAdapterNativeProgram.nullResultKind
      : 2;
    if (nullableCompletion && event.resultKind === nullResultKind) {
      if (event.payload.byteLength !== 0) {
        throw new TypeError('WebGPU null result must carry zero payload bytes');
      }
      return Object.freeze({ kind: 'null' });
    }
    const reader = new Reader(event.payload, manifest.maxPayloadBytes);
    readHeader(
      reader,
      manifest.layout.resultMagic,
      manifest.layout.version,
      codec.wireTag,
      route.wireId,
    );
    if (adapterCompletion) {
      const present = reader.u8();
      if (
        present !== 1 ||
        event.resultKind !== requestAdapterNativeProgram.objectResultKind
      ) {
        throw new TypeError('Invalid nullable adapter result');
      }
      const objectId = positiveIdentity(reader.u64(), 'GPUAdapter.objectId');
      const objectGeneration = positiveIdentity(
        reader.u64(),
        'GPUAdapter.objectGeneration',
      );
      const providerGeneration = positiveIdentity(
        reader.u64(),
        'GPUAdapter.providerGeneration',
      );
      const serviceDetachedExpiredTag = reader.u8();
      if (
        serviceDetachedExpiredTag !== 0 &&
        serviceDetachedExpiredTag !== 1
      ) {
        throw new TypeError(
          'GPUAdapter result has invalid authenticated detached state',
        );
      }
      if (providerGeneration !== event.operationProviderGeneration) {
        throw new TypeError('GPUAdapter result provider provenance mismatch');
      }
      const featureCount = reader.u32();
      if (featureCount > manifest.layout.sequenceMaxCount) {
        throw new TypeError('GPUAdapter feature sequence exceeds the reviewed bound');
      }
      const features: string[] = [];
      for (let index = 0; index < featureCount; index += 1) {
        const feature = reader.string(manifest.maxPayloadBytes);
        if (
          !manifest.webIdlVocabulary.gpuFeatureNames.includes(feature) ||
          (index > 0 && feature <= features[index - 1])
        ) {
          throw new TypeError(
            'GPUAdapter features must be known, sorted, and unique',
          );
        }
        features.push(feature);
      }
      reader.done();
      return Object.freeze({
        kind: 'object',
        object: Object.freeze({
          kind: 'GPUAdapter',
          objectId,
          objectGeneration,
          providerGeneration,
          serviceDetachedExpired: serviceDetachedExpiredTag === 1,
          features: Object.freeze(features),
        }),
      });
    }
    if (route.serviceCompletionCodec === 'gpu-device-service-completion-v1') {
      const detachedAlreadyLost = validateRequestDeviceCompletionCarrier(
        event as DetachedOperationResultEvent,
        requestAdapterNativeProgram,
      );
      const objectId = positiveIdentity(reader.u64(), 'GPUDevice.objectId');
      const objectGeneration = positiveIdentity(
        reader.u64(),
        'GPUDevice.objectGeneration',
      );
      const logicalDeviceId = positiveIdentity(
        reader.u64(),
        'GPUDevice.logicalDeviceId',
      );
      const logicalDeviceGeneration = positiveIdentity(
        reader.u64(),
        'GPUDevice.logicalDeviceGeneration',
      );
      const providerGeneration = positiveIdentity(
        reader.u64(),
        'GPUDevice.providerGeneration',
      );
      if (
        logicalDeviceId !== event.logicalDeviceId ||
        logicalDeviceGeneration !== event.logicalDeviceGeneration ||
        providerGeneration !== event.providerGeneration
      ) {
        throw new TypeError('GPUDevice result provenance mismatch');
      }
      const queueObjectId = positiveIdentity(reader.u64(), 'GPUQueue.objectId');
      const queueObjectGeneration = positiveIdentity(
        reader.u64(),
        'GPUQueue.objectGeneration',
      );
      const featureCount = reader.u32();
      if (featureCount > manifest.layout.sequenceMaxCount) {
        throw new TypeError('GPUDevice feature sequence exceeds the reviewed bound');
      }
      const features: string[] = [];
      for (let index = 0; index < featureCount; index += 1) {
        const feature = reader.string(manifest.maxPayloadBytes);
        if (index > 0 && feature <= features[index - 1]) {
          throw new TypeError('GPUDevice features are not sorted and unique');
        }
        features.push(feature);
      }
      const limits: Record<string, number> = {};
      for (const name of manifest.completeLimitNames) {
        const decimal = reader.u64();
        const value = Number(decimal);
        if (!Number.isSafeInteger(value)) {
          throw new TypeError(`GPUDevice limit ${name} is not JS-safe`);
        }
        limits[name] = value;
      }
      const message = reader.string(manifest.layout.diagnosticMaxBytes);
      reader.done();
      let alreadyLost: Readonly<{ reason: 'unknown'; message: string }> | undefined;
      if (detachedAlreadyLost) {
        alreadyLost = Object.freeze({ reason: 'unknown', message });
      } else if (message !== '') {
        throw new TypeError('Live GPUDevice result carries detached-only diagnostics');
      }
      return Object.freeze({
        kind: 'object',
        object: Object.freeze({
          kind: 'GPUDevice',
          objectId,
          objectGeneration,
          logicalDeviceId,
          logicalDeviceGeneration,
          providerGeneration,
          features: Object.freeze(features),
          limits: Object.freeze(limits),
          queue: Object.freeze({
            objectId: queueObjectId,
            objectGeneration: queueObjectGeneration,
          }),
          alreadyLost,
        }),
      });
    }
    if (
      route.operationId === BUFFER_MAP_ASYNC_OPERATION_ID &&
      route.serviceCompletionCodec === BUFFER_MAP_ASYNC_COMPLETION_CODEC
    ) {
      if (
        event.resultKind !== requestAdapterNativeProgram.bytesResultKind ||
        event.deviceTransition !==
          requestAdapterNativeProgram.unchangedDeviceTransition ||
        event.promiseId === '0' ||
        event.providerAdmission !== requestAdapterNativeProgram.providerAdmitted ||
        event.physicalSequence === '0' ||
        event.receiverKind !== objectKinds.GPUBuffer ||
        event.receiverFlags !== 0 ||
        event.receiverId === '0' ||
        event.receiverGeneration === '0' ||
        event.targetKind !== 0 ||
        event.targetFlags !== 0 ||
        event.targetId !== '0' ||
        event.targetGeneration !== '0' ||
        event.adapterOrdinal !== '0' ||
        event.deviceIngressOrdinal === '0' ||
        event.queueIngressOrdinal !== '0' ||
        event.ingressLogicalDeviceId === '0' ||
        event.ingressLogicalDeviceGeneration === '0' ||
        event.ingressProviderGeneration === '0' ||
        event.logicalDeviceId === '0' ||
        event.logicalDeviceGeneration === '0' ||
        event.providerGeneration === '0' ||
        event.operationProviderGeneration === '0'
      ) {
        throw new TypeError('GPUBuffer.mapAsync completion carrier is invalid');
      }
      const variantTag = reader.u8();
      const variant = new Map<number, WebGpuCodecTestBufferMapResult['variant']>([
        [1, 'mapped-bytes'],
        [2, 'provider-operation-error'],
        [3, 'allocation-range-error'],
        [4, 'late-cancelled-cleanup'],
      ]).get(variantTag);
      if (!variant) {
        throw new TypeError('GPUBuffer.mapAsync completion variant is unknown');
      }
      const pendingMapGeneration = positiveIdentity(
        reader.u64(),
        'GPUBuffer.mapAsync completion generation',
      );
      const mode = reader.u32();
      const offset = reader.u64();
      const size = reader.u64();
      if (mode !== 1 && mode !== 2) {
        throw new TypeError('GPUBuffer.mapAsync completion mode is invalid');
      }
      const ownedBytes = variant === 'mapped-bytes'
        ? readOwnedMappedBytes(
          reader,
          manifest.maxPayloadBytes,
          'GPUBuffer mapped bytes',
        )
        : new Uint8Array(0);
      if (variant === 'mapped-bytes' && String(ownedBytes.byteLength) !== size) {
        throw new TypeError('GPUBuffer mapped byte extent does not match completion size');
      }
      reader.done();
      return Object.freeze({
        kind: 'value',
        value: Object.freeze({
          variant,
          pendingMapGeneration,
          mode,
          offset,
          size,
          ownedBytes,
        }),
      });
    }
    if (route.serviceCompletionCodec === 'nullable-gpu-error-service-completion-v1') {
      const present = reader.u8();
      if (present !== 1 || event.resultKind !== 4) {
        throw new TypeError('Invalid nullable GPUError result');
      }
      const errorKind = reader.u8();
      const message = reader.string(manifest.layout.diagnosticMaxBytes);
      reader.done();
      return Object.freeze({ kind: 'value', value: makeGpuError(errorKind, message) });
    }
    throw new TypeError(
      `${operationId} does not have a Promise-bearing service result codec`,
    );
  };

  const decodeDeviceLoss = (
    event: Extract<NativeGpuEventV2, { kind: 3 | 4 | 5 | 6 }>,
  ): Readonly<{ reason: 'destroyed' | 'unknown'; message: string }> => {
    const reader = new Reader(event.payload, manifest.maxPayloadBytes);
    if (reader.ascii4() !== manifest.layout.lossMagic) {
      throw new TypeError('Unknown WebGPU device-loss payload magic');
    }
    if (reader.u16() !== manifest.layout.version || reader.u16() !== 0) {
      throw new TypeError('Unknown WebGPU device-loss codec version');
    }
    const message = reader.string(manifest.layout.diagnosticMaxBytes);
    reader.done();
    if (event.kind === 3 || event.kind === 4) {
      if (!Number.isInteger(event.backendClass) || event.backendClass < 0 || event.backendClass > 5) {
        throw new TypeError('Unknown authenticated WebGPU backend class');
      }
      if (![1, 2, 3, 4, 5].includes(event.lossReason)) {
        throw new TypeError('Unknown authenticated WebGPU device-loss reason');
      }
      return Object.freeze({
        reason: event.lossReason === 2 ? 'destroyed' : 'unknown',
        message,
      });
    }
    return Object.freeze({ reason: 'unknown', message });
  };

  const inspectServiceRequest = (payload: ArrayBufferView): unknown => {
    const reader = new Reader(payload, manifest.maxPayloadBytes);
    if (reader.ascii4() !== manifest.layout.requestMagic) {
      throw new TypeError('Unknown WebGPU request payload magic');
    }
    if (reader.u16() !== manifest.layout.version) {
      throw new TypeError('Unknown WebGPU request codec version');
    }
    const codecTag = reader.u16();
    const codec = manifest.serviceArguments.find((row) => row.wireTag === codecTag);
    if (!codec) throw new TypeError(`Unknown WebGPU service request tag: ${codecTag}`);
    const wireId = reader.u32();
    const route = WEBGPU_PRODUCTION_PLAN.routes.find((row) => row.wireId === wireId);
    if (!route || route.serviceArgumentCodec !== codec.tag) {
      throw new TypeError('WebGPU request operation/codec mismatch');
    }
    const receiver = readReference(reader, objectKindsByTag);
    const targetPresence = reader.u8();
    if (targetPresence !== 0 && targetPresence !== 1) {
      throw new TypeError('Invalid WebGPU target presence tag');
    }
    const target = targetPresence === 1
      ? readReference(reader, objectKindsByTag)
      : null;
    const capturedScopeId = reader.u64();
    const adapterOrdinal = reader.u64();
    const deviceIngressOrdinal = reader.u64();
    const queueIngressOrdinal = reader.u64();
    const bufferLifecycleRoute =
      route.operationId === BUFFER_DESTROY_OPERATION_ID ||
      route.operationId === BUFFER_MAP_ASYNC_OPERATION_ID ||
      route.operationId === BUFFER_UNMAP_OPERATION_ID;
    const queueWriteBufferRoute =
      route.operationId === QUEUE_WRITE_BUFFER_OPERATION_ID;
    const queueSubmitRoute = route.operationId === QUEUE_SUBMIT_OPERATION_ID;
    const canvasServiceRoute =
      route.operationId === CANVAS_CONFIGURE_OPERATION_ID ||
      route.operationId === CANVAS_UNCONFIGURE_OPERATION_ID ||
      route.operationId === TEXTURE_DESTROY_OPERATION_ID;
    const bufferLifecycle = bufferLifecycleRoute
      ? readBufferLifecycleBody(
          reader,
          route.operationId,
          manifest.maxPayloadBytes,
        )
      : undefined;
    const queueWriteBuffer = queueWriteBufferRoute
      ? readQueueWriteBufferBody(
          reader,
          manifest.maxPayloadBytes,
          objectKindsByTag,
        )
      : undefined;
    const queueSubmit = queueSubmitRoute
      ? readQueueSubmitBody(
          reader,
          queueSubmitRecordSpecs,
          receiver,
          deviceIngressOrdinal,
          manifest.maxPayloadBytes,
          objectKinds,
          objectKindsByTag,
          manifest.layout,
        )
      : undefined;
    const closedBodyTimeline: readonly unknown[] = Object.freeze([]);
    const sealedLocalTimeline = queueSubmit
      ? queueSubmit.pendingTimeline
      : bufferLifecycleRoute || queueWriteBufferRoute
      ? closedBodyTimeline
      : reader.value(manifest.layout);
    const canvasService = canvasServiceRoute
      ? readCanvasServiceBody(
          reader,
          route.operationId,
          receiver,
          objectKindsByTag,
          manifest.webIdlVocabulary.gpuTextureFormats,
          manifest.layout.sequenceMaxCount,
        )
      : undefined;
    const convertedArguments = bufferLifecycle?.kind === 'map-async-v1'
      ? Object.freeze({
          mode: bufferLifecycle.mode,
          offset: u64Number(bufferLifecycle.offset, 'GPUBuffer.mapAsync offset'),
          ...(bufferLifecycle.requestedSizePresent === 1
            ? {
                size: u64Number(
                  bufferLifecycle.requestedSize,
                  'GPUBuffer.mapAsync requested size',
                ),
              }
            : {}),
        })
      : bufferLifecycleRoute
      ? null
      : queueWriteBuffer
      ? Object.freeze({
          buffer: queueWriteBuffer.destination,
          bufferOffset: u64Number(
            queueWriteBuffer.destinationOffset,
            'GPUQueue.writeBuffer destination offset',
          ),
          bytes: queueWriteBuffer.bytes,
        })
      : queueSubmit
      ? Object.freeze({
          commandBuffers: queueSubmit.commandBuffers,
          wrapperValidationError:
            queueSubmit.wrapperValidationError ?? undefined,
        })
      : canvasService?.kind === 'canvas-configure-v1'
      ? Object.freeze({
          format: canvasService.format,
          usage: canvasService.usage,
          viewFormats: canvasService.viewFormats,
          alphaMode: canvasService.alphaMode,
          colorSpace: canvasService.colorSpace,
          toneMapping: Object.freeze({ mode: canvasService.toneMappingMode }),
        })
      : canvasServiceRoute
      ? null
      : reader.value(manifest.layout);
    reader.done();
    if (route.operationId === requestAdapterNativeProgram.route.operationId) {
      validateRequestAdapterRequestFields(
        receiver,
        target,
        capturedScopeId,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.requestDeviceRoute.operationId
    ) {
      validateRequestDeviceRequestFields(
        receiver,
        target,
        capturedScopeId,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.layout.dictionaryMaxFields,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createBindGroupRoute.operationId
    ) {
      validateCreateBindGroupRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createBindGroupLayoutRoute.operationId
    ) {
      validateCreateBindGroupLayoutRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary.gpuTextureFormats,
      );
    } else if (
      route.operationId === requestAdapterNativeProgram.createBufferRoute.operationId
    ) {
      validateCreateBufferRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createPipelineLayoutRoute.operationId
    ) {
      validateCreatePipelineLayoutRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createComputePipelineRoute.operationId
    ) {
      validateCreateComputePipelineRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.layout.dictionaryMaxFields,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createRenderPipelineRoute.operationId
    ) {
      validateCreateRenderPipelineRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.layout.dictionaryMaxFields,
        manifest.webIdlVocabulary.gpuTextureFormats,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createSamplerRoute.operationId
    ) {
      validateCreateSamplerRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createTextureRoute.operationId
    ) {
      validateCreateTextureRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createTextureViewRoute.operationId
    ) {
      validateCreateTextureViewRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
        manifest.webIdlVocabulary,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createCommandEncoderRoute.operationId
    ) {
      validateCreateCommandEncoderRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.createShaderModuleRoute.operationId
    ) {
      validateCreateShaderModuleRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (
      route.operationId ===
        requestAdapterNativeProgram.deviceDestroyRoute.operationId
    ) {
      validateDeviceDestroyRequestFields(
        receiver,
        target,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline,
        convertedArguments,
        manifest.layout.sequenceMaxCount,
      );
    } else if (bufferLifecycle) {
      validateBufferLifecycleRequestFields({
        operationId: route.operationId,
        wireId: route.wireId,
        receiver,
        target: target ?? undefined,
        capturedScopeId,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline: closedBodyTimeline,
        convertedArguments,
        bufferLifecycle,
      }, manifest.maxPayloadBytes);
    } else if (queueWriteBuffer) {
      validateQueueWriteBufferRequestFields({
        operationId: route.operationId,
        wireId: route.wireId,
        receiver,
        target: target ?? undefined,
        capturedScopeId,
        adapterOrdinal,
        deviceIngressOrdinal,
        queueIngressOrdinal,
        sealedLocalTimeline: closedBodyTimeline,
        convertedArguments,
      }, manifest.maxPayloadBytes);
    } else if (queueSubmit) {
      submitReference(receiver, 'GPUQueue.submit receiver', 'GPUQueue');
      if (
        receiver.kind !== 'GPUQueue' ||
        target !== null ||
        adapterOrdinal !== '0' ||
        deviceIngressOrdinal === '0' ||
        queueIngressOrdinal === '0'
      ) {
        throw new TypeError('GPUQueue.submit decoded carrier projection is invalid');
      }
    } else if (canvasService) {
      if (!Array.isArray(sealedLocalTimeline)) {
        throw new TypeError('Canvas lifecycle timeline must be a closed sequence');
      }
      validateCanvasServiceRequestFields(
        {
          operationId: route.operationId,
          wireId: route.wireId,
          receiver,
          target: target ?? undefined,
          capturedScopeId,
          adapterOrdinal,
          deviceIngressOrdinal,
          queueIngressOrdinal,
          sealedLocalTimeline,
          convertedArguments,
          canvasService,
        },
        manifest.webIdlVocabulary.gpuTextureFormats,
        manifest.layout.sequenceMaxCount,
      );
    }
    const inspectedBufferLifecycle = bufferLifecycle?.kind === 'cleanup-v1'
      ? Object.freeze({
          ...bufferLifecycle,
          writeback: Object.freeze(Array.from(
            arrayBufferViewBytes(
              bufferLifecycle.writeback,
              'GPUBuffer cleanup writeback',
            ),
          )),
        })
      : bufferLifecycle;
    const inspectedConvertedArguments = queueWriteBuffer
      ? Object.freeze({
          buffer: queueWriteBuffer.destination,
          bufferOffset: u64Number(
            queueWriteBuffer.destinationOffset,
            'GPUQueue.writeBuffer destination offset',
          ),
          bytes: Object.freeze(Array.from(queueWriteBuffer.bytes)),
        })
      : convertedArguments;
    const result = frozenRecord({
      operationId: route.operationId,
      codec: codec.tag,
      receiver,
      target,
      capturedScopeId,
      adapterOrdinal,
      deviceIngressOrdinal,
      queueIngressOrdinal,
      sealedLocalTimeline,
      convertedArguments: inspectedConvertedArguments,
      ...(queueSubmit ? { recordTable: queueSubmit.recordTable } : {}),
      ...(inspectedBufferLifecycle
        ? { bufferLifecycle: inspectedBufferLifecycle }
        : {}),
      ...(canvasService ? { canvasService } : {}),
    });
    return result;
  };

  const encodeServiceResult = (
    operationId: string,
    result: WebGpuCodecTestServiceResult,
  ): Uint8Array => {
    const route = selectedRoute(operationId);
    const codec = completionCodecs.get(route.serviceCompletionCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service completion codec');
    const adapterCompletion = route.operationId ===
        requestAdapterNativeProgram.route.operationId &&
      route.serviceCompletionCodec === REQUEST_ADAPTER_COMPLETION_CODEC;
    if (
      result.kind === 'null' &&
      (adapterCompletion ||
        route.serviceCompletionCodec ===
          'nullable-gpu-error-service-completion-v1')
    ) {
      return new Uint8Array(0);
    }
    if (
      route.operationId === BUFFER_DESTROY_OPERATION_ID ||
      route.operationId === BUFFER_UNMAP_OPERATION_ID
    ) {
      if (result.kind !== 'buffer-cleanup') {
        throw new TypeError(
          `${route.operationId} completion test value has the wrong shape`,
        );
      }
      exactLifecycleKeys(
        result,
        ['kind', 'terminal'],
        `${route.operationId} completion`,
      );
      const allowed = route.operationId === BUFFER_DESTROY_OPERATION_ID
        ? [
            'repeat-cleanup-noop',
            'first-cleanup-rejection',
            'first-cleanup-provider',
          ]
        : ['unmapped-noop', 'cleanup-rejection', 'cleanup-provider'];
      if (!allowed.includes(result.terminal)) {
        throw new TypeError(`${route.operationId} cleanup terminal is invalid`);
      }
      return new Uint8Array(0);
    }
    if (
      route.operationId === CANVAS_CONFIGURE_OPERATION_ID ||
      route.operationId === CANVAS_UNCONFIGURE_OPERATION_ID ||
      route.operationId === TEXTURE_DESTROY_OPERATION_ID
    ) {
      if (result.kind !== 'canvas-terminal') {
        throw new TypeError(
          `${route.operationId} completion test value has the wrong shape`,
        );
      }
      exactLifecycleKeys(
        result,
        ['kind', 'terminal'],
        `${route.operationId} completion`,
      );
      const allowed = route.operationId === CANVAS_CONFIGURE_OPERATION_ID
        ? ['operation-success']
        : route.operationId === CANVAS_UNCONFIGURE_OPERATION_ID
          ? ['first-cleanup-provider']
          : ['repeat-cleanup-noop', 'first-cleanup-provider'];
      if (!allowed.includes(result.terminal)) {
        throw new TypeError(`${route.operationId} canvas terminal is invalid`);
      }
      return new Uint8Array(0);
    }
    if (route.operationId === QUEUE_WRITE_BUFFER_OPERATION_ID) {
      if (result.kind !== 'queue-write-buffer') {
        throw new TypeError(
          'GPUQueue.writeBuffer completion test value has the wrong shape',
        );
      }
      exactLifecycleKeys(
        result,
        ['kind', 'terminal'],
        'GPUQueue.writeBuffer completion',
      );
      if (
        result.terminal !== 'later-predicate-rejection' &&
        result.terminal !== 'operation-success'
      ) {
        throw new TypeError(
          'GPUQueue.writeBuffer completion terminal is invalid',
        );
      }
      return new Uint8Array(0);
    }
    if (
      (route.operationId ===
          requestAdapterNativeProgram.createBindGroupRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createBindGroupLayoutRoute.operationId ||
        route.operationId === requestAdapterNativeProgram.createBufferRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createPipelineLayoutRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createComputePipelineRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createRenderPipelineRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createSamplerRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createTextureRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createTextureViewRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createCommandEncoderRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.createShaderModuleRoute.operationId ||
        route.operationId ===
          requestAdapterNativeProgram.deviceDestroyRoute.operationId) &&
      route.serviceCompletionCodec === DEVICE_DESTROY_COMPLETION_CODEC
    ) {
      if (result.kind !== 'none') {
        throw new TypeError(
          `${route.operationId} completion test value has the wrong shape`,
        );
      }
      return new Uint8Array(0);
    }
    const writer = new Writer(manifest.maxPayloadBytes);
    writeHeader(
      writer,
      manifest.layout.resultMagic,
      manifest.layout.version,
      codec.wireTag,
      route.wireId,
    );
    if (route.operationId === BUFFER_MAP_ASYNC_OPERATION_ID) {
      if (result.kind !== 'buffer-map') {
        throw new TypeError('GPUBuffer.mapAsync completion test value has the wrong shape');
      }
      exactLifecycleKeys(result, [
        'kind',
        'variant',
        'pendingMapGeneration',
        'mode',
        'offset',
        'size',
        'ownedBytes',
      ], 'GPUBuffer.mapAsync completion');
      const tag = {
        'mapped-bytes': 1,
        'provider-operation-error': 2,
        'allocation-range-error': 3,
        'late-cancelled-cleanup': 4,
      }[result.variant];
      positiveIdentity(
        result.pendingMapGeneration,
        'GPUBuffer.mapAsync completion generation',
      );
      parseU64Decimal(result.offset);
      parseU64Decimal(result.size);
      if (result.mode !== 1 && result.mode !== 2) {
        throw new TypeError('GPUBuffer.mapAsync completion mode is invalid');
      }
      const ownedBytes = arrayBufferViewBytes(
        result.ownedBytes,
        'GPUBuffer.mapAsync completion bytes',
      );
      if (
        (result.variant === 'mapped-bytes' &&
          String(ownedBytes.byteLength) !== result.size) ||
        (result.variant !== 'mapped-bytes' && ownedBytes.byteLength !== 0)
      ) {
        throw new TypeError(
          'GPUBuffer.mapAsync completion byte ownership does not match its variant',
        );
      }
      writer.u8(tag);
      writer.u64(result.pendingMapGeneration);
      writer.u32(result.mode);
      writer.u64(result.offset);
      writer.u64(result.size);
      if (result.variant === 'mapped-bytes') {
        writeOwnedBytes(
          writer,
          result.ownedBytes,
          manifest.maxPayloadBytes,
          'GPUBuffer mapped bytes',
        );
      }
      return writer.finish();
    }
    if (adapterCompletion) {
      if (result.kind === 'adapter') {
        if (typeof result.serviceDetachedExpired !== 'boolean') {
          throw new TypeError(
            'GPUAdapter completion test value lacks authenticated detached state',
          );
        }
        writer.u8(1);
        writer.u64(positiveIdentity(result.objectId, 'GPUAdapter.objectId'));
        writer.u64(positiveIdentity(
          result.objectGeneration,
          'GPUAdapter.objectGeneration',
        ));
        writer.u64(positiveIdentity(
          result.providerGeneration,
          'GPUAdapter.providerGeneration',
        ));
        writer.u8(result.serviceDetachedExpired ? 1 : 0);
        const features = [...result.features];
        if (
          features.length > manifest.layout.sequenceMaxCount ||
          features.some(
            (feature, index) =>
              !manifest.webIdlVocabulary.gpuFeatureNames.includes(feature) ||
              (index > 0 && feature <= features[index - 1]),
          )
        ) {
          throw new TypeError(
            'Adapter completion features must be known, sorted, and unique',
          );
        }
        writer.u32(features.length);
        for (const feature of features) writer.string(feature);
      } else {
        throw new TypeError('Adapter completion test value has the wrong shape');
      }
      return writer.finish();
    }
    if (route.serviceCompletionCodec === 'gpu-device-service-completion-v1') {
      if (result.kind !== 'device') {
        throw new TypeError('Device completion test value has the wrong shape');
      }
      writer.u64(result.objectId);
      writer.u64(result.objectGeneration);
      writer.u64(result.logicalDeviceId);
      writer.u64(result.logicalDeviceGeneration);
      writer.u64(result.providerGeneration);
      writer.u64(result.queueObjectId);
      writer.u64(result.queueObjectGeneration);
      const features = [...result.features];
      if (
        features.length > manifest.layout.sequenceMaxCount ||
        features.some((feature, index) => index > 0 && feature <= features[index - 1])
      ) {
        throw new TypeError('Device completion features must be sorted and unique');
      }
      writer.u32(features.length);
      for (const feature of features) writer.string(feature);
      for (const name of manifest.completeLimitNames) {
        if (!Object.prototype.hasOwnProperty.call(result.limits, name)) {
          throw new TypeError(`Device completion omits required limit: ${name}`);
        }
        writer.u64(String(u64Number(result.limits[name], `GPUDevice limit ${name}`)));
      }
      writer.string(
        result.diagnosticMessage ?? '',
        manifest.layout.diagnosticMaxBytes,
      );
      return writer.finish();
    }
    if (route.serviceCompletionCodec === 'nullable-gpu-error-service-completion-v1') {
      if (result.kind === 'error') {
        writer.u8(1);
        writer.u8(result.errorKind);
        writer.string(result.message, manifest.layout.diagnosticMaxBytes);
      } else {
        throw new TypeError('GPUError completion test value has the wrong shape');
      }
      return writer.finish();
    }
    throw new TypeError(`${operationId} has no decodable service result`);
  };

  const encodeDeviceLoss = (message: string): Uint8Array => {
    const writer = new Writer(manifest.maxPayloadBytes);
    writer.ascii4(manifest.layout.lossMagic);
    writer.u16(manifest.layout.version);
    writer.u16(0);
    writer.string(message, manifest.layout.diagnosticMaxBytes);
    return writer.finish();
  };

  const encodeCanonicalValue = (value: unknown): Uint8Array => {
    const writer = new Writer(manifest.maxPayloadBytes);
    writer.value(value, manifest.layout);
    return writer.finish();
  };

  const deriveTextureOriginDigest = (
    input: ProductionGpuTextureOriginDigestInput,
  ): string => sha256HexUtf8(
    canonicalTextureOriginDigestInput(input, manifest.webIdlVocabulary),
  );

  const bundle: ExecutableWebGpuCodecBundle = Object.freeze({
    schema: 'ibex/webgpu-executable-codecs/1',
    operationSetDigest: manifest.digests.operationSet,
    semanticProgramDigest: manifest.digests.semanticProgramSet,
    runtimeRoutingDigest: manifest.digests.runtimeRouting,
    webgpuCVocabularyDigest: manifest.digests.webgpuCVocabulary,
    operationIds: Object.freeze(manifest.operationIds.slice()),
    deriveTextureOriginDigest,
    convertPublicArguments,
    encodeServiceRequest,
    decodeServiceResult,
    decodeDeviceLoss,
  });

  return Object.freeze({
    bundle,
    testSupport: Object.freeze({
      inspectServiceRequest,
      encodeNativeCodegenRequest,
      encodeServiceResult,
      encodeDeviceLoss,
      encodeCanonicalValue,
    }),
  });
}
