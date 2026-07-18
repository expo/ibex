// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Executable codecs are a separate generated authority. The checked-in route
// plan alone is intentionally insufficient to publish navigator.gpu.

import type { NativeGpuEventV2 } from './native-bridge';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';

export type ProductionGpuWrapperKind =
  | 'GPU'
  | 'GPUAdapter'
  | 'GPUBindGroupLayout'
  | 'GPUBuffer'
  | 'GPUPipelineLayout'
  | 'GPUSampler'
  | 'GPUCanvasContext'
  | 'GPUCommandBuffer'
  | 'GPUCommandEncoder'
  | 'GPUDevice'
  | 'GPUQueue'
  | 'GPURenderPassEncoder'
  | 'GPURenderPipeline'
  | 'GPUShaderModule'
  | 'GPUTexture'
  | 'GPUTextureView';

export interface ProductionGpuObjectIdentity {
  readonly kind: ProductionGpuWrapperKind;
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly logicalDeviceId?: string;
  readonly logicalDeviceGeneration?: string;
  readonly providerGeneration?: string;
  /** Required for GPUAdapter identities; never inferred or defaulted. */
  readonly serviceDetachedExpired?: boolean;
  readonly features?: readonly string[];
  readonly limits?: Readonly<Record<string, number>>;
  readonly queue?: Readonly<{
    objectId: string;
    objectGeneration: string;
  }>;
  readonly alreadyLost?: Readonly<{
    reason: 'destroyed' | 'unknown';
    message: string;
  }>;
}

export type ProductionGpuDecodedResult =
  | Readonly<{ kind: 'null' }>
  | Readonly<{ kind: 'value'; value: unknown }>
  | Readonly<{ kind: 'object'; object: ProductionGpuObjectIdentity }>;

export interface ProductionGpuFullObjectReference {
  readonly kind: ProductionGpuWrapperKind;
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
}

/** Closed, source-affine input to the codec-owned canvas-current digest. */
export interface ProductionGpuTextureOriginDigestInput {
  readonly originClass: 'canvas-current';
  readonly receiverTextureRef: ProductionGpuFullObjectReference;
  readonly contextRef: ProductionGpuFullObjectReference;
  readonly attachmentGeneration: string;
  readonly contextGeneration: string;
  readonly configurationGeneration: string;
  readonly currentEpoch: string;
  readonly mintOperationProvenance: Readonly<{
    readonly operationInstanceId: string;
    readonly deviceIngressOrdinal: string;
  }>;
  readonly configuredDeviceRef: ProductionGpuFullObjectReference;
  readonly format: string;
  readonly usage: number;
  readonly alphaMode: 'opaque' | 'premultiplied';
  readonly colorSpace: 'srgb' | 'display-p3';
  readonly targetAuthorityDigest: string;
  readonly surfaceAccountToken: string;
  readonly surfaceAccountGeneration: string;
}

export interface ProductionGpuCodecWrapperAccess {
  readonly reference: (
    value: unknown,
    expectedKind?: ProductionGpuWrapperKind,
  ) => Readonly<ProductionGpuFullObjectReference>;
}

export interface ProductionGpuServiceEncodingInput {
  readonly operationId: string;
  readonly wireId: number;
  readonly convertedArguments: unknown;
  readonly receiver: ReturnType<ProductionGpuCodecWrapperAccess['reference']>;
  readonly target?: ReturnType<ProductionGpuCodecWrapperAccess['reference']>;
  readonly capturedScopeId: string;
  readonly adapterOrdinal: string;
  readonly deviceIngressOrdinal: string;
  readonly queueIngressOrdinal: string;
  readonly sealedLocalTimeline: readonly unknown[];
}

/** Conversion runs at the public operation's declared timing, while encoding
 * is allowed only after wrapper-local validation and identity projection have
 * completed. The generated injection bundle implements this interface but is
 * deliberately not the embedded default until a matching native decoder and
 * every required authenticated semantic field exist.
 */
export interface ExecutableWebGpuCodecBundle {
  readonly schema: 'ibex/webgpu-executable-codecs/1';
  readonly operationSetDigest: string;
  readonly semanticProgramDigest: string;
  readonly runtimeRoutingDigest: string;
  readonly webgpuCVocabularyDigest: string;
  readonly operationIds: readonly string[];
  readonly deriveTextureOriginDigest: (
    input: ProductionGpuTextureOriginDigestInput,
  ) => string;
  readonly convertPublicArguments: (
    operationId: string,
    args: readonly unknown[],
    wrappers: ProductionGpuCodecWrapperAccess,
  ) => unknown;
  readonly encodeServiceRequest: (
    input: ProductionGpuServiceEncodingInput,
  ) => ArrayBuffer | ArrayBufferView;
  readonly decodeServiceResult: (
    operationId: string,
    event: Extract<NativeGpuEventV2, { kind: 1 }>,
  ) => ProductionGpuDecodedResult;
  readonly decodeDeviceLoss: (
    event: Extract<NativeGpuEventV2, { kind: 3 | 4 | 5 | 6 }>,
  ) => Readonly<{
    reason: 'destroyed' | 'unknown';
    message: string;
  }>;
}

/**
 * This remains undefined until the generated injection layout has a matching
 * native decoder and the manifest's unavailable semantic-field list is empty.
 * A route table, V2 carrier, or explicit test injection cannot substitute for
 * that production-readiness evidence.
 */
export const EMBEDDED_EXECUTABLE_WEBGPU_CODECS:
  | ExecutableWebGpuCodecBundle
  | undefined = undefined;

const EXPECTED_OPERATION_IDS = Object.freeze(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => route.operationId).sort(),
);

function isHexDigest(value: string): boolean {
  return /^[0-9a-f]{64}$/u.test(value);
}

export function validateExecutableWebGpuCodecs(
  value: ExecutableWebGpuCodecBundle | undefined,
): value is ExecutableWebGpuCodecBundle {
  if (!value || value.schema !== 'ibex/webgpu-executable-codecs/1') return false;
  if (
    !isHexDigest(value.operationSetDigest) ||
    !isHexDigest(value.semanticProgramDigest) ||
    !isHexDigest(value.runtimeRoutingDigest) ||
    !isHexDigest(value.webgpuCVocabularyDigest)
  ) {
    return false;
  }
  if (
    value.operationSetDigest !== WEBGPU_PRODUCTION_PLAN.digests.operationSet ||
    value.semanticProgramDigest !==
      WEBGPU_PRODUCTION_PLAN.digests.semanticProgramSet ||
    value.runtimeRoutingDigest !== WEBGPU_PRODUCTION_PLAN.digests.runtimeRouting ||
    value.webgpuCVocabularyDigest !==
      WEBGPU_PRODUCTION_PLAN.digests.webgpuCVocabulary
  ) {
    return false;
  }
  if (
    !Array.isArray(value.operationIds) ||
    value.operationIds.length !== WEBGPU_PRODUCTION_PLAN.routes.length
  ) {
    return false;
  }
  const actual = value.operationIds.slice().sort();
  if (actual.some((operationId, index) => operationId !== EXPECTED_OPERATION_IDS[index])) {
    return false;
  }
  return (
    typeof value.deriveTextureOriginDigest === 'function' &&
    typeof value.convertPublicArguments === 'function' &&
    typeof value.encodeServiceRequest === 'function' &&
    typeof value.decodeServiceResult === 'function' &&
    typeof value.decodeDeviceLoss === 'function'
  );
}

export { WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION } from './production-codecs.generated';
