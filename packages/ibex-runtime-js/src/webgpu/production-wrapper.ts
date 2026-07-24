// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Cross-repo design authority: Exact LLP 0379, sections 3.5 and 9.1.

import type {
  NativeGpuBridge,
  NativeGpuBridgeV2,
  NativeGpuCallMetadataV2,
  NativeGpuEventV2,
  NativeGpuPresentationAuthorityMetadataV2,
  NativeGpuPresentationAuthorityV2,
  NativeGpuSealedOperationAuthorityV2,
} from './native-bridge';
import {
  EMBEDDED_EXECUTABLE_WEBGPU_CODECS,
  type ExecutableWebGpuCodecBundle,
  type ProductionGpuBufferLifecycleEncoding,
  type ProductionGpuCanvasCurrentTextureOriginEncoding,
  type ProductionGpuCanvasServiceEncoding,
  type ProductionGpuDecodedResult,
  type ProductionGpuErrorScopeServiceEncoding,
  type ProductionGpuFullObjectReference,
  type ProductionGpuObjectIdentity,
  type ProductionGpuPresentationAuthorityEncoding,
  type ProductionGpuTextureOriginDigestInput,
  type ProductionGpuWrapperKind,
  validateExecutableWebGpuCodecs,
} from './production-codecs';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';
import { WEBGPU_OBJECT_KIND_TAGS } from './production-codecs.generated';
import { Event } from '../events/Event';
import { EventTarget } from '../events/EventTarget';
import { markNonTransferableArrayBuffer } from '../arraybuffer-detach';
import {
  createProductionGpuPrivateImageBitmapFactoryV1,
  type ProductionGpuDecodedImageAuthorityV1,
  type ProductionGpuExternalImageSnapshotV1,
} from './private-image-bitmap';

type ProductionRoute = (typeof WEBGPU_PRODUCTION_PLAN.routes)[number];
type ProductionGpuAllocatedWrapperKind = Exclude<
  ProductionGpuWrapperKind,
  'GPUExternalTexture'
>;

type ServiceSubmissionFailureKind =
  | 'bridge-threw'
  | 'submission-rejected';

const ROUTES = new Map<string, ProductionRoute>(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.operationId, route]),
);
const ROUTES_BY_WIRE = new Map<number, ProductionRoute>(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.wireId, route]),
);
const AUTHENTICATED_LOCAL_PROMOTIONS = new Set(
  WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.authenticatedPromotions.map(
    (promotion) => promotion.operationId,
  ),
);
const STAGED_LOCAL_RECORDS: ReadonlyMap<
  string,
  (typeof WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.operations)[number]
> = new Map(
  WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.operations
    .filter(
      (operation) => !AUTHENTICATED_LOCAL_PROMOTIONS.has(operation.operationId),
    )
    .map((operation) => [operation.operationId, operation] as const),
);
const STAGED_LOCAL_RECORDS_BY_ID = new Map(
  [...STAGED_LOCAL_RECORDS.values()].map(
    (operation) => [operation.localRecordId, operation] as const,
  ),
);
const MAX_LOCAL_RECORDS =
  WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.recordLimit;

const OBJECT_KINDS: Readonly<
  Record<ProductionGpuAllocatedWrapperKind, number>
> =
  WEBGPU_OBJECT_KIND_TAGS;
const IMPLEMENTED_WEBGPU_INTERFACE_KINDS = new WeakMap<
  object,
  ProductionGpuAllocatedWrapperKind
>();

// Capture trusted realm intrinsics before app code can replace the writable
// global binding. Structural lockdown freezes the intrinsic object, but it
// does not make globalThis.ArrayBuffer immutable.
const INTRINSIC_ARRAY_BUFFER = ArrayBuffer;
const INTRINSIC_ARRAY_BUFFER_IS_VIEW = INTRINSIC_ARRAY_BUFFER.isView;
const INTRINSIC_UINT8_ARRAY = Uint8Array;
const INTRINSIC_UINT32_ARRAY = Uint32Array;
const INTRINSIC_REFLECT_APPLY = Reflect.apply;
const INTRINSIC_REFLECT_CONSTRUCT = Reflect.construct;
const INTRINSIC_STRING_CHAR_CODE_AT = String.prototype.charCodeAt;
const INTRINSIC_STRING_FROM_CHAR_CODE = String.fromCharCode;
const INTRINSIC_OBJECT_CREATE = Object.create;
const INTRINSIC_OBJECT_DEFINE_PROPERTY = Object.defineProperty;
const INTRINSIC_OBJECT_FREEZE = Object.freeze;
const INTRINSIC_OBJECT_SET_PROTOTYPE_OF = Object.setPrototypeOf;
const INTRINSIC_EVENT_TARGET_DISPATCH = EventTarget.prototype.dispatchEvent;
const INTRINSIC_GLOBAL_THIS = globalThis;
// Ibex currently approximates the spec's dedicated WebGPU task source with
// one trusted zero-delay timer task per notification.
const INTRINSIC_SET_TIMEOUT =
  typeof INTRINSIC_GLOBAL_THIS.setTimeout === 'function'
    ? INTRINSIC_GLOBAL_THIS.setTimeout
    : undefined;
const LOWER_HEX_DIGITS = Object.freeze([
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
]);
const INTRINSIC_TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(
  INTRINSIC_UINT32_ARRAY.prototype,
) as object;
const INTRINSIC_TYPED_ARRAY_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  'length',
)?.get;
const INTRINSIC_TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  'buffer',
)?.get;
const INTRINSIC_TYPED_ARRAY_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  'byteOffset',
)?.get;
const INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  'byteLength',
)?.get;
const INTRINSIC_TYPED_ARRAY_TAG_GETTER = Object.getOwnPropertyDescriptor(
  INTRINSIC_TYPED_ARRAY_PROTOTYPE,
  Symbol.toStringTag,
)?.get;
const INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_GETTER =
  Object.getOwnPropertyDescriptor(INTRINSIC_ARRAY_BUFFER.prototype, 'byteLength')
    ?.get;
const EMPTY_BUFFER_WRITEBACK = INTRINSIC_REFLECT_CONSTRUCT(
  INTRINSIC_UINT8_ARRAY,
  [0],
) as Uint8Array;

// This is a construction-private memory-safety guard, deliberately no larger
// than the authenticated structural per-descriptor ceiling. It is not the
// leaf-plus-envelope reservation required to publish mapped buffers. Until the
// bridge can transfer an affine preallocation credit into the service ledger,
// mapped-buffer publication authority remains absent. Selected-build explicit
// codec injection does not grant that affine credit, and this guard is monotonic.
const PRIVATE_MAPPED_ALLOCATION_GUARD_MAX_BYTES = 268_435_456;
const PRIVATE_MAPPED_RANGE_LEASE_LIMIT = 4_096;
const MAX_UNCAPTURED_ERROR_COUNT = 1_024;
const MAX_UNCAPTURED_ERROR_DIAGNOSTIC_BYTES = 4_096;
const MAX_UNCAPTURED_ERROR_QUEUED_DIAGNOSTIC_BYTES =
  MAX_UNCAPTURED_ERROR_COUNT * MAX_UNCAPTURED_ERROR_DIAGNOSTIC_BYTES;

function decodeCanonicalGpuErrorDiagnostic(bytes: Uint8Array): string {
  const codeUnits: number[] = [];
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index++]!;
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
      throw new TypeError('Malformed UTF-8 in WebGPU error diagnostic');
    }
    for (let part = 0; part < remaining; part += 1) {
      if (index >= bytes.length) {
        throw new TypeError('Truncated UTF-8 in WebGPU error diagnostic');
      }
      const continuation = bytes[index++]!;
      if ((continuation & 0xc0) !== 0x80) {
        throw new TypeError('Malformed UTF-8 in WebGPU error diagnostic');
      }
      codePoint = (codePoint << 6) | (continuation & 0x3f);
    }
    if (
      codePoint < minimum ||
      codePoint > 0x10ffff ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    ) {
      throw new TypeError('Non-canonical UTF-8 in WebGPU error diagnostic');
    }
    const forbiddenControl =
      (codePoint <= 0x1f &&
       codePoint !== 0x09 &&
       codePoint !== 0x0a &&
       codePoint !== 0x0d) ||
      (codePoint >= 0x7f && codePoint <= 0x9f);
    if (forbiddenControl) {
      throw new TypeError('Forbidden control in WebGPU error diagnostic');
    }
    if (codePoint <= 0xffff) {
      codeUnits.push(codePoint);
    } else {
      const scalar = codePoint - 0x10000;
      codeUnits.push(
        0xd800 + (scalar >> 10),
        0xdc00 + (scalar & 0x3ff),
      );
    }
  }
  return INTRINSIC_REFLECT_APPLY(
    INTRINSIC_STRING_FROM_CHAR_CODE,
    undefined,
    codeUnits,
  ) as string;
}

interface LostController {
  readonly promise: Promise<unknown>;
  readonly resolve: (value: unknown) => void;
  settled: boolean;
}

interface DeviceState {
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
  readonly features: object;
  readonly featureNames: readonly string[];
  readonly limits: Readonly<Record<string, number>>;
  readonly lost: LostController;
  eventTarget: EventTarget | undefined;
  queue: object | undefined;
  destroyed: boolean;
  nextIngress: string;
  ingressExhausted: boolean;
  nextQueueIngress: string;
  queueIngressExhausted: boolean;
  nextScope: string;
  scopeExhausted: boolean;
  scopeStackGeneration: string;
  scopes: Array<Readonly<{ id: string; filter: string }>>;
  pendingLocalTimeline: unknown[];
  readonly pendingCurrentTextureMaterializations: Map<
    WrapperState,
    {
      readonly records: unknown[];
      readonly materializesOnPrefixCarrier: boolean;
    }
  >;
  readonly configuredCanvasContexts: Set<WrapperState>;
  readonly buffers: Set<WrapperState>;
}

interface PendingBufferMapState {
  readonly generation: string;
  readonly mode: 1 | 2;
  readonly offset: number;
  readonly size: number;
  readonly promise: Promise<undefined>;
  readonly resolve: () => void;
  readonly reject: (error: unknown) => void;
  settled: boolean;
  operationInstanceId: string | undefined;
  promiseId: string | undefined;
}

interface BufferMappedRangeLease {
  readonly offset: number;
  readonly size: number;
  readonly bytes: ArrayBuffer;
  live: boolean;
}

interface ActiveBufferMappingState {
  readonly generation: string;
  readonly mode: 1 | 2;
  readonly offset: number;
  readonly size: number;
  /** The exact affine view retained from the codec or mapped-at-creation root. */
  readonly bytes: Uint8Array;
  readonly ranges: BufferMappedRangeLease[];
}

interface PendingBufferCleanupState {
  readonly operationId: 'GPUBuffer.destroy' | 'GPUBuffer.unmap';
  readonly body: Extract<ProductionGpuBufferLifecycleEncoding, { kind: 'cleanup-v1' }>;
}

type CanvasContextLifecycle =
  | 'attached-unconfigured'
  | 'configured'
  | 'lost'
  | 'stale'
  | 'revoked';

type CanvasCurrentTextureOriginState = Readonly<
  Omit<ProductionGpuTextureOriginDigestInput, 'receiverTextureRef'> & {
    readonly textureOriginDigest: string;
  }
>;

interface WrapperState {
  readonly realm: RealmState;
  readonly kind: ProductionGpuAllocatedWrapperKind;
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly wrapper: object;
  device: DeviceState | undefined;
  providerGeneration: string;
  nextAdapterOrdinal: string;
  adapterOrdinalExhausted: boolean;
  expired: boolean;
  serviceDetached: boolean;
  retired: boolean;
  status: string;
  invalid: boolean;
  activePass: WrapperState | undefined;
  encoder: WrapperState | undefined;
  records: unknown[];
  debugGroupDepth: number;
  readonly boundBindGroups: Map<number, BoundBindGroupState>;
  readonly usedBindGroups: Set<WrapperState>;
  currentPipeline: WrapperState | undefined;
  indexBufferBinding: Readonly<{
    buffer: WrapperState;
    indexFormat: 'uint16' | 'uint32';
    offset: number;
    size: number;
  }> | undefined;
  bindGroupLayoutEntries: readonly BindGroupLayoutBufferEntry[] | undefined;
  bindGroupLayout: WrapperState | undefined;
  bindGroupBufferBindings: readonly BindGroupBufferBinding[] | undefined;
  submitted: boolean;
  configuration: Record<string, unknown> | undefined;
  configurationGeneration: string;
  currentEpoch: string;
  currentTexture: object | undefined;
  configuredDevice: DeviceState | undefined;
  configuredDeviceWrapper: object | undefined;
  canvasAuthority: ProductionGpuCanvasContextAuthority | undefined;
  canvasContextLifecycle: CanvasContextLifecycle | undefined;
  destroyed: boolean;
  textureExpired: boolean;
  textureExpiryAccepted: boolean;
  materialized: boolean;
  presentationAuthorityRetirement: 'live' | 'retiring' | 'retired';
  currentOrigin: CanvasCurrentTextureOriginState | undefined;
  adapterFeatures: object | undefined;
  adapterFeatureNames: readonly string[] | undefined;
  bufferSize: number | undefined;
  bufferUsage: number | undefined;
  bufferMapState: 'mapped' | 'pending' | 'unmapped' | undefined;
  bufferNextMapGeneration: string;
  bufferMapGenerationExhausted: boolean;
  bufferNextCleanupGeneration: string;
  bufferCleanupGenerationExhausted: boolean;
  bufferPendingMap: PendingBufferMapState | undefined;
  bufferActiveMapping: ActiveBufferMappingState | undefined;
  bufferPendingCleanup: PendingBufferCleanupState | undefined;
  querySetCount: number | undefined;
  querySetType: 'occlusion' | 'timestamp' | undefined;
  textureDimension: '1d' | '2d' | '3d' | undefined;
  textureFormat: string | undefined;
  textureUsage: number | undefined;
  textureWidth: number | undefined;
  textureHeight: number | undefined;
  textureDepthOrArrayLayers: number | undefined;
  drawingBufferWidth: number | undefined;
  drawingBufferHeight: number | undefined;
}

interface BindGroupLayoutBufferEntry {
  readonly binding: number;
  readonly hasDynamicOffset: boolean;
  readonly minBindingSize: number;
}

interface BindGroupBufferBinding {
  readonly binding: number;
  readonly buffer: WrapperState;
  readonly offset: number;
}

interface BoundBindGroupState {
  readonly bindGroup: WrapperState | null;
  readonly dynamicOffsets: readonly number[];
}

/** Host-authenticated, construction-private canvas identity and authority. */
export interface ProductionGpuCanvasContextAuthority {
  readonly attachmentGeneration: string;
  readonly contextGeneration: string;
  readonly targetAuthorityDigest: string;
  readonly surfaceAccountToken: string;
  readonly surfaceAccountGeneration: string;
}

interface PendingPromiseCall {
  readonly route: ProductionRoute;
  readonly promiseId: string;
  readonly deviceKey: string | undefined;
}

interface PendingUncapturedError {
  readonly deviceKey: string;
  readonly target: EventTarget;
  readonly message: string;
  /** Fully typed and snapshotted at ingress; never reconstructed in the task. */
  readonly error: object;
  /** Original UTF-8 extent retained for aggregate diagnostic accounting. */
  readonly eventByteLength: number;
}

interface PendingSealedBatch {
  readonly childIds: readonly string[];
  readonly outerOperationId: number;
  readonly outerWantsPromise: boolean;
  readonly outerMetadata: NativeGpuCallMetadataV2;
  nextTerminalIndex: number;
  accepted: boolean;
  parentOperationInstanceId: string | undefined;
  parentPromiseId: string | undefined;
  carrierAuthorityContextDigest: string | undefined;
  terminalObserved: boolean;
}

interface PendingSealedOperation {
  readonly authority: NativeGpuSealedOperationAuthorityV2;
  readonly deviceKey: string;
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
  readonly operationProviderGeneration: string;
  readonly batch: PendingSealedBatch;
}

interface RealmState {
  readonly bridge: NativeGpuBridgeV2;
  readonly codecs: ExecutableWebGpuCodecBundle;
  readonly prototypes: Readonly<
    Record<ProductionGpuAllocatedWrapperKind, object>
  >;
  readonly wrappers: WeakMap<object, WrapperState>;
  readonly devices: Map<string, DeviceState>;
  readonly buffers: Set<WrapperState>;
  readonly hostCanvasContextsByIdentity: Map<string, WrapperState>;
  readonly currentHostCanvasContextByObject: Map<string, WrapperState>;
  readonly currentHostCanvasContextBySurfaceToken: Map<string, WrapperState>;
  readonly pendingCanvasTextureExpiries: Set<WrapperState>;
  readonly pendingPromiseCalls: Map<string, PendingPromiseCall>;
  readonly pendingSealedOperations: Map<string, PendingSealedOperation>;
  readonly pendingSealedBatches: Map<string, PendingSealedBatch>;
  readonly provisionalSealedBatches: Set<PendingSealedBatch>;
  readonly resultEvents: Map<
    string,
    Extract<NativeGpuEventV2, { kind: 1 }>
  >;
  readonly pendingUncapturedErrors: PendingUncapturedError[];
  pendingUncapturedDiagnosticBytes: number;
  uncapturedErrorTaskScheduled: boolean;
  nextLocalObjectId: string;
  localObjectIdExhausted: boolean;
  nextLocalOperationInstanceId: string;
  localOperationInstanceIdExhausted: boolean;
  allocatedWrapperCount: number;
  readonly privateMappedAllocationGuardLimitBytes: number;
  privateMappedAllocationGuardBytes: number;
  canvasLossTransitionCount: number;
  activePassCount: number;
  closeReason: string | undefined;
  lastCloseSnapshot: ProductionWebGpuPrivateBindingInspection | undefined;
  active: boolean;
}

export interface ProductionWebGpuPrivateBindingInspection {
  readonly active: boolean;
  readonly closeReason: string | undefined;
  readonly allocatedWrapperCount: number;
  readonly privateMappedAllocationGuardLimitBytes: number;
  readonly privateMappedAllocationGuardBytes: number;
  readonly canvasLossTransitionCount: number;
  readonly activePassCount: number;
  readonly trackedBufferLifecycleCount: number;
  readonly routedDeviceCount: number;
  readonly indexedCanvasContextCount: number;
  readonly indexedCanvasObjectCount: number;
  readonly indexedCanvasSurfaceTokenCount: number;
  readonly invalidCurrentTextureCount: number;
  readonly pendingLocalRecordCount: number;
  readonly pendingPromiseCount: number;
}

export interface ProductionWebGpuPrivateBindingTestOptions {
  readonly counterSeeds?: Readonly<{
    nextLocalObjectId?: string;
    nextLocalOperationInstanceId?: string;
    nextAdapterOrdinal?: string;
    nextDeviceIngressOrdinal?: string;
    nextQueueIngressOrdinal?: string;
    nextScopeId?: string;
    canvasConfigurationGeneration?: string;
    canvasCurrentEpoch?: string;
    nextBufferMapGeneration?: string;
    nextBufferCleanupGeneration?: string;
  }>;
  readonly privateMappedAllocationGuardLimitBytes?: number;
  readonly enableStateInspection?: boolean;
}

export interface ProductionWebGpuPrivateBinding {
  readonly gpu: object;
  readonly interfaceObjects: Readonly<Record<string, object>>;
  readonly constantObjects: Readonly<Record<string, object>>;
  readonly createImageBitmap?: (
    source: import('../blob/Blob').Blob,
  ) => Promise<object>;
  readonly snapshotImageBitmapForCopy?: (
    bitmap: unknown,
  ) => ProductionGpuExternalImageSnapshotV1;
  readonly mintCanvasContext: (
    identity: Readonly<{
      objectId: string;
      objectGeneration: string;
      drawingBufferWidth: number;
      drawingBufferHeight: number;
      authority: ProductionGpuCanvasContextAuthority;
    }>,
  ) => object;
  /**
   * Construction-private end-of-host-task control. Native invokes it only
   * after the outer runtime-owner task has fully drained its continuations.
   */
  readonly checkpointHostTask: () => void;
  readonly revoke: () => void;
  readonly inspectForTest?: () => Readonly<{
    current: ProductionWebGpuPrivateBindingInspection;
    lastClose: ProductionWebGpuPrivateBindingInspection | undefined;
  }>;
}

export interface ProductionWebGpuPrivateBindingExtensions {
  readonly decodedImageAuthority?: ProductionGpuDecodedImageAuthorityV1;
}

/**
 * Construction-private authority handed only to Exact's native Canvas
 * integration. It deliberately delegates one operation instead of exposing
 * the complete wrapper binding or its public-surface installation state.
 */
export interface ProductionGpuCanvasContextMinter {
  readonly mintCanvasContext: ProductionWebGpuPrivateBinding['mintCanvasContext'];
}

const TYPEGPU_WORKLOAD_STAGING = Object.freeze({
  scopeId: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.scopeId,
  status: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.status,
  supportClaim: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.supportClaim,
  conditionalExecutionLane:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.conditionalExecutionLane,
  nativeExecutionEvidence:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.nativeExecutionEvidence,
  typegpuVersion: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.typegpuVersion,
  activeRouteOperationCount:
    WEBGPU_PRODUCTION_PLAN.activeRouteSubset.operationCount,
  workloadOperationCount:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.operationCount,
  additionalOperationCount:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.additionalOperationCount,
  additionalOperations: Object.freeze(
    (
      WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.additionalOperations as readonly Readonly<
        Record<string, unknown>
      >[]
    ).map((operation) => Object.freeze({ ...operation })),
  ),
  localRecordingSubset: Object.freeze({
    ...WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset,
    operations: Object.freeze(
      WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.localRecordingSubset.operations
        .map((operation) => Object.freeze({ ...operation })),
    ),
  }),
  claimBoundaryAbsences: Object.freeze([
    ...WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.claimBoundaryAbsences,
  ]),
  publicSurfaceRule:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.publicSurfaceRule,
  embeddedCodecRule:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.embeddedCodecRule,
});

/**
 * Selected-build execution evidence for the pinned TypeGPU workloads.
 * The authenticated local-recording subset executes inside the private
 * wrapper without provider submission. Default/public/worker installation,
 * platform qualification, CTS evidence, and support claims remain absent.
 */
export function describeProductionWebGpuWorkloadStaging() {
  return TYPEGPU_WORKLOAD_STAGING;
}

export type ProductionWebGpuInstallResult =
  | Readonly<{
    status: 'not-installed';
    reason:
      | 'provider-absent'
      | 'abi-v2-required'
      | 'not-app-realm'
      | 'executable-codecs-unavailable'
      | 'navigator-unavailable'
      | 'public-surface-conflict';
  }>
  | Readonly<{
    status: 'installed';
    revoke: () => void;
    canvasContextMinter: Readonly<ProductionGpuCanvasContextMinter>;
    checkpointHostTask: () => void;
  }>;

const U64_MAX_DECIMAL = '18446744073709551615';

function isCanonicalU64Decimal(value: unknown, positive: boolean): value is string {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    return false;
  }
  if (positive && value === '0') return false;
  return value.length < U64_MAX_DECIMAL.length ||
    (value.length === U64_MAX_DECIMAL.length && value <= U64_MAX_DECIMAL);
}

/** Exact private u64 arithmetic; it rejects overflow before changing state. */
export function incrementCanonicalU64Decimal(value: string): string {
  if (!isCanonicalU64Decimal(value, false)) {
    throw new TypeError('WebGPU counter must be a canonical unsigned 64-bit decimal');
  }
  if (value === U64_MAX_DECIMAL) {
    throw new RangeError('WebGPU counter exceeds unsigned 64-bit capacity');
  }
  const digits = value.split('');
  let carry = 1;
  for (let index = digits.length - 1; index >= 0 && carry; index -= 1) {
    const next = Number(digits[index]) + carry;
    digits[index] = String(next % 10);
    carry = next >= 10 ? 1 : 0;
  }
  if (carry) digits.unshift('1');
  return digits.join('');
}

function isPositiveDecimal(value: string): boolean {
  return isCanonicalU64Decimal(value, true);
}

function compareCanonicalU64Decimal(left: string, right: string): number {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return left === right ? 0 : left < right ? -1 : 1;
}

function hostCanvasContextIdentityKey(
  objectId: string,
  objectGeneration: string,
): string {
  return `GPUCanvasContext/${objectId}/${objectGeneration}`;
}

function hostCanvasContextObjectKey(objectId: string): string {
  return `GPUCanvasContext/${objectId}`;
}

function snapshotOwnEnumerableDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
  message: string,
): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null) throw new TypeError(message);
  // This is the sole observation of the source object. In particular, it
  // never invokes a source getter and never follows inherited properties.
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const ownKeys = Reflect.ownKeys(descriptors);
  if (
    ownKeys.length !== expectedKeys.length ||
    ownKeys.some((key) => typeof key !== 'string')
  ) {
    throw new TypeError(message);
  }
  const sortedKeys = (ownKeys as string[]).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (sortedKeys.some((key, index) => key !== sortedExpected[index])) {
    throw new TypeError(message);
  }
  const snapshot: Record<string, unknown> = Object.create(null);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError(message);
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function freezeCanvasAuthority(
  value: unknown,
): ProductionGpuCanvasContextAuthority {
  const expectedKeys = [
    'attachmentGeneration',
    'contextGeneration',
    'surfaceAccountGeneration',
    'surfaceAccountToken',
    'targetAuthorityDigest',
  ];
  const snapshot = snapshotOwnEnumerableDataRecord(
    value,
    expectedKeys,
    'GPUCanvasContext authority is incomplete or malformed',
  );
  const attachmentGeneration = snapshot.attachmentGeneration;
  const contextGeneration = snapshot.contextGeneration;
  const targetAuthorityDigest = snapshot.targetAuthorityDigest;
  const surfaceAccountToken = snapshot.surfaceAccountToken;
  const surfaceAccountGeneration = snapshot.surfaceAccountGeneration;
  if (
    typeof attachmentGeneration !== 'string' ||
    !isPositiveDecimal(attachmentGeneration) ||
    typeof contextGeneration !== 'string' ||
    !isPositiveDecimal(contextGeneration) ||
    typeof targetAuthorityDigest !== 'string' ||
    !/^[0-9a-f]{64}$/u.test(targetAuthorityDigest) ||
    typeof surfaceAccountToken !== 'string' ||
    !isPositiveDecimal(surfaceAccountToken) ||
    typeof surfaceAccountGeneration !== 'string' ||
    !isPositiveDecimal(surfaceAccountGeneration)
  ) {
    throw new TypeError('GPUCanvasContext authority is incomplete or malformed');
  }
  return Object.freeze({
    attachmentGeneration,
    contextGeneration,
    targetAuthorityDigest,
    surfaceAccountToken,
    surfaceAccountGeneration,
  });
}

interface CapturedCanvasContextIdentity {
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly drawingBufferWidth: number;
  readonly drawingBufferHeight: number;
  readonly authority: ProductionGpuCanvasContextAuthority;
}

function captureCanvasContextIdentity(value: unknown): CapturedCanvasContextIdentity {
  const snapshot = snapshotOwnEnumerableDataRecord(
    value,
    [
      'objectId',
      'objectGeneration',
      'drawingBufferWidth',
      'drawingBufferHeight',
      'authority',
    ],
    'GPUCanvasContext identity is incomplete or malformed',
  );
  if (!isPositiveDecimal(snapshot.objectId as string)) {
    throw new TypeError('Invalid GPUCanvasContext object identity');
  }
  if (!isPositiveDecimal(snapshot.objectGeneration as string)) {
    throw new TypeError('Invalid GPUCanvasContext object generation');
  }
  return Object.freeze({
    objectId: snapshot.objectId as string,
    objectGeneration: snapshot.objectGeneration as string,
    drawingBufferWidth: drawingBufferCoordinate(
      snapshot.drawingBufferWidth,
      'GPUCanvasContext drawingBufferWidth',
    ),
    drawingBufferHeight: drawingBufferCoordinate(
      snapshot.drawingBufferHeight,
      'GPUCanvasContext drawingBufferHeight',
    ),
    authority: freezeCanvasAuthority(snapshot.authority),
  });
}

function sameCanvasAuthority(
  left: ProductionGpuCanvasContextAuthority,
  right: ProductionGpuCanvasContextAuthority,
): boolean {
  return left.attachmentGeneration === right.attachmentGeneration &&
    left.contextGeneration === right.contextGeneration &&
    left.targetAuthorityDigest === right.targetAuthorityDigest &&
    left.surfaceAccountToken === right.surfaceAccountToken &&
    left.surfaceAccountGeneration === right.surfaceAccountGeneration;
}

function isStrictCanvasLineageSuccessor(
  predecessor: ProductionGpuCanvasContextAuthority,
  successor: ProductionGpuCanvasContextAuthority,
): boolean {
  if (predecessor.surfaceAccountToken !== successor.surfaceAccountToken) return false;
  const accountOrder = compareCanonicalU64Decimal(
    successor.surfaceAccountGeneration,
    predecessor.surfaceAccountGeneration,
  );
  const attachmentOrder = compareCanonicalU64Decimal(
    successor.attachmentGeneration,
    predecessor.attachmentGeneration,
  );
  const contextOrder = compareCanonicalU64Decimal(
    successor.contextGeneration,
    predecessor.contextGeneration,
  );
  if (accountOrder > 0) return true;
  if (accountOrder < 0) return false;
  return attachmentOrder > 0 && contextOrder > 0;
}

function route(operationId: string): ProductionRoute {
  const selected = ROUTES.get(operationId);
  if (!selected) throw new Error(`Unreviewed WebGPU operation: ${operationId}`);
  return selected;
}

function namedError(name: string, message: string): Error {
  const error = new Error(message);
  Object.defineProperty(error, 'name', {
    value: name,
    writable: false,
    enumerable: false,
    configurable: true,
  });
  return error;
}

function makeLostController(): LostController {
  let resolvePromise: ((value: unknown) => void) | undefined;
  const promise = new Promise<unknown>((resolve) => {
    resolvePromise = resolve;
  });
  return {
    promise,
    resolve(value: unknown): void {
      resolvePromise?.(value);
    },
    settled: false,
  };
}

function defineMethod(
  prototype: object,
  name: PropertyKey,
  implementation: (...args: unknown[]) => unknown,
): void {
  Object.defineProperty(prototype, name, {
    value: implementation,
    writable: false,
    enumerable: true,
    configurable: false,
  });
}

function defineGetter(
  prototype: object,
  name: PropertyKey,
  implementation: () => unknown,
): void {
  Object.defineProperty(prototype, name, {
    get: implementation,
    enumerable: true,
    configurable: false,
  });
}

function installReadonlyFeatureSetPrototype(
  prototype: object,
  states: WeakMap<object, readonly string[]>,
): void {
  const requireState = (value: unknown): readonly string[] => {
    if (typeof value !== 'object' || value === null || !states.has(value)) {
      throw new TypeError('Incompatible GPUSupportedFeatures receiver');
    }
    return states.get(value)!;
  };
  defineGetter(prototype, 'size', function (this: object) {
    return requireState(this).length;
  });
  defineMethod(prototype, 'has', function (this: object, feature: unknown) {
    return requireState(this).includes(String(feature));
  });
  defineMethod(prototype, 'keys', function (this: object) {
    return requireState(this).slice()[Symbol.iterator]();
  });
  defineMethod(prototype, 'values', function (this: object) {
    return requireState(this).slice()[Symbol.iterator]();
  });
  defineMethod(prototype, 'entries', function (this: object) {
    return requireState(this)
      .map((value) => [value, value] as const)
      [Symbol.iterator]();
  });
  defineMethod(
    prototype,
    'forEach',
    function (this: object, callback: unknown, thisArg?: unknown) {
      if (typeof callback !== 'function') {
        throw new TypeError('GPUSupportedFeatures callback must be callable');
      }
      for (const value of requireState(this)) {
        Reflect.apply(callback, thisArg, [value, value, this]);
      }
    },
  );
  defineMethod(prototype, Symbol.iterator, function (this: object) {
    return requireState(this).slice()[Symbol.iterator]();
  });
  Object.freeze(prototype);
}

function normalizeFeatureNames(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values.map((value) => String(value)))].sort());
}

function createReadonlyFeatureSet(
  values: readonly string[],
  prototype: object,
  states: WeakMap<object, readonly string[]>,
): object {
  const ordered = normalizeFeatureNames(values);
  const result = Object.create(prototype) as object;
  states.set(result, Object.freeze(ordered));
  return Object.freeze(result);
}

function createPrototypeTable(): Record<
  ProductionGpuAllocatedWrapperKind,
  object
> {
  return {
    GPU: Object.create(null),
    GPUAdapter: Object.create(null),
    GPUBindGroup: Object.create(null),
    GPUBindGroupLayout: Object.create(null),
    GPUBuffer: Object.create(null),
    GPUPipelineLayout: Object.create(null),
    GPUSampler: Object.create(null),
    GPUCanvasContext: Object.create(null),
    GPUCommandBuffer: Object.create(null),
    GPUCommandEncoder: Object.create(null),
    // These identities are part of the authenticated private object-kind
    // vocabulary. Keeping their prototypes in the closed table makes wrapper
    // allocation exhaustive without granting an app-visible constructor;
    // publication still requires the separately authenticated install gate.
    GPUComputePipeline: Object.create(null),
    GPUComputePassEncoder: Object.create(null),
    GPUDevice: Object.create(EventTarget.prototype),
    GPUQueue: Object.create(null),
    GPURenderPassEncoder: Object.create(null),
    GPURenderPipeline: Object.create(null),
    GPUQuerySet: Object.create(null),
    GPUShaderModule: Object.create(null),
    GPUTexture: Object.create(null),
    GPUTextureView: Object.create(null),
  };
}

function currentScopeId(device: DeviceState | undefined): string {
  if (!device || device.scopes.length === 0) return '0';
  return device.scopes[device.scopes.length - 1].id;
}

function deviceKey(
  logicalDeviceId: string,
  logicalDeviceGeneration: string,
  providerGeneration: string,
): string {
  return `${logicalDeviceId}/${logicalDeviceGeneration}/${providerGeneration}`;
}

function cloneConfiguration(
  value: Record<string, unknown>,
): Record<string, unknown> {
  const clone: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    const member = value[key];
    if (key === 'viewFormats' && Array.isArray(member)) {
      clone[key] = member.slice();
    } else if (
      key === 'toneMapping' &&
      typeof member === 'object' &&
      member !== null &&
      !Array.isArray(member)
    ) {
      clone[key] = { ...(member as Record<string, unknown>) };
    } else {
      clone[key] = member;
    }
  }
  return clone;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
    throw new TypeError(`${label} must be a dictionary`);
  }
  return value as Record<string, unknown>;
}

function stagedDictionary(
  value: unknown,
  label: string,
): Record<PropertyKey, unknown> {
  if (value === undefined || value === null) return Object.create(null);
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
    throw new TypeError(`${label} must be a dictionary`);
  }
  return value as Record<PropertyKey, unknown>;
}

function stagedU32(value: unknown, label: string, defaultValue?: number): number {
  if (value === undefined && defaultValue !== undefined) return defaultValue;
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

function stagedU64(value: unknown, label: string, defaultValue?: number): number {
  if (value === undefined && defaultValue !== undefined) return defaultValue;
  const converted = +(value as number);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be an unsigned 64-bit integer`);
  }
  const integer = Math.trunc(converted);
  if (integer < 0 || integer > Number.MAX_SAFE_INTEGER) {
    throw new TypeError(`${label} must be an unsigned 64-bit integer`);
  }
  return Object.is(integer, -0) ? 0 : integer;
}

function stagedString(value: unknown, label: string): string {
  if (typeof value === 'symbol') throw new TypeError(`${label} cannot be a Symbol`);
  return String(value);
}

function stagedUsvString(value: unknown, label: string): string {
  const converted = stagedString(value, label);
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

function stagedEnum(
  value: unknown,
  allowed: readonly string[],
  label: string,
): string {
  const converted = stagedString(value, label);
  if (!allowed.includes(converted)) {
    throw new TypeError(`${label} is not a supported enum value`);
  }
  return converted;
}

function stagedSequence(
  value: unknown,
  label: string,
  convertMember: (member: unknown, index: number) => unknown,
): readonly unknown[] {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
    throw new TypeError(`${label} must be iterable`);
  }
  const iteratorMethod = (value as { [Symbol.iterator]?: unknown })[Symbol.iterator];
  if (typeof iteratorMethod !== 'function') {
    throw new TypeError(`${label} must be iterable`);
  }
  const iterator = INTRINSIC_REFLECT_APPLY(iteratorMethod, value, []);
  if ((typeof iterator !== 'object' && typeof iterator !== 'function') || iterator === null) {
    throw new TypeError(`${label} iterator must be an object`);
  }
  const output: unknown[] = [];
  const iterable = {
    [Symbol.iterator]() {
      return iterator as Iterator<unknown>;
    },
  };
  for (const member of iterable) {
    if (output.length >= MAX_LOCAL_RECORDS) {
      throw new TypeError(`${label} exceeds the staged local record bound`);
    }
    output.push(convertMember(member, output.length));
  }
  return Object.freeze(output);
}

function snapshotUint32Range(
  value: unknown,
  start: number,
  length: number,
): readonly number[] {
  if (!INTRINSIC_TYPED_ARRAY_LENGTH_GETTER || !INTRINSIC_TYPED_ARRAY_TAG_GETTER) {
    throw new Error('Trusted typed-array intrinsics are unavailable');
  }
  let sourceLength: number;
  let sourceTag: unknown;
  try {
    sourceLength = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_LENGTH_GETTER,
      value,
      [],
    ) as number;
    sourceTag = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_TAG_GETTER,
      value,
      [],
    );
  } catch {
    throw new TypeError('dynamicOffsetsData must be a Uint32Array');
  }
  if (sourceTag !== 'Uint32Array') {
    throw new TypeError('dynamicOffsetsData must be a Uint32Array');
  }
  if (start > sourceLength || length > sourceLength - start) {
    throw new RangeError('dynamicOffsetsData range exceeds the source Uint32Array');
  }
  if (length > MAX_LOCAL_RECORDS) {
    throw new RangeError('dynamicOffsetsData range exceeds the staged local record bound');
  }
  const source = value as Readonly<Record<number, number>>;
  const copied: number[] = [];
  for (let index = 0; index < length; index += 1) {
    copied.push(source[start + index]);
  }
  return Object.freeze(copied);
}

function sealLocalValue(value: unknown, depth = 0): unknown {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('WebGPU local records require finite numeric values');
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (depth >= 16 || typeof value !== 'object' || value === null) {
    throw new TypeError('WebGPU local record value is not canonically sealable');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Array.isArray(value)) {
    if (value.length > MAX_LOCAL_RECORDS) {
      throw new TypeError('WebGPU local record sequence exceeds its bound');
    }
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) =>
        typeof key !== 'string' ||
        (key !== 'length' && !/^(?:0|[1-9][0-9]*)$/u.test(key))
      )
    ) {
      throw new TypeError('WebGPU local record sequence has extra properties');
    }
    const result: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
        throw new TypeError('WebGPU local record sequence must be dense data');
      }
      result.push(sealLocalValue(descriptor.value, depth + 1));
    }
    return Object.freeze(result);
  }
  const ownKeys = Reflect.ownKeys(descriptors);
  if (ownKeys.length > 128 || ownKeys.some((key) => typeof key !== 'string')) {
    throw new TypeError('WebGPU local record dictionary exceeds its bound');
  }
  const keys = (ownKeys as string[]).slice().sort();
  const result: Record<string, unknown> = Object.create(null);
  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw new TypeError('WebGPU local record dictionary must contain data properties');
    }
    result[key] = sealLocalValue(descriptor.value, depth + 1);
  }
  return Object.freeze(result);
}

function drawingBufferCoordinate(value: unknown, label: string): number {
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value <= 0 ||
    value >= 0x1_0000_0000
  ) {
    throw new TypeError(`${label} must be a positive unsigned 32-bit integer`);
  }
  return value;
}

function makeIllegalConstructor(name: string, prototype: object): object {
  const constructor = function (): never {
    throw new TypeError(`Illegal constructor: ${name}`);
  };
  Object.defineProperty(constructor, 'name', { value: name });
  Object.defineProperty(constructor, 'prototype', { value: prototype });
  return Object.freeze(constructor);
}

function makeMessageConstructor(name: string, parent: object): object {
  const constructor = function (this: object, message?: unknown): object {
    const target = this instanceof (constructor as unknown as Function)
      ? this
      : Object.create((constructor as unknown as { prototype: object }).prototype);
    Object.defineProperty(target, 'message', {
      value: message === undefined ? '' : String(message),
      enumerable: true,
      configurable: false,
    });
    return target;
  };
  Object.defineProperty(constructor, 'name', { value: name });
  const prototype = Object.create(parent);
  Object.defineProperty(prototype, 'name', {
    value: name,
    enumerable: false,
  });
  Object.freeze(prototype);
  Object.defineProperty(constructor, 'prototype', { value: prototype });
  return Object.freeze(constructor);
}

function capturePrivateBindingTestOptions(
  value: ProductionWebGpuPrivateBindingTestOptions,
): Readonly<{
  counterSeeds: Readonly<Record<string, string>>;
  privateMappedAllocationGuardLimitBytes: number;
  enableStateInspection: boolean;
}> {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowedOptionKeys = new Set([
    'counterSeeds',
    'privateMappedAllocationGuardLimitBytes',
    'enableStateInspection',
  ]);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (
      typeof key !== 'string' ||
      !allowedOptionKeys.has(key) ||
      !descriptors[key]?.enumerable ||
      !('value' in descriptors[key]!)
    ) {
      throw new TypeError('Invalid private WebGPU test options');
    }
  }
  const enableStateInspectionValue = descriptors.enableStateInspection?.value;
  if (
    enableStateInspectionValue !== undefined &&
    typeof enableStateInspectionValue !== 'boolean'
  ) {
    throw new TypeError('Invalid private WebGPU test inspection option');
  }
  const privateMappedAllocationGuardLimitBytes =
    descriptors.privateMappedAllocationGuardLimitBytes?.value ??
      PRIVATE_MAPPED_ALLOCATION_GUARD_MAX_BYTES;
  if (
    typeof privateMappedAllocationGuardLimitBytes !== 'number' ||
    !Number.isSafeInteger(privateMappedAllocationGuardLimitBytes) ||
    privateMappedAllocationGuardLimitBytes < 0 ||
    privateMappedAllocationGuardLimitBytes % 4 !== 0 ||
    privateMappedAllocationGuardLimitBytes >
      PRIVATE_MAPPED_ALLOCATION_GUARD_MAX_BYTES
  ) {
    throw new TypeError('Invalid private WebGPU mapped allocation guard limit');
  }
  const rawSeeds = descriptors.counterSeeds?.value;
  if (rawSeeds !== undefined && (typeof rawSeeds !== 'object' || rawSeeds === null)) {
    throw new TypeError('Invalid private WebGPU counter seeds');
  }
  const seedDescriptors = rawSeeds === undefined
    ? Object.create(null) as PropertyDescriptorMap
    : Object.getOwnPropertyDescriptors(rawSeeds);
  const seedPositive = Object.freeze({
    nextLocalObjectId: true,
    nextLocalOperationInstanceId: true,
    nextAdapterOrdinal: true,
    nextDeviceIngressOrdinal: true,
    nextQueueIngressOrdinal: true,
    nextScopeId: true,
    canvasConfigurationGeneration: false,
    canvasCurrentEpoch: false,
    nextBufferMapGeneration: true,
    nextBufferCleanupGeneration: true,
  });
  const counterSeeds: Record<string, string> = Object.create(null);
  for (const key of Reflect.ownKeys(seedDescriptors)) {
    if (
      typeof key !== 'string' ||
      !Object.prototype.hasOwnProperty.call(seedPositive, key) ||
      !seedDescriptors[key]?.enumerable ||
      !('value' in seedDescriptors[key]!)
    ) {
      throw new TypeError('Invalid private WebGPU counter seeds');
    }
    const seed = seedDescriptors[key]!.value;
    if (
      !isCanonicalU64Decimal(
        seed,
        seedPositive[key as keyof typeof seedPositive],
      ) ||
      ((key === 'nextLocalObjectId' ||
        key === 'nextLocalOperationInstanceId') &&
        compareCanonicalU64Decimal(seed, '9223372036854775808') < 0)
    ) {
      throw new TypeError(`Invalid private WebGPU counter seed: ${key}`);
    }
    counterSeeds[key] = seed;
  }
  return Object.freeze({
    counterSeeds: Object.freeze(counterSeeds),
    privateMappedAllocationGuardLimitBytes,
    enableStateInspection: enableStateInspectionValue === true,
  });
}

export function createProductionWebGpuPrivateBinding(
  bridge: NativeGpuBridgeV2,
  codecs: ExecutableWebGpuCodecBundle,
  testOptions: ProductionWebGpuPrivateBindingTestOptions = {},
  extensions: ProductionWebGpuPrivateBindingExtensions | undefined = undefined,
): ProductionWebGpuPrivateBinding {
  if (!validateExecutableWebGpuCodecs(codecs)) {
    throw new TypeError('WebGPU executable codec authority is invalid');
  }
  if (!INTRINSIC_SET_TIMEOUT) {
    throw new TypeError(
      'WebGPU uncaptured-error task scheduling authority is unavailable',
    );
  }
  const capturedTestOptions = capturePrivateBindingTestOptions(testOptions);
  const effectiveExtensions = extensions ??
    (bridge.decodedImageAuthority === undefined
      ? Object.freeze({})
      : Object.freeze({
        decodedImageAuthority: bridge.decodedImageAuthority,
      }));
  if (typeof effectiveExtensions !== 'object' || effectiveExtensions === null) {
    throw new TypeError('Invalid private WebGPU binding extensions');
  }
  const extensionDescriptors = Object.getOwnPropertyDescriptors(effectiveExtensions);
  const extensionKeys = Reflect.ownKeys(extensionDescriptors);
  if (
    extensionKeys.length > 1 ||
    extensionKeys.some((key) => key !== 'decodedImageAuthority')
  ) {
    throw new TypeError('Invalid private WebGPU binding extensions');
  }
  const decodedImageAuthority = extensionDescriptors.decodedImageAuthority;
  if (
    decodedImageAuthority !== undefined &&
    (!decodedImageAuthority.enumerable || !('value' in decodedImageAuthority))
  ) {
    throw new TypeError('Invalid private WebGPU binding extensions');
  }
  const privateImageBitmaps =
    decodedImageAuthority?.value === undefined
      ? undefined
      : createProductionGpuPrivateImageBitmapFactoryV1(
        {
          runtimeAddress: bridge.runtimeAddress,
          runtimeNonce: bridge.runtimeNonce,
        },
        decodedImageAuthority.value as ProductionGpuDecodedImageAuthorityV1,
      );

  const mutablePrototypes = createPrototypeTable();
  if (Object.getPrototypeOf(mutablePrototypes.GPUDevice) !== EventTarget.prototype) {
    throw new Error('GPUDevice must inherit the shared EventTarget prototype');
  }
  const featurePrototype = Object.create(null) as object;
  const featureStates = new WeakMap<object, readonly string[]>();
  installReadonlyFeatureSetPrototype(featurePrototype, featureStates);
  const supportedLimitsPrototype = Object.freeze(Object.create(null) as object);
  const deviceLostInfoPrototype = Object.freeze(Object.create(null) as object);
  const gpuErrorPrototype = Object.freeze(
    Object.assign(Object.create(null) as object, { name: 'GPUError' }),
  );
  const gpuInternalErrorConstructor = makeMessageConstructor(
    'GPUInternalError',
    gpuErrorPrototype,
  );
  const gpuOutOfMemoryErrorConstructor = makeMessageConstructor(
    'GPUOutOfMemoryError',
    gpuErrorPrototype,
  );
  const gpuValidationErrorConstructor = makeMessageConstructor(
    'GPUValidationError',
    gpuErrorPrototype,
  );
  const gpuUncapturedErrorEventStates = new WeakMap<object, object>();
  const gpuUncapturedErrorEventPrototype = Object.create(Event.prototype) as object;
  defineGetter(
    gpuUncapturedErrorEventPrototype,
    'error',
    function (this: object): object {
      if (!gpuUncapturedErrorEventStates.has(this)) {
        throw new TypeError('Incompatible GPUUncapturedErrorEvent receiver');
      }
      return gpuUncapturedErrorEventStates.get(this)!;
    },
  );
  Object.freeze(gpuUncapturedErrorEventPrototype);
  const counterSeed = (
    key: keyof NonNullable<ProductionWebGpuPrivateBindingTestOptions['counterSeeds']>,
    fallback: string,
    positive: boolean,
  ): string => {
    const value = capturedTestOptions.counterSeeds[key] ?? fallback;
    // Provided values were validated during the one-time options snapshot;
    // this assertion covers only internal fallback mistakes.
    if (!isCanonicalU64Decimal(value, positive)) throw new TypeError(
      `Invalid private WebGPU counter seed: ${key}`,
    );
    return value;
  };
  const realm: RealmState = {
    bridge,
    codecs,
    prototypes: mutablePrototypes,
    wrappers: new WeakMap(),
    devices: new Map(),
    buffers: new Set(),
    hostCanvasContextsByIdentity: new Map(),
    currentHostCanvasContextByObject: new Map(),
    currentHostCanvasContextBySurfaceToken: new Map(),
    pendingCanvasTextureExpiries: new Set(),
    pendingPromiseCalls: new Map(),
    pendingSealedOperations: new Map(),
    pendingSealedBatches: new Map(),
    provisionalSealedBatches: new Set(),
    resultEvents: new Map(),
    pendingUncapturedErrors: [],
    pendingUncapturedDiagnosticBytes: 0,
    uncapturedErrorTaskScheduled: false,
    // Client-allocated targets occupy the high unsigned half of the service
    // namespace, independently of provider-assigned result identities.
    nextLocalObjectId: counterSeed(
      'nextLocalObjectId',
      '9223372036854775808',
      true,
    ),
    localObjectIdExhausted: false,
    // Wrapper-recording operations never enter the service individually, but
    // their sealed records still require nonzero per-realm identities. Keep
    // that wrapper-owned namespace in the high unsigned half as well.
    nextLocalOperationInstanceId: counterSeed(
      'nextLocalOperationInstanceId',
      '9223372036854775808',
      true,
    ),
    localOperationInstanceIdExhausted: false,
    allocatedWrapperCount: 0,
    privateMappedAllocationGuardLimitBytes:
      capturedTestOptions.privateMappedAllocationGuardLimitBytes,
    privateMappedAllocationGuardBytes: 0,
    canvasLossTransitionCount: 0,
    activePassCount: 0,
    closeReason: undefined,
    lastCloseSnapshot: undefined,
    active: true,
  };

  const requireState = (
    value: unknown,
    expectedKind?: ProductionGpuWrapperKind,
  ): WrapperState => {
    if (typeof value !== 'object' || value === null) {
      throw new TypeError('WebGPU receiver is not an object');
    }
    const state = realm.wrappers.get(value);
    if (!state || state.realm !== realm || (expectedKind && state.kind !== expectedKind)) {
      throw new TypeError(
        expectedKind
          ? `Incompatible ${expectedKind} receiver`
          : 'Value is not a branded WebGPU wrapper',
      );
    }
    return state;
  };

  const reference = (
    value: unknown,
    expectedKind?: ProductionGpuWrapperKind,
  ): Readonly<ProductionGpuFullObjectReference> => {
    const state = requireState(value, expectedKind);
    return Object.freeze({
      kind: state.kind,
      objectId: state.objectId,
      objectGeneration: state.objectGeneration,
      logicalDeviceId: state.device?.logicalDeviceId ?? '0',
      logicalDeviceGeneration: state.device?.logicalDeviceGeneration ?? '0',
      providerGeneration: state.device?.providerGeneration ?? state.providerGeneration,
    });
  };

  const referenceIfBranded = (
    value: unknown,
    expectedKind: ProductionGpuWrapperKind,
  ): Readonly<ProductionGpuFullObjectReference> | undefined => {
    if (
      typeof value !== 'object' ||
      value === null ||
      !IMPLEMENTED_WEBGPU_INTERFACE_KINDS.has(value)
    ) {
      return undefined;
    }
    return reference(value, expectedKind);
  };

  const referenceWithDevice = (
    state: WrapperState,
    device: DeviceState,
  ): Readonly<ProductionGpuFullObjectReference> => Object.freeze({
    kind: state.kind,
    objectId: state.objectId,
    objectGeneration: state.objectGeneration,
    logicalDeviceId: device.logicalDeviceId,
    logicalDeviceGeneration: device.logicalDeviceGeneration,
    providerGeneration: device.providerGeneration,
  });

  const intrinsicArrayBufferByteLength = (buffer: ArrayBuffer): number => {
    if (!INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_GETTER) {
      throw new TypeError('ArrayBuffer byteLength intrinsic is unavailable');
    }
    return INTRINSIC_REFLECT_APPLY(
      INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_GETTER,
      buffer,
      [],
    ) as number;
  };

  const retainOwnedUint8View = (value: unknown, expectedSize: number): Uint8Array => {
    if (
      !INTRINSIC_TYPED_ARRAY_TAG_GETTER ||
      !INTRINSIC_TYPED_ARRAY_BUFFER_GETTER ||
      !INTRINSIC_TYPED_ARRAY_BYTE_OFFSET_GETTER ||
      !INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER ||
      INTRINSIC_REFLECT_APPLY(
        INTRINSIC_TYPED_ARRAY_TAG_GETTER,
        value,
        [],
      ) !== 'Uint8Array'
    ) {
      throw new TypeError('GPUBuffer map completion bytes must be a Uint8Array');
    }
    const sourceBuffer = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_BUFFER_GETTER,
      value,
      [],
    ) as ArrayBuffer;
    const sourceOffset = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_BYTE_OFFSET_GETTER,
      value,
      [],
    ) as number;
    const sourceLength = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER,
      value,
      [],
    ) as number;
    if (sourceLength !== expectedSize) {
      throw new TypeError('GPUBuffer map completion byte extent is inconsistent');
    }
    const sourceBufferLength = intrinsicArrayBufferByteLength(sourceBuffer);
    if (
      !Number.isSafeInteger(sourceOffset) ||
      sourceOffset < 0 ||
      sourceOffset > sourceBufferLength - sourceLength
    ) {
      throw new TypeError('GPUBuffer map completion affine view is inconsistent');
    }
    return value as Uint8Array;
  };

  const copyExactUint8View = (
    value: unknown,
    expectedSize: number,
    label: string,
  ): Uint8Array => {
    let source: Uint8Array;
    try {
      source = retainOwnedUint8View(value, expectedSize);
    } catch {
      throw new TypeError(`${label} must be an exact Uint8Array`);
    }
    return INTRINSIC_REFLECT_CONSTRUCT(
      INTRINSIC_UINT8_ARRAY,
      [source],
    ) as Uint8Array;
  };

  const bytesToLowerHex = (bytes: Uint8Array): string => {
    let result = '';
    for (const byte of bytes) {
      result += LOWER_HEX_DIGITS[byte >>> 4]!;
      result += LOWER_HEX_DIGITS[byte & 0x0f]!;
    }
    return result;
  };

  const lowerHexToBytes = (value: string, label: string): Uint8Array => {
    if (value.length !== 64) {
      throw new TypeError(`${label} must be 64 lowercase hex digits`);
    }
    const bytes = INTRINSIC_REFLECT_CONSTRUCT(
      INTRINSIC_UINT8_ARRAY,
      [32],
    ) as Uint8Array;
    for (let index = 0; index < 32; index += 1) {
      const highCode = INTRINSIC_REFLECT_APPLY(
        INTRINSIC_STRING_CHAR_CODE_AT,
        value,
        [index * 2],
      ) as number;
      const lowCode = INTRINSIC_REFLECT_APPLY(
        INTRINSIC_STRING_CHAR_CODE_AT,
        value,
        [index * 2 + 1],
      ) as number;
      const high = highCode >= 0x30 && highCode <= 0x39
        ? highCode - 0x30
        : highCode >= 0x61 && highCode <= 0x66
          ? highCode - 0x57
          : -1;
      const low = lowCode >= 0x30 && lowCode <= 0x39
        ? lowCode - 0x30
        : lowCode >= 0x61 && lowCode <= 0x66
          ? lowCode - 0x57
          : -1;
      if (high < 0 || low < 0) {
        throw new TypeError(`${label} must be 64 lowercase hex digits`);
      }
      bytes[index] = (high << 4) | low;
    }
    return bytes;
  };

  const encodePresentationAuthority = (
    value: NativeGpuPresentationAuthorityV2,
    capturedScopeId: string,
  ): ProductionGpuPresentationAuthorityEncoding => {
    if (
      !isPositiveDecimal(value.acquireSessionId) ||
      !isPositiveDecimal(value.presentSessionId) ||
      value.acquireSessionId === value.presentSessionId ||
      !isCanonicalU64Decimal(capturedScopeId, false)
    ) {
      throw new TypeError('Canvas presentation authority identity is malformed');
    }
    const digest = copyExactUint8View(
      value.authorityContextDigest,
      32,
      'Canvas presentation authority digest',
    );
    return Object.freeze({
      acquireSessionId: value.acquireSessionId,
      presentSessionId: value.presentSessionId,
      authorityContextDigest: bytesToLowerHex(digest),
      capturedScopeId,
    });
  };

  const nativePresentationAuthority = (
    value: ProductionGpuPresentationAuthorityEncoding,
  ): NativeGpuPresentationAuthorityV2 => Object.freeze({
    acquireSessionId: value.acquireSessionId,
    presentSessionId: value.presentSessionId,
    authorityContextDigest: lowerHexToBytes(
      value.authorityContextDigest,
      'Canvas presentation authority digest',
    ),
  });

  const tryRetirePresentationAuthorityOnce = (
    texture: WrapperState,
    retained: NativeGpuPresentationAuthorityV2,
  ): boolean => {
    if (texture.presentationAuthorityRetirement === 'retired') return true;
    if (texture.presentationAuthorityRetirement === 'retiring') return false;
    texture.presentationAuthorityRetirement = 'retiring';
    try {
      const status = bridge.retirePresentationAuthority(retained);
      if (status === 1 || status === -2) {
        texture.presentationAuthorityRetirement = 'retired';
        return true;
      }
      texture.presentationAuthorityRetirement = 'live';
      if (status === 0) return false;
      throw new Error(
        'Canvas presentation authority retirement failed structurally',
      );
    } catch (error) {
      texture.presentationAuthorityRetirement = 'live';
      throw error;
    }
  };

  const makePendingBufferMap = (
    generation: string,
    mode: 1 | 2,
    offset: number,
    size: number,
  ): PendingBufferMapState => {
    let resolvePromise: (() => void) | undefined;
    let rejectPromise: ((error: unknown) => void) | undefined;
    const promise = new Promise<undefined>((resolve, reject) => {
      resolvePromise = () => resolve(undefined);
      rejectPromise = reject;
    });
    return {
      generation,
      mode,
      offset,
      size,
      promise,
      resolve: () => resolvePromise?.(),
      reject: (error) => rejectPromise?.(error),
      settled: false,
      operationInstanceId: undefined,
      promiseId: undefined,
    };
  };

  const settlePendingBufferMap = (
    pending: PendingBufferMapState,
    error?: unknown,
  ): void => {
    if (pending.settled) return;
    pending.settled = true;
    if (error === undefined) pending.resolve();
    else pending.reject(error);
  };

  const retainBufferLifecycle = (buffer: WrapperState): void => {
    realm.buffers.add(buffer);
    buffer.device?.buffers.add(buffer);
  };

  const releaseBufferLifecycleIfIdle = (buffer: WrapperState): void => {
    if (
      buffer.bufferPendingMap ||
      buffer.bufferActiveMapping ||
      buffer.bufferPendingCleanup
    ) {
      return;
    }
    realm.buffers.delete(buffer);
    buffer.device?.buffers.delete(buffer);
  };

  const cancelPendingBufferMap = (
    buffer: WrapperState,
    message: string,
    issueNativeCancel: boolean,
  ): PendingBufferMapState | undefined => {
    const pending = buffer.bufferPendingMap;
    if (!pending) return undefined;
    buffer.bufferPendingMap = undefined;
    buffer.bufferMapState = buffer.bufferActiveMapping ? 'mapped' : 'unmapped';
    if (
      issueNativeCancel &&
      pending.operationInstanceId !== undefined &&
      pending.promiseId !== undefined
    ) {
      try {
        bridge.cancel(pending.operationInstanceId, pending.promiseId);
      } catch {
        // The authenticated cleanup request carries the same cancelled map
        // generation. A throwing low-level cancel cannot restore wrapper
        // authority or delay the public AbortError.
      }
    }
    settlePendingBufferMap(pending, namedError('AbortError', message));
    releaseBufferLifecycleIfIdle(buffer);
    return pending;
  };

  const detachMappedRangeLeases = (
    active: ActiveBufferMappingState,
  ): boolean => {
    let contradicted = false;
    for (const range of active.ranges) {
      if (!range.live) continue;
      // Consume wrapper authority before crossing the native boundary. Even a
      // throwing or false-returning bridge must never cause a second detach
      // attempt for the same engine-keyed alias.
      range.live = false;
      try {
        if (bridge.detachMappedRange(range.bytes) !== true) contradicted = true;
      } catch {
        contradicted = true;
      }
    }
    return contradicted;
  };

  const detachActiveBufferMapping = (
    buffer: WrapperState,
  ): ActiveBufferMappingState | undefined => {
    const active = buffer.bufferActiveMapping;
    if (!active) return undefined;
    const detachContradiction = detachMappedRangeLeases(active);
    buffer.bufferActiveMapping = undefined;
    buffer.bufferMapState = buffer.bufferPendingMap ? 'pending' : 'unmapped';
    releaseBufferLifecycleIfIdle(buffer);
    if (detachContradiction) {
      closeRealmCounterIndependently(
        'buffer-mapped-range-detach-contradiction',
        'The WebGPU realm closed after mapped-range detachment contradicted the engine bridge',
      );
    }
    return active;
  };

  const moveActiveBufferMappingIntoCleanup = (
    buffer: WrapperState,
  ): ActiveBufferMappingState | undefined => {
    const active = buffer.bufferActiveMapping;
    if (!active) return undefined;
    const detachContradiction = detachMappedRangeLeases(active);
    // The retained affine root view is moved into the authenticated cleanup
    // snapshot. Engine-keyed app-visible aliases were detached above; their
    // MAP_WRITE mutations already share this root block and require no shadow
    // copy or range-by-range writeback.
    buffer.bufferActiveMapping = undefined;
    buffer.bufferMapState = buffer.bufferPendingMap ? 'pending' : 'unmapped';
    releaseBufferLifecycleIfIdle(buffer);
    if (detachContradiction) {
      closeRealmCounterIndependently(
        'buffer-mapped-range-detach-contradiction',
        'The WebGPU realm closed after mapped-range detachment contradicted the engine bridge',
      );
    }
    return active;
  };

  const discardPendingBufferCleanup = (buffer: WrapperState): void => {
    if (!buffer.bufferPendingCleanup) return;
    buffer.bufferPendingCleanup = undefined;
    releaseBufferLifecycleIfIdle(buffer);
  };

  const clearRealmBufferMappings = (
    issueNativeCancel: boolean,
    message: string,
  ): void => {
    for (const buffer of realm.buffers) {
      cancelPendingBufferMap(buffer, message, issueNativeCancel);
      detachActiveBufferMapping(buffer);
      discardPendingBufferCleanup(buffer);
    }
  };

  const clearDeviceBufferMappings = (
    device: DeviceState,
    clearActive: boolean,
    issueNativeCancel: boolean,
    message: string,
  ): void => {
    for (const buffer of device.buffers) {
      cancelPendingBufferMap(buffer, message, issueNativeCancel);
      if (clearActive) {
        detachActiveBufferMapping(buffer);
      }
      // A retained cleanup snapshot is wrapper-detached authority whose
      // retry target disappeared with the device/provider. Drop it on every
      // physical loss transition, while preserving ordinary active mapped
      // views until the wrapper realm itself closes.
      discardPendingBufferCleanup(buffer);
    }
  };

  const inspectCurrentState = (): ProductionWebGpuPrivateBindingInspection =>
    Object.freeze({
      active: realm.active,
      closeReason: realm.closeReason,
      allocatedWrapperCount: realm.allocatedWrapperCount,
      privateMappedAllocationGuardLimitBytes:
        realm.privateMappedAllocationGuardLimitBytes,
      privateMappedAllocationGuardBytes:
        realm.privateMappedAllocationGuardBytes,
      canvasLossTransitionCount: realm.canvasLossTransitionCount,
      activePassCount: realm.activePassCount,
      trackedBufferLifecycleCount: realm.buffers.size,
      routedDeviceCount: realm.devices.size,
      indexedCanvasContextCount: realm.hostCanvasContextsByIdentity.size,
      indexedCanvasObjectCount: realm.currentHostCanvasContextByObject.size,
      indexedCanvasSurfaceTokenCount:
        realm.currentHostCanvasContextBySurfaceToken.size,
      invalidCurrentTextureCount:
        [...realm.hostCanvasContextsByIdentity.values()].reduce(
          (count, context) => {
            const current = context.currentTexture === undefined
              ? undefined
              : realm.wrappers.get(context.currentTexture);
            return count + (current?.invalid ? 1 : 0);
          },
          0,
        ),
      pendingLocalRecordCount:
        [...realm.devices.values()].reduce(
          (count, device) => count + device.pendingLocalTimeline.length,
          0,
        ),
      pendingPromiseCount: realm.pendingPromiseCalls.size,
    });

  const closeRealmCounterIndependently = (
    reason: string,
    deviceMessage: string,
  ): void => {
    if (realm.closeReason !== undefined) return;
    realm.closeReason = reason;
    realm.active = false;
    const contexts = [...realm.hostCanvasContextsByIdentity.values()];
    const devices = [...realm.devices.values()];
    const snapshot: ProductionWebGpuPrivateBindingInspection = Object.freeze({
      active: false,
      closeReason: reason,
      allocatedWrapperCount: realm.allocatedWrapperCount,
      privateMappedAllocationGuardLimitBytes:
        realm.privateMappedAllocationGuardLimitBytes,
      privateMappedAllocationGuardBytes:
        realm.privateMappedAllocationGuardBytes,
      canvasLossTransitionCount: realm.canvasLossTransitionCount,
      activePassCount: realm.activePassCount,
      trackedBufferLifecycleCount: realm.buffers.size,
      routedDeviceCount: devices.length,
      indexedCanvasContextCount: contexts.length,
      indexedCanvasObjectCount: realm.currentHostCanvasContextByObject.size,
      indexedCanvasSurfaceTokenCount:
        realm.currentHostCanvasContextBySurfaceToken.size,
      invalidCurrentTextureCount: contexts.reduce((count, context) => {
        const current = context.currentTexture === undefined
          ? undefined
          : realm.wrappers.get(context.currentTexture);
        return count + (current?.invalid ? 1 : 0);
      }, 0),
      pendingLocalRecordCount: devices.reduce(
        (count, device) => count + device.pendingLocalTimeline.length,
        0,
      ),
      pendingPromiseCount: realm.pendingPromiseCalls.size,
    });
    for (const context of contexts) {
      if (!context.currentTexture) continue;
      const texture = realm.wrappers.get(context.currentTexture);
      if (
        texture?.kind !== 'GPUTexture' ||
        texture.materialized ||
        texture.currentOrigin === undefined
      ) {
        continue;
      }
      try {
        tryRetirePresentationAuthorityOnce(
          texture,
          nativePresentationAuthority(
            texture.currentOrigin.presentationAuthority,
          ),
        );
      } catch {
        // Realm closure is already the terminal fail-closed path. The Host
        // context purge remains the final backstop if native retirement itself
        // rejects or throws.
      }
    }
    realm.hostCanvasContextsByIdentity.clear();
    realm.currentHostCanvasContextByObject.clear();
    realm.currentHostCanvasContextBySurfaceToken.clear();
    realm.pendingCanvasTextureExpiries.clear();
    clearRealmBufferMappings(false, 'The WebGPU realm was closed');
    realm.buffers.clear();
    realm.devices.clear();
    realm.pendingPromiseCalls.clear();
    realm.pendingSealedOperations.clear();
    realm.pendingSealedBatches.clear();
    realm.provisionalSealedBatches.clear();
    realm.resultEvents.clear();
    realm.pendingUncapturedErrors.length = 0;
    realm.pendingUncapturedDiagnosticBytes = 0;
    realm.activePassCount = 0;
    realm.lastCloseSnapshot = snapshot;
    for (const context of contexts) {
      context.configuredDevice?.configuredCanvasContexts.delete(context);
      if (context.currentTexture) {
        const texture = realm.wrappers.get(context.currentTexture);
        if (texture?.kind === 'GPUTexture') texture.textureExpired = true;
      }
      context.currentTexture = undefined;
      context.configuration = undefined;
      context.configuredDevice = undefined;
      context.configuredDeviceWrapper = undefined;
      context.canvasContextLifecycle = 'revoked';
    }
    for (const device of devices) {
      device.configuredCanvasContexts.clear();
      device.pendingLocalTimeline.length = 0;
      device.pendingCurrentTextureMaterializations.clear();
      if (!device.lost.settled) {
        device.lost.settled = true;
        const info = Object.freeze(Object.assign(
          Object.create(deviceLostInfoPrototype) as object,
          device.destroyed
            ? {
              reason: 'destroyed',
              message: 'The device was destroyed',
            }
            : { reason: 'unknown', message: deviceMessage },
        ));
        device.lost.resolve(info);
      }
    }
  };

  const closeForCounterExhaustion = (label: string): void => {
    closeRealmCounterIndependently(
      `counter-exhausted:${label}`,
      `The WebGPU realm closed because ${label} was exhausted`,
    );
  };

  const advanceCounterOrClose = (value: string, label: string): string => {
    try {
      return incrementCanonicalU64Decimal(value);
    } catch (error) {
      closeForCounterExhaustion(label);
      throw error;
    }
  };

  interface NextCounterConsumption {
    readonly value: string;
    readonly next: string;
    readonly exhaustedAfter: boolean;
  }

  const consumeNextCounterOrClose = (
    value: string,
    exhausted: boolean,
    label: string,
  ): NextCounterConsumption => {
    if (exhausted) {
      closeForCounterExhaustion(label);
      throw new RangeError('WebGPU counter exceeds unsigned 64-bit capacity');
    }
    if (value === U64_MAX_DECIMAL) {
      return Object.freeze({ value, next: value, exhaustedAfter: true });
    }
    return Object.freeze({
      value,
      next: incrementCanonicalU64Decimal(value),
      exhaustedAfter: false,
    });
  };

  interface PreparedWrapperAllocation {
    readonly state: WrapperState;
    readonly localObjectPlan: NextCounterConsumption | undefined;
  }

  const prepareWrapperAllocation = (
    kind: ProductionGpuAllocatedWrapperKind,
    device: DeviceState | undefined,
    identity?: Readonly<{ objectId: string; objectGeneration: string }>,
  ): PreparedWrapperAllocation => {
    if (!realm.active) throw namedError('SecurityError', 'WebGPU realm is revoked');
    const localObjectPlan = identity
      ? undefined
      : consumeNextCounterOrClose(
        realm.nextLocalObjectId,
        realm.localObjectIdExhausted,
        'local object identity',
      );
    const objectId = identity?.objectId ?? localObjectPlan!.value;
    if (!isPositiveDecimal(objectId)) {
      throw new TypeError(`Invalid ${kind} object identity`);
    }
    const objectGeneration = identity?.objectGeneration ?? '1';
    if (!isPositiveDecimal(objectGeneration)) {
      throw new TypeError(`Invalid ${kind} object generation`);
    }
    const wrapper = kind === 'GPUDevice'
      ? new EventTarget((target) => {
        requireState(target, 'GPUDevice');
      })
      : Object.create(realm.prototypes[kind]) as object;
    if (kind === 'GPUDevice') {
      Object.setPrototypeOf(wrapper, realm.prototypes.GPUDevice);
    }
    const state: WrapperState = {
      realm,
      kind,
      objectId,
      objectGeneration,
      wrapper,
      device,
      providerGeneration: device?.providerGeneration ?? '0',
      nextAdapterOrdinal: counterSeed('nextAdapterOrdinal', '1', true),
      adapterOrdinalExhausted: false,
      expired: false,
      serviceDetached: false,
      retired: false,
      status: 'live',
      invalid: false,
      activePass: undefined,
      encoder: undefined,
      records: [],
      debugGroupDepth: 0,
      boundBindGroups: new Map(),
      usedBindGroups: new Set(),
      currentPipeline: undefined,
      indexBufferBinding: undefined,
      bindGroupLayoutEntries: undefined,
      bindGroupLayout: undefined,
      bindGroupBufferBindings: undefined,
      submitted: false,
      configuration: undefined,
      configurationGeneration: counterSeed(
        'canvasConfigurationGeneration',
        '0',
        false,
      ),
      currentEpoch: counterSeed('canvasCurrentEpoch', '0', false),
      currentTexture: undefined,
      configuredDevice: undefined,
      configuredDeviceWrapper: undefined,
      canvasAuthority: undefined,
      canvasContextLifecycle: undefined,
      destroyed: false,
      textureExpired: false,
      textureExpiryAccepted: false,
      materialized: false,
      presentationAuthorityRetirement: 'live',
      currentOrigin: undefined,
      adapterFeatures: undefined,
      adapterFeatureNames: undefined,
      bufferSize: undefined,
      bufferUsage: undefined,
      bufferMapState: undefined,
      bufferNextMapGeneration: counterSeed(
        'nextBufferMapGeneration',
        '1',
        true,
      ),
      bufferMapGenerationExhausted: false,
      bufferNextCleanupGeneration: counterSeed(
        'nextBufferCleanupGeneration',
        '1',
        true,
      ),
      bufferCleanupGenerationExhausted: false,
      bufferPendingMap: undefined,
      bufferActiveMapping: undefined,
      bufferPendingCleanup: undefined,
      querySetCount: undefined,
      querySetType: undefined,
      textureDimension: undefined,
      textureFormat: undefined,
      textureUsage: undefined,
      textureWidth: undefined,
      textureHeight: undefined,
      textureDepthOrArrayLayers: undefined,
      drawingBufferWidth: undefined,
      drawingBufferHeight: undefined,
    };
    return Object.freeze({ state, localObjectPlan });
  };

  const commitWrapperAllocation = (
    plan: PreparedWrapperAllocation,
  ): WrapperState => {
    const { state, localObjectPlan } = plan;
    if (
      !realm.active ||
      realm.closeReason !== undefined ||
      (localObjectPlan !== undefined &&
        (realm.nextLocalObjectId !== localObjectPlan.value ||
          realm.localObjectIdExhausted))
    ) {
      closeRealmCounterIndependently(
        'wrapper-allocation-plan-conflict',
        'The WebGPU realm closed after a wrapper allocation plan conflict',
      );
      throw namedError(
        'OperationError',
        'WebGPU wrapper allocation plan is stale',
      );
    }
    if (localObjectPlan !== undefined) {
      realm.nextLocalObjectId = localObjectPlan.next;
      realm.localObjectIdExhausted = localObjectPlan.exhaustedAfter;
    }
    realm.wrappers.set(state.wrapper, state);
    IMPLEMENTED_WEBGPU_INTERFACE_KINDS.set(state.wrapper, state.kind);
    realm.allocatedWrapperCount += 1;
    return state;
  };

  const allocateWrapper = (
    kind: ProductionGpuAllocatedWrapperKind,
    device: DeviceState | undefined,
    identity?: Readonly<{ objectId: string; objectGeneration: string }>,
  ): WrapperState => commitWrapperAllocation(
    prepareWrapperAllocation(kind, device, identity),
  );

  const convert = (operationId: string, args: readonly unknown[]): unknown => {
    route(operationId);
    return codecs.convertPublicArguments(operationId, args, {
      reference,
      referenceIfBranded,
      ...(privateImageBitmaps
        ? {
            snapshotExternalImageForCopy:
              privateImageBitmaps.snapshotForExternalCopy,
          }
        : {}),
    });
  };

  const referenceKey = (
    value: Readonly<ProductionGpuFullObjectReference>,
  ): string => [
    value.kind,
    value.objectId,
    value.objectGeneration,
    value.logicalDeviceId,
    value.logicalDeviceGeneration,
    value.providerGeneration,
  ].join('/');

  const convertWithCapturedStates = (
    operationId: string,
    args: readonly unknown[],
  ): Readonly<{
    converted: unknown;
    statesByReference: ReadonlyMap<string, WrapperState>;
  }> => {
    route(operationId);
    const statesByReference = new Map<string, WrapperState>();
    const converted = codecs.convertPublicArguments(operationId, args, {
      referenceIfBranded,
      reference(value, expectedKind) {
        const state = requireState(value, expectedKind);
        const projected = reference(value, expectedKind);
        statesByReference.set(referenceKey(projected), state);
        return projected;
      },
      ...(privateImageBitmaps
        ? {
            snapshotExternalImageForCopy:
              privateImageBitmaps.snapshotForExternalCopy,
          }
        : {}),
    });
    return Object.freeze({ converted, statesByReference });
  };

  const stateForCapturedReference = (
    statesByReference: ReadonlyMap<string, WrapperState>,
    value: unknown,
    label: string,
  ): WrapperState => {
    const record = asRecord(value, label) as unknown as ProductionGpuFullObjectReference;
    const state = statesByReference.get(referenceKey(record));
    if (!state) throw new TypeError(`${label} was not captured from a branded wrapper`);
    return state;
  };

  const convertOrigin3D = (
    value: unknown,
    label: string,
  ): Readonly<{ x: number; y: number; z: number }> => {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
      throw new TypeError(`${label} must be an iterable or dictionary`);
    }
    const iteratorMethod = (value as { [Symbol.iterator]?: unknown })[Symbol.iterator];
    if (iteratorMethod !== undefined && iteratorMethod !== null) {
      const values = stagedSequence(
        value,
        label,
        (member, index) => stagedU32(member, `${label}[${index}]`),
      ) as readonly number[];
      if (values.length > 3) throw new TypeError(`${label} has too many members`);
      return Object.freeze({
        x: values[0] ?? 0,
        y: values[1] ?? 0,
        z: values[2] ?? 0,
      });
    }
    const source = stagedDictionary(value, label);
    // Web IDL dictionary members are observed lexicographically.
    const x = stagedU32(source.x, `${label}.x`, 0);
    const y = stagedU32(source.y, `${label}.y`, 0);
    const z = stagedU32(source.z, `${label}.z`, 0);
    return Object.freeze({ x, y, z });
  };

  const convertExtent3D = (
    value: unknown,
    label: string,
  ): Readonly<{ width: number; height: number; depthOrArrayLayers: number }> => {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
      throw new TypeError(`${label} must be an iterable or dictionary`);
    }
    const iteratorMethod = (value as { [Symbol.iterator]?: unknown })[Symbol.iterator];
    if (iteratorMethod !== undefined && iteratorMethod !== null) {
      const values = stagedSequence(
        value,
        label,
        (member, index) => stagedU32(member, `${label}[${index}]`),
      ) as readonly number[];
      if (values.length === 0 || values.length > 3) {
        throw new TypeError(`${label} must contain one to three members`);
      }
      return Object.freeze({
        width: values[0],
        height: values[1] ?? 1,
        depthOrArrayLayers: values[2] ?? 1,
      });
    }
    const source = stagedDictionary(value, label);
    // depthOrArrayLayers, height, width is the Web IDL dictionary order.
    const depthOrArrayLayers = stagedU32(
      source.depthOrArrayLayers,
      `${label}.depthOrArrayLayers`,
      1,
    );
    const height = stagedU32(source.height, `${label}.height`, 1);
    if (source.width === undefined) throw new TypeError(`${label}.width is required`);
    const width = stagedU32(source.width, `${label}.width`);
    return Object.freeze({ width, height, depthOrArrayLayers });
  };

  const convertTexelCopyTextureInfo = (
    value: unknown,
    label: string,
  ): Readonly<{
    aspect: string;
    mipLevel: number;
    origin: Readonly<{ x: number; y: number; z: number }>;
    texture: Readonly<ProductionGpuFullObjectReference>;
    textureState: WrapperState;
  }> => {
    const source = stagedDictionary(value, label);
    const aspect = source.aspect === undefined
      ? 'all'
      : stagedEnum(
        source.aspect,
        ['all', 'stencil-only', 'depth-only'],
        `${label}.aspect`,
      );
    const mipLevel = stagedU32(source.mipLevel, `${label}.mipLevel`, 0);
    const origin = source.origin === undefined
      ? Object.freeze({ x: 0, y: 0, z: 0 })
      : convertOrigin3D(source.origin, `${label}.origin`);
    if (source.texture === undefined) throw new TypeError(`${label}.texture is required`);
    const textureState = requireState(source.texture, 'GPUTexture');
    return Object.freeze({
      aspect,
      mipLevel,
      origin,
      texture: reference(source.texture, 'GPUTexture'),
      textureState,
    });
  };

  const convertSetBindGroupArguments = (
    args: readonly unknown[],
  ): Readonly<{
    index: number;
    bindGroup: WrapperState | null;
    bindGroupRef: Readonly<ProductionGpuFullObjectReference> | null;
    dynamicOffsets: readonly number[];
    overload: 'iterable' | 'uint32-range';
  }> => {
    if (args.length < 2) throw new TypeError('setBindGroup requires index and bindGroup');
    const index = stagedU32(args[0], 'setBindGroup index');
    const bindGroupValue = args[1];
    const bindGroup = bindGroupValue === null || bindGroupValue === undefined
      ? null
      : requireState(bindGroupValue, 'GPUBindGroup');
    const bindGroupRef = bindGroup === null
      ? null
      : reference(bindGroupValue, 'GPUBindGroup');
    if (args.length >= 5) {
      const start = stagedU64(args[3], 'dynamicOffsetsDataStart');
      const length = stagedU32(args[4], 'dynamicOffsetsDataLength');
      return Object.freeze({
        index,
        bindGroup,
        bindGroupRef,
        dynamicOffsets: snapshotUint32Range(args[2], start, length),
        overload: 'uint32-range',
      });
    }
    if (args.length === 4) {
      throw new TypeError('setBindGroup overload requires either three or five arguments');
    }
    const dynamicOffsets = args[2] === undefined
      ? Object.freeze([]) as readonly number[]
      : stagedSequence(
        args[2],
        'dynamicOffsets',
        (member, offsetIndex) =>
          stagedU32(member, `dynamicOffsets[${offsetIndex}]`),
      ) as readonly number[];
    return Object.freeze({
      index,
      bindGroup,
      bindGroupRef,
      dynamicOffsets,
      overload: 'iterable',
    });
  };

  const retirePresentationAuthorityOrClose = (
    texture: WrapperState,
    retained: NativeGpuPresentationAuthorityV2,
  ): void => {
    let retired = false;
    try {
      retired = tryRetirePresentationAuthorityOnce(texture, retained);
    } catch {
      closeRealmCounterIndependently(
        'canvas-presentation-retire-threw',
        'The WebGPU realm closed because Canvas presentation retirement threw',
      );
      throw namedError(
        'OperationError',
        'GPUCanvasContext presentation retirement failed',
      );
    }
    if (!retired) {
      closeRealmCounterIndependently(
        'canvas-presentation-retire-rejected',
        'The WebGPU realm closed because Canvas presentation retirement was rejected',
      );
      throw namedError(
        'OperationError',
        'GPUCanvasContext presentation retirement was rejected',
      );
    }
  };

  const encodeCanvasCurrentOrigin = (
    texture: WrapperState,
  ): ProductionGpuCanvasCurrentTextureOriginEncoding => {
    const currentOrigin = texture.currentOrigin;
    if (texture.kind !== 'GPUTexture' || currentOrigin === undefined) {
      throw new TypeError('Canvas current texture lacks immutable origin');
    }
    return Object.freeze({
      kind: 'canvas-current-v1',
      contextRef: currentOrigin.contextRef,
      attachmentGeneration: currentOrigin.attachmentGeneration,
      contextGeneration: currentOrigin.contextGeneration,
      configurationGeneration: currentOrigin.configurationGeneration,
      currentEpoch: currentOrigin.currentEpoch,
      mintOperationProvenance: Object.freeze({
        operationInstanceId:
          currentOrigin.mintOperationProvenance.operationInstanceId,
        deviceIngressOrdinal:
          currentOrigin.mintOperationProvenance.deviceIngressOrdinal,
      }),
      presentationAuthority: currentOrigin.presentationAuthority,
      textureOriginDigest: currentOrigin.textureOriginDigest,
    });
  };

  const submitCanvasTextureExpiry = (
    texture: WrapperState,
    bridgeThrowReason: string,
    bridgeThrowMessage: string,
  ): void => {
    const device = texture.device;
    if (
      texture.kind !== 'GPUTexture' ||
      !device ||
      texture.currentOrigin === undefined ||
      texture.textureExpired
    ) {
      closeRealmCounterIndependently(
        'canvas-current-expiry-origin',
        'The WebGPU realm closed after a Canvas current-texture expiry mismatch',
      );
      throw namedError(
        'OperationError',
        'GPUCanvasContext current-texture expiry is inconsistent',
      );
    }
    realm.pendingCanvasTextureExpiries.add(texture);
    const converted = convert('GPUTexture.destroy', []);
    const onFailure = (failure: ServiceSubmissionFailureKind): void => {
      if (failure === 'bridge-threw') {
        closeRealmCounterIndependently(
          bridgeThrowReason,
          bridgeThrowMessage,
        );
      }
    };
    if (!texture.materialized) {
      const materializationAuthority: ProductionGpuCanvasServiceEncoding =
        Object.freeze({
          kind: 'texture-destroy-v1',
          receiverTextureRef: reference(texture.wrapper, 'GPUTexture'),
          terminalIntent: 'first-cleanup',
          materializationState: 'unmaterialized',
          origin: encodeCanvasCurrentOrigin(texture),
        });
      submitService(
        'GPUTexture.destroy',
        texture,
        undefined,
        converted,
        false,
        undefined,
        undefined,
        onFailure,
        materializationAuthority,
      );
      texture.destroyed = true;
      if (!texture.materialized) {
        closeRealmCounterIndependently(
          'canvas-current-materialization-missing',
          'The WebGPU realm closed because Canvas expiry failed to materialize its exact origin',
        );
        throw namedError(
          'OperationError',
          'GPUCanvasContext current-texture materialization was not committed',
        );
      }
    }
    if (texture.textureExpiryAccepted) return;
    const expiryAuthority: ProductionGpuCanvasServiceEncoding = Object.freeze({
      kind: 'texture-expire-v1',
      receiverTextureRef: reference(texture.wrapper, 'GPUTexture'),
      expiryIntent: 'host-task-expiry',
      materializationState: 'materialized',
      origin: encodeCanvasCurrentOrigin(texture),
    });
    submitService(
      'GPUTexture.destroy',
      texture,
      undefined,
      converted,
      false,
      undefined,
      undefined,
      onFailure,
      expiryAuthority,
    );
    texture.textureExpiryAccepted = true;
  };

  const finalizeCanvasTextureExpiry = (texture: WrapperState): void => {
    if (!texture.textureExpiryAccepted) {
      throw new Error('Canvas texture expiry was not accepted');
    }
    texture.textureExpired = true;
    texture.destroyed = true;
    realm.pendingCanvasTextureExpiries.delete(texture);
  };

  const expireCurrentTexture = (context: WrapperState): void => {
    if (!context.currentTexture) return;
    const textureWrapper = context.currentTexture;
    const texture = requireState(textureWrapper, 'GPUTexture');
    const device = context.configuredDevice;
    if (!device || texture.device !== device || texture.currentOrigin === undefined) {
      closeRealmCounterIndependently(
        'canvas-current-expiry-origin',
        'The WebGPU realm closed after a Canvas current-texture expiry mismatch',
      );
      throw namedError(
        'OperationError',
        'GPUCanvasContext current-texture expiry is inconsistent',
      );
    }
    submitCanvasTextureExpiry(
      texture,
      'canvas-current-expiry-threw',
      'The WebGPU realm closed because Canvas current-texture expiry threw',
    );
    finalizeCanvasTextureExpiry(texture);
    if (context.currentTexture === textureWrapper) {
      context.currentTexture = undefined;
    }
  };

  const detachCurrentTextureForExpiry = (
    context: WrapperState,
  ): WrapperState | undefined => {
    if (!context.currentTexture) return undefined;
    const texture = requireState(context.currentTexture, 'GPUTexture');
    if (
      !context.configuredDevice ||
      texture.device !== context.configuredDevice ||
      texture.currentOrigin === undefined
    ) {
      closeRealmCounterIndependently(
        'canvas-current-expiry-origin',
        'The WebGPU realm closed after a Canvas current-texture expiry mismatch',
      );
      throw namedError(
        'OperationError',
        'GPUCanvasContext current-texture expiry is inconsistent',
      );
    }
    realm.pendingCanvasTextureExpiries.add(texture);
    context.currentTexture = undefined;
    return texture;
  };

  const unlinkConfiguredCanvasContext = (context: WrapperState): void => {
    context.configuredDevice?.configuredCanvasContexts.delete(context);
  };

  const transitionCanvasContextToLost = (
    context: WrapperState,
    device: DeviceState,
    nextConfigurationGeneration: string,
  ): void => {
    if (
      context.configuredDevice !== device ||
      context.canvasContextLifecycle !== 'configured'
    ) {
      return;
    }
    expireCurrentTexture(context);
    realm.canvasLossTransitionCount += 1;
    context.configurationGeneration = nextConfigurationGeneration;
    context.canvasContextLifecycle = 'lost';
    device.configuredCanvasContexts.delete(context);
  };

  const settleDeviceLost = (
    device: DeviceState,
    reason: 'destroyed' | 'unknown',
    message: string,
  ): void => {
    clearDeviceBufferMappings(
      device,
      false,
      true,
      'GPUBuffer mapping was cancelled because its device was lost',
    );
    if (device.lost.settled) return;
    const transitions = [...device.configuredCanvasContexts]
      .filter((context) =>
        context.configuredDevice === device &&
        context.canvasContextLifecycle === 'configured'
      )
      .map((context) => Object.freeze({
        context,
        nextConfigurationGeneration: advanceCounterOrClose(
          context.configurationGeneration,
          'canvas configuration generation',
        ),
      }));
    for (const transition of transitions) {
      transitionCanvasContextToLost(
        transition.context,
        device,
        transition.nextConfigurationGeneration,
      );
    }
    device.configuredCanvasContexts.clear();
    const key = deviceKey(
      device.logicalDeviceId,
      device.logicalDeviceGeneration,
      device.providerGeneration,
    );
    if (realm.devices.get(key) === device) realm.devices.delete(key);
    device.lost.settled = true;
    const winningReason = device.destroyed ? 'destroyed' : reason;
    const winningMessage = device.destroyed
      ? 'The device was destroyed'
      : message;
    const info = Object.freeze(Object.assign(Object.create(deviceLostInfoPrototype) as object, {
      reason: winningReason,
      message: winningMessage,
    }));
    device.lost.resolve(info);
  };

  const retireCanvasContext = (
    context: WrapperState,
    lifecycle: 'stale' | 'revoked',
  ): void => {
    unlinkConfiguredCanvasContext(context);
    expireCurrentTexture(context);
    context.configuration = undefined;
    context.configuredDevice = undefined;
    context.configuredDeviceWrapper = undefined;
    context.canvasContextLifecycle = lifecycle;
    const identityKey = hostCanvasContextIdentityKey(
      context.objectId,
      context.objectGeneration,
    );
    const objectKey = hostCanvasContextObjectKey(context.objectId);
    const surfaceToken = context.canvasAuthority?.surfaceAccountToken;
    if (realm.hostCanvasContextsByIdentity.get(identityKey) === context) {
      realm.hostCanvasContextsByIdentity.delete(identityKey);
    }
    if (realm.currentHostCanvasContextByObject.get(objectKey) === context) {
      realm.currentHostCanvasContextByObject.delete(objectKey);
    }
    if (
      surfaceToken !== undefined &&
      realm.currentHostCanvasContextBySurfaceToken.get(surfaceToken) === context
    ) {
      realm.currentHostCanvasContextBySurfaceToken.delete(surfaceToken);
    }
  };

  const assertCanvasContextUsable = (context: WrapperState): void => {
    if (!realm.active || context.canvasContextLifecycle === 'revoked') {
      throw namedError('SecurityError', 'WebGPU realm is revoked');
    }
    if (context.canvasContextLifecycle === 'stale') {
      throw namedError('InvalidStateError', 'GPUCanvasContext identity is stale');
    }
  };

  const retireRealmState = (): void => {
    closeRealmCounterIndependently(
      'realm-retired',
      'The WebGPU realm was retired',
    );
  };

  interface LocalRecordPlan {
    readonly operationName: string;
    readonly recordOperationId: number;
    readonly recordIdentitySha256: string | null;
    readonly recordIdentityClass: 'active-route' | 'staged-local';
    readonly device: DeviceState;
    readonly operationInstanceId: string;
    readonly nextOperationInstanceId: string;
    readonly operationInstanceIdExhaustedAfter: boolean;
    readonly deviceIngressOrdinal: string;
    readonly nextDeviceIngress: string;
    readonly deviceIngressExhaustedAfter: boolean;
    readonly capturedScopeId: string;
  }

  const prepareLocalRecord = (
    operationId: string,
    receiver: WrapperState,
    targetDevice?: DeviceState,
  ): LocalRecordPlan => {
    if (!realm.active) throw namedError('SecurityError', 'WebGPU realm is revoked');
    if (receiver.retired) {
      throw namedError('InvalidStateError', `${receiver.kind} identity is stale`);
    }
    const staged = STAGED_LOCAL_RECORDS.get(operationId);
    const selected = staged === undefined ? route(operationId) : undefined;
    if (selected !== undefined) {
      if (selected.providerSubmission !== 'none') {
        throw new Error(`${operationId} is not wrapper-local`);
      }
      if (
        selected.operationInstanceIdentity !==
          'wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record'
      ) {
        throw new Error(`${operationId} has no sealed local operation identity`);
      }
    } else if (
      staged?.logicalExecutionKind !== 'wrapper-local-recording' ||
      staged.terminalDisposition !== 'sealed-logical-record-no-provider-submit' ||
      staged.routingDisposition !==
        'selected-build-wrapper-local-no-provider-routing'
    ) {
      throw new Error(`${operationId} is not an authenticated staged local record`);
    }
    const device = receiver.device ?? targetDevice;
    if (!device) throw new Error(`${operationId} lacks a logical device`);
    if (device.pendingLocalTimeline.length >= MAX_LOCAL_RECORDS) {
      throw new RangeError('WebGPU pending local timeline exceeds its authenticated bound');
    }
    const operationPlan = consumeNextCounterOrClose(
      realm.nextLocalOperationInstanceId,
      realm.localOperationInstanceIdExhausted,
      'local operation identity',
    );
    const ingressPlan = consumeNextCounterOrClose(
      device.nextIngress,
      device.ingressExhausted,
      'device ingress ordinal',
    );
    return Object.freeze({
      operationName: operationId,
      recordOperationId: staged?.localRecordId ?? selected!.wireId,
      recordIdentitySha256: staged?.recordIdentitySha256 ?? null,
      recordIdentityClass: staged === undefined ? 'active-route' : 'staged-local',
      device,
      operationInstanceId: operationPlan.value,
      nextOperationInstanceId: operationPlan.next,
      operationInstanceIdExhaustedAfter: operationPlan.exhaustedAfter,
      deviceIngressOrdinal: ingressPlan.value,
      nextDeviceIngress: ingressPlan.next,
      deviceIngressExhaustedAfter: ingressPlan.exhaustedAfter,
      capturedScopeId: currentScopeId(device),
    });
  };

  const commitLocalRecord = (
    plan: LocalRecordPlan,
    receiver: WrapperState,
    target: WrapperState | undefined,
    convertedArguments: unknown,
    error: Error | undefined,
  ): Readonly<{
    operationInstanceId: string;
    deviceIngressOrdinal: string;
    sealedRecord: Readonly<Record<string, unknown>>;
  }> => {
    const {
      operationName,
      recordOperationId,
      recordIdentitySha256,
      recordIdentityClass,
      device,
      operationInstanceId,
      nextOperationInstanceId,
      operationInstanceIdExhaustedAfter,
      deviceIngressOrdinal,
      nextDeviceIngress,
      deviceIngressExhaustedAfter,
      capturedScopeId,
    } = plan;
    const receiverRef = referenceWithDevice(receiver, device);
    const pass = receiver.kind === 'GPUComputePassEncoder' ||
      receiver.kind === 'GPURenderPassEncoder'
      ? receiver
      : target?.kind === 'GPUComputePassEncoder' ||
          target?.kind === 'GPURenderPassEncoder'
        ? target
        : undefined;
    const commandEncoder = receiver.kind === 'GPUCommandEncoder'
      ? receiver
      : pass?.encoder;
    const sealedRecord = sealLocalValue({
      recordIdentityClass,
      operationId: recordOperationId,
      operationName,
      operationIdentitySha256: recordIdentitySha256,
      operationInstanceId,
      deviceIngressOrdinal,
      capturedScopeId,
      receiverRef,
      commandEncoderRef: commandEncoder
        ? referenceWithDevice(commandEncoder, device)
        : null,
      passRef: pass ? referenceWithDevice(pass, device) : null,
      wrapperAllocatedTargetRef: target
        ? referenceWithDevice(target, device)
        : null,
      argumentBody: convertedArguments,
      logicalError: error
        ? Object.freeze({ name: error.name, message: error.message })
        : null,
    }) as Readonly<Record<string, unknown>>;
    if (
      !realm.active ||
      realm.closeReason !== undefined ||
      realm.nextLocalOperationInstanceId !== operationInstanceId ||
      realm.localOperationInstanceIdExhausted ||
      device.nextIngress !== deviceIngressOrdinal ||
      device.ingressExhausted
    ) {
      closeRealmCounterIndependently(
        'counter-plan-conflict',
        'The WebGPU realm closed after a counter-plan conflict',
      );
      throw namedError('OperationError', 'WebGPU local counter plan is stale');
    }
    realm.nextLocalOperationInstanceId = nextOperationInstanceId;
    realm.localOperationInstanceIdExhausted =
      operationInstanceIdExhaustedAfter;
    device.nextIngress = nextDeviceIngress;
    device.ingressExhausted = deviceIngressExhaustedAfter;
    device.pendingLocalTimeline.push(sealedRecord);
    return Object.freeze({
      operationInstanceId,
      deviceIngressOrdinal,
      sealedRecord,
    });
  };

  const recordLocal = (
    operationId: string,
    receiver: WrapperState,
    target: WrapperState | undefined,
    convertedArguments: unknown,
    error: Error | undefined,
  ): Readonly<{
    operationInstanceId: string;
    deviceIngressOrdinal: string;
    sealedRecord: Readonly<Record<string, unknown>>;
  }> => commitLocalRecord(
    prepareLocalRecord(operationId, receiver, target?.device),
    receiver,
    target,
    convertedArguments,
    error,
  );

  const preflightCommandRecordCapacity = (
    states: readonly (WrapperState | undefined)[],
  ): readonly WrapperState[] => {
    const unique = [...new Set(states.filter(
      (state): state is WrapperState => state !== undefined,
    ))];
    if (unique.some((state) => state.records.length >= MAX_LOCAL_RECORDS)) {
      throw new RangeError('WebGPU command program exceeds its authenticated bound');
    }
    return unique;
  };

  const appendCommandRecord = (
    states: readonly WrapperState[],
    record: Readonly<Record<string, unknown>>,
  ): void => {
    for (const state of states) state.records.push(record);
  };

  const nativeReference = (
    state: WrapperState | undefined,
    singleton: boolean,
  ): Readonly<{
    kind: number;
    id: string;
    generation: string;
  }> => {
    if (singleton) {
      return Object.freeze({ kind: OBJECT_KINDS.GPU, id: bridge.realmId, generation: bridge.realmGeneration });
    }
    if (!state) return Object.freeze({ kind: 0, id: '0', generation: '0' });
    return Object.freeze({
      kind: OBJECT_KINDS[state.kind],
      id: state.objectId,
      generation: state.objectGeneration,
    });
  };

  const nativeSealedOperationAuthorities = (
    authorities: ReturnType<
      ExecutableWebGpuCodecBundle['encodeServiceRequestWithSealedOperations']
    >['sealedOperations'],
  ): readonly NativeGpuSealedOperationAuthorityV2[] => {
    if (
      !Array.isArray(authorities) ||
      authorities.length > MAX_LOCAL_RECORDS
    ) {
      throw new TypeError(
        'WebGPU sealed-operation authority projection exceeds its bound',
      );
    }
    let previousOperationInstanceId: string | undefined;
    let previousDeviceIngressOrdinal: string | undefined;
    const nativeReferenceFromCodec = (
      reference: Readonly<{
        kind: ProductionGpuWrapperKind;
        id: string;
        generation: string;
      }>,
      label: string,
    ) => {
      if (
        typeof reference !== 'object' ||
        reference === null ||
        !Object.prototype.hasOwnProperty.call(
          WEBGPU_OBJECT_KIND_TAGS,
          reference.kind,
        ) ||
        !isPositiveDecimal(reference.id) ||
        !isPositiveDecimal(reference.generation)
      ) {
        throw new TypeError(`${label} is not an exact WebGPU object reference`);
      }
      return INTRINSIC_OBJECT_FREEZE({
        kind: WEBGPU_OBJECT_KIND_TAGS[reference.kind],
        id: reference.id,
        generation: reference.generation,
      });
    };
    return INTRINSIC_OBJECT_FREEZE(authorities.map((authority, index) => {
      if (
        typeof authority !== 'object' ||
        authority === null ||
        (authority.identityClass !== 'active-route' &&
          authority.identityClass !== 'staged-local') ||
        (authority.authorityContextSource !== 'command-program' &&
          authority.authorityContextSource !== 'enclosing-carrier' &&
          authority.authorityContextSource !== 'staged-record') ||
        !Number.isInteger(authority.operationId) ||
        authority.operationId < 1 ||
        authority.operationId > 0xffff_ffff ||
        !isPositiveDecimal(authority.operationInstanceId) ||
        compareCanonicalU64Decimal(
          authority.operationInstanceId,
          '9223372036854775808',
        ) < 0 ||
        !isPositiveDecimal(authority.deviceIngressOrdinal) ||
        !isCanonicalU64Decimal(authority.capturedScopeId, false) ||
        (previousOperationInstanceId !== undefined &&
          compareCanonicalU64Decimal(
            previousOperationInstanceId,
            authority.operationInstanceId,
          ) >= 0) ||
        (previousDeviceIngressOrdinal !== undefined &&
          compareCanonicalU64Decimal(
            previousDeviceIngressOrdinal,
            authority.deviceIngressOrdinal,
          ) >= 0)
      ) {
        throw new TypeError(
          `WebGPU sealed-operation authority[${index}] is malformed`,
        );
      }
      const activeRoute = ROUTES_BY_WIRE.get(authority.operationId);
      const stagedRecord = STAGED_LOCAL_RECORDS_BY_ID.get(authority.operationId);
      const digestRequired =
        authority.authorityContextSource !== 'enclosing-carrier';
      if (
        (authority.identityClass === 'active-route'
          ? !activeRoute ||
            activeRoute.providerSubmission !== 'none' ||
            authority.authorityContextSource === 'staged-record'
          : !stagedRecord ||
            activeRoute !== undefined ||
            authority.authorityContextSource !== 'staged-record') ||
        (digestRequired
          ? typeof authority.authorityContextDigest !== 'string'
          : authority.authorityContextDigest !== undefined) ||
        (stagedRecord !== undefined &&
          authority.authorityContextDigest !==
            stagedRecord.recordIdentitySha256)
      ) {
        throw new TypeError(
          `WebGPU sealed-operation authority[${index}] has invalid identity`,
        );
      }
      const receiver = nativeReferenceFromCodec(
        authority.receiver,
        `WebGPU sealed-operation authority[${index}].receiver`,
      );
      const target = authority.target === undefined
        ? undefined
        : nativeReferenceFromCodec(
          authority.target,
          `WebGPU sealed-operation authority[${index}].target`,
        );
      previousOperationInstanceId = authority.operationInstanceId;
      previousDeviceIngressOrdinal = authority.deviceIngressOrdinal;
      return INTRINSIC_OBJECT_FREEZE({
        identityClass: authority.identityClass,
        authorityContextSource: authority.authorityContextSource,
        operationId: authority.operationId,
        operationInstanceId: authority.operationInstanceId,
        deviceIngressOrdinal: authority.deviceIngressOrdinal,
        capturedScopeId: authority.capturedScopeId,
        receiver,
        ...(target === undefined ? {} : { target }),
        ...(digestRequired
          ? {
            authorityContextDigest: lowerHexToBytes(
              authority.authorityContextDigest!,
              `WebGPU sealed-operation authority[${index}] context digest`,
            ),
          }
          : {}),
      });
    }));
  };

  const registerProvisionalSealedBatch = (
    authorities: readonly NativeGpuSealedOperationAuthorityV2[],
    metadata: NativeGpuCallMetadataV2,
    outerOperationId: number,
    outerWantsPromise: boolean,
  ): PendingSealedBatch | undefined => {
    if (authorities.length === 0) return undefined;
    const childIds = INTRINSIC_OBJECT_FREEZE(
      authorities.map((authority) => authority.operationInstanceId),
    );
    const batch: PendingSealedBatch = {
      childIds,
      outerOperationId,
      outerWantsPromise,
      outerMetadata: metadata,
      nextTerminalIndex: 0,
      accepted: false,
      parentOperationInstanceId: undefined,
      parentPromiseId: undefined,
      carrierAuthorityContextDigest: undefined,
      terminalObserved: false,
    };
    const routedDeviceKey = deviceKey(
      metadata.logicalDeviceId,
      metadata.logicalDeviceGeneration,
      metadata.providerGeneration,
    );
    for (const authority of authorities) {
      if (realm.pendingSealedOperations.has(authority.operationInstanceId)) {
        throw new TypeError('WebGPU sealed-operation identity is already pending');
      }
    }
    const insertedChildIds: string[] = [];
    try {
      for (const authority of authorities) {
        realm.pendingSealedOperations.set(authority.operationInstanceId, {
          authority,
          deviceKey: routedDeviceKey,
          logicalDeviceId: metadata.logicalDeviceId,
          logicalDeviceGeneration: metadata.logicalDeviceGeneration,
          providerGeneration: metadata.providerGeneration,
          operationProviderGeneration: metadata.operationProviderGeneration,
          batch,
        });
        insertedChildIds.push(authority.operationInstanceId);
      }
      realm.provisionalSealedBatches.add(batch);
    } catch (error) {
      // The caller cannot receive `batch` until this function returns, so
      // registration owns rollback for every partial Map/Set mutation.
      realm.provisionalSealedBatches.delete(batch);
      for (const childId of insertedChildIds) {
        const pending = realm.pendingSealedOperations.get(childId);
        if (pending?.batch === batch) {
          realm.pendingSealedOperations.delete(childId);
        }
      }
      throw error;
    }
    return batch;
  };

  const removeSealedBatch = (batch: PendingSealedBatch | undefined): void => {
    if (!batch) return;
    for (const childId of batch.childIds) {
      const pending = realm.pendingSealedOperations.get(childId);
      if (pending?.batch === batch) {
        realm.pendingSealedOperations.delete(childId);
      }
    }
    realm.provisionalSealedBatches.delete(batch);
    if (
      batch.parentOperationInstanceId !== undefined &&
      realm.pendingSealedBatches.get(batch.parentOperationInstanceId) === batch
    ) {
      realm.pendingSealedBatches.delete(batch.parentOperationInstanceId);
    }
  };

  const acceptSealedBatch = (
    batch: PendingSealedBatch | undefined,
    parentOperationInstanceId: string,
    parentPromiseId: string,
  ): void => {
    if (!batch) return;
    if (
      !isPositiveDecimal(parentOperationInstanceId) ||
      compareCanonicalU64Decimal(
        parentOperationInstanceId,
        '9223372036854775808',
      ) >= 0 ||
      batch.accepted ||
      batch.parentOperationInstanceId !== undefined ||
      batch.parentPromiseId !== undefined ||
      (batch.outerWantsPromise
        ? !isPositiveDecimal(parentPromiseId)
        : parentPromiseId !== '0') ||
      !realm.provisionalSealedBatches.has(batch) ||
      realm.pendingSealedBatches.has(parentOperationInstanceId)
    ) {
      throw new TypeError('WebGPU sealed-operation parent identity is invalid');
    }
    batch.accepted = true;
    batch.parentOperationInstanceId = parentOperationInstanceId;
    batch.parentPromiseId = parentPromiseId;
    realm.provisionalSealedBatches.delete(batch);
    realm.pendingSealedBatches.set(parentOperationInstanceId, batch);
  };

  const presentationAuthorityMetadata = (
    context: WrapperState,
    texture: WrapperState,
    plan: LocalRecordPlan,
  ): NativeGpuPresentationAuthorityMetadataV2 => {
    const device = plan.device;
    if (
      context.kind !== 'GPUCanvasContext' ||
      texture.kind !== 'GPUTexture' ||
      context.configuredDevice !== device ||
      texture.device !== device
    ) {
      throw new TypeError('Canvas presentation authority target is inconsistent');
    }
    const receiver = nativeReference(context, false);
    const target = nativeReference(texture, false);
    return Object.freeze({
      accountId: bridge.rootAccountId,
      accountGeneration: bridge.rootAccountGeneration,
      authorityDigest: bridge.rootAuthorityDigest,
      logicalDeviceId: device.logicalDeviceId,
      logicalDeviceGeneration: device.logicalDeviceGeneration,
      providerGeneration: device.providerGeneration,
      operationProviderGeneration: device.providerGeneration,
      operationInstanceId: plan.operationInstanceId,
      capturedScopeId: plan.capturedScopeId,
      adapterOrdinal: '0',
      deviceIngressOrdinal: plan.deviceIngressOrdinal,
      queueIngressOrdinal: '0',
      receiverKind: receiver.kind,
      receiverId: receiver.id,
      receiverGeneration: receiver.generation,
      targetKind: target.kind,
      targetId: target.id,
      targetGeneration: target.generation,
      sealedOperations: Object.freeze([]),
    });
  };

  interface ServiceCounterPlan {
    readonly selected: ProductionRoute;
    readonly receiver: WrapperState;
    readonly device: DeviceState | undefined;
    readonly deviceIngressOrdinal: string;
    readonly nextDeviceIngress: string | undefined;
    readonly deviceIngressExhaustedAfter: boolean;
    readonly queueIngressOrdinal: string;
    readonly nextQueueIngress: string | undefined;
    readonly queueIngressExhaustedAfter: boolean;
    readonly adapterOrdinal: string;
    readonly nextAdapterOrdinal: string | undefined;
    readonly adapterOrdinalExhaustedAfter: boolean;
    readonly capturedScopeId: string;
  }

  const prepareServiceCounters = (
    operationId: string,
    receiver: WrapperState,
    targetDevice?: DeviceState,
  ): ServiceCounterPlan => {
    if (!realm.active) throw namedError('SecurityError', 'WebGPU realm is revoked');
    const selected = route(operationId);
    if (selected.providerSubmission === 'none') {
      throw new Error(`${operationId} has no semantic service route`);
    }
    const projection = selected.serviceReceiverProjection;
    if (
      projection.source !== 'wrapper-full-reference' &&
      projection.source !== 'realm-gpu-singleton'
    ) {
      throw new Error(`${operationId} has an invalid service receiver projection`);
    }
    if (
      projection.source === 'wrapper-full-reference' &&
      selected.receiverHandleKind !== receiver.kind
    ) {
      throw new TypeError(`${operationId} receiver projection does not match its wrapper`);
    }
    const device = receiver.device ?? targetDevice;
    const ingressPlan = device
      ? consumeNextCounterOrClose(
        device.nextIngress,
        device.ingressExhausted,
        'device ingress ordinal',
      )
      : undefined;
    const entersPhysicalQueue =
      selected.receiverHandleKind === 'GPUQueue' ||
      operationId === 'GPUCanvasContext.configure' ||
      operationId === 'GPUCanvasContext.unconfigure';
    const queuePlan = entersPhysicalQueue && device
      ? consumeNextCounterOrClose(
        device.nextQueueIngress,
        device.queueIngressExhausted,
        'queue ingress ordinal',
      )
      : undefined;
    const adapterPlan = operationId === 'GPUAdapter.requestDevice'
      ? consumeNextCounterOrClose(
        receiver.nextAdapterOrdinal,
        receiver.adapterOrdinalExhausted,
        'adapter request ordinal',
      )
      : undefined;
    return Object.freeze({
      selected,
      receiver,
      device,
      deviceIngressOrdinal: ingressPlan?.value ?? '0',
      nextDeviceIngress: ingressPlan?.next,
      deviceIngressExhaustedAfter: ingressPlan?.exhaustedAfter ?? false,
      queueIngressOrdinal: queuePlan?.value ?? '0',
      nextQueueIngress: queuePlan?.next,
      queueIngressExhaustedAfter: queuePlan?.exhaustedAfter ?? false,
      adapterOrdinal: adapterPlan?.value ?? '0',
      nextAdapterOrdinal: adapterPlan?.next,
      adapterOrdinalExhaustedAfter: adapterPlan?.exhaustedAfter ?? false,
      capturedScopeId: currentScopeId(device),
    });
  };

  const submitService = (
    operationId: string,
    receiver: WrapperState,
    target: WrapperState | undefined,
    convertedArguments: unknown,
    wantsPromise: boolean,
    preparedPlan?: ServiceCounterPlan,
    beforeNativeSubmit?: () => void,
    onNativeSubmitFailure?: (failure: ServiceSubmissionFailureKind) => void,
    canvasService?: ProductionGpuCanvasServiceEncoding,
    bufferLifecycle?: ProductionGpuBufferLifecycleEncoding,
    afterNativeSubmit?: (identity: Readonly<{
      operationInstanceId: string;
      promiseId: string;
    }>) => void,
    errorScopeService?: ProductionGpuErrorScopeServiceEncoding,
  ) => {
    const plan = preparedPlan ?? prepareServiceCounters(
      operationId,
      receiver,
      target?.device,
    );
    const { selected } = plan;
    if (selected.operationId !== operationId || plan.receiver !== receiver) {
      throw new Error(`${operationId} received an incompatible counter plan`);
    }
    const projection = selected.serviceReceiverProjection;
    const singleton = projection.source === 'realm-gpu-singleton';
    const {
      device,
      deviceIngressOrdinal,
      queueIngressOrdinal,
      adapterOrdinal,
      capturedScopeId,
    } = plan;
    if ((receiver.device ?? target?.device) !== device) {
      throw new Error(`${operationId} counter plan changed logical device`);
    }
    // writeBuffer owns an immediate affine byte snapshot and queue ordinal,
    // and wrapper-owned buffer lifecycle calls are likewise independent of
    // command recording, so they must neither consume nor duplicate command
    // records still waiting for their eventual queue.submit carrier. A pending
    // canvas-current mint likewise remains pending until a carrier that
    // authenticates that exact origin takes it. Direct createView/destroy
    // selects only its receiver's mint record; queue.submit/popErrorScope take
    // the contiguous global prefix. Unrelated accepted operations cannot
    // silently erase the source-affine origin/materialization obligation.
    const carriesCanvasCurrentOrigin =
      operationId === 'GPUQueue.submit' ||
      operationId === 'GPUDevice.popErrorScope' ||
      ((operationId === 'GPUTexture.createView' ||
        operationId === 'GPUTexture.destroy') &&
        receiver.kind === 'GPUTexture' &&
        receiver.currentOrigin !== undefined);
    const directCanvasCurrentMaterialization =
      operationId === 'GPUTexture.createView'
        ? receiver.kind === 'GPUTexture' &&
          receiver.currentOrigin !== undefined &&
          !receiver.materialized
        : operationId === 'GPUTexture.destroy' &&
          canvasService?.kind === 'texture-destroy-v1' &&
          canvasService.terminalIntent === 'first-cleanup' &&
          canvasService.materializationState === 'unmaterialized' &&
          canvasService.origin.kind === 'canvas-current-v1';
    const directCanvasCurrentRecords =
      directCanvasCurrentMaterialization && device
        ? device.pendingCurrentTextureMaterializations.get(receiver)?.records
        : undefined;
    const sealedLocalTimeline = Object.freeze(
      directCanvasCurrentRecords !== undefined
        ? directCanvasCurrentRecords.slice()
        : (operationId === 'GPUQueue.submit' ||
            operationId === 'GPUDevice.popErrorScope')
          ? device?.pendingLocalTimeline.slice() ?? []
          : [],
    );
    const prefixCurrentTextureOrigins = Object.freeze(
      sealedLocalTimeline.length === 0 || !device
        ? []
        : [...device.pendingCurrentTextureMaterializations.entries()]
          .filter(([, origin]) =>
            origin.records.every((record) => sealedLocalTimeline.includes(record))
          )
    );
    const receiverReference = singleton
      ? Object.freeze({
        kind: 'GPU' as const,
        objectId: bridge.realmId,
        objectGeneration: bridge.realmGeneration,
        logicalDeviceId: '0',
        logicalDeviceGeneration: '0',
        providerGeneration: '0',
      })
      : reference(receiver.wrapper, receiver.kind);
    const targetReference = target
      ? reference(target.wrapper, target.kind)
      : undefined;
    const encodedRequest = codecs.encodeServiceRequestWithSealedOperations({
      operationId,
      wireId: selected.wireId,
      convertedArguments,
      receiver: receiverReference,
      target: targetReference,
      capturedScopeId,
      adapterOrdinal,
      deviceIngressOrdinal,
      queueIngressOrdinal,
      sealedLocalTimeline,
      ...(canvasService === undefined ? {} : { canvasService }),
      ...(bufferLifecycle === undefined ? {} : { bufferLifecycle }),
      ...(errorScopeService === undefined ? {} : { errorScopeService }),
    });
    const payload = encodedRequest.payload;
    const sealedOperations = nativeSealedOperationAuthorities(
      encodedRequest.sealedOperations,
    );
    if (
      sealedOperations.length !== sealedLocalTimeline.length ||
      realm.pendingSealedOperations.size >
        MAX_LOCAL_RECORDS - sealedOperations.length
    ) {
      throw new TypeError(
        'WebGPU sealed-operation projection is incomplete or exceeds its pending bound',
      );
    }
    const payloadIsView = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_ARRAY_BUFFER_IS_VIEW,
      INTRINSIC_ARRAY_BUFFER,
      [payload],
    );
    const payloadLength = payloadIsView
      ? payload.byteLength
      : (INTRINSIC_REFLECT_CONSTRUCT(
        INTRINSIC_UINT8_ARRAY,
        [payload],
      ) as Uint8Array).byteLength;
    if (payloadLength > WEBGPU_PRODUCTION_PLAN.maxPayloadBytes) {
      throw new TypeError('WebGPU service payload exceeds the authenticated bound');
    }

    const wireReceiver = nativeReference(receiver, singleton);
    const wireTarget = nativeReference(target, false);
    const metadata: NativeGpuCallMetadataV2 = {
      accountId: bridge.rootAccountId,
      accountGeneration: bridge.rootAccountGeneration,
      authorityDigest: bridge.rootAuthorityDigest,
      logicalDeviceId: device?.logicalDeviceId ?? '0',
      logicalDeviceGeneration: device?.logicalDeviceGeneration ?? '0',
      providerGeneration: device?.providerGeneration ?? '0',
      operationProviderGeneration:
        device?.providerGeneration ?? receiver.providerGeneration,
      capturedScopeId,
      adapterOrdinal,
      deviceIngressOrdinal,
      queueIngressOrdinal,
      receiverKind: wireReceiver.kind,
      receiverId: wireReceiver.id,
      receiverGeneration: wireReceiver.generation,
      targetKind: wireTarget.kind,
      targetId: wireTarget.id,
      targetGeneration: wireTarget.generation,
      sealedOperations,
    };
    if (
      !realm.active ||
      realm.closeReason !== undefined ||
      (device && device.nextIngress !== deviceIngressOrdinal) ||
      (device && device.ingressExhausted) ||
      (plan.nextQueueIngress !== undefined &&
        (device?.nextQueueIngress !== queueIngressOrdinal ||
          device.queueIngressExhausted)) ||
      (plan.nextAdapterOrdinal !== undefined &&
        (receiver.nextAdapterOrdinal !== adapterOrdinal ||
          receiver.adapterOrdinalExhausted))
    ) {
      closeRealmCounterIndependently(
        'counter-plan-conflict',
        'The WebGPU realm closed after a counter-plan conflict',
      );
      throw namedError('OperationError', 'WebGPU service counter plan is stale');
    }
    if (device && plan.nextDeviceIngress !== undefined) {
      device.nextIngress = plan.nextDeviceIngress;
      device.ingressExhausted = plan.deviceIngressExhaustedAfter;
    }
    if (device && plan.nextQueueIngress !== undefined) {
      device.nextQueueIngress = plan.nextQueueIngress;
      device.queueIngressExhausted = plan.queueIngressExhaustedAfter;
    }
    if (plan.nextAdapterOrdinal !== undefined) {
      receiver.nextAdapterOrdinal = plan.nextAdapterOrdinal;
      receiver.adapterOrdinalExhausted = plan.adapterOrdinalExhaustedAfter;
    }
    beforeNativeSubmit?.();
    let carrier: ReturnType<NativeGpuBridgeV2['submit']>;
    let sealedBatch: PendingSealedBatch | undefined;
    try {
      // Install exact child reservations before native submit so even a
      // synchronous owner drain cannot race an unregistered terminal.
      sealedBatch = registerProvisionalSealedBatch(
        metadata.sealedOperations,
        metadata,
        selected.wireId,
        wantsPromise,
      );
      carrier = bridge.submit(selected.wireId, wantsPromise, metadata, payload);
    } catch (error) {
      if (sealedBatch?.terminalObserved) {
        closeRealmCounterIndependently(
          'sealed-operation-callback-then-rejection',
          'The WebGPU realm closed after a sealed terminal preceded submit failure',
        );
      } else {
        removeSealedBatch(sealedBatch);
      }
      onNativeSubmitFailure?.('bridge-threw');
      throw error;
    }
    if (carrier.submissionStatus !== 0) {
      if (sealedBatch?.terminalObserved) {
        closeRealmCounterIndependently(
          'sealed-operation-callback-then-rejection',
          'The WebGPU realm closed after a sealed terminal preceded service rejection',
        );
      } else {
        removeSealedBatch(sealedBatch);
      }
      carrier.receipt?.catch(() => undefined);
      onNativeSubmitFailure?.('submission-rejected');
      throw namedError(
        'OperationError',
        `WebGPU semantic service rejected ${operationId} (${carrier.submissionStatus})`,
      );
    }
    try {
      acceptSealedBatch(
        sealedBatch,
        carrier.operationInstanceId,
        carrier.promiseId,
      );
    } catch {
      removeSealedBatch(sealedBatch);
      closeRealmCounterIndependently(
        'sealed-operation-parent-malformed',
        'The WebGPU realm closed after malformed sealed-operation parent admission',
      );
      carrier.receipt?.catch(() => undefined);
      throw namedError(
        'OperationError',
        'WebGPU sealed-operation parent admission was malformed',
      );
    }
    afterNativeSubmit?.(Object.freeze({
      operationInstanceId: carrier.operationInstanceId,
      promiseId: carrier.promiseId,
    }));
    if (!realm.active || realm.closeReason !== undefined) {
      carrier.receipt?.catch(() => undefined);
      throw namedError(
        'SecurityError',
        `WebGPU realm closed during ${operationId}`,
      );
    }
    if (device) {
      if (directCanvasCurrentRecords !== undefined) {
        for (const currentRecord of directCanvasCurrentRecords) {
          const recordIndex = device.pendingLocalTimeline.indexOf(currentRecord);
          if (recordIndex >= 0) {
            device.pendingLocalTimeline.splice(recordIndex, 1);
          }
        }
      } else {
        device.pendingLocalTimeline.splice(0, sealedLocalTimeline.length);
      }
      if (
        operationId === 'GPUQueue.submit' ||
        operationId === 'GPUDevice.popErrorScope'
      ) {
        for (const [texture, origin] of prefixCurrentTextureOrigins) {
          device.pendingCurrentTextureMaterializations.delete(texture);
          if (origin.materializesOnPrefixCarrier) texture.materialized = true;
        }
      }
      if (
        (operationId === 'GPUTexture.createView' ||
          operationId === 'GPUTexture.destroy') &&
        receiver.kind === 'GPUTexture' &&
        receiver.currentOrigin !== undefined
      ) {
        // Direct texture carriers authenticate their receiver's immutable
        // origin independently of whether its original mint record remains in
        // this particular contiguous prefix. Never settle a second context's
        // obligation merely because that record shared the encoded prefix.
        const directOrigin =
          device.pendingCurrentTextureMaterializations.get(receiver);
        device.pendingCurrentTextureMaterializations.delete(receiver);
        if (directOrigin?.materializesOnPrefixCarrier) {
          receiver.materialized = true;
        }
      }
    }
    if (!wantsPromise) return undefined;
    if (!carrier.receipt || carrier.promiseId === '0') {
      throw new Error(`${operationId} did not return its required receipt`);
    }
    realm.pendingPromiseCalls.set(carrier.operationInstanceId, {
      route: selected,
      promiseId: carrier.promiseId,
      deviceKey: device === undefined
        ? undefined
        : deviceKey(
          device.logicalDeviceId,
          device.logicalDeviceGeneration,
          device.providerGeneration,
        ),
    });
    return carrier.receipt.then(
      () => {
        const event = realm.resultEvents.get(carrier.operationInstanceId);
        realm.resultEvents.delete(carrier.operationInstanceId);
        realm.pendingPromiseCalls.delete(carrier.operationInstanceId);
        if (!event || event.promiseId !== carrier.promiseId) {
          throw new Error(`${operationId} completed without its typed raw event`);
        }
        return codecs.decodeServiceResult(operationId, event);
      },
      (error) => {
        realm.resultEvents.delete(carrier.operationInstanceId);
        realm.pendingPromiseCalls.delete(carrier.operationInstanceId);
        throw error;
      },
    );
  };

  const checkpointHostTask = (): void => {
    if (!realm.active || realm.closeReason !== undefined) {
      throw namedError('SecurityError', 'WebGPU realm is revoked');
    }
    const contextByTexture = new Map<WrapperState, WrapperState>();
    for (const context of realm.hostCanvasContextsByIdentity.values()) {
      if (context.currentTexture === undefined) continue;
      if (
        (context.canvasContextLifecycle !== 'configured' &&
          context.canvasContextLifecycle !== 'lost') ||
        !context.configuredDevice
      ) {
        closeRealmCounterIndependently(
          'canvas-host-task-checkpoint-state',
          'The WebGPU realm closed after an inconsistent Canvas host-task checkpoint',
        );
        throw namedError(
          'OperationError',
          'GPUCanvasContext host-task checkpoint state is inconsistent',
        );
      }
      const texture = requireState(context.currentTexture, 'GPUTexture');
      if (
        texture.device !== context.configuredDevice ||
        texture.currentOrigin === undefined ||
        texture.textureExpired
      ) {
        closeRealmCounterIndependently(
          'canvas-host-task-checkpoint-origin',
          'The WebGPU realm closed after a Canvas host-task origin mismatch',
        );
        throw namedError(
          'OperationError',
          'GPUCanvasContext host-task checkpoint origin is inconsistent',
        );
      }
      contextByTexture.set(texture, context);
      realm.pendingCanvasTextureExpiries.add(texture);
    }
    const currentTextures = [...new Set([
      ...realm.pendingCanvasTextureExpiries,
      ...contextByTexture.keys(),
    ])]
      .filter((texture) => !texture.textureExpired)
      .sort((left, right) => {
        const objectOrder = compareCanonicalU64Decimal(
          left.objectId,
          right.objectId,
        );
        return objectOrder !== 0
          ? objectOrder
          : compareCanonicalU64Decimal(
            left.objectGeneration,
            right.objectGeneration,
          );
      });

    // Validate and encode the complete deterministic set before the first
    // service submission. Native may have accepted an earlier expiry when a
    // later one rejects, so the wrapper commits no local epoch transition
    // until every source-affine control is accepted; the native caller then
    // reduces the realm if this function throws.
    for (const texture of currentTextures) {
      submitCanvasTextureExpiry(
        texture,
        'canvas-host-task-checkpoint-threw',
        'The WebGPU realm closed because Canvas host-task expiry threw',
      );
    }
    for (const texture of currentTextures) {
      // Native accepted the source-affine expiry before the wrapper drops its
      // current identity. Manual destroy is orthogonal: an already-destroyed
      // current texture still reaches this branch and preserves its immutable
      // drawing buffer until this exact checkpoint.
      finalizeCanvasTextureExpiry(texture);
      const context = contextByTexture.get(texture);
      if (context?.currentTexture === texture.wrapper) {
        context.currentTexture = undefined;
      }
    }
  };

  const materializeObject = (
    decoded: ProductionGpuDecodedResult,
    expectedKind: ProductionGpuAllocatedWrapperKind,
    nullable: boolean,
  ): object | null | unknown => {
    if (decoded.kind === 'null') {
      if (nullable) return null;
      throw new TypeError(`${expectedKind} result cannot be null`);
    }
    if (decoded.kind !== 'object') {
      throw new TypeError(`${expectedKind} result must carry an object identity`);
    }
    const identity: ProductionGpuObjectIdentity = decoded.object;
    if (identity.kind !== expectedKind) {
      throw new TypeError(
        `WebGPU result kind ${identity.kind} does not match ${expectedKind}`,
      );
    }
    if (expectedKind === 'GPUAdapter') {
      const state = allocateWrapper('GPUAdapter', undefined, identity);
      state.providerGeneration = identity.providerGeneration ?? '0';
      if (!isPositiveDecimal(state.providerGeneration)) {
        throw new TypeError('GPUAdapter result lacks a provider generation');
      }
      if (typeof identity.serviceDetachedExpired !== 'boolean') {
        throw new TypeError(
          'GPUAdapter result lacks authenticated detached state',
        );
      }
      state.expired = identity.serviceDetachedExpired;
      state.serviceDetached = identity.serviceDetachedExpired;
      if (!Array.isArray(identity.features)) {
        throw new TypeError(
          'GPUAdapter result lacks authenticated exposed features',
        );
      }
      const knownFeatureNames: readonly string[] =
        WEBGPU_PRODUCTION_PLAN.webIdlVocabulary.gpuFeatureNames;
      const adapterFeatureNames = normalizeFeatureNames(identity.features);
      if (
        identity.features.some(
          (feature, index) =>
            typeof feature !== 'string' ||
            !knownFeatureNames.includes(feature) ||
            adapterFeatureNames[index] !== feature,
        ) ||
        adapterFeatureNames.length !== identity.features.length
      ) {
        throw new TypeError(
          'GPUAdapter result features must be known, sorted, and unique',
        );
      }
      state.adapterFeatureNames = adapterFeatureNames;
      state.adapterFeatures = createReadonlyFeatureSet(
        state.adapterFeatureNames,
        featurePrototype,
        featureStates,
      );
      return state.wrapper;
    }
    if (expectedKind === 'GPUDevice') {
      const logicalDeviceId = identity.logicalDeviceId ?? '0';
      const logicalDeviceGeneration = identity.logicalDeviceGeneration ?? '0';
      const providerGeneration = identity.providerGeneration ?? '0';
      if (
        !isPositiveDecimal(logicalDeviceId) ||
        !isPositiveDecimal(logicalDeviceGeneration) ||
        !isPositiveDecimal(providerGeneration) ||
        !identity.queue
      ) {
        throw new TypeError('GPUDevice result lacks its full typed identity');
      }
      const featureNames = normalizeFeatureNames(identity.features ?? []);
      const device: DeviceState = {
        logicalDeviceId,
        logicalDeviceGeneration,
        providerGeneration,
        features: createReadonlyFeatureSet(
          featureNames,
          featurePrototype,
          featureStates,
        ),
        featureNames,
        limits: Object.freeze(
          Object.assign(
            Object.create(supportedLimitsPrototype) as Record<string, number>,
            identity.limits ?? {},
          ),
        ),
        lost: makeLostController(),
        eventTarget: undefined,
        queue: undefined,
        destroyed: false,
        nextIngress: counterSeed('nextDeviceIngressOrdinal', '1', true),
        ingressExhausted: false,
        nextQueueIngress: counterSeed('nextQueueIngressOrdinal', '1', true),
        queueIngressExhausted: false,
        nextScope: counterSeed('nextScopeId', '1', true),
        scopeExhausted: false,
        scopeStackGeneration: '1',
        scopes: [],
        pendingLocalTimeline: [],
        pendingCurrentTextureMaterializations: new Map(),
        configuredCanvasContexts: new Set(),
        buffers: new Set(),
      };
      const state = allocateWrapper('GPUDevice', device, identity);
      device.eventTarget = state.wrapper as EventTarget;
      const queue = allocateWrapper('GPUQueue', device, identity.queue);
      device.queue = queue.wrapper;
      // An expired-adapter result is a fresh service-detached wrapper. Its
      // stable lost promise must settle before requestDevice resolves, but
      // the realm must not retain an unbounded series of these results or
      // route later service lifecycle events into them.
      if (identity.alreadyLost) {
        settleDeviceLost(
          device,
          identity.alreadyLost.reason,
          identity.alreadyLost.message,
        );
      } else {
        realm.devices.set(
          deviceKey(logicalDeviceId, logicalDeviceGeneration, providerGeneration),
          device,
        );
      }
      return state.wrapper;
    }
    return allocateWrapper(expectedKind, undefined, identity).wrapper;
  };

  const decodePromiseObject = (
    operationId: string,
    promise: Promise<ProductionGpuDecodedResult>,
    expectedKind: ProductionGpuAllocatedWrapperKind,
    nullable = false,
  ): Promise<unknown> =>
    promise.then((decoded) => materializeObject(decoded, expectedKind, nullable));

  const settleLossEvent = (
    event: Extract<NativeGpuEventV2, { kind: 3 | 4 | 5 | 6 }>,
  ): void => {
    const decoded = codecs.decodeDeviceLoss(event);
    if (event.kind === 4) {
      const device = realm.devices.get(
        deviceKey(
          event.logicalDeviceId,
          event.logicalDeviceGeneration,
          event.providerGeneration,
        ),
      );
      if (device) settleDeviceLost(device, decoded.reason, decoded.message);
      return;
    }
    if (event.kind === 3) {
      for (const device of [...realm.devices.values()]) {
        if (device.providerGeneration === event.providerGeneration) {
          settleDeviceLost(device, decoded.reason, decoded.message);
        }
      }
      return;
    }
    clearRealmBufferMappings(
      true,
      'GPUBuffer mapping was cancelled by owning lifecycle cleanup',
    );
    for (const device of [...realm.devices.values()]) {
      settleDeviceLost(device, decoded.reason, decoded.message);
    }
    if (event.kind === 6) retireRealmState();
  };

  const makeUncapturedGpuError = (
    errorKind: 1 | 2 | 3,
    message: string,
  ): object => {
    const constructor = errorKind === 1
      ? gpuValidationErrorConstructor
      : errorKind === 2
        ? gpuOutOfMemoryErrorConstructor
        : gpuInternalErrorConstructor;
    const prototype =
      (constructor as Readonly<{ prototype: object }>).prototype;
    const error = INTRINSIC_OBJECT_CREATE(prototype) as object;
    INTRINSIC_OBJECT_DEFINE_PROPERTY(error, 'message', {
      value: message,
      enumerable: true,
      configurable: false,
    });
    return error;
  };

  const makeUncapturedErrorEvent = (error: object): Event => {
    const event = INTRINSIC_REFLECT_CONSTRUCT(
      Event,
      [
        'uncapturederror',
        {
          bubbles: false,
          cancelable: false,
          composed: false,
        },
      ],
    ) as Event;
    INTRINSIC_OBJECT_SET_PROTOTYPE_OF(
      event,
      gpuUncapturedErrorEventPrototype,
    );
    gpuUncapturedErrorEventStates.set(event, error);
    return event;
  };

  const scheduleNextUncapturedErrorTask = (): void => {
    if (
      !realm.active ||
      realm.uncapturedErrorTaskScheduled ||
      realm.pendingUncapturedErrors.length === 0
    ) {
      return;
    }
    realm.uncapturedErrorTaskScheduled = true;
    try {
      INTRINSIC_REFLECT_APPLY(
        INTRINSIC_SET_TIMEOUT!,
        INTRINSIC_GLOBAL_THIS,
        [
          () => {
            realm.uncapturedErrorTaskScheduled = false;
            const pending = realm.pendingUncapturedErrors.shift();
            if (!pending) return;
            realm.pendingUncapturedDiagnosticBytes -=
              pending.eventByteLength;
            try {
              if (!realm.active) return;
              const event = makeUncapturedErrorEvent(pending.error);
              try {
                INTRINSIC_REFLECT_APPLY(
                  INTRINSIC_EVENT_TARGET_DISPATCH,
                  pending.target,
                  [event],
                );
              } catch {
                // Listener reporting is app-observable behavior, not carrier
                // authority. It cannot strand later authenticated ingress.
              }
            } catch {
              closeRealmCounterIndependently(
                'uncaptured-error-dispatch-invariant',
                'The WebGPU realm closed after uncaptured-error dispatch failed',
              );
            } finally {
              // WebGPU queues one task per notification. Schedule the next
              // FIFO item even when this task observed a listener/reporting
              // exception; realm closure clears the remainder explicitly.
              scheduleNextUncapturedErrorTask();
            }
          },
          0,
        ],
      );
    } catch {
      realm.uncapturedErrorTaskScheduled = false;
      closeRealmCounterIndependently(
        'uncaptured-error-task-scheduling',
        'The WebGPU realm closed after uncaptured-error task scheduling failed',
      );
    }
  };

  const closeForMalformedUncapturedError = (): void => {
    closeRealmCounterIndependently(
      'uncaptured-error-malformed',
      'The WebGPU realm closed after malformed uncaptured-error ingress',
    );
  };

  const closeForMalformedOperationTerminal = (): void => {
    closeRealmCounterIndependently(
      'operation-terminal-malformed',
      'The WebGPU realm closed after malformed operation-terminal ingress',
    );
  };

  const eventAuthorityContextDigest = (
    event: Extract<NativeGpuEventV2, { kind: 1 | 2 }>,
  ): string => bytesToLowerHex(copyExactUint8View(
    event.authorityContextDigest,
    32,
    'WebGPU operation authority context digest',
  ));

  const eventHasExactEmptyPayload = (
    event: Extract<NativeGpuEventV2, { kind: 1 | 2 }>,
  ): boolean => {
    try {
      copyExactUint8View(event.payload, 0, 'WebGPU empty operation payload');
      return true;
    } catch {
      return false;
    }
  };

  const validateAndConsumeSealedTerminal = (
    event: Extract<NativeGpuEventV2, { kind: 1 | 2 }>,
  ): PendingSealedOperation | undefined => {
    const pending = realm.pendingSealedOperations.get(
      event.operationInstanceId,
    );
    if (!pending) return undefined;
    const { authority, batch } = pending;
    batch.terminalObserved = true;
    const target = authority.target;
    let actualContextDigest: string;
    try {
      actualContextDigest = eventAuthorityContextDigest(event);
      const expectedContextDigest = authority.authorityContextDigest === undefined
        ? undefined
        : bytesToLowerHex(copyExactUint8View(
          authority.authorityContextDigest,
          32,
          'WebGPU sealed-operation context digest',
        ));
      if (
        (!batch.accepted &&
          !realm.provisionalSealedBatches.has(batch)) ||
        batch.childIds[batch.nextTerminalIndex] !==
          event.operationInstanceId ||
        event.topologyId !== 1 ||
        event.runtimeAddress !== bridge.runtimeAddress ||
        event.runtimeNonce !== bridge.runtimeNonce ||
        event.realmId !== bridge.realmId ||
        event.realmGeneration !== bridge.realmGeneration ||
        event.accountId !== bridge.rootAccountId ||
        event.accountGeneration !== bridge.rootAccountGeneration ||
        bytesToLowerHex(copyExactUint8View(
          event.accountAuthorityDigest,
          32,
          'WebGPU sealed-operation account authority digest',
        )) !== bytesToLowerHex(copyExactUint8View(
          bridge.rootAuthorityDigest,
          32,
          'WebGPU root account authority digest',
        )) ||
        event.operationId !== authority.operationId ||
        event.promiseId !== '0' ||
        event.adapterOrdinal !== '0' ||
        event.queueIngressOrdinal !== '0' ||
        event.capturedScopeId !== authority.capturedScopeId ||
        event.deviceIngressOrdinal !== authority.deviceIngressOrdinal ||
        event.logicalDeviceId !== pending.logicalDeviceId ||
        event.logicalDeviceGeneration !== pending.logicalDeviceGeneration ||
        event.providerGeneration !== pending.providerGeneration ||
        event.ingressLogicalDeviceId !== pending.logicalDeviceId ||
        event.ingressLogicalDeviceGeneration !==
          pending.logicalDeviceGeneration ||
        event.ingressProviderGeneration !== pending.providerGeneration ||
        event.operationProviderGeneration !==
          pending.operationProviderGeneration ||
        event.deviceTransition !== 0 ||
        event.receiverKind !== authority.receiver.kind ||
        event.receiverFlags !== 0 ||
        event.receiverId !== authority.receiver.id ||
        event.receiverGeneration !== authority.receiver.generation ||
        event.targetKind !== (target?.kind ?? 0) ||
        event.targetFlags !== 0 ||
        event.targetId !== (target?.id ?? '0') ||
        event.targetGeneration !== (target?.generation ?? '0') ||
        (expectedContextDigest !== undefined &&
          actualContextDigest !== expectedContextDigest) ||
        (authority.authorityContextSource === 'enclosing-carrier' &&
          batch.carrierAuthorityContextDigest !== undefined &&
          batch.carrierAuthorityContextDigest !== actualContextDigest)
      ) {
        throw new TypeError('Malformed sealed-operation provenance');
      }
      if (event.kind === 1) {
        if (
          event.resultKind !== 0 ||
          event.status !== 0 ||
          event.detachedAlreadyLost !== false ||
          event.providerAdmission !== 0 ||
          event.physicalSequence !== '0' ||
          !eventHasExactEmptyPayload(event)
        ) {
          throw new TypeError('Malformed sealed-operation success terminal');
        }
      } else {
        if (
          typeof event.uncapturedError !== 'boolean' ||
          !Number.isInteger(event.errorKind) ||
          event.errorKind < 1 ||
          event.errorKind > 3 ||
          !Number.isInteger(event.status) ||
          event.status === 0 ||
          event.providerAdmission !== 0 ||
          event.physicalSequence !== '0' ||
          event.backendClass !== 0
        ) {
          throw new TypeError('Malformed sealed-operation error terminal');
        }
        const diagnostic = copyExactUint8View(
          event.payload,
          INTRINSIC_REFLECT_APPLY(
            INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER!,
            event.payload,
            [],
          ) as number,
          'WebGPU sealed-operation error diagnostic',
        );
        if (
          diagnostic.byteLength > MAX_UNCAPTURED_ERROR_DIAGNOSTIC_BYTES
        ) {
          throw new TypeError(
            'Sealed-operation error diagnostic exceeds its bound',
          );
        }
        decodeCanonicalGpuErrorDiagnostic(diagnostic);
      }
    } catch {
      closeForMalformedOperationTerminal();
      return undefined;
    }
    if (authority.authorityContextSource === 'enclosing-carrier') {
      batch.carrierAuthorityContextDigest ??= actualContextDigest;
    }
    realm.pendingSealedOperations.delete(event.operationInstanceId);
    batch.nextTerminalIndex += 1;
    return pending;
  };

  const consumeOuterSealedBatchTerminal = (
    event: Extract<NativeGpuEventV2, { kind: 1 | 2 }>,
  ): boolean => {
    const batch = realm.pendingSealedBatches.get(event.operationInstanceId);
    if (!batch) return true;
    try {
      const metadata = batch.outerMetadata;
      if (
        !batch.accepted ||
        batch.parentOperationInstanceId !== event.operationInstanceId ||
        batch.parentPromiseId === undefined ||
        event.operationId !== batch.outerOperationId ||
        event.promiseId !== batch.parentPromiseId ||
        event.topologyId !== 1 ||
        event.runtimeAddress !== bridge.runtimeAddress ||
        event.runtimeNonce !== bridge.runtimeNonce ||
        event.realmId !== bridge.realmId ||
        event.realmGeneration !== bridge.realmGeneration ||
        event.accountId !== bridge.rootAccountId ||
        event.accountGeneration !== bridge.rootAccountGeneration ||
        bytesToLowerHex(copyExactUint8View(
          event.accountAuthorityDigest,
          32,
          'WebGPU outer account authority digest',
        )) !== bytesToLowerHex(copyExactUint8View(
          bridge.rootAuthorityDigest,
          32,
          'WebGPU root account authority digest',
        )) ||
        event.logicalDeviceId !== metadata.logicalDeviceId ||
        event.logicalDeviceGeneration !== metadata.logicalDeviceGeneration ||
        event.providerGeneration !== metadata.providerGeneration ||
        event.ingressLogicalDeviceId !== metadata.logicalDeviceId ||
        event.ingressLogicalDeviceGeneration !==
          metadata.logicalDeviceGeneration ||
        event.ingressProviderGeneration !== metadata.providerGeneration ||
        event.operationProviderGeneration !==
          metadata.operationProviderGeneration ||
        event.capturedScopeId !== metadata.capturedScopeId ||
        event.adapterOrdinal !== metadata.adapterOrdinal ||
        event.deviceIngressOrdinal !== metadata.deviceIngressOrdinal ||
        event.queueIngressOrdinal !== metadata.queueIngressOrdinal ||
        event.receiverKind !== metadata.receiverKind ||
        event.receiverFlags !== 0 ||
        event.receiverId !== metadata.receiverId ||
        event.receiverGeneration !== metadata.receiverGeneration ||
        event.targetKind !== metadata.targetKind ||
        event.targetFlags !== 0 ||
        event.targetId !== metadata.targetId ||
        event.targetGeneration !== metadata.targetGeneration ||
        batch.nextTerminalIndex !== batch.childIds.length ||
        batch.childIds.some((childId) =>
          realm.pendingSealedOperations.has(childId)) ||
        (batch.carrierAuthorityContextDigest !== undefined &&
          eventAuthorityContextDigest(event) !==
            batch.carrierAuthorityContextDigest)
      ) {
        throw new TypeError('Outer terminal preceded its sealed children');
      }
      if (
        event.kind === 1
          ? event.status !== 0 ||
            (event.providerAdmission === 0
              ? event.physicalSequence !== '0'
              : event.providerAdmission !== 1 ||
                !isPositiveDecimal(event.physicalSequence))
          : typeof event.uncapturedError !== 'boolean' ||
            !Number.isInteger(event.status) ||
            event.status === 0 ||
            (event.providerAdmission === 0
              ? event.physicalSequence !== '0' ||
                event.backendClass !== 0
              : event.providerAdmission !== 1 ||
                !isPositiveDecimal(event.physicalSequence) ||
                !Number.isInteger(event.backendClass) ||
                event.backendClass < 1 ||
                event.backendClass > 5)
      ) {
        throw new TypeError('Outer terminal result carrier is malformed');
      }
    } catch {
      closeForMalformedOperationTerminal();
      return false;
    }
    realm.pendingSealedBatches.delete(event.operationInstanceId);
    return true;
  };

  const rejectProvisionalOuterSealedBatchTerminal = (
    event: Extract<NativeGpuEventV2, { kind: 1 | 2 }>,
  ): boolean => {
    for (const batch of realm.provisionalSealedBatches) {
      const metadata = batch.outerMetadata;
      let matches = false;
      try {
        matches =
          event.operationId === batch.outerOperationId &&
          isPositiveDecimal(event.operationInstanceId) &&
          compareCanonicalU64Decimal(
            event.operationInstanceId,
            '9223372036854775808',
          ) < 0 &&
          (batch.outerWantsPromise
            ? isPositiveDecimal(event.promiseId)
            : event.promiseId === '0') &&
          event.topologyId === 1 &&
          event.runtimeAddress === bridge.runtimeAddress &&
          event.runtimeNonce === bridge.runtimeNonce &&
          event.realmId === bridge.realmId &&
          event.realmGeneration === bridge.realmGeneration &&
          event.accountId === bridge.rootAccountId &&
          event.accountGeneration === bridge.rootAccountGeneration &&
          bytesToLowerHex(copyExactUint8View(
            event.accountAuthorityDigest,
            32,
            'WebGPU provisional outer account authority digest',
          )) === bytesToLowerHex(copyExactUint8View(
            bridge.rootAuthorityDigest,
            32,
            'WebGPU root account authority digest',
          )) &&
          event.logicalDeviceId === metadata.logicalDeviceId &&
          event.logicalDeviceGeneration ===
            metadata.logicalDeviceGeneration &&
          event.providerGeneration === metadata.providerGeneration &&
          event.ingressLogicalDeviceId === metadata.logicalDeviceId &&
          event.ingressLogicalDeviceGeneration ===
            metadata.logicalDeviceGeneration &&
          event.ingressProviderGeneration === metadata.providerGeneration &&
          event.operationProviderGeneration ===
            metadata.operationProviderGeneration &&
          event.capturedScopeId === metadata.capturedScopeId &&
          event.adapterOrdinal === metadata.adapterOrdinal &&
          event.deviceIngressOrdinal === metadata.deviceIngressOrdinal &&
          event.queueIngressOrdinal === metadata.queueIngressOrdinal &&
          event.receiverKind === metadata.receiverKind &&
          event.receiverFlags === 0 &&
          event.receiverId === metadata.receiverId &&
          event.receiverGeneration === metadata.receiverGeneration &&
          event.targetKind === metadata.targetKind &&
          event.targetFlags === 0 &&
          event.targetId === metadata.targetId &&
          event.targetGeneration === metadata.targetGeneration;
      } catch {
        matches = false;
      }
      if (!matches) continue;
      // The native carrier identity is not returned until submit unwinds, so
      // accepting its outer terminal here would lose the parent/child join.
      // Child terminals may be provisionally authenticated; the outer one
      // must wait until the batch is bound to its exact low-half parent.
      batch.terminalObserved = true;
      closeForMalformedOperationTerminal();
      return false;
    }
    return true;
  };

  bridge.setEventSink((event) => {
    if (!realm.active && event.kind !== 6) return;
    let sealedTerminal: PendingSealedOperation | undefined;
    if (event.kind === 1 || event.kind === 2) {
      const hadSealedReservation = realm.pendingSealedOperations.has(
        event.operationInstanceId,
      );
      if (hadSealedReservation) {
        sealedTerminal = validateAndConsumeSealedTerminal(event);
        if (!sealedTerminal) return;
      } else if (
        isPositiveDecimal(event.operationInstanceId) &&
        compareCanonicalU64Decimal(
          event.operationInstanceId,
          '9223372036854775808',
        ) >= 0
      ) {
        closeForMalformedOperationTerminal();
        return;
      }
      if (!rejectProvisionalOuterSealedBatchTerminal(event)) return;
      if (!consumeOuterSealedBatchTerminal(event)) return;
    }
    if (event.kind === 1) {
      if (sealedTerminal) return;
      const selected = ROUTES_BY_WIRE.get(event.operationId);
      if (!selected) {
        closeForMalformedOperationTerminal();
        return;
      }
      const pending = realm.pendingPromiseCalls.get(event.operationInstanceId);
      if (event.promiseId !== '0' && pending && pending.route !== selected) {
        closeForMalformedOperationTerminal();
        return;
      }
      if (event.promiseId !== '0') {
        realm.resultEvents.set(event.operationInstanceId, event);
      }
      return;
    }
    if (event.kind === 3 || event.kind === 4 || event.kind === 5 || event.kind === 6) {
      try {
        settleLossEvent(event);
      } catch (error) {
        if (realm.closeReason?.startsWith('counter-exhausted:')) return;
        throw error;
      }
    }
    if (event.kind !== 2) return;
    if (typeof event.uncapturedError !== 'boolean') {
      closeForMalformedUncapturedError();
      return;
    }
    // Kind 2 always remains the mandatory operation terminal. Only the
    // authenticated secondary-disposition projection queues a public event.
    if (!event.uncapturedError) return;

    const selected = ROUTES_BY_WIRE.get(event.operationId);
    const routedDeviceKey = deviceKey(
      event.logicalDeviceId,
      event.logicalDeviceGeneration,
      event.providerGeneration,
    );
    const device = realm.devices.get(routedDeviceKey);
    const pending = realm.pendingPromiseCalls.get(event.operationInstanceId);
    let diagnostic: Uint8Array;
    let diagnosticByteLength = 0;
    let message = '';
    try {
      if (
        (!selected && !sealedTerminal) ||
        event.topologyId !== 1 ||
        event.runtimeAddress !== bridge.runtimeAddress ||
        event.runtimeNonce !== bridge.runtimeNonce ||
        event.realmId !== bridge.realmId ||
        event.realmGeneration !== bridge.realmGeneration ||
        event.accountId !== bridge.rootAccountId ||
        event.accountGeneration !== bridge.rootAccountGeneration ||
        bytesToLowerHex(
          copyExactUint8View(
            event.accountAuthorityDigest,
            32,
            'Uncaptured-error account authority digest',
          ),
        ) !==
          bytesToLowerHex(
            copyExactUint8View(
              bridge.rootAuthorityDigest,
              32,
              'WebGPU root account authority digest',
            ),
          ) ||
        !Number.isInteger(event.errorKind) ||
        event.errorKind < 1 ||
        event.errorKind > 3 ||
        !Number.isInteger(event.status) ||
        event.status === 0 ||
        event.deviceTransition !== 0 ||
        !isPositiveDecimal(event.logicalDeviceId) ||
        !isPositiveDecimal(event.logicalDeviceGeneration) ||
        !isPositiveDecimal(event.providerGeneration) ||
        event.ingressLogicalDeviceId !== event.logicalDeviceId ||
        event.ingressLogicalDeviceGeneration !==
          event.logicalDeviceGeneration ||
        event.ingressProviderGeneration !== event.providerGeneration ||
        event.operationProviderGeneration !== event.providerGeneration ||
        !isPositiveDecimal(event.operationInstanceId) ||
        !isCanonicalU64Decimal(event.promiseId, false) ||
        (event.providerAdmission === 0
          ? event.physicalSequence !== '0' ||
            event.backendClass !== 0
          : event.providerAdmission !== 1 ||
            !isPositiveDecimal(event.physicalSequence) ||
            !Number.isInteger(event.backendClass) ||
            event.backendClass < 1 ||
            event.backendClass > 5) ||
        !device ||
        !device.eventTarget ||
        (sealedTerminal
          ? event.promiseId !== '0' ||
            pending !== undefined ||
            sealedTerminal.deviceKey !== routedDeviceKey
          : event.promiseId !== '0'
            ? !pending ||
              pending.route !== selected ||
              pending.promiseId !== event.promiseId ||
              pending.deviceKey !== routedDeviceKey
            : pending !== undefined)
      ) {
        throw new TypeError('Malformed uncaptured-error provenance');
      }
      if (
        !INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER ||
        !INTRINSIC_TYPED_ARRAY_TAG_GETTER ||
        INTRINSIC_REFLECT_APPLY(
          INTRINSIC_TYPED_ARRAY_TAG_GETTER,
          event.payload,
          [],
        ) !== 'Uint8Array'
      ) {
        throw new TypeError('Malformed uncaptured-error diagnostic bytes');
      }
      diagnosticByteLength = INTRINSIC_REFLECT_APPLY(
        INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER,
        event.payload,
        [],
      ) as number;
      if (
        !Number.isSafeInteger(diagnosticByteLength) ||
        diagnosticByteLength < 0 ||
        diagnosticByteLength > MAX_UNCAPTURED_ERROR_DIAGNOSTIC_BYTES
      ) {
        throw new TypeError('Uncaptured-error diagnostic exceeds its bound');
      }
      diagnostic = copyExactUint8View(
        event.payload,
        diagnosticByteLength,
        'Uncaptured-error diagnostic',
      );
      // Validate canonical UTF-8 and the redacted diagnostic control policy
      // synchronously, before retaining or scheduling any app-visible work.
      message = decodeCanonicalGpuErrorDiagnostic(diagnostic);
    } catch {
      closeForMalformedUncapturedError();
      return;
    }
    if (
      realm.pendingUncapturedErrors.length >=
        MAX_UNCAPTURED_ERROR_COUNT ||
      diagnosticByteLength >
        MAX_UNCAPTURED_ERROR_QUEUED_DIAGNOSTIC_BYTES -
          realm.pendingUncapturedDiagnosticBytes
    ) {
      closeRealmCounterIndependently(
        'uncaptured-error-queue-overflow',
        'The WebGPU realm closed after uncaptured-error queue overflow',
      );
      return;
    }
    let error: object;
    try {
      error = makeUncapturedGpuError(
        event.errorKind as 1 | 2 | 3,
        message,
      );
    } catch {
      closeRealmCounterIndependently(
        'uncaptured-error-dispatch-invariant',
        'The WebGPU realm closed after uncaptured-error construction failed',
      );
      return;
    }
    realm.pendingUncapturedErrors.push(INTRINSIC_OBJECT_FREEZE({
      deviceKey: routedDeviceKey,
      target: device.eventTarget,
      message,
      error,
      eventByteLength: diagnosticByteLength,
    }));
    realm.pendingUncapturedDiagnosticBytes += diagnosticByteLength;
    scheduleNextUncapturedErrorTask();
  });

  const gpuState = allocateWrapper('GPU', undefined, {
    objectId: bridge.realmId,
    objectGeneration: bridge.realmGeneration,
  });

  defineMethod(mutablePrototypes.GPU, 'getPreferredCanvasFormat', function (this: object) {
    requireState(this, 'GPU');
    convert('GPU.getPreferredCanvasFormat', []);
    return 'bgra8unorm';
  });

  defineMethod(mutablePrototypes.GPU, 'requestAdapter', function (
    this: object,
    options?: unknown,
  ) {
    const state = requireState(this, 'GPU');
    let converted: unknown;
    try {
      // Web IDL conversion effects happen during the call. A conversion
      // exception becomes the returned Promise's rejection; only the WebGPU
      // semantic/provider algorithm is queued.
      converted = convert('GPU.requestAdapter', [options]);
    } catch (error) {
      return Promise.reject(error);
    }
    return Promise.resolve().then(() => {
      const featureLevel = asRecord(
        converted,
        'converted GPURequestAdapterOptions',
      ).featureLevel;
      if (featureLevel !== 'core' && featureLevel !== 'compatibility') {
        return null;
      }
      const receipt = submitService(
        'GPU.requestAdapter',
        state,
        undefined,
        converted,
        true,
      ) as Promise<ProductionGpuDecodedResult>;
      return decodePromiseObject('GPU.requestAdapter', receipt, 'GPUAdapter', true);
    });
  });

  defineMethod(mutablePrototypes.GPUAdapter, 'requestDevice', function (
    this: object,
    descriptor?: unknown,
  ) {
    const state = requireState(this, 'GPUAdapter');
    let converted: unknown;
    try {
      converted = convert('GPUAdapter.requestDevice', [descriptor]);
    } catch (error) {
      return Promise.reject(error);
    }
    return Promise.resolve().then(() => {
      const receipt = submitService(
        'GPUAdapter.requestDevice',
        state,
        undefined,
        converted,
        true,
      ) as Promise<ProductionGpuDecodedResult>;
      return decodePromiseObject(
        'GPUAdapter.requestDevice',
        receipt,
        'GPUDevice',
      ).then((device) => {
        state.expired = true;
        return device;
      });
    });
  });

  defineMethod(mutablePrototypes.GPUCanvasContext, 'configure', function (
    this: object,
    configuration: unknown,
  ) {
    const context = requireState(this, 'GPUCanvasContext');
    assertCanvasContextUsable(context);
    const converted = asRecord(
      convert('GPUCanvasContext.configure', [configuration]),
      'GPUCanvasConfiguration',
    );
    const deviceWrapper = converted.device;
    const deviceState = requireState(deviceWrapper, 'GPUDevice');
    if (!deviceState.device) throw new Error('GPUDevice lacks logical device state');
    const configuredDevice = deviceState.device;
    const canvasAuthority = context.canvasAuthority;
    const configuredFormat = converted.format;
    const configuredUsage = converted.usage;
    const configuredAlphaMode = converted.alphaMode;
    const configuredColorSpace = converted.colorSpace;
    const configuredViewFormats = converted.viewFormats;
    const configuredToneMapping = converted.toneMapping;
    if (
      !canvasAuthority ||
      typeof configuredFormat !== 'string' ||
      typeof configuredUsage !== 'number' ||
      !Array.isArray(configuredViewFormats) ||
      typeof configuredToneMapping !== 'object' ||
      configuredToneMapping === null ||
      Array.isArray(configuredToneMapping) ||
      (configuredAlphaMode !== 'opaque' &&
        configuredAlphaMode !== 'premultiplied') ||
      (configuredColorSpace !== 'srgb' && configuredColorSpace !== 'display-p3')
    ) {
      throw new Error('GPUCanvasContext lacks closed configure authority');
    }
    const toneMappingMode = (configuredToneMapping as Record<string, unknown>).mode;
    if (toneMappingMode !== 'standard' && toneMappingMode !== 'extended') {
      throw new Error('GPUCanvasContext lacks a normalized tone-mapping mode');
    }
    const requiredFeatures: Readonly<Record<string, string | null>> =
      WEBGPU_PRODUCTION_PLAN.webIdlVocabulary.gpuTextureFormatRequiredFeatures;
    for (const format of [configuredFormat, ...configuredViewFormats]) {
      if (
        typeof format !== 'string' ||
        !Object.prototype.hasOwnProperty.call(requiredFeatures, format)
      ) {
        throw new Error(`GPUTextureFormat ${String(format)} lacks capability metadata`);
      }
      const requiredFeature = requiredFeatures[format];
      if (
        requiredFeature !== null &&
        !configuredDevice.featureNames.includes(requiredFeature)
      ) {
        throw new TypeError(
          `GPUTextureFormat ${format} requires feature ${requiredFeature}`,
        );
      }
    }
    if (
      configuredFormat !== 'bgra8unorm' &&
      configuredFormat !== 'rgba8unorm' &&
      configuredFormat !== 'rgba16float'
    ) {
      throw new TypeError(
        `GPUTextureFormat ${configuredFormat} is not a supported canvas context format`,
      );
    }
    // @webgpu/types exposes this post-CRD bit, but Exact's pinned CRD profile
    // excludes it. The WebGPU configure algorithm rejects it on the content
    // timeline before configuration state changes.
    if ((configuredUsage & 0x20) !== 0) {
      throw new TypeError(
        'GPUCanvasConfiguration.usage may not include TRANSIENT_ATTACHMENT',
      );
    }
    if (toneMappingMode !== 'standard') {
      throw new TypeError(
        'GPUCanvasConfiguration.toneMapping.mode must be standard in this profile',
      );
    }
    const nextConfigurationGeneration = advanceCounterOrClose(
      context.configurationGeneration,
      'canvas configuration generation',
    );
    const copiedConfiguration = cloneConfiguration(converted);
    let submissionFailure: ServiceSubmissionFailureKind | undefined;
    const configureServiceAuthority: ProductionGpuCanvasServiceEncoding =
      Object.freeze({
        kind: 'canvas-configure-v1',
        receiverContextRef: referenceWithDevice(context, configuredDevice),
        attachmentGeneration: canvasAuthority.attachmentGeneration,
        contextGeneration: canvasAuthority.contextGeneration,
        configurationGeneration: nextConfigurationGeneration,
        configuredDeviceRef: reference(deviceWrapper, 'GPUDevice'),
        format: configuredFormat,
        usage: configuredUsage,
        viewFormats: Object.freeze(configuredViewFormats.slice()) as readonly string[],
        alphaMode: configuredAlphaMode,
        colorSpace: configuredColorSpace,
        toneMappingMode,
        targetAuthorityDigest: canvasAuthority.targetAuthorityDigest,
        surfaceAccountToken: canvasAuthority.surfaceAccountToken,
        surfaceAccountGeneration: canvasAuthority.surfaceAccountGeneration,
      });
    // Preflight queue exhaustion before publishing the replacement
    // configuration or expiring its current texture. A reconfiguration
    // expiry legitimately consumes device ingress but never queue ingress,
    // so the committed plan is recomputed after that expiry.
    prepareServiceCounters(
      'GPUCanvasContext.configure',
      context,
      configuredDevice,
    );
    // LLP 0380 §2.2 installs the copied configuration immediately after the
    // synchronous content checks. Native payload encoding and service
    // admission are downstream implementation work: neither a deterministic
    // non-admission nor a later device-timeline validation may resurrect the
    // old configuration or current texture.
    const replacedTexture = detachCurrentTextureForExpiry(context);
    unlinkConfiguredCanvasContext(context);
    context.configurationGeneration = nextConfigurationGeneration;
    context.configuration = copiedConfiguration;
    context.configuredDevice = configuredDevice;
    context.configuredDeviceWrapper = deviceWrapper as object;
    context.canvasContextLifecycle = 'configured';
    configuredDevice.configuredCanvasContexts.add(context);
    if (configuredDevice.destroyed || configuredDevice.lost.settled) {
      context.canvasContextLifecycle = 'lost';
      configuredDevice.configuredCanvasContexts.delete(context);
    }
    if (replacedTexture) {
      submitCanvasTextureExpiry(
        replacedTexture,
        'canvas-reconfigure-expiry-threw',
        'The WebGPU realm closed because replaced Canvas texture expiry threw',
      );
      finalizeCanvasTextureExpiry(replacedTexture);
    }
    const servicePlan = prepareServiceCounters(
      'GPUCanvasContext.configure',
      context,
      configuredDevice,
    );
    // The semantic call carries the configured device as ingress while the
    // service receiver remains the complete canvas-context reference.
    context.device = configuredDevice;
    try {
      try {
        submitService(
          'GPUCanvasContext.configure',
          context,
          undefined,
          converted,
          false,
          servicePlan,
          undefined,
          (failure) => {
            submissionFailure = failure;
          },
          configureServiceAuthority,
        );
      } catch (error) {
        if (submissionFailure === 'bridge-threw' && realm.active) {
          // A synchronous LLP 0380 §2.4 loss is already terminal and must
          // dominate the thrown bridge return. Otherwise admission is
          // ambiguous, so close the realm instead of guessing. An explicit
          // non-admission is not ambiguous and leaves the already-installed
          // configuration intact for the caller's next operation.
          const lossWon =
            configuredDevice.lost.settled &&
            context.canvasContextLifecycle === 'lost' &&
            context.configuredDevice === configuredDevice &&
            !configuredDevice.configuredCanvasContexts.has(context);
          if (!lossWon) {
            closeRealmCounterIndependently(
              'canvas-configure-submit-threw',
              'The WebGPU realm closed because canvas configure submission threw',
            );
          }
        }
        throw error;
      }
    } finally {
      context.device = undefined;
    }
    if (configuredDevice.lost.settled) {
      if (
        context.canvasContextLifecycle !== 'lost' ||
        context.configuredDevice !== configuredDevice ||
        configuredDevice.configuredCanvasContexts.has(context)
      ) {
        closeRealmCounterIndependently(
          'canvas-configure-terminal-race',
          'The WebGPU realm closed after a canvas configure terminal race',
        );
        throw namedError(
          'OperationError',
          'GPUCanvasContext configure terminal state is inconsistent',
        );
      }
      return;
    }
    if (
      context.canvasContextLifecycle !== 'configured' ||
      context.configuredDevice !== configuredDevice ||
      !configuredDevice.configuredCanvasContexts.has(context)
    ) {
      closeRealmCounterIndependently(
        'canvas-configure-publication-race',
        'The WebGPU realm closed after a canvas configure publication race',
      );
      throw namedError(
        'OperationError',
        'GPUCanvasContext configure publication is inconsistent',
      );
    }
  });

  defineMethod(
    mutablePrototypes.GPUCanvasContext,
    'getConfiguration',
    function (this: object) {
      const context = requireState(this, 'GPUCanvasContext');
      assertCanvasContextUsable(context);
      convert('GPUCanvasContext.getConfiguration', []);
      return context.configuration
        ? cloneConfiguration(context.configuration)
        : null;
    },
  );

  defineMethod(
    mutablePrototypes.GPUCanvasContext,
    'getCurrentTexture',
    function (this: object) {
      const context = requireState(this, 'GPUCanvasContext');
      assertCanvasContextUsable(context);
      convert('GPUCanvasContext.getCurrentTexture', []);
      if (
        !context.configuration ||
        !context.configuredDevice ||
        !context.configuredDeviceWrapper ||
        !context.canvasAuthority
      ) {
        throw namedError('InvalidStateError', 'GPUCanvasContext is not configured');
      }
      if (context.currentTexture) {
        const current = requireState(context.currentTexture, 'GPUTexture');
        if (current.currentOrigin === undefined) {
          throw new Error('GPUCanvasContext current texture lacks immutable origin');
        }
        const localRecordPlan = prepareLocalRecord(
          'GPUCanvasContext.getCurrentTexture',
          context,
          context.configuredDevice,
        );
        const retained = nativePresentationAuthority(
          current.currentOrigin.presentationAuthority,
        );
        let allowed = false;
        try {
          allowed = bridge.recheckPresentationAuthority(
            route('GPUCanvasContext.getCurrentTexture').wireId,
            presentationAuthorityMetadata(context, current, localRecordPlan),
            retained,
          );
        } catch {
          closeRealmCounterIndependently(
            'canvas-presentation-recheck-invalid',
            'The WebGPU realm closed because Canvas presentation recheck failed structurally',
          );
          throw namedError(
            'OperationError',
            'GPUCanvasContext presentation authority recheck failed',
          );
        }
        if (!allowed) {
          throw namedError(
            'SecurityError',
            'GPUCanvasContext current presentation authority was denied',
          );
        }
        let localCommitStarted = false;
        try {
          const pendingOrigin = context.configuredDevice
            .pendingCurrentTextureMaterializations.get(current) ?? {
              records: [],
              materializesOnPrefixCarrier:
                !current.materialized && !current.destroyed,
            };
          localCommitStarted = true;
          const committedCurrentRecord = commitLocalRecord(
            localRecordPlan,
            context,
            current,
            Object.freeze({ currentOrigin: current.currentOrigin }),
            undefined,
          );
          if (
            !context.configuredDevice
              .pendingCurrentTextureMaterializations.has(current)
          ) {
            context.configuredDevice.pendingCurrentTextureMaterializations.set(
              current,
              pendingOrigin,
            );
          }
          pendingOrigin.records.push(committedCurrentRecord.sealedRecord);
          return context.currentTexture;
        } catch (error) {
          if (localCommitStarted && realm.active) {
            closeRealmCounterIndependently(
              'canvas-current-recheck-publication-failed',
              'The WebGPU realm closed after a partial current-texture recheck publication',
            );
          }
          throw error;
        }
      }
      if (
        context.drawingBufferWidth === undefined ||
        context.drawingBufferHeight === undefined
      ) {
        throw new Error('GPUCanvasContext lacks its drawing-buffer extent');
      }
      const configuredFormat = context.configuration.format;
      const configuredUsage = context.configuration.usage;
      const configuredAlphaMode = context.configuration.alphaMode;
      const configuredColorSpace = context.configuration.colorSpace;
      if (
        typeof configuredFormat !== 'string' ||
        typeof configuredUsage !== 'number' ||
        (configuredAlphaMode !== 'opaque' &&
          configuredAlphaMode !== 'premultiplied') ||
        (configuredColorSpace !== 'srgb' &&
          configuredColorSpace !== 'display-p3')
      ) {
        throw new Error('GPUCanvasContext lacks its converted texture configuration');
      }
      const nextCurrentEpoch = advanceCounterOrClose(
        context.currentEpoch,
        'canvas current epoch',
      );
      const configuredDevice = context.configuredDevice;
      const configuredDeviceWrapper = context.configuredDeviceWrapper;
      const localRecordPlan = prepareLocalRecord(
        'GPUCanvasContext.getCurrentTexture',
        context,
        configuredDevice,
      );
      const textureAllocation = prepareWrapperAllocation(
        'GPUTexture',
        configuredDevice,
      );
      const texture = textureAllocation.state;
      texture.textureDimension = '2d';
      texture.textureFormat = configuredFormat;
      texture.textureWidth = context.drawingBufferWidth;
      texture.textureHeight = context.drawingBufferHeight;
      texture.textureDepthOrArrayLayers = 1;
      if (context.canvasContextLifecycle === 'lost') {
        texture.invalid = true;
        texture.status = 'invalid-device';
      }
      const mintOperationProvenance = Object.freeze({
        operationInstanceId: localRecordPlan.operationInstanceId,
        deviceIngressOrdinal: localRecordPlan.deviceIngressOrdinal,
      });
      const authority = context.canvasAuthority;
      const receiverTextureRef = referenceWithDevice(
        texture,
        configuredDevice,
      );
      const contextRef = referenceWithDevice(context, configuredDevice);
      const configuredDeviceRef = reference(
        configuredDeviceWrapper,
        'GPUDevice',
      );
      const capturedPresentationAuthority =
        bridge.capturePresentationAuthority(
          route('GPUCanvasContext.getCurrentTexture').wireId,
          presentationAuthorityMetadata(context, texture, localRecordPlan),
        );
      if (capturedPresentationAuthority === null) {
        throw namedError(
          'SecurityError',
          'GPUCanvasContext presentation authority was denied',
        );
      }
      let committedMintRecord:
        | Readonly<{
            operationInstanceId: string;
            deviceIngressOrdinal: string;
            sealedRecord: Readonly<Record<string, unknown>>;
          }>
        | undefined;
      let publicationCommitStarted = false;
      try {
        const presentationAuthority = encodePresentationAuthority(
          capturedPresentationAuthority,
          localRecordPlan.capturedScopeId,
        );
        const digestInput: ProductionGpuTextureOriginDigestInput = Object.freeze({
          originClass: 'canvas-current',
          receiverTextureRef,
          contextRef,
          attachmentGeneration: authority.attachmentGeneration,
          contextGeneration: authority.contextGeneration,
          configurationGeneration: context.configurationGeneration,
          currentEpoch: nextCurrentEpoch,
          mintOperationProvenance,
          presentationAuthority,
          configuredDeviceRef,
          format: configuredFormat,
          usage: configuredUsage,
          alphaMode: configuredAlphaMode,
          colorSpace: configuredColorSpace,
          targetAuthorityDigest: authority.targetAuthorityDigest,
          surfaceAccountToken: authority.surfaceAccountToken,
          surfaceAccountGeneration: authority.surfaceAccountGeneration,
        });
        const textureOriginDigest =
          codecs.deriveTextureOriginDigest(digestInput);
        const currentOrigin: CanvasCurrentTextureOriginState = Object.freeze({
          originClass: digestInput.originClass,
          contextRef: digestInput.contextRef,
          attachmentGeneration: digestInput.attachmentGeneration,
          contextGeneration: digestInput.contextGeneration,
          configurationGeneration: digestInput.configurationGeneration,
          currentEpoch: digestInput.currentEpoch,
          mintOperationProvenance: digestInput.mintOperationProvenance,
          presentationAuthority: digestInput.presentationAuthority,
          textureOriginDigest,
          configuredDeviceRef: digestInput.configuredDeviceRef,
          format: digestInput.format,
          usage: digestInput.usage,
          alphaMode: digestInput.alphaMode,
          colorSpace: digestInput.colorSpace,
          targetAuthorityDigest: digestInput.targetAuthorityDigest,
          surfaceAccountToken: digestInput.surfaceAccountToken,
          surfaceAccountGeneration: digestInput.surfaceAccountGeneration,
        });
        texture.currentOrigin = currentOrigin;
        publicationCommitStarted = true;
        commitWrapperAllocation(textureAllocation);
        committedMintRecord = commitLocalRecord(
          localRecordPlan,
          context,
          texture,
          Object.freeze({ currentOrigin }),
          undefined,
        );
        configuredDevice.pendingCurrentTextureMaterializations.set(
          texture,
          {
            records: [committedMintRecord.sealedRecord],
            materializesOnPrefixCarrier: true,
          },
        );
        context.currentEpoch = nextCurrentEpoch;
        context.currentTexture = texture.wrapper;
        return texture.wrapper;
      } catch (error) {
        configuredDevice.pendingCurrentTextureMaterializations.delete(
          texture,
        );
        if (committedMintRecord !== undefined) {
          const recordIndex = configuredDevice.pendingLocalTimeline.indexOf(
            committedMintRecord.sealedRecord,
          );
          if (recordIndex >= 0) {
            configuredDevice.pendingLocalTimeline.splice(recordIndex, 1);
          }
        }
        texture.textureExpired = true;
        try {
          retirePresentationAuthorityOrClose(
            texture,
            capturedPresentationAuthority,
          );
        } finally {
          if (publicationCommitStarted && realm.active) {
            closeRealmCounterIndependently(
              'canvas-current-first-publication-failed',
              'The WebGPU realm closed after a partial first current-texture publication',
            );
          }
        }
        throw error;
      }
    },
  );

  defineMethod(mutablePrototypes.GPUCanvasContext, 'unconfigure', function (
    this: object,
  ) {
    const context = requireState(this, 'GPUCanvasContext');
    assertCanvasContextUsable(context);
    const converted = convert('GPUCanvasContext.unconfigure', []);
    if (context.canvasContextLifecycle === 'attached-unconfigured') return;
    const canvasAuthority = context.canvasAuthority;
    const configuredDevice = context.configuredDevice;
    if (!canvasAuthority || !configuredDevice) {
      throw new Error('GPUCanvasContext lacks closed unconfigure authority');
    }
    const nextConfigurationGeneration = advanceCounterOrClose(
      context.configurationGeneration,
      'canvas configuration generation',
    );
    // Preflight queue exhaustion before current-texture expiry. The expiry
    // consumes device ingress only, so the committed plan is recomputed
    // afterward without weakening the queue preflight.
    prepareServiceCounters(
      'GPUCanvasContext.unconfigure',
      context,
      configuredDevice,
    );
    expireCurrentTexture(context);
    const servicePlan = prepareServiceCounters(
      'GPUCanvasContext.unconfigure',
      context,
      configuredDevice,
    );
    const unconfigureServiceAuthority: ProductionGpuCanvasServiceEncoding =
      Object.freeze({
        kind: 'canvas-unconfigure-v1',
        receiverContextRef: referenceWithDevice(context, configuredDevice),
        attachmentGeneration: canvasAuthority.attachmentGeneration,
        contextGeneration: canvasAuthority.contextGeneration,
        configurationGeneration: context.configurationGeneration,
        terminalIntent: 'first-cleanup',
        targetAuthorityDigest: canvasAuthority.targetAuthorityDigest,
        surfaceAccountToken: canvasAuthority.surfaceAccountToken,
        surfaceAccountGeneration: canvasAuthority.surfaceAccountGeneration,
      });
    context.device = configuredDevice;
    try {
      submitService(
        'GPUCanvasContext.unconfigure',
        context,
        undefined,
        converted,
        false,
        servicePlan,
        undefined,
        (failure) => {
          if (failure === 'bridge-threw') {
            closeRealmCounterIndependently(
              'canvas-unconfigure-submit-threw',
              'The WebGPU realm closed because canvas unconfigure submission threw',
            );
          }
        },
        unconfigureServiceAuthority,
      );
    } finally {
      context.device = undefined;
    }
    unlinkConfiguredCanvasContext(context);
    context.configurationGeneration = nextConfigurationGeneration;
    context.configuration = undefined;
    context.configuredDevice = undefined;
    context.configuredDeviceWrapper = undefined;
    context.canvasContextLifecycle = 'attached-unconfigured';
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createBindGroupLayout', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createBindGroupLayout', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createBindGroupLayout',
      state,
      state.device,
    );
    const layout = allocateWrapper('GPUBindGroupLayout', state.device);
    const convertedRecord = asRecord(
      converted,
      'converted GPUBindGroupLayoutDescriptor',
    );
    if (!Array.isArray(convertedRecord.entries)) {
      throw new TypeError('converted GPUBindGroupLayoutDescriptor entries are missing');
    }
    layout.bindGroupLayoutEntries = Object.freeze(
      convertedRecord.entries.flatMap((entryValue, index) => {
        const entry = asRecord(entryValue, `converted layout entry ${index}`);
        if (entry.buffer === undefined) return [];
        const buffer = asRecord(
          entry.buffer,
          `converted layout buffer entry ${index}`,
        );
        return [Object.freeze({
          binding: stagedU32(entry.binding, `converted layout entry ${index}.binding`),
          hasDynamicOffset: Boolean(buffer.hasDynamicOffset),
          minBindingSize: stagedU64(
            buffer.minBindingSize,
            `converted layout entry ${index}.minBindingSize`,
            0,
          ),
        })];
      }),
    );
    submitService(
      'GPUDevice.createBindGroupLayout',
      state,
      layout,
      converted,
      false,
      servicePlan,
    );
    return layout.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createBindGroup', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const { converted, statesByReference } = convertWithCapturedStates(
      'GPUDevice.createBindGroup',
      [descriptor],
    );
    const convertedRecord = asRecord(converted, 'converted GPUBindGroupDescriptor');
    if (!Array.isArray(convertedRecord.entries)) {
      throw new TypeError('converted GPUBindGroupDescriptor entries are missing');
    }
    const layout = stateForCapturedReference(
      statesByReference,
      convertedRecord.layout,
      'converted GPUBindGroupDescriptor layout',
    );
    const bufferBindings: BindGroupBufferBinding[] = [];
    for (let index = 0; index < convertedRecord.entries.length; index += 1) {
      const entry = asRecord(
        convertedRecord.entries[index],
        `converted bind group entry ${index}`,
      );
      const resource = asRecord(
        entry.resource,
        `converted bind group resource ${index}`,
      );
      if (resource.resourceKind !== 'GPUBufferBinding') continue;
      const buffer = stateForCapturedReference(
        statesByReference,
        resource.buffer,
        `converted bind group buffer ${index}`,
      );
      bufferBindings.push(Object.freeze({
        binding: stagedU32(entry.binding, `converted bind group entry ${index}.binding`),
        buffer,
        offset: stagedU64(
          resource.offset,
          `converted bind group resource ${index}.offset`,
          0,
        ),
      }));
    }
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createBindGroup',
      state,
      state.device,
    );
    const bindGroup = allocateWrapper('GPUBindGroup', state.device);
    bindGroup.bindGroupLayout = layout;
    bindGroup.bindGroupBufferBindings = Object.freeze(bufferBindings);
    submitService(
      'GPUDevice.createBindGroup',
      state,
      bindGroup,
      converted,
      false,
      servicePlan,
    );
    return bindGroup.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createBuffer', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createBuffer', [descriptor]) as Readonly<{
      mappedAtCreation: boolean;
      size: number;
      usage: number;
    }>;
    let mappedBytes: Uint8Array | undefined;
    if (converted.mappedAtCreation) {
      if (converted.size % 4 !== 0) {
        throw new RangeError(
          'GPUBufferDescriptor.size must be a multiple of 4 when mappedAtCreation is true',
        );
      }
      const guardBytesBefore = realm.privateMappedAllocationGuardBytes;
      if (
        converted.size >
          realm.privateMappedAllocationGuardLimitBytes - guardBytesBefore
      ) {
        throw new RangeError(
          'GPUBuffer mapped-at-creation private allocation guard is exhausted',
        );
      }
      try {
        mappedBytes = INTRINSIC_REFLECT_CONSTRUCT(
          INTRINSIC_UINT8_ARRAY,
          [converted.size],
        ) as Uint8Array;
      } catch {
        throw new RangeError(
          'GPUBuffer mapped-at-creation byte block could not be allocated',
        );
      }
      // Intrinsic construction cannot invoke app code, so this commit occurs
      // immediately after allocation without a reentrant observation window.
      // Allocation failure therefore precedes every counter mutation.
      realm.privateMappedAllocationGuardBytes =
        guardBytesBefore + converted.size;
    }
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createBuffer',
      state,
      state.device,
    );
    const buffer = allocateWrapper('GPUBuffer', state.device);
    buffer.bufferSize = converted.size;
    buffer.bufferUsage = converted.usage;
    buffer.bufferMapState = converted.mappedAtCreation ? 'mapped' : 'unmapped';
    if (converted.mappedAtCreation) {
      if (!mappedBytes) {
        throw new Error('GPUBuffer mapped-at-creation byte block is missing');
      }
      buffer.bufferActiveMapping = {
        generation: '1',
        mode: 2,
        offset: 0,
        size: converted.size,
        bytes: mappedBytes,
        ranges: [],
      };
      if (compareCanonicalU64Decimal(buffer.bufferNextMapGeneration, '1') <= 0) {
        buffer.bufferNextMapGeneration = '2';
      }
      retainBufferLifecycle(buffer);
    }
    try {
      submitService(
        'GPUDevice.createBuffer',
        state,
        buffer,
        converted,
        false,
        servicePlan,
      );
    } catch (error) {
      detachActiveBufferMapping(buffer);
      throw error;
    }
    return buffer.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createPipelineLayout', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createPipelineLayout', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createPipelineLayout',
      state,
      state.device,
    );
    const layout = allocateWrapper('GPUPipelineLayout', state.device);
    submitService(
      'GPUDevice.createPipelineLayout',
      state,
      layout,
      converted,
      false,
      servicePlan,
    );
    return layout.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createSampler', function (
    this: object,
    descriptor?: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createSampler', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createSampler',
      state,
      state.device,
    );
    const sampler = allocateWrapper('GPUSampler', state.device);
    submitService(
      'GPUDevice.createSampler',
      state,
      sampler,
      converted,
      false,
      servicePlan,
    );
    return sampler.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createTexture', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const logicalDevice = state.device;
    if (!logicalDevice) throw new Error('GPUDevice lacks logical device state');
    const converted = convert('GPUDevice.createTexture', [descriptor]) as Readonly<{
      dimension: '1d' | '2d' | '3d';
      format: string;
      usage: number;
      size: Readonly<{
        width: number;
        height: number;
        depthOrArrayLayers: number;
      }>;
      viewFormats: readonly string[];
    }>;
    const requiredFeatures: Readonly<Record<string, string | null>> =
      WEBGPU_PRODUCTION_PLAN.webIdlVocabulary.gpuTextureFormatRequiredFeatures;
    for (const format of [converted.format, ...converted.viewFormats]) {
      if (!Object.prototype.hasOwnProperty.call(requiredFeatures, format)) {
        throw new Error(`GPUTextureFormat ${format} lacks capability metadata`);
      }
      const requiredFeature = requiredFeatures[format];
      if (
        requiredFeature !== null &&
        !logicalDevice.featureNames.includes(requiredFeature)
      ) {
        throw new TypeError(
          `GPUTextureFormat ${format} requires feature ${requiredFeature}`,
        );
      }
    }
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createTexture',
      state,
      logicalDevice,
    );
    const texture = allocateWrapper('GPUTexture', logicalDevice);
    texture.textureDimension = converted.dimension;
    texture.textureFormat = converted.format;
    texture.textureUsage = converted.usage;
    texture.textureWidth = converted.size.width;
    texture.textureHeight = converted.size.height;
    texture.textureDepthOrArrayLayers = converted.size.depthOrArrayLayers;
    submitService(
      'GPUDevice.createTexture',
      state,
      texture,
      converted,
      false,
      servicePlan,
    );
    return texture.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createQuerySet', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const device = state.device;
    if (!device) throw new Error('GPUDevice lacks logical device state');
    const converted = convert(
      'GPUDevice.createQuerySet',
      [descriptor],
    ) as Readonly<{
      count: number;
      label: string;
      type: 'occlusion' | 'timestamp';
    }>;
    // This is the operation's content-timeline feature gate. It precedes
    // target allocation, ingress counters, and every semantic-service call.
    if (
      converted.type === 'timestamp' &&
      !device.featureNames.includes('timestamp-query')
    ) {
      throw new TypeError(
        'GPUQuerySet type timestamp requires feature timestamp-query',
      );
    }
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createQuerySet',
      state,
      device,
    );
    const querySet = allocateWrapper('GPUQuerySet', device);
    querySet.querySetCount = converted.count;
    querySet.querySetType = converted.type;
    submitService(
      'GPUDevice.createQuerySet',
      state,
      querySet,
      converted,
      false,
      servicePlan,
    );
    return querySet.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createCommandEncoder', function (
    this: object,
    descriptor?: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createCommandEncoder', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createCommandEncoder',
      state,
      state.device,
    );
    const encoder = allocateWrapper('GPUCommandEncoder', state.device);
    encoder.status = 'recording';
    submitService(
      'GPUDevice.createCommandEncoder',
      state,
      encoder,
      converted,
      false,
      servicePlan,
    );
    return encoder.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createShaderModule', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createShaderModule', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createShaderModule',
      state,
      state.device,
    );
    const module = allocateWrapper('GPUShaderModule', state.device);
    submitService(
      'GPUDevice.createShaderModule',
      state,
      module,
      converted,
      false,
      servicePlan,
    );
    return module.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createRenderPipeline', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createRenderPipeline', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createRenderPipeline',
      state,
      state.device,
    );
    const pipeline = allocateWrapper('GPURenderPipeline', state.device);
    submitService(
      'GPUDevice.createRenderPipeline',
      state,
      pipeline,
      converted,
      false,
      servicePlan,
    );
    return pipeline.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createComputePipeline', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createComputePipeline', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.createComputePipeline',
      state,
      state.device,
    );
    const pipeline = allocateWrapper('GPUComputePipeline', state.device);
    submitService(
      'GPUDevice.createComputePipeline',
      state,
      pipeline,
      converted,
      false,
      servicePlan,
    );
    return pipeline.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'destroy', function (this: object) {
    const state = requireState(this, 'GPUDevice');
    const device = state.device;
    if (!device || device.destroyed) return;
    const converted = convert('GPUDevice.destroy', []);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.destroy',
      state,
      device,
    );
    let destroyLinearized = false;
    try {
      submitService(
        'GPUDevice.destroy',
        state,
        undefined,
        converted,
        false,
        servicePlan,
        () => {
          clearDeviceBufferMappings(
            device,
            true,
            true,
            'GPUBuffer mapping was cancelled because its device was destroyed',
          );
          device.destroyed = true;
          destroyLinearized = true;
        },
      );
    } finally {
      if (destroyLinearized) {
        settleDeviceLost(device, 'destroyed', 'The device was destroyed');
      }
    }
  });

  defineGetter(mutablePrototypes.GPUDevice, 'features', function (this: object) {
    const state = requireState(this, 'GPUDevice');
    convert('GPUDevice.features', []);
    return state.device!.features;
  });

  defineGetter(mutablePrototypes.GPUDevice, 'limits', function (this: object) {
    const state = requireState(this, 'GPUDevice');
    convert('GPUDevice.limits', []);
    return state.device!.limits;
  });

  defineGetter(mutablePrototypes.GPUDevice, 'lost', function (this: object) {
    const state = requireState(this, 'GPUDevice');
    convert('GPUDevice.lost', []);
    return state.device!.lost.promise;
  });

  defineGetter(mutablePrototypes.GPUDevice, 'queue', function (this: object) {
    const state = requireState(this, 'GPUDevice');
    convert('GPUDevice.queue', []);
    return state.device!.queue;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'pushErrorScope', function (
    this: object,
    filter: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert(
      'GPUDevice.pushErrorScope',
      [filter],
    ) as 'validation' | 'out-of-memory' | 'internal';
    const device = state.device!;
    const scopePlan = consumeNextCounterOrClose(
      device.nextScope,
      device.scopeExhausted,
      'error scope identity',
    );
    const scopeId = scopePlan.value;
    const scopeStackGeneration = device.scopeStackGeneration;
    const nextScopeStackGeneration = advanceCounterOrClose(
      scopeStackGeneration,
      'error scope stack generation',
    );
    const precedingScopeId = currentScopeId(device);
    const servicePlan = prepareServiceCounters(
      'GPUDevice.pushErrorScope',
      state,
      device,
    );
    submitService(
      'GPUDevice.pushErrorScope',
      state,
      undefined,
      converted,
      false,
      servicePlan,
      () => {
        if (
          !realm.active ||
          device.nextScope !== scopeId ||
          device.scopeExhausted
        ) {
          closeRealmCounterIndependently(
            'counter-plan-conflict',
            'The WebGPU realm closed after a counter-plan conflict',
          );
          throw namedError('OperationError', 'WebGPU scope counter plan is stale');
        }
        device.nextScope = scopePlan.next;
        device.scopeExhausted = scopePlan.exhaustedAfter;
      },
      undefined,
      undefined,
      undefined,
      undefined,
      Object.freeze({
        kind: 'push-error-scope-v1',
        scopeId,
        filter: converted,
        scopeStackGeneration,
        precedingScopeId,
      }),
    );
    device.scopes.push(
      Object.freeze({ id: scopeId, filter: converted }),
    );
    device.scopeStackGeneration = nextScopeStackGeneration;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'popErrorScope', function (
    this: object,
  ) {
    const state = requireState(this, 'GPUDevice');
    try {
      const converted = convert('GPUDevice.popErrorScope', []);
      const device = state.device!;
      const scope = device.scopes[device.scopes.length - 1];
      if (!scope) {
        return Promise.reject(
          namedError('OperationError', 'The error scope stack is empty'),
        );
      }
      const scopeStackGeneration = device.scopeStackGeneration;
      const nextScopeStackGeneration = advanceCounterOrClose(
        scopeStackGeneration,
        'error scope stack generation',
      );
      if (device.lost.settled) {
        device.scopes.pop();
        device.scopeStackGeneration = nextScopeStackGeneration;
        return Promise.resolve(null);
      }
      const receipt = submitService(
        'GPUDevice.popErrorScope',
        state,
        undefined,
        converted,
        true,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        Object.freeze({
          kind: 'pop-error-scope-v1',
          scopeId: scope.id,
          scopeStackGeneration,
        }),
      ) as Promise<ProductionGpuDecodedResult>;
      device.scopes.pop();
      device.scopeStackGeneration = nextScopeStackGeneration;
      return receipt.then((decoded) => {
        if (device.lost.settled) return null;
        return decoded.kind === 'value' ? decoded.value : null;
      });
    } catch (error) {
      return Promise.reject(error);
    }
  });

  const stateIsUsableOnDevice = (
    state: WrapperState,
    device: DeviceState | undefined,
  ): boolean =>
    device !== undefined &&
    state.device === device &&
    !state.retired &&
    !state.destroyed &&
    !device.destroyed &&
    !device.lost.settled;

  const invalidatePass = (pass: WrapperState): void => {
    pass.invalid = true;
    if (pass.encoder) pass.encoder.invalid = true;
  };

  const bindGroupValidationError = (
    pass: WrapperState,
    index: number,
    bindGroup: WrapperState | null,
    dynamicOffsets: readonly number[],
  ): Error | undefined => {
    if (pass.status !== 'open' || pass.invalid) {
      return namedError('GPUValidationError', `${pass.kind} is not open`);
    }
    const device = pass.device;
    if (!device || device.destroyed || device.lost.settled) {
      return namedError('GPUValidationError', 'The pass device is unavailable');
    }
    const maxBindGroups = device.limits.maxBindGroups;
    if (typeof maxBindGroups === 'number' && index >= maxBindGroups) {
      return namedError('GPUValidationError', 'Bind group index exceeds maxBindGroups');
    }
    if (bindGroup === null) {
      return dynamicOffsets.length === 0
        ? undefined
        : namedError(
          'GPUValidationError',
          'A null bind group requires an empty dynamic offset sequence',
        );
    }
    if (!stateIsUsableOnDevice(bindGroup, device)) {
      return namedError(
        'GPUValidationError',
        'Bind group belongs to another or unavailable logical device',
      );
    }
    const layoutEntries = bindGroup.bindGroupLayout?.bindGroupLayoutEntries;
    const bufferBindings = bindGroup.bindGroupBufferBindings;
    if (!layoutEntries || !bufferBindings) {
      return namedError('GPUValidationError', 'Bind group metadata is unavailable');
    }
    const dynamicEntries = layoutEntries
      .filter((entry) => entry.hasDynamicOffset)
      .slice()
      .sort((left, right) => left.binding - right.binding);
    if (dynamicOffsets.length !== dynamicEntries.length) {
      return namedError(
        'GPUValidationError',
        'Dynamic offset count does not match the bind group layout',
      );
    }
    for (let dynamicIndex = 0; dynamicIndex < dynamicEntries.length; dynamicIndex += 1) {
      const layout = dynamicEntries[dynamicIndex];
      const binding = bufferBindings.find(
        (candidate) => candidate.binding === layout.binding,
      );
      if (
        !binding ||
        binding.buffer.kind !== 'GPUBuffer' ||
        !stateIsUsableOnDevice(binding.buffer, device) ||
        binding.buffer.bufferSize === undefined
      ) {
        return namedError(
          'GPUValidationError',
          'Dynamic buffer binding metadata is unavailable',
        );
      }
      const bufferSize = binding.buffer.bufferSize;
      const dynamicOffset = dynamicOffsets[dynamicIndex];
      // This is intentionally the sole dynamic range predicate. In
      // particular, GPUBindingResource.size does not participate here:
      // binding.offset + dynamicOffset + layout.minBindingSize <= buffer.size.
      if (
        binding.offset > bufferSize ||
        dynamicOffset > bufferSize - binding.offset ||
        layout.minBindingSize > bufferSize - binding.offset - dynamicOffset
      ) {
        return namedError(
          'GPUValidationError',
          'Dynamic buffer binding exceeds the backing buffer size',
        );
      }
    }
    return undefined;
  };

  const recordSetBindGroup = (
    pass: WrapperState,
    args: readonly unknown[],
    mergeUsageImmediately: boolean,
  ): void => {
    const converted = convertSetBindGroupArguments(args);
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      `${pass.kind}.setBindGroup`,
      pass,
      pass.device,
    );
    pass.boundBindGroups.set(
      converted.index,
      Object.freeze({
        bindGroup: converted.bindGroup,
        dynamicOffsets: converted.dynamicOffsets,
      }),
    );
    if (mergeUsageImmediately && converted.bindGroup !== null && pass.encoder) {
      for (const bound of pass.boundBindGroups.values()) {
        if (bound.bindGroup !== null) pass.encoder.usedBindGroups.add(bound.bindGroup);
      }
    }
    const error = bindGroupValidationError(
      pass,
      converted.index,
      converted.bindGroup,
      converted.dynamicOffsets,
    );
    if (error) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      Object.freeze({
        index: converted.index,
        bindGroup: converted.bindGroupRef,
        dynamicOffsets: converted.dynamicOffsets,
        overload: converted.overload,
      }),
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  };

  const passTimestampWritesAreInvalid = (
    timestampWrites: Readonly<Record<string, unknown>> | null,
    querySet: WrapperState | undefined,
    device: DeviceState | undefined,
  ): boolean => {
    if (timestampWrites === null) return false;
    const beginningOfPassWriteIndex =
      timestampWrites.beginningOfPassWriteIndex as number | null;
    const endOfPassWriteIndex =
      timestampWrites.endOfPassWriteIndex as number | null;
    const count = querySet?.querySetCount;
    return (
      device === undefined ||
      !device.featureNames.includes('timestamp-query') ||
      querySet === undefined ||
      querySet.kind !== 'GPUQuerySet' ||
      !stateIsUsableOnDevice(querySet, device) ||
      querySet.querySetType !== 'timestamp' ||
      count === undefined ||
      (
        beginningOfPassWriteIndex === null &&
        endOfPassWriteIndex === null
      ) ||
      (
        beginningOfPassWriteIndex !== null &&
        beginningOfPassWriteIndex >= count
      ) ||
      (
        endOfPassWriteIndex !== null &&
        endOfPassWriteIndex >= count
      ) ||
      (
        beginningOfPassWriteIndex !== null &&
        endOfPassWriteIndex !== null &&
        beginningOfPassWriteIndex === endOfPassWriteIndex
      )
    );
  };

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'beginComputePass', function (
    this: object,
    descriptor?: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const source = stagedDictionary(descriptor, 'GPUComputePassDescriptor');
    const labelValue = source.label;
    const label = labelValue === undefined
      ? ''
      : stagedUsvString(labelValue, 'GPUComputePassDescriptor.label');
    const timestampWritesValue = source.timestampWrites;
    let timestampQuerySet: WrapperState | undefined;
    let timestampWrites: Readonly<Record<string, unknown>> | null = null;
    if (timestampWritesValue !== undefined) {
      const timestampSource = stagedDictionary(
        timestampWritesValue,
        'GPUComputePassTimestampWrites',
      );
      const beginningOfPassWriteIndexValue =
        timestampSource.beginningOfPassWriteIndex;
      const beginningOfPassWriteIndex = beginningOfPassWriteIndexValue === undefined
        ? null
        : stagedU32(
          beginningOfPassWriteIndexValue,
          'GPUComputePassTimestampWrites.beginningOfPassWriteIndex',
        );
      const endOfPassWriteIndexValue = timestampSource.endOfPassWriteIndex;
      const endOfPassWriteIndex = endOfPassWriteIndexValue === undefined
        ? null
        : stagedU32(
          endOfPassWriteIndexValue,
          'GPUComputePassTimestampWrites.endOfPassWriteIndex',
        );
      const querySetValue = timestampSource.querySet;
      if (querySetValue === undefined) {
        throw new TypeError(
          'GPUComputePassTimestampWrites.querySet is required',
        );
      }
      timestampQuerySet = requireState(querySetValue, 'GPUQuerySet');
      timestampWrites = Object.freeze({
        beginningOfPassWriteIndex,
        endOfPassWriteIndex,
        querySet: reference(querySetValue, 'GPUQuerySet'),
      });
    }
    const converted = Object.freeze({ label, timestampWrites });
    const commandTargets = preflightCommandRecordCapacity([encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUCommandEncoder.beginComputePass',
      encoder,
      encoder.device,
    );
    const canLock =
      encoder.status === 'recording' && !encoder.activePass && !encoder.invalid;
    const pass = allocateWrapper('GPUComputePassEncoder', encoder.device);
    pass.encoder = encoder;
    pass.status = canLock ? 'open' : 'invalid';
    pass.invalid = !canLock;
    // The parent is locked before timestamp validation. Even an invalid
    // timestamp pass owns this lock until its mandatory end transition.
    if (canLock) {
      encoder.activePass = pass;
      realm.activePassCount += 1;
    }
    const timestampInvalid = passTimestampWritesAreInvalid(
      timestampWrites,
      timestampQuerySet,
      encoder.device,
    );
    const error = !canLock
      ? namedError('GPUValidationError', 'Command encoder cannot begin a compute pass')
      : timestampInvalid
        ? namedError(
          'GPUValidationError',
          'Compute pass timestamp writes are unavailable or invalid',
        )
        : undefined;
    if (error) {
      pass.invalid = true;
      // A timestamp error belongs to the newly locked pass. Defer poisoning
      // the parent until end() has first performed its mandatory unlock and
      // used-bind-group transition.
      if (!canLock) encoder.invalid = true;
    }
    const committed = commitLocalRecord(
      localRecordPlan,
      encoder,
      pass,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
    return pass.wrapper;
  });

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'clearBuffer', function (
    this: object,
    bufferValue: unknown,
    offsetValue?: unknown,
    sizeValue?: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const buffer = requireState(bufferValue, 'GPUBuffer');
    const offset = stagedU64(offsetValue, 'GPUCommandEncoder.clearBuffer offset', 0);
    const size = sizeValue === undefined
      ? null
      : stagedU64(sizeValue, 'GPUCommandEncoder.clearBuffer size');
    const converted = Object.freeze({
      buffer: reference(bufferValue, 'GPUBuffer'),
      offset,
      size,
    });
    const commandTargets = preflightCommandRecordCapacity([encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUCommandEncoder.clearBuffer',
      encoder,
      encoder.device,
    );
    const remaining = buffer.bufferSize === undefined || offset > buffer.bufferSize
      ? -1
      : buffer.bufferSize - offset;
    const invalid =
      encoder.status !== 'recording' ||
      Boolean(encoder.activePass) ||
      encoder.invalid ||
      !stateIsUsableOnDevice(buffer, encoder.device) ||
      buffer.bufferSize === undefined ||
      (buffer.bufferUsage !== undefined && (buffer.bufferUsage & 8) === 0) ||
      offset % 4 !== 0 ||
      (size !== null && size % 4 !== 0) ||
      remaining < 0 ||
      (size !== null && size > remaining);
    const error = invalid
      ? namedError('GPUValidationError', 'Buffer clear is invalid for this encoder')
      : undefined;
    if (invalid) encoder.invalid = true;
    const committed = commitLocalRecord(
      localRecordPlan,
      encoder,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(
    mutablePrototypes.GPUCommandEncoder,
    'copyBufferToBuffer',
    function (this: object, ...args: unknown[]) {
      const encoder = requireState(this, 'GPUCommandEncoder');
      if (args.length < 2) {
        throw new TypeError('copyBufferToBuffer requires source and destination');
      }
      const source = requireState(args[0], 'GPUBuffer');
      let sourceOffset = 0;
      let destinationValue: unknown;
      let destination: WrapperState;
      let destinationOffset = 0;
      let sizeValue: unknown;
      let overload: 'short' | 'full';
      try {
        destination = requireState(args[1], 'GPUBuffer');
        destinationValue = args[1];
        sizeValue = args[2];
        overload = 'short';
      } catch (error) {
        if (!(error instanceof TypeError)) throw error;
        if (args.length < 3) throw error;
        sourceOffset = stagedU64(
          args[1],
          'GPUCommandEncoder.copyBufferToBuffer sourceOffset',
        );
        destinationValue = args[2];
        destination = requireState(destinationValue, 'GPUBuffer');
        destinationOffset = stagedU64(
          args[3],
          'GPUCommandEncoder.copyBufferToBuffer destinationOffset',
        );
        sizeValue = args[4];
        overload = 'full';
      }
      const size = sizeValue === undefined
        ? null
        : stagedU64(sizeValue, 'GPUCommandEncoder.copyBufferToBuffer size');
      const converted = Object.freeze({
        source: reference(args[0], 'GPUBuffer'),
        sourceOffset,
        destination: reference(destinationValue, 'GPUBuffer'),
        destinationOffset,
        size,
        overload,
      });
      const commandTargets = preflightCommandRecordCapacity([encoder]);
      const localRecordPlan = prepareLocalRecord(
        'GPUCommandEncoder.copyBufferToBuffer',
        encoder,
        encoder.device,
      );
      const sourceRemaining = source.bufferSize === undefined ||
          sourceOffset > source.bufferSize
        ? -1
        : source.bufferSize - sourceOffset;
      const destinationRemaining = destination.bufferSize === undefined ||
          destinationOffset > destination.bufferSize
        ? -1
        : destination.bufferSize - destinationOffset;
      const effectiveSize = size ?? sourceRemaining;
      const invalid =
        encoder.status !== 'recording' ||
        Boolean(encoder.activePass) ||
        encoder.invalid ||
        !stateIsUsableOnDevice(source, encoder.device) ||
        !stateIsUsableOnDevice(destination, encoder.device) ||
        source.bufferSize === undefined ||
        destination.bufferSize === undefined ||
        (source.bufferUsage !== undefined && (source.bufferUsage & 4) === 0) ||
        (destination.bufferUsage !== undefined &&
          (destination.bufferUsage & 8) === 0) ||
        source === destination ||
        sourceOffset % 4 !== 0 ||
        destinationOffset % 4 !== 0 ||
        effectiveSize < 0 ||
        effectiveSize % 4 !== 0 ||
        effectiveSize > sourceRemaining ||
        effectiveSize > destinationRemaining;
      const error = invalid
        ? namedError('GPUValidationError', 'Buffer copy is invalid for this encoder')
        : undefined;
      if (invalid) encoder.invalid = true;
      const committed = commitLocalRecord(
        localRecordPlan,
        encoder,
        undefined,
        converted,
        error,
      );
      appendCommandRecord(commandTargets, committed.sealedRecord);
    },
  );

  defineMethod(
    mutablePrototypes.GPUCommandEncoder,
    'copyTextureToTexture',
    function (
      this: object,
      sourceValue: unknown,
      destinationValue: unknown,
      copySizeValue: unknown,
    ) {
      const encoder = requireState(this, 'GPUCommandEncoder');
      const source = convertTexelCopyTextureInfo(
        sourceValue,
        'GPUCommandEncoder.copyTextureToTexture source',
      );
      const destination = convertTexelCopyTextureInfo(
        destinationValue,
        'GPUCommandEncoder.copyTextureToTexture destination',
      );
      const copySize = convertExtent3D(
        copySizeValue,
        'GPUCommandEncoder.copyTextureToTexture copySize',
      );
      const converted = Object.freeze({
        source: Object.freeze({
          aspect: source.aspect,
          mipLevel: source.mipLevel,
          origin: source.origin,
          texture: source.texture,
        }),
        destination: Object.freeze({
          aspect: destination.aspect,
          mipLevel: destination.mipLevel,
          origin: destination.origin,
          texture: destination.texture,
        }),
        copySize,
      });
      const commandTargets = preflightCommandRecordCapacity([encoder]);
      const localRecordPlan = prepareLocalRecord(
        'GPUCommandEncoder.copyTextureToTexture',
        encoder,
        encoder.device,
      );
      const textureRangeIsValid = (
        texture: WrapperState,
        mipLevel: number,
        origin: Readonly<{ x: number; y: number; z: number }>,
      ): boolean => {
        if (
          texture.textureWidth === undefined ||
          texture.textureHeight === undefined ||
          texture.textureDepthOrArrayLayers === undefined
        ) return false;
        const divisor = 2 ** Math.min(mipLevel, 1_024);
        const width = Math.max(1, Math.floor(texture.textureWidth / divisor));
        const height = texture.textureDimension === '1d'
          ? 1
          : Math.max(1, Math.floor(texture.textureHeight / divisor));
        const depth = texture.textureDimension === '3d'
          ? Math.max(
            1,
            Math.floor(texture.textureDepthOrArrayLayers / divisor),
          )
          : texture.textureDepthOrArrayLayers;
        return origin.x <= width &&
          copySize.width <= width - origin.x &&
          origin.y <= height &&
          copySize.height <= height - origin.y &&
          origin.z <= depth &&
          copySize.depthOrArrayLayers <= depth - origin.z;
      };
      const invalid =
        encoder.status !== 'recording' ||
        Boolean(encoder.activePass) ||
        encoder.invalid ||
        !stateIsUsableOnDevice(source.textureState, encoder.device) ||
        !stateIsUsableOnDevice(destination.textureState, encoder.device) ||
        source.textureState.textureExpired ||
        destination.textureState.textureExpired ||
        (source.textureState.textureUsage !== undefined &&
          (source.textureState.textureUsage & 1) === 0) ||
        (destination.textureState.textureUsage !== undefined &&
          (destination.textureState.textureUsage & 2) === 0) ||
        !textureRangeIsValid(source.textureState, source.mipLevel, source.origin) ||
        !textureRangeIsValid(
          destination.textureState,
          destination.mipLevel,
          destination.origin,
        );
      const error = invalid
        ? namedError('GPUValidationError', 'Texture copy is invalid for this encoder')
        : undefined;
      if (invalid) encoder.invalid = true;
      const committed = commitLocalRecord(
        localRecordPlan,
        encoder,
        undefined,
        converted,
        error,
      );
      appendCommandRecord(commandTargets, committed.sealedRecord);
    },
  );

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'resolveQuerySet', function (
    this: object,
    querySetValue: unknown,
    firstQueryValue: unknown,
    queryCountValue: unknown,
    destinationValue: unknown,
    destinationOffsetValue: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const { converted, statesByReference } = convertWithCapturedStates(
      'GPUCommandEncoder.resolveQuerySet',
      [
        querySetValue,
        firstQueryValue,
        queryCountValue,
        destinationValue,
        destinationOffsetValue,
      ],
    );
    const body = asRecord(converted, 'resolveQuerySet converted arguments');
    const querySet = stateForCapturedReference(
      statesByReference,
      body.querySet,
      'resolveQuerySet querySet',
    );
    const destination = stateForCapturedReference(
      statesByReference,
      body.destination,
      'resolveQuerySet destination',
    );
    const firstQuery = body.firstQuery as number;
    const queryCount = body.queryCount as number;
    const destinationOffset = body.destinationOffset as number;
    const commandTargets = preflightCommandRecordCapacity([encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUCommandEncoder.resolveQuerySet',
      encoder,
      encoder.device,
    );
    const destinationRemaining = destination.bufferSize === undefined ||
        destinationOffset > destination.bufferSize
      ? -1
      : destination.bufferSize - destinationOffset;
    const resolvedBytes = queryCount * 8;
    const invalid =
      encoder.status !== 'recording' ||
      Boolean(encoder.activePass) ||
      encoder.invalid ||
      !stateIsUsableOnDevice(querySet, encoder.device) ||
      querySet.querySetCount === undefined ||
      firstQuery >= querySet.querySetCount ||
      firstQuery + queryCount > querySet.querySetCount ||
      !stateIsUsableOnDevice(destination, encoder.device) ||
      destination.bufferSize === undefined ||
      (destination.bufferUsage !== undefined &&
        (destination.bufferUsage & 512) === 0) ||
      destinationOffset % 256 !== 0 ||
      destinationRemaining < 0 ||
      resolvedBytes > destinationRemaining;
    const error = invalid
      ? namedError('GPUValidationError', 'Query-set resolve is invalid')
      : undefined;
    if (invalid) encoder.invalid = true;
    const committed = commitLocalRecord(
      localRecordPlan,
      encoder,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'beginRenderPass', function (
    this: object,
    descriptor: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const { converted, statesByReference } = convertWithCapturedStates(
      'GPUCommandEncoder.beginRenderPass',
      [descriptor],
    );
    const convertedBody = asRecord(
      converted,
      'beginRenderPass converted arguments',
    );
    const timestampWrites = convertedBody.timestampWrites === null
      ? null
      : asRecord(
        convertedBody.timestampWrites,
        'GPURenderPassTimestampWrites',
      );
    const timestampQuerySet = timestampWrites === null
      ? undefined
      : stateForCapturedReference(
        statesByReference,
        timestampWrites.querySet,
        'GPURenderPassTimestampWrites.querySet',
      );
    const commandTargets = preflightCommandRecordCapacity([encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUCommandEncoder.beginRenderPass',
      encoder,
      encoder.device,
    );
    const canOpen =
      encoder.status === 'recording' && !encoder.activePass && !encoder.invalid;
    const pass = allocateWrapper('GPURenderPassEncoder', encoder.device);
    pass.encoder = encoder;
    pass.status = canOpen ? 'open' : 'invalid';
    pass.invalid = !canOpen;
    if (canOpen) {
      encoder.activePass = pass;
      realm.activePassCount += 1;
    }
    const timestampInvalid = passTimestampWritesAreInvalid(
      timestampWrites,
      timestampQuerySet,
      encoder.device,
    );
    const error = !canOpen
      ? namedError('GPUValidationError', 'Command encoder cannot begin a pass')
      : timestampInvalid
        ? namedError(
          'GPUValidationError',
          'Render pass timestamp writes are unavailable or invalid',
        )
        : undefined;
    if (error) {
      pass.invalid = true;
      // As with compute passes, a post-lock timestamp failure is owned by
      // this pass. Its end() transition unlocks before poisoning the parent.
      if (!canOpen) encoder.invalid = true;
    }
    const committed = commitLocalRecord(
      localRecordPlan,
      encoder,
      pass,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
    return pass.wrapper;
  });

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'finish', function (
    this: object,
    descriptor?: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const converted = convert('GPUCommandEncoder.finish', [descriptor]);
    const commandTargets = preflightCommandRecordCapacity([encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUCommandEncoder.finish',
      encoder,
      encoder.device,
    );
    const invalid =
      encoder.status !== 'recording' || Boolean(encoder.activePass) || encoder.invalid;
    const error = invalid
      ? namedError('GPUValidationError', 'Command encoder cannot finish')
      : undefined;
    encoder.status = 'finished';
    const commandBuffer = allocateWrapper('GPUCommandBuffer', encoder.device);
    commandBuffer.invalid = invalid;
    const usedBindGroups = Object.freeze(
      [...encoder.usedBindGroups]
        .map((bindGroup) => reference(bindGroup.wrapper, 'GPUBindGroup'))
        .sort((left, right) => {
          const leftKey = `${left.objectId}/${left.objectGeneration}`;
          const rightKey = `${right.objectId}/${right.objectGeneration}`;
          return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        }),
    );
    const committed = commitLocalRecord(
      localRecordPlan,
      encoder,
      commandBuffer,
      Object.freeze({ descriptor: converted, usedBindGroups }),
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
    commandBuffer.records = Object.freeze(encoder.records.slice()) as unknown[];
    return commandBuffer.wrapper;
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'draw', function (
    this: object,
    vertexCount: unknown,
    instanceCount?: unknown,
    firstVertex?: unknown,
    firstInstance?: unknown,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const converted = convert('GPURenderPassEncoder.draw', [
      vertexCount,
      instanceCount,
      firstVertex,
      firstInstance,
    ]);
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.draw',
      pass,
      pass.device,
    );
    const invalid = pass.status !== 'open' || pass.invalid;
    const error = invalid
      ? namedError('GPUValidationError', 'Render pass has ended')
      : undefined;
    if (invalid) {
      pass.invalid = true;
      if (pass.encoder) pass.encoder.invalid = true;
    }
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'drawIndexed', function (
    this: object,
    indexCount: unknown,
    instanceCount?: unknown,
    firstIndex?: unknown,
    baseVertex?: unknown,
    firstInstance?: unknown,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const converted = convert(
      'GPURenderPassEncoder.drawIndexed',
      [indexCount, instanceCount, firstIndex, baseVertex, firstInstance],
    ) as Readonly<{
      indexCount: number;
      instanceCount: number;
      firstIndex: number;
      baseVertex: number;
      firstInstance: number;
    }>;
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.drawIndexed',
      pass,
      pass.device,
    );
    const binding = pass.indexBufferBinding;
    const indexByteSize = binding?.indexFormat === 'uint16' ? 2 : 4;
    const availableIndexCount = binding === undefined
      ? -1
      : Math.floor(binding.size / indexByteSize);
    const invalid =
      pass.status !== 'open' ||
      pass.invalid ||
      !pass.currentPipeline ||
      binding === undefined ||
      converted.firstIndex + converted.indexCount > availableIndexCount;
    const error = invalid
      ? namedError('GPUValidationError', 'Indexed draw is invalid for this render pass')
      : undefined;
    if (invalid) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'drawIndirect', function (
    this: object,
    indirectBufferValue: unknown,
    indirectOffsetValue: unknown,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const { converted, statesByReference } = convertWithCapturedStates(
      'GPURenderPassEncoder.drawIndirect',
      [indirectBufferValue, indirectOffsetValue],
    );
    const body = asRecord(converted, 'drawIndirect converted arguments');
    const indirectBuffer = stateForCapturedReference(
      statesByReference,
      body.indirectBuffer,
      'drawIndirect indirectBuffer',
    );
    const indirectOffset = body.indirectOffset as number;
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.drawIndirect',
      pass,
      pass.device,
    );
    const remaining = indirectBuffer.bufferSize === undefined ||
        indirectOffset > indirectBuffer.bufferSize
      ? -1
      : indirectBuffer.bufferSize - indirectOffset;
    const invalid =
      pass.status !== 'open' ||
      pass.invalid ||
      !pass.currentPipeline ||
      !stateIsUsableOnDevice(indirectBuffer, pass.device) ||
      indirectBuffer.bufferSize === undefined ||
      (indirectBuffer.bufferUsage !== undefined &&
        (indirectBuffer.bufferUsage & 256) === 0) ||
      indirectOffset % 4 !== 0 ||
      remaining < 16;
    const error = invalid
      ? namedError('GPUValidationError', 'Indirect draw is invalid for this render pass')
      : undefined;
    if (invalid) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'setPipeline', function (
    this: object,
    pipelineValue: unknown,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const converted = convert('GPURenderPassEncoder.setPipeline', [pipelineValue]);
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.setPipeline',
      pass,
      pass.device,
    );
    const pipeline = requireState(pipelineValue, 'GPURenderPipeline');
    const invalid =
      pass.status !== 'open' ||
      pass.invalid ||
      pipeline.device !== pass.device;
    const error = invalid
      ? namedError('GPUValidationError', 'Pipeline is invalid for this render pass')
      : undefined;
    if (invalid) {
      pass.invalid = true;
      if (pass.encoder) pass.encoder.invalid = true;
    } else {
      pass.currentPipeline = pipeline;
    }
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(
    mutablePrototypes.GPURenderPassEncoder,
    'setBindGroup',
    function (this: object, ...args: unknown[]) {
      recordSetBindGroup(
        requireState(this, 'GPURenderPassEncoder'),
        args,
        true,
      );
    },
  );

  defineMethod(
    mutablePrototypes.GPURenderPassEncoder,
    'setIndexBuffer',
    function (
      this: object,
      bufferValue: unknown,
      indexFormatValue: unknown,
      offsetValue?: unknown,
      sizeValue?: unknown,
    ) {
      const pass = requireState(this, 'GPURenderPassEncoder');
      const { converted, statesByReference } = convertWithCapturedStates(
        'GPURenderPassEncoder.setIndexBuffer',
        [bufferValue, indexFormatValue, offsetValue, sizeValue],
      );
      const body = asRecord(converted, 'setIndexBuffer converted arguments');
      const buffer = stateForCapturedReference(
        statesByReference,
        body.buffer,
        'setIndexBuffer buffer',
      );
      const indexFormat = body.indexFormat as 'uint16' | 'uint32';
      const offset = body.offset as number;
      const sizePresent = body.sizePresent as boolean;
      const encodedSize = body.size as number;
      const normalizedSize = sizePresent
        ? encodedSize
        : Math.max(0, (buffer.bufferSize ?? 0) - offset);
      const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
      const localRecordPlan = prepareLocalRecord(
        'GPURenderPassEncoder.setIndexBuffer',
        pass,
        pass.device,
      );
      const remaining = buffer.bufferSize === undefined ||
          offset > buffer.bufferSize
        ? -1
        : buffer.bufferSize - offset;
      const alignment = indexFormat === 'uint16' ? 2 : 4;
      const invalid =
        pass.status !== 'open' ||
        pass.invalid ||
        !stateIsUsableOnDevice(buffer, pass.device) ||
        buffer.bufferSize === undefined ||
        (buffer.bufferUsage !== undefined && (buffer.bufferUsage & 16) === 0) ||
        offset % alignment !== 0 ||
        remaining < 0 ||
        normalizedSize > remaining;
      const error = invalid
        ? namedError(
          'GPUValidationError',
          'Index buffer is invalid for this render pass',
        )
        : undefined;
      if (invalid) {
        invalidatePass(pass);
      } else {
        pass.indexBufferBinding = Object.freeze({
          buffer,
          indexFormat,
          offset,
          size: normalizedSize,
        });
      }
      const committed = commitLocalRecord(
        localRecordPlan,
        pass,
        undefined,
        converted,
        error,
      );
      appendCommandRecord(commandTargets, committed.sealedRecord);
    },
  );

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'setVertexBuffer', function (
    this: object,
    slotValue: unknown,
    bufferValue: unknown,
    offsetValue?: unknown,
    sizeValue?: unknown,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const slot = stagedU32(slotValue, 'GPURenderPassEncoder.setVertexBuffer slot');
    const buffer = bufferValue === null || bufferValue === undefined
      ? null
      : requireState(bufferValue, 'GPUBuffer');
    const offset = stagedU64(
      offsetValue,
      'GPURenderPassEncoder.setVertexBuffer offset',
      0,
    );
    const size = sizeValue === undefined
      ? null
      : stagedU64(sizeValue, 'GPURenderPassEncoder.setVertexBuffer size');
    const converted = Object.freeze({
      slot,
      buffer: buffer === null ? null : reference(bufferValue, 'GPUBuffer'),
      offset,
      size,
    });
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.setVertexBuffer',
      pass,
      pass.device,
    );
    const maxVertexBuffers = pass.device?.limits.maxVertexBuffers;
    const remaining = buffer?.bufferSize === undefined ||
        offset > buffer.bufferSize
      ? -1
      : buffer.bufferSize - offset;
    const invalid =
      pass.status !== 'open' ||
      pass.invalid ||
      (typeof maxVertexBuffers === 'number' && slot >= maxVertexBuffers) ||
      (buffer === null
        ? offset !== 0 || size !== null
        : !stateIsUsableOnDevice(buffer, pass.device) ||
          buffer.bufferSize === undefined ||
          (buffer.bufferUsage !== undefined && (buffer.bufferUsage & 32) === 0) ||
          remaining < 0 ||
          (size !== null && size > remaining));
    const error = invalid
      ? namedError('GPUValidationError', 'Vertex buffer is invalid for this render pass')
      : undefined;
    if (invalid) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(
    mutablePrototypes.GPUComputePassEncoder,
    'setBindGroup',
    function (this: object, ...args: unknown[]) {
      recordSetBindGroup(
        requireState(this, 'GPUComputePassEncoder'),
        args,
        false,
      );
    },
  );

  defineMethod(mutablePrototypes.GPUComputePassEncoder, 'setPipeline', function (
    this: object,
    pipelineValue: unknown,
  ) {
    const pass = requireState(this, 'GPUComputePassEncoder');
    const pipeline = requireState(pipelineValue);
    const pipelineRef = reference(pipelineValue);
    const converted = Object.freeze({ pipeline: pipelineRef });
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUComputePassEncoder.setPipeline',
      pass,
      pass.device,
    );
    pass.currentPipeline = pipeline;
    const invalid =
      pass.status !== 'open' ||
      pass.invalid ||
      (pipeline.kind as string) !== 'GPUComputePipeline' ||
      !stateIsUsableOnDevice(pipeline, pass.device);
    const error = invalid
      ? namedError('GPUValidationError', 'Pipeline is invalid for this compute pass')
      : undefined;
    if (invalid) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(
    mutablePrototypes.GPUComputePassEncoder,
    'dispatchWorkgroups',
    function (
      this: object,
      workgroupCountXValue: unknown,
      workgroupCountYValue?: unknown,
      workgroupCountZValue?: unknown,
    ) {
      const pass = requireState(this, 'GPUComputePassEncoder');
      const converted = Object.freeze({
        workgroupCountX: stagedU32(
          workgroupCountXValue,
          'GPUComputePassEncoder.dispatchWorkgroups workgroupCountX',
        ),
        workgroupCountY: stagedU32(
          workgroupCountYValue,
          'GPUComputePassEncoder.dispatchWorkgroups workgroupCountY',
          1,
        ),
        workgroupCountZ: stagedU32(
          workgroupCountZValue,
          'GPUComputePassEncoder.dispatchWorkgroups workgroupCountZ',
          1,
        ),
      });
      const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
      const localRecordPlan = prepareLocalRecord(
        'GPUComputePassEncoder.dispatchWorkgroups',
        pass,
        pass.device,
      );
      const limit = pass.device?.limits.maxComputeWorkgroupsPerDimension;
      const invalid =
        pass.status !== 'open' ||
        pass.invalid ||
        !pass.currentPipeline ||
        (pass.currentPipeline.kind as string) !== 'GPUComputePipeline' ||
        (typeof limit === 'number' && (
          converted.workgroupCountX > limit ||
          converted.workgroupCountY > limit ||
          converted.workgroupCountZ > limit
        ));
      const error = invalid
        ? namedError('GPUValidationError', 'Compute dispatch is invalid for this pass')
        : undefined;
      if (invalid) invalidatePass(pass);
      const committed = commitLocalRecord(
        localRecordPlan,
        pass,
        undefined,
        converted,
        error,
      );
      appendCommandRecord(commandTargets, committed.sealedRecord);
    },
  );

  defineMethod(mutablePrototypes.GPUComputePassEncoder, 'end', function (
    this: object,
  ) {
    const pass = requireState(this, 'GPUComputePassEncoder');
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPUComputePassEncoder.end',
      pass,
      pass.device,
    );
    const wasOpen = pass.status === 'open';
    // The end/unlock/used-group transition is mandatory and precedes every
    // invalid-pass or unbalanced-debug-group check, including a second end().
    pass.status = 'ended';
    if (pass.encoder?.activePass === pass) {
      pass.encoder.activePass = undefined;
      realm.activePassCount -= 1;
    }
    if (pass.encoder) {
      for (const bound of pass.boundBindGroups.values()) {
        if (bound.bindGroup !== null) pass.encoder.usedBindGroups.add(bound.bindGroup);
      }
    }
    const usedBindGroups = Object.freeze(
      [...(pass.encoder?.usedBindGroups ?? [])]
        .map((bindGroup) => reference(bindGroup.wrapper, 'GPUBindGroup'))
        .sort((left, right) => {
          const leftKey = `${left.objectId}/${left.objectGeneration}`;
          const rightKey = `${right.objectId}/${right.objectGeneration}`;
          return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        }),
    );
    const invalid = !wasOpen || pass.invalid || pass.debugGroupDepth !== 0;
    const error = invalid
      ? namedError(
        'GPUValidationError',
        !wasOpen
          ? 'Compute pass already ended'
          : pass.debugGroupDepth !== 0
            ? 'Compute pass has unbalanced debug groups'
            : 'Compute pass is invalid',
      )
      : undefined;
    if (invalid) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      Object.freeze({ usedBindGroups }),
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'end', function (
    this: object,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const converted = convert('GPURenderPassEncoder.end', []);
    const commandTargets = preflightCommandRecordCapacity([pass, pass.encoder]);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.end',
      pass,
      pass.device,
    );
    const wasOpen = pass.status === 'open';
    pass.status = 'ended';
    if (pass.encoder?.activePass === pass) {
      pass.encoder.activePass = undefined;
      realm.activePassCount -= 1;
    }
    const invalid = !wasOpen || pass.invalid;
    const error = invalid
      ? namedError(
        'GPUValidationError',
        !wasOpen
          ? 'Render pass already ended'
          : 'Render pass is invalid',
      )
      : undefined;
    if (invalid) invalidatePass(pass);
    const committed = commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
    appendCommandRecord(commandTargets, committed.sealedRecord);
  });

  defineMethod(mutablePrototypes.GPUQueue, 'writeTexture', function (
    this: object,
    destination: unknown,
    data: unknown,
    dataLayout: unknown,
    size: unknown,
  ) {
    const queue = requireState(this, 'GPUQueue');
    const converted = convert('GPUQueue.writeTexture', [
      destination,
      data,
      dataLayout,
      size,
    ]);
    submitService(
      'GPUQueue.writeTexture',
      queue,
      undefined,
      converted,
      false,
    );
  });

  defineMethod(
    mutablePrototypes.GPUQueue,
    'copyExternalImageToTexture',
    function (
      this: object,
      source: unknown,
      destination: unknown,
      copySize: unknown,
    ) {
      const queue = requireState(this, 'GPUQueue');
      const converted = convert('GPUQueue.copyExternalImageToTexture', [
        source,
        destination,
        copySize,
      ]);
      submitService(
        'GPUQueue.copyExternalImageToTexture',
        queue,
        undefined,
        converted,
        false,
      );
    },
  );

  defineMethod(mutablePrototypes.GPUQueue, 'submit', function (
    this: object,
    commandBuffers: unknown,
  ) {
    const queue = requireState(this, 'GPUQueue');
    const converted = convert('GPUQueue.submit', [commandBuffers]);
    if (!Array.isArray(converted)) {
      throw new TypeError('GPUQueue.submit conversion must produce a sequence');
    }
    if (converted.length > MAX_LOCAL_RECORDS) {
      throw new RangeError('GPUQueue.submit command buffer sequence exceeds its bound');
    }
    const sealedPrograms: unknown[] = [];
    const states: WrapperState[] = [];
    let totalProgramRecordCount = 0;
    let wrapperValidationError: Readonly<{ name: string; message: string }> | undefined;
    for (const value of converted) {
      const buffer = requireState(value, 'GPUCommandBuffer');
      if (buffer.device !== queue.device) {
        wrapperValidationError = Object.freeze({
          name: 'GPUValidationError',
          message: 'Command buffer belongs to another logical device',
        });
      }
      if (buffer.submitted) {
        wrapperValidationError = Object.freeze({
          name: 'GPUValidationError',
          message: 'Command buffer is single-use',
        });
      }
      if (buffer.invalid) {
        wrapperValidationError = Object.freeze({
          name: 'GPUValidationError',
          message: 'Command buffer contains invalid recorded commands',
        });
      }
      states.push(buffer);
      if (buffer.records.length > MAX_LOCAL_RECORDS - totalProgramRecordCount) {
        throw new RangeError(
          'GPUQueue.submit command programs exceed their authenticated record bound',
        );
      }
      totalProgramRecordCount += buffer.records.length;
      const records = Object.freeze(buffer.records.slice());
      sealedPrograms.push(
        Object.freeze({
          commandBuffer: reference(value, 'GPUCommandBuffer'),
          invalid: buffer.invalid,
          records,
        }),
      );
    }
    submitService(
      'GPUQueue.submit',
      queue,
      undefined,
      Object.freeze({
        commandBuffers: Object.freeze(sealedPrograms),
        wrapperValidationError,
      }),
      false,
    );
    if (!wrapperValidationError) {
      for (const state of states) state.submitted = true;
    }
  });

  defineMethod(mutablePrototypes.GPUQueue, 'writeBuffer', function (
    this: object,
    buffer: unknown,
    bufferOffset: unknown,
    data: unknown,
    dataOffset?: unknown,
    size?: unknown,
  ) {
    const queue = requireState(this, 'GPUQueue');
    const converted = convert('GPUQueue.writeBuffer', [
      buffer,
      bufferOffset,
      data,
      dataOffset,
      size,
    ]);
    submitService(
      'GPUQueue.writeBuffer',
      queue,
      undefined,
      converted,
      false,
    );
  });

  type DecodedBufferMapCompletion = Readonly<{
    variant:
      | 'mapped-bytes'
      | 'provider-operation-error'
      | 'allocation-range-error'
      | 'late-cancelled-cleanup';
    pendingMapGeneration: string;
    mode: 1 | 2;
    offset: number;
    size: number;
    ownedBytes: unknown;
  }>;

  const decodeBufferMapCompletion = (
    decoded: ProductionGpuDecodedResult,
  ): DecodedBufferMapCompletion => {
    if (decoded.kind !== 'value') {
      throw new TypeError('GPUBuffer.mapAsync completion must carry a value');
    }
    const value = snapshotOwnEnumerableDataRecord(
      decoded.value,
      [
        'variant',
        'pendingMapGeneration',
        'mode',
        'offset',
        'size',
        'ownedBytes',
      ],
      'GPUBuffer.mapAsync completion has the wrong shape',
    );
    const variant = value.variant;
    if (
      variant !== 'mapped-bytes' &&
      variant !== 'provider-operation-error' &&
      variant !== 'allocation-range-error' &&
      variant !== 'late-cancelled-cleanup'
    ) {
      throw new TypeError('GPUBuffer.mapAsync completion variant is invalid');
    }
    const pendingMapGeneration = value.pendingMapGeneration;
    const offsetText = value.offset;
    const sizeText = value.size;
    if (
      typeof pendingMapGeneration !== 'string' ||
      !isPositiveDecimal(pendingMapGeneration) ||
      typeof offsetText !== 'string' ||
      !isCanonicalU64Decimal(offsetText, false) ||
      typeof sizeText !== 'string' ||
      !isCanonicalU64Decimal(sizeText, false)
    ) {
      throw new TypeError('GPUBuffer.mapAsync completion generations are invalid');
    }
    const mode = value.mode;
    if (mode !== 1 && mode !== 2) {
      throw new TypeError('GPUBuffer.mapAsync completion mode is invalid');
    }
    const offset = Number(offsetText);
    const size = Number(sizeText);
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size)) {
      throw new TypeError('GPUBuffer.mapAsync completion range is unsafe');
    }
    const ownedBytes = value.ownedBytes;
    const ownedLength = (() => {
      if (
        !INTRINSIC_TYPED_ARRAY_TAG_GETTER ||
        !INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER ||
        INTRINSIC_REFLECT_APPLY(
          INTRINSIC_TYPED_ARRAY_TAG_GETTER,
          ownedBytes,
          [],
        ) !== 'Uint8Array'
      ) {
        throw new TypeError('GPUBuffer.mapAsync completion bytes are invalid');
      }
      return INTRINSIC_REFLECT_APPLY(
        INTRINSIC_TYPED_ARRAY_BYTE_LENGTH_GETTER,
        ownedBytes,
        [],
      ) as number;
    })();
    if (
      (variant === 'mapped-bytes' && ownedLength !== size) ||
      (variant !== 'mapped-bytes' && ownedLength !== 0)
    ) {
      throw new TypeError('GPUBuffer.mapAsync completion byte ownership is invalid');
    }
    return Object.freeze({
      variant,
      pendingMapGeneration,
      mode,
      offset,
      size,
      ownedBytes,
    });
  };

  const clearCurrentPendingMap = (
    buffer: WrapperState,
    pending: PendingBufferMapState,
    error: unknown,
  ): void => {
    if (buffer.bufferPendingMap !== pending) return;
    buffer.bufferPendingMap = undefined;
    buffer.bufferMapState = buffer.bufferActiveMapping ? 'mapped' : 'unmapped';
    settlePendingBufferMap(pending, error);
    releaseBufferLifecycleIfIdle(buffer);
  };

  const reclaimRejectedBufferMapCompletion = (
    buffer: WrapperState,
    pending: PendingBufferMapState,
    completion: DecodedBufferMapCompletion,
    error: unknown,
  ): void => {
    if (buffer.bufferPendingMap !== pending) return;
    // Settle the public promise before any reclamation preparation. Counter or
    // allocation failure below may close the realm, but it must neither replace
    // the original map error with AbortError nor escape from this ignored
    // Promise fulfillment handler.
    clearCurrentPendingMap(buffer, pending, error);
    try {
      if (buffer.bufferPendingCleanup !== undefined) {
        closeRealmCounterIndependently(
          'buffer-map-reclamation-conflict',
          'The WebGPU realm closed after a buffer map reclamation conflict',
        );
        return;
      }
      const cleanupPlan = consumeNextCounterOrClose(
        buffer.bufferNextCleanupGeneration,
        buffer.bufferCleanupGenerationExhausted,
        'buffer cleanup generation',
      );
      const cleanup = Object.freeze({
        operationId: 'GPUBuffer.unmap' as const,
        body: Object.freeze({
          kind: 'cleanup-v1' as const,
          cleanupAction: 1 as const,
          cleanupGeneration: cleanupPlan.value,
          cancelledMapGeneration: '0',
          activeMapGeneration: pending.generation,
          activeMapMode: pending.mode,
          mappedOffset: String(pending.offset),
          mappedSize: String(pending.size),
          writeback: pending.mode === 2
            ? completion.ownedBytes as Uint8Array
            : EMPTY_BUFFER_WRITEBACK,
        }),
      });
      buffer.bufferPendingCleanup = cleanup;
      retainBufferLifecycle(buffer);
      submitBufferCleanup(buffer, cleanup);
    } catch {
      closeRealmCounterIndependently(
        'buffer-map-reclamation-preparation-failed',
        'The WebGPU realm closed after buffer map reclamation preparation failed',
      );
    }
  };

  const handleBufferMapCompletion = (
    buffer: WrapperState,
    pending: PendingBufferMapState,
    decoded: ProductionGpuDecodedResult,
  ): void => {
    let completion: DecodedBufferMapCompletion;
    try {
      completion = decodeBufferMapCompletion(decoded);
    } catch {
      clearCurrentPendingMap(
        buffer,
        pending,
        namedError('OperationError', 'GPUBuffer map completion is invalid'),
      );
      closeRealmCounterIndependently(
        'buffer-map-terminal-invalid',
        'The WebGPU realm closed after an invalid buffer map terminal',
      );
      return;
    }
    if (
      completion.pendingMapGeneration !== pending.generation ||
      completion.mode !== pending.mode ||
      completion.offset !== pending.offset ||
      completion.size !== pending.size
    ) {
      clearCurrentPendingMap(
        buffer,
        pending,
        namedError(
          'OperationError',
          'GPUBuffer.mapAsync completion does not match its pending generation',
        ),
      );
      closeRealmCounterIndependently(
        'buffer-map-terminal-mismatch',
        'The WebGPU realm closed after a mismatched buffer map terminal',
      );
      return;
    }
    // A cleanup or lifecycle terminal may already have settled and removed
    // this pending generation. The typed completion is then reclamation-only.
    if (buffer.bufferPendingMap !== pending) return;
    if (completion.variant === 'provider-operation-error') {
      clearCurrentPendingMap(
        buffer,
        pending,
        namedError('OperationError', 'GPUBuffer provider mapping failed'),
      );
      return;
    }
    if (completion.variant === 'allocation-range-error') {
      clearCurrentPendingMap(
        buffer,
        pending,
        new RangeError('GPUBuffer mapped byte block could not be allocated'),
      );
      return;
    }
    if (completion.variant === 'late-cancelled-cleanup') {
      clearCurrentPendingMap(
        buffer,
        pending,
        namedError('AbortError', 'GPUBuffer mapping was cancelled'),
      );
      return;
    }
    const guardBytesBefore = realm.privateMappedAllocationGuardBytes;
    if (
      completion.size >
        realm.privateMappedAllocationGuardLimitBytes - guardBytesBefore
    ) {
      reclaimRejectedBufferMapCompletion(
        buffer,
        pending,
        completion,
        new RangeError('GPUBuffer private mapped allocation guard is exhausted'),
      );
      return;
    }
    let ownedBlock: Uint8Array;
    try {
      ownedBlock = retainOwnedUint8View(completion.ownedBytes, completion.size);
    } catch (error) {
      reclaimRejectedBufferMapCompletion(
        buffer,
        pending,
        completion,
        error instanceof RangeError
          ? error
          : new RangeError('GPUBuffer mapped byte block could not be allocated'),
      );
      return;
    }
    realm.privateMappedAllocationGuardBytes = guardBytesBefore + completion.size;
    buffer.bufferPendingMap = undefined;
    buffer.bufferActiveMapping = {
      generation: pending.generation,
      mode: pending.mode,
      offset: pending.offset,
      size: pending.size,
      bytes: ownedBlock,
      ranges: [],
    };
    buffer.bufferMapState = 'mapped';
    settlePendingBufferMap(pending);
  };

  const captureBufferCleanup = (
    buffer: WrapperState,
    operationId: 'GPUBuffer.destroy' | 'GPUBuffer.unmap',
  ): PendingBufferCleanupState | undefined => {
    const existing = buffer.bufferPendingCleanup;
    if (existing) {
      if (buffer.bufferPendingMap || buffer.bufferActiveMapping) {
        closeRealmCounterIndependently(
          'buffer-cleanup-state-conflict',
          'The WebGPU realm closed because retained cleanup overlapped a newer map',
        );
        return undefined;
      }
      if (operationId === 'GPUBuffer.destroy' && existing.operationId === 'GPUBuffer.unmap') {
        const upgraded = Object.freeze({
          operationId,
          body: Object.freeze({
            ...existing.body,
            cleanupAction: 2 as const,
          }),
        });
        buffer.bufferPendingCleanup = upgraded;
        buffer.destroyed = true;
        return upgraded;
      }
      return existing.operationId === operationId ? existing : undefined;
    }
    const pendingMap = buffer.bufferPendingMap;
    const active = buffer.bufferActiveMapping;
    if (operationId === 'GPUBuffer.unmap' && !pendingMap && !active) {
      return undefined;
    }
    const cleanupPlan = consumeNextCounterOrClose(
      buffer.bufferNextCleanupGeneration,
      buffer.bufferCleanupGenerationExhausted,
      'buffer cleanup generation',
    );
    // Move the exact retained affine root view into cleanup. Engine aliases
    // share this block, so MAP_WRITE needs neither range shadow copies nor a
    // second full-extent allocation. Aliases are detached below before this
    // method returns.
    const writeback = active?.mode === 2
      ? active.bytes
      : EMPTY_BUFFER_WRITEBACK;
    const body = Object.freeze({
      kind: 'cleanup-v1' as const,
      cleanupAction: operationId === 'GPUBuffer.destroy' ? 2 as const : 1 as const,
      cleanupGeneration: cleanupPlan.value,
      cancelledMapGeneration: pendingMap?.generation ?? '0',
      activeMapGeneration: active?.generation ?? '0',
      activeMapMode: active?.mode ?? 0,
      mappedOffset: String(active?.offset ?? 0),
      mappedSize: String(active?.size ?? 0),
      writeback,
    });
    const cleanup = Object.freeze({ operationId, body });
    buffer.bufferPendingCleanup = cleanup;
    retainBufferLifecycle(buffer);
    cancelPendingBufferMap(
      buffer,
      operationId === 'GPUBuffer.destroy'
        ? 'GPUBuffer was destroyed'
        : 'GPUBuffer was unmapped',
      true,
    );
    moveActiveBufferMappingIntoCleanup(buffer);
    return cleanup;
  };

  function submitBufferCleanup(
    buffer: WrapperState,
    cleanup: PendingBufferCleanupState,
  ): void {
    let submissionFailure: ServiceSubmissionFailureKind | undefined;
    try {
      if (
        buffer.bufferPendingCleanup !== cleanup ||
        cleanup.body.cleanupGeneration !== buffer.bufferNextCleanupGeneration
      ) {
        closeRealmCounterIndependently(
          'buffer-cleanup-generation-conflict',
          'The WebGPU realm closed after a buffer cleanup generation conflict',
        );
        return;
      }
      const cleanupPlan = consumeNextCounterOrClose(
        buffer.bufferNextCleanupGeneration,
        buffer.bufferCleanupGenerationExhausted,
        'buffer cleanup generation',
      );
      const servicePlan = prepareServiceCounters(
        cleanup.operationId,
        buffer,
        buffer.device,
      );
      submitService(
        cleanup.operationId,
        buffer,
        undefined,
        null,
        false,
        servicePlan,
        undefined,
        (failure) => {
          submissionFailure = failure;
          if (failure === 'bridge-threw') {
            closeRealmCounterIndependently(
              'buffer-cleanup-bridge-threw',
              'The WebGPU realm closed after an ambiguous buffer cleanup',
            );
          }
        },
        undefined,
        cleanup.body,
        () => {
          if (buffer.bufferPendingCleanup !== cleanup) {
            closeRealmCounterIndependently(
              'buffer-cleanup-generation-conflict',
              'The WebGPU realm closed after a buffer cleanup generation conflict',
            );
            return;
          }
          buffer.bufferNextCleanupGeneration = cleanupPlan.next;
          buffer.bufferCleanupGenerationExhausted = cleanupPlan.exhaustedAfter;
          buffer.bufferPendingCleanup = undefined;
          releaseBufferLifecycleIfIdle(buffer);
        },
      );
    } catch {
      if (submissionFailure === 'submission-rejected') {
        // Known non-admission leaves the exact affine cleanup snapshot in
        // place. A later void cleanup call retries it with the same cleanup
        // generation and a fresh authenticated device ingress.
        return;
      }
      if (submissionFailure === 'bridge-threw') {
        // Ambiguous admission already closed the realm in the failure hook.
        return;
      }
      if (realm.active) {
        closeRealmCounterIndependently(
          'buffer-cleanup-preparation-failed',
          'The WebGPU realm closed after buffer cleanup preparation failed',
        );
      }
    }
  }

  const captureAndSubmitBufferCleanup = (
    buffer: WrapperState,
    operationId: 'GPUBuffer.destroy' | 'GPUBuffer.unmap',
  ): void => {
    try {
      if (buffer.device?.lost.settled) {
        // The physical target disappeared before this owning cleanup. WebGPU's
        // invalid-device branch still performs the synchronous content-side
        // authority reduction, but it issues no device/provider work. Do not
        // mint a retry snapshot for a target that can never admit it.
        cancelPendingBufferMap(
          buffer,
          operationId === 'GPUBuffer.destroy'
            ? 'GPUBuffer was destroyed after device loss'
            : 'GPUBuffer was unmapped after device loss',
          false,
        );
        detachActiveBufferMapping(buffer);
        discardPendingBufferCleanup(buffer);
        return;
      }
      const cleanup = captureBufferCleanup(buffer, operationId);
      if (cleanup) submitBufferCleanup(buffer, cleanup);
    } catch {
      if (realm.active) {
        closeRealmCounterIndependently(
          'buffer-cleanup-capture-failed',
          'The WebGPU realm closed after buffer cleanup capture failed',
        );
      }
    }
  };

  defineMethod(mutablePrototypes.GPUBuffer, 'destroy', function (this: object) {
    const buffer = requireState(this, 'GPUBuffer');
    convert('GPUBuffer.destroy', []);
    if (buffer.destroyed && buffer.bufferPendingCleanup === undefined) return;
    // Destruction is a synchronous authority reduction even if cleanup
    // capture, encoding, or service admission subsequently fails.
    buffer.destroyed = true;
    captureAndSubmitBufferCleanup(buffer, 'GPUBuffer.destroy');
  });

  defineMethod(mutablePrototypes.GPUBuffer, 'getMappedRange', function (
    this: object,
    offset?: unknown,
    size?: unknown,
  ) {
    const buffer = requireState(this, 'GPUBuffer');
    const converted = asRecord(
      convert('GPUBuffer.getMappedRange', [offset, size]),
      'converted GPUBuffer.getMappedRange arguments',
    );
    const active = buffer.bufferActiveMapping;
    const bufferSize = buffer.bufferSize;
    if (!active || bufferSize === undefined) {
      throw namedError('OperationError', 'GPUBuffer has no active mapping');
    }
    const rangeOffset = stagedU64(
      converted.offset,
      'converted GPUBuffer.getMappedRange offset',
    );
    const rangeSize = converted.size === undefined
      ? Math.max(0, bufferSize - rangeOffset)
      : stagedU64(converted.size, 'converted GPUBuffer.getMappedRange size');
    const rangeEnd = rangeOffset + rangeSize;
    if (
      rangeOffset % 8 !== 0 ||
      rangeSize % 4 !== 0 ||
      !Number.isSafeInteger(rangeEnd) ||
      rangeOffset < active.offset ||
      rangeEnd > active.offset + active.size ||
      active.ranges.some((range) =>
        rangeOffset < range.offset + range.size && range.offset < rangeEnd
      ) ||
      active.ranges.length >= PRIVATE_MAPPED_RANGE_LEASE_LIMIT
    ) {
      throw namedError('OperationError', 'GPUBuffer mapped range is unavailable');
    }
    if (
      !INTRINSIC_TYPED_ARRAY_BUFFER_GETTER ||
      !INTRINSIC_TYPED_ARRAY_BYTE_OFFSET_GETTER
    ) {
      closeRealmCounterIndependently(
        'buffer-mapped-range-source-unavailable',
        'The WebGPU realm closed because the mapped-range source intrinsics are unavailable',
      );
      throw namedError('OperationError', 'GPUBuffer mapped byte block is unavailable');
    }
    const source = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_BUFFER_GETTER,
      active.bytes,
      [],
    ) as ArrayBuffer;
    const sourceViewOffset = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_TYPED_ARRAY_BYTE_OFFSET_GETTER,
      active.bytes,
      [],
    ) as number;
    const aliasOffset = sourceViewOffset + rangeOffset - active.offset;
    let bytes: ArrayBuffer;
    try {
      bytes = bridge.createMappedRangeAlias(source, aliasOffset, rangeSize);
    } catch {
      closeRealmCounterIndependently(
        'buffer-mapped-range-mint-contradiction',
        'The WebGPU realm closed after mapped-range minting contradicted the engine bridge',
      );
      throw namedError('OperationError', 'GPUBuffer mapped range could not be minted');
    }
    // Ownership begins at the native return boundary. Track before inspecting
    // the result so even a malformed engine value is offered exactly once to
    // the matching detach method during fail-closed realm cleanup.
    const lease: BufferMappedRangeLease = {
      offset: rangeOffset,
      size: rangeSize,
      bytes,
      live: true,
    };
    active.ranges.push(lease);
    let aliasLength: number;
    try {
      aliasLength = intrinsicArrayBufferByteLength(bytes);
    } catch {
      closeRealmCounterIndependently(
        'buffer-mapped-range-mint-contradiction',
        'The WebGPU realm closed after mapped-range minting contradicted the engine bridge',
      );
      throw namedError('OperationError', 'GPUBuffer mapped range is invalid');
    }
    if (aliasLength !== rangeSize) {
      closeRealmCounterIndependently(
        'buffer-mapped-range-mint-contradiction',
        'The WebGPU realm closed after mapped-range minting contradicted the engine bridge',
      );
      throw namedError('OperationError', 'GPUBuffer mapped range has the wrong extent');
    }
    // Hermes' detach key is the engine authority. Mirror the validated alias
    // into Ibex's private set as well so its JS structuredClone implementation
    // rejects before attempting the separate legacy transfer fallback.
    markNonTransferableArrayBuffer(bytes);
    return bytes;
  });

  defineMethod(mutablePrototypes.GPUBuffer, 'mapAsync', function (
    this: object,
    mode: unknown,
    offset?: unknown,
    size?: unknown,
  ) {
    const buffer = requireState(this, 'GPUBuffer');
    let converted!: Readonly<Record<string, unknown>>;
    let generationPlan!: NextCounterConsumption;
    let pending!: PendingBufferMapState;
    let body!: ProductionGpuBufferLifecycleEncoding;
    try {
      converted = asRecord(
        convert('GPUBuffer.mapAsync', [mode, offset, size]),
        'converted GPUBuffer.mapAsync arguments',
      );
      const convertedMode = stagedU32(
        converted.mode,
        'converted GPUBuffer.mapAsync mode',
      );
      if (convertedMode !== 1 && convertedMode !== 2) {
        throw namedError(
          'OperationError',
          'GPUBuffer map mode must be exactly READ or WRITE',
        );
      }
      const mapOffset = stagedU64(
        converted.offset,
        'converted GPUBuffer.mapAsync offset',
      );
      const bufferSize = buffer.bufferSize ?? 0;
      const mapSize = converted.size === undefined
        ? Math.max(0, bufferSize - mapOffset)
        : stagedU64(converted.size, 'converted GPUBuffer.mapAsync size');
      if (buffer.destroyed || buffer.bufferPendingCleanup !== undefined) {
        throw namedError(
          'OperationError',
          'GPUBuffer is destroyed or awaiting cleanup',
        );
      }
      if (
        buffer.bufferMapState !== 'unmapped' ||
        buffer.bufferPendingMap !== undefined ||
        buffer.bufferActiveMapping !== undefined
      ) {
        // Content-timeline refusal: WebGPU permits only one pending/active map
        // lifecycle at a time. This rejected Promise consumes neither a map
        // generation nor authenticated service ingress.
        throw namedError('OperationError', 'GPUBuffer already has a mapping');
      }
      generationPlan = consumeNextCounterOrClose(
        buffer.bufferNextMapGeneration,
        buffer.bufferMapGenerationExhausted,
        'buffer map generation',
      );
      pending = makePendingBufferMap(
        generationPlan.value,
        convertedMode,
        mapOffset,
        mapSize,
      );
      body = Object.freeze({
        kind: 'map-async-v1',
        pendingMapGeneration: pending.generation,
        mode: pending.mode,
        offset: String(pending.offset),
        requestedSizePresent: converted.size === undefined ? 0 : 1,
        requestedSize: converted.size === undefined ? '0' : String(mapSize),
      });
    } catch (error) {
      return Promise.reject(error);
    }
    let servicePromise: Promise<ProductionGpuDecodedResult>;
    try {
      servicePromise = submitService(
        'GPUBuffer.mapAsync',
        buffer,
        undefined,
        converted,
        true,
        undefined,
        () => {
          buffer.bufferPendingMap = pending;
          buffer.bufferMapState = 'pending';
          retainBufferLifecycle(buffer);
        },
        (failure) => {
          if (buffer.bufferPendingMap === pending) {
            buffer.bufferPendingMap = undefined;
            buffer.bufferMapState = buffer.bufferActiveMapping
              ? 'mapped'
              : 'unmapped';
            releaseBufferLifecycleIfIdle(buffer);
          }
          if (failure === 'bridge-threw') {
            closeRealmCounterIndependently(
              'buffer-map-bridge-threw',
              'The WebGPU realm closed after an ambiguous buffer map',
            );
          }
        },
        undefined,
        body,
        (identity) => {
          buffer.bufferNextMapGeneration = generationPlan.next;
          buffer.bufferMapGenerationExhausted = generationPlan.exhaustedAfter;
          pending.operationInstanceId = identity.operationInstanceId;
          pending.promiseId = identity.promiseId;
        },
      ) as Promise<ProductionGpuDecodedResult>;
    } catch (error) {
      if (buffer.bufferPendingMap === pending) {
        buffer.bufferPendingMap = undefined;
        buffer.bufferMapState = buffer.bufferActiveMapping ? 'mapped' : 'unmapped';
        releaseBufferLifecycleIfIdle(buffer);
      }
      settlePendingBufferMap(
        pending,
        error instanceof Error && error.name === 'SecurityError'
          ? error
          : namedError('OperationError', 'GPUBuffer map submission was rejected'),
      );
      return pending.promise;
    }
    servicePromise.then(
      (decoded) => handleBufferMapCompletion(buffer, pending, decoded),
      (error) => {
        clearCurrentPendingMap(
          buffer,
          pending,
          error instanceof Error && error.name === 'AbortError'
            ? error
            : namedError('OperationError', 'GPUBuffer map validation failed'),
        );
      },
    );
    return pending.promise;
  });

  defineMethod(mutablePrototypes.GPUBuffer, 'unmap', function (this: object) {
    const buffer = requireState(this, 'GPUBuffer');
    convert('GPUBuffer.unmap', []);
    captureAndSubmitBufferCleanup(buffer, 'GPUBuffer.unmap');
  });

  defineMethod(mutablePrototypes.GPUTexture, 'createView', function (
    this: object,
    descriptor?: unknown,
  ) {
    const texture = requireState(this, 'GPUTexture');
    const converted = convert('GPUTexture.createView', [descriptor]);
    const servicePlan = prepareServiceCounters(
      'GPUTexture.createView',
      texture,
      texture.device,
    );
    const view = allocateWrapper('GPUTextureView', texture.device);
    submitService(
      'GPUTexture.createView',
      texture,
      view,
      Object.freeze({
        converted,
        ...(texture.currentOrigin === undefined
          ? {}
          : { currentOrigin: texture.currentOrigin }),
      }),
      false,
      servicePlan,
    );
    texture.materialized = true;
    return view.wrapper;
  });

  defineMethod(mutablePrototypes.GPUTexture, 'destroy', function (this: object) {
    const texture = requireState(this, 'GPUTexture');
    const converted = convert('GPUTexture.destroy', []);
    const receiverTextureRef = reference(texture.wrapper, 'GPUTexture');
    const terminalIntent = texture.destroyed
      ? 'repeat-cleanup-noop' as const
      : texture.textureExpired
        ? 'first-expired-cleanup' as const
        : 'first-cleanup' as const;
    const currentOrigin = texture.currentOrigin;
    let origin:
      | Readonly<{ kind: 'device-created-v1' }>
      | ProductionGpuCanvasCurrentTextureOriginEncoding;
    if (currentOrigin === undefined) {
      origin = Object.freeze({ kind: 'device-created-v1' });
    } else {
      origin = encodeCanvasCurrentOrigin(texture);
    }
    const textureDestroyServiceAuthority = Object.freeze({
      kind: 'texture-destroy-v1',
      receiverTextureRef,
      terminalIntent,
      materializationState: texture.materialized
        ? 'materialized' as const
        : 'unmaterialized' as const,
      origin,
    }) as ProductionGpuCanvasServiceEncoding;
    submitService(
      'GPUTexture.destroy',
      texture,
      undefined,
      converted,
      false,
      undefined,
      undefined,
      (failure) => {
        if (failure === 'bridge-threw') {
          closeRealmCounterIndependently(
            'texture-destroy-submit-threw',
            'The WebGPU realm closed because texture destroy submission threw',
          );
        }
      },
      textureDestroyServiceAuthority,
    );
    texture.destroyed = true;
  });

  // These are exact wrapper-local metadata reads. They deliberately do not
  // enter the service and remain private while the CapSec publication edge is
  // absent.
  defineGetter(mutablePrototypes.GPUAdapter, 'features', function (this: object) {
    const adapter = requireState(this, 'GPUAdapter');
    if (adapter.adapterFeatures === undefined) {
      throw new TypeError('GPUAdapter features metadata is unavailable');
    }
    return adapter.adapterFeatures;
  });
  defineGetter(mutablePrototypes.GPUBuffer, 'size', function (this: object) {
    const buffer = requireState(this, 'GPUBuffer');
    if (buffer.bufferSize === undefined) {
      throw new TypeError('GPUBuffer size metadata is unavailable');
    }
    return buffer.bufferSize;
  });
  defineGetter(mutablePrototypes.GPUBuffer, 'usage', function (this: object) {
    const buffer = requireState(this, 'GPUBuffer');
    if (buffer.bufferUsage === undefined) {
      throw new TypeError('GPUBuffer usage metadata is unavailable');
    }
    return buffer.bufferUsage;
  });
  defineGetter(mutablePrototypes.GPUBuffer, 'mapState', function (this: object) {
    const buffer = requireState(this, 'GPUBuffer');
    if (buffer.bufferMapState === undefined) {
      throw new TypeError('GPUBuffer mapState metadata is unavailable');
    }
    return buffer.bufferMapState;
  });
  defineGetter(mutablePrototypes.GPUTexture, 'dimension', function (this: object) {
    const texture = requireState(this, 'GPUTexture');
    if (texture.textureDimension === undefined) {
      throw new TypeError('GPUTexture dimension metadata is unavailable');
    }
    return texture.textureDimension;
  });
  defineGetter(mutablePrototypes.GPUTexture, 'format', function (this: object) {
    const texture = requireState(this, 'GPUTexture');
    if (texture.textureFormat === undefined) {
      throw new TypeError('GPUTexture format metadata is unavailable');
    }
    return texture.textureFormat;
  });
  defineGetter(mutablePrototypes.GPUTexture, 'height', function (this: object) {
    const texture = requireState(this, 'GPUTexture');
    if (texture.textureHeight === undefined) {
      throw new TypeError('GPUTexture height metadata is unavailable');
    }
    return texture.textureHeight;
  });
  defineGetter(
    mutablePrototypes.GPUTexture,
    'depthOrArrayLayers',
    function (this: object) {
      const texture = requireState(this, 'GPUTexture');
      if (texture.textureDepthOrArrayLayers === undefined) {
        throw new TypeError(
          'GPUTexture depthOrArrayLayers metadata is unavailable',
        );
      }
      return texture.textureDepthOrArrayLayers;
    },
  );
  defineGetter(mutablePrototypes.GPUTexture, 'width', function (this: object) {
    const texture = requireState(this, 'GPUTexture');
    if (texture.textureWidth === undefined) {
      throw new TypeError('GPUTexture width metadata is unavailable');
    }
    return texture.textureWidth;
  });

  for (const prototype of Object.values(mutablePrototypes)) Object.freeze(prototype);

  const interfaceObjects: Record<string, object> = {
    GPU: makeIllegalConstructor('GPU', mutablePrototypes.GPU),
    GPUAdapter: makeIllegalConstructor('GPUAdapter', mutablePrototypes.GPUAdapter),
    GPUBindGroupLayout: makeIllegalConstructor(
      'GPUBindGroupLayout',
      mutablePrototypes.GPUBindGroupLayout,
    ),
    GPUBuffer: makeIllegalConstructor('GPUBuffer', mutablePrototypes.GPUBuffer),
    GPUPipelineLayout: makeIllegalConstructor(
      'GPUPipelineLayout',
      mutablePrototypes.GPUPipelineLayout,
    ),
    GPUSampler: makeIllegalConstructor('GPUSampler', mutablePrototypes.GPUSampler),
    GPUCanvasContext: makeIllegalConstructor(
      'GPUCanvasContext',
      mutablePrototypes.GPUCanvasContext,
    ),
    GPUCommandBuffer: makeIllegalConstructor(
      'GPUCommandBuffer',
      mutablePrototypes.GPUCommandBuffer,
    ),
    GPUCommandEncoder: makeIllegalConstructor(
      'GPUCommandEncoder',
      mutablePrototypes.GPUCommandEncoder,
    ),
    GPUComputePipeline: makeIllegalConstructor(
      'GPUComputePipeline',
      mutablePrototypes.GPUComputePipeline,
    ),
    GPUComputePassEncoder: makeIllegalConstructor(
      'GPUComputePassEncoder',
      mutablePrototypes.GPUComputePassEncoder,
    ),
    GPUDevice: makeIllegalConstructor('GPUDevice', mutablePrototypes.GPUDevice),
    GPUDeviceLostInfo: makeIllegalConstructor(
      'GPUDeviceLostInfo',
      deviceLostInfoPrototype,
    ),
    GPUError: makeIllegalConstructor('GPUError', gpuErrorPrototype),
    GPUInternalError: gpuInternalErrorConstructor,
    GPUOutOfMemoryError: gpuOutOfMemoryErrorConstructor,
    GPUQuerySet: makeIllegalConstructor(
      'GPUQuerySet',
      mutablePrototypes.GPUQuerySet,
    ),
    GPUQueue: makeIllegalConstructor('GPUQueue', mutablePrototypes.GPUQueue),
    GPURenderPassEncoder: makeIllegalConstructor(
      'GPURenderPassEncoder',
      mutablePrototypes.GPURenderPassEncoder,
    ),
    GPURenderPipeline: makeIllegalConstructor(
      'GPURenderPipeline',
      mutablePrototypes.GPURenderPipeline,
    ),
    GPUShaderModule: makeIllegalConstructor(
      'GPUShaderModule',
      mutablePrototypes.GPUShaderModule,
    ),
    GPUSupportedFeatures: makeIllegalConstructor(
      'GPUSupportedFeatures',
      featurePrototype,
    ),
    GPUSupportedLimits: makeIllegalConstructor(
      'GPUSupportedLimits',
      supportedLimitsPrototype,
    ),
    GPUTexture: makeIllegalConstructor('GPUTexture', mutablePrototypes.GPUTexture),
    GPUTextureView: makeIllegalConstructor(
      'GPUTextureView',
      mutablePrototypes.GPUTextureView,
    ),
    GPUUncapturedErrorEvent: makeIllegalConstructor(
      'GPUUncapturedErrorEvent',
      gpuUncapturedErrorEventPrototype,
    ),
    GPUValidationError: gpuValidationErrorConstructor,
  };
  for (const key of Object.keys(interfaceObjects)) {
    Object.freeze(interfaceObjects[key]);
  }

  const constantObjects = Object.freeze({
    GPUBufferUsage: Object.freeze({
      MAP_READ: 1,
      MAP_WRITE: 2,
      COPY_SRC: 4,
      COPY_DST: 8,
      INDEX: 16,
      VERTEX: 32,
      UNIFORM: 64,
      STORAGE: 128,
      INDIRECT: 256,
      QUERY_RESOLVE: 512,
    }),
    GPUColorWrite: Object.freeze({ RED: 1, GREEN: 2, BLUE: 4, ALPHA: 8, ALL: 15 }),
    GPUMapMode: Object.freeze({ READ: 1, WRITE: 2 }),
    GPUShaderStage: Object.freeze({ VERTEX: 1, FRAGMENT: 2, COMPUTE: 4 }),
    GPUTextureUsage: Object.freeze({
      COPY_SRC: 1,
      COPY_DST: 2,
      TEXTURE_BINDING: 4,
      STORAGE_BINDING: 8,
      RENDER_ATTACHMENT: 16,
      TRANSIENT_ATTACHMENT: 32,
    }),
  });

  let revoked = false;
  return Object.freeze({
    gpu: gpuState.wrapper,
    interfaceObjects: Object.freeze(interfaceObjects),
    constantObjects,
    ...(privateImageBitmaps
      ? {
        createImageBitmap: privateImageBitmaps.createImageBitmap,
        snapshotImageBitmapForCopy: privateImageBitmaps.snapshotForCopy,
      }
      : {}),
    ...(capturedTestOptions.enableStateInspection
      ? {
        inspectForTest: () => Object.freeze({
          current: inspectCurrentState(),
          lastClose: realm.lastCloseSnapshot,
        }),
      }
      : {}),
    mintCanvasContext(identity: Readonly<{
      objectId: string;
      objectGeneration: string;
      drawingBufferWidth: number;
      drawingBufferHeight: number;
      authority: ProductionGpuCanvasContextAuthority;
    }>) {
      if (!realm.active) throw namedError('SecurityError', 'WebGPU realm is revoked');
      const captured = captureCanvasContextIdentity(identity);
      const {
        authority,
        drawingBufferWidth,
        drawingBufferHeight,
        objectGeneration,
        objectId,
      } = captured;
      const identityKey = hostCanvasContextIdentityKey(
        objectId,
        objectGeneration,
      );
      const existing = realm.hostCanvasContextsByIdentity.get(identityKey);
      if (existing) {
        const existingAuthority = existing.canvasAuthority;
        if (
          existing.canvasContextLifecycle === 'stale' ||
          existing.canvasContextLifecycle === 'revoked'
        ) {
          throw namedError('InvalidStateError', 'GPUCanvasContext identity is stale');
        }
        if (
          !existingAuthority ||
          existing.drawingBufferWidth !== drawingBufferWidth ||
          existing.drawingBufferHeight !== drawingBufferHeight ||
          !sameCanvasAuthority(existingAuthority, authority)
        ) {
          throw new TypeError(
            'GPUCanvasContext identity conflicts with existing host authority or extent',
          );
        }
        if (
          realm.currentHostCanvasContextByObject.get(
            hostCanvasContextObjectKey(objectId),
          ) !== existing ||
          realm.currentHostCanvasContextBySurfaceToken.get(
            authority.surfaceAccountToken,
          ) !== existing
        ) {
          closeRealmCounterIndependently(
            'canvas-index-split-brain',
            'The WebGPU realm closed after a canvas identity split-brain',
          );
          throw namedError(
            'OperationError',
            'GPUCanvasContext identity indexes are inconsistent',
          );
        }
        return existing.wrapper;
      }

      const objectKey = hostCanvasContextObjectKey(objectId);
      const objectPredecessor = realm.currentHostCanvasContextByObject.get(objectKey);
      const tokenPredecessor = realm.currentHostCanvasContextBySurfaceToken.get(
        authority.surfaceAccountToken,
      );
      if (
        objectPredecessor !== undefined &&
        tokenPredecessor !== undefined &&
        objectPredecessor !== tokenPredecessor
      ) {
        closeRealmCounterIndependently(
          'canvas-index-split-brain',
          'The WebGPU realm closed after a canvas identity split-brain',
        );
        throw namedError(
          'OperationError',
          'GPUCanvasContext identity indexes are inconsistent',
        );
      }
      const predecessor = objectPredecessor ?? tokenPredecessor;
      if (
        objectPredecessor &&
        compareCanonicalU64Decimal(
          objectGeneration,
          objectPredecessor.objectGeneration,
        ) <= 0
      ) {
        throw namedError('InvalidStateError', 'GPUCanvasContext identity is stale');
      }
      if (predecessor) {
        const predecessorAuthority = predecessor.canvasAuthority;
        if (!predecessorAuthority) {
          closeRealmCounterIndependently(
            'canvas-index-missing-authority',
            'The WebGPU realm closed after a canvas authority inconsistency',
          );
          throw namedError(
            'OperationError',
            'GPUCanvasContext identity indexes are inconsistent',
          );
        }
        const predecessorIdentityKey = hostCanvasContextIdentityKey(
          predecessor.objectId,
          predecessor.objectGeneration,
        );
        if (
          realm.hostCanvasContextsByIdentity.get(predecessorIdentityKey) !==
            predecessor ||
          realm.currentHostCanvasContextByObject.get(
            hostCanvasContextObjectKey(predecessor.objectId),
          ) !== predecessor ||
          realm.currentHostCanvasContextBySurfaceToken.get(
            predecessorAuthority.surfaceAccountToken,
          ) !== predecessor
        ) {
          closeRealmCounterIndependently(
            'canvas-index-split-brain',
            'The WebGPU realm closed after a canvas identity split-brain',
          );
          throw namedError(
            'OperationError',
            'GPUCanvasContext identity indexes are inconsistent',
          );
        }
        if (
          predecessorAuthority.surfaceAccountToken !==
            authority.surfaceAccountToken
        ) {
          throw new TypeError(
            'GPUCanvasContext object identity conflicts with another surface account',
          );
        }
        if (sameCanvasAuthority(predecessorAuthority, authority)) {
          throw new TypeError(
            'GPUCanvasContext authority aliases an existing live identity',
          );
        }
        if (!isStrictCanvasLineageSuccessor(predecessorAuthority, authority)) {
          throw namedError(
            'InvalidStateError',
            'GPUCanvasContext authority lineage is stale or conflicting',
          );
        }
      }
      const capturedObjectIdentity = Object.freeze({
        objectId,
        objectGeneration,
      });
      const context = allocateWrapper(
        'GPUCanvasContext',
        undefined,
        capturedObjectIdentity,
      );
      context.canvasAuthority = authority;
      context.canvasContextLifecycle = 'attached-unconfigured';
      context.drawingBufferWidth = drawingBufferWidth;
      context.drawingBufferHeight = drawingBufferHeight;
      if (predecessor) retireCanvasContext(predecessor, 'stale');
      realm.hostCanvasContextsByIdentity.set(identityKey, context);
      realm.currentHostCanvasContextByObject.set(objectKey, context);
      realm.currentHostCanvasContextBySurfaceToken.set(
        authority.surfaceAccountToken,
        context,
      );
      return context.wrapper;
    },
    checkpointHostTask,
    revoke() {
      if (revoked) return;
      let expiryFailure: unknown;
      try {
        if (realm.active && realm.closeReason === undefined) {
          checkpointHostTask();
        }
      } catch (error) {
        expiryFailure = error;
      } finally {
        revoked = true;
        privateImageBitmaps?.revoke();
        closeRealmCounterIndependently(
          'realm-revoked',
          'The WebGPU realm was revoked',
        );
      }
      if (expiryFailure !== undefined) throw expiryFailure;
    },
  });
}

const PUBLIC_INTERFACE_NAMES = Object.freeze([
  'GPU',
  'GPUAdapter',
  'GPUBindGroupLayout',
  'GPUBuffer',
  'GPUPipelineLayout',
  'GPUSampler',
  'GPUCanvasContext',
  'GPUCommandBuffer',
  'GPUCommandEncoder',
  'GPUComputePipeline',
  'GPUComputePassEncoder',
  'GPUDevice',
  'GPUDeviceLostInfo',
  'GPUError',
  'GPUInternalError',
  'GPUOutOfMemoryError',
  'GPUQuerySet',
  'GPUQueue',
  'GPURenderPassEncoder',
  'GPURenderPipeline',
  'GPUShaderModule',
  'GPUSupportedFeatures',
  'GPUSupportedLimits',
  'GPUTexture',
  'GPUTextureView',
  'GPUUncapturedErrorEvent',
  'GPUValidationError',
]);
const PUBLIC_CONSTANT_NAMES = Object.freeze([
  'GPUBufferUsage',
  'GPUColorWrite',
  'GPUMapMode',
  'GPUShaderStage',
  'GPUTextureUsage',
]);
const PUBLIC_FUNCTION_NAMES = Object.freeze(['createImageBitmap']);

export function installProductionWebGpu(
  globalObject: typeof globalThis,
  bridge: NativeGpuBridge | undefined,
  codecs: ExecutableWebGpuCodecBundle | undefined =
    EMBEDDED_EXECUTABLE_WEBGPU_CODECS,
  realmKind: 'app' | 'worker' | 'agent' | 'worklet' = 'app',
): ProductionWebGpuInstallResult {
  if (!bridge) return Object.freeze({ status: 'not-installed', reason: 'provider-absent' });
  if (!('abiVersion' in bridge) || bridge.abiVersion !== 0x0002_0000) {
    return Object.freeze({ status: 'not-installed', reason: 'abi-v2-required' });
  }
  if (realmKind !== 'app') {
    return Object.freeze({ status: 'not-installed', reason: 'not-app-realm' });
  }
  if (!validateExecutableWebGpuCodecs(codecs)) {
    return Object.freeze({
      status: 'not-installed',
      reason: 'executable-codecs-unavailable',
    });
  }
  const navigatorValue = (globalObject as unknown as Record<string, unknown>).navigator;
  if (typeof navigatorValue !== 'object' || navigatorValue === null) {
    return Object.freeze({ status: 'not-installed', reason: 'navigator-unavailable' });
  }
  if (
    'gpu' in navigatorValue ||
    [
      ...PUBLIC_INTERFACE_NAMES,
      ...PUBLIC_CONSTANT_NAMES,
      ...PUBLIC_FUNCTION_NAMES,
    ].some(
      (name) => name in globalObject,
    )
  ) {
    return Object.freeze({ status: 'not-installed', reason: 'public-surface-conflict' });
  }

  const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
  const installed: Array<Readonly<{ target: object; name: string; value: object }>> = [];
  const installValue = (target: object, name: string, value: object): void => {
    Object.defineProperty(target, name, {
      value,
      writable: false,
      enumerable: true,
      configurable: true,
    });
    installed.push(Object.freeze({ target, name, value }));
  };

  try {
    installValue(navigatorValue, 'gpu', binding.gpu);
    if (binding.createImageBitmap) {
      installValue(globalObject, 'createImageBitmap', binding.createImageBitmap);
    }
    for (const name of PUBLIC_INTERFACE_NAMES) {
      installValue(globalObject, name, binding.interfaceObjects[name]);
    }
    for (const name of PUBLIC_CONSTANT_NAMES) {
      installValue(globalObject, name, binding.constantObjects[name]);
    }
    if (binding.createImageBitmap !== undefined) {
      installValue(globalObject, 'createImageBitmap', binding.createImageBitmap);
    }
  } catch (error) {
    for (let index = installed.length - 1; index >= 0; index -= 1) {
      const entry = installed[index];
      const descriptor = Object.getOwnPropertyDescriptor(entry.target, entry.name);
      if (descriptor?.value === entry.value) Reflect.deleteProperty(entry.target, entry.name);
    }
    binding.revoke();
    throw error;
  }

  let revoked = false;
  const canvasContextMinter = Object.freeze({
    mintCanvasContext(
      identity: Parameters<ProductionWebGpuPrivateBinding['mintCanvasContext']>[0],
    ): object {
      return binding.mintCanvasContext(identity);
    },
  });
  return Object.freeze({
    status: 'installed',
    canvasContextMinter,
    checkpointHostTask: binding.checkpointHostTask,
    revoke() {
      if (revoked) return;
      revoked = true;
      for (let index = installed.length - 1; index >= 0; index -= 1) {
        const entry = installed[index];
        const descriptor = Object.getOwnPropertyDescriptor(entry.target, entry.name);
        if (descriptor?.value === entry.value) Reflect.deleteProperty(entry.target, entry.name);
      }
      binding.revoke();
    },
  });
}
