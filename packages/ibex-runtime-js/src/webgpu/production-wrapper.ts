// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Cross-repo design authority: Exact LLP 0367, sections 3.5 and 9.1.

import type {
  NativeGpuBridge,
  NativeGpuBridgeV2,
  NativeGpuCallMetadataV2,
  NativeGpuEventV2,
} from './native-bridge';
import {
  EMBEDDED_EXECUTABLE_WEBGPU_CODECS,
  type ExecutableWebGpuCodecBundle,
  type ProductionGpuDecodedResult,
  type ProductionGpuFullObjectReference,
  type ProductionGpuObjectIdentity,
  type ProductionGpuTextureOriginDigestInput,
  type ProductionGpuWrapperKind,
  validateExecutableWebGpuCodecs,
} from './production-codecs';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';
import { WEBGPU_OBJECT_KIND_TAGS } from './production-codecs.generated';

type ProductionRoute = (typeof WEBGPU_PRODUCTION_PLAN.routes)[number];

type ServiceSubmissionFailureKind =
  | 'bridge-threw'
  | 'submission-rejected';

const ROUTES = new Map<string, ProductionRoute>(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.operationId, route]),
);
const ROUTES_BY_WIRE = new Map<number, ProductionRoute>(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.wireId, route]),
);

const OBJECT_KINDS: Readonly<Record<ProductionGpuWrapperKind, number>> =
  WEBGPU_OBJECT_KIND_TAGS;

// Capture trusted realm intrinsics before app code can replace the writable
// global binding. Structural lockdown freezes the intrinsic object, but it
// does not make globalThis.ArrayBuffer immutable.
const INTRINSIC_ARRAY_BUFFER = ArrayBuffer;
const INTRINSIC_ARRAY_BUFFER_IS_VIEW = INTRINSIC_ARRAY_BUFFER.isView;
const INTRINSIC_UINT8_ARRAY = Uint8Array;
const INTRINSIC_REFLECT_APPLY = Reflect.apply;
const INTRINSIC_REFLECT_CONSTRUCT = Reflect.construct;

// This is a construction-private memory-safety guard, deliberately no larger
// than the authenticated structural per-descriptor ceiling. It is not the
// leaf-plus-envelope reservation required to publish mapped buffers. Until the
// bridge can transfer an affine preallocation credit into the service ledger,
// the production codec authority remains absent and this guard is monotonic.
const PRIVATE_MAPPED_ALLOCATION_GUARD_MAX_BYTES = 268_435_456;

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
  queue: object | undefined;
  destroyed: boolean;
  nextIngress: string;
  ingressExhausted: boolean;
  nextQueueIngress: string;
  queueIngressExhausted: boolean;
  nextScope: string;
  scopeExhausted: boolean;
  scopes: Array<Readonly<{ id: string; filter: string }>>;
  pendingLocalTimeline: unknown[];
  readonly configuredCanvasContexts: Set<WrapperState>;
}

type CanvasContextLifecycle =
  | 'attached-unconfigured'
  | 'configured'
  | 'lost'
  | 'stale'
  | 'revoked';

interface WrapperState {
  readonly realm: RealmState;
  readonly kind: ProductionGpuWrapperKind;
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
  materialized: boolean;
  currentOrigin: Readonly<Record<string, unknown>> | undefined;
  bufferSize: number | undefined;
  bufferUsage: number | undefined;
  bufferMapState: 'mapped' | 'pending' | 'unmapped' | undefined;
  bufferMappedBytes: ArrayBuffer | undefined;
  textureDimension: '1d' | '2d' | '3d' | undefined;
  textureFormat: string | undefined;
  textureWidth: number | undefined;
  textureHeight: number | undefined;
  drawingBufferWidth: number | undefined;
  drawingBufferHeight: number | undefined;
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
}

interface RealmState {
  readonly bridge: NativeGpuBridgeV2;
  readonly codecs: ExecutableWebGpuCodecBundle;
  readonly prototypes: Readonly<Record<ProductionGpuWrapperKind, object>>;
  readonly wrappers: WeakMap<object, WrapperState>;
  readonly devices: Map<string, DeviceState>;
  readonly hostCanvasContextsByIdentity: Map<string, WrapperState>;
  readonly currentHostCanvasContextByObject: Map<string, WrapperState>;
  readonly currentHostCanvasContextBySurfaceToken: Map<string, WrapperState>;
  readonly pendingPromiseCalls: Map<string, PendingPromiseCall>;
  readonly resultEvents: Map<
    string,
    Extract<NativeGpuEventV2, { kind: 1 }>
  >;
  nextLocalObjectId: string;
  localObjectIdExhausted: boolean;
  nextLocalOperationInstanceId: string;
  localOperationInstanceIdExhausted: boolean;
  allocatedWrapperCount: number;
  readonly privateMappedAllocationGuardLimitBytes: number;
  privateMappedAllocationGuardBytes: number;
  canvasLossTransitionCount: number;
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
  }>;
  readonly privateMappedAllocationGuardLimitBytes?: number;
  readonly enableStateInspection?: boolean;
}

export interface ProductionWebGpuPrivateBinding {
  readonly gpu: object;
  readonly interfaceObjects: Readonly<Record<string, object>>;
  readonly constantObjects: Readonly<Record<string, object>>;
  readonly mintCanvasContext: (
    identity: Readonly<{
      objectId: string;
      objectGeneration: string;
      drawingBufferWidth: number;
      drawingBufferHeight: number;
      authority: ProductionGpuCanvasContextAuthority;
    }>,
  ) => object;
  readonly revoke: () => void;
  readonly inspectForTest?: () => Readonly<{
    current: ProductionWebGpuPrivateBindingInspection;
    lastClose: ProductionWebGpuPrivateBindingInspection | undefined;
  }>;
}

const TYPEGPU_WORKLOAD_STAGING = Object.freeze({
  scopeId: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.scopeId,
  status: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.status,
  supportClaim: WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.supportClaim,
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
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.additionalOperations.map(
      (operation) => Object.freeze({ ...operation }),
    ),
  ),
  blockers: Object.freeze([
    ...WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.blockers,
  ]),
  publicSurfaceRule:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.publicSurfaceRule,
  embeddedCodecRule:
    WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure.embeddedCodecRule,
});

/**
 * Construction-private planning evidence for the pinned TypeGPU workloads.
 * Additional members are intentionally descriptive only: they have no route,
 * codec, prototype entry, or install path until every listed blocker closes.
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

function createPrototypeTable(): Record<ProductionGpuWrapperKind, object> {
  return {
    GPU: Object.create(null),
    GPUAdapter: Object.create(null),
    GPUBindGroupLayout: Object.create(null),
    GPUBuffer: Object.create(null),
    GPUPipelineLayout: Object.create(null),
    GPUSampler: Object.create(null),
    GPUCanvasContext: Object.create(null),
    GPUCommandBuffer: Object.create(null),
    GPUCommandEncoder: Object.create(null),
    GPUDevice: Object.create(null),
    GPUQueue: Object.create(null),
    GPURenderPassEncoder: Object.create(null),
    GPURenderPipeline: Object.create(null),
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
  for (const key of Object.keys(value)) clone[key] = value[key];
  return clone;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
    throw new TypeError(`${label} must be a dictionary`);
  }
  return value as Record<string, unknown>;
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
      )
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
): ProductionWebGpuPrivateBinding {
  if (!validateExecutableWebGpuCodecs(codecs)) {
    throw new TypeError('WebGPU executable codec authority is invalid');
  }
  const capturedTestOptions = capturePrivateBindingTestOptions(testOptions);

  const mutablePrototypes = createPrototypeTable();
  const featurePrototype = Object.create(null) as object;
  const featureStates = new WeakMap<object, readonly string[]>();
  installReadonlyFeatureSetPrototype(featurePrototype, featureStates);
  const supportedLimitsPrototype = Object.freeze(Object.create(null) as object);
  const deviceLostInfoPrototype = Object.freeze(Object.create(null) as object);
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
    hostCanvasContextsByIdentity: new Map(),
    currentHostCanvasContextByObject: new Map(),
    currentHostCanvasContextBySurfaceToken: new Map(),
    pendingPromiseCalls: new Map(),
    resultEvents: new Map(),
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
    realm.hostCanvasContextsByIdentity.clear();
    realm.currentHostCanvasContextByObject.clear();
    realm.currentHostCanvasContextBySurfaceToken.clear();
    realm.devices.clear();
    realm.pendingPromiseCalls.clear();
    realm.resultEvents.clear();
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

  const allocateWrapper = (
    kind: ProductionGpuWrapperKind,
    device: DeviceState | undefined,
    identity?: Readonly<{ objectId: string; objectGeneration: string }>,
  ): WrapperState => {
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
    const wrapper = Object.create(realm.prototypes[kind]) as object;
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
      materialized: false,
      currentOrigin: undefined,
      bufferSize: undefined,
      bufferUsage: undefined,
      bufferMapState: undefined,
      bufferMappedBytes: undefined,
      textureDimension: undefined,
      textureFormat: undefined,
      textureWidth: undefined,
      textureHeight: undefined,
      drawingBufferWidth: undefined,
      drawingBufferHeight: undefined,
    };
    if (localObjectPlan !== undefined) {
      realm.nextLocalObjectId = localObjectPlan.next;
      realm.localObjectIdExhausted = localObjectPlan.exhaustedAfter;
    }
    realm.wrappers.set(wrapper, state);
    realm.allocatedWrapperCount += 1;
    return state;
  };

  const convert = (operationId: string, args: readonly unknown[]): unknown => {
    route(operationId);
    return codecs.convertPublicArguments(operationId, args, { reference });
  };

  const expireCurrentTexture = (context: WrapperState): void => {
    if (!context.currentTexture) return;
    const texture = requireState(context.currentTexture, 'GPUTexture');
    texture.textureExpired = true;
    context.currentTexture = undefined;
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
    readonly selected: ProductionRoute;
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
    const selected = route(operationId);
    if (selected.providerSubmission !== 'none') {
      throw new Error(`${operationId} is not wrapper-local`);
    }
    if (
      selected.operationInstanceIdentity !==
        'wrapper-allocated-nonzero-carried-in-sealed-local-timeline-record'
    ) {
      throw new Error(`${operationId} has no sealed local operation identity`);
    }
    const device = receiver.device ?? targetDevice;
    if (!device) throw new Error(`${operationId} lacks a logical device`);
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
      selected,
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
  }> => {
    const {
      selected,
      device,
      operationInstanceId,
      nextOperationInstanceId,
      operationInstanceIdExhaustedAfter,
      deviceIngressOrdinal,
      nextDeviceIngress,
      deviceIngressExhaustedAfter,
      capturedScopeId,
    } = plan;
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
    device.pendingLocalTimeline.push(
      Object.freeze({
        operationId: selected.wireId,
        operationName: selected.operationId,
        operationInstanceId,
        deviceIngressOrdinal,
        capturedScopeId,
        receiverRef: referenceWithDevice(receiver, device),
        wrapperAllocatedTargetRef: target
          ? referenceWithDevice(target, device)
          : null,
        argumentBody: convertedArguments,
        logicalError: error
          ? Object.freeze({ name: error.name, message: error.message })
          : null,
      }),
    );
    return Object.freeze({ operationInstanceId, deviceIngressOrdinal });
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
  }> => commitLocalRecord(
    prepareLocalRecord(operationId, receiver, target?.device),
    receiver,
    target,
    convertedArguments,
    error,
  );

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
    const queuePlan = operationId === 'GPUQueue.submit' && device
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
    const sealedLocalTimeline = device?.pendingLocalTimeline.slice() ?? [];
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
    const payload = codecs.encodeServiceRequest({
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
    });
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
    try {
      carrier = bridge.submit(selected.wireId, wantsPromise, metadata, payload);
    } catch (error) {
      onNativeSubmitFailure?.('bridge-threw');
      throw error;
    }
    if (carrier.submissionStatus !== 0) {
      carrier.receipt?.catch(() => undefined);
      onNativeSubmitFailure?.('submission-rejected');
      throw namedError(
        'OperationError',
        `WebGPU semantic service rejected ${operationId} (${carrier.submissionStatus})`,
      );
    }
    if (!realm.active || realm.closeReason !== undefined) {
      carrier.receipt?.catch(() => undefined);
      throw namedError(
        'SecurityError',
        `WebGPU realm closed during ${operationId}`,
      );
    }
    if (device) device.pendingLocalTimeline.splice(0, sealedLocalTimeline.length);
    if (!wantsPromise) return undefined;
    if (!carrier.receipt || carrier.promiseId === '0') {
      throw new Error(`${operationId} did not return its required receipt`);
    }
    realm.pendingPromiseCalls.set(carrier.operationInstanceId, { route: selected });
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

  const materializeObject = (
    decoded: ProductionGpuDecodedResult,
    expectedKind: ProductionGpuWrapperKind,
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
        queue: undefined,
        destroyed: false,
        nextIngress: counterSeed('nextDeviceIngressOrdinal', '1', true),
        ingressExhausted: false,
        nextQueueIngress: counterSeed('nextQueueIngressOrdinal', '1', true),
        queueIngressExhausted: false,
        nextScope: counterSeed('nextScopeId', '1', true),
        scopeExhausted: false,
        scopes: [],
        pendingLocalTimeline: [],
        configuredCanvasContexts: new Set(),
      };
      const state = allocateWrapper('GPUDevice', device, identity);
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
    expectedKind: ProductionGpuWrapperKind,
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
    for (const device of [...realm.devices.values()]) {
      settleDeviceLost(device, decoded.reason, decoded.message);
    }
    if (event.kind === 6) retireRealmState();
  };

  bridge.setEventSink((event) => {
    if (!realm.active && event.kind !== 6) return;
    if (event.kind === 1) {
      const selected = ROUTES_BY_WIRE.get(event.operationId);
      if (!selected) {
        realm.active = false;
        return;
      }
      const pending = realm.pendingPromiseCalls.get(event.operationInstanceId);
      if (event.promiseId !== '0' && pending && pending.route !== selected) {
        realm.active = false;
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
    // Kind 2 settles the native receipt. Wrapper-local error-scope routing is
    // represented in the sealed timeline and decided by the semantic service;
    // it is not reconstructed from an untrusted backend diagnostic here.
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
    if (
      !deviceState.device ||
      deviceState.device.destroyed ||
      deviceState.device.lost.settled
    ) {
      throw namedError('InvalidStateError', 'GPUDevice is unavailable');
    }
    const configuredDevice = deviceState.device;
    const nextConfigurationGeneration = advanceCounterOrClose(
      context.configurationGeneration,
      'canvas configuration generation',
    );
    const servicePlan = prepareServiceCounters(
      'GPUCanvasContext.configure',
      context,
      configuredDevice,
    );
    const copiedConfiguration = cloneConfiguration(converted);
    const previousConfiguration = context.configuration;
    const previousConfigurationGeneration = context.configurationGeneration;
    const previousConfiguredDevice = context.configuredDevice;
    const previousConfiguredDeviceWrapper = context.configuredDeviceWrapper;
    const previousCanvasContextLifecycle = context.canvasContextLifecycle;
    const previousDeviceMembership = previousConfiguredDevice
      ?.configuredCanvasContexts.has(context) ?? false;
    let provisionalConfigurationInstalled = false;
    let submissionFailure: ServiceSubmissionFailureKind | undefined;
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
          () => {
            if (
              !realm.active ||
              configuredDevice.destroyed ||
              configuredDevice.lost.settled
            ) {
              throw namedError('InvalidStateError', 'GPUDevice is unavailable');
            }
            // LLP 0368 §2.2 installs the copied configuration before later
            // device-timeline validation. A loss delivered reentrantly by the
            // bridge must therefore observe and terminalize this generation.
            unlinkConfiguredCanvasContext(context);
            expireCurrentTexture(context);
            context.configurationGeneration = nextConfigurationGeneration;
            context.configuration = copiedConfiguration;
            context.configuredDevice = configuredDevice;
            context.configuredDeviceWrapper = deviceWrapper as object;
            context.canvasContextLifecycle = 'configured';
            configuredDevice.configuredCanvasContexts.add(context);
            provisionalConfigurationInstalled = true;
          },
          (failure) => {
            submissionFailure = failure;
          },
        );
      } catch (error) {
        if (
          provisionalConfigurationInstalled &&
          submissionFailure !== undefined &&
          realm.active
        ) {
          // A synchronous LLP 0368 §2.4 loss is already terminal and must
          // dominate either provider return. Otherwise an explicit rejection
          // proves non-admission and may roll back only the provisional
          // publication; ingress remains consumed and an expired old texture
          // never revives. A thrown bridge call has ambiguous admission, so
          // it closes the realm instead of guessing.
          const lossWon =
            configuredDevice.lost.settled &&
            context.canvasContextLifecycle === 'lost' &&
            context.configuredDevice === configuredDevice &&
            !configuredDevice.configuredCanvasContexts.has(context);
          if (!lossWon) {
            const provisionalStateIsIntact =
              !configuredDevice.destroyed &&
              !configuredDevice.lost.settled &&
              context.canvasContextLifecycle === 'configured' &&
              context.configurationGeneration === nextConfigurationGeneration &&
              context.configuration === copiedConfiguration &&
              context.configuredDevice === configuredDevice &&
              context.configuredDeviceWrapper === deviceWrapper &&
              context.currentTexture === undefined &&
              configuredDevice.configuredCanvasContexts.has(context);
            const previousStateCanBeRestored =
              !previousDeviceMembership ||
              (previousConfiguredDevice !== undefined &&
                !previousConfiguredDevice.destroyed &&
                !previousConfiguredDevice.lost.settled);
            if (
              submissionFailure === 'submission-rejected' &&
              provisionalStateIsIntact &&
              previousStateCanBeRestored
            ) {
              configuredDevice.configuredCanvasContexts.delete(context);
              context.configurationGeneration = previousConfigurationGeneration;
              context.configuration = previousConfiguration;
              context.configuredDevice = previousConfiguredDevice;
              context.configuredDeviceWrapper = previousConfiguredDeviceWrapper;
              context.canvasContextLifecycle = previousCanvasContextLifecycle;
              if (previousDeviceMembership && previousConfiguredDevice) {
                previousConfiguredDevice.configuredCanvasContexts.add(context);
              }
            } else {
              closeRealmCounterIndependently(
                submissionFailure === 'bridge-threw'
                  ? 'canvas-configure-submit-threw'
                  : 'canvas-configure-rejection-race',
                submissionFailure === 'bridge-threw'
                  ? 'The WebGPU realm closed because canvas configure submission threw'
                  : 'The WebGPU realm closed after a canvas configure rejection race',
              );
            }
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
      const converted = convert('GPUCanvasContext.getCurrentTexture', []);
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
        recordLocal(
          'GPUCanvasContext.getCurrentTexture',
          context,
          current,
          converted,
          undefined,
        );
        return context.currentTexture;
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
      const localRecordPlan = prepareLocalRecord(
        'GPUCanvasContext.getCurrentTexture',
        context,
        context.configuredDevice,
      );
      const texture = allocateWrapper(
        'GPUTexture',
        context.configuredDevice,
      );
      texture.textureDimension = '2d';
      texture.textureFormat = configuredFormat;
      texture.textureWidth = context.drawingBufferWidth;
      texture.textureHeight = context.drawingBufferHeight;
      if (context.canvasContextLifecycle === 'lost') {
        texture.invalid = true;
        texture.status = 'invalid-device';
      }
      const mintOperationProvenance = commitLocalRecord(
        localRecordPlan,
        context,
        texture,
        converted,
        undefined,
      );
      const authority = context.canvasAuthority;
      const receiverTextureRef = reference(texture.wrapper, 'GPUTexture');
      const contextRef = referenceWithDevice(context, context.configuredDevice);
      const configuredDeviceRef = reference(
        context.configuredDeviceWrapper,
        'GPUDevice',
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
        configuredDeviceRef,
        format: configuredFormat,
        usage: configuredUsage,
        alphaMode: configuredAlphaMode,
        colorSpace: configuredColorSpace,
        targetAuthorityDigest: authority.targetAuthorityDigest,
        surfaceAccountToken: authority.surfaceAccountToken,
        surfaceAccountGeneration: authority.surfaceAccountGeneration,
      });
      const textureOriginDigest = codecs.deriveTextureOriginDigest(digestInput);
      context.currentEpoch = nextCurrentEpoch;
      texture.currentOrigin = Object.freeze({
        originClass: digestInput.originClass,
        contextRef: digestInput.contextRef,
        attachmentGeneration: digestInput.attachmentGeneration,
        contextGeneration: digestInput.contextGeneration,
        configurationGeneration: digestInput.configurationGeneration,
        currentEpoch: digestInput.currentEpoch,
        mintOperationProvenance: digestInput.mintOperationProvenance,
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
      context.currentTexture = texture.wrapper;
      return texture.wrapper;
    },
  );

  defineMethod(mutablePrototypes.GPUCanvasContext, 'unconfigure', function (
    this: object,
  ) {
    const context = requireState(this, 'GPUCanvasContext');
    assertCanvasContextUsable(context);
    const converted = convert('GPUCanvasContext.unconfigure', []);
    if (context.canvasContextLifecycle === 'attached-unconfigured') return;
    const nextConfigurationGeneration = advanceCounterOrClose(
      context.configurationGeneration,
      'canvas configuration generation',
    );
    const servicePlan = prepareServiceCounters(
      'GPUCanvasContext.unconfigure',
      context,
      context.configuredDevice,
    );
    context.device = context.configuredDevice;
    try {
      submitService(
        'GPUCanvasContext.unconfigure',
        context,
        undefined,
        converted,
        false,
        servicePlan,
      );
    } finally {
      context.device = undefined;
    }
    unlinkConfiguredCanvasContext(context);
    expireCurrentTexture(context);
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
    let mappedBytes: ArrayBuffer | undefined;
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
          INTRINSIC_ARRAY_BUFFER,
          [converted.size],
        ) as ArrayBuffer;
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
    buffer.bufferMappedBytes = mappedBytes;
    submitService(
      'GPUDevice.createBuffer',
      state,
      buffer,
      converted,
      false,
      servicePlan,
    );
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
      size: Readonly<{ width: number; height: number }>;
      viewFormats: readonly string[];
    }>;
    const requiredFeatures =
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
    texture.textureWidth = converted.size.width;
    texture.textureHeight = converted.size.height;
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
    const converted = convert('GPUDevice.pushErrorScope', [filter]);
    const device = state.device!;
    const scopePlan = consumeNextCounterOrClose(
      device.nextScope,
      device.scopeExhausted,
      'error scope identity',
    );
    const scopeId = scopePlan.value;
    const servicePlan = prepareServiceCounters(
      'GPUDevice.pushErrorScope',
      state,
      device,
    );
    submitService(
      'GPUDevice.pushErrorScope',
      state,
      undefined,
      Object.freeze({ converted, scopeId }),
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
    );
    if (!device.lost.settled) {
      device.scopes.push(
        Object.freeze({ id: scopeId, filter: String(converted) }),
      );
    }
  });

  defineMethod(mutablePrototypes.GPUDevice, 'popErrorScope', function (
    this: object,
  ) {
    const state = requireState(this, 'GPUDevice');
    return Promise.resolve().then(() => {
      const converted = convert('GPUDevice.popErrorScope', []);
      const device = state.device!;
      const scope = device.lost.settled || device.scopes.length === 0
        ? undefined
        : device.scopes[device.scopes.length - 1];
      const receipt = submitService(
        'GPUDevice.popErrorScope',
        state,
        undefined,
        Object.freeze({
          converted,
          scopeId: scope?.id ?? '0',
          deviceLost: device.lost.settled,
        }),
        true,
      ) as Promise<ProductionGpuDecodedResult>;
      if (!device.lost.settled && scope) device.scopes.pop();
      return receipt.then((decoded) => {
        if (device.lost.settled) return null;
        if (!scope) {
          throw namedError('OperationError', 'The error scope stack is empty');
        }
        return decoded.kind === 'value' ? decoded.value : null;
      });
    });
  });

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'beginRenderPass', function (
    this: object,
    descriptor: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const converted = convert('GPUCommandEncoder.beginRenderPass', [descriptor]);
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
    const error = canOpen
      ? undefined
      : namedError('GPUValidationError', 'Command encoder cannot begin a pass');
    if (canOpen) encoder.activePass = pass;
    else encoder.invalid = true;
    encoder.records.push(
      Object.freeze({ operation: 'beginRenderPass', arguments: converted }),
    );
    commitLocalRecord(
      localRecordPlan,
      encoder,
      pass,
      converted,
      error,
    );
    return pass.wrapper;
  });

  defineMethod(mutablePrototypes.GPUCommandEncoder, 'finish', function (
    this: object,
    descriptor?: unknown,
  ) {
    const encoder = requireState(this, 'GPUCommandEncoder');
    const converted = convert('GPUCommandEncoder.finish', [descriptor]);
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
    encoder.records.push(
      Object.freeze({ operation: 'finish', arguments: converted }),
    );
    const commandBuffer = allocateWrapper('GPUCommandBuffer', encoder.device);
    commandBuffer.invalid = invalid;
    commandBuffer.records = encoder.records.slice();
    commitLocalRecord(
      localRecordPlan,
      encoder,
      commandBuffer,
      converted,
      error,
    );
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
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.draw',
      pass,
      pass.device,
    );
    const invalid = pass.status !== 'open' || pass.invalid;
    const error = invalid
      ? namedError('GPUValidationError', 'Render pass has ended')
      : undefined;
    pass.records.push(Object.freeze({ operation: 'draw', arguments: converted }));
    pass.encoder?.records.push(
      Object.freeze({ operation: 'draw', arguments: converted }),
    );
    if (invalid) {
      pass.invalid = true;
      if (pass.encoder) pass.encoder.invalid = true;
    }
    commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'setPipeline', function (
    this: object,
    pipelineValue: unknown,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const converted = convert('GPURenderPassEncoder.setPipeline', [pipelineValue]);
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
    pass.records.push(
      Object.freeze({ operation: 'setPipeline', pipeline: reference(pipelineValue) }),
    );
    pass.encoder?.records.push(
      Object.freeze({ operation: 'setPipeline', pipeline: reference(pipelineValue) }),
    );
    if (invalid) {
      pass.invalid = true;
      if (pass.encoder) pass.encoder.invalid = true;
    }
    commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
  });

  defineMethod(mutablePrototypes.GPURenderPassEncoder, 'end', function (
    this: object,
  ) {
    const pass = requireState(this, 'GPURenderPassEncoder');
    const converted = convert('GPURenderPassEncoder.end', []);
    const localRecordPlan = prepareLocalRecord(
      'GPURenderPassEncoder.end',
      pass,
      pass.device,
    );
    const invalid = pass.status !== 'open';
    const error = invalid
      ? namedError('GPUValidationError', 'Render pass already ended')
      : undefined;
    pass.status = 'ended';
    if (pass.encoder?.activePass === pass) pass.encoder.activePass = undefined;
    pass.records.push(Object.freeze({ operation: 'end' }));
    pass.encoder?.records.push(Object.freeze({ operation: 'end' }));
    if (invalid) {
      pass.invalid = true;
      if (pass.encoder) pass.encoder.invalid = true;
    }
    commitLocalRecord(
      localRecordPlan,
      pass,
      undefined,
      converted,
      error,
    );
  });

  defineMethod(mutablePrototypes.GPUQueue, 'submit', function (
    this: object,
    commandBuffers: unknown,
  ) {
    const queue = requireState(this, 'GPUQueue');
    const converted = convert('GPUQueue.submit', [commandBuffers]);
    if (!Array.isArray(converted)) {
      throw new TypeError('GPUQueue.submit conversion must produce a sequence');
    }
    const sealedPrograms: unknown[] = [];
    const states: WrapperState[] = [];
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
      sealedPrograms.push(
        Object.freeze({
          commandBuffer: reference(value, 'GPUCommandBuffer'),
          invalid: buffer.invalid,
          records: buffer.invalid ? [] : buffer.records.slice(),
        }),
      );
    }
    submitService(
      'GPUQueue.submit',
      queue,
      undefined,
      Object.freeze({
        commandBuffers: sealedPrograms,
        wrapperValidationError,
      }),
      false,
    );
    if (!wrapperValidationError) {
      for (const state of states) state.submitted = true;
    }
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
    submitService(
      'GPUTexture.destroy',
      texture,
      undefined,
      Object.freeze({
        converted,
        currentOrigin: texture.currentOrigin,
        materialized: texture.materialized,
        alreadyDestroyed: texture.destroyed,
        expired: texture.textureExpired,
      }),
      false,
    );
    texture.destroyed = true;
  });

  // These are exact wrapper-local metadata reads. They deliberately do not
  // enter the service and remain private while the CapSec publication edge is
  // absent.
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
  defineGetter(mutablePrototypes.GPUTexture, 'width', function (this: object) {
    const texture = requireState(this, 'GPUTexture');
    if (texture.textureWidth === undefined) {
      throw new TypeError('GPUTexture width metadata is unavailable');
    }
    return texture.textureWidth;
  });

  for (const prototype of Object.values(mutablePrototypes)) Object.freeze(prototype);

  const gpuErrorPrototype = Object.freeze(
    Object.assign(Object.create(null) as object, { name: 'GPUError' }),
  );
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
    GPUDevice: makeIllegalConstructor('GPUDevice', mutablePrototypes.GPUDevice),
    GPUDeviceLostInfo: makeIllegalConstructor(
      'GPUDeviceLostInfo',
      deviceLostInfoPrototype,
    ),
    GPUError: makeIllegalConstructor('GPUError', gpuErrorPrototype),
    GPUInternalError: makeMessageConstructor('GPUInternalError', gpuErrorPrototype),
    GPUOutOfMemoryError: makeMessageConstructor(
      'GPUOutOfMemoryError',
      gpuErrorPrototype,
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
      Object.freeze(Object.create(null) as object),
    ),
    GPUValidationError: makeMessageConstructor(
      'GPUValidationError',
      gpuErrorPrototype,
    ),
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
    revoke() {
      if (revoked) return;
      revoked = true;
      closeRealmCounterIndependently(
        'realm-revoked',
        'The WebGPU realm was revoked',
      );
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
  'GPUDevice',
  'GPUDeviceLostInfo',
  'GPUError',
  'GPUInternalError',
  'GPUOutOfMemoryError',
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
    [...PUBLIC_INTERFACE_NAMES, ...PUBLIC_CONSTANT_NAMES].some(
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
    for (const name of PUBLIC_INTERFACE_NAMES) {
      installValue(globalObject, name, binding.interfaceObjects[name]);
    }
    for (const name of PUBLIC_CONSTANT_NAMES) {
      installValue(globalObject, name, binding.constantObjects[name]);
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
  return Object.freeze({
    status: 'installed',
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
