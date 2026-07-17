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
  type ProductionGpuObjectIdentity,
  type ProductionGpuWrapperKind,
  validateExecutableWebGpuCodecs,
} from './production-codecs';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';
import { WEBGPU_OBJECT_KIND_TAGS } from './production-codecs.generated';

type ProductionRoute = (typeof WEBGPU_PRODUCTION_PLAN.routes)[number];

const ROUTES = new Map<string, ProductionRoute>(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.operationId, route]),
);
const ROUTES_BY_WIRE = new Map<number, ProductionRoute>(
  WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.wireId, route]),
);

const OBJECT_KINDS: Readonly<Record<ProductionGpuWrapperKind, number>> =
  WEBGPU_OBJECT_KIND_TAGS;

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
  readonly limits: Readonly<Record<string, number>>;
  readonly lost: LostController;
  queue: object | undefined;
  destroyed: boolean;
  nextIngress: string;
  nextQueueIngress: string;
  nextScope: string;
  scopes: Array<Readonly<{ id: string; filter: string }>>;
  pendingLocalTimeline: unknown[];
}

interface WrapperState {
  readonly realm: RealmState;
  readonly kind: ProductionGpuWrapperKind;
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly wrapper: object;
  device: DeviceState | undefined;
  providerGeneration: string;
  nextAdapterOrdinal: string;
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
  destroyed: boolean;
  textureExpired: boolean;
  materialized: boolean;
  currentOrigin: Readonly<Record<string, unknown>> | undefined;
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
  readonly pendingPromiseCalls: Map<string, PendingPromiseCall>;
  readonly resultEvents: Map<
    string,
    Extract<NativeGpuEventV2, { kind: 1 }>
  >;
  nextLocalObjectId: string;
  active: boolean;
}

export interface ProductionWebGpuPrivateBinding {
  readonly gpu: object;
  readonly interfaceObjects: Readonly<Record<string, object>>;
  readonly constantObjects: Readonly<Record<string, object>>;
  readonly mintCanvasContext: (
    identity: Readonly<{
      objectId: string;
      objectGeneration: string;
    }>,
  ) => object;
  readonly revoke: () => void;
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

function incrementDecimal(value: string): string {
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
  return /^[1-9][0-9]*$/u.test(value);
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

function createReadonlyFeatureSet(
  values: readonly string[],
  prototype: object,
  states: WeakMap<object, readonly string[]>,
): object {
  const ordered = [...new Set(values.map((value) => String(value)))].sort();
  const result = Object.create(prototype) as object;
  states.set(result, Object.freeze(ordered));
  return Object.freeze(result);
}

function createPrototypeTable(): Record<ProductionGpuWrapperKind, object> {
  return {
    GPU: Object.create(null),
    GPUAdapter: Object.create(null),
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

export function createProductionWebGpuPrivateBinding(
  bridge: NativeGpuBridgeV2,
  codecs: ExecutableWebGpuCodecBundle,
): ProductionWebGpuPrivateBinding {
  if (!validateExecutableWebGpuCodecs(codecs)) {
    throw new TypeError('WebGPU executable codec authority is invalid');
  }

  const mutablePrototypes = createPrototypeTable();
  const featurePrototype = Object.create(null) as object;
  const featureStates = new WeakMap<object, readonly string[]>();
  installReadonlyFeatureSetPrototype(featurePrototype, featureStates);
  const supportedLimitsPrototype = Object.freeze(Object.create(null) as object);
  const deviceLostInfoPrototype = Object.freeze(Object.create(null) as object);
  const realm: RealmState = {
    bridge,
    codecs,
    prototypes: mutablePrototypes,
    wrappers: new WeakMap(),
    devices: new Map(),
    pendingPromiseCalls: new Map(),
    resultEvents: new Map(),
    // Client-allocated targets occupy the high unsigned half of the service
    // namespace, independently of provider-assigned result identities.
    nextLocalObjectId: '9223372036854775808',
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
  ) => {
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

  const allocateWrapper = (
    kind: ProductionGpuWrapperKind,
    device: DeviceState | undefined,
    identity?: Readonly<{ objectId: string; objectGeneration: string }>,
  ): WrapperState => {
    const wrapper = Object.create(realm.prototypes[kind]) as object;
    const objectId = identity?.objectId ?? realm.nextLocalObjectId;
    if (!identity) realm.nextLocalObjectId = incrementDecimal(realm.nextLocalObjectId);
    if (!isPositiveDecimal(objectId)) {
      throw new TypeError(`Invalid ${kind} object identity`);
    }
    const objectGeneration = identity?.objectGeneration ?? '1';
    if (!isPositiveDecimal(objectGeneration)) {
      throw new TypeError(`Invalid ${kind} object generation`);
    }
    const state: WrapperState = {
      realm,
      kind,
      objectId,
      objectGeneration,
      wrapper,
      device,
      providerGeneration: device?.providerGeneration ?? '0',
      nextAdapterOrdinal: '1',
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
      configurationGeneration: '0',
      currentEpoch: '0',
      currentTexture: undefined,
      configuredDevice: undefined,
      destroyed: false,
      textureExpired: false,
      materialized: false,
      currentOrigin: undefined,
    };
    realm.wrappers.set(wrapper, state);
    return state;
  };

  const convert = (operationId: string, args: readonly unknown[]): unknown => {
    route(operationId);
    return codecs.convertPublicArguments(operationId, args, { reference });
  };

  const settleDeviceLost = (
    device: DeviceState,
    reason: 'destroyed' | 'unknown',
    message: string,
  ): void => {
    if (device.lost.settled) return;
    device.lost.settled = true;
    const info = Object.freeze(Object.assign(Object.create(deviceLostInfoPrototype) as object, {
      reason,
      message,
    }));
    device.lost.resolve(info);
  };

  const expireCurrentTexture = (context: WrapperState): void => {
    if (!context.currentTexture) return;
    const texture = requireState(context.currentTexture, 'GPUTexture');
    texture.textureExpired = true;
    context.currentTexture = undefined;
  };

  const assignDeviceIngress = (device: DeviceState | undefined): string => {
    if (!device) return '0';
    const result = device.nextIngress;
    device.nextIngress = incrementDecimal(result);
    return result;
  };

  const recordLocal = (
    operationId: string,
    receiver: WrapperState,
    target: WrapperState | undefined,
    convertedArguments: unknown,
    error: Error | undefined,
  ): void => {
    const selected = route(operationId);
    if (selected.providerSubmission !== 'none') {
      throw new Error(`${operationId} is not wrapper-local`);
    }
    const device = receiver.device ?? target?.device;
    if (!device) throw new Error(`${operationId} lacks a logical device`);
    device.pendingLocalTimeline.push(
      Object.freeze({
        operationId,
        wireId: selected.wireId,
        receiver: reference(receiver.wrapper, receiver.kind),
        target: target ? reference(target.wrapper, target.kind) : undefined,
        deviceIngressOrdinal: assignDeviceIngress(device),
        capturedScopeId: currentScopeId(device),
        convertedArguments,
        error: error
          ? Object.freeze({ name: error.name, message: error.message })
          : undefined,
      }),
    );
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

  const submitService = (
    operationId: string,
    receiver: WrapperState,
    target: WrapperState | undefined,
    convertedArguments: unknown,
    wantsPromise: boolean,
  ) => {
    if (!realm.active) throw namedError('SecurityError', 'WebGPU realm is revoked');
    const selected = route(operationId);
    if (selected.providerSubmission === 'none') {
      throw new Error(`${operationId} has no semantic service route`);
    }
    const projection = selected.serviceReceiverProjection;
    const singleton = projection.source === 'realm-gpu-singleton';
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

    const device = receiver.device ?? target?.device;
    const deviceIngressOrdinal = assignDeviceIngress(device);
    const queueIngressOrdinal =
      operationId === 'GPUQueue.submit' && device
        ? (() => {
          const value = device.nextQueueIngress;
          device.nextQueueIngress = incrementDecimal(value);
          return value;
        })()
        : '0';
    const adapterOrdinal =
      operationId === 'GPUAdapter.requestDevice'
        ? (() => {
          const value = receiver.nextAdapterOrdinal;
          receiver.nextAdapterOrdinal = incrementDecimal(value);
          return value;
        })()
        : '0';
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
    const capturedScopeId = currentScopeId(device);
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
    const payloadLength = ArrayBuffer.isView(payload)
      ? payload.byteLength
      : payload.byteLength;
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
    const carrier = bridge.submit(selected.wireId, wantsPromise, metadata, payload);
    if (carrier.submissionStatus !== 0) {
      carrier.receipt?.catch(() => undefined);
      throw namedError(
        'OperationError',
        `WebGPU semantic service rejected ${operationId} (${carrier.submissionStatus})`,
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
      const device: DeviceState = {
        logicalDeviceId,
        logicalDeviceGeneration,
        providerGeneration,
        features: createReadonlyFeatureSet(
          identity.features ?? [],
          featurePrototype,
          featureStates,
        ),
        limits: Object.freeze(
          Object.assign(
            Object.create(supportedLimitsPrototype) as Record<string, number>,
            identity.limits ?? {},
          ),
        ),
        lost: makeLostController(),
        queue: undefined,
        destroyed: false,
        nextIngress: '1',
        nextQueueIngress: '1',
        nextScope: '1',
        scopes: [],
        pendingLocalTimeline: [],
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
      for (const device of realm.devices.values()) {
        if (device.providerGeneration === event.providerGeneration) {
          settleDeviceLost(device, decoded.reason, decoded.message);
        }
      }
      return;
    }
    for (const device of realm.devices.values()) {
      settleDeviceLost(device, decoded.reason, decoded.message);
    }
    if (event.kind === 6) realm.active = false;
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
      settleLossEvent(event);
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
    const converted = asRecord(
      convert('GPUCanvasContext.configure', [configuration]),
      'GPUCanvasConfiguration',
    );
    const deviceWrapper = converted.device;
    const deviceState = requireState(deviceWrapper, 'GPUDevice');
    if (!deviceState.device || deviceState.device.destroyed) {
      throw namedError('InvalidStateError', 'GPUDevice is unavailable');
    }
    // The semantic call carries the configured device as ingress while the
    // service receiver remains the complete canvas-context reference.
    context.device = deviceState.device;
    try {
      submitService(
        'GPUCanvasContext.configure',
        context,
        undefined,
        converted,
        false,
      );
    } finally {
      context.device = undefined;
    }
    expireCurrentTexture(context);
    context.configurationGeneration = incrementDecimal(
      context.configurationGeneration,
    );
    context.configuration = cloneConfiguration(converted);
    context.configuredDevice = deviceState.device;
  });

  defineMethod(
    mutablePrototypes.GPUCanvasContext,
    'getConfiguration',
    function (this: object) {
      const context = requireState(this, 'GPUCanvasContext');
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
      const converted = convert('GPUCanvasContext.getCurrentTexture', []);
      if (!context.configuration || !context.configuredDevice) {
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
      const texture = allocateWrapper(
        'GPUTexture',
        context.configuredDevice,
      );
      context.currentEpoch = incrementDecimal(context.currentEpoch);
      texture.currentOrigin = Object.freeze({
        contextObjectId: context.objectId,
        contextObjectGeneration: context.objectGeneration,
        configurationGeneration: context.configurationGeneration,
        currentEpoch: context.currentEpoch,
      });
      context.currentTexture = texture.wrapper;
      recordLocal(
        'GPUCanvasContext.getCurrentTexture',
        context,
        texture,
        converted,
        undefined,
      );
      return texture.wrapper;
    },
  );

  defineMethod(mutablePrototypes.GPUCanvasContext, 'unconfigure', function (
    this: object,
  ) {
    const context = requireState(this, 'GPUCanvasContext');
    const converted = convert('GPUCanvasContext.unconfigure', []);
    context.device = context.configuredDevice;
    try {
      submitService(
        'GPUCanvasContext.unconfigure',
        context,
        undefined,
        converted,
        false,
      );
    } finally {
      context.device = undefined;
    }
    expireCurrentTexture(context);
    context.configuration = undefined;
    context.configuredDevice = undefined;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createCommandEncoder', function (
    this: object,
    descriptor?: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createCommandEncoder', [descriptor]);
    const encoder = allocateWrapper('GPUCommandEncoder', state.device);
    encoder.status = 'recording';
    submitService(
      'GPUDevice.createCommandEncoder',
      state,
      encoder,
      converted,
      false,
    );
    return encoder.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createShaderModule', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createShaderModule', [descriptor]);
    const module = allocateWrapper('GPUShaderModule', state.device);
    submitService(
      'GPUDevice.createShaderModule',
      state,
      module,
      converted,
      false,
    );
    return module.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'createRenderPipeline', function (
    this: object,
    descriptor: unknown,
  ) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.createRenderPipeline', [descriptor]);
    const pipeline = allocateWrapper('GPURenderPipeline', state.device);
    submitService(
      'GPUDevice.createRenderPipeline',
      state,
      pipeline,
      converted,
      false,
    );
    return pipeline.wrapper;
  });

  defineMethod(mutablePrototypes.GPUDevice, 'destroy', function (this: object) {
    const state = requireState(this, 'GPUDevice');
    const converted = convert('GPUDevice.destroy', []);
    submitService('GPUDevice.destroy', state, undefined, converted, false);
    if (state.device && !state.device.destroyed) {
      state.device.destroyed = true;
      settleDeviceLost(state.device, 'destroyed', 'The device was destroyed');
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
    const scopeId = device.nextScope;
    device.nextScope = incrementDecimal(scopeId);
    submitService(
      'GPUDevice.pushErrorScope',
      state,
      undefined,
      Object.freeze({ converted, scopeId }),
      false,
    );
    device.scopes.push(
      Object.freeze({ id: scopeId, filter: String(converted) }),
    );
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
    recordLocal(
      'GPUCommandEncoder.beginRenderPass',
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
    recordLocal(
      'GPUCommandEncoder.finish',
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
    recordLocal(
      'GPURenderPassEncoder.draw',
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
    recordLocal(
      'GPURenderPassEncoder.setPipeline',
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
    recordLocal(
      'GPURenderPassEncoder.end',
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
    const view = allocateWrapper('GPUTextureView', texture.device);
    submitService(
      'GPUTexture.createView',
      texture,
      view,
      Object.freeze({
        converted,
        currentOrigin: texture.currentOrigin,
      }),
      false,
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

  for (const prototype of Object.values(mutablePrototypes)) Object.freeze(prototype);

  const gpuErrorPrototype = Object.freeze(
    Object.assign(Object.create(null) as object, { name: 'GPUError' }),
  );
  const interfaceObjects: Record<string, object> = {
    GPU: makeIllegalConstructor('GPU', mutablePrototypes.GPU),
    GPUAdapter: makeIllegalConstructor('GPUAdapter', mutablePrototypes.GPUAdapter),
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
    mintCanvasContext(identity: Readonly<{
      objectId: string;
      objectGeneration: string;
    }>) {
      if (!realm.active) throw namedError('SecurityError', 'WebGPU realm is revoked');
      return allocateWrapper('GPUCanvasContext', undefined, identity).wrapper;
    },
    revoke() {
      if (revoked) return;
      revoked = true;
      realm.active = false;
      for (const device of realm.devices.values()) {
        settleDeviceLost(device, 'unknown', 'The WebGPU realm was revoked');
      }
      realm.pendingPromiseCalls.clear();
      realm.resultEvents.clear();
    },
  });
}

const PUBLIC_INTERFACE_NAMES = Object.freeze([
  'GPU',
  'GPUAdapter',
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
