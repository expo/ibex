// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam — the native
// bridge is captured during the embedder construction transaction and never
// itself becomes an app-visible global or navigator property. An authenticated
// V2 capture may use it to publish the separately reviewed WebGPU wrapper.

import type { ProductionGpuDecodedImageAuthorityV1 } from './private-image-bitmap';

const CAPTURE_NAME = '__ibexCaptureGpuNativeBridge';

export interface NativeGpuBridgeV1 {
  readonly realmToken: string;
  readonly accountToken: string;
  readonly submit: (
    operationId: number,
    deviceOrdinal: string,
    queueOrdinal: string,
    accountToken: string,
    payload: ArrayBuffer | ArrayBufferView,
  ) => {
    completionId: string;
    admissionStatus: number;
    receipt: Promise<unknown>;
  };
  readonly cancel: (completionId: string) => number;
  readonly retire: (logicalHandles: readonly string[]) => number;
}

/** Full generation-bearing metadata consumed only by the production-private
 * wrapper. Synchronous wrapper-local recording operations never call submit;
 * the queue submit operation carries its already-sealed bounded program here.
 */
export interface NativeGpuCallMetadataV2 {
  readonly accountId: string;
  readonly accountGeneration: string;
  readonly authorityDigest: ArrayBuffer | ArrayBufferView;
  /** Exact logical-device identity at API ingress; all zero before device creation. */
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
  /** Standalone physical provider incarnation; may precede device creation. */
  readonly operationProviderGeneration: string;
  /** Scope captured at API ingress; zero means no eligible scope. */
  readonly capturedScopeId: string;
  readonly adapterOrdinal: string;
  readonly deviceIngressOrdinal: string;
  readonly queueIngressOrdinal: string;
  readonly receiverKind: number;
  readonly receiverId: string;
  readonly receiverGeneration: string;
  readonly targetKind: number;
  readonly targetId: string;
  readonly targetGeneration: string;
}

export interface NativeGpuOwnedObjectV2 {
  readonly accountId: string;
  readonly accountGeneration: string;
  readonly authorityDigest: ArrayBuffer | ArrayBufferView;
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
  readonly objectKind: number;
  readonly objectId: string;
  readonly objectGeneration: string;
}

interface NativeGpuOperationProvenanceV2 {
  readonly runtimeAddress: string;
  readonly runtimeNonce: string;
  readonly topologyId: number;
  readonly operationId: number;
  readonly operationInstanceId: string;
  readonly promiseId: string;
  readonly providerAdmission: 0 | 1;
  readonly physicalSequence: string;
  readonly capturedScopeId: string;
  readonly realmId: string;
  readonly realmGeneration: string;
  readonly accountId: string;
  readonly accountGeneration: string;
  readonly accountAuthorityDigest: ArrayBufferView;
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  /** Provider generation attached to the result/common-completion device. */
  readonly providerGeneration: string;
  readonly ingressLogicalDeviceId: string;
  readonly ingressLogicalDeviceGeneration: string;
  readonly ingressProviderGeneration: string;
  readonly deviceTransition: 0 | 1 | 2;
  readonly operationProviderGeneration: string;
  readonly authorityContextDigest: ArrayBufferView;
  readonly adapterOrdinal: string;
  readonly deviceIngressOrdinal: string;
  readonly queueIngressOrdinal: string;
  readonly receiverKind: number;
  readonly receiverFlags: number;
  readonly receiverId: string;
  readonly receiverGeneration: string;
  readonly targetKind: number;
  readonly targetFlags: number;
  readonly targetId: string;
  readonly targetGeneration: string;
}

export type NativeGpuEventV2 =
  | (NativeGpuOperationProvenanceV2 & {
      readonly kind: 1;
      readonly resultKind: number;
      readonly status: 0;
      /**
       * True only for ASSIGNED_DETACHED requestDevice results, preserving
       * either NOT_ADMITTED + sequence zero or ADMITTED + a nonzero sequence.
       * The generated wrapper must keep this fresh device out of its strong
       * realm registry and settle its stable lost promise before the outer
       * receipt.
       */
      readonly detachedAlreadyLost: boolean;
      /** Present exactly when detachedAlreadyLost is true. */
      readonly lossReason?: 1;
      /** Present exactly when detachedAlreadyLost is true. */
      readonly backendClass?: 0;
      readonly payload: ArrayBufferView;
    })
  | (NativeGpuOperationProvenanceV2 & {
      readonly kind: 2;
      readonly errorKind: number;
      readonly backendClass: number;
      readonly status: number;
      readonly payload: ArrayBufferView;
    })
  | {
      readonly kind: 3;
      readonly runtimeAddress: string;
      readonly runtimeNonce: string;
      readonly topologyId: number;
      readonly realmId: string;
      readonly realmGeneration: string;
      readonly logicalDeviceId: string;
      readonly logicalDeviceGeneration: string;
      readonly providerGeneration: string;
      readonly lastAcceptedPhysicalSequence: string;
      readonly backendClass: number;
      readonly lossReason: number;
      readonly hasInitiatingOperation: boolean;
      readonly initiatingOperation?: NativeGpuOperationProvenanceV2;
      readonly payload: ArrayBufferView;
    }
  | {
      /** Exactly-once settlement input for the stable GPUDevice.lost promise. */
      readonly kind: 4;
      readonly runtimeAddress: string;
      readonly runtimeNonce: string;
      readonly topologyId: number;
      readonly realmId: string;
      readonly realmGeneration: string;
      readonly accountId: string;
      readonly accountGeneration: string;
      readonly accountAuthorityDigest: ArrayBufferView;
      readonly logicalDeviceId: string;
      readonly logicalDeviceGeneration: string;
      readonly providerGeneration: string;
      readonly logicalLossOrdinal: string;
      readonly lastAcceptedPhysicalSequence: string;
      readonly backendClass: number;
      readonly lossReason: number;
      readonly hasInitiatingOperation: boolean;
      readonly initiatingOperation?: NativeGpuOperationProvenanceV2;
      readonly payload: ArrayBufferView;
    }
  | {
      readonly kind: 5;
      readonly runtimeAddress: string;
      readonly runtimeNonce: string;
      readonly realmId: string;
      readonly realmGeneration: string;
      readonly accountId: string;
      readonly accountGeneration: string;
      readonly accountAuthorityDigest: ArrayBufferView;
      readonly closeOrdinal: string;
      readonly closeReason: number;
      readonly payload: ArrayBufferView;
    }
  | {
      readonly kind: 6;
      readonly runtimeAddress: string;
      readonly runtimeNonce: string;
      readonly realmId: string;
      readonly realmGeneration: string;
      readonly closeOrdinal: string;
      readonly closeReason: number;
      readonly payload: ArrayBufferView;
    };

export interface NativeGpuBridgeV2 {
  readonly abiVersion: 0x0002_0000;
  readonly runtimeAddress: string;
  readonly runtimeNonce: string;
  readonly realmId: string;
  readonly realmGeneration: string;
  readonly rootAccountId: string;
  readonly rootAccountGeneration: string;
  readonly rootAuthorityDigest: ArrayBufferView;
  /** Optional construction-private Apple decoded-image callback authority. */
  readonly decodedImageAuthority?: ProductionGpuDecodedImageAuthorityV1;
  readonly submit: (
    operationId: number,
    wantsPromise: boolean,
    metadata: NativeGpuCallMetadataV2,
    payload: ArrayBuffer | ArrayBufferView,
  ) => {
    operationInstanceId: string;
    /** Zero for non-Promise semantic work. */
    promiseId: string;
    /** Semantic-service acceptance/tracking; not physical provider admission. */
    submissionStatus: number;
    receipt?: Promise<unknown>;
  };
  readonly cancel: (operationInstanceId: string, promiseId: string) => number;
  readonly retire: (objects: readonly NativeGpuOwnedObjectV2[]) => number;
  /**
   * Mints one engine-keyed, non-transferable ArrayBuffer alias over an
   * already-owned external mapped byte block. This method never copies bytes.
   */
  readonly createMappedRangeAlias: (
    source: ArrayBuffer,
    byteOffset: number,
    byteLength: number,
  ) => ArrayBuffer;
  /** Detaches only aliases minted by createMappedRangeAlias. */
  readonly detachMappedRange: (buffer: ArrayBuffer) => boolean;
  /**
   * One-shot owner-thread ordered raw-event channel. It receives every typed
   * record, including Promise terminals also settled through `receipt`; the
   * generated wrapper correlates by operationInstanceId/promiseId and must not
   * treat the second projection as a second settlement.
   */
  readonly setEventSink: (sink: (event: NativeGpuEventV2) => void) => void;
}

export type NativeGpuBridge = NativeGpuBridgeV1 | NativeGpuBridgeV2;

/** Exact construction result understood by the native V2 capture. */
export interface NativeGpuCanvasCaptureInstallation {
  readonly revoke: () => void;
  readonly canvasReceiptSink: (receipt: unknown) => void;
  readonly checkpointHostTask: () => void;
  readonly beginCanvasAppBundle: (
    expectation: 0 | 1 | 2,
  ) => ((candidate: unknown) => void) | undefined;
  readonly finishCanvasAppBundle: (evaluationSucceeded: boolean) => boolean;
}

export type NativeGpuBridgeCaptureInstallation =
  | (() => void)
  | Readonly<NativeGpuCanvasCaptureInstallation>;

let capturedBridge: NativeGpuBridge | undefined;
let captureClosed = false;

function isExactCanvasCaptureInstallation(
  value: unknown,
): value is Readonly<NativeGpuCanvasCaptureInstallation> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !Object.isFrozen(value)
  ) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 5 ||
    !keys.includes('revoke') ||
    !keys.includes('canvasReceiptSink') ||
    !keys.includes('checkpointHostTask') ||
    !keys.includes('beginCanvasAppBundle') ||
    !keys.includes('finishCanvasAppBundle')
  ) {
    return false;
  }
  for (
    const key of [
      'revoke',
      'canvasReceiptSink',
      'checkpointHostTask',
      'beginCanvasAppBundle',
      'finishCanvasAppBundle',
    ] as const
  ) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      !descriptor ||
      typeof descriptor.value !== 'function' ||
      descriptor.writable !== false ||
      descriptor.enumerable !== true ||
      descriptor.configurable !== false
    ) {
      return false;
    }
  }
  return true;
}

/** Internal validation hook used by the construction handoff and its tests. */
export function isNativeGpuBridge(value: unknown): value is NativeGpuBridge {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  const methodsArePresent = typeof candidate.submit === 'function' &&
    typeof candidate.cancel === 'function' &&
    typeof candidate.retire === 'function';
  if (!methodsArePresent) return false;
  if (candidate.abiVersion === 0x0002_0000) {
    return typeof candidate.runtimeAddress === 'string' &&
      typeof candidate.runtimeNonce === 'string' &&
      typeof candidate.realmId === 'string' &&
      typeof candidate.realmGeneration === 'string' &&
      typeof candidate.rootAccountId === 'string' &&
      typeof candidate.rootAccountGeneration === 'string' &&
      ArrayBuffer.isView(candidate.rootAuthorityDigest) &&
      typeof candidate.createMappedRangeAlias === 'function' &&
      typeof candidate.detachMappedRange === 'function' &&
      typeof candidate.setEventSink === 'function';
  }
  return typeof candidate.realmToken === 'string' &&
    typeof candidate.accountToken === 'string';
}

/** Install the one-shot construction handoff before any untrusted code runs. */
export function installNativeGpuBridgeCapture(
  globalObject: typeof globalThis,
  onCapture?: (
    bridge: NativeGpuBridge,
  ) => NativeGpuBridgeCaptureInstallation | undefined,
): void {
  if (captureClosed) return;
  if (Object.prototype.hasOwnProperty.call(globalObject, CAPTURE_NAME)) {
    throw new TypeError('Native GPU bridge capture name is already occupied');
  }
  const capture = (
    candidate?: unknown,
  ): NativeGpuBridgeCaptureInstallation | undefined => {
    if (candidate === undefined) {
      captureClosed = true;
      Reflect.deleteProperty(globalObject, CAPTURE_NAME);
      return undefined;
    }
    if (captureClosed || capturedBridge !== undefined || !isNativeGpuBridge(candidate)) {
      throw new TypeError('Invalid or repeated native GPU bridge capture');
    }
    let revoked = false;
    const revoke = () => {
      if (revoked) return;
      revoked = true;
      if (capturedBridge === candidate) capturedBridge = undefined;
    };
    capturedBridge = candidate;
    captureClosed = true;
    if (!Reflect.deleteProperty(globalObject, CAPTURE_NAME)) {
      revoke();
      throw new TypeError('Native GPU bridge capture could not delete its handoff');
    }
    let installedSurface: NativeGpuBridgeCaptureInstallation | undefined;
    try {
      installedSurface = onCapture?.(candidate);
      if (
        installedSurface !== undefined &&
        typeof installedSurface !== 'function' &&
        !isExactCanvasCaptureInstallation(installedSurface)
      ) {
        throw new TypeError('Invalid native GPU bridge capture installation');
      }
    } catch (error) {
      revoke();
      throw error;
    }
    let captureRevoked = false;
    const revokeCapture = () => {
      if (captureRevoked) return;
      captureRevoked = true;
      if (typeof installedSurface === 'function') {
        installedSurface();
      } else {
        installedSurface?.revoke();
      }
      revoke();
    };
    return isExactCanvasCaptureInstallation(installedSurface)
      ? Object.freeze({
        revoke: revokeCapture,
        canvasReceiptSink: installedSurface.canvasReceiptSink,
        checkpointHostTask: installedSurface.checkpointHostTask,
        beginCanvasAppBundle: installedSurface.beginCanvasAppBundle,
        finishCanvasAppBundle: installedSurface.finishCanvasAppBundle,
      })
      : revokeCapture;
  };
  Object.defineProperty(globalObject, CAPTURE_NAME, {
    value: capture,
    writable: false,
    configurable: true,
    enumerable: false,
  });
}

/** Permanently close an unused construction handoff before user execution. */
export function closeNativeGpuBridgeCapture(globalObject: typeof globalThis): void {
  captureClosed = true;
  Reflect.deleteProperty(globalObject, CAPTURE_NAME);
}

/** Internal-only accessor shared with the production-private WebGPU wrapper. */
export function getNativeGpuBridge(): NativeGpuBridge | undefined {
  return capturedBridge;
}

/** Test-only reset for exercising both construction orderings in one realm. */
export function resetNativeGpuBridgeCaptureForTests(): void {
  capturedBridge = undefined;
  captureClosed = false;
}
