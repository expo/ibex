// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam — the native
// bridge is captured during the embedder construction transaction and never
// becomes an app-visible global or navigator property.

const CAPTURE_NAME = '__ibexCaptureGpuNativeBridge';

export interface NativeGpuBridge {
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

let capturedBridge: NativeGpuBridge | undefined;
let captureClosed = false;

function isNativeGpuBridge(value: unknown): value is NativeGpuBridge {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<NativeGpuBridge>;
  return typeof candidate.realmToken === 'string' &&
    typeof candidate.accountToken === 'string' &&
    typeof candidate.submit === 'function' &&
    typeof candidate.cancel === 'function' &&
    typeof candidate.retire === 'function';
}

/** Install the one-shot construction handoff before any untrusted code runs. */
export function installNativeGpuBridgeCapture(globalObject: typeof globalThis): void {
  if (captureClosed) return;
  if (Object.prototype.hasOwnProperty.call(globalObject, CAPTURE_NAME)) {
    throw new TypeError('Native GPU bridge capture name is already occupied');
  }
  const capture = (candidate?: unknown): (() => void) | undefined => {
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
    return revoke;
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

/** Internal-only accessor for a later generated runtime-js WebGPU wrapper. */
export function getNativeGpuBridge(): NativeGpuBridge | undefined {
  return capturedBridge;
}
