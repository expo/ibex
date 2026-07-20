// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// This module is bundled with bootstrap and the eventual generated WebGPU
// wrapper. Ibex's app module loader rejects every source under this directory,
// so this forwarding layer is not an app import surface.

import {
  getNativeGpuBridge,
  installNativeGpuBridgeCapture as installCapture,
  type NativeGpuBridge,
} from './native-bridge';
import { WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION } from './production-codecs.generated';
import {
  installProductionWebGpu,
  type ProductionGpuCanvasContextMinter,
} from './production-wrapper';

/** Exact-owned half of one app-bundle Canvas rendezvous. */
export interface ExactGpuCanvasRuntimeIntegration {
  readonly installCanvasContextMinter: (
    minter: Readonly<ProductionGpuCanvasContextMinter>,
  ) => () => void;
  readonly deliverCanvasAttachmentReceipt: (receipt: unknown) => void;
}

const CANVAS_INTEGRATION_CAPTURE_NAME =
  '__ibexCaptureGpuCanvasRuntimeIntegration';

// These reflection operations are captured with the trusted embedded bundle.
// A bundle being evaluated inside a begin/finish transaction may replace the
// ambient Object/Reflect methods, but it cannot redirect handoff validation or
// cleanup through those replacements.
const objectDefineProperty = Object.defineProperty.bind(Object);
const objectFreeze = Object.freeze.bind(Object);
const objectGetOwnPropertyDescriptor =
  Object.getOwnPropertyDescriptor.bind(Object);
const objectGetPrototypeOf = Object.getPrototypeOf.bind(Object);
const objectIsFrozen = Object.isFrozen.bind(Object);
const objectPrototype = Object.prototype;
const hasOwnProperty = Function.prototype.call.bind(
  Object.prototype.hasOwnProperty,
) as (object: object, key: PropertyKey) => boolean;
const reflectDeleteProperty = Reflect.deleteProperty.bind(Reflect);
const reflectOwnKeys = Reflect.ownKeys.bind(Reflect);

type CanvasAppBundlePhase = 'closed' | 'open' | 'consumed';
type CanvasAppBundleExpectation = 1 | 2;
type CanvasAppBundleBeginPhase = 0 | CanvasAppBundleExpectation;

let exactCanvasIntegration:
  | Readonly<ExactGpuCanvasRuntimeIntegration>
  | undefined;
let activeCanvasContextMinter:
  | Readonly<ProductionGpuCanvasContextMinter>
  | undefined;
let releaseCanvasContextMinter: (() => void) | undefined;
let canvasReceiptDeliveryActive = false;
let canvasReceiptDeliveryCommitted = false;
let canvasAppBundlePrepared = false;
let canvasAppBundlePhase: CanvasAppBundlePhase = 'closed';
let canvasAppBundleCaptureAccepted = false;
let canvasAppBundleCapture:
  | ((candidate: unknown) => void)
  | undefined;
let canvasAppBundleGlobal: typeof globalThis | undefined;
let canvasAppBundleExpectation: CanvasAppBundleExpectation | undefined;

function installRegisteredCanvasMinter(): void {
  if (
    !exactCanvasIntegration ||
    !activeCanvasContextMinter ||
    releaseCanvasContextMinter
  ) {
    return;
  }
  const release = exactCanvasIntegration.installCanvasContextMinter(
    activeCanvasContextMinter,
  );
  if (typeof release !== 'function') {
    throw new TypeError('Exact GPU Canvas minter installation returned no revoker');
  }
  releaseCanvasContextMinter = release;
}

function canvasReceiptSink(receipt: unknown): void {
  const integration = exactCanvasIntegration;
  if (
    !canvasReceiptDeliveryActive ||
    !canvasReceiptDeliveryCommitted ||
    canvasAppBundlePhase !== 'closed' ||
    !integration
  ) {
    throw new TypeError('Exact GPU Canvas receipt integration is unavailable');
  }
  integration.deliverCanvasAttachmentReceipt(receipt);
}

function revokeExactCanvasRuntimeIntegration(): void {
  const release = releaseCanvasContextMinter;
  // Clear every route before invoking app-owned cleanup. A throwing revoker
  // cannot keep its integration current or receive a later native receipt.
  releaseCanvasContextMinter = undefined;
  exactCanvasIntegration = undefined;
  canvasReceiptDeliveryCommitted = false;
  release?.();
}

function acceptExactCanvasRuntimeIntegration(
  integration: Readonly<ExactGpuCanvasRuntimeIntegration>,
): void {
  exactCanvasIntegration = integration;
  try {
    installRegisteredCanvasMinter();
  } catch (error) {
    exactCanvasIntegration = undefined;
    throw error;
  }
}

function isExactGpuCanvasRuntimeIntegration(
  value: unknown,
): value is Readonly<ExactGpuCanvasRuntimeIntegration> {
  if (
    typeof value !== 'object' ||
    value === null ||
    objectGetPrototypeOf(value) !== objectPrototype ||
    !objectIsFrozen(value)
  ) {
    return false;
  }
  const keys = reflectOwnKeys(value);
  if (
    keys.length !== 2 ||
    !keys.includes('installCanvasContextMinter') ||
    !keys.includes('deliverCanvasAttachmentReceipt')
  ) {
    return false;
  }
  for (
    const key of [
      'installCanvasContextMinter',
      'deliverCanvasAttachmentReceipt',
    ] as const
  ) {
    const descriptor = objectGetOwnPropertyDescriptor(value, key);
    if (
      !descriptor ||
      typeof descriptor.value !== 'function' ||
      descriptor.writable !== false ||
      descriptor.enumerable !== true ||
      descriptor.configurable !== false ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Prepare and then arm one host-delimited app-bundle transaction. Native
 * first calls phase 0 inside a complete host task, so prior app-owned cleanup
 * drains while the capture root is absent. It calls phase 1 or 2 only after
 * that checkpoint to publish the next transaction.
 */
function beginExactGpuCanvasAppBundle(
  globalObject: typeof globalThis,
  expectation: CanvasAppBundleBeginPhase,
): ((candidate: unknown) => void) | undefined {
  if (expectation === 0) {
    if (
      !canvasReceiptDeliveryActive ||
      canvasAppBundlePrepared ||
      canvasAppBundlePhase !== 'closed' ||
      hasOwnProperty(globalObject, CANVAS_INTEGRATION_CAPTURE_NAME)
    ) {
      throw new TypeError(
        'Exact GPU Canvas app-bundle preparation is unavailable',
      );
    }
    // Native checkpoints this private phase before it asks us to publish the
    // next capture root. An app-owned G(n-1) release may therefore enqueue
    // work, but that work runs to completion while the reserved root is still
    // absent and cannot steal G(n)'s one-shot handoff.
    revokeExactCanvasRuntimeIntegration();
    canvasReceiptDeliveryCommitted = false;
    canvasAppBundlePrepared = true;
    return undefined;
  }
  if (
    (expectation !== 1 && expectation !== 2) ||
    !canvasReceiptDeliveryActive ||
    !canvasAppBundlePrepared ||
    canvasAppBundlePhase !== 'closed'
  ) {
    throw new TypeError('Exact GPU Canvas app-bundle transaction is unavailable');
  }
  if (
    hasOwnProperty(globalObject, CANVAS_INTEGRATION_CAPTURE_NAME)
  ) {
    throw new TypeError(
      'Exact GPU Canvas integration capture name is already occupied',
    );
  }

  canvasAppBundlePrepared = false;
  canvasAppBundleGlobal = globalObject;
  canvasAppBundleCapture = undefined;
  canvasAppBundleCaptureAccepted = false;
  canvasAppBundleExpectation = expectation;
  canvasAppBundlePhase = 'open';

  // A bundle whose authenticated manifest declares no Exact GPU prelude gets
  // no capture at all. Native still brackets its raw evaluation so finish can
  // prove the reserved root remained absent.
  if (expectation === 2) return undefined;

  const capture = (candidate: unknown): void => {
    if (
      canvasAppBundlePhase !== 'open' ||
      canvasAppBundleCapture !== capture ||
      !isExactGpuCanvasRuntimeIntegration(candidate)
    ) {
      throw new TypeError(
        'Invalid or repeated Exact GPU Canvas integration capture',
      );
    }
    const descriptor = objectGetOwnPropertyDescriptor(
      globalObject,
      CANVAS_INTEGRATION_CAPTURE_NAME,
    );
    if (
      !descriptor ||
      descriptor.value !== capture ||
      descriptor.writable !== false ||
      descriptor.enumerable !== false ||
      descriptor.configurable !== true
    ) {
      throw new TypeError('Exact GPU Canvas integration handoff was replaced');
    }

    // Delete before accepting either app-owned callback. If validation or
    // installation later throws, no second candidate can race into this
    // transaction and finish will keep receipt delivery disabled.
    canvasAppBundlePhase = 'consumed';
    if (
      !reflectDeleteProperty(
        globalObject,
        CANVAS_INTEGRATION_CAPTURE_NAME,
      ) ||
      hasOwnProperty(globalObject, CANVAS_INTEGRATION_CAPTURE_NAME)
    ) {
      throw new TypeError(
        'Exact GPU Canvas integration capture could not delete its handoff',
      );
    }
    try {
      acceptExactCanvasRuntimeIntegration(candidate);
      canvasAppBundleCaptureAccepted = true;
    } catch (error) {
      revokeExactCanvasRuntimeIntegration();
      throw error;
    }
  };
  objectDefineProperty(
    globalObject,
    CANVAS_INTEGRATION_CAPTURE_NAME,
    {
      value: capture,
      writable: false,
      configurable: true,
      enumerable: false,
    },
  );
  canvasAppBundleCapture = capture;
  return capture;
}

/**
 * Close the currently armed app-bundle transaction. `true` reports that the
 * exact integration was consumed during evaluation; `false` is the safe
 * no-GPU-bundle outcome. Evaluation failure always revokes even a consumed
 * integration, while still reporting whether consumption occurred.
 */
function finishExactGpuCanvasAppBundle(
  evaluationSucceeded: boolean,
): boolean {
  if (
    typeof evaluationSucceeded !== 'boolean' ||
    canvasAppBundlePhase === 'closed' ||
    !canvasAppBundleGlobal ||
    !canvasAppBundleExpectation
  ) {
    throw new TypeError('No Exact GPU Canvas app-bundle transaction is open');
  }

  const globalObject = canvasAppBundleGlobal;
  const capture = canvasAppBundleCapture;
  const expectation = canvasAppBundleExpectation;
  const phase = canvasAppBundlePhase;
  const accepted =
    phase === 'consumed' && canvasAppBundleCaptureAccepted;
  let cleanupFailed = false;
  let handoffWasReplaced = false;
  const descriptor = objectGetOwnPropertyDescriptor(
    globalObject,
    CANVAS_INTEGRATION_CAPTURE_NAME,
  );

  if (descriptor) {
    const expectedOpenDescriptor =
      expectation === 1 &&
      phase === 'open' &&
      capture !== undefined &&
      descriptor.value === capture &&
      descriptor.writable === false &&
      descriptor.enumerable === false &&
      descriptor.configurable === true &&
      descriptor.get === undefined &&
      descriptor.set === undefined;
    handoffWasReplaced = !expectedOpenDescriptor;
    cleanupFailed =
      !reflectDeleteProperty(globalObject, CANVAS_INTEGRATION_CAPTURE_NAME) ||
      hasOwnProperty(globalObject, CANVAS_INTEGRATION_CAPTURE_NAME);
  } else if (phase === 'open' && expectation === 1) {
    // An untouched no-GPU bundle leaves the expected descriptor for finish to
    // delete. Absence without successful capture means app code intercepted it.
    handoffWasReplaced = true;
  }

  canvasAppBundleGlobal = undefined;
  canvasAppBundlePrepared = false;
  canvasAppBundleCapture = undefined;
  canvasAppBundleCaptureAccepted = false;
  canvasAppBundleExpectation = undefined;
  canvasAppBundlePhase = 'closed';
  canvasReceiptDeliveryCommitted =
    evaluationSucceeded &&
    expectation === 1 &&
    accepted &&
    !cleanupFailed &&
    !handoffWasReplaced;

  if (!canvasReceiptDeliveryCommitted) {
    try {
      revokeExactCanvasRuntimeIntegration();
    } catch {
      cleanupFailed = true;
    }
  }
  if (cleanupFailed) {
    throw new TypeError('Exact GPU Canvas integration handoff cleanup failed');
  }
  if (evaluationSucceeded && handoffWasReplaced) {
    throw new TypeError('Exact GPU Canvas integration handoff was replaced');
  }
  if (evaluationSucceeded && phase === 'consumed' && !accepted) {
    throw new TypeError('Exact GPU Canvas integration capture was not accepted');
  }
  return accepted;
}

/**
 * Register the authenticated construction handoff and bind the app-realm
 * wrapper install to the same native revoker. The generated executable bundle
 * is injected only after Ibex has authenticated and opened a V2 service; a
 * crosses only after the authenticated V2 bridge has opened its native service
 * and realm. Importing the generic wrapper carries no ambient provider or
 * platform-support authority, and a runtime without that bridge publishes no
 * WebGPU surface.
 */
export function installNativeGpuBridgeCapture(
  globalObject: typeof globalThis,
): void {
  installCapture(globalObject, (bridge) => {
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
      'app',
    );
    if (installation.status !== 'installed') return undefined;
    activeCanvasContextMinter = installation.canvasContextMinter;
    canvasReceiptDeliveryActive = true;
    return objectFreeze({
      revoke() {
        try {
          // Terminal reduction closes public globals and every retained
          // wrapper before invoking an app-owned Canvas minter revoker.
          installation.revoke();
          if (canvasAppBundlePhase !== 'closed') {
            finishExactGpuCanvasAppBundle(false);
          }
        } finally {
          activeCanvasContextMinter = undefined;
          canvasReceiptDeliveryActive = false;
          canvasReceiptDeliveryCommitted = false;
          canvasAppBundlePrepared = false;
          try {
            revokeExactCanvasRuntimeIntegration();
          } finally {
            installation.revoke();
          }
        }
      },
      canvasReceiptSink,
      checkpointHostTask: installation.checkpointHostTask,
      beginCanvasAppBundle(expectation: CanvasAppBundleBeginPhase) {
        return beginExactGpuCanvasAppBundle(globalObject, expectation);
      },
      finishCanvasAppBundle: finishExactGpuCanvasAppBundle,
    });
  });
}

/** The generated wrapper resolves the bridge from bootstrap's module graph. */
export function nativeGpuBridgeForGeneratedWrapper(): NativeGpuBridge | undefined {
  return getNativeGpuBridge();
}

/** Test-only reset for construction-order and one-shot fixtures. */
export function resetExactGpuCanvasRuntimeIntegrationForTests(): void {
  if (canvasAppBundlePhase !== 'closed') {
    try {
      finishExactGpuCanvasAppBundle(false);
    } catch {
      if (canvasAppBundleGlobal) {
        reflectDeleteProperty(
          canvasAppBundleGlobal,
          CANVAS_INTEGRATION_CAPTURE_NAME,
        );
      }
    }
  }
  try {
    revokeExactCanvasRuntimeIntegration();
  } catch {
    // Test reset must still restore the module state after a throwing fixture.
  }
  activeCanvasContextMinter = undefined;
  canvasReceiptDeliveryActive = false;
  canvasReceiptDeliveryCommitted = false;
  canvasAppBundleGlobal = undefined;
  canvasAppBundleCapture = undefined;
  canvasAppBundleCaptureAccepted = false;
  canvasAppBundleExpectation = undefined;
  canvasAppBundlePhase = 'closed';
}
