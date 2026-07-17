// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// This module is bundled with bootstrap and the eventual generated WebGPU
// wrapper. Ibex's app module loader rejects every source under this directory,
// so this forwarding layer is not an app import surface.

import {
  getNativeGpuBridge,
  installNativeGpuBridgeCapture as installCapture,
  type NativeGpuBridge,
} from './native-bridge';
import { installProductionWebGpu } from './production-wrapper';

/**
 * Register the authenticated construction handoff and bind the app-realm
 * wrapper install to the same native revoker. The current embedded codec
 * authority is intentionally absent, so this is a fail-closed no-op until a
 * reviewed executable codec bundle lands.
 */
export function installNativeGpuBridgeCapture(
  globalObject: typeof globalThis,
): void {
  installCapture(globalObject, (bridge) => {
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      undefined,
      'app',
    );
    return installation.status === 'installed' ? installation.revoke : undefined;
  });
}

/** The generated wrapper resolves the bridge from bootstrap's module graph. */
export function nativeGpuBridgeForGeneratedWrapper(): NativeGpuBridge | undefined {
  return getNativeGpuBridge();
}
