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
import { installProductionWebGpu } from './production-wrapper';

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
    return installation.status === 'installed' ? installation.revoke : undefined;
  });
}

/** The generated wrapper resolves the bridge from bootstrap's module graph. */
export function nativeGpuBridgeForGeneratedWrapper(): NativeGpuBridge | undefined {
  return getNativeGpuBridge();
}
