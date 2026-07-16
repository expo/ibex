// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// This module is bundled with bootstrap and the eventual generated WebGPU
// wrapper. Ibex's app module loader rejects every source under this directory,
// so this forwarding layer is not an app import surface.

import {
  getNativeGpuBridge,
  installNativeGpuBridgeCapture,
  type NativeGpuBridge,
} from './native-bridge';

export { installNativeGpuBridgeCapture };

/** The generated wrapper resolves the bridge from bootstrap's module graph. */
export function nativeGpuBridgeForGeneratedWrapper(): NativeGpuBridge | undefined {
  return getNativeGpuBridge();
}
