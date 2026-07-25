/**
 * Runtime entry for builds without the optional WebGPU provider seam.
 *
 * Keep the small one-shot construction capture so native can prove and close
 * the reserved handoff exactly as it does in WebGPU builds, without embedding
 * the production wrapper and generated codec graph that can never be used.
 */

import {
  installGlobals,
  areGlobalsInstalled,
  getRuntimeVersion,
  detectEngine,
  detectPlatform,
  runtimeInfo,
} from './bootstrap.js';
import { installNativeGpuBridgeCapture } from './webgpu/native-bridge';

installNativeGpuBridgeCapture(globalThis);
installGlobals();

(globalThis as any).__exactRuntime = {
  version: getRuntimeVersion(),
  installed: true,
  installedAt: Date.now(),
  engine: detectEngine(),
  platform: detectPlatform(),
};

const g = globalThis as any;
if (!g.exact) {
  g.exact = {};
}
g.exact.runtime = {
  version: getRuntimeVersion(),
  info: runtimeInfo,
  isInstalled: areGlobalsInstalled,
  detectEngine,
  detectPlatform,
};

try {
  if (!(globalThis as any).__exactSuppressRuntimeBanner) {
    console.log(`[Ibex Runtime v${getRuntimeVersion()}] Installed (${detectEngine()})`);
  }
} catch {
  // Console is optional during trusted bootstrap.
}
