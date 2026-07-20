/**
 * Ibex Runtime Entry Point
 *
 * This file is the entry point for building the standalone runtime bundle.
 * It installs all web-standard globals and exposes runtime utilities.
 *
 * Build: vite build --config vite.config.runtime.ts
 * Output: dist/runtime.js -> hermesc -> dist/runtime.hbc
 */

import { installGlobals, areGlobalsInstalled, getRuntimeVersion, detectEngine, detectPlatform, runtimeInfo } from './bootstrap.js';
import { installNativeGpuBridgeCapture } from './webgpu/runtime-internal';

// Agent runtime is loaded on demand (when EXACT_AGENT_BOOT=1), not during
// core runtime startup.  Importing it here pulled in the renderer/inspector
// module graph (React, Solid, Vue, etc.) and inflated the runtime bundle
// from ~100 KB to >2 MB, adding >10 ms of HBC evaluation on every startup.
// The agent bootstrap is now loaded lazily by the CLI when agent mode is
// explicitly requested.
// import '../agent/runtime-bootstrap.js';

// Install the construction-only bridge handoff only in this trusted embedded
// entry graph, never when an app imports the public `./bootstrap` subpath. The
// C++ finalizer invokes it directly and it deletes itself; the common runtime
// entry gate closes an unused handoff before app/module/debugger execution.
installNativeGpuBridgeCapture(globalThis);

// Install globals immediately when the runtime loads
installGlobals();

// Mark the runtime as installed with version info
(globalThis as any).__exactRuntime = {
  version: getRuntimeVersion(),
  installed: true,
  installedAt: Date.now(),
  engine: detectEngine(),
  platform: detectPlatform(),
};

// Expose runtime utilities on the exact global (created by native layer)
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

// Log that the runtime was installed (will be visible if console is set up)
// Using try-catch in case console isn't ready yet
try {
  if (!(globalThis as any).__exactSuppressRuntimeBanner) {
    console.log(`[Ibex Runtime v${getRuntimeVersion()}] Installed (${detectEngine()})`);
  }
} catch {
  // Console not ready yet, that's fine
}
