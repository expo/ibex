/**
 * Internal detection utilities
 * 
 * These are used by modules that need to detect engine/platform
 * WITHOUT importing from bootstrap (to avoid circular dependencies).
 */

/**
 * Get the runtime version
 */
export function getRuntimeVersion(): string {
  return "0.1.0";
}

/**
 * Detect the JavaScript engine at runtime.
 */
export function detectEngine(): "Hermes" | "JSC" | "V8" | "browser" | "unknown" {
  const g = globalThis as any;

  // Hermes detection
  if (typeof g.HermesInternal !== "undefined") {
    return "Hermes";
  }

  // Browser detection (must come before V8 check since Chrome has both)
  if (typeof document !== "undefined" && typeof document.createElement === "function") {
    return "browser";
  }

  // V8 detection (Node.js or standalone V8)
  if (typeof g.v8debug !== "undefined" || g._v8runtime) {
    return "V8";
  }

  // JSC detection (JavaScriptCore specific globals)
  if (typeof g.gc === "function" && !g.v8debug) {
    return "JSC";
  }

  return "unknown";
}

/**
 * Detect the platform at runtime.
 * Note: This must NOT access navigator to avoid circular dependency.
 */
export function detectPlatform(): string {
  const g = globalThis as any;

  if (typeof g.__exactPlatform === "string" && g.__exactPlatform.length > 0) {
    return g.__exactPlatform;
  }

  // Browser/web detection (check for DOM document, not our window shim)
  if (typeof document !== "undefined" && typeof document.createElement === "function") {
    return "web";
  }

  // If process exists (CLI/Node-like), prefer it unless it's Exact's process shim.
  const hostProcess = g.process;
  if (hostProcess) {
    let isExactProcess = false;
    try {
      const versions = hostProcess.versions;
      isExactProcess = !!(versions && typeof versions === "object" && (typeof versions.ibex === "string" || typeof versions.exact === "string"));
    } catch {
      isExactProcess = false;
    }
    if (!isExactProcess) {
      try {
        const platform = hostProcess.platform;
        if (typeof platform === "string" && platform.length > 0) {
          return platform;
        }
      } catch {
        // Ignore host process platform lookup errors and continue fallback chain.
      }
    }
  }

  // Check for Hermes-specific platform hints
  if (typeof g.HermesInternal !== "undefined") {
    // Hermes is used in Exact for iOS/Android
    // Default to iOS since that's our primary target
    return "ios";
  }

  return "unknown";
}

/**
 * Runtime info object with lazy getters
 */
export const runtimeInfo = {
  name: "Exact",
  version: getRuntimeVersion(),
  get engine() {
    return detectEngine();
  },
  get platform() {
    return detectPlatform();
  },
};
