// @system @ref LLP 0011#state-modules — accessibility preferences in shared runtime state.
import { hostCallBridge } from "./host-call-bridge.js";
import {
  addExactAccessibilityEventListener,
  getExactAccessibilitySnapshot,
  readNativeAccessibilitySnapshot,
  subscribeExactAccessibilityChanges,
  updateAccessibilitySnapshot,
  type AccessibilityEventListener,
  type AccessibilityInfoEvent,
  type AccessibilityInfoKey,
  type ExactAccessibilitySnapshot,
  type NativeAccessibilitySnapshot,
} from "./accessibility-state.js";

export {
  _resetExactAccessibilityForTests,
  getExactAccessibilitySnapshot,
  refreshExactAccessibility,
  subscribeExactAccessibilityChanges,
  type AccessibilityInfoEvent,
  type AccessibilityInfoKey,
  type ExactAccessibilitySnapshot,
} from "./accessibility-state.js";

interface ExactAccessibilityNamespace {
  readonly prefersReducedMotion: boolean;
  readonly isBoldTextEnabled: boolean;
  readonly prefersHighContrast: boolean;
  readonly prefersReducedTransparency: boolean;
  readonly fontScale: number;
  readonly isScreenReaderEnabled: boolean;
  readonly colorScheme: "light" | "dark";
  readonly isInvertColorsEnabled: boolean;
  readonly isGrayscaleEnabled: boolean;
  readonly dynamicTypeSize: string | null;
  get<K extends AccessibilityInfoKey>(key: K): ExactAccessibilitySnapshot[K];
  addEventListener(event: AccessibilityInfoEvent, listener: AccessibilityEventListener): () => void;
  announce(message: string, options?: { queue?: boolean }): boolean;
}

function createAccessibilityNamespace(): ExactAccessibilityNamespace {
  return {
    get prefersReducedMotion() {
      return getExactAccessibilitySnapshot().prefersReducedMotion;
    },
    get isBoldTextEnabled() {
      return getExactAccessibilitySnapshot().isBoldTextEnabled;
    },
    get prefersHighContrast() {
      return getExactAccessibilitySnapshot().prefersHighContrast;
    },
    get prefersReducedTransparency() {
      return getExactAccessibilitySnapshot().prefersReducedTransparency;
    },
    get fontScale() {
      return getExactAccessibilitySnapshot().fontScale;
    },
    get isScreenReaderEnabled() {
      return getExactAccessibilitySnapshot().isScreenReaderEnabled;
    },
    get colorScheme() {
      return getExactAccessibilitySnapshot().colorScheme;
    },
    get isInvertColorsEnabled() {
      return getExactAccessibilitySnapshot().isInvertColorsEnabled;
    },
    get isGrayscaleEnabled() {
      return getExactAccessibilitySnapshot().isGrayscaleEnabled;
    },
    get dynamicTypeSize() {
      return getExactAccessibilitySnapshot().dynamicTypeSize;
    },
    get(key) {
      return getExactAccessibilitySnapshot()[key];
    },
    addEventListener(event, listener) {
      return addExactAccessibilityEventListener(event, listener);
    },
    announce(message, options) {
      return announceForAccessibility(message, options);
    },
  };
}

export function installExactAccessibilityGlobal(): ExactAccessibilityNamespace {
  const g = globalThis as typeof globalThis & {
    Exact?: Record<string, unknown>;
  };

  if (typeof g.Exact !== "object" || g.Exact === null) {
    g.Exact = {};
  }

  const exact = g.Exact as Record<string, unknown>;
  const existing = exact.accessibility;
  if (
    existing &&
    typeof existing === "object" &&
    typeof (existing as ExactAccessibilityNamespace).addEventListener === "function"
  ) {
    return existing as ExactAccessibilityNamespace;
  }

  updateAccessibilitySnapshot(readNativeAccessibilitySnapshot(), false);

  const accessibility = createAccessibilityNamespace();
  Object.defineProperty(exact, "accessibility", {
    value: accessibility,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  globalThis.__exactAccessibilityChanged = (snapshot?: NativeAccessibilitySnapshot | null) => {
    if (snapshot && typeof snapshot === "object") {
      globalThis.__exactAccessibilitySnapshot = snapshot;
    }
    updateAccessibilitySnapshot(snapshot ?? readNativeAccessibilitySnapshot(), true);
  };

  return accessibility;
}

export function announceForAccessibility(
  message: string,
  options: { queue?: boolean } = {},
): boolean {
  if (typeof message !== "string" || message.trim().length === 0) {
    return false;
  }

  const hostCall = hostCallBridge();
  if (!hostCall) {
    return false;
  }

  try {
    const result = hostCall(
      "accessibility.announce",
      JSON.stringify({
        message,
        queue: options.queue !== false,
      }),
    );
    return result !== false;
  } catch {
    return false;
  }
}

export function focusElementForAccessibility(
  target:
    | { readonly viewId: number }
    | { readonly nativeID: string }
    | { readonly testId: string },
): boolean {
  const hostCall = hostCallBridge();
  if (!hostCall) {
    return false;
  }

  try {
    const result = hostCall("accessibility.focus", JSON.stringify(target));
    return result !== false;
  } catch {
    return false;
  }
}

export const AccessibilityInfo = {
  get<K extends AccessibilityInfoKey>(key: K): ExactAccessibilitySnapshot[K] {
    return getExactAccessibilitySnapshot()[key];
  },
  addEventListener(
    event: AccessibilityInfoEvent,
    listener: AccessibilityEventListener,
  ): () => void {
    return addExactAccessibilityEventListener(event, listener);
  },
  announce(message: string, options?: { queue?: boolean }): boolean {
    return announceForAccessibility(message, options);
  },
} as const;
