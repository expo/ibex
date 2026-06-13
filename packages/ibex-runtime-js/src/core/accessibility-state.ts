// @system @ref LLP 0141 — Renderer startup imports only accessibility state.
export interface ExactAccessibilitySnapshot {
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
}

export interface NativeAccessibilitySnapshot {
  readonly prefersReducedMotion?: boolean;
  readonly isBoldTextEnabled?: boolean;
  readonly prefersHighContrast?: boolean;
  readonly prefersReducedTransparency?: boolean;
  readonly fontScale?: number;
  readonly isScreenReaderEnabled?: boolean;
  readonly colorScheme?: "light" | "dark";
  readonly isInvertColorsEnabled?: boolean;
  readonly isGrayscaleEnabled?: boolean;
  readonly dynamicTypeSize?: string | null;
}

export type AccessibilityInfoKey = keyof ExactAccessibilitySnapshot;
export type AccessibilityInfoEvent =
  | "change"
  | "reduceMotionChanged"
  | "boldTextChanged"
  | "highContrastChanged"
  | "reducedTransparencyChanged"
  | "fontScaleChanged"
  | "screenReaderChanged"
  | "colorSchemeChanged"
  | "invertColorsChanged"
  | "grayscaleChanged"
  | "dynamicTypeSizeChanged";

export type ExactAccessibilityListener = (snapshot: ExactAccessibilitySnapshot) => void;
export type AccessibilityEventListener = (value: unknown) => void;

interface ExactAccessibilityRuntimeState {
  snapshot: ExactAccessibilitySnapshot;
  listeners: Set<ExactAccessibilityListener>;
  eventListeners: Map<AccessibilityInfoEvent, Set<AccessibilityEventListener>>;
  changeTimer: ReturnType<typeof setTimeout> | null;
}

declare global {
  // eslint-disable-next-line no-var
  var __exactAccessibilityState: ExactAccessibilityRuntimeState | undefined;
  // eslint-disable-next-line no-var
  var __exactAccessibilitySnapshot: NativeAccessibilitySnapshot | undefined;
  // eslint-disable-next-line no-var
  var __exactAccessibilityChanged:
    | ((snapshot?: NativeAccessibilitySnapshot | null) => void)
    | undefined;
  // eslint-disable-next-line no-var
  var __exactAppearanceState:
    | {
        colorScheme?: "light" | "dark";
        reducedMotion?: boolean;
      }
    | undefined;
  // eslint-disable-next-line no-var
  var __exactWindowNotifyMediaChange:
    | ((next: { colorScheme?: "light" | "dark"; reducedMotion?: boolean }) => void)
    | undefined;
}

function freezeSnapshot(snapshot: ExactAccessibilitySnapshot): ExactAccessibilitySnapshot {
  return Object.freeze({ ...snapshot });
}

function normalizeFontScale(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 1;
}

export function readNativeAccessibilitySnapshot(): NativeAccessibilitySnapshot | null {
  const nativeSnapshot = globalThis.__exactAccessibilitySnapshot;
  if (nativeSnapshot && typeof nativeSnapshot === "object") {
    return nativeSnapshot;
  }

  const appearanceState = globalThis.__exactAppearanceState;
  if (appearanceState && typeof appearanceState === "object") {
    return {
      colorScheme: appearanceState.colorScheme === "dark" ? "dark" : "light",
      prefersReducedMotion: appearanceState.reducedMotion === true,
    };
  }

  return null;
}

function buildAccessibilitySnapshot(
  value: NativeAccessibilitySnapshot | null,
): ExactAccessibilitySnapshot {
  return freezeSnapshot({
    prefersReducedMotion: value?.prefersReducedMotion === true,
    isBoldTextEnabled: value?.isBoldTextEnabled === true,
    prefersHighContrast: value?.prefersHighContrast === true,
    prefersReducedTransparency: value?.prefersReducedTransparency === true,
    fontScale: normalizeFontScale(value?.fontScale),
    isScreenReaderEnabled: value?.isScreenReaderEnabled === true,
    colorScheme: value?.colorScheme === "dark" ? "dark" : "light",
    isInvertColorsEnabled: value?.isInvertColorsEnabled === true,
    isGrayscaleEnabled: value?.isGrayscaleEnabled === true,
    dynamicTypeSize:
      typeof value?.dynamicTypeSize === "string" && value.dynamicTypeSize.length > 0
        ? value.dynamicTypeSize
        : null,
  });
}

function createDefaultState(): ExactAccessibilityRuntimeState {
  return {
    snapshot: buildAccessibilitySnapshot(readNativeAccessibilitySnapshot()),
    listeners: new Set(),
    eventListeners: new Map(),
    changeTimer: null,
  };
}

function getAccessibilityState(): ExactAccessibilityRuntimeState {
  if (!globalThis.__exactAccessibilityState) {
    globalThis.__exactAccessibilityState = createDefaultState();
  }
  return globalThis.__exactAccessibilityState;
}

function dispatchAccessibilityChange(state: ExactAccessibilityRuntimeState): void {
  const snapshot = state.snapshot;
  for (const listener of state.listeners) {
    try {
      listener(snapshot);
    } catch {
      // Ignore listener failures.
    }
  }
}

function emitNamedEvent(
  state: ExactAccessibilityRuntimeState,
  event: AccessibilityInfoEvent,
  value: unknown,
): void {
  const listeners = state.eventListeners.get(event);
  if (!listeners) {
    return;
  }

  for (const listener of listeners) {
    try {
      listener(value);
    } catch {
      // Ignore listener failures.
    }
  }
}

function scheduleAccessibilityChange(state: ExactAccessibilityRuntimeState): void {
  if (state.changeTimer != null) {
    clearTimeout(state.changeTimer);
  }

  state.changeTimer = setTimeout(() => {
    state.changeTimer = null;
    dispatchAccessibilityChange(state);
  }, 100);
}

function updateAppearanceMirror(snapshot: ExactAccessibilitySnapshot): void {
  globalThis.__exactAppearanceState = {
    colorScheme: snapshot.colorScheme,
    reducedMotion: snapshot.prefersReducedMotion,
  };
  globalThis.__exactWindowNotifyMediaChange?.({
    colorScheme: snapshot.colorScheme,
    reducedMotion: snapshot.prefersReducedMotion,
  });
}

export function updateAccessibilitySnapshot(
  value: NativeAccessibilitySnapshot | null,
  notify: boolean,
): ExactAccessibilitySnapshot {
  const state = getAccessibilityState();
  const previous = state.snapshot;
  const next = buildAccessibilitySnapshot(value);
  state.snapshot = next;
  updateAppearanceMirror(next);

  const changedEntries = ([
    ["prefersReducedMotion", "reduceMotionChanged"],
    ["isBoldTextEnabled", "boldTextChanged"],
    ["prefersHighContrast", "highContrastChanged"],
    ["prefersReducedTransparency", "reducedTransparencyChanged"],
    ["fontScale", "fontScaleChanged"],
    ["isScreenReaderEnabled", "screenReaderChanged"],
    ["colorScheme", "colorSchemeChanged"],
    ["isInvertColorsEnabled", "invertColorsChanged"],
    ["isGrayscaleEnabled", "grayscaleChanged"],
    ["dynamicTypeSize", "dynamicTypeSizeChanged"],
  ] as const).filter(([key]) => previous[key] !== next[key]);

  if (notify && changedEntries.length > 0) {
    scheduleAccessibilityChange(state);
    for (const [key, event] of changedEntries) {
      emitNamedEvent(state, event, next[key]);
    }
    emitNamedEvent(state, "change", next);
  }

  return next;
}

export function subscribeExactAccessibilityChanges(
  listener: ExactAccessibilityListener,
): () => void {
  const state = getAccessibilityState();
  state.listeners.add(listener);
  return () => {
    state.listeners.delete(listener);
  };
}

export function addExactAccessibilityEventListener(
  event: AccessibilityInfoEvent,
  listener: AccessibilityEventListener,
): () => void {
  const state = getAccessibilityState();
  const listeners = state.eventListeners.get(event) ?? new Set<AccessibilityEventListener>();
  listeners.add(listener);
  state.eventListeners.set(event, listeners);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      state.eventListeners.delete(event);
    }
  };
}

export function getExactAccessibilitySnapshot(): ExactAccessibilitySnapshot {
  return getAccessibilityState().snapshot;
}

export function refreshExactAccessibility(): ExactAccessibilitySnapshot {
  return updateAccessibilitySnapshot(readNativeAccessibilitySnapshot(), true);
}

export function _resetExactAccessibilityForTests(): void {
  const state = globalThis.__exactAccessibilityState;
  if (state?.changeTimer != null) {
    clearTimeout(state.changeTimer);
  }
  delete globalThis.__exactAccessibilityState;
  delete globalThis.__exactAccessibilityChanged;
  delete globalThis.__exactAccessibilitySnapshot;
}
