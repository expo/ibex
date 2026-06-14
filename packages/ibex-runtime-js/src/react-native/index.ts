import { detectPlatform } from '../internal/detect';
import { window as exactWindow } from '../window';

type AppStateStatus = 'active' | 'background' | 'inactive' | 'unknown';
type ColorSchemeName = 'light' | 'dark' | null | undefined;
type PlatformOS =
  | 'ios'
  | 'android'
  | 'macos'
  | 'windows'
  | 'linux'
  | 'web'
  | 'native'
  | 'unknown';

interface EmitterSubscription {
  remove(): void;
}

interface ScaledSize {
  width: number;
  height: number;
  scale: number;
  fontScale: number;
}

interface DimensionsValue {
  window: ScaledSize;
  screen: ScaledSize;
}

interface DimensionsChangePayload {
  window: ScaledSize;
  screen: ScaledSize;
}

interface AppearancePreferences {
  colorScheme: ColorSchemeName;
}

interface AppearanceChangePayload {
  colorScheme: ColorSchemeName;
}

interface LinkingUrlEvent {
  url: string;
}

type DimensionsChangeHandler = (payload: DimensionsChangePayload) => void;
type AppearanceChangeHandler = (payload: AppearanceChangePayload) => void;
type AppStateChangeHandler = (state: AppStateStatus) => void;
type AppStateEventHandler = () => void;
type LinkingUrlHandler = (event: LinkingUrlEvent) => void;

type PlatformSelectSpec<T> = Partial<Record<PlatformOS | 'default', T>>;

declare global {
  var __exactInitialURL: string | null | undefined;
  var __exactOpenURL:
    | ((url: string) => boolean | void | Promise<boolean | void>)
    | undefined;
  var __exactCanOpenURL:
    | ((url: string) => boolean | Promise<boolean>)
    | undefined;
  var __exactReactNativeNotifyURL:
    | ((url: string) => void)
    | undefined;
  var __exactReactNativeNotifyAppState:
    | ((state: AppStateStatus) => void)
    | undefined;
  var __exactReactNativeNotifyMemoryWarning:
    | (() => void)
    | undefined;
  var __exactReactNativeNotifyDimensionsChange:
    | ((next?: Partial<DimensionsValue>) => void)
    | undefined;
  var __exactAppState: AppStateStatus | undefined;
}

function normalizePlatform(value: string): PlatformOS {
  const normalized = value.toLowerCase();
  if (normalized === 'darwin' || normalized === 'mac') {
    return 'macos';
  }
  if (normalized === 'win32') {
    return 'windows';
  }
  if (
    normalized === 'ios' ||
    normalized === 'android' ||
    normalized === 'macos' ||
    normalized === 'windows' ||
    normalized === 'linux' ||
    normalized === 'web' ||
    normalized === 'native'
  ) {
    return normalized;
  }
  return 'unknown';
}

function currentPlatform(): PlatformOS {
  return normalizePlatform(detectPlatform());
}

function screenInfo(): ScaledSize {
  const nativeInfo =
    typeof globalThis.__exactGetScreenInfo === 'function'
      ? globalThis.__exactGetScreenInfo()
      : null;

  return {
    width: nativeInfo?.width ?? exactWindow.innerWidth,
    height: nativeInfo?.height ?? exactWindow.innerHeight,
    scale: nativeInfo?.scale ?? exactWindow.devicePixelRatio,
    fontScale: nativeInfo?.fontScale ?? 1,
  };
}

function currentDimensions(): DimensionsValue {
  const current = screenInfo();
  return {
    window: { ...current },
    screen: { ...current },
  };
}

function normalizeDimensions(next?: Partial<DimensionsValue>): DimensionsValue {
  const fallback = currentDimensions();
  return {
    window: { ...fallback.window, ...next?.window },
    screen: { ...fallback.screen, ...next?.screen },
  };
}

const dimensionsListeners = new Set<DimensionsChangeHandler>();
let lastDimensions = currentDimensions();

function notifyDimensions(next?: Partial<DimensionsValue>): void {
  lastDimensions = normalizeDimensions(next);
  const payload: DimensionsChangePayload = {
    window: { ...lastDimensions.window },
    screen: { ...lastDimensions.screen },
  };
  for (const listener of [...dimensionsListeners]) {
    listener(payload);
  }
}

globalThis.__exactReactNativeNotifyDimensionsChange = notifyDimensions;

export const Dimensions = {
  get(dimension: 'window' | 'screen'): ScaledSize {
    const dimensions = currentDimensions();
    return { ...dimensions[dimension] };
  },
  addEventListener(
    eventType: 'change',
    handler: DimensionsChangeHandler,
  ): EmitterSubscription {
    if (eventType !== 'change') {
      return { remove() {} };
    }
    dimensionsListeners.add(handler);
    return {
      remove() {
        dimensionsListeners.delete(handler);
      },
    };
  },
  removeEventListener(
    eventType: 'change',
    handler: DimensionsChangeHandler,
  ): void {
    if (eventType === 'change') {
      dimensionsListeners.delete(handler);
    }
  },
};

export const Platform = {
  get OS(): PlatformOS {
    return currentPlatform();
  },
  get Version(): string {
    const runtime = globalThis as { __exactPlatformVersion?: unknown };
    return typeof runtime.__exactPlatformVersion === 'string'
      ? runtime.__exactPlatformVersion
      : '0';
  },
  get isPad(): boolean {
    const dimensions = Dimensions.get('screen');
    return Platform.OS === 'ios' && Math.min(dimensions.width, dimensions.height) >= 768;
  },
  get isTV(): boolean {
    return false;
  },
  get isTesting(): boolean {
    return Boolean((globalThis as { __exactIsTesting?: unknown }).__exactIsTesting);
  },
  select<T>(spec: PlatformSelectSpec<T>): T | undefined {
    const os = Platform.OS;
    return spec[os] ?? spec.default;
  },
};

function currentColorScheme(): ColorSchemeName {
  const state = globalThis.__exactAppearanceState;
  return state?.colorScheme === 'dark' ? 'dark' : 'light';
}

const appearanceListeners = new Set<AppearanceChangeHandler>();
const previousAppearanceNotifier = globalThis.__exactWindowNotifyMediaChange;

function notifyAppearance(next: AppearancePreferences): void {
  previousAppearanceNotifier?.({
    colorScheme: next.colorScheme === 'dark' ? 'dark' : 'light',
  });
  const payload = { colorScheme: currentColorScheme() };
  for (const listener of [...appearanceListeners]) {
    listener(payload);
  }
}

globalThis.__exactWindowNotifyMediaChange = (next) => {
  previousAppearanceNotifier?.(next);
  const payload = { colorScheme: currentColorScheme() };
  for (const listener of [...appearanceListeners]) {
    listener(payload);
  }
};

export const Appearance = {
  getColorScheme(): ColorSchemeName {
    return currentColorScheme();
  },
  addChangeListener(listener: AppearanceChangeHandler): EmitterSubscription {
    appearanceListeners.add(listener);
    return {
      remove() {
        appearanceListeners.delete(listener);
      },
    };
  },
  removeChangeListener(listener: AppearanceChangeHandler): void {
    appearanceListeners.delete(listener);
  },
  setColorScheme(colorScheme: ColorSchemeName): void {
    notifyAppearance({ colorScheme });
  },
};

const appStateChangeListeners = new Set<AppStateChangeHandler>();
const appStateFocusListeners = new Set<AppStateEventHandler>();
const appStateBlurListeners = new Set<AppStateEventHandler>();
const appStateMemoryWarningListeners = new Set<AppStateEventHandler>();

function normalizeAppState(state: unknown): AppStateStatus {
  return state === 'active' || state === 'background' || state === 'inactive'
    ? state
    : 'unknown';
}

let currentAppState: AppStateStatus = normalizeAppState(globalThis.__exactAppState) === 'unknown'
  ? 'active'
  : normalizeAppState(globalThis.__exactAppState);

function notifyAppState(state: AppStateStatus): void {
  const previous = currentAppState;
  currentAppState = normalizeAppState(state);
  globalThis.__exactAppState = currentAppState;

  if (previous !== currentAppState) {
    for (const listener of [...appStateChangeListeners]) {
      listener(currentAppState);
    }
  }
  if (currentAppState === 'active' && previous !== 'active') {
    for (const listener of [...appStateFocusListeners]) {
      listener();
    }
  }
  if (currentAppState !== 'active' && previous === 'active') {
    for (const listener of [...appStateBlurListeners]) {
      listener();
    }
  }
}

globalThis.__exactReactNativeNotifyAppState = notifyAppState;
globalThis.__exactReactNativeNotifyMemoryWarning = () => {
  for (const listener of [...appStateMemoryWarningListeners]) {
    listener();
  }
};

export const AppState = {
  get currentState(): AppStateStatus {
    return currentAppState;
  },
  addEventListener(
    type: 'change' | 'focus' | 'blur' | 'memoryWarning',
    listener: AppStateChangeHandler | AppStateEventHandler,
  ): EmitterSubscription {
    const target =
      type === 'change'
        ? appStateChangeListeners
        : type === 'focus'
          ? appStateFocusListeners
          : type === 'blur'
            ? appStateBlurListeners
            : appStateMemoryWarningListeners;
    target.add(listener as never);
    return {
      remove() {
        target.delete(listener as never);
      },
    };
  },
};

const linkingListeners = new Set<LinkingUrlHandler>();

function notifyURL(url: string): void {
  for (const listener of [...linkingListeners]) {
    listener({ url });
  }
}

globalThis.__exactReactNativeNotifyURL = notifyURL;

function normalizeURL(url: string): string {
  if (url.length === 0) {
    return exactWindow.location.href;
  }
  try {
    return new URL(url, exactWindow.location.href).href;
  } catch {
    return url;
  }
}

export const Linking = {
  async canOpenURL(url: string): Promise<boolean> {
    if (typeof globalThis.__exactCanOpenURL === 'function') {
      return Boolean(await globalThis.__exactCanOpenURL(url));
    }
    return /^(exact|https?|mailto|tel|sms):/i.test(url);
  },
  async openURL(url: string): Promise<void> {
    if (typeof globalThis.__exactOpenURL === 'function') {
      await globalThis.__exactOpenURL(url);
    } else {
      exactWindow.location.assign(normalizeURL(url));
    }
    notifyURL(normalizeURL(url));
  },
  async getInitialURL(): Promise<string | null> {
    return globalThis.__exactInitialURL ?? null;
  },
  addEventListener(
    type: 'url',
    handler: LinkingUrlHandler,
  ): EmitterSubscription {
    if (type !== 'url') {
      return { remove() {} };
    }
    linkingListeners.add(handler);
    return {
      remove() {
        linkingListeners.delete(handler);
      },
    };
  },
  removeEventListener(type: 'url', handler: LinkingUrlHandler): void {
    if (type === 'url') {
      linkingListeners.delete(handler);
    }
  },
};

export default {
  AppState,
  Appearance,
  Dimensions,
  Linking,
  Platform,
};
