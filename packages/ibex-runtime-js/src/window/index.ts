// @ts-nocheck
/**
 * Window API Implementation for Exact Runtime
 *
 * Provides browser-compatible window object for library compatibility.
 * Many npm packages check for `typeof window !== 'undefined'` to detect
 * browser environments.
 *
 * Note: This is NOT a DOM window - it's a compatibility shim that provides
 * commonly-used window properties that make sense in a native app context.
 */

import { CustomEvent, Event, EventTarget } from "../events";

// Type declarations for native bridge
declare global {
  var __exactGetScreenInfo: (() => {
    width: number;
    height: number;
    scale: number;
    fontScale: number;
  }) | undefined;
  var __exactAppearanceState:
    | {
        colorScheme?: 'light' | 'dark';
        reducedMotion?: boolean;
      }
    | undefined;
  var __exactWindowNotifyMediaChange:
    | ((next: { colorScheme?: 'light' | 'dark'; reducedMotion?: boolean }) => void)
    | undefined;
  var __exactWindowNotifyResize: (() => void) | undefined;
  var __exactAndroidDispatchPlatformEvent:
    | ((event: string | AndroidPlatformEvent, state?: AndroidPlatformState | null) => void)
    | undefined;
  var __exactAndroidDrainPlatformEvents: (() => void) | undefined;
  var __exactAndroidGetPlatformState: (() => AndroidPlatformState) | undefined;
  var __exactAppState: AndroidAppState | undefined;
  var __exactInitialURL: string | null | undefined;
  var __exactLocaleChanged:
    | ((snapshot?: { tag?: string; tags?: readonly string[]; uses24Hour?: boolean } | null) => void)
    | undefined;
  var __exactAccessibilityChanged:
    | ((snapshot?: Record<string, unknown> | null) => void)
    | undefined;
  var __exactReactNativeNotifyDimensionsChange:
    | ((next?: AndroidPlatformState['dimensions']) => void)
    | undefined;
  var __exactReactNativeNotifyAppState:
    | ((state: AndroidAppState) => void)
    | undefined;
  var __exactReactNativeNotifyMemoryWarning: (() => void) | undefined;
  var __exactReactNativeNotifyURL: ((url: string) => void) | undefined;
}

type AndroidAppState = 'active' | 'background' | 'inactive' | 'unknown';

interface AndroidPlatformEvent {
  type?: string;
  state?: AndroidAppState;
  url?: string;
}

interface AndroidPlatformState {
  appState?: AndroidAppState;
  initialURL?: string | null;
  locale?: { tag?: string; tags?: readonly string[]; uses24Hour?: boolean };
  screen?: {
    width?: number;
    height?: number;
    scale?: number;
    fontScale?: number;
  };
  dimensions?: {
    window?: {
      width?: number;
      height?: number;
      scale?: number;
      fontScale?: number;
    };
    screen?: {
      width?: number;
      height?: number;
      scale?: number;
      fontScale?: number;
    };
  };
  appearance?: {
    colorScheme?: 'light' | 'dark';
    reducedMotion?: boolean;
  };
  accessibility?: Record<string, unknown>;
}

/**
 * Screen information
 */
export interface ScreenInfo {
  /** Screen width in points */
  width: number;
  /** Screen height in points */
  height: number;
  /** Available width (minus system UI) */
  availWidth: number;
  /** Available height (minus system UI) */
  availHeight: number;
  /** Color depth (always 24 for mobile) */
  colorDepth: number;
  /** Pixel depth (always 24 for mobile) */
  pixelDepth: number;
  /** Screen orientation */
  orientation: {
    type: 'portrait-primary' | 'portrait-secondary' | 'landscape-primary' | 'landscape-secondary';
    angle: number;
  };
}

/**
 * Location stub for compatibility
 * In a native app, this represents the current "virtual" location
 */
export interface LocationInfo {
  href: string;
  protocol: string;
  host: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  origin: string;
  reload: () => void;
  replace: (url: string) => void;
  assign: (url: string) => void;
}

/**
 * Get screen dimensions from native or use defaults
 */
function getScreenDimensions(): { width: number; height: number; scale: number; fontScale: number } {
  if (typeof __exactGetScreenInfo === 'function') {
    const info = __exactGetScreenInfo();
    return {
      width: info.width,
      height: info.height,
      scale: info.scale,
      fontScale: info.fontScale,
    };
  }
  // Default fallback (iPhone 14 Pro dimensions)
  return { width: 393, height: 852, scale: 3, fontScale: 1 };
}

function getScreenOrientation(): ScreenInfo['orientation'] {
  const dims = getScreenDimensions();
  const landscape = dims.width > dims.height;
  return {
    type: landscape ? 'landscape-primary' : 'portrait-primary',
    angle: landscape ? 90 : 0,
  };
}

/**
 * Create the screen object
 */
function createScreen(): ScreenInfo {
  const dims = getScreenDimensions();
  
  return {
    get width() {
      return getScreenDimensions().width;
    },
    get height() {
      return getScreenDimensions().height;
    },
    get availWidth() {
      return getScreenDimensions().width;
    },
    get availHeight() {
      // Subtract status bar height approximation
      return getScreenDimensions().height - 47;
    },
    colorDepth: 24,
    pixelDepth: 24,
    orientation: {
      get type() {
        return getScreenOrientation().type;
      },
      get angle() {
        return getScreenOrientation().angle;
      },
    },
  };
}

/**
 * Create location stub
 */
function createLocation(): LocationInfo {
  // In native apps, we use a virtual location
  // Apps can override this if they implement deep linking
  let currentHref = 'exact://app/';
  
  const parseUrl = (href: string) => {
    try {
      const url = new URL(href);
      return {
        href: url.href,
        protocol: url.protocol,
        host: url.host,
        hostname: url.hostname,
        port: url.port,
        pathname: url.pathname,
        search: url.search,
        hash: url.hash,
        origin: url.origin,
      };
    } catch {
      return {
        href,
        protocol: 'exact:',
        host: 'app',
        hostname: 'app',
        port: '',
        pathname: '/',
        search: '',
        hash: '',
        origin: 'exact://app',
      };
    }
  };

  const location: LocationInfo = {
    get href() { return parseUrl(currentHref).href; },
    get protocol() { return parseUrl(currentHref).protocol; },
    get host() { return parseUrl(currentHref).host; },
    get hostname() { return parseUrl(currentHref).hostname; },
    get port() { return parseUrl(currentHref).port; },
    get pathname() { return parseUrl(currentHref).pathname; },
    get search() { return parseUrl(currentHref).search; },
    get hash() { return parseUrl(currentHref).hash; },
    get origin() { return parseUrl(currentHref).origin; },
    toString() { return parseUrl(currentHref).href; },
    reload: () => {
      // No-op in native - could trigger app refresh
      console.warn('location.reload() is not supported in Exact runtime');
    },
    replace: (url: string) => {
      currentHref = url;
    },
    assign: (url: string) => {
      currentHref = url;
    },
  };

  return location;
}

interface AppearanceState {
  colorScheme: 'light' | 'dark';
  reducedMotion: boolean;
}

const mediaQueryLists = new Set<MediaQueryList>();

function normalizeAppearanceState(value: unknown): AppearanceState {
  const candidate =
    typeof value === 'object' && value !== null
      ? (value as { colorScheme?: unknown; reducedMotion?: unknown })
      : null;

  return {
    colorScheme: candidate?.colorScheme === 'dark' ? 'dark' : 'light',
    reducedMotion: candidate?.reducedMotion === true,
  };
}

let appearanceState = normalizeAppearanceState(globalThis.__exactAppearanceState);

function updateAppearanceState(next: unknown): void {
  appearanceState = normalizeAppearanceState(next);
  globalThis.__exactAppearanceState = { ...appearanceState };
  for (const mediaQueryList of mediaQueryLists) {
    mediaQueryList._syncFromAppearance();
  }
}

function syncMediaQueries(): void {
  for (const mediaQueryList of mediaQueryLists) {
    mediaQueryList._syncFromAppearance();
  }
}

function dispatchWindowEvent(event: Event): void {
  try {
    window.dispatchEvent(event);
  } catch {
    // Ignore app listener failures.
  }
  const globalDispatch = (globalThis as typeof globalThis & {
    dispatchEvent?: (event: Event) => boolean;
  }).dispatchEvent;
  if (typeof globalDispatch === 'function' && globalThis !== window) {
    try {
      globalDispatch.call(globalThis, event);
    } catch {
      // Ignore app listener failures.
    }
  }
}

function normalizeAndroidPlatformEvent(event: string | AndroidPlatformEvent): AndroidPlatformEvent {
  if (typeof event === 'string') {
    try {
      const parsed = JSON.parse(event);
      return parsed && typeof parsed === 'object' ? parsed : { type: event };
    } catch {
      return { type: event };
    }
  }
  return event && typeof event === 'object' ? event : {};
}

function applyAndroidPlatformState(
  event: AndroidPlatformEvent,
  state?: AndroidPlatformState | null,
): void {
  if (state?.locale) {
    globalThis.__exactLocaleSnapshot = state.locale;
    globalThis.__exactLocaleChanged?.(state.locale);
  }

  if (state?.accessibility) {
    globalThis.__exactAccessibilitySnapshot = state.accessibility;
    globalThis.__exactAccessibilityChanged?.(state.accessibility);
  } else if (state?.appearance) {
    updateAppearanceState(state.appearance);
  }

  if (state?.initialURL !== undefined) {
    globalThis.__exactInitialURL = state.initialURL ?? null;
  }

  const nextState = event.state ?? state?.appState;
  if (nextState) {
    const previous = globalThis.__exactAppState;
    globalThis.__exactAppState = nextState;
    globalThis.__exactReactNativeNotifyAppState?.(nextState);
    if (previous !== nextState) {
      dispatchWindowEvent(new CustomEvent('appstatechange', { detail: { state: nextState } }));
    }
  }

  if (state?.dimensions) {
    globalThis.__exactReactNativeNotifyDimensionsChange?.(state.dimensions);
  }

  if (event.type === 'configuration') {
    syncMediaQueries();
    dispatchWindowEvent(new Event('resize'));
    dispatchWindowEvent(new Event('orientationchange'));
  } else if (event.type === 'memoryWarning') {
    globalThis.__exactReactNativeNotifyMemoryWarning?.();
    dispatchWindowEvent(new Event('memorywarning'));
  }

  if (event.type === 'url' && typeof event.url === 'string' && event.url.length > 0) {
    globalThis.__exactInitialURL ??= event.url;
    globalThis.__exactReactNativeNotifyURL?.(event.url);
    dispatchWindowEvent(new CustomEvent('url', { detail: { url: event.url } }));
  }
}

/**
 * MediaQueryList for matchMedia support
 */
export class MediaQueryList extends EventTarget {
  readonly media: string;
  private _matches: boolean;
  
  /** @deprecated Use addEventListener instead */
  onchange: ((this: MediaQueryList, ev: MediaQueryListEvent) => any) | null = null;

  constructor(media: string) {
    super();
    this.media = media;
    this._matches = this._evaluate(media);
    mediaQueryLists.add(this);
  }

  get matches(): boolean {
    return this._matches;
  }

  private _evaluate(query: string): boolean {
    const dims = getScreenDimensions();
    
    // Simple media query parser
    // Supports: (min-width: Xpx), (max-width: Xpx), (orientation: portrait/landscape)
    // and (prefers-color-scheme: dark/light)
    
    const minWidthMatch = query.match(/\(min-width:\s*(\d+)px\)/);
    if (minWidthMatch) {
      return dims.width >= parseInt(minWidthMatch[1], 10);
    }
    
    const maxWidthMatch = query.match(/\(max-width:\s*(\d+)px\)/);
    if (maxWidthMatch) {
      return dims.width <= parseInt(maxWidthMatch[1], 10);
    }
    
    const minHeightMatch = query.match(/\(min-height:\s*(\d+)px\)/);
    if (minHeightMatch) {
      return dims.height >= parseInt(minHeightMatch[1], 10);
    }
    
    const maxHeightMatch = query.match(/\(max-height:\s*(\d+)px\)/);
    if (maxHeightMatch) {
      return dims.height <= parseInt(maxHeightMatch[1], 10);
    }
    
    const orientationMatch = query.match(/\(orientation:\s*(portrait|landscape)\)/);
    if (orientationMatch) {
      const isPortrait = dims.height > dims.width;
      return orientationMatch[1] === 'portrait' ? isPortrait : !isPortrait;
    }
    
    const colorSchemeMatch = query.match(/\(prefers-color-scheme:\s*(dark|light)\)/);
    if (colorSchemeMatch) {
      return appearanceState.colorScheme === colorSchemeMatch[1];
    }
    
    const reducedMotionMatch = query.match(/\(prefers-reduced-motion:\s*(reduce|no-preference)\)/);
    if (reducedMotionMatch) {
      return reducedMotionMatch[1] === 'reduce'
        ? appearanceState.reducedMotion
        : !appearanceState.reducedMotion;
    }
    
    // Unknown query - return false
    return false;
  }

  /** @deprecated Use addEventListener('change', ...) instead */
  addListener(callback: (this: MediaQueryList, ev: MediaQueryListEvent) => any): void {
    this.addEventListener('change', callback as EventListener);
  }

  /** @deprecated Use removeEventListener('change', ...) instead */
  removeListener(callback: (this: MediaQueryList, ev: MediaQueryListEvent) => any): void {
    this.removeEventListener('change', callback as EventListener);
  }

  _syncFromAppearance(): void {
    const nextMatches = this._evaluate(this.media);
    if (nextMatches === this._matches) {
      return;
    }

    this._matches = nextMatches;
    const event = new MediaQueryListEvent('change', {
      matches: nextMatches,
      media: this.media,
    });
    this.dispatchEvent(event);
    this.onchange?.call(this, event);
  }
}

/**
 * MediaQueryListEvent for matchMedia change events
 */
export class MediaQueryListEvent extends Event {
  readonly matches: boolean;
  readonly media: string;

  constructor(type: string, init?: { matches?: boolean; media?: string }) {
    super(type);
    this.matches = init?.matches ?? false;
    this.media = init?.media ?? '';
  }
}

/**
 * Window object implementation
 */
class Window extends EventTarget {
  // Self-references
  get window(): Window { return this; }
  get self(): Window { return this; }
  get globalThis(): typeof globalThis { return globalThis; }
  get frames(): Window { return this; }
  get parent(): Window { return this; }
  get top(): Window { return this; }
  
  // Length (number of frames - always 0 in native)
  readonly length: number = 0;
  
  // Name (empty in native)
  name: string = '';
  
  // Opener (null in native - no popup windows)
  readonly opener: null = null;
  
  // Frame element (null in native)
  readonly frameElement: null = null;
  
  // Closed status
  readonly closed: boolean = false;

  // Screen info
  readonly screen: ScreenInfo = createScreen();
  
  // Location
  readonly location: LocationInfo = createLocation();

  // Device pixel ratio
  get devicePixelRatio(): number {
    return getScreenDimensions().scale;
  }

  // Viewport dimensions (same as screen in native fullscreen apps)
  get innerWidth(): number {
    return getScreenDimensions().width;
  }

  get innerHeight(): number {
    return getScreenDimensions().height;
  }

  get outerWidth(): number {
    return getScreenDimensions().width;
  }

  get outerHeight(): number {
    return getScreenDimensions().height;
  }

  // Scroll position (always 0 in native - no document scrolling)
  get scrollX(): number { return 0; }
  get scrollY(): number { return 0; }
  get pageXOffset(): number { return 0; }
  get pageYOffset(): number { return 0; }

  // Screen position (always 0)
  get screenX(): number { return 0; }
  get screenY(): number { return 0; }
  get screenLeft(): number { return 0; }
  get screenTop(): number { return 0; }

  // Visual viewport (same as dimensions)
  get visualViewport(): { width: number; height: number; scale: number; offsetLeft: number; offsetTop: number } {
    const dims = getScreenDimensions();
    return {
      width: dims.width,
      height: dims.height,
      scale: 1,
      offsetLeft: 0,
      offsetTop: 0,
    };
  }

  // Is secure context (always true in native)
  get isSecureContext(): boolean {
    return true;
  }

  // Origin
  get origin(): string {
    return 'exact://app';
  }

  // Methods

  /**
   * Match media query
   */
  matchMedia(query: string): MediaQueryList {
    return new MediaQueryList(query);
  }

  /**
   * Get computed style (stub - no DOM)
   */
  getComputedStyle(_element: unknown, _pseudoElt?: string | null): Record<string, string> {
    console.warn('getComputedStyle() is not supported in Exact runtime (no DOM)');
    return new Proxy({}, {
      get: () => '',
    });
  }

  /**
   * Get selection (stub - no DOM)
   */
  getSelection(): null {
    return null;
  }

  /**
   * Scroll methods (no-op in native)
   */
  scroll(_x?: number | ScrollToOptions, _y?: number): void {
    // No-op - no document to scroll
  }

  scrollTo(_x?: number | ScrollToOptions, _y?: number): void {
    // No-op
  }

  scrollBy(_x?: number | ScrollToOptions, _y?: number): void {
    // No-op
  }

  /**
   * Focus/blur (no-op in native)
   */
  focus(): void {
    // No-op
  }

  blur(): void {
    // No-op
  }

  /**
   * Print (not supported)
   */
  print(): void {
    console.warn('print() is not supported in Exact runtime');
  }

  /**
   * Stop (no-op)
   */
  stop(): void {
    // No-op
  }

  /**
   * Open (not supported - no popup windows)
   */
  open(_url?: string, _target?: string, _features?: string): null {
    console.warn('window.open() is not supported in Exact runtime');
    return null;
  }

  /**
   * Close (not supported)
   */
  close(): void {
    console.warn('window.close() is not supported in Exact runtime');
  }

  /**
   * Alert dialog
   * TODO: Implement native alert
   */
  alert(message?: any): void {
    console.log('[Alert]', String(message ?? ''));
  }

  /**
   * Confirm dialog
   * TODO: Implement native confirm - for now always returns false
   */
  confirm(_message?: string): boolean {
    console.warn('confirm() is not fully supported in Exact runtime');
    return false;
  }

  /**
   * Prompt dialog
   * TODO: Implement native prompt - for now always returns null
   */
  prompt(_message?: string, _defaultValue?: string): string | null {
    console.warn('prompt() is not fully supported in Exact runtime');
    return null;
  }

  /**
   * Post message (for compatibility)
   */
  postMessage(message: any, _targetOrigin?: string, _transfer?: Transferable[]): void {
    // Dispatch message event to self
    const event = new MessageEvent('message', {
      data: message,
      origin: this.origin,
      source: this,
    });
    this.dispatchEvent(event);
  }

  /**
   * Request animation frame - forward to global
   */
  requestAnimationFrame(callback: FrameRequestCallback): number {
    return (globalThis as any).requestAnimationFrame(callback);
  }

  /**
   * Cancel animation frame - forward to global
   */
  cancelAnimationFrame(handle: number): void {
    return (globalThis as any).cancelAnimationFrame(handle);
  }

  /**
   * Request idle callback - forward to global
   */
  requestIdleCallback(callback: IdleRequestCallback, options?: IdleRequestOptions): number {
    return (globalThis as any).requestIdleCallback(callback, options);
  }

  /**
   * Cancel idle callback - forward to global
   */
  cancelIdleCallback(handle: number): void {
    return (globalThis as any).cancelIdleCallback(handle);
  }

  /**
   * Set timeout - forward to global
   */
  setTimeout(handler: TimerHandler, timeout?: number, ...args: any[]): number {
    return (globalThis as any).setTimeout(handler, timeout, ...args);
  }

  /**
   * Clear timeout - forward to global
   */
  clearTimeout(id?: number): void {
    return (globalThis as any).clearTimeout(id);
  }

  /**
   * Set interval - forward to global
   */
  setInterval(handler: TimerHandler, timeout?: number, ...args: any[]): number {
    return (globalThis as any).setInterval(handler, timeout, ...args);
  }

  /**
   * Clear interval - forward to global
   */
  clearInterval(id?: number): void {
    return (globalThis as any).clearInterval(id);
  }

  /**
   * Queue microtask - forward to global
   */
  queueMicrotask(callback: VoidFunction): void {
    return (globalThis as any).queueMicrotask(callback);
  }

  /**
   * Create image bitmap (not supported - no DOM)
   */
  createImageBitmap(..._args: any[]): Promise<never> {
    return Promise.reject(new Error('createImageBitmap() is not supported in Exact runtime'));
  }

  /**
   * Fetch - forward to global
   */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return (globalThis as any).fetch(input, init);
  }

  /**
   * btoa - forward to global
   */
  btoa(data: string): string {
    return (globalThis as any).btoa(data);
  }

  /**
   * atob - forward to global
   */
  atob(data: string): string {
    return (globalThis as any).atob(data);
  }

  /**
   * structuredClone - forward to global
   */
  structuredClone<T>(value: T, options?: StructuredSerializeOptions): T {
    return (globalThis as any).structuredClone(value, options);
  }

  // String tag
  get [Symbol.toStringTag](): string {
    return 'Window';
  }
}

// Type definitions for callbacks
type TimerHandler = string | Function;
type FrameRequestCallback = (time: DOMHighResTimeStamp) => void;
type IdleRequestCallback = (deadline: IdleDeadline) => void;
interface IdleRequestOptions {
  timeout?: number;
}
interface IdleDeadline {
  didTimeout: boolean;
  timeRemaining(): DOMHighResTimeStamp;
}
type DOMHighResTimeStamp = number;

// Create window instance directly
// Note: This runs at module load time, but the circular dependency
// issue was fixed by having Navigator use inline detection functions
export const window = new Window();

globalThis.__exactWindowNotifyMediaChange = (next) => {
  updateAppearanceState(next);
};

globalThis.__exactWindowNotifyResize = () => {
  syncMediaQueries();
  dispatchWindowEvent(new Event('resize'));
  dispatchWindowEvent(new Event('orientationchange'));
};

globalThis.__exactAndroidDispatchPlatformEvent = (event, state) => {
  applyAndroidPlatformState(normalizeAndroidPlatformEvent(event), state);
};

if (typeof globalThis.__exactAndroidGetPlatformState === 'function') {
  applyAndroidPlatformState({ type: 'initial' }, globalThis.__exactAndroidGetPlatformState());
}
if (typeof globalThis.__exactAndroidDrainPlatformEvents === 'function') {
  globalThis.__exactAndroidDrainPlatformEvents();
}

// Also export the class for type checking
export { Window };

export default window;
