// @ts-nocheck
/**
 * Window API Implementation for Ibex Runtime
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
  var __exactNativeDialog:
    | ((type: 'alert' | 'confirm' | 'prompt', message: string, defaultValue?: string) => string | null)
    | undefined;
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

  // Resolve a possibly-relative URL against the current href so that
  // assign('/profile?tab=2') updates pathname/search (not just href). Without
  // resolution the raw string is stored and parseUrl's catch-branch reports
  // pathname '/' and empty search, stranding routers that key off them
  // (ENG-22979).
  const resolveHref = (url: string): string => {
    try {
      return new URL(url, currentHref).href;
    } catch {
      return url;
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
      console.warn('location.reload() is not supported in Ibex runtime');
    },
    replace: (url: string) => {
      currentHref = resolveHref(url);
    },
    assign: (url: string) => {
      currentHref = resolveHref(url);
    },
  };

  return location;
}

interface AppearanceState {
  colorScheme: 'light' | 'dark';
  reducedMotion: boolean;
}

// Registry of live MediaQueryList instances so appearance/resize changes can
// re-evaluate them. Instances are held WEAKLY: a matchMedia() result the app
// has dropped (e.g. an unmounted useColorScheme hook that no longer references
// its MediaQueryList) must be collectable instead of leaking for the lifetime
// of the runtime and being re-evaluated on every appearance/resize change
// (ENG-22979). Where WeakRef/FinalizationRegistry are unavailable we fall back
// to strong references — correct, just not leak-free.
const supportsWeakRef = typeof WeakRef === 'function';
const mediaQueryLists = new Set<WeakRef<MediaQueryList> | MediaQueryList>();
const mediaQueryFinalization =
  typeof FinalizationRegistry === 'function'
    ? new FinalizationRegistry<WeakRef<MediaQueryList>>((ref) => {
        mediaQueryLists.delete(ref);
      })
    : null;

// (ENG-23140) Strong retention for MediaQueryLists that currently have change
// listeners (or an onchange handler). The HTML spec requires an MQL with
// listeners to be kept alive even when the app drops its own reference —
// ENG-22979's WeakRef registry over-collected them, so a
// matchMedia('(prefers-color-scheme: dark)').addEventListener('change', cb)
// pattern went silent after the next GC. Instances move into this set while
// they have listeners and drop back to weak-only tracking when the last
// listener is removed, preserving ENG-22979's leak fix for listener-less MQLs.
const retainedMediaQueryLists = new Set<MediaQueryList>();

function retainMediaQueryList(mql: MediaQueryList): void {
  retainedMediaQueryLists.add(mql);
}

function releaseMediaQueryList(mql: MediaQueryList): void {
  retainedMediaQueryLists.delete(mql);
}

function registerMediaQueryList(mql: MediaQueryList): void {
  if (supportsWeakRef) {
    const ref = new WeakRef(mql);
    mediaQueryLists.add(ref);
    mediaQueryFinalization?.register(mql, ref);
  } else {
    mediaQueryLists.add(mql);
  }
}

function derefMediaQueryList(
  entry: WeakRef<MediaQueryList> | MediaQueryList,
): MediaQueryList | undefined {
  return supportsWeakRef
    ? (entry as WeakRef<MediaQueryList>).deref()
    : (entry as MediaQueryList);
}

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
  syncMediaQueries();
}

function syncMediaQueries(): void {
  for (const entry of mediaQueryLists) {
    const mediaQueryList = derefMediaQueryList(entry);
    if (mediaQueryList) {
      mediaQueryList._syncFromAppearance();
    } else {
      // The instance was garbage-collected; drop its now-empty weak reference.
      mediaQueryLists.delete(entry);
    }
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

  // Accessibility and appearance are independent payloads — a single platform
  // event can carry both, so handle them separately rather than as an
  // either/or (ENG-22979). Apply appearance AFTER accessibility: the
  // accessibility handler mirrors its own colorScheme into
  // __exactAppearanceState (defaulting to 'light' when the record omits it), so
  // an explicit state.appearance must win to avoid reverting a pushed dark
  // value.
  if (state?.accessibility) {
    globalThis.__exactAccessibilitySnapshot = state.accessibility;
    globalThis.__exactAccessibilityChanged?.(state.accessibility);
  }
  if (state?.appearance) {
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

function callNativeDialog(
  type: 'alert' | 'confirm' | 'prompt',
  message: string,
  defaultValue = '',
): string | null | undefined {
  if (typeof globalThis.__exactNativeDialog !== 'function') {
    return undefined;
  }
  try {
    return globalThis.__exactNativeDialog(type, message, defaultValue);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.warn(`${type}() native dialog failed: ${detail}`);
    return undefined;
  }
}

/**
 * MediaQueryList for matchMedia support
 */
export class MediaQueryList extends EventTarget {
  readonly media: string;
  private _matches: boolean;
  // Registered 'change' callbacks, tracked so the instance can move between
  // strong retention (has listeners) and weak-only registry (no listeners).
  // (ENG-23140)
  private _changeListeners = new Set<object>();
  private _onchange: ((this: MediaQueryList, ev: MediaQueryListEvent) => any) | null = null;

  constructor(media: string) {
    super();
    this.media = media;
    this._matches = this._evaluate(media);
    registerMediaQueryList(this);
  }

  get matches(): boolean {
    return this._matches;
  }

  /** @deprecated Use addEventListener instead */
  get onchange(): ((this: MediaQueryList, ev: MediaQueryListEvent) => any) | null {
    return this._onchange;
  }

  set onchange(handler: ((this: MediaQueryList, ev: MediaQueryListEvent) => any) | null) {
    this._onchange = typeof handler === 'function' ? handler : null;
    this._updateRetention();
  }

  addEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: boolean | AddEventListenerOptions,
  ): void {
    super.addEventListener(type, callback, options);
    // Mirror EventTarget's "already aborted signal adds nothing" rule so we do
    // not retain the MQL for a listener that was never registered. once/signal
    // auto-removals inside EventTarget are not observable from here; they can
    // only over-retain (never under-retain), which is the safe direction.
    const alreadyAborted =
      typeof options === 'object' && options !== null && (options as AddEventListenerOptions).signal?.aborted;
    if (type === 'change' && callback && !alreadyAborted) {
      this._changeListeners.add(callback as object);
      this._updateRetention();
    }
  }

  removeEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: boolean | EventListenerOptions,
  ): void {
    super.removeEventListener(type, callback, options);
    if (type === 'change' && callback) {
      this._changeListeners.delete(callback as object);
      this._updateRetention();
    }
  }

  private _updateRetention(): void {
    if (this._changeListeners.size > 0 || this._onchange) {
      retainMediaQueryList(this);
    } else {
      releaseMediaQueryList(this);
    }
  }

  // Supports comma-separated query lists (logical OR), `and`-joined feature
  // conjunctions (logical AND), leading `not`/`only` modifiers, and the
  // features (min/max-width, min/max-height, orientation, prefers-color-scheme,
  // prefers-reduced-motion). Previously this returned on the FIRST recognized
  // feature, so a compound query like
  // `(min-width: 768px) and (max-width: 1024px)` matched on min-width alone and
  // stayed active well past 1024px (ENG-22979).
  private _evaluate(query: string): boolean {
    // A comma-separated list matches when ANY of its queries matches.
    return query.split(',').some((part) => this._evaluateQuery(part));
  }

  private _evaluateQuery(query: string): boolean {
    const trimmed = query.trim();
    if (trimmed.length === 0) {
      return false;
    }

    // An optional leading `not`/`only` modifier applies to the whole query.
    // `only` is a legacy no-op used to hide queries from old parsers.
    let negate = false;
    let rest = trimmed;
    const modifierMatch = rest.match(/^(not|only)\s+/i);
    if (modifierMatch) {
      if (modifierMatch[1].toLowerCase() === 'not') {
        negate = true;
      }
      rest = rest.slice(modifierMatch[0].length).trim();
    }

    // `and`-joined features must ALL match.
    const result = rest
      .split(/\s+and\s+/i)
      .every((feature) => this._evaluateFeature(feature.trim()));

    return negate ? !result : result;
  }

  private _evaluateFeature(feature: string): boolean {
    const dims = getScreenDimensions();

    // A bare media type (e.g. `screen`, `all`, `print`) rather than a
    // parenthesized `(feature: value)` expression. The native runtime behaves
    // like an on-screen context.
    if (!feature.startsWith('(')) {
      const type = feature.toLowerCase();
      return type === 'screen' || type === 'all';
    }

    const minWidthMatch = feature.match(/\(min-width:\s*(\d+)px\)/);
    if (minWidthMatch) {
      return dims.width >= parseInt(minWidthMatch[1], 10);
    }

    const maxWidthMatch = feature.match(/\(max-width:\s*(\d+)px\)/);
    if (maxWidthMatch) {
      return dims.width <= parseInt(maxWidthMatch[1], 10);
    }

    const minHeightMatch = feature.match(/\(min-height:\s*(\d+)px\)/);
    if (minHeightMatch) {
      return dims.height >= parseInt(minHeightMatch[1], 10);
    }

    const maxHeightMatch = feature.match(/\(max-height:\s*(\d+)px\)/);
    if (maxHeightMatch) {
      return dims.height <= parseInt(maxHeightMatch[1], 10);
    }

    const orientationMatch = feature.match(/\(orientation:\s*(portrait|landscape)\)/);
    if (orientationMatch) {
      const isPortrait = dims.height > dims.width;
      return orientationMatch[1] === 'portrait' ? isPortrait : !isPortrait;
    }

    const colorSchemeMatch = feature.match(/\(prefers-color-scheme:\s*(dark|light)\)/);
    if (colorSchemeMatch) {
      return appearanceState.colorScheme === colorSchemeMatch[1];
    }

    const reducedMotionMatch = feature.match(/\(prefers-reduced-motion:\s*(reduce|no-preference)\)/);
    if (reducedMotionMatch) {
      return reducedMotionMatch[1] === 'reduce'
        ? appearanceState.reducedMotion
        : !appearanceState.reducedMotion;
    }

    // Unknown feature - does not match.
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
    console.warn('getComputedStyle() is not supported in Ibex runtime (no DOM)');
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
    console.warn('print() is not supported in Ibex runtime');
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
    console.warn('window.open() is not supported in Ibex runtime');
    return null;
  }

  /**
   * Close (not supported)
   */
  close(): void {
    console.warn('window.close() is not supported in Ibex runtime');
  }

  /**
   * Alert dialog
   */
  alert(message?: any): void {
    const nativeResult = callNativeDialog('alert', String(message ?? ''));
    if (nativeResult !== undefined) {
      return;
    }
    console.log('[Alert]', String(message ?? ''));
  }

  /**
   * Confirm dialog
   */
  confirm(message?: string): boolean {
    const nativeResult = callNativeDialog('confirm', String(message ?? ''));
    if (nativeResult !== undefined) {
      return nativeResult === 'true';
    }
    console.warn('confirm() is not fully supported in Ibex runtime');
    return false;
  }

  /**
   * Prompt dialog
   */
  prompt(message?: string, defaultValue?: string): string | null {
    const nativeResult = callNativeDialog(
      'prompt',
      String(message ?? ''),
      String(defaultValue ?? ''),
    );
    if (nativeResult !== undefined) {
      return nativeResult;
    }
    console.warn('prompt() is not fully supported in Ibex runtime');
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
    return Promise.reject(new Error('createImageBitmap() is not supported in Ibex runtime'));
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

// A second copy of this module can evaluate in the same runtime (the embedded
// runtime bundle boots one; a bundled agent/app bootstrap can evaluate
// another). `globalThis.matchMedia` stays lazily bound to whichever copy
// defined it first while each copy owns its own mediaQueryLists registry, so
// these host notify hooks must CHAIN to any previously installed hook instead
// of clobbering it — otherwise the first copy's registry goes permanently deaf
// to host appearance/resize notifications (ENG-22805, root cause of
// ENG-22789's broken macOS system-appearance propagation).
const previousNotifyMediaChange = globalThis.__exactWindowNotifyMediaChange;
globalThis.__exactWindowNotifyMediaChange = (next) => {
  previousNotifyMediaChange?.(next);
  updateAppearanceState(next);
};

const previousNotifyResize = globalThis.__exactWindowNotifyResize;
globalThis.__exactWindowNotifyResize = () => {
  previousNotifyResize?.();
  syncMediaQueries();
  dispatchWindowEvent(new Event('resize'));
  dispatchWindowEvent(new Event('orientationchange'));
};

const previousAndroidDispatchPlatformEvent = globalThis.__exactAndroidDispatchPlatformEvent;
globalThis.__exactAndroidDispatchPlatformEvent = (event, state) => {
  previousAndroidDispatchPlatformEvent?.(event, state);
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
