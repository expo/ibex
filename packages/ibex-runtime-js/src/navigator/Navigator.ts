/**
 * Navigator implementation for Exact runtime
 * 
 * Provides browser-like navigator object with device/platform info.
 * @see https://html.spec.whatwg.org/multipage/system-state.html#the-navigator-object
 */

import { USER_AGENT } from '../identity.generated';
import { LockManager } from '../locks/LockManager';
import { Clipboard } from '../clipboard/Clipboard';
import { StorageManager } from '../storage/StorageManager';
import { getGeolocation } from '../location';
import { getExactLocaleSnapshot } from '../locale';

function runtimePlatform(): string {
  const g = globalThis as any;
  if (typeof g.__exactPlatform === 'string' && g.__exactPlatform.length > 0) {
    return g.__exactPlatform.toLowerCase();
  }
  if (
    g.process &&
    typeof g.process.platform === 'string' &&
    g.process.platform.length > 0
  ) {
    return g.process.platform.toLowerCase();
  }
  return 'ios';
}

function platformLabelForNavigator(): string {
  const p = runtimePlatform();
  if (p === 'android') return 'Android';
  if (p === 'web' || p === 'browser') return 'MacIntel';
  if (p === 'macos' || p === 'mac' || p === 'darwin') return 'MacIntel';
  if (p === 'windows' || p === 'win32') return 'Win32';
  if (p === 'linux') return 'Linux x86_64';
  return 'iPhone';
}

function platformLabelForAppVersion(): string {
  const p = runtimePlatform();
  if (p === 'android') return 'Android';
  if (p === 'web' || p === 'browser') return 'Macintosh';
  if (p === 'macos' || p === 'mac' || p === 'darwin') return 'Macintosh';
  if (p === 'windows' || p === 'win32') return 'Windows';
  if (p === 'linux') return 'Linux';
  return 'iOS';
}

function callNumericHostFunction(name: string): number | null {
  const fn = (globalThis as any)[name];
  if (typeof fn !== 'function') return null;
  try {
    const value = Number(fn());
    return Number.isFinite(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

function approximateDeviceMemory(totalBytes: number | null): number {
  if (totalBytes == null) return 4;
  const gib = totalBytes / (1024 * 1024 * 1024);
  const buckets = [0.25, 0.5, 1, 2, 4, 8];
  let selected = buckets[0];
  for (const bucket of buckets) {
    if (gib >= bucket) {
      selected = bucket;
    }
  }
  return selected;
}

/**
 * Navigator provides information about the runtime environment.
 */
export class Navigator {
  readonly __exactNavigator = true;

  private _locks: LockManager | null = null;
  private _storage: StorageManager | null = null;
  private _clipboard: Clipboard | null = null;
  private _geolocation: Geolocation | null = null;
  /**
   * User agent string identifying the runtime.
   * Format: "Exact/{version} ({platform}; {engine})"
   */
  get userAgent(): string {
    return USER_AGENT;
  }

  /**
   * Vendor string (always "Exact" for this runtime).
   */
  get vendor(): string {
    return 'Exact';
  }

  /**
   * Vendor sub-version (empty string).
   */
  get vendorSub(): string {
    return '';
  }

  /**
   * Product name (always "Exact").
   */
  get product(): string {
    return 'Exact';
  }

  /**
   * Product sub-version (empty string).
   */
  get productSub(): string {
    return '';
  }

  /**
   * App name for compatibility (always "Netscape" per spec).
   */
  get appName(): string {
    return 'Netscape';
  }

  /**
   * App code name for compatibility.
   */
  get appCodeName(): string {
    return 'Mozilla';
  }

  /**
   * App version string.
   */
  get appVersion(): string {
    return `5.0 (${platformLabelForAppVersion()})`;
  }

  /**
   * Platform identifier.
   * Returns "iPhone", "Android", "MacIntel", etc. depending on the runtime platform.
   */
  get platform(): string {
    return platformLabelForNavigator();
  }

  /**
   * Primary language preference.
   * Returns the device's preferred language via native bridge if available.
   */
  get language(): string {
    const exactLocale = getExactLocaleSnapshot();
    if (exactLocale.tag.length > 0) {
      return exactLocale.tag;
    }

    const g = globalThis as any;
    if (typeof g.__exactLocale === 'string' && g.__exactLocale) {
      return g.__exactLocale;
    }
    if (typeof g.__exactLanguage === 'string' && g.__exactLanguage) {
      return g.__exactLanguage;
    }
    return 'en-US';
  }

  /**
   * Array of preferred languages.
   */
  get languages(): readonly string[] {
    const exactLocale = getExactLocaleSnapshot();
    if (exactLocale.tags.length > 0) {
      return exactLocale.tags;
    }

    const lang = this.language;
    const base = lang.includes('-') ? lang.split('-')[0] : lang;
    if (base !== lang) {
      return Object.freeze([lang, base]);
    }
    return Object.freeze([lang]);
  }

  /**
   * Whether the device is online.
   * Note: Requires native bridge for accurate status.
   */
  get onLine(): boolean {
    // Default to true - native bridge should update this
    return true;
  }

  /**
   * Number of logical processors available.
   */
  get hardwareConcurrency(): number {
    // @ref LLP 0008#os-info - Android navigator device hints use native sysconf/sysinfo values.
    const nativeCount = callNumericHostFunction('__exactGetCpuCount');
    return nativeCount == null ? 4 : Math.max(1, Math.floor(nativeCount));
  }

  /**
   * Maximum touch points supported by the device.
   */
  get maxTouchPoints(): number {
    // Mobile devices support multi-touch
    return 5;
  }

  /**
   * Whether cookies are enabled.
   * Always returns true in Exact (we support cookies in fetch).
   */
  get cookieEnabled(): boolean {
    return true;
  }

  /**
   * Whether Java is enabled (always false).
   */
  javaEnabled(): boolean {
    return false;
  }

  /**
   * Device memory in GB (approximate).
   * Note: This is a hint, not exact value.
   */
  get deviceMemory(): number {
    // @ref LLP 0008#os-info - Android navigator device hints use native sysconf/sysinfo values.
    return approximateDeviceMemory(callNumericHostFunction('__exactGetTotalMem'));
  }

  /**
   * PDF viewer support (always false in native app).
   */
  get pdfViewerEnabled(): boolean {
    return false;
  }

  /**
   * Web driver status (always false).
   */
  get webdriver(): boolean {
    return false;
  }

  /**
   * Clipboard API for reading and writing clipboard data.
   * @see https://developer.mozilla.org/en-US/docs/Web/API/Navigator/clipboard
   */
  get clipboard(): Clipboard {
    if (!this._clipboard) {
      this._clipboard = new Clipboard();
    }
    return this._clipboard;
  }

  /**
   * Geolocation API installed from the runtime location backend.
   */
  get geolocation(): Geolocation {
    if (!this._geolocation) {
      this._geolocation = getGeolocation();
    }
    return this._geolocation;
  }

  /**
   * Web Locks API for coordinating concurrent access.
   * @see https://developer.mozilla.org/en-US/docs/Web/API/Navigator/locks
   */
  get locks(): LockManager {
    if (!this._locks) {
      this._locks = new LockManager();
    }
    return this._locks;
  }

  /**
   * Storage manager for quota and persistence info.
   * @see https://developer.mozilla.org/en-US/docs/Web/API/Navigator/storage
   */
  get storage(): StorageManager {
    if (!this._storage) {
      this._storage = new StorageManager();
    }
    return this._storage;
  }

  get [Symbol.toStringTag](): string {
    return 'Navigator';
  }
}

// Singleton navigator instance
let _navigator: Navigator | null = null;

export function getNavigator(): Navigator {
  if (!_navigator) {
    _navigator = new Navigator();
  }
  return _navigator;
}

export const navigator = getNavigator();

export default Navigator;
