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
    return `5.0 (iOS)`;
  }

  /**
   * Platform identifier.
   * Returns "iPhone", "Android", "MacIntel", etc. depending on the runtime platform.
   */
  get platform(): string {
    const g = globalThis as any;
    if (typeof g.__exactPlatform === 'string') {
      const p = g.__exactPlatform.toLowerCase();
      if (p === 'android') return 'Android';
      if (p === 'web' || p === 'browser') return 'MacIntel';
      if (p === 'macos' || p === 'mac') return 'MacIntel';
      if (p === 'windows' || p === 'win32') return 'Win32';
      if (p === 'linux') return 'Linux x86_64';
      // iOS devices
      return 'iPhone';
    }
    return 'iPhone';
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
    // Mobile devices typically have 4-8 cores
    // Could be enhanced with native bridge for actual value
    return 4;
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
    // Conservative estimate for mobile devices
    return 4;
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
