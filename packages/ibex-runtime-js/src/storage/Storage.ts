/**
 * Storage implementation for Ibex runtime (localStorage/sessionStorage)
 * 
 * Implements the Web Storage API.
 * @see https://html.spec.whatwg.org/multipage/webstorage.html
 */

import { createQuotaExceededError } from '../events/DOMException';
import { getNativeModule } from '../native/NativeModules';
import { requireCapability, Capabilities, type Capability } from '../security/Capabilities';

// Default quota: 10MB
const DEFAULT_QUOTA = 10 * 1024 * 1024;

function isNativeQuotaSignal(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const candidate = error as { name?: unknown; code?: unknown };
  return (
    candidate.code === 'QuotaExceededError' ||
    candidate.code === 'QUOTA_EXCEEDED_ERR' ||
    candidate.code === 22
  );
}

/**
 * Storage provides synchronous key-value storage.
 * 
 * Note: In Exact, localStorage is per-app, not per-origin (since there's no
 * concept of origins in a native app context).
 */
export class Storage {
  #data: Map<string, string>;
  #quota: number;
  #persistent: boolean;
  #nativeStorage: any;
  #capability: Capability;

  constructor(persistent: boolean = true, quota: number = DEFAULT_QUOTA, capability?: Capability) {
    this.#data = new Map();
    this.#quota = quota;
    this.#persistent = persistent;
    this.#capability = capability ?? (persistent ? Capabilities.STORAGE_LOCAL : Capabilities.STORAGE_SESSION);
    this.#nativeStorage = getNativeModule('storage');

    // If native storage is available and this is persistent, load existing data
    if (this.#nativeStorage && persistent) {
      this.#loadFromNative();
    }
  }

  /**
   * Check capability before any storage operation.
   * @throws NotAllowedError if capability is not granted
   */
  #checkCapability(): void {
    requireCapability(this.#capability);
  }

  /**
   * Returns the number of key/value pairs.
   */
  get length(): number {
    this.#checkCapability();
    if (this.#nativeStorage && this.#persistent) {
      return this.#nativeStorage.length();
    }
    return this.#data.size;
  }

  /**
   * Returns the name of the nth key, or null if n >= length.
   */
  key(index: number): string | null {
    this.#checkCapability();
    if (this.#nativeStorage && this.#persistent) {
      return this.#nativeStorage.key(index);
    }

    if (index < 0 || index >= this.#data.size) {
      return null;
    }
    const keys = [...this.#data.keys()];
    return keys[index] ?? null;
  }

  /**
   * Returns the current value associated with the given key.
   */
  getItem(key: string): string | null {
    this.#checkCapability();
    if (this.#nativeStorage && this.#persistent) {
      return this.#nativeStorage.getItem(String(key));
    }
    return this.#data.get(String(key)) ?? null;
  }

  /**
   * Sets the value of the pair identified by key.
   * Throws QuotaExceededError if the quota is exceeded.
   */
  setItem(key: string, value: string): void {
    this.#checkCapability();
    const keyStr = String(key);
    const valueStr = String(value);

    if (this.#nativeStorage && this.#persistent) {
      try {
        this.#nativeStorage.setItem(keyStr, valueStr);
      } catch (e: any) {
        if (e?.name === 'QuotaExceededError') {
          throw e;
        }
        if (isNativeQuotaSignal(e)) {
          throw createQuotaExceededError('Storage quota exceeded');
        }
        throw e;
      }
      return;
    }

    // Check quota for in-memory storage
    const currentSize = this.#calculateSize();
    const oldValue = this.#data.get(keyStr);
    const oldSize = oldValue ? keyStr.length + oldValue.length : 0;
    const newSize = keyStr.length + valueStr.length;
    
    if (currentSize - oldSize + newSize > this.#quota) {
      throw createQuotaExceededError('Storage quota exceeded');
    }

    this.#data.set(keyStr, valueStr);
  }

  /**
   * Removes the key/value pair with the given key.
   */
  removeItem(key: string): void {
    this.#checkCapability();
    const keyStr = String(key);

    if (this.#nativeStorage && this.#persistent) {
      this.#nativeStorage.removeItem(keyStr);
      return;
    }

    this.#data.delete(keyStr);
  }

  /**
   * Removes all key/value pairs.
   */
  clear(): void {
    this.#checkCapability();
    if (this.#nativeStorage && this.#persistent) {
      this.#nativeStorage.clear();
      return;
    }

    this.#data.clear();
  }

  /**
   * Calculate total size of stored data.
   */
  #calculateSize(): number {
    let size = 0;
    for (const [key, value] of this.#data) {
      size += key.length + value.length;
    }
    return size;
  }

  /**
   * Load data from native storage.
   */
  #loadFromNative(): void {
    if (!this.#nativeStorage) return;

    const length = this.#nativeStorage.length();
    for (let i = 0; i < length; i++) {
      const key = this.#nativeStorage.key(i);
      if (key !== null) {
        const value = this.#nativeStorage.getItem(key);
        if (value !== null) {
          this.#data.set(key, value);
        }
      }
    }
  }

  get [Symbol.toStringTag](): string {
    return 'Storage';
  }
}

// Create singleton instances
let _localStorage: Storage | null = null;
let _sessionStorage: Storage | null = null;

/**
 * Get the localStorage instance.
 * localStorage persists across sessions.
 */
export function getLocalStorage(): Storage {
  if (!_localStorage) {
    _localStorage = new Storage(true, DEFAULT_QUOTA, Capabilities.STORAGE_LOCAL);
  }
  return _localStorage;
}

/**
 * Get the sessionStorage instance.
 * sessionStorage is cleared when the app is closed.
 */
export function getSessionStorage(): Storage {
  if (!_sessionStorage) {
    _sessionStorage = new Storage(false, DEFAULT_QUOTA, Capabilities.STORAGE_SESSION);
  }
  return _sessionStorage;
}

function createLazyStorageProxy(factory: () => Storage): Storage {
  let storage: Storage | null = null;

  const getStorage = (): Storage => {
    if (!storage) {
      storage = factory();
    }
    return storage;
  };

  return new Proxy({} as Storage, {
    get(target, prop, receiver) {
      target = getStorage();
      if (typeof prop === 'string') {
        // Check if it's a Storage method/property first
        if (prop in target || prop === 'length') {
          const value = Reflect.get(target, prop, target);
          return typeof value === 'function' ? value.bind(target) : value;
        }
        // Otherwise treat as getItem
        return target.getItem(prop);
      }
      const value = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
    set(target, prop, value) {
      target = getStorage();
      if (typeof prop === 'string') {
        target.setItem(prop, String(value));
        return true;
      }
      return false;
    },
    deleteProperty(target, prop) {
      target = getStorage();
      if (typeof prop === 'string') {
        target.removeItem(prop);
        return true;
      }
      return false;
    },
    has(target, prop) {
      target = getStorage();
      if (typeof prop === 'string') {
        return target.getItem(prop) !== null;
      }
      return prop in target;
    },
    ownKeys(target) {
      target = getStorage();
      const keys: string[] = [];
      for (let i = 0; i < target.length; i++) {
        const key = target.key(i);
        if (key !== null) {
          keys.push(key);
        }
      }
      return keys;
    },
    getOwnPropertyDescriptor(target, prop) {
      target = getStorage();
      if (typeof prop === 'string') {
        const value = target.getItem(prop);
        if (value !== null) {
          return {
            value,
            writable: true,
            enumerable: true,
            configurable: true,
          };
        }
      }
      return undefined;
    },
  });
}

// Export proxy-wrapped singletons
export const localStorage = createLazyStorageProxy(getLocalStorage);
export const sessionStorage = createLazyStorageProxy(getSessionStorage);

export default Storage;
