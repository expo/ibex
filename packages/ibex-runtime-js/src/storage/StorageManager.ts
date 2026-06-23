/**
 * StorageManager - navigator.storage API
 *
 * Provides methods for estimating storage usage/quota and
 * requesting persistent storage.
 * @see https://storage.spec.whatwg.org/#storagemanager
 */

import { getNativeModule } from '../native/NativeModules';
import { requireCapability, Capabilities } from '../security/Capabilities';

// Default quota: 100MB (typical for native apps)
const DEFAULT_QUOTA = 100 * 1024 * 1024;

export interface StorageEstimate {
  usage: number;
  quota: number;
}

export class StorageManager {
  _nativeStorage: any;

  constructor() {
    this._nativeStorage = getNativeModule('storage');
  }

  /**
   * Returns an estimate of the total storage used and the available quota.
   *
   * @returns A promise that resolves to a StorageEstimate with usage and quota.
   */
  async estimate(): Promise<StorageEstimate> {
    if (this._nativeStorage?.estimate) {
      return this._nativeStorage.estimate();
    }

    // Fallback: return a default estimate
    return {
      usage: 0,
      quota: DEFAULT_QUOTA,
    };
  }

  /**
   * Requests permission to use persistent storage.
   *
   * In the Ibex runtime, persistent storage is granted based on the
   * STORAGE_PERSIST capability.
   *
   * @returns A promise that resolves to true if persistent storage is granted.
   */
  async persist(): Promise<boolean> {
    try {
      requireCapability(Capabilities.STORAGE_PERSIST);
    } catch {
      return false;
    }

    if (this._nativeStorage?.persist) {
      return this._nativeStorage.persist();
    }

    // Default: grant persistence if capability is available
    return true;
  }

  /**
   * Checks whether persistent storage has been granted.
   *
   * @returns A promise that resolves to true if storage is persistent.
   */
  async persisted(): Promise<boolean> {
    if (this._nativeStorage?.persisted) {
      return this._nativeStorage.persisted();
    }

    // Default: check if the capability is available
    try {
      requireCapability(Capabilities.STORAGE_PERSIST);
      return true;
    } catch {
      return false;
    }
  }

  get [Symbol.toStringTag](): string {
    return 'StorageManager';
  }
}

export default StorageManager;
