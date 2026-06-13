/**
 * Native Fetch Bridge
 *
 * Bridges the C++ __nativeFetch function to the TypeScript NativeFetchModule interface.
 * This allows the TypeScript fetch implementation to use the native HTTP layer.
 */

import type { NativeFetchModule, NativeRequestInit, NativeResponse } from './types.js';
import { setNativeFetchModule } from './fetch.js';

// Declare the global __nativeFetch function installed by C++
declare global {
  /**
   * Native fetch function installed by ExactHermesBridge.cpp
   * @param url - Request URL
   * @param init - Native request init object
   * @param body - Request body as Uint8Array or null
   * @returns Promise resolving to NativeResponse
   */
  function __nativeFetch(
    url: string,
    init: NativeRequestInit,
    body: Uint8Array | null
  ): Promise<NativeResponse>;
}

/**
 * Check if the native fetch bridge is available
 */
export function isNativeFetchAvailable(): boolean {
  return typeof __nativeFetch === 'function';
}

/**
 * Create a NativeFetchModule that wraps the C++ __nativeFetch function
 */
export function createNativeFetchModule(): NativeFetchModule | null {
  if (!isNativeFetchAvailable()) {
    return null;
  }

  return {
    __exactNativeBridge: true,
    fetch: (
      url: string,
      init: NativeRequestInit,
      body: Uint8Array | null
    ): Promise<NativeResponse> => {
      return __nativeFetch(url, init, body);
    },
  };
}

/**
 * Auto-initialize the native fetch module if available.
 * Call this during runtime bootstrap.
 */
export function initializeNativeFetch(): boolean {
  const module = createNativeFetchModule();
  if (module) {
    setNativeFetchModule(module);
    return true;
  }
  return false;
}
