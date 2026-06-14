/**
 * Native Module Interfaces
 *
 * These interfaces define the bridge between JavaScript and native code.
 * The native side (Swift/Rust) must implement these for production use.
 * JavaScript fallbacks exist for testing.
 */

// =============================================================================
// Timer Module (MUST BE NATIVE)
// Native implementation handles event loop integration
// =============================================================================
export interface NativeTimerModule {
  setTimeout(callback: () => void, delay: number): number;
  clearTimeout(id: number): void;
  setInterval(callback: () => void, delay: number): number;
  clearInterval(id: number): void;
}

// =============================================================================
// Performance Module (MUST BE NATIVE)
// Native implementation provides monotonic clock
// =============================================================================
export interface NativePerformanceModule {
  /** High-resolution timestamp in milliseconds since timeOrigin */
  now(): number;
  /** Unix timestamp when the runtime started */
  timeOrigin: number;
}

// =============================================================================
// Crypto Module (MUST BE NATIVE)
// Native implementation uses CryptoKit/RustCrypto for security
// =============================================================================
export interface NativeCryptoModule {
  /** Fill array with cryptographically secure random bytes */
  getRandomValues(array: Uint8Array): Uint8Array;
  /** Generate a random UUID v4 */
  randomUUID(): string;
  /** SHA-256 hash */
  sha256(data: Uint8Array): Promise<ArrayBuffer>;
  /** SHA-384 hash */
  sha384(data: Uint8Array): Promise<ArrayBuffer>;
  /** SHA-512 hash */
  sha512(data: Uint8Array): Promise<ArrayBuffer>;
  /** SHA-1 hash (legacy, not recommended) */
  sha1(data: Uint8Array): Promise<ArrayBuffer>;
  /** Generic hash digest */
  digest?: (hash: string, data: Uint8Array) => Promise<ArrayBuffer>;
  /** Native HMAC sign helper */
  hmacSign?: (hash: string, key: Uint8Array, data: Uint8Array) => Promise<ArrayBuffer>;
  /** Native HMAC verify helper */
  hmacVerify?: (hash: string, key: Uint8Array, signature: Uint8Array, data: Uint8Array) => Promise<boolean>;
}

// =============================================================================
// Encoding Module (SHOULD BE NATIVE for large strings)
// Native implementation is faster for large payloads
// =============================================================================
export interface NativeEncodingModule {
  /** Encode string to UTF-8 bytes */
  encodeUTF8(input: string): Uint8Array;
  /** Decode UTF-8 bytes to string */
  decodeUTF8(input: Uint8Array, fatal?: boolean): string;
}

// =============================================================================
// Console Module (Native output)
// Native handles actual logging to system console/debugger
// =============================================================================
export interface NativeConsoleModule {
  log(level: string, message: string): void;
}

// =============================================================================
// Fetch Module (MUST BE NATIVE)
// Native implementation uses URLSession/OkHttp
// =============================================================================
export interface NativeFetchModule {
  fetch(
    url: string,
    options: {
      method?: string;
      headers?: Record<string, string>;
      body?: Uint8Array | string;
      signal?: { aborted: boolean };
    }
  ): Promise<{
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: Uint8Array;
  }>;
}

// =============================================================================
// WebSocket Module (MUST BE NATIVE)
// Native implementation uses platform WebSocket
// =============================================================================
export interface NativeWebSocketModule {
  create(url: string, protocols?: string[], instance?: any): number; // Returns socket ID
  send(id: number, data: string | Uint8Array): void;
  close(id: number, code?: number, reason?: string): void;
  pause?(id: number): void;
  resume?(id: number): void;
  setFlowControlled?(id: number, enabled: boolean): void;
  // Events are dispatched via callbacks set during creation
}

// =============================================================================
// Storage Module (MUST BE NATIVE - SQLite in Rust kernel)
// =============================================================================
export interface NativeStorageModule {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void; // May throw QuotaExceededError
  removeItem(key: string): void;
  clear(): void;
  key(index: number): string | null;
  length(): number;
  estimate?(): { usage: number; quota: number } | Promise<{ usage: number; quota: number }>;
  persist?(): boolean | Promise<boolean>;
  persisted?(): boolean | Promise<boolean>;
}

// =============================================================================
// File System Module (MUST BE NATIVE)
// Sandboxed access to app directories
// =============================================================================
export interface NativeFileSystemModule {
  /** Read file as bytes */
  readFile(path: string): Promise<Uint8Array>;
  /** Write bytes to file */
  writeFile(path: string, data: Uint8Array): Promise<void>;
  /** Append bytes to file */
  appendFile(path: string, data: Uint8Array): Promise<void>;
  /** Check if file exists */
  exists(path: string): Promise<boolean>;
  /** Delete file */
  unlink(path: string): Promise<void>;
  /** Get file metadata */
  stat(path: string): Promise<{ size: number; mtime_ms: number; is_dir: boolean; is_file: boolean; mode: number }>;
  /** Get file metadata (no symlink follow) */
  lstat(path: string): Promise<{ size: number; mtime_ms: number; is_dir: boolean; is_file: boolean; is_symlink: boolean; mode: number }>;
  /** List directory entries */
  readdir(path: string): Promise<string[]>;
  /** Create directory */
  mkdir(path: string, options?: { recursive?: boolean }): Promise<void>;
  /** Remove empty directory */
  rmdir(path: string): Promise<void>;
  /** Rename file or directory */
  rename(oldPath: string, newPath: string): Promise<void>;
  /** Copy a file */
  copyFile(src: string, dest: string): Promise<void>;
  /** Check access permissions */
  access(path: string, mode?: number): Promise<void>;
  /** Change file permissions */
  chmod(path: string, mode: number): Promise<void>;
  /** Resolve to canonical absolute path */
  realpath(path: string): Promise<string>;
  /** Create temporary directory */
  mkdtemp(prefix: string): Promise<string>;
  /** Get app documents directory */
  getDocumentsDir(): string;
  /** Get app cache directory */
  getCacheDir(): string;
  /** Get temp directory */
  getTempDir(): string;
}

// =============================================================================
// Global native module registry
// Native side calls these setters during bootstrap
// =============================================================================

let _timerModule: NativeTimerModule | null = null;
let _performanceModule: NativePerformanceModule | null = null;
let _cryptoModule: NativeCryptoModule | null = null;
let _encodingModule: NativeEncodingModule | null = null;
let _consoleModule: NativeConsoleModule | null = null;
let _fetchModule: NativeFetchModule | null = null;
let _webSocketModule: NativeWebSocketModule | null = null;
let _storageModule: NativeStorageModule | null = null;
let _fileSystemModule: NativeFileSystemModule | null = null;

export function setNativeTimerModule(module: NativeTimerModule): void {
  _timerModule = module;
}

export function getNativeTimerModule(): NativeTimerModule | null {
  return _timerModule;
}

export function setNativePerformanceModule(module: NativePerformanceModule): void {
  _performanceModule = module;
}

export function getNativePerformanceModule(): NativePerformanceModule | null {
  return _performanceModule;
}

export function setNativeCryptoModule(module: NativeCryptoModule): void {
  _cryptoModule = module;
}

export function getNativeCryptoModule(): NativeCryptoModule | null {
  return _cryptoModule;
}

export function setNativeEncodingModule(module: NativeEncodingModule): void {
  _encodingModule = module;
}

export function getNativeEncodingModule(): NativeEncodingModule | null {
  return _encodingModule;
}

export function setNativeConsoleModule(module: NativeConsoleModule): void {
  _consoleModule = module;
}

export function getNativeConsoleModule(): NativeConsoleModule | null {
  return _consoleModule;
}

export function setNativeFetchModule(module: NativeFetchModule): void {
  _fetchModule = module;
}

export function getNativeFetchModule(): NativeFetchModule | null {
  return _fetchModule;
}

export function setNativeWebSocketModule(module: NativeWebSocketModule): void {
  _webSocketModule = module;
}

export function getNativeWebSocketModule(): NativeWebSocketModule | null {
  return _webSocketModule;
}

export function setNativeStorageModule(module: NativeStorageModule): void {
  _storageModule = module;
}

export function getNativeStorageModule(): NativeStorageModule | null {
  return _storageModule;
}

export function setNativeFileSystemModule(module: NativeFileSystemModule): void {
  _fileSystemModule = module;
}

export function getNativeFileSystemModule(): NativeFileSystemModule | null {
  return _fileSystemModule;
}

/**
 * Check if all required native modules are available
 */
export function hasRequiredNativeModules(): boolean {
  return (
    _timerModule !== null &&
    _performanceModule !== null &&
    _cryptoModule !== null &&
    _consoleModule !== null
  );
}

/**
 * Get list of missing native modules
 */
export function getMissingNativeModules(): string[] {
  const missing: string[] = [];
  if (!_timerModule) missing.push("timer");
  if (!_performanceModule) missing.push("performance");
  if (!_cryptoModule) missing.push("crypto");
  if (!_consoleModule) missing.push("console");
  if (!_fetchModule) missing.push("fetch");
  if (!_storageModule) missing.push("storage");
  return missing;
}

// =============================================================================
// Scheduling Module (SHOULD BE NATIVE for vsync integration)
// =============================================================================
export interface NativeSchedulingModule {
  requestAnimationFrame(callback: () => void): void;
  requestIdleCallback(callback: (deadline: { didTimeout: boolean; timeRemaining: () => number }) => void, options?: { timeout?: number }): void;
}

let _schedulingModule: NativeSchedulingModule | null = null;

export function setNativeSchedulingModule(module: NativeSchedulingModule): void {
  _schedulingModule = module;
}

export function getNativeSchedulingModule(): NativeSchedulingModule | null {
  return _schedulingModule;
}

/**
 * Map of module names to their types for type-safe access
 */
export interface NativeModuleMap {
  timer: NativeTimerModule;
  performance: NativePerformanceModule;
  crypto: NativeCryptoModule;
  encoding: NativeEncodingModule;
  console: NativeConsoleModule;
  fetch: NativeFetchModule;
  websocket: NativeWebSocketModule;
  storage: NativeStorageModule;
  filesystem: NativeFileSystemModule;
  scheduling: NativeSchedulingModule;
}

/**
 * Type-safe getter for native modules by name.
 * Returns null if the module is not available.
 * 
 * @example
 * const crypto = getNativeModule('crypto');
 * if (crypto) {
 *   crypto.getRandomValues(new Uint8Array(16)); // Type-safe!
 * }
 */
export function getNativeModule<K extends keyof NativeModuleMap>(
  name: K
): NativeModuleMap[K] | null {
  switch (name) {
    case 'timer':
      return _timerModule as NativeModuleMap[K] | null;
    case 'performance':
      return _performanceModule as NativeModuleMap[K] | null;
    case 'crypto':
      return _cryptoModule as NativeModuleMap[K] | null;
    case 'encoding':
      return _encodingModule as NativeModuleMap[K] | null;
    case 'console':
      return _consoleModule as NativeModuleMap[K] | null;
    case 'fetch':
      return _fetchModule as NativeModuleMap[K] | null;
    case 'websocket':
      return _webSocketModule as NativeModuleMap[K] | null;
    case 'storage':
      return _storageModule as NativeModuleMap[K] | null;
    case 'filesystem':
      return _fileSystemModule as NativeModuleMap[K] | null;
    case 'scheduling':
      return _schedulingModule as NativeModuleMap[K] | null;
    default:
      return null;
  }
}
