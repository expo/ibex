// @ts-nocheck
/**
 * Ibex Runtime Bootstrap
 *
 * Installs web-standard globals on demand using lazy loading.
 * Essential APIs (console, timers, process, Buffer, require) load eagerly.
 * Non-essential APIs (streams, crypto, fetch, inspect) use lazy getters
 * that self-replace on first access, reducing startup GC pressure.
 */

// ---- Essential imports (always needed at startup) ----
import { setNativeCryptoModule, setNativeFileSystemModule, setNativeSchedulingModule, setNativeStorageModule, setNativeWebSocketModule } from "./native";
import { setNativeCapabilityModule, enableStrictMode } from "./security";

// ---- Lazy-loaded module imports ----
// These are still bundled, but the globals are installed via lazy getters
// so their constructors/prototypes don't allocate until first access.
import { initializeNativeFetch } from "./fetch/native-bridge";
import { installFetchGlobals } from "./fetch/fetch";
import { Headers as FetchHeaders } from "./fetch/Headers";
import { Request as FetchRequest } from "./fetch/Request";
import { Response as FetchResponse } from "./fetch/Response";
import { inspect } from "./inspect";
import { crypto as exactCrypto, Crypto, SubtleCrypto, CryptoKey } from "./crypto";
import {
  ReadableStream,
  ReadableStreamDefaultReader,
  ReadableStreamDefaultController,
  ReadableStreamBYOBReader,
  ReadableByteStreamController,
  ReadableStreamBYOBRequest,
  isReadableStream,
  WritableStream,
  WritableStreamDefaultWriter,
  WritableStreamDefaultController,
  TransformStream,
  TransformStreamDefaultController,
  ByteLengthQueuingStrategy,
  CountQueuingStrategy,
} from "./streams";

// ---- Lazy-loaded web API imports ----
// Static imports so bundler can tree-shake; values only used in lazy getters.
import { Blob, File, FormData } from "./blob";
import {
  Event, CustomEvent, EventTarget, DOMException,
  MessageEvent, CloseEvent, ErrorEvent, ProgressEvent,
  KeyboardEvent, FocusEvent,
  PromiseRejectionEvent,
} from "./events";
import { AbortController, AbortSignal } from "./abort";
import { TextEncoder, TextDecoder, TextEncoderStream, TextDecoderStream } from "./encoding";
import { URL, URLSearchParams, URLPattern } from "./url";
import { MessageChannel, MessagePort } from "./messaging";
import { VideoFrame } from "./media/VideoFrame";
import { BroadcastChannel } from "./broadcast";
import { WebSocket, WebSocketError, WebSocketStream } from "./websocket";
import { EventSource } from "./eventsource";
import { FileReader } from "./filereader";
import { navigator } from "./navigator";
import { localStorage, sessionStorage } from "./storage";
import { CacheStorage } from "./cache";
import { ClipboardItem } from "./clipboard";
import { performance as perfInstance, PerformanceObserver, PerformanceEntry, PerformanceMark, PerformanceMeasure, setNativePerformanceModule } from "./performance";
import { structuredClone as structuredCloneFn } from "./clone";
import { atob as atobFn, btoa as btoaFn } from "./base64";
import {
  requestAnimationFrame as rafFn, cancelAnimationFrame as cafFn,
  requestIdleCallback as ricFn, cancelIdleCallback as cicFn,
} from "./scheduling";
import { CompressionStream, DecompressionStream } from "./compression";
import { IDBFactory, IDBKeyRange, IDBDatabase, IDBObjectStore, IDBTransaction, IDBRequest, IDBOpenDBRequest, IDBCursor, IDBCursorWithValue, IDBIndex } from "./indexeddb";
import { Database } from "./sqlite";
import { installPolyfills } from "./polyfills";
import { installPromiseRejectionTracking } from "./promise-rejection-tracking";
import { installExactGlobal } from "./fs/ExactFile";
import { installExactAccessibilityGlobal } from "./accessibility";
import { installExactLocaleGlobal } from "./locale";
import {
  setImmediate as exactSetImmediate,
  clearImmediate as exactClearImmediate,
} from "./timers";
import { Buffer as ExactBuffer } from "./node/Buffer";
import { window as exactWindow, MediaQueryList, MediaQueryListEvent } from "./window";
import { process as exactProcess } from "./node/process";

function createGlobalBufferConstructor(BufferCtor: typeof ExactBuffer): typeof ExactBuffer {
  function Buffer(value?: unknown, encodingOrOffset?: unknown, length?: number): unknown {
    if (typeof value === 'number') {
      if (arguments.length > 1) {
        const err = new TypeError(
          `The "string" argument must be of type string. Received type number (${value})`,
        ) as TypeError & { code?: string };
        err.code = 'ERR_INVALID_ARG_TYPE';
        throw err;
      }
      return BufferCtor.allocUnsafe(value);
    }
    return (BufferCtor as any).from(value, encodingOrOffset, length);
  }

  Object.setPrototypeOf(Buffer, BufferCtor);
  Object.defineProperty(Buffer, 'prototype', {
    value: BufferCtor.prototype,
    writable: false,
    configurable: false,
  });
  return Buffer as unknown as typeof ExactBuffer;
}

/**
 * Define a lazy global property that self-replaces with the real value on first access.
 * This avoids eagerly assigning heavy objects to globalThis during bootstrap,
 * reducing GC registration and startup cost for unused APIs.
 */
function defineLazyGlobal(g: any, name: string, factory: () => any): void {
  // Skip if already defined (e.g. by native layer)
  if (typeof g[name] !== 'undefined') return;

  Object.defineProperty(g, name, {
    configurable: true,
    enumerable: true,
    get() {
      const value = factory();
      // Replace getter with direct value property for subsequent accesses
      Object.defineProperty(g, name, {
        value,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      return value;
    },
  });
}

function preserveConstructorName<T>(value: T, expectedName: string): T {
  if (typeof value === 'function' && (value as Function).name !== expectedName) {
    try {
      Object.defineProperty(value, 'name', {
        value: expectedName,
        writable: false,
        configurable: true,
        enumerable: false,
      });
    } catch (_) {}
  }
  return value;
}

// Track whether fetch has been lazily initialized
let _fetchInitialized = false;

// Track whether filesystem module has been lazily initialized
let _fsModuleInitialized = false;

const WEB_STORAGE_QUOTA_BYTES = 10 * 1024 * 1024;

function trimTrailingSlash(path: string): string {
  return path.replace(/\/+$/, '') || '/';
}

function getNativeStorageRoot(g: any): string {
  const androidFilesDir = g.__exactAndroidStoragePaths?.filesDir;
  if (typeof androidFilesDir === 'string' && androidFilesDir.length > 0) {
    return trimTrailingSlash(androidFilesDir);
  }

  const env = g.process?.env;
  const envFilesDir = env?.EXACT_ANDROID_FILES_DIR ?? env?.HOME;
  if (typeof envFilesDir === 'string' && envFilesDir.length > 0) {
    return trimTrailingSlash(envFilesDir);
  }

  return '/tmp';
}

function ensureStorageDirectory(g: any, directory: string): void {
  try {
    if (typeof g.__exactMkdir !== 'function' && typeof g.__exactEnsureFs === 'function') {
      g.__exactEnsureFs();
    }
    if (typeof g.__exactMkdir === 'function') {
      g.__exactMkdir(directory, true);
    }
  } catch (_) {}
}

function installSQLiteStorageModule(g: any): boolean {
  if (
    typeof g.__exactSqliteOpen !== 'function' &&
    typeof g.__exactEnsureSqlite !== 'function'
  ) {
    return false;
  }

  let db: Database | null = null;

  const ensureDb = (): Database => {
    if (db) return db;
    if (typeof g.__exactSqliteOpen !== 'function' && typeof g.__exactEnsureSqlite === 'function') {
      g.__exactEnsureSqlite();
    }
    if (typeof g.__exactSqliteOpen !== 'function') {
      throw new Error('SQLite native bridge is not available for Web Storage');
    }

    // @ref LLP 0008#android-backend-matrix — Android localStorage persists under app filesDir.
    const directory = `${getNativeStorageRoot(g)}/.ibex`;
    ensureStorageDirectory(g, directory);
    db = new Database(`${directory}/web-storage.sqlite`, {
      create: true,
      readwrite: true,
    });
    db.run(
      'CREATE TABLE IF NOT EXISTS exact_web_storage (' +
        'storage_key TEXT PRIMARY KEY NOT NULL, ' +
        'storage_value TEXT NOT NULL' +
      ')',
    );
    return db;
  };

  const storageUsage = (): number => {
    const row = ensureDb()
      .query<{ usage: number | bigint }>('SELECT COALESCE(SUM(length(storage_key) + length(storage_value)), 0) AS usage FROM exact_web_storage')
      .get();
    return Number(row?.usage ?? 0);
  };

  const quotaExceeded = (): never => {
    throw new DOMException('Storage quota exceeded', 'QuotaExceededError');
  };

  setNativeStorageModule({
    getItem(key: string): string | null {
      const row = ensureDb()
        .query<{ storage_value: string }, [string]>('SELECT storage_value FROM exact_web_storage WHERE storage_key = ?')
        .get(String(key));
      return typeof row?.storage_value === 'string' ? row.storage_value : null;
    },
    setItem(key: string, value: string): void {
      const keyStr = String(key);
      const valueStr = String(value);
      const oldValue = this.getItem(keyStr);
      const oldSize = oldValue === null ? 0 : keyStr.length + oldValue.length;
      const nextSize = storageUsage() - oldSize + keyStr.length + valueStr.length;
      if (nextSize > WEB_STORAGE_QUOTA_BYTES) {
        quotaExceeded();
      }
      ensureDb().run(
        'INSERT INTO exact_web_storage(storage_key, storage_value) VALUES (?, ?) ' +
          'ON CONFLICT(storage_key) DO UPDATE SET storage_value = excluded.storage_value',
        keyStr,
        valueStr,
      );
    },
    removeItem(key: string): void {
      ensureDb().run('DELETE FROM exact_web_storage WHERE storage_key = ?', String(key));
    },
    clear(): void {
      ensureDb().run('DELETE FROM exact_web_storage');
    },
    key(index: number): string | null {
      const offset = Math.trunc(Number(index));
      if (!Number.isFinite(offset) || offset < 0) return null;
      const row = ensureDb()
        .query<{ storage_key: string }, [number]>('SELECT storage_key FROM exact_web_storage ORDER BY rowid LIMIT 1 OFFSET ?')
        .get(offset);
      return typeof row?.storage_key === 'string' ? row.storage_key : null;
    },
    length(): number {
      const row = ensureDb()
        .query<{ count: number | bigint }>('SELECT COUNT(*) AS count FROM exact_web_storage')
        .get();
      return Number(row?.count ?? 0);
    },
    estimate() {
      return {
        usage: storageUsage(),
        quota: WEB_STORAGE_QUOTA_BYTES,
      };
    },
    persist() {
      return true;
    },
    persisted() {
      return true;
    },
  });

  return true;
}

/**
 * Ensure fetch globals are initialized (called lazily on first access)
 */
function ensureFetchInitialized(): void {
  if (_fetchInitialized) return;
  _fetchInitialized = true;
  const g = globalThis as any;
  if (typeof g.__nativeFetch === 'function') {
    initializeNativeFetch();
    installFetchGlobals(g);
  }
}

// Track whether crypto has been lazily initialized
let _cryptoInitialized = false;

/**
 * Get the crypto object, initializing native crypto module if needed.
 * Called lazily on first access of globalThis.crypto.
 */
function ensureCryptoInitialized(): any {
  if (_cryptoInitialized) return exactCrypto;
  _cryptoInitialized = true;
  return exactCrypto;
}

/**
 * Install runtime globals with lazy loading for non-essential APIs.
 *
 * Essential (immediate): process, __exactRuntimeLoaded, capabilities, fs bridge
 * Lazy (on first access): crypto, streams, fetch, inspect
 */
export function installGlobals(): void {
  const g = globalThis as any;
  if (g.__exactLoadTimings) g.__exactLoadTimings.installGlobalsStart = Date.now();

  if (typeof g.__exactHostNavigator === 'undefined' && typeof g.navigator === 'object' && g.navigator) {
    g.__exactHostNavigator = g.navigator;
  }

  installExactLocaleGlobal();
  installExactAccessibilityGlobal();

  // ========================================
  // ESSENTIAL: Runtime marker
  // ========================================
  g.__exactRuntimeLoaded = true;

  // ========================================
  // ESSENTIAL: process object (Node.js compat)
  // Install the full Process class with real event emitter support.
  // Preserve key env vars from the host runtime's process (e.g. NODE_ENV=test in Bun).
  // ========================================
  const _prevEnv: Record<string, string | undefined> = {};
  const _oldProcess = g.process;
  if (
    g.__exactRuntimeContext !== 'shell' &&
    g.process?.env &&
    typeof g.process.env === 'object'
  ) {
    const hostEnv = g.process.env;
    for (const key of ['NODE_ENV', 'EXACT_ALLOW_INSECURE_CRYPTO', 'CI', 'TEST']) {
      const val = hostEnv[key];
      if (typeof val === 'string') _prevEnv[key] = val;
    }
  }
  g.process = exactProcess;
  // Copy over properties from the old (native-patched) process object that
  // the new Process class doesn't have (e.g. emitWarning, features, etc.)
  if (_oldProcess && typeof _oldProcess === 'object') {
    const skip = new Set(['env', 'version', 'versions', 'platform', 'arch',
      'pid', 'ppid', 'argv', 'argv0', 'execPath', 'execArgv', 'title',
      'stdin', 'stdout', 'stderr', 'config', 'release', 'browser',
      'on', 'off', 'once', 'emit', 'removeListener', 'removeAllListeners',
      'listeners', 'listenerCount', 'addListener', '_events']);
    for (const key of Object.getOwnPropertyNames(_oldProcess)) {
      if (!skip.has(key) && (exactProcess as any)[key] === undefined) {
        try {
          (exactProcess as any)[key] = (_oldProcess as any)[key];
        } catch (_e) { /* skip read-only */ }
      }
    }
    // Also check the prototype chain for methods added via addEventEmitter
    const proto = Object.getPrototypeOf(_oldProcess);
    if (proto && proto !== Object.prototype) {
      for (const key of Object.getOwnPropertyNames(proto)) {
        if (!skip.has(key) && (exactProcess as any)[key] === undefined) {
          try {
            (exactProcess as any)[key] = proto[key];
          } catch (_e) { /* skip */ }
        }
      }
    }
  }
  // Re-apply host env vars so existing env checks (e.g. NODE_ENV === 'test') still work
  for (const [key, val] of Object.entries(_prevEnv)) {
    if (exactProcess.env[key] === undefined || exactProcess.env[key] === 'development') {
      exactProcess.env[key] = val;
    }
  }

  // ========================================
  // ESSENTIAL: Buffer (Node.js compat)
  // Shared runtime bootstrap must install this explicitly because the legacy
  // bootstrap-globals path is skipped once the runtime bundle loads.
  // ========================================
  if (typeof g.Buffer === 'undefined') {
    Object.defineProperty(g, 'Buffer', {
      value: createGlobalBufferConstructor(ExactBuffer),
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }

  Object.defineProperty(g, 'setImmediate', {
    value: exactSetImmediate,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  Object.defineProperty(g, 'clearImmediate', {
    value: exactClearImmediate,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  const exactFormatBytes = (value: unknown): string => {
    let bytes = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(bytes) || bytes <= 0) {
      return '0B';
    }
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let unitIndex = 0;
    while (bytes >= 1024 && unitIndex < units.length - 1) {
      bytes /= 1024;
      unitIndex += 1;
    }
    const formatted = bytes >= 100 || unitIndex === 0
      ? bytes.toFixed(0)
      : bytes.toFixed(1).replace(/\.0$/, '');
    return `${formatted}${units[unitIndex]}`;
  };

  const exactEstimateStringBytes = (value: unknown): number => {
    if (typeof value !== 'string' || value.length === 0) {
      return 0;
    }
    if (typeof TextEncoder === 'function') {
      try {
        return new TextEncoder().encode(value).length;
      } catch {
        return value.length * 2;
      }
    }
    return value.length * 2;
  };

  const exactNormalizeMemoryOptions = (input: unknown) => {
    if (input && typeof input === 'object') {
      const candidate = input as {
        includeExpensive?: unknown;
        includeGCStats?: unknown;
      };
      return {
        includeExpensive: candidate.includeExpensive === true,
        includeGCStats: candidate.includeGCStats === true,
      };
    }
    return {
      includeExpensive: input === true,
      includeGCStats: false,
    };
  };

  const exactGetDebugModuleSourcesSummary = () => {
    const entries = Array.isArray(g.__exactDebugModuleSources)
      ? g.__exactDebugModuleSources
      : [];
    let totalBytes = 0;
    for (const entry of entries) {
      if (entry && typeof entry.source === 'string') {
        totalBytes += exactEstimateStringBytes(entry.source);
      }
    }
    const configuredLimit = Number(g.__exactDebugModuleSourceLimit);
    return {
      count: entries.length,
      totalBytes,
      currentSourceBytes: exactEstimateStringBytes(
        typeof g.__exactDebugModuleSource === 'string'
          ? g.__exactDebugModuleSource
          : '',
      ),
      limit:
        Number.isFinite(configuredLimit) && configuredLimit > 0
          ? Math.floor(configuredLimit)
          : 256,
    };
  };

  const exactGetPerformanceTimelineSummary = () => {
    const performanceObject =
      typeof g.performance === 'object' && g.performance !== null
        ? g.performance as {
            _entries?: unknown;
            _marks?: { size?: unknown } | null;
            _measures?: { size?: unknown } | null;
          }
        : null;
    if (!performanceObject) {
      return {
        entries: 0,
        markNames: 0,
        measureNames: 0,
      };
    }
    const entries = Array.isArray(performanceObject._entries)
      ? performanceObject._entries.length
      : 0;
    const markNames =
      typeof performanceObject._marks?.size === 'number'
        ? performanceObject._marks.size
        : 0;
    const measureNames =
      typeof performanceObject._measures?.size === 'number'
        ? performanceObject._measures.size
        : 0;
    return {
      entries,
      markNames,
      measureNames,
    };
  };

  const exactMemorySnapshot = (input: unknown) => {
    const options = exactNormalizeMemoryOptions(input);
    let usage: unknown = null;
    if (typeof exactProcess.memoryUsage === 'function') {
      try {
        usage = exactProcess.memoryUsage();
      } catch {
        usage = null;
      }
    }

    let heapInfo: unknown = null;
    if (typeof g.__exactGetHeapInfo === 'function') {
      try {
        heapInfo = g.__exactGetHeapInfo(options.includeExpensive);
      } catch {
        heapInfo = null;
      }
    }

    let gcStats: unknown = null;
    if (options.includeGCStats && typeof g.__exactGetGCStats === 'function') {
      try {
        const rawGcStats = g.__exactGetGCStats();
        gcStats = typeof rawGcStats === 'string' ? JSON.parse(rawGcStats) : null;
      } catch {
        gcStats = null;
      }
    }

    let sourceCache: unknown = null;
    if (typeof g.__exactGetSourceCacheStats === 'function') {
      try {
        sourceCache = g.__exactGetSourceCacheStats();
      } catch {
        sourceCache = null;
      }
    }

    const loader = typeof g.__exactRequire === 'function' ? g.__exactRequire : g.require;
    const requireCacheCount =
      loader && loader.cache && typeof loader.cache === 'object'
        ? Object.keys(loader.cache).length
        : 0;

    return {
      timestamp: Date.now(),
      usage,
      heapInfo,
      gcStats,
      sourceCache,
      performanceTimeline: exactGetPerformanceTimelineSummary(),
      requireCacheCount,
      debugModuleSources: exactGetDebugModuleSourcesSummary(),
    };
  };

  const exactMemorySummary = (snapshotInput: unknown) => {
    const snapshot =
      snapshotInput && typeof snapshotInput === 'object'
        ? snapshotInput as Record<string, any>
        : exactMemorySnapshot(snapshotInput);
    const usage = snapshot.usage && typeof snapshot.usage === 'object'
      ? snapshot.usage
      : {};
    const heapInfo = snapshot.heapInfo && typeof snapshot.heapInfo === 'object'
      ? snapshot.heapInfo
      : {};
    const sourceCache = snapshot.sourceCache && typeof snapshot.sourceCache === 'object'
      ? snapshot.sourceCache
      : {};
    const performanceTimeline =
      snapshot.performanceTimeline && typeof snapshot.performanceTimeline === 'object'
        ? snapshot.performanceTimeline
        : {};
    const debugModuleSources =
      snapshot.debugModuleSources && typeof snapshot.debugModuleSources === 'object'
        ? snapshot.debugModuleSources
        : {};
    const heapUsed =
      typeof usage.heapUsed === 'number'
        ? usage.heapUsed
        : typeof heapInfo.hermes_allocatedBytes === 'number'
          ? heapInfo.hermes_allocatedBytes
          : 0;
    const heapTotal =
      typeof usage.heapTotal === 'number'
        ? usage.heapTotal
        : typeof heapInfo.hermes_heapSize === 'number'
          ? heapInfo.hermes_heapSize
          : 0;
    return {
      timestamp: typeof snapshot.timestamp === 'number' ? snapshot.timestamp : Date.now(),
      heapUsed,
      heapTotal,
      rss: typeof usage.rss === 'number' ? usage.rss : 0,
      external:
        typeof usage.external === 'number'
          ? usage.external
          : typeof heapInfo.hermes_externalBytes === 'number'
            ? heapInfo.hermes_externalBytes
            : 0,
      requireCacheCount:
        typeof snapshot.requireCacheCount === 'number' ? snapshot.requireCacheCount : 0,
      performanceEntriesCount:
        typeof performanceTimeline.entries === 'number' ? performanceTimeline.entries : 0,
      debugModuleSourcesCount:
        typeof debugModuleSources.count === 'number' ? debugModuleSources.count : 0,
      debugModuleSourcesBytes:
        typeof debugModuleSources.totalBytes === 'number' ? debugModuleSources.totalBytes : 0,
      sourceCacheCount:
        typeof sourceCache.count === 'number' ? sourceCache.count : 0,
      sourceCacheBytes:
        typeof sourceCache.totalBytes === 'number' ? sourceCache.totalBytes : 0,
      numCollections:
        typeof heapInfo.hermes_numCollections === 'number'
          ? heapInfo.hermes_numCollections
          : typeof heapInfo.numCollections === 'number'
            ? heapInfo.numCollections
            : 0,
    };
  };

  const exactLogMemorySample = (snapshot: unknown) => {
    const summary = exactMemorySummary(snapshot);
    console.info(
      '[exact:memory]',
      `heap=${exactFormatBytes(summary.heapUsed)}/${exactFormatBytes(summary.heapTotal)}`,
      `rss=${exactFormatBytes(summary.rss)}`,
      `external=${exactFormatBytes(summary.external)}`,
      `require=${summary.requireCacheCount}`,
      `perf=${summary.performanceEntriesCount}`,
      `debugSources=${summary.debugModuleSourcesCount}/${exactFormatBytes(summary.debugModuleSourcesBytes)}`,
      `sourceCache=${summary.sourceCacheCount}/${exactFormatBytes(summary.sourceCacheBytes)}`,
      `gc=${summary.numCollections}`,
    );
  };

  if (!g.__exactMemoryDebugState || typeof g.__exactMemoryDebugState !== 'object') {
    g.__exactMemoryDebugState = {
      timer: null,
      samples: [],
      nextSampleId: 0,
      options: null,
      sampleCount: 0,
      lastLoggedHeapUsed: 0,
    };
  }

  const exactMemoryDebugState = g.__exactMemoryDebugState;
  const exactStopMemorySampler = () => {
    if (exactMemoryDebugState.timer != null) {
      clearInterval(exactMemoryDebugState.timer);
      exactMemoryDebugState.timer = null;
    }
    return exactMemoryDebugState.samples.slice();
  };

  g.__exactMemoryDebug = {
    snapshot: (options?: unknown) => exactMemorySnapshot(options),
    summary: (options?: unknown) => exactMemorySummary(exactMemorySnapshot(options)),
    samples: () => exactMemoryDebugState.samples.slice(),
    state: () => ({
      running: exactMemoryDebugState.timer != null,
      options: exactMemoryDebugState.options,
      sampleCount: exactMemoryDebugState.sampleCount,
      retainedSamples: exactMemoryDebugState.samples.length,
    }),
    clearModuleDebugSources: () => {
      if (Array.isArray(g.__exactDebugModuleSources)) {
        g.__exactDebugModuleSources.length = 0;
      }
      g.__exactDebugModuleSource = undefined;
      return exactGetDebugModuleSourcesSummary();
    },
    stop: () => exactStopMemorySampler(),
    start: (options?: {
      intervalMs?: number;
      maxSamples?: number;
      logEvery?: number;
      logOnGrowthBytes?: number;
      includeExpensive?: boolean;
      includeGCStats?: boolean;
    }) => {
      exactStopMemorySampler();
      const normalizedOptions = {
        intervalMs: Math.max(200, Number(options?.intervalMs) || 1000),
        maxSamples: Math.max(10, Number(options?.maxSamples) || 240),
        logEvery: Math.max(0, Math.floor(Number(options?.logEvery) || 0)),
        logOnGrowthBytes: Math.max(
          0,
          Math.floor(Number(options?.logOnGrowthBytes) || (32 * 1024 * 1024)),
        ),
        includeExpensive: options?.includeExpensive === true,
        includeGCStats: options?.includeGCStats === true,
      };
      exactMemoryDebugState.samples = [];
      exactMemoryDebugState.sampleCount = 0;
      exactMemoryDebugState.lastLoggedHeapUsed = 0;
      exactMemoryDebugState.options = normalizedOptions;
      const takeSample = () => {
        const sample = exactMemorySnapshot(normalizedOptions);
        exactMemoryDebugState.nextSampleId += 1;
        sample.sampleId = exactMemoryDebugState.nextSampleId;
        exactMemoryDebugState.samples.push(sample);
        if (exactMemoryDebugState.samples.length > normalizedOptions.maxSamples) {
          exactMemoryDebugState.samples.splice(
            0,
            exactMemoryDebugState.samples.length - normalizedOptions.maxSamples,
          );
        }
        exactMemoryDebugState.sampleCount += 1;
        const summary = exactMemorySummary(sample);
        const shouldLog =
          exactMemoryDebugState.sampleCount === 1 ||
          (normalizedOptions.logEvery > 0 &&
            exactMemoryDebugState.sampleCount % normalizedOptions.logEvery === 0) ||
          (normalizedOptions.logOnGrowthBytes > 0 &&
            summary.heapUsed - exactMemoryDebugState.lastLoggedHeapUsed >=
              normalizedOptions.logOnGrowthBytes);
        if (shouldLog) {
          exactMemoryDebugState.lastLoggedHeapUsed = summary.heapUsed;
          exactLogMemorySample(sample);
        }
        return sample;
      };
      const first = takeSample();
      exactMemoryDebugState.timer = setInterval(takeSample, normalizedOptions.intervalMs);
      if (typeof exactMemoryDebugState.timer?.unref === 'function') {
        exactMemoryDebugState.timer.unref();
      }
      return first;
    },
    formatBytes: exactFormatBytes,
  };

  // ========================================
  // ESSENTIAL: Capability security bridge
  // ========================================
  if (typeof g.__exactCapabilityCheck === 'function') {
    setNativeCapabilityModule({
      checkCapability: (capability: string, moduleId?: number) =>
        !!g.__exactCapabilityCheck(capability, moduleId),
      requestCapability: async (capability: string) =>
        !!g.__exactCapabilityCheck(capability),
      getGrantedCapabilities: () => [],
    });
    enableStrictMode();
  }

  // ========================================
  // ESSENTIAL: Native crypto bridge registration
  // (registers the native module but doesn't create the global crypto object)
  // ========================================
  if (typeof g.__exactRandomBytes === 'function') {
    setNativeCryptoModule({
      getRandomValues: (array: Uint8Array) => {
        const bytes: Uint8Array = g.__exactRandomBytes(array.byteLength);
        array.set(bytes);
        return array;
      },
      randomUUID: () => {
        const bytes: Uint8Array = g.__exactRandomBytes(16);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'));
        return (
          hex.slice(0, 4).join('') + '-' +
          hex.slice(4, 6).join('') + '-' +
          hex.slice(6, 8).join('') + '-' +
          hex.slice(8, 10).join('') + '-' +
          hex.slice(10).join('')
        );
      },
      sha256: async () => {
        throw new DOMException('sha256 not available', 'NotSupportedError');
      },
      sha384: async () => {
        throw new DOMException('sha384 not available', 'NotSupportedError');
      },
      sha512: async () => {
        throw new DOMException('sha512 not available', 'NotSupportedError');
      },
      sha1: async () => {
        throw new DOMException('sha1 not available', 'NotSupportedError');
      },
      digest: typeof g.__exactCryptoSubtleDigest === 'function'
        ? async (hash: string, data: Uint8Array) => Promise.resolve(g.__exactCryptoSubtleDigest(hash, data))
        : undefined,
      hmacSign: typeof g.__exactCryptoSubtleSign === 'function'
        ? async (hash: string, key: Uint8Array, data: Uint8Array) => Promise.resolve(
            g.__exactCryptoSubtleSign(hash, key, data)
          )
        : undefined,
      hmacVerify: typeof g.__exactCryptoSubtleVerify === 'function'
        ? async (
            hash: string,
            key: Uint8Array,
            signature: Uint8Array,
            data: Uint8Array
          ) => Promise.resolve(g.__exactCryptoSubtleVerify(hash, key, signature, data))
        : undefined,
    });
  }

  // ========================================
  // LAZY: crypto global (deferred until first access)
  // ========================================
  if (!g.crypto) {
    Object.defineProperty(g, 'crypto', {
      configurable: true,
      enumerable: true,
      get() {
        const value = ensureCryptoInitialized();
        Object.defineProperty(g, 'crypto', {
          value,
          writable: true,
          configurable: true,
          enumerable: true,
        });
        return value;
      },
    });
  } else {
    // crypto object may already exist (e.g., from native/bootstrap layer).
    // Replace subtle with our full SubtleCrypto implementation as a read-only
    // getter property. In browsers/Bun, crypto.subtle is a getter-only property —
    // assigning to it is silently ignored. This prevents test code from
    // accidentally clobbering subtle (e.g. `globalThis.crypto.subtle = 123`).
    const fullSubtle = exactCrypto.subtle;
    const subtleDescriptor = Object.getOwnPropertyDescriptor(g.crypto, 'subtle');

    // If subtle already exists and is non-configurable (common in Bun), we
    // should not redefine it; simply leave the existing descriptor in place.
    if (!subtleDescriptor || subtleDescriptor.configurable) {
      Object.defineProperty(g.crypto, 'subtle', {
        get() { return fullSubtle; },
        set() { /* no-op, matching browser behavior */ },
        enumerable: true,
        configurable: true,
      });
    }
  }

  // Mark that the full SubtleCrypto is installed so the bootstrap shim
  // (web-crypto.js) doesn't overwrite it when loaded later via
  // __exactEnsureWebCrypto() triggered by require("node:crypto").
  if (g.crypto && g.crypto.subtle) {
    try {
      Object.defineProperty(g.crypto.subtle, '__exactFullSubtle', {
        value: true,
        writable: false,
        enumerable: false,
        configurable: false,
      });
    } catch (_) {}
  }

  if (typeof g.Crypto === 'undefined') {
    Object.defineProperty(g, 'Crypto', {
      value: Crypto,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }

  if (typeof g.SubtleCrypto === 'undefined') {
    Object.defineProperty(g, 'SubtleCrypto', {
      value: SubtleCrypto,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }

  if (typeof g.CryptoKey === 'undefined') {
    Object.defineProperty(g, 'CryptoKey', {
      value: CryptoKey,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }

  // ========================================
  // LAZY: Filesystem bridge
  // Deferred until first fs operation to avoid triggering macOS sandbox
  // permission prompts at startup.
  // ========================================
  if (typeof g.__exactReadFile === 'function' || typeof g.__exactEnsureFs === 'function') {
    g.__exactEnsureFilesystemModule = () => {
      if (_fsModuleInitialized) return;
      if (typeof g.__exactReadFile !== 'function' && typeof g.__exactEnsureFs === 'function') {
        g.__exactEnsureFs();
      }
      if (typeof g.__exactReadFile !== 'function') {
        return;
      }
      _fsModuleInitialized = true;

      const toBytes = (data: Uint8Array): Uint8Array => {
        if (data instanceof Uint8Array) return data;
        return new Uint8Array(data);
      };

      setNativeFileSystemModule({
        readFile: async (path: string) => g.__exactReadFile(path),
        writeFile: async (path: string, data: Uint8Array) => g.__exactWriteFile(path, toBytes(data)),
        appendFile: async (path: string, data: Uint8Array) => g.__exactAppendFile(path, toBytes(data)),
        exists: async (path: string) => {
          try { g.__exactAccess(path, 0); return true; } catch { return false; }
        },
        unlink: async (path: string) => g.__exactUnlink(path),
        stat: async (path: string) => JSON.parse(g.__exactStat(path)),
        lstat: async (path: string) => JSON.parse(g.__exactLstat(path)),
        readdir: async (path: string) => JSON.parse(g.__exactReaddir(path)),
        mkdir: async (path: string, options?: { recursive?: boolean }) =>
          g.__exactMkdir(path, !!(options && options.recursive)),
        rmdir: async (path: string) => g.__exactRmdir(path),
        rename: async (oldPath: string, newPath: string) => g.__exactRename(oldPath, newPath),
        copyFile: async (src: string, dest: string) => g.__exactCopyFile(src, dest),
        access: async (path: string, mode?: number) => g.__exactAccess(path, mode ?? 0),
        chmod: async (path: string, mode: number) => g.__exactChmod(path, mode),
        realpath: async (path: string) => g.__exactRealpath(path),
        mkdtemp: async (prefix: string) => g.__exactMkdtemp(prefix),
        getDocumentsDir: () => '/',
        getCacheDir: () => '/',
        getTempDir: () => '/',
      });
    };
  }

  // ========================================
  // Fetch API
  // ========================================
  // Headers, Request, Response are always available (they work without native fetch).
  // The fetch() function itself requires the native bridge.
  Object.defineProperty(g, 'Headers', {
    value: FetchHeaders,
    writable: true,
    configurable: true,
    enumerable: true,
  });
  Object.defineProperty(g, 'Request', {
    value: FetchRequest,
    writable: true,
    configurable: true,
    enumerable: true,
  });
  Object.defineProperty(g, 'Response', {
    value: FetchResponse,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  if (typeof g.__nativeFetch === 'function') {
    if (typeof g.fetch === 'undefined') {
      // Install a lazy getter for 'fetch' that triggers full fetch initialization.
      // We must delete the getter first to avoid infinite recursion, since
      // installFetchGlobals will redefine g.fetch as a data property.
      Object.defineProperty(g, 'fetch', {
        configurable: true,
        enumerable: true,
        get() {
          // Remove the getter before initializing to prevent recursion
          delete g.fetch;
          ensureFetchInitialized();
          return g.fetch;
        },
      });
    }
  }

  // ========================================
  // ESSENTIAL: WebSocket native bridge registration
  // Wire up C++ __exactWsConnect/__exactWsSend/__exactWsClose as the native WebSocket module.
  // The create() method passes the WebSocket instance so C++ callbacks can call
  // _handleOpen/_handleMessage/_handleClose/_handleError/_handleBytesSent on it.
  // ========================================
  if (typeof g.__exactWsConnect === 'function') {
    setNativeWebSocketModule({
      create(url: string, protocols?: string[], instance?: any): number {
        const protocolStr = (protocols || []).join(',');
        return g.__exactWsConnect(url, protocolStr, instance);
      },
      send(id: number, data: string | Uint8Array): void {
        g.__exactWsSend(id, data);
      },
      close(id: number, code?: number, reason?: string): void {
        g.__exactWsClose(id, code ?? 1005, reason ?? '');
      },
      pause(id: number): void {
        if (typeof g.__exactWsPause === 'function') {
          g.__exactWsPause(id);
        }
      },
      resume(id: number): void {
        if (typeof g.__exactWsResume === 'function') {
          g.__exactWsResume(id);
        }
      },
      setFlowControlled(id: number, enabled: boolean): void {
        if (typeof g.__exactWsSetFlowControlled === 'function') {
          g.__exactWsSetFlowControlled(id, !!enabled);
        }
      },
    });
  }

  // ========================================
  // LAZY: Exact.inspect (pretty printing) & setModuleCapabilities
  // ========================================
  g.Exact = g.Exact || ({} as any);
  // Lazy-load inspect: only resolve when actually called
  Object.defineProperty(g.Exact, 'inspect', {
    configurable: true,
    enumerable: true,
    get() {
      Object.defineProperty(g.Exact, 'inspect', {
        value: inspect,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      return inspect;
    },
  });
  g.Exact.setModuleCapabilities = function(moduleId: number, capabilities: string[]) {
    // Grant capabilities through native layer
    const grantFn = (g as any).__exactGrantCapability;
    if (typeof grantFn === 'function') {
      for (let i = 0; i < capabilities.length; i++) {
        grantFn(moduleId, capabilities[i]);
      }
    }
  };

  // ========================================
  // LAZY: Web Streams API (deferred until first access)
  // ========================================
  defineLazyGlobal(g, 'ReadableStream', () => preserveConstructorName(ReadableStream, 'ReadableStream'));
  defineLazyGlobal(g, 'ReadableStreamDefaultReader', () => preserveConstructorName(ReadableStreamDefaultReader, 'ReadableStreamDefaultReader'));
  defineLazyGlobal(g, 'ReadableStreamDefaultController', () => preserveConstructorName(ReadableStreamDefaultController, 'ReadableStreamDefaultController'));
  defineLazyGlobal(g, 'ReadableByteStreamController', () => preserveConstructorName(ReadableByteStreamController, 'ReadableByteStreamController'));
  defineLazyGlobal(g, 'ReadableStreamBYOBReader', () => preserveConstructorName(ReadableStreamBYOBReader, 'ReadableStreamBYOBReader'));
  defineLazyGlobal(g, 'ReadableStreamBYOBRequest', () => preserveConstructorName(ReadableStreamBYOBRequest, 'ReadableStreamBYOBRequest'));
  defineLazyGlobal(g, 'WritableStream', () => preserveConstructorName(WritableStream, 'WritableStream'));
  defineLazyGlobal(g, 'WritableStreamDefaultWriter', () => preserveConstructorName(WritableStreamDefaultWriter, 'WritableStreamDefaultWriter'));
  defineLazyGlobal(g, 'WritableStreamDefaultController', () => preserveConstructorName(WritableStreamDefaultController, 'WritableStreamDefaultController'));
  defineLazyGlobal(g, 'TransformStream', () => preserveConstructorName(TransformStream, 'TransformStream'));
  defineLazyGlobal(g, 'TransformStreamDefaultController', () => preserveConstructorName(TransformStreamDefaultController, 'TransformStreamDefaultController'));
  defineLazyGlobal(g, 'ByteLengthQueuingStrategy', () => preserveConstructorName(ByteLengthQueuingStrategy, 'ByteLengthQueuingStrategy'));
  defineLazyGlobal(g, 'CountQueuingStrategy', () => preserveConstructorName(CountQueuingStrategy, 'CountQueuingStrategy'));
  if (typeof g.__exactIsReadableStream !== 'function') {
    g.__exactIsReadableStream = isReadableStream;
  }

  // ========================================
  // LAZY: Blob, File, FormData
  // ========================================
  defineLazyGlobal(g, 'Blob', () => Blob);
  defineLazyGlobal(g, 'File', () => File);
  defineLazyGlobal(g, 'FormData', () => FormData);


  // ========================================
  // LAZY: Event, CustomEvent, EventTarget, DOMException
  // ========================================
  defineLazyGlobal(g, 'Event', () => Event);
  defineLazyGlobal(g, 'CustomEvent', () => CustomEvent);
  defineLazyGlobal(g, 'EventTarget', () => EventTarget);
  defineLazyGlobal(g, 'DOMException', () => DOMException);
  defineLazyGlobal(g, 'MessageEvent', () => MessageEvent);
  defineLazyGlobal(g, 'CloseEvent', () => {
    const globalEvent = g.Event || Event;
    if (globalEvent && Object.getPrototypeOf(CloseEvent) !== globalEvent) {
      Object.setPrototypeOf(CloseEvent, globalEvent);
    }
    if (
      globalEvent &&
      globalEvent.prototype &&
      Object.getPrototypeOf(CloseEvent.prototype) !== globalEvent.prototype
    ) {
      Object.setPrototypeOf(CloseEvent.prototype, globalEvent.prototype);
    }
    return CloseEvent;
  });
  defineLazyGlobal(g, 'ErrorEvent', () => ErrorEvent);
  defineLazyGlobal(g, 'ProgressEvent', () => ProgressEvent);
  defineLazyGlobal(g, 'KeyboardEvent', () => KeyboardEvent);
  defineLazyGlobal(g, 'FocusEvent', () => FocusEvent);
  defineLazyGlobal(g, 'PromiseRejectionEvent', () => PromiseRejectionEvent);

  // ========================================
  // LAZY: AbortController, AbortSignal
  // ========================================
  defineLazyGlobal(g, 'AbortController', () => AbortController);
  defineLazyGlobal(g, 'AbortSignal', () => AbortSignal);

  // ========================================
  // TextEncoder, TextDecoder
  // ========================================
  // Install TextEncoder/TextDecoder lazily — the full TextDecoder is ~4K
  // lines and initializing it eagerly adds measurable startup cost.
  defineLazyGlobal(g, 'TextEncoder', () => TextEncoder);
  defineLazyGlobal(g, 'TextDecoder', () => TextDecoder);
  defineLazyGlobal(g, 'TextEncoderStream', () => TextEncoderStream);
  defineLazyGlobal(g, 'TextDecoderStream', () => TextDecoderStream);

  // ========================================
  // LAZY: URL, URLSearchParams
  // ========================================
  // Prefer the host's WHATWG URL implementation when it exists. Our TypeScript
  // fallback stays available for runtimes that do not provide URL globals.
  if (typeof g.URL === 'undefined') {
    Object.defineProperty(g, 'URL', {
      value: URL,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }
  if (typeof g.URLSearchParams === 'undefined') {
    Object.defineProperty(g, 'URLSearchParams', {
      value: URLSearchParams,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }
  if (typeof g.URL === 'function') {
    const urlCtor = g.URL as typeof URL;
    if (typeof (urlCtor as any).createObjectURL !== 'function') {
      Object.defineProperty(urlCtor, 'createObjectURL', {
        value: URL.createObjectURL,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    }
    if (typeof (urlCtor as any).revokeObjectURL !== 'function') {
      Object.defineProperty(urlCtor, 'revokeObjectURL', {
        value: URL.revokeObjectURL,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    }
  }
  defineLazyGlobal(g, 'URLPattern', () => URLPattern);

  // ========================================
  // LAZY: MessageChannel, MessagePort, BroadcastChannel
  // ========================================
  defineLazyGlobal(g, 'MessageChannel', () => MessageChannel);
  defineLazyGlobal(g, 'MessagePort', () => MessagePort);
  defineLazyGlobal(g, 'VideoFrame', () => VideoFrame);
  defineLazyGlobal(g, 'BroadcastChannel', () => BroadcastChannel);

  // ========================================
  // LAZY: WebSocket
  // ========================================
  defineLazyGlobal(g, 'WebSocket', () => {
    const globalEventTarget = g.EventTarget || EventTarget;
    if (globalEventTarget && Object.getPrototypeOf(WebSocket) !== globalEventTarget) {
      Object.setPrototypeOf(WebSocket, globalEventTarget);
    }
    if (
      globalEventTarget &&
      globalEventTarget.prototype &&
      Object.getPrototypeOf(WebSocket.prototype) !== globalEventTarget.prototype
    ) {
      Object.setPrototypeOf(WebSocket.prototype, globalEventTarget.prototype);
    }
    return WebSocket;
  });
  defineLazyGlobal(g, 'WebSocketError', () => WebSocketError);
  defineLazyGlobal(g, 'WebSocketStream', () => WebSocketStream);

  // ========================================
  // LAZY: EventSource (Server-Sent Events)
  // ========================================
  defineLazyGlobal(g, 'EventSource', () => EventSource);

  // ========================================
  // LAZY: FileReader
  // ========================================
  defineLazyGlobal(g, 'FileReader', () => FileReader);

  // ========================================
  // navigator - always install ours (even if Node/native provides one)
  // Our navigator includes locks, storage, and other web-standard properties
  // that the host navigator may lack.
  // ========================================
  Object.defineProperty(g, 'navigator', {
    value: navigator,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  // ========================================
  // LAZY: localStorage, sessionStorage
  // ========================================
  const hasNativeStorage = installSQLiteStorageModule(g);
  if (hasNativeStorage) {
    Object.defineProperty(g, 'localStorage', {
      value: localStorage,
      writable: true,
      configurable: true,
      enumerable: true,
    });
    Object.defineProperty(g, 'sessionStorage', {
      value: sessionStorage,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  } else {
    defineLazyGlobal(g, 'localStorage', () => localStorage);
    defineLazyGlobal(g, 'sessionStorage', () => sessionStorage);
  }

  // ========================================
  // Scheduling bridge
  // ========================================
  if (typeof g.__exactRequestAnimationFrame === 'function') {
    setNativeSchedulingModule({
      requestAnimationFrame(callback: () => void): void {
        try {
          const scheduled = g.__exactRequestAnimationFrame(callback);
          if (scheduled !== false) {
            return;
          }
        } catch (_) {}
        setTimeout(callback, 16);
      },
    });
  }

  // ========================================
  // performance, PerformanceObserver
  // Always override: the C++ bootstrap installs a stub with no-op mark/measure
  // that blocks the real implementation via defineLazyGlobal.
  // ========================================
  if (typeof g.__exactPerformanceNow === 'function') {
    try {
      const nativeTimeOrigin =
        typeof g.__exactPerformanceTimeOrigin === 'function'
          ? Number(g.__exactPerformanceTimeOrigin())
          : Date.now();
      const timeOrigin = Number.isFinite(nativeTimeOrigin) ? nativeTimeOrigin : Date.now();
      setNativePerformanceModule({
        now: () => {
          const value = Number(g.__exactPerformanceNow());
          return Number.isFinite(value) ? value : Date.now() - timeOrigin;
        },
        timeOrigin,
      });
    } catch (_) {}
  }
  Object.defineProperty(g, 'performance', {
    value: perfInstance,
    writable: true,
    configurable: true,
    enumerable: true,
  });
  defineLazyGlobal(g, 'PerformanceObserver', () => PerformanceObserver);
  defineLazyGlobal(g, 'PerformanceEntry', () => PerformanceEntry);
  defineLazyGlobal(g, 'PerformanceMark', () => PerformanceMark);
  defineLazyGlobal(g, 'PerformanceMeasure', () => PerformanceMeasure);

  // ========================================
  // structuredClone
  // Always override: the C++ bootstrap polyfill may not handle all types
  // (e.g. Map, Set, TypedArrays) correctly.
  // ========================================
  Object.defineProperty(g, 'structuredClone', {
    value: structuredCloneFn,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  // ========================================
  // LAZY: atob, btoa
  // ========================================
  defineLazyGlobal(g, 'atob', () => atobFn);
  defineLazyGlobal(g, 'btoa', () => btoaFn);

  // ========================================
  // LAZY: requestAnimationFrame, cancelAnimationFrame,
  //       requestIdleCallback, cancelIdleCallback
  // ========================================
  defineLazyGlobal(g, 'requestAnimationFrame', () => rafFn);
  defineLazyGlobal(g, 'cancelAnimationFrame', () => cafFn);
  defineLazyGlobal(g, 'requestIdleCallback', () => ricFn);
  defineLazyGlobal(g, 'cancelIdleCallback', () => cicFn);

  // ========================================
  // LAZY: CompressionStream, DecompressionStream
  // ========================================
  defineLazyGlobal(g, 'CompressionStream', () => CompressionStream);
  defineLazyGlobal(g, 'DecompressionStream', () => DecompressionStream);

  // ========================================
  // LAZY: Cache API (caches global)
  // ========================================
  defineLazyGlobal(g, 'caches', () => new CacheStorage());

  // ========================================
  // LAZY: ClipboardItem (Clipboard API)
  // ========================================
  defineLazyGlobal(g, 'ClipboardItem', () => ClipboardItem);

  // ========================================
  // LAZY: IndexedDB API (backed by exact:sqlite)
  // ========================================
  defineLazyGlobal(g, 'indexedDB', () => new IDBFactory());
  defineLazyGlobal(g, 'IDBKeyRange', () => IDBKeyRange);
  defineLazyGlobal(g, 'IDBDatabase', () => IDBDatabase);
  defineLazyGlobal(g, 'IDBObjectStore', () => IDBObjectStore);
  defineLazyGlobal(g, 'IDBTransaction', () => IDBTransaction);
  defineLazyGlobal(g, 'IDBRequest', () => IDBRequest);
  defineLazyGlobal(g, 'IDBOpenDBRequest', () => IDBOpenDBRequest);
  defineLazyGlobal(g, 'IDBCursor', () => IDBCursor);
  defineLazyGlobal(g, 'IDBCursorWithValue', () => IDBCursorWithValue);
  defineLazyGlobal(g, 'IDBIndex', () => IDBIndex);

  // ========================================
  // LAZY: window (for library compat)
  // ========================================
  if (typeof g.window === 'undefined') {
    // Point window at globalThis for libraries that check `typeof window !== 'undefined'`
    g.window = g;
  }
  // self alias (used by some web workers and libraries)
  if (typeof g.self === 'undefined') {
    g.self = g;
  }
  // Node.js-style global alias
  if (typeof g.global === 'undefined') {
    g.global = g;
  }
  defineLazyGlobal(g, 'matchMedia', () => exactWindow.matchMedia.bind(exactWindow));
  defineLazyGlobal(g, 'MediaQueryList', () => MediaQueryList);
  defineLazyGlobal(g, 'MediaQueryListEvent', () => MediaQueryListEvent);

  // ========================================
  // Bun / Exact file globals (Bun.file, Bun.write, Bun.env, etc.)
  // Lazy: installExactGlobal() only runs when Exact.file or Bun.file is first accessed,
  // to avoid triggering macOS filesystem permission prompts at startup.
  // ========================================
  g.Exact = g.Exact || ({} as any);
  if (typeof g.__exactReadFile === 'function' || typeof g.__exactEnsureFs === 'function') {
    const exactFileDescriptor = Object.getOwnPropertyDescriptor(g.Exact, 'file');
    const exactWriteDescriptor = Object.getOwnPropertyDescriptor(g.Exact, 'write');
    const hasConcreteExactFile =
      !!exactFileDescriptor && !exactFileDescriptor.get && typeof exactFileDescriptor.value === 'function';
    const hasConcreteExactWrite =
      !!exactWriteDescriptor && !exactWriteDescriptor.get && typeof exactWriteDescriptor.value === 'function';

    if (!hasConcreteExactFile || !hasConcreteExactWrite) {
      let _exactGlobalInstalled = false;
      let _exactFileFactory: ((path: string, options?: any) => any) | undefined;
      let _exactWriteFactory: typeof import('./fs/ExactFile').exactWrite | undefined;
      const ensureExactGlobal = () => {
        if (_exactGlobalInstalled) {
          return {
            file: _exactFileFactory!,
            write: _exactWriteFactory!,
          };
        }
        _exactGlobalInstalled = true;
        const installed = installExactGlobal();
        _exactFileFactory = installed.file;
        _exactWriteFactory = installed.write;
        return installed;
      };
      Object.defineProperty(g.Exact, 'file', {
        configurable: true,
        enumerable: true,
        get() {
          return ensureExactGlobal().file;
        },
      });
      Object.defineProperty(g.Exact, 'write', {
        configurable: true,
        enumerable: true,
        get() {
          return ensureExactGlobal().write;
        },
      });
    }
  }
  // The Bun-shaped facade is opt-in (`ibex --compat=bun` or
  // EXACT_COMPAT_BUN=1): an ambient 16-key Bun global made `typeof Bun`
  // detection lie to ecosystem packages (LLP 0012#decision). Implementations
  // stay reachable under `Exact`.
  const compatModes = (g as any).__exactCompatModes;
  const bunCompatEnabled =
    (Array.isArray(compatModes) && compatModes.indexOf('bun') !== -1) ||
    g.process?.env?.EXACT_COMPAT_BUN === '1';
  if (bunCompatEnabled && !g.Bun) g.Bun = g.Exact;
  // Wire Bun.env to process.env so packages can use either
  if (g.Exact && !g.Exact.env) {
    Object.defineProperty(g.Exact, 'env', {
      get() { return g.process?.env; },
      configurable: true,
      enumerable: true,
    });
  }
  // Bun.sleep(ms) - Promise-based delay
  if (g.Exact && !g.Exact.sleep) {
    g.Exact.sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
    g.Exact.sleepSync = (ms: number) => {
      const end = Date.now() + ms;
      while (Date.now() < end) { /* spin */ }
    };
  }
  // Bun.which(cmd) - native PATH lookup, capability-gated at the host boundary.
  if (g.Exact && (typeof (g as any).__exactWhich === 'function' || !g.Exact.which)) {
    g.Exact.which = (cmd: string) => {
      if (typeof cmd !== 'string' || !cmd) return null;
      if (
        typeof (g as any).__exactWhich !== 'function' &&
        typeof (g as any).__exactEnsureChildProcess === 'function'
      ) {
        try { (g as any).__exactEnsureChildProcess(); } catch (_) {}
      }
      return typeof (g as any).__exactWhich === 'function'
        ? (g as any).__exactWhich(cmd)
        : null;
    };
  }
  // Exact.unsafe (aliased as Bun.unsafe under --compat=bun) - shims expected
  // by the CLI test harness.
  if (g.Exact) {
    const bunUnsafe = g.Exact.unsafe && typeof g.Exact.unsafe === 'object'
      ? g.Exact.unsafe
      : {};
    if (typeof bunUnsafe.gcAggressionLevel !== 'function') {
      bunUnsafe.gcAggressionLevel = (level?: number) => level !== undefined ? level : 0;
    }
    if (typeof bunUnsafe.arrayBufferToString !== 'function') {
      bunUnsafe.arrayBufferToString = (buf: ArrayBuffer | ArrayBufferView) => {
        const bytes = buf instanceof ArrayBuffer
          ? new Uint8Array(buf)
          : buf instanceof Uint8Array
            ? buf
            : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        return new TextDecoder().decode(bytes);
      };
    }
    if (typeof bunUnsafe.segfault !== 'function') {
      bunUnsafe.segfault = () => {
        throw new Error('Bun.unsafe.segfault is not implemented');
      };
    }
    g.Exact.unsafe = bunUnsafe;
  }
  // Bun.peek.status - promise state probe shim used by compat tests.
  if (g.Exact) {
    if (typeof g.Exact.peek !== 'function') {
      g.Exact.peek = <T>(value: T) => value;
    }
    if (g.Exact.peek && typeof g.Exact.peek.status !== 'function') {
      g.Exact.peek.status = (_promise: Promise<unknown>) => 'pending';
    }
  }
  // Bun.deepMatch(obj, subset) - check if subset is a subset of obj
  if (g.Exact && !g.Exact.deepMatch) {
    g.Exact.deepMatch = function deepMatch(obj: any, subset: any): boolean {
      if (subset === obj) return true;
      if (subset === null || typeof subset !== 'object') return subset === obj;
      if (obj === null || typeof obj !== 'object') return false;
      for (const key of Object.keys(subset)) {
        if (!deepMatch((obj as any)[key], (subset as any)[key])) return false;
      }
      return true;
    };
  }
  // Bun.password - argon2/bcrypt (stub - rejects since we lack native support)
  if (g.Exact && !g.Exact.password) {
    g.Exact.password = {
      hash: () => Promise.reject(new Error('Bun.password not available in Ibex runtime')),
      verify: () => Promise.reject(new Error('Bun.password not available in Ibex runtime')),
      hashSync: () => { throw new Error('Bun.password not available in Ibex runtime'); },
      verifySync: () => { throw new Error('Bun.password not available in Ibex runtime'); },
    };
  }
  // Bun.semver - semver comparison utilities
  if (g.Exact && !g.Exact.semver) {
    g.Exact.semver = {
      satisfies: (_version: string, _range: string) => false,
      order: (a: string, b: string) => {
        const parse = (v: string) => v.replace(/^[^0-9]*/, '').split('.').map(Number);
        const [aMajor = 0, aMinor = 0, aPatch = 0] = parse(a);
        const [bMajor = 0, bMinor = 0, bPatch = 0] = parse(b);
        if (aMajor !== bMajor) return aMajor - bMajor;
        if (aMinor !== bMinor) return aMinor - bMinor;
        return aPatch - bPatch;
      },
    };
  }
  // Bun.CryptoHasher - wraps node:crypto hash API
  if (g.Exact && !g.Exact.CryptoHasher) {
    g.Exact.CryptoHasher = class CryptoHasher {
      private _algo: string;
      private _chunks: string[] = [];
      static readonly algorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'sha224'];
      constructor(algorithm: string) {
        this._algo = algorithm.toLowerCase().replace(/-/g, '');
      }
      update(data: string | ArrayBuffer | Uint8Array): this {
        if (typeof data === 'string') {
          this._chunks.push(data);
        } else {
          const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
          let s = '';
          for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
          this._chunks.push(s);
        }
        return this;
      }
      digest(encoding?: 'hex' | 'base64' | 'base64url'): string | Uint8Array {
        const joined = this._chunks.join('');
        const gx = globalThis as any;
        if (typeof gx.__exactHashSync === 'function') {
          const hex = gx.__exactHashSync(this._algo, joined);
          if (!encoding || encoding === 'hex') return hex;
          if (encoding === 'base64' || encoding === 'base64url') {
            const bytes: number[] = [];
            for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
            const b64 = btoa(bytes.map(b => String.fromCharCode(b)).join(''));
            return encoding === 'base64url' ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '') : b64;
          }
        }
        throw new Error('CryptoHasher: native hash not available');
      }
    };
  }

  // ========================================
  // SharedArrayBuffer stub (prevents ReferenceError in Hermes)
  // Many compat tests reference SharedArrayBuffer at file scope.
  // This stub allows files to load; actual shared memory semantics are not supported.
  // ========================================
  if (typeof g.SharedArrayBuffer === 'undefined') {
    g.SharedArrayBuffer = class SharedArrayBuffer {
      _buffer: ArrayBuffer;

      constructor(byteLength: number) {
        const length = Math.floor(Number(byteLength));
        if (!Number.isFinite(length) || length < 0) {
          throw new RangeError('Invalid SharedArrayBuffer length');
        }
        this._buffer = new ArrayBuffer(length);
      }

      get byteLength(): number {
        return this._buffer.byteLength;
      }

      slice(begin?: number, end?: number): SharedArrayBuffer {
        const sliced = this._buffer.slice(begin, end);
        const result = new (g.SharedArrayBuffer as typeof SharedArrayBuffer)(sliced.byteLength);
        new Uint8Array((result as SharedArrayBuffer)._buffer).set(new Uint8Array(sliced));
        return result;
      }

      get [Symbol.toStringTag]() {
        return 'SharedArrayBuffer';
      }
    } as any;
  }

  const patchBrokenSharedArrayBufferViews = () => {
    if (typeof g.SharedArrayBuffer !== 'function' || typeof g.Uint8Array !== 'function') {
      return;
    }

    let needsViewPatch = false;
    try {
      const probeBuffer = new g.SharedArrayBuffer(1);
      const probeView = new g.Uint8Array(probeBuffer);
      needsViewPatch =
        probeView.length === 0 ||
        probeView.byteLength === 0 ||
        Object.prototype.toString.call(probeView.buffer) !== '[object SharedArrayBuffer]';
    } catch {
      return;
    }

    if (!needsViewPatch) {
      return;
    }

    const getSharedArrayBufferBacking = (buffer: any): ArrayBuffer | null => {
      if (!buffer || typeof buffer !== 'object') return null;
      if (Object.prototype.toString.call(buffer) !== '[object SharedArrayBuffer]') return null;
      if (!buffer._buffer || Object.prototype.toString.call(buffer._buffer) !== '[object ArrayBuffer]') {
        return null;
      }
      return buffer._buffer;
    };

    const exposeSharedArrayBufferView = <T extends object>(view: T, originalBuffer: any): T => {
      try {
        Object.defineProperty(view, 'buffer', {
          configurable: true,
          enumerable: false,
          get() {
            return originalBuffer;
          },
        });
      } catch {}
      try {
        Object.defineProperty(view, '__exactSharedArrayBuffer', {
          value: originalBuffer,
          writable: false,
          configurable: true,
          enumerable: false,
        });
      } catch {}
      return view;
    };

    const wrapSharedArrayBufferViewCtor = (name: string) => {
      const NativeCtor = (g as any)[name];
      if (typeof NativeCtor !== 'function' || NativeCtor.__exactSharedArrayBufferWrapped) {
        return;
      }

      const WrappedCtor = function(this: any, buffer?: any, byteOffset?: number, length?: number) {
        if (!(this instanceof WrappedCtor)) {
          throw new TypeError(`Constructor ${name} requires "new"`);
        }

        const backing = getSharedArrayBufferBacking(buffer);
        if (backing) {
          let view;
          if (arguments.length <= 1) {
            view = new NativeCtor(backing);
          } else if (arguments.length === 2) {
            view = new NativeCtor(backing, byteOffset);
          } else {
            view = new NativeCtor(backing, byteOffset, length);
          }
          return exposeSharedArrayBufferView(view, buffer);
        }

        if (arguments.length === 0) return new NativeCtor();
        if (arguments.length === 1) return new NativeCtor(buffer);
        if (arguments.length === 2) return new NativeCtor(buffer, byteOffset);
        return new NativeCtor(buffer, byteOffset, length);
      } as any;

      WrappedCtor.prototype = NativeCtor.prototype;
      try {
        Object.defineProperty(WrappedCtor.prototype, 'constructor', {
          value: WrappedCtor,
          writable: true,
          configurable: true,
          enumerable: false,
        });
      } catch {}
      try {
        Object.setPrototypeOf(WrappedCtor, NativeCtor);
      } catch {}
      try {
        Object.defineProperty(WrappedCtor, 'name', {
          value: name,
          configurable: true,
        });
      } catch {}
      try {
        Object.defineProperty(WrappedCtor, '__exactSharedArrayBufferWrapped', {
          value: true,
          writable: false,
          configurable: true,
          enumerable: false,
        });
      } catch {}
      try {
        Object.defineProperty(g, name, {
          value: WrappedCtor,
          writable: true,
          configurable: true,
          enumerable: false,
        });
      } catch {
        (g as any)[name] = WrappedCtor;
      }
    };

    const typedArrayNames = [
      'Int8Array',
      'Uint8Array',
      'Uint8ClampedArray',
      'Int16Array',
      'Uint16Array',
      'Int32Array',
      'Uint32Array',
      'Float32Array',
      'Float64Array',
    ];
    if (typeof (g as any).Float16Array === 'function') {
      typedArrayNames.push('Float16Array');
    }
    if (typeof (g as any).BigInt64Array === 'function') {
      typedArrayNames.push('BigInt64Array');
    }
    if (typeof (g as any).BigUint64Array === 'function') {
      typedArrayNames.push('BigUint64Array');
    }

    for (const name of typedArrayNames) {
      wrapSharedArrayBufferViewCtor(name);
    }
    wrapSharedArrayBufferViewCtor('DataView');
  };

  patchBrokenSharedArrayBufferViews();

  const ensureSharedArrayBufferUint8ArrayWorks = () => {
    if (typeof g.SharedArrayBuffer !== 'function' || typeof g.Uint8Array !== 'function') {
      return;
    }

    const exposeUint8ArrayBuffer = <T extends object>(view: T, originalBuffer: any): T => {
      try {
        Object.defineProperty(view, 'buffer', {
          configurable: true,
          enumerable: false,
          get() {
            return originalBuffer;
          },
        });
      } catch {}
      try {
        Object.defineProperty(view, '__exactSharedArrayBuffer', {
          value: originalBuffer,
          writable: false,
          configurable: true,
          enumerable: false,
        });
      } catch {}
      return view;
    };

    try {
      const probeBuffer = new g.SharedArrayBuffer(1);
      const probeView = new g.Uint8Array(probeBuffer);
      if (
        probeView.length === 1 &&
        probeView.byteLength === 1 &&
        Object.prototype.toString.call(probeView.buffer) === '[object SharedArrayBuffer]'
      ) {
        return;
      }
    } catch {}

    const NativeUint8Array = g.Uint8Array;
    const WrappedUint8Array = function Uint8Array(
      this: any,
      buffer?: any,
      byteOffset?: number,
      length?: number
    ) {
      if (!(this instanceof WrappedUint8Array)) {
        throw new TypeError('Constructor Uint8Array requires "new"');
      }

      const backing = buffer && buffer._buffer;
      if (backing && Object.prototype.toString.call(backing) === '[object ArrayBuffer]') {
        let view;
        if (arguments.length <= 1) {
          view = new NativeUint8Array(backing);
        } else if (arguments.length === 2) {
          view = new NativeUint8Array(backing, byteOffset);
        } else {
          view = new NativeUint8Array(backing, byteOffset, length);
        }
        return exposeUint8ArrayBuffer(view, buffer);
      }

      if (arguments.length === 0) return new NativeUint8Array();
      if (arguments.length === 1) return new NativeUint8Array(buffer);
      if (arguments.length === 2) return new NativeUint8Array(buffer, byteOffset);
      return new NativeUint8Array(buffer, byteOffset, length);
    } as any;

    WrappedUint8Array.prototype = NativeUint8Array.prototype;
    try {
      Object.setPrototypeOf(WrappedUint8Array, NativeUint8Array);
    } catch {}
    try {
      Object.defineProperty(WrappedUint8Array.prototype, 'constructor', {
        value: WrappedUint8Array,
        writable: true,
        configurable: true,
      });
    } catch {}
    try {
      Object.defineProperty(WrappedUint8Array, '__exactSharedArrayBufferWrapped', {
        value: true,
        writable: false,
        configurable: true,
      });
    } catch {}
    try {
      Object.defineProperty(g, 'Uint8Array', {
        value: WrappedUint8Array,
        writable: true,
        configurable: true,
        enumerable: false,
      });
    } catch {
      g.Uint8Array = WrappedUint8Array;
    }
  };

  ensureSharedArrayBufferUint8ArrayWorks();

  // ========================================
  // Atomics stub (companion to SharedArrayBuffer stub)
  // ========================================
  if (typeof g.Atomics === 'undefined') {
    g.Atomics = {
      add(ta: any, index: number, value: number) { const old = ta[index]; ta[index] += value; return old; },
      and(ta: any, index: number, value: number) { const old = ta[index]; ta[index] &= value; return old; },
      compareExchange(ta: any, index: number, expected: number, replacement: number) {
        const old = ta[index]; if (old === expected) ta[index] = replacement; return old;
      },
      exchange(ta: any, index: number, value: number) { const old = ta[index]; ta[index] = value; return old; },
      isLockFree(size: number) { return size === 1 || size === 2 || size === 4; },
      load(ta: any, index: number) { return ta[index]; },
      or(ta: any, index: number, value: number) { const old = ta[index]; ta[index] |= value; return old; },
      store(ta: any, index: number, value: number) { ta[index] = value; return value; },
      sub(ta: any, index: number, value: number) { const old = ta[index]; ta[index] -= value; return old; },
      wait() { return 'not-equal' as const; },
      notify() { return 0; },
      xor(ta: any, index: number, value: number) { const old = ta[index]; ta[index] ^= value; return old; },
      [Symbol.toStringTag]: 'Atomics',
    };
  }

  // ========================================
  // Float16Array stub (TC39 Stage 3, not yet in Hermes)
  // Prevents ReferenceError in tests that reference it at file scope.
  // ========================================
  if (typeof g.Float16Array === 'undefined') {
    g.Float16Array = class Float16Array extends Uint16Array {
      static get BYTES_PER_ELEMENT() { return 2; }
      get [Symbol.toStringTag]() { return 'Float16Array'; }
    };
  }

  // ========================================
  // ES2023+ Polyfills (Array, Set, Object.groupBy, Promise.withResolvers, Iterator helpers)
  // ========================================
  installPolyfills();

  // ========================================
  // Promise rejection tracking (unhandledrejection / rejectionhandled)
  // Must come after Event, EventTarget, and PromiseRejectionEvent globals
  // ========================================
  installPromiseRejectionTracking();
  if (g.__exactLoadTimings) g.__exactLoadTimings.installGlobalsEnd = Date.now();
}

// Stub exports to prevent import errors
export function getRuntimeVersion() { return '0.1.0'; }
export function detectEngine() { return 'hermes'; }
export function detectPlatform() {
  const g: any = globalThis as any;
  if (typeof g.__exactPlatform === 'string' && g.__exactPlatform.length > 0) return g.__exactPlatform;
  const hostProcess = g.process;
  if (hostProcess) {
    let isExactProcess = false;
    try {
      const versions = hostProcess.versions;
      isExactProcess = !!(versions && typeof versions === 'object' && (typeof versions.ibex === 'string' || typeof versions.exact === 'string'));
    } catch {
      isExactProcess = false;
    }
    if (!isExactProcess) {
      try {
        const platform = hostProcess.platform;
        if (typeof platform === 'string' && platform.length > 0) {
          return platform;
        }
      } catch {
        // Ignore host process platform lookup errors and keep falling back.
      }
    }
  }
  return 'ios';
}
export const runtimeInfo = {
  version: '0.1.0',
  engine: 'hermes',
  get platform() { return detectPlatform(); },
};

export function areGlobalsInstalled(): boolean {
  return (globalThis as any).__exactRuntimeLoaded === true;
}

const runtimeBundle = {
  installGlobals,
  areGlobalsInstalled,
  getRuntimeVersion,
  detectEngine,
  detectPlatform,
  runtimeInfo,
};

(globalThis as any).ExactBundle = (globalThis as any).ExactBundle || runtimeBundle;

if ((globalThis as any).ExactBundle && (globalThis as any).ExactBundle !== runtimeBundle) {
  Object.assign((globalThis as any).ExactBundle, runtimeBundle);
}
