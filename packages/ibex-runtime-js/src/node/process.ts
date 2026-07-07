// @ts-nocheck
/**
 * process object implementation for Ibex runtime (Node.js compatibility)
 * 
 * Provides a subset of Node.js process API for compatibility with
 * libraries that check for Node.js environment.
 */

import { getRuntimeVersion, runtimeInfo } from '../bootstrap';
import {
  BUN_COMPAT_VERSION,
  RELEASE_NAME,
  RUNTIME_VERSIONS,
} from '../identity.generated';

// Declare the global functions from native bridge
declare global {
  var __exactGetEnv: ((name: string) => string | undefined) | undefined;
  var __exactGetAllEnv: (() => Record<string, string>) | undefined;
  var __exactGetCwd: (() => string) | undefined;
  var __exactSetCwd: ((path: string) => void) | undefined;
  var __exactArgv: string[] | undefined;
  var __exactExecArgv: string[] | undefined;
  var __exactExecPath: string | undefined;
}

var _processCwd = "/";
const _nextTickQueue: Array<{ callback: (...args: any[]) => void; args: any[] }> = [];
let _nextTickScheduled = false;
let _nextTickHooksInstalled = false;
const _nativeGlobalNextTick:
  | ((callback: (...args: any[]) => void, ...args: any[]) => void)
  | undefined =
  typeof (globalThis as any).nextTick === 'function'
    ? (globalThis as any).nextTick.bind(globalThis)
    : undefined;
const _nativeProcessNextTick:
  | ((callback: (...args: any[]) => void, ...args: any[]) => void)
  | undefined =
  typeof (globalThis as any).process?.nextTick === 'function'
    ? (globalThis as any).process.nextTick.bind((globalThis as any).process)
    : undefined;
const _nativeProcessHrtime: ((time?: [number, number]) => [number, number]) | undefined =
  typeof (globalThis as any).process?.hrtime === 'function'
    ? (globalThis as any).process.hrtime.bind((globalThis as any).process)
    : undefined;
const _nativeProcessHrtimeBigint: (() => bigint) | undefined =
  typeof (globalThis as any).process?.hrtime?.bigint === 'function'
    ? (globalThis as any).process.hrtime.bigint.bind((globalThis as any).process.hrtime)
    : undefined;
const _nativeProcessKill:
  | ((pid: number, signal?: string | number) => true)
  | undefined =
  typeof (globalThis as any).process?.kill === 'function'
    ? (globalThis as any).process.kill.bind((globalThis as any).process)
    : undefined;
const _nativeArch: string | undefined =
  typeof (globalThis as any).process?.arch === 'string'
    ? (globalThis as any).process.arch
    : undefined;
const _nativeGetuid: (() => number) | undefined =
  typeof (globalThis as any).process?.getuid === 'function'
    ? (globalThis as any).process.getuid.bind((globalThis as any).process)
    : undefined;
const _nativeGetgid: (() => number) | undefined =
  typeof (globalThis as any).process?.getgid === 'function'
    ? (globalThis as any).process.getgid.bind((globalThis as any).process)
    : undefined;
const _nativeGeteuid: (() => number) | undefined =
  typeof (globalThis as any).process?.geteuid === 'function'
    ? (globalThis as any).process.geteuid.bind((globalThis as any).process)
    : undefined;
const _nativeGetegid: (() => number) | undefined =
  typeof (globalThis as any).process?.getegid === 'function'
    ? (globalThis as any).process.getegid.bind((globalThis as any).process)
    : undefined;
// (ENG-23234) Real OS pid/ppid from the native process object this shim
// replaces. The old hardcoded `pid = 1` made process.kill(process.pid, sig)
// a silent no-op on desktop: kill(1, sig) fails EPERM, the catch below fell
// through, and `pid === this.pid` (1 === 1) faked success — so self-signaling
// delivered nothing. Mobile embeds without a native process keep the 1/0
// placeholders.
const _nativePid: number | undefined =
  typeof (globalThis as any).process?.pid === 'number' && (globalThis as any).process.pid > 0
    ? (globalThis as any).process.pid
    : undefined;
const _nativePpid: number | undefined =
  typeof (globalThis as any).process?.ppid === 'number' && (globalThis as any).process.ppid >= 0
    ? (globalThis as any).process.ppid
    : undefined;
// (ENG-23234) Reconcile native signal traps with this emitter's listener
// table. Installed by the ibex bootstrap (stream-enhance.js); absent on
// mobile embeds, where this is a no-op.
function _syncSignalTrap(event?: string): void {
  const hook = (globalThis as any).__exactSignalWatchSync;
  if (typeof hook === 'function') {
    try {
      hook(event);
    } catch (_err) {}
  }
}
const _nativePromiseThen = Promise.prototype.then;
const _nativeQueueMicrotask =
  typeof queueMicrotask === 'function' ? queueMicrotask.bind(globalThis) : undefined;
const _nativeBigInt = typeof BigInt === 'function' ? BigInt : undefined;

// (ENG-23140/ENG-23316) Signal numbers are platform-specific and diverge for common
// signals: SIGUSR1 is 30 on Darwin but 10 on Linux, SIGBUS is 10 on Darwin but
// 7 on Linux. Prefer the native/global table when present so JS never drifts
// from compiled kernel constants; merge with the platform fallback because
// __exactSignalNumbers intentionally omits untrappable SIGKILL/SIGSTOP.
const FALLBACK_SIGNAL_NAMES_DARWIN: Record<string, number> = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGIOT: 6, SIGBUS: 10, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 30, SIGSEGV: 11,
  SIGUSR2: 31, SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGCHLD: 20,
  SIGCONT: 19, SIGSTOP: 17, SIGTSTP: 18, SIGTTIN: 21, SIGTTOU: 22,
  SIGURG: 16, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27,
  SIGWINCH: 28, SIGIO: 23, SIGINFO: 29, SIGSYS: 12,
};
const FALLBACK_SIGNAL_NAMES_LINUX: Record<string, number> = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGIOT: 6, SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11,
  SIGUSR2: 12, SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGSTKFLT: 16,
  SIGCHLD: 17, SIGCONT: 18, SIGSTOP: 19, SIGTSTP: 20, SIGTTIN: 21,
  SIGTTOU: 22, SIGURG: 23, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26,
  SIGPROF: 27, SIGWINCH: 28, SIGIO: 29, SIGPOLL: 29, SIGPWR: 30, SIGSYS: 31,
};

/** Exported for tests: the signal name -> number table for a platform. */
export function signalNameToNumberMap(platform: string): Record<string, number> {
  const fallback = platform === 'linux' || platform === 'android'
    ? FALLBACK_SIGNAL_NAMES_LINUX
    : FALLBACK_SIGNAL_NAMES_DARWIN;
  const out: Record<string, number> = { ...fallback };
  // The native table describes the kernel we are running on, so it can only
  // refine the table for THIS host's platform. Merging it into a table
  // requested for a foreign platform would hand out host numbers under the
  // other platform's name (e.g. Linux SIGUSR1=10 in a 'darwin' table).
  let hostPlatform: string | undefined;
  try {
    hostPlatform = (globalThis as any).process?.platform;
  } catch (_err) {}
  if (platform !== hostPlatform) return out;
  let nativeMap: any = undefined;
  try {
    nativeMap = (globalThis as any).__exactSignalNumbersMap;
    if (!nativeMap && typeof (globalThis as any).__exactSignalNumbers === 'function') {
      nativeMap = (globalThis as any).__exactSignalNumbers();
    }
  } catch (_err) {}
  if (nativeMap && typeof nativeMap === 'object') {
    for (const key of Object.keys(nativeMap)) {
      if (typeof nativeMap[key] === 'number') out[key] = nativeMap[key];
    }
  }
  return out;
}

function currentSignalNameToNumberMap(): Record<string, number> {
  let platform = 'darwin';
  try {
    const detected = process?.platform;
    if (typeof detected === 'string' && detected.length > 0) {
      platform = detected;
    }
  } catch (_err) {}
  return signalNameToNumberMap(platform);
}

const USER_CREDENTIALS: Record<string, number> = {
  root: 0,
  nobody: 65534,
};

const GROUP_CREDENTIALS: Record<string, number> = {
  root: 0,
  nobody: 65534,
  nogroup: 65534,
};

const CANONICAL_ALLOWED_NODE_ENVIRONMENT_FLAGS = [
  '--perf-basic-prof',
  '--stack-trace-limit',
  '-r',
  '--debug-arraybuffer-allocations',
  '--no-debug-arraybuffer-allocations',
  '--es-module-specifier-resolution',
  '--experimental-fetch',
  '--experimental-global-customevent',
  '--experimental-global-webcrypto',
  '--experimental-quic',
  '--experimental-report',
  '--experimental-wasm-modules',
  '--experimental-worker',
  '--loader',
  '--no-node-snapshot',
  '--node-snapshot',
  '--no-trace-promises',
  '--no-verify-base-objects',
  '--trace-promises',
  '--verify-base-objects',
] as const;

const _nativeSetAdd = Set.prototype.add;
const _nativeSetClear = Set.prototype.clear;
const _nativeSetDelete = Set.prototype.delete;
const _nativeSetHas = Set.prototype.has;
let _immutableAllowedNodeEnvironmentFlags: Set<string> | null = null;
let _dateToStringPatched = false;
const _nativeDateToString = Date.prototype.toString;

function makeInvalidObjectDefinePropertyError(message: string): TypeError & { code: string } {
  const err = new TypeError(message) as TypeError & { code: string };
  err.code = 'ERR_INVALID_OBJECT_DEFINE_PROPERTY';
  return err;
}

function normalizeAllowedNodeEnvironmentFlag(flag: unknown): string | null {
  if (typeof flag !== 'string' || flag.length === 0) {
    return null;
  }

  let dashCount = 0;
  while (dashCount < flag.length && flag.charCodeAt(dashCount) === 0x2d) {
    dashCount += 1;
  }

  let name = flag.slice(dashCount);
  if (name.length === 0) {
    return null;
  }

  const equalsIndex = name.indexOf('=');
  if (equalsIndex !== -1) {
    name = name.slice(0, equalsIndex);
  }
  name = name.replace(/_/g, '-');

  if (dashCount === 0) {
    return name.length === 1 ? `-${name}` : `--${name}`;
  }
  if (dashCount === 1) {
    return `-${name}`;
  }
  if (dashCount === 2) {
    return `--${name}`;
  }
  return `${'-'.repeat(dashCount)}${name}`;
}

function createAllowedNodeEnvironmentFlags(): Set<string> {
  if (!_immutableAllowedNodeEnvironmentFlags) {
    const allowedFlags = new Set<string>(CANONICAL_ALLOWED_NODE_ENVIRONMENT_FLAGS);
    if (!(Set.prototype as any).__exactImmutableAllowedFlagsPatched) {
      Object.defineProperty(Set.prototype, 'add', {
        value(this: Set<unknown>, value: unknown) {
          if (this === _immutableAllowedNodeEnvironmentFlags) {
            return this;
          }
          return _nativeSetAdd.call(this, value);
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(Set.prototype, 'delete', {
        value(this: Set<unknown>, value: unknown) {
          if (this === _immutableAllowedNodeEnvironmentFlags) {
            return false;
          }
          return _nativeSetDelete.call(this, value);
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(Set.prototype, 'clear', {
        value(this: Set<unknown>) {
          if (this === _immutableAllowedNodeEnvironmentFlags) {
            return undefined;
          }
          return _nativeSetClear.call(this);
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(Set.prototype, '__exactImmutableAllowedFlagsPatched', {
        value: true,
        writable: false,
        configurable: true,
      });
    }

    Object.defineProperty(allowedFlags, 'has', {
      value(this: Set<string>, value: unknown): boolean {
        const normalized = normalizeAllowedNodeEnvironmentFlag(value);
        if (normalized === null) {
          return false;
        }
        return _nativeSetHas.call(this, normalized);
      },
      writable: false,
      configurable: false,
    });

    _immutableAllowedNodeEnvironmentFlags = Object.freeze(allowedFlags);
  }

  return _immutableAllowedNodeEnvironmentFlags;
}

function _normalizeResolvedPath(path: string): string {
  let rest = path;
  let prefix = '';
  let absolute = false;

  if (/^[A-Za-z]:[\\/]/.test(rest)) {
    prefix = rest.slice(0, 2);
    rest = rest.slice(2);
    absolute = true;
  } else if (rest.startsWith('/')) {
    rest = rest.slice(1);
    absolute = true;
  }

  const parts = rest.split(/[\\/]+/);
  const normalized: string[] = [];
  for (const part of parts) {
    if (!part || part === '.') {
      continue;
    }
    if (part === '..') {
      if (normalized.length > 0) {
        normalized.pop();
      } else if (!absolute) {
        normalized.push(part);
      }
      continue;
    }
    normalized.push(part);
  }

  const joined = normalized.join('/');
  if (prefix) {
    return joined ? `${prefix}/${joined}` : `${prefix}/`;
  }
  if (absolute) {
    return joined ? `/${joined}` : '/';
  }
  return joined || '.';
}

// (ENG-23140) Surface a throwing tick the way Node surfaces it (as an
// uncaughtException), without letting it escape into whatever microtask
// happened to trigger the drain. Previously a throw propagated out of the
// wrapped Promise.prototype.then callback: the unrelated promise chain
// rejected with the tick's error (misattribution) and the rest of the
// nextTick queue was dropped.
function _reportNextTickError(error: unknown): void {
  try {
    if (process.listenerCount('uncaughtException') > 0) {
      process.emit('uncaughtException', error);
      return;
    }
  } catch (_err) {}
  const g = globalThis as any;
  if (typeof g.reportError === 'function') {
    g.reportError(error);
    return;
  }
  if (typeof setTimeout === 'function') {
    setTimeout(() => {
      throw error;
    }, 0);
    return;
  }
  // No async escape hatch available; better loud than silent. The remaining
  // queue entries survive (we dequeue one entry at a time), so a later drain
  // still runs them.
  throw error;
}

// Exported for tests (the fallback queue is only reachable when the engine
// provides no native nextTick hook, which never holds under the test runner).
export function _drainNextTickQueue(): void {
  if (_nextTickQueue.length === 0) {
    _nextTickScheduled = false;
    return;
  }

  _nextTickScheduled = false;
  while (_nextTickQueue.length > 0) {
    // Dequeue one entry at a time so a throwing tick cannot drop the entries
    // behind it in the same batch.
    const entry = _nextTickQueue.shift()!;
    try {
      entry.callback(...entry.args);
    } catch (error) {
      // Node keeps processing the queue after routing the error to
      // uncaughtException; do the same.
      _reportNextTickError(error);
    }
  }
}

// Exported for tests: enqueue on the fallback queue without going through the
// native-hook delegation in Process#nextTick.
export function _enqueueNextTickForTesting(
  callback: (...args: any[]) => void,
  ...args: any[]
): void {
  _nextTickQueue.push({ callback, args });
}

function _wrapNextTickAwareCallback<TArgs extends any[], TResult>(
  callback?: ((...args: TArgs) => TResult) | null
): ((...args: TArgs) => TResult) | undefined {
  if (typeof callback !== 'function') {
    return undefined;
  }

  return function(this: unknown, ...args: TArgs): TResult {
    _drainNextTickQueue();
    return callback.apply(this, args);
  };
}

function _installNextTickHooks(): void {
  if (_nextTickHooksInstalled || _nativeProcessNextTick || _nativeGlobalNextTick) {
    return;
  }
  _nextTickHooksInstalled = true;

  Promise.prototype.then = function then(
    onFulfilled?: ((value: any) => any) | null,
    onRejected?: ((reason: any) => any) | null
  ) {
    return _nativePromiseThen.call(
      this,
      _wrapNextTickAwareCallback(onFulfilled),
      _wrapNextTickAwareCallback(onRejected)
    );
  };

  if (_nativeQueueMicrotask) {
    try {
      (globalThis as any).queueMicrotask = (callback: () => void): void => {
        _nativeQueueMicrotask(() => {
          _drainNextTickQueue();
          callback();
        });
      };
    } catch (_err) {}
  }
}

function _scheduleNextTickDrain(): void {
  if (_nextTickScheduled) {
    return;
  }
  _nextTickScheduled = true;
  _installNextTickHooks();
  if (_nativeQueueMicrotask) {
    _nativeQueueMicrotask(_drainNextTickQueue);
    return;
  }
  Promise.resolve().then(_drainNextTickQueue);
}

function _monotonicTimeNs(): bigint {
  if (!_nativeBigInt) {
    throw new TypeError('BigInt is not supported by this JavaScript engine');
  }
  const perf = (globalThis as any).performance;
  if (perf && typeof perf.now === 'function') {
    const originMs =
      typeof perf.timeOrigin === 'number' && Number.isFinite(perf.timeOrigin)
        ? perf.timeOrigin
        : Date.now();
    return _nativeBigInt(Math.floor((originMs + perf.now()) * 1e6));
  }
  return _nativeBigInt(Date.now()) * _nativeBigInt(1000000);
}

function _monotonicHrtimeTuple(): [number, number] {
  if (_nativeProcessHrtime) {
    const nativeNow = _nativeProcessHrtime();
    if (
      Array.isArray(nativeNow) &&
      typeof nativeNow[0] === 'number' &&
      typeof nativeNow[1] === 'number'
    ) {
      return [nativeNow[0], nativeNow[1]];
    }
  }

  const perf = (globalThis as any).performance;
  const nowMs =
    perf && typeof perf.now === 'function'
      ? (typeof perf.timeOrigin === 'number' && Number.isFinite(perf.timeOrigin)
          ? perf.timeOrigin
          : Date.now()) + perf.now()
      : Date.now();
  const seconds = Math.floor(nowMs / 1000);
  const nanoseconds = Math.floor((nowMs - seconds * 1000) * 1e6);
  return [seconds, nanoseconds];
}

function _stringifyPathPart(path: any): string {
  if (typeof path === 'string') return path;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer?.(path)) return path.toString();
  return String(path);
}

function _normalizeCwdPath(value: any): string {
  const path = _stringifyPathPart(value);
  if (path.length === 0) return "/";
  if (path.charAt(0) === "/" || /^[A-Za-z]:[\\/]/.test(path)) {
    return _normalizeResolvedPath(path);
  }
  return _normalizeResolvedPath(`/${path}`);
}

function _resolveCwd(path: string): string {
  if (path.charAt(0) === '/' || /^[A-Za-z]:[\\/]/.test(path)) {
    return _normalizeResolvedPath(path);
  }
  const cwd = typeof process === 'object' && process && typeof process.cwd === 'function' ? process.cwd() : "/";
  if (cwd.charAt(cwd.length - 1) !== '/') {
    return _normalizeResolvedPath(`${cwd}/${path}`);
  }
  return _normalizeResolvedPath(`${cwd}${path}`);
}

function _readNativeCwd(): string | null {
  if (typeof __exactGetCwd !== 'function') {
    return null;
  }
  try {
    const value = __exactGetCwd();
    if (typeof value === 'string' && value.length > 0) {
      return _normalizeCwdPath(value);
    }
  } catch (_err) {}
  return null;
}

function _coerceChdirError(err: unknown, origArg: string): Error & { code?: string; errno?: number; syscall?: string; path?: string; dest?: string } {
  const fallbackErrorMap: Record<string, number> = {
    EACCES: 13,
    EINVAL: 22,
    ENOENT: 2,
    ENOTDIR: 20,
  };
  // Use native cwd if available, fall back to _processCwd
  const currentCwd = (typeof __exactGetCwd === 'function' ? __exactGetCwd() : null) || _processCwd;
  if (err && typeof err === 'object' && typeof (err as any).message === 'string') {
    const message = (err as any).message as string;
    const lower = message.toLowerCase();
    let code: string | undefined;
    if (lower.includes('no such file') || lower.includes('does not exist')) {
      code = 'ENOENT';
    } else if (lower.includes('permission denied')) {
      code = 'EACCES';
    } else if (lower.includes('not a directory')) {
      code = 'ENOTDIR';
    }
    if (code) {
      const codeStr: Record<string, string> = { ENOENT: 'no such file or directory', EACCES: 'permission denied', ENOTDIR: 'not a directory' };
      const errMsg = `${code}: ${codeStr[code] || message}, chdir '${currentCwd}' -> '${origArg}'`;
      const mapped = new Error(errMsg) as Error & { code?: string; errno?: number; syscall?: string; path?: string; dest?: string };
      mapped.code = code;
      const errno = fallbackErrorMap[code];
      if (errno !== undefined) {
        mapped.errno = -errno;
      }
      mapped.syscall = 'chdir';
      mapped.path = currentCwd;
      mapped.dest = origArg;
      return mapped;
    }
  }
  const fallback = new Error('process.chdir failed') as Error & { code?: string; errno?: number; syscall?: string; path?: string; dest?: string };
  fallback.code = 'EINVAL';
  fallback.syscall = 'chdir';
  fallback.path = currentCwd;
  fallback.dest = origArg;
  return fallback;
}

function _deepFreeze<T>(value: T): T {
  if (!value || (typeof value !== 'object' && typeof value !== 'function') || Object.isFrozen(value)) {
    return value;
  }

  Object.freeze(value);
  for (const key of Object.getOwnPropertyNames(value)) {
    _deepFreeze((value as Record<string, unknown>)[key] as T);
  }
  return value;
}

function _getConfiguredTimeZone(): string | undefined {
  const env = (globalThis as any).process?.env;
  const timeZone = env?.TZ;
  return typeof timeZone === 'string' && timeZone.length > 0 ? timeZone : undefined;
}

function _getTimeZoneOffsetMinutes(date: Date, timeZone: string): number {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);

  const values: Record<string, number> = {};
  for (const part of parts) {
    if (part.type === 'literal') {
      continue;
    }
    values[part.type] = Number(part.value);
  }

  const zonedAsUtc = Date.UTC(
    values.year,
    (values.month ?? 1) - 1,
    values.day ?? 1,
    values.hour ?? 0,
    values.minute ?? 0,
    values.second ?? 0,
  );
  return Math.round((zonedAsUtc - date.getTime()) / 60000);
}

function _formatDateForConfiguredTimeZone(date: Date, timeZone: string): string | null {
  if (Number.isNaN(date.getTime()) || typeof Intl === 'undefined' || typeof Intl.DateTimeFormat !== 'function') {
    return null;
  }

  try {
    const formatted = new Intl.DateTimeFormat('en-US', {
      timeZone,
      weekday: 'short',
      month: 'short',
      day: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    }).format(date);
    const match = formatted.match(/^([A-Za-z]{3}), ([A-Za-z]{3}) (\d{2}), (\d{4}) at (\d{2}:\d{2}:\d{2})$/);
    if (!match) {
      return null;
    }

    const timeZoneNameFormatted = new Intl.DateTimeFormat('en-US', {
      timeZone,
      timeZoneName: 'long',
    }).format(date);
    const timeZoneName = timeZoneNameFormatted.split(', ').slice(1).join(', ') || timeZone;

    const totalOffsetMinutes = _getTimeZoneOffsetMinutes(date, timeZone);
    const absoluteOffsetMinutes = Math.abs(totalOffsetMinutes);
    const offsetHours = Math.floor(absoluteOffsetMinutes / 60).toString().padStart(2, '0');
    const offsetMinutes = (absoluteOffsetMinutes % 60).toString().padStart(2, '0');
    const sign = totalOffsetMinutes >= 0 ? '+' : '-';

    return `${match[1]} ${match[2]} ${match[3]} ${match[4]} ${match[5]} ` +
      `GMT${sign}${offsetHours}${offsetMinutes} (${timeZoneName})`;
  } catch {
    return null;
  }
}

function _installTimeZoneAwareDateToString(): void {
  if (_dateToStringPatched) {
    return;
  }
  _dateToStringPatched = true;

  Date.prototype.toString = function exactToString(this: Date): string {
    const timeZone = _getConfiguredTimeZone();
    if (!timeZone) {
      return _nativeDateToString.call(this);
    }

    const formatted = _formatDateForConfiguredTimeZone(this, timeZone);
    return formatted ?? _nativeDateToString.call(this);
  };
}

export interface ProcessVersions {
  node?: string;
  acorn?: string;
  ada?: string;
  amaro?: string;
  ares?: string;
  brotli?: string;
  cjs_module_lexer?: string;
  cldr?: string;
  icu?: string;
  llhttp?: string;
  modules?: string;
  napi?: string;
  nbytes?: string;
  ncrypto?: string;
  nghttp2?: string;
  nghttp3?: string;
  ngtcp2?: string;
  openssl?: string;
  simdjson?: string;
  simdutf?: string;
  sqlite?: string;
  tz?: string;
  undici?: string;
  unicode?: string;
  v8?: string;
  uv?: string;
  uvwasi?: string;
  zlib?: string;
  zstd?: string;
  [key: string]: string | undefined;
}

const PROCESS_DEFAULT_CONFIG = _deepFreeze({
  target_defaults: {
    cflags: [] as string[],
    default_configuration: 'Release',
    defines: [] as string[],
    include_dirs: [] as string[],
    libraries: [] as string[],
  },
  variables: {
    asan: 0,
    coverage: false,
    debug_nghttp2: false,
    enable_lto: false,
    enable_pgo_generate: false,
    enable_pgo_use: false,
    error_on_warn: false,
    force_dynamic_crt: 0,
    host_arch: 'arm64',
    icu_data_in: '../../deps/icu-tmp/icudt76l.dat',
    icu_endianness: 'l',
    icu_gyp_path: 'tools/icu/icu-generic.gyp',
    icu_path: 'deps/icu-small',
    icu_small: false,
    icu_ver_major: '76',
    is_debug: 0,
    llvm_version: '0.0',
    napi_build_version: '9',
    node_builtin_shareable_builtins: [] as string[],
    node_byteorder: 'little',
    node_debug_lib: false,
    node_enable_d8: false,
    node_enable_v8_vtunejit: false,
    node_fipsinstall: false,
    node_install_corepack: true,
    node_install_npm: true,
    node_library_files: [] as string[],
    node_module_version: 131,
    node_no_browser_globals: false,
    node_prefix: '/',
    node_release_urlbase: '',
    node_section_ordering_info: '',
    node_shared: false,
    node_shared_brotli: false,
    node_shared_cares: false,
    node_shared_http_parser: false,
    node_shared_libuv: false,
    node_shared_nghttp2: false,
    node_shared_openssl: false,
    node_shared_zlib: false,
    node_tag: '',
    node_target_type: 'executable',
    node_use_bundled_v8: true,
    node_use_node_code_cache: true,
    node_use_node_snapshot: true,
    node_use_openssl: true,
    node_use_v8_platform: true,
    node_with_ltcg: false,
    node_without_node_options: false,
    openssl_is_fips: false,
    openssl_quic: true,
    ossfuzz: false,
    shlib_suffix: 'so.131',
    target_arch: 'arm64',
    v8_enable_31bit_smis_on_64bit_arch: 0,
    v8_enable_gdbjit: 0,
    v8_enable_hugepage: 0,
    v8_enable_i18n_support: 1,
    v8_enable_inspector: 1,
    v8_enable_javascript_promise_hooks: 1,
    v8_enable_lite_mode: 0,
    v8_enable_object_print: 1,
    v8_enable_pointer_compression: 0,
    v8_enable_shared_ro_heap: 1,
    v8_enable_short_builtin_calls: 1,
    v8_enable_webassembly: 1,
    v8_no_strict_aliasing: 1,
    v8_optimized_debug: 1,
    v8_promise_internal_field_count: 1,
    v8_random_seed: 0,
    v8_trace_maps: 0,
    v8_use_siphash: 1,
    want_separate_host_toolset: 0,
  },
});

const PROCESS_VERSIONS = createProcessVersions();
const PROCESS_RELEASE = createProcessRelease(
  PROCESS_VERSIONS.node ?? RUNTIME_VERSIONS.find(([key]) => key === 'node')?.[1] ?? '0.0.0'
);

function createProcessVersions(): ProcessVersions {
  const versions: ProcessVersions = {};
  // Node-primary identity (LLP 0012#decision): only truthful keys ship ambient —
  // the runtime, the engine, and the Node release the vendored compat corpus
  // tracks. The old v8/uv/openssl/modules masquerade is gone from default
  // execution; compat fixtures that hard-require those keys get them through
  // the harness escape hatch below, never ambient.
  const entries: Array<[string, string]> = [...RUNTIME_VERSIONS];

  if (isCompatModeEnabled('bun')) {
    // Opt-in Bun compat keeps detection coherent: when the Bun global
    // exists, process.versions.bun exists too (LLP 0012#decision).
    entries.push(['bun', BUN_COMPAT_VERSION]);
  }

  if (isCompatFixtureMode()) {
    // Fixture-fidelity keys for the compat harness (EXACT_COMPAT_TEST):
    // vendored Node/WPT tests read these. They describe what the fixtures
    // expect, not what this runtime links (LLP 0012#decision escape hatch).
    entries.push(
      ['acorn', '8.15.0'],
      ['ada', '2.9.2'],
      ['ares', '1.34.4'],
      ['brotli', '1.1.0'],
      ['cjs_module_lexer', '2.1.0'],
      ['cldr', '46.0'],
      ['icu', '76.1'],
      ['llhttp', '9.3.0'],
      ['modules', '131'],
      ['napi', '9'],
      ['nbytes', '0.1.1'],
      ['ncrypto', '0.0.1'],
      ['nghttp2', '1.64.0'],
      ['nghttp3', '1.6.0'],
      ['ngtcp2', '1.9.1'],
      ['openssl', '3.4.1'],
      ['simdjson', '3.13.0'],
      ['simdutf', '6.4.2'],
      ['tz', '2025a'],
      ['unicode', '16.0'],
      ['uv', '1.50.0'],
      ['uvwasi', '0.0.21'],
      ['v8', '13.6.233.8-node.26'],
      ['zlib', '1.3.1.1-motley-82a5fec'],
      ['zstd', '1.5.7'],
    );
  }

  for (const [key, value] of entries) {
    Object.defineProperty(versions, key, {
      value,
      writable: false,
      enumerable: true,
      configurable: true,
    });
  }

  return versions;
}

/// True when the named opt-in compat mode is active (set by the ibex CLI's
/// `--compat` flag via globalThis.__exactCompatModes, or the
/// EXACT_COMPAT_BUN env contract used by child spawns).
function isCompatModeEnabled(mode: string): boolean {
  try {
    const g = globalThis as any;
    const modes = g.__exactCompatModes;
    if (Array.isArray(modes) && modes.indexOf(mode) !== -1) return true;
    if (mode === 'bun') {
      const env = g.__exactHostEnv ?? g.process?.env;
      if (env && env.EXACT_COMPAT_BUN === '1') return true;
    }
  } catch (_) {
    // Identity must never throw during bootstrap.
  }
  return false;
}

function isCompatFixtureMode(): boolean {
  try {
    const g = globalThis as any;
    const env = g.__exactHostEnv ?? g.process?.env;
    return !!(env && env.EXACT_COMPAT_TEST);
  } catch (_) {
    return false;
  }
}

function createProcessRelease(nodeVersion: string): ProcessRelease {
  const release: ProcessRelease = { name: RELEASE_NAME };
  const [majorText = '', minorText = ''] = String(nodeVersion).split('.');
  const major = Number.parseInt(majorText, 10);
  const minor = Number.parseInt(minorText, 10);
  const ltsMap: Array<[number, number, string]> = [
    [4, 2, 'Argon'],
    [6, 9, 'Boron'],
    [8, 9, 'Carbon'],
    [10, 13, 'Dubnium'],
    [12, 13, 'Erbium'],
    [14, 15, 'Fermium'],
    [16, 13, 'Gallium'],
    [18, 12, 'Hydrogen'],
    [20, 9, 'Iron'],
    [22, 11, 'Jod'],
    [24, 11, 'Krypton'],
  ];
  for (const [ltsMajor, ltsMinor, ltsName] of ltsMap) {
    if (major === ltsMajor && minor >= ltsMinor) {
      release.lts = ltsName;
      break;
    }
  }
  return release;
}

// Console fallback only (no native write available): a lossy decode is the
// best a text console can do with binary chunks.
function _decodeStreamChunkForConsole(data: string | Uint8Array): string {
  if (typeof data === 'string') return data;
  if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(data);
  let out = '';
  for (let i = 0; i < data.length; i++) out += String.fromCharCode(data[i]);
  return out;
}

/**
 * Create a process stream (stdout/stderr/stdin) with basic EventEmitter support.
 * This ensures pipe() and other stream operations work even before stream-enhance runs.
 */
function _makeProcessStream(fd: number, isTTY: boolean, writeFn?: (data: string | Uint8Array) => boolean): any {
  const listeners: Record<string, Array<{fn: Function, once: boolean}>> = {};
  // Buffer / Uint8Array chunks are passed through as raw bytes: the native
  // write (__exactFsWrite) accepts a Uint8Array verbatim, while decoding to a
  // JS string UTF-8-mangled binary output (0xff -> U+FFFD), silently
  // corrupting e.g. an image piped to stdout. (ENG-23140)
  function coerceChunk(chunk: any): string | Uint8Array {
    if (chunk == null) return '';
    if (typeof chunk === 'string') return chunk;
    if (chunk instanceof Uint8Array) return chunk;
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer && Buffer.isBuffer(chunk)) return chunk;
    return String(chunk);
  }
  const stream: any = {
    fd,
    isTTY,
    readable: fd === 0,
    readableEnded: false,
    readableFlowing: null,
    readableLength: 0,
    writable: fd > 0,
    writableEnded: false,
    writableFinished: false,
    destroyed: false,
    _encoding: null,
    _paused: true,
    _ended: false,
    _pollTimer: 0,
    on(event: string, fn: Function) { if (!listeners[event]) listeners[event] = []; listeners[event].push({fn, once: false}); return stream; },
    addListener(event: string, fn: Function) { return stream.on(event, fn); },
    once(event: string, fn: Function) { if (!listeners[event]) listeners[event] = []; listeners[event].push({fn, once: true}); return stream; },
    emit(event: string, ...args: any[]) {
      const list = listeners[event];
      if (!list) return false;
      const keep: typeof list = [];
      for (let i = 0; i < list.length; i++) {
        if (typeof list[i].fn === 'function') list[i].fn.apply(stream, args);
        if (!list[i].once) keep.push(list[i]);
      }
      listeners[event] = keep;
      return true;
    },
    removeListener(event: string, fn: Function) {
      const list = listeners[event];
      if (list) listeners[event] = list.filter(l => l.fn !== fn);
      return stream;
    },
    off(event: string, fn: Function) { return stream.removeListener(event, fn); },
    removeAllListeners(event?: string) { if (event) { listeners[event] = []; } else { for (const k in listeners) listeners[k] = []; } return stream; },
    setMaxListeners() { return stream; },
    getMaxListeners() { return 10; },
    listenerCount(event: string) { return listeners[event] ? listeners[event].length : 0; },
    listeners(event: string) { return (listeners[event] || []).map(l => l.fn); },
    prependListener(event: string, fn: Function) { if (!listeners[event]) listeners[event] = []; listeners[event].unshift({fn, once: false}); return stream; },
    prependOnceListener(event: string, fn: Function) { if (!listeners[event]) listeners[event] = []; listeners[event].unshift({fn, once: true}); return stream; },
    rawListeners(event: string) { return stream.listeners(event); },
    eventNames() { return Object.keys(listeners).filter(k => listeners[k] && listeners[k].length > 0); },
    destroy(err?: any) {
      stream.destroyed = true;
      if (fd === 0) {
        stream.readable = false;
        stream.readableEnded = true;
        stream.readableFlowing = false;
      } else {
        stream.writableEnded = true;
        stream.writableFinished = true;
      }
      if (err) stream.emit('error', err);
      stream.emit('close');
      return stream;
    },
  };
  if (fd === 0) {
    const stdinBytes = (data: any): any => {
      if (typeof data === 'string') {
        if (typeof Buffer !== 'undefined' && Buffer.from) {
          return Buffer.from(data, 'binary');
        }
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) out[i] = data.charCodeAt(i) & 0xff;
        return out;
      }
      if (typeof ArrayBuffer !== 'undefined' && data instanceof ArrayBuffer) {
        return new Uint8Array(data);
      }
      if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength || 0);
      }
      return data;
    };
    const stdinChunk = (data: any, flush = false): any => {
      const bytes = stdinBytes(data);
      if (!stream._encoding) {
        if (typeof Buffer !== 'undefined' && Buffer.from) return Buffer.from(bytes);
        return bytes;
      }
      if (typeof TextDecoder === 'function') {
        try {
          if (!stream._decoder) {
            stream._decoder = new TextDecoder(stream._encoding === 'utf8' ? 'utf-8' : stream._encoding);
          }
          return stream._decoder.decode(bytes || new Uint8Array(0), { stream: !flush });
        } catch {
          stream._decoder = null;
        }
      }
      if (typeof Buffer !== 'undefined' && Buffer.from) {
        return Buffer.from(bytes).toString(stream._encoding);
      }
      return String(data || '');
    };
    const emitStdinChunk = (data: any) => {
      const chunk = stdinChunk(data, false);
      stream.readableLength += chunk?.byteLength || chunk?.length || 0;
      stream.emit('data', chunk);
      stream.readableLength = 0;
    };
    const flushStdinDecoder = () => {
      if (!stream._encoding || !stream._decoder) return;
      const tail = stdinChunk(new Uint8Array(0), true);
      if (!tail) return;
      stream.readableLength += tail.length || 0;
      stream.emit('data', tail);
      stream.readableLength = 0;
    };
    stream.setEncoding = function(enc: string) {
      stream._encoding = enc;
      stream._decoder = null;
      return stream;
    };
    stream.resume = function() {
      stream.readable = true;
      stream._paused = false;
      stream.readableFlowing = true;
      if (!stream._ended && !stream._pollTimer && typeof (globalThis as any).__exactStdinRead === 'function') {
        (function pollStdin() {
          if (stream._paused || stream._ended || stream.destroyed) {
            return;
          }
          const stdinRead = (globalThis as any).__exactStdinRead;
          const data = stdinRead(4096);
          if (data === null) {
            stream._pollTimer = setTimeout(pollStdin, 25);
            return;
          }
          if (data === '') {
            flushStdinDecoder();
            stream._ended = true;
            stream._pollTimer = 0;
            stream.readableEnded = true;
            stream.emit('end');
            stream.emit('close');
            return;
          }
          stream._pollTimer = 0;
          emitStdinChunk(data);
          if (!stream._paused && !stream._ended) {
            stream._pollTimer = setTimeout(pollStdin, 10);
          }
        })();
      }
      return stream;
    };
    stream.pause = function() {
      stream._paused = true;
      stream.readableFlowing = false;
      if (stream._pollTimer) {
        clearTimeout(stream._pollTimer);
        stream._pollTimer = 0;
      }
      return stream;
    };
    stream.read = function(size?: number) {
      const stdinRead = (globalThis as any).__exactStdinRead;
      if (typeof stdinRead !== 'function') {
        return null;
      }
      const data = stdinRead(size || 4096);
      if (data === '') {
        return null;
      }
      if (data === null) {
        return null;
      }
      return stdinChunk(data, false);
    };
    stream.pipe = function(destination: any) {
      stream.on('data', (chunk: any) => {
        destination.write(chunk);
      });
      stream.once('end', () => {
        destination.end?.();
      });
      stream.once('error', (error: any) => {
        if (typeof destination.emit === 'function') {
          destination.emit('error', error);
        } else {
          destination.destroy?.(error);
        }
      });
      stream.resume();
      return destination;
    };
    const originalOn = stream.on;
    stream.on = function(event: string, fn: Function) {
      const result = originalOn.call(stream, event, fn);
      if (event === 'data' && !stream._ended && stream._paused) {
        stream.resume();
      }
      return result;
    };
    stream.addListener = stream.on;
    const originalOnce = stream.once;
    stream.once = function(event: string, fn: Function) {
      const result = originalOnce.call(stream, event, fn);
      if (event === 'data' && !stream._ended && stream._paused) {
        stream.resume();
      }
      return result;
    };
  }
  // Node invokes stream.write callbacks asynchronously even when the
  // underlying write completed synchronously; a synchronous call lets the
  // callback observe pre-write program state. Real Node runs them on the
  // nextTick queue (after all synchronous code, before microtasks), so defer
  // through the same delegation as Process#nextTick to keep write callbacks
  // and user nextTicks interleaving in one queue. (ENG-23236)
  function _deferWriteCallback(callback: Function): void {
    const cb = callback as (...args: any[]) => void;
    if (_nativeProcessNextTick) {
      _nativeProcessNextTick(cb);
      return;
    }
    if (_nativeGlobalNextTick) {
      _nativeGlobalNextTick(cb);
      return;
    }
    _nextTickQueue.push({ callback: cb, args: [] });
    _scheduleNextTickDrain();
  }
  function _writeAfterEndError(): Error & { code: string } {
    const err = new Error('write after end') as Error & { code: string };
    err.code = 'ERR_STREAM_WRITE_AFTER_END';
    return err;
  }
  if (writeFn) {
    const _exactWriteImpl = function(chunk: any, encoding?: any, callback?: Function) {
      if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
      if (stream.writableEnded || stream.destroyed) {
        const err = _writeAfterEndError();
        if (typeof callback === 'function') _deferWriteCallback(() => callback(err));
        _deferWriteCallback(() => stream.emit('error', err));
        return false;
      }
      // Honor the encoding argument: the native write path (__exactFsWrite)
      // treats strings as UTF-8, so write('aGVsbG8=', 'base64') must be
      // converted to bytes here or the literal base64 text is emitted.
      // Same shape as the bootstrap-layer fix from ENG-23132; this
      // shared-bundle write is the one that actually executes in all
      // runtime modes. (ENG-23236)
      if (typeof chunk === 'string' && typeof encoding === 'string' &&
          encoding !== '' && encoding !== 'utf8' && encoding !== 'utf-8') {
        if (typeof Buffer !== 'undefined' && Buffer.from) {
          try {
            chunk = Buffer.from(chunk, encoding);
            encoding = undefined;
          } catch (_err) {
            // Unknown encoding label: fall through and emit the raw string
            // (matches the landed bootstrap fallback shape).
          }
        }
      }
      const normalizedChunk = coerceChunk(chunk);
      const result = writeFn(normalizedChunk);
      if (typeof callback === 'function') _deferWriteCallback(callback);
      return result;
    };
    (_exactWriteImpl as any).__exactNativeWrite = true;
    stream.write = _exactWriteImpl;
    stream.end = function(chunk?: any, encoding?: any, callback?: Function) {
      if (typeof chunk === 'function') { callback = chunk; chunk = undefined; }
      if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
      if (chunk != null) stream.write(chunk, encoding);
      stream.writableEnded = true;
      stream.writableFinished = true;
      _deferWriteCallback(() => {
        stream.emit('finish');
        if (typeof callback === 'function') callback();
        stream.emit('close');
      });
      return stream;
    };
  }
  return stream;
}

export interface ProcessRelease {
  name: string;
  lts?: string | false;
  sourceUrl?: string;
  headersUrl?: string;
}

export interface HrtimeFunction {
  (time?: [number, number]): [number, number];
  bigint?: () => bigint;
}

/**
 * Create a Proxy-based env object that reads from native
 */
export function createEnvProxy(): Record<string, string | undefined> {
  // Seeded JS defaults commonly expected by npm packages. Both the native env
  // and explicit JS writes take precedence over these, so the native layer can
  // still promote NODE_ENV to 'production' for release builds while a
  // `process.env.NODE_ENV = ...` assignment from user code also sticks.
  const jsEnv: Record<string, string | undefined> = {
    NODE_ENV: 'development',
  };
  // Keys explicitly written on the JS side. Tracking these separately from the
  // seeded defaults lets a write win over a native value (native never wins
  // back over an explicit `process.env.X = ...`).
  const jsOverrides = new Set<string>();
  // Tombstones for keys deleted on the JS side. These hide any native value so
  // `delete process.env.X` actually sticks instead of resurrecting the host var.
  const jsDeleted = new Set<string>();
  // Read-through cache of the native env only. It never stores JS overrides, so
  // refreshNativeCache() re-cloning __exactGetAllEnv() can't wipe JS state.
  let nativeCache: Record<string, string> | null = null;

  function refreshNativeCache(): Record<string, string> {
    if (typeof __exactGetAllEnv === 'function') {
      nativeCache = { ...__exactGetAllEnv() };
    } else if (nativeCache === null) {
      nativeCache = {};
    }
    return nativeCache ?? {};
  }

  function getNativeValue(key: string): string | undefined {
    if (nativeCache && Object.prototype.hasOwnProperty.call(nativeCache, key)) {
      return nativeCache[key];
    }
    if (typeof __exactGetEnv === 'function') {
      const value = __exactGetEnv(key);
      if (value !== undefined) {
        refreshNativeCache()[key] = value;
      }
      return value;
    }
    return refreshNativeCache()[key];
  }

  // Resolve a key with correct precedence: a JS delete hides everything, then an
  // explicit JS write wins over native, then native wins over a seeded default.
  function resolveValue(key: string): string | undefined {
    if (jsDeleted.has(key)) {
      return undefined;
    }
    if (jsOverrides.has(key)) {
      return jsEnv[key];
    }
    const nativeValue = getNativeValue(key);
    if (nativeValue !== undefined) {
      return nativeValue;
    }
    return jsEnv[key];
  }

  function collectAll(): Record<string, string> {
    const keys = new Set<string>();
    Object.keys(refreshNativeCache()).forEach(k => keys.add(k));
    Object.keys(jsEnv).forEach(k => keys.add(k));
    const all: Record<string, string> = {};
    for (const key of keys) {
      const value = resolveValue(key);
      if (value !== undefined) {
        all[key] = value;
      }
    }
    return all;
  }

  return new Proxy(jsEnv, {
    get(target, prop: string | symbol): string | undefined {
      if (typeof prop === 'symbol') {
        return undefined;
      }

      // Special handling for toJSON
      if (prop === 'toJSON') {
        return () => collectAll();
      }

      return resolveValue(prop);
    },

    set(target, prop: string | symbol, value: any): boolean {
      if (typeof prop === 'symbol') {
        throw new TypeError('Cannot convert a Symbol value to a string');
      }
      if (typeof value === 'symbol') {
        throw new TypeError('Cannot convert a Symbol value to a string');
      }
      const key = prop as string;
      if (key.length === 0) {
        return true;
      }
      const normalized = String(value);
      target[key] = normalized;
      // Mark as an explicit JS write so it wins over native, and clear any prior
      // tombstone so re-setting a deleted key brings it back.
      jsOverrides.add(key);
      jsDeleted.delete(key);
      return true;
    },

    has(target, prop: string | symbol): boolean {
      if (typeof prop === 'symbol') {
        return false;
      }

      return resolveValue(prop) !== undefined;
    },

    deleteProperty(target, prop: string | symbol): boolean {
      if (typeof prop === 'symbol') {
        return true;
      }
      const key = prop as string;
      delete target[key];
      // Drop the override flag and record a tombstone so the native value stays
      // hidden until the key is written again.
      jsOverrides.delete(key);
      jsDeleted.add(key);
      return true;
    },

    ownKeys(target): string[] {
      const keys = new Set<string>();
      Object.keys(refreshNativeCache()).forEach(k => keys.add(k));
      Object.keys(target).forEach(k => keys.add(k));

      return Array.from(keys).filter(k => resolveValue(k) !== undefined);
    },

    defineProperty(target, prop: string | symbol, descriptor: PropertyDescriptor): boolean {
      if (typeof prop === 'symbol') {
        throw makeInvalidObjectDefinePropertyError(
          '\'process.env\' only accepts a configurable, writable, and enumerable data descriptor',
        );
      }

      if (typeof descriptor.get === 'function' || typeof descriptor.set === 'function') {
        throw makeInvalidObjectDefinePropertyError(
          '\'process.env\' does not accept an accessor(getter/setter) descriptor',
        );
      }

      if (descriptor.configurable !== true || descriptor.writable !== true || descriptor.enumerable !== true) {
        throw makeInvalidObjectDefinePropertyError(
          '\'process.env\' only accepts a configurable, writable, and enumerable data descriptor',
        );
      }

      this.set!(target, prop, descriptor.value, target);
      return true;
    },

    getOwnPropertyDescriptor(target, prop: string | symbol): PropertyDescriptor | undefined {
      if (typeof prop === 'symbol') {
        return undefined;
      }

      const value = resolveValue(prop as string);
      if (value === undefined) {
        return undefined;
      }

      return {
        value,
        writable: true,
        enumerable: true,
        configurable: true,
      };
    },
  });
}

/**
 * Process object providing Node.js-like environment info.
 */
class Process {
  private _maxListeners = 10;
  /**
   * Environment variables.
   * Reads from native layer with fallback to JS-set values.
   * NODE_ENV defaults to 'development' (native layer sets 'production' for release builds).
   */
  readonly env: Record<string, string | undefined> = createEnvProxy();

  /**
   * Platform identifier.
   * Returns host platform when available (e.g. "linux", "darwin", "win32"),
   * otherwise falls back to runtime detection.
   */
  get platform(): string {
    const g = globalThis as any;
    if (typeof g.__exactPlatform === 'string' && g.__exactPlatform.length > 0) {
      return g.__exactPlatform;
    }
    return runtimeInfo.platform;
  }

  /**
   * Process architecture.
   * Returns host arch when available (e.g. "x64", "arm64").
   */
  get arch(): string {
    const g = globalThis as any;
    if (typeof g.__exactArch === 'string' && g.__exactArch.length > 0) {
      return g.__exactArch;
    }
    // Avoid reading g.process.arch — it may be this instance, causing infinite recursion.
    // Use the cached native arch captured at init time instead.
    if (_nativeArch) {
      return _nativeArch;
    }
    return 'arm64';
  }

  /**
   * Node.js-compatible version string.
   * Format: "v{major}.{minor}.{patch}"
   */
  get version(): string {
    return `v${PROCESS_VERSIONS.node ?? getRuntimeVersion()}`;
  }

  /**
   * Version strings for various components.
   * Includes all fields that Node.js tests expect on `process.versions`.
   */
  get versions(): ProcessVersions {
    return PROCESS_VERSIONS;
  }

  readonly config = PROCESS_DEFAULT_CONFIG;

  /**
   * Release information.
   */
  get release(): ProcessRelease {
    return PROCESS_RELEASE;
  }

  /**
   * Process title (runtime name).
   * Writable like Node's: a getter-only property made strict-mode ESM code
   * throw on the common `process.title = ...` assignment. (ENG-23140)
   */
  private _title = 'ibex';

  get title(): string {
    return this._title;
  }

  set title(value: string) {
    if (typeof value !== 'string') {
      const err = new TypeError(
        `The "title" argument must be of type string. Received ${formatReceivedValue(value)}`,
      ) as TypeError & { code: string };
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    this._title = value;
  }

  /**
   * Process ID. Real OS pid on desktop (captured from the native process
   * object before this shim replaced it — ENG-23234); 1 on mobile embeds
   * where there is no meaningful pid.
   */
  get pid(): number {
    return _nativePid ?? 1;
  }

  /**
   * Parent process ID. Real OS ppid on desktop; 0 on mobile embeds.
   */
  get ppid(): number {
    return _nativePpid ?? 0;
  }

  binding(name: string): unknown {
    if (name === 'util') {
      const types = (globalThis as any).require?.('util')?.types ?? {};
      const binding: Record<string, unknown> = {};
      for (const key of [
        'isAnyArrayBuffer',
        'isArrayBuffer',
        'isArrayBufferView',
        'isAsyncFunction',
        'isDataView',
        'isDate',
        'isExternal',
        'isMap',
        'isMapIterator',
        'isNativeError',
        'isPromise',
        'isRegExp',
        'isSet',
        'isSetIterator',
        'isTypedArray',
        'isUint8Array',
      ]) {
        binding[key] = types[key];
      }
      return binding;
    }
    // Return empty stubs for deprecated/internal bindings that vendored Node
    // modules may request at import time.  Throwing here causes "unhandled
    // error between tests" noise and can break module-level initialization.
    if (name === 'constants') {
      return {
        os: {
          errno: {
            E2BIG: 7, EACCES: 13, EADDRINUSE: 48, EADDRNOTAVAIL: 49,
            EAFNOSUPPORT: 47, EAGAIN: 35, EALREADY: 37, EBADF: 9,
            EBUSY: 16, ECANCELED: 89, ECHILD: 10, ECONNABORTED: 53,
            ECONNREFUSED: 61, ECONNRESET: 54, EDEADLK: 11, EDESTADDRREQ: 39,
            EDOM: 33, EEXIST: 17, EFAULT: 14, EFBIG: 27, EHOSTUNREACH: 65,
            EINPROGRESS: 36, EINTR: 4, EINVAL: 22, EIO: 5, EISCONN: 56,
            EISDIR: 21, ELOOP: 62, EMFILE: 24, EMLINK: 31, EMSGSIZE: 40,
            ENAMETOOLONG: 63, ENETDOWN: 50, ENETRESET: 52, ENETUNREACH: 51,
            ENFILE: 23, ENOBUFS: 55, ENODEV: 19, ENOENT: 2, ENOEXEC: 8,
            ENOLCK: 77, ENOMEM: 12, ENOPROTOOPT: 42, ENOSPC: 28, ENOSYS: 78,
            ENOTCONN: 57, ENOTDIR: 20, ENOTEMPTY: 66, ENOTSOCK: 38,
            ENOTSUP: 45, ENOTTY: 25, ENXIO: 6, EOPNOTSUPP: 102,
            EOVERFLOW: 84, EPERM: 1, EPIPE: 32, EPROTONOSUPPORT: 43,
            EPROTOTYPE: 41, ERANGE: 34, EROFS: 30, ESPIPE: 29, ESRCH: 3,
            ETIMEDOUT: 60, ETXTBSY: 26, EWOULDBLOCK: 35, EXDEV: 18,
          },
          // Share the platform-branched table with process.kill() so the two
          // can never disagree about signal numbering again. (ENG-23140)
          signals: { ...currentSignalNameToNumberMap() },
        },
        fs: {
          O_RDONLY: 0, O_WRONLY: 1, O_RDWR: 2, O_CREAT: 512, O_EXCL: 2048,
          O_TRUNC: 1024, O_APPEND: 8, O_DIRECTORY: 1048576, O_SYMLINK: 2097152,
          S_IFMT: 61440, S_IFREG: 32768, S_IFDIR: 16384, S_IFLNK: 40960,
          S_IFCHR: 8192, S_IFBLK: 24576, S_IFIFO: 4096, S_IFSOCK: 49152,
        },
        zlib: {
          Z_NO_FLUSH: 0, Z_PARTIAL_FLUSH: 1, Z_SYNC_FLUSH: 2,
          Z_FULL_FLUSH: 3, Z_FINISH: 4, Z_BLOCK: 5,
          Z_OK: 0, Z_STREAM_END: 1, Z_NEED_DICT: 2,
          Z_ERRNO: -1, Z_STREAM_ERROR: -2, Z_DATA_ERROR: -3,
          Z_MEM_ERROR: -4, Z_BUF_ERROR: -5, Z_VERSION_ERROR: -6,
          Z_NO_COMPRESSION: 0, Z_BEST_SPEED: 1, Z_BEST_COMPRESSION: 9,
          Z_DEFAULT_COMPRESSION: -1,
          Z_FILTERED: 1, Z_HUFFMAN_ONLY: 2, Z_RLE: 3, Z_FIXED: 4,
          Z_DEFAULT_STRATEGY: 0,
          Z_MIN_WINDOWBITS: 8, Z_MAX_WINDOWBITS: 15, Z_DEFAULT_WINDOWBITS: 15,
          Z_MIN_CHUNK: 64, Z_MAX_CHUNK: null, Z_DEFAULT_CHUNK: 16384,
          Z_MIN_MEMLEVEL: 1, Z_MAX_MEMLEVEL: 9, Z_DEFAULT_MEMLEVEL: 8,
          Z_MIN_LEVEL: -1, Z_MAX_LEVEL: 9, Z_DEFAULT_LEVEL: -1,
          DEFLATE: 1, INFLATE: 2, GZIP: 3, GUNZIP: 4,
          DEFLATERAW: 5, INFLATERAW: 6, UNZIP: 7,
          BROTLI_DECODE: 8, BROTLI_ENCODE: 9,
          BROTLI_OPERATION_PROCESS: 0, BROTLI_OPERATION_FLUSH: 1,
          BROTLI_OPERATION_FINISH: 2, BROTLI_OPERATION_EMIT_METADATA: 3,
          BROTLI_PARAM_MODE: 0, BROTLI_MODE_GENERIC: 0,
          BROTLI_MODE_TEXT: 1, BROTLI_MODE_FONT: 2, BROTLI_DEFAULT_MODE: 0,
          BROTLI_PARAM_QUALITY: 1, BROTLI_MIN_QUALITY: 0,
          BROTLI_MAX_QUALITY: 11, BROTLI_DEFAULT_QUALITY: 11,
          BROTLI_PARAM_LGWIN: 2, BROTLI_MIN_WINDOW_BITS: 10,
          BROTLI_MAX_WINDOW_BITS: 24, BROTLI_LARGE_MAX_WINDOW_BITS: 30,
          BROTLI_DEFAULT_WINDOW: 22, BROTLI_PARAM_LGBLOCK: 3,
          BROTLI_MIN_INPUT_BLOCK_BITS: 16, BROTLI_MAX_INPUT_BLOCK_BITS: 24,
          BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING: 4,
          BROTLI_PARAM_SIZE_HINT: 5, BROTLI_PARAM_LARGE_WINDOW: 6,
          BROTLI_PARAM_NPOSTFIX: 7, BROTLI_PARAM_NDIRECT: 8,
          BROTLI_DECODER_RESULT_ERROR: 0, BROTLI_DECODER_RESULT_SUCCESS: 1,
          BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: 2,
          BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: 3,
          BROTLI_DECODER_PARAM_DISABLE_RING_BUFFER_REALLOCATION: 0,
          BROTLI_DECODER_PARAM_LARGE_WINDOW: 1,
          BROTLI_DECODER_NO_ERROR: 0, BROTLI_DECODER_SUCCESS: 1,
          BROTLI_DECODER_NEEDS_MORE_INPUT: 2,
          BROTLI_DECODER_NEEDS_MORE_OUTPUT: 3,
        },
      };
    }
    if (name === 'uv' || name === 'http_parser') {
      return {};
    }
    throw new Error(`No such module: ${name}`);
  }

  /**
   * IPC channel (not available in Ibex runtime).
   */
  get channel(): undefined {
    return undefined;
  }

  execve(execPath: string, args: string[], envObj?: Record<string, string>): void {
    validateExecveArguments(execPath, args, envObj, arguments.length >= 3);

    if (isChildProcessPermissionDenied(this.execArgv)) {
      const err = new Error('Access to this API has been restricted') as Error & {
        code: string;
        permission: string;
        resource: string;
      };
      err.code = 'ERR_ACCESS_DENIED';
      err.permission = 'ChildProcess';
      err.resource = execPath;
      throw err;
    }

    const requireFn = (globalThis as any).require;
    if (typeof requireFn !== 'function') {
      const err = new TypeError('process.execve is not supported in this runtime') as TypeError & { code: string };
      err.code = 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM';
      throw err;
    }

    const childProcess = requireFn('child_process');
    if (!childProcess || typeof childProcess.spawnSync !== 'function') {
      const err = new TypeError('process.execve is not supported in this runtime') as TypeError & { code: string };
      err.code = 'ERR_FEATURE_UNAVAILABLE_ON_PLATFORM';
      throw err;
    }

    const result = childProcess.spawnSync(execPath, args.slice(1), {
      env: envObj ?? { ...this.env },
      stdio: 'inherit',
    });

    if (result?.error) {
      throw result.error;
    }

    this.exit(typeof result?.status === 'number' ? result.status : 0);
  }

  /**
   * Exit code for the process.
   * Node.js accepts number, string-convertible-to-number, null (resets to undefined), or undefined.
   */
  private _exitCode: number | undefined = undefined;
  private _uid = readNativeProcessId(_nativeGetuid, 0);
  private _gid = readNativeProcessId(_nativeGetgid, 0);
  private _euid = readNativeProcessId(_nativeGeteuid, this._uid);
  private _egid = readNativeProcessId(_nativeGetegid, this._gid);

  get exitCode(): number | undefined {
    return this._exitCode;
  }

  set exitCode(value: number | undefined) {
    if (value === null || value === undefined) {
      this._exitCode = undefined;
      return;
    }
    if (typeof value === 'string') {
      if (value.length === 0) {
        const e: any = new TypeError(`The "code" argument must be of type number. Received type string ('')`);
        e.code = 'ERR_INVALID_ARG_TYPE';
        throw e;
      }
      const num = Number(value);
      if (Number.isNaN(num) || !Number.isInteger(num) || !Number.isFinite(num)) {
        const e: any = new TypeError(`The "code" argument must be of type number. Received type string ('${value}')`);
        e.code = 'ERR_INVALID_ARG_TYPE';
        throw e;
      }
      this._exitCode = num;
      return;
    }
    if (typeof value === 'bigint') {
      const e: any = new TypeError(`The "code" argument must be of type number. Received type bigint (${value}n)`);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (typeof value !== 'number') {
      const e: any = new TypeError(`The "code" argument must be of type number. Received type ${typeof value}`);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (!Number.isInteger(value) || !Number.isFinite(value)) {
      const e: any = new RangeError(`The value of "code" is out of range. It must be an integer. Received ${value}`);
      e.code = 'ERR_OUT_OF_RANGE';
      throw e;
    }
    this._exitCode = value;
  }

  /**
   * Whether deprecation warnings should be suppressed.
   */
  noDeprecation = false;

  /**
   * Whether to throw on deprecation warnings instead of logging.
   */
  throwDeprecation = false;

  /**
   * Whether to show stack traces for deprecation warnings.
   */
  traceDeprecation = false;

  /**
   * Whether the process is currently exiting.
   */
  _exactExiting = false;

  /**
   * Get the user ID of the process.
   */
  getuid(): number {
    return this._uid;
  }

  /**
   * Get the group ID of the process.
   */
  getgid(): number {
    return this._gid;
  }

  /**
   * Get the effective user ID of the process.
   */
  geteuid(): number {
    return this._euid;
  }

  /**
   * Get the effective group ID of the process.
   */
  getegid(): number {
    return this._egid;
  }

  /**
   * Set the user ID (throws - not supported).
   */
  setuid(id: number | string): void {
    const resolved = resolveCredentialId(id, 'user');
    if (this._uid !== 0 && this._euid !== 0) {
      throw makeCredentialPermissionError();
    }
    this._uid = resolved;
    this._euid = resolved;
  }

  /**
   * Set the group ID (throws - not supported).
   */
  setgid(id: number | string): void {
    const resolved = resolveCredentialId(id, 'group');
    if (this._uid !== 0 && this._euid !== 0) {
      throw makeCredentialPermissionError();
    }
    this._gid = resolved;
    this._egid = resolved;
  }

  /**
   * Set the effective user ID (throws - not supported).
   */
  seteuid(id: number | string): void {
    const resolved = resolveCredentialId(id, 'user');
    if (this._uid !== 0 && this._euid !== 0) {
      throw makeCredentialPermissionError();
    }
    this._euid = resolved;
  }

  /**
   * Set the effective group ID (throws - not supported).
   */
  setegid(id: number | string): void {
    const resolved = resolveCredentialId(id, 'group');
    if (this._uid !== 0 && this._euid !== 0) {
      throw makeCredentialPermissionError();
    }
    this._egid = resolved;
  }

  /**
   * Get supplementary group IDs.
   */
  getgroups(): number[] {
    return [this._gid];
  }

  /**
   * Send a signal to a process.
   * Validates signal names/numbers per Node.js behavior.
   */
  kill(pid: number | string, signal?: string | number): true {
    const normalizedPid = normalizeProcessId(pid);
    const normalizedSignal = normalizeSignal(signal);
    (this._kill as (pid: number, signalNumber: number) => true).call(this, normalizedPid, normalizedSignal);
    return true;
  }

  _kill(pid: number, signalNumber: number): true {
    if (_nativeProcessKill) {
      try {
        _nativeProcessKill(pid, signalNumber);
        return true;
      } catch {
        // Fall through to manual handling if native kill fails (e.g. sandbox)
      }
    }
    // Signal 0 is an existence check — always succeeds for our own pid
    if (pid === this.pid) {
      return true;
    }
    const e: any = new Error('kill ESRCH');
    e.code = 'ESRCH';
    e.errno = -3;
    e.syscall = 'kill';
    throw e;
  }

  /**
   * Returns the current working directory.
   * In mobile context, this is the app's documents directory.
   */
  cwd(): string {
    if (_processCwd && _processCwd !== '/') {
      return _processCwd;
    }
    const nativeCwd = _readNativeCwd();
    if (nativeCwd) {
      _processCwd = nativeCwd;
      return _processCwd;
    }
    if (!_processCwd || _processCwd === '/') {
      _processCwd = '/';
    }
    return _processCwd;
  }

  /**
   * Change working directory.
   */
  chdir(_directory: string): void {
    if (typeof _directory !== 'string') {
      const err = new TypeError(`The "directory" argument must be of type string. Received type ${typeof _directory}`);
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }

    const resolvedPath = _resolveCwd(_directory);
    if (typeof __exactSetCwd !== 'function') {
      if (typeof (globalThis as any).__exactAccess === 'function') {
        try {
          (globalThis as any).__exactAccess(resolvedPath, 0);
        } catch (e) {
          throw _coerceChdirError(e, _directory);
        }
      }
      _processCwd = resolvedPath;
      return;
    }

    try {
      __exactSetCwd(resolvedPath);
      _processCwd = resolvedPath;
    } catch (e) {
      throw _coerceChdirError(e, _directory);
    }
  }

  /**
   * Exit the process.
   * Sets exitCode first, fires exit handlers, then terminates if native exit is available.
   */
  exit(code?: number): void {
    const requestedExitCode = code ?? this.exitCode ?? 0;
    this.exitCode = requestedExitCode;

    if (this._exactExiting) {
      return;
    }

    this._exactExiting = true;
    try {
      const listeners = [...(this._events.get('exit') || [])];
      for (const entry of listeners) {
        try {
          entry.fn(requestedExitCode);
        } catch (_e) {
          /* ignore */
        }
      }
    } catch (_e) {
      /* ignore */
    } finally {
      if (typeof this._events.clear === 'function') {
        this._events.clear();
      }
    }
    // Try native exit if available, but never throw from runtime-side.
    const finalExitCode = this.exitCode ?? 0;
    const g = globalThis as any;
    if (typeof g.__exactExit === 'function') {
      try {
        g.__exactExit(finalExitCode);
      } catch (_e) {
        /* ignore */
      }
    }
  }

  /**
   * Abort the process.
   */
  abort(): never {
    throw new Error('process.abort() is not supported in Ibex runtime');
  }

  /**
   * Schedule a callback to run on the next tick of the event loop.
   * This runs before any I/O events but after the current operation.
   */
  nextTick(callback: (...args: any[]) => void, ...args: any[]): void {
    if (typeof callback !== 'function') {
      // Node throws synchronously at the call site (ERR_INVALID_ARG_TYPE);
      // deferring the TypeError into the queue misattributes it. (ENG-23140)
      const err = new TypeError(
        `The "callback" argument must be of type function. Received ${formatReceivedValue(callback)}`,
      ) as TypeError & { code: string };
      err.code = 'ERR_INVALID_ARG_TYPE';
      throw err;
    }
    if (_nativeProcessNextTick) {
      _nativeProcessNextTick(callback, ...args);
      return;
    }
    if (_nativeGlobalNextTick) {
      _nativeGlobalNextTick(callback, ...args);
      return;
    }
    _nextTickQueue.push({ callback, args });
    _scheduleNextTickDrain();
  }

  /**
   * High-resolution time.
   * Returns [seconds, nanoseconds] tuple.
   * Also has hrtime.bigint() when the engine supports BigInt.
   */
  hrtime: HrtimeFunction = (() => {
    const hrtime = (time?: [number, number]): [number, number] => {
      if (time !== undefined) {
        if (!Array.isArray(time)) {
          const e: any = new TypeError(`The "time" argument must be an instance of Array. Received type ${typeof time} (${String(time)})`);
          e.code = 'ERR_INVALID_ARG_TYPE';
          throw e;
        }
        if (time.length !== 2) {
          const e: any = new RangeError(`The value of "time" is out of range. It must be 2. Received ${time.length}`);
          e.code = 'ERR_OUT_OF_RANGE';
          throw e;
        }
      }
      const [seconds, nanoseconds] = _monotonicHrtimeTuple();

      if (time) {
        let diffSeconds = seconds - time[0];
        let diffNanos = nanoseconds - time[1];
        if (diffNanos < 0) {
          diffSeconds -= 1;
          diffNanos += 1e9;
        }
        return [diffSeconds, diffNanos];
      }

      return [seconds, nanoseconds];
    };

    if (_nativeBigInt) {
      hrtime.bigint = (): bigint =>
        _nativeProcessHrtimeBigint ? _nativeProcessHrtimeBigint() : _monotonicTimeNs();
    }

    return hrtime;
  })();

  /**
   * Memory usage (approximate, not accurate on mobile).
   */
  memoryUsage(): { rss: number; heapTotal: number; heapUsed: number; external: number; arrayBuffers: number } {
    const exactGlobal = globalThis as any;
    const nativeHeapInfo =
      typeof exactGlobal.__exactGetHeapInfo === 'function'
        ? exactGlobal.__exactGetHeapInfo(false)
        : null;
    if (nativeHeapInfo && typeof nativeHeapInfo === 'object') {
      const heapTotal =
        typeof nativeHeapInfo.hermes_heapSize === 'number'
          ? nativeHeapInfo.hermes_heapSize
          : typeof nativeHeapInfo.heapSize === 'number'
            ? nativeHeapInfo.heapSize
            : 0;
      const heapUsed =
        typeof nativeHeapInfo.hermes_allocatedBytes === 'number'
          ? nativeHeapInfo.hermes_allocatedBytes
          : typeof nativeHeapInfo.allocatedBytes === 'number'
            ? nativeHeapInfo.allocatedBytes
            : 0;
      const external =
        typeof nativeHeapInfo.hermes_externalBytes === 'number'
          ? nativeHeapInfo.hermes_externalBytes
          : typeof nativeHeapInfo.externalBytes === 'number'
            ? nativeHeapInfo.externalBytes
            : 0;
      const arrayBuffers =
        typeof nativeHeapInfo.hermes_arrayBufferBytes === 'number'
          ? nativeHeapInfo.hermes_arrayBufferBytes
          : typeof nativeHeapInfo.arrayBufferBytes === 'number'
            ? nativeHeapInfo.arrayBufferBytes
            : 0;
      const nativeRss =
        typeof exactGlobal.__exactGetProcessRSS === 'function'
          ? exactGlobal.__exactGetProcessRSS()
          : null;
      const rss =
        typeof nativeRss === 'number' && nativeRss > 0
          ? nativeRss
          : Math.max(heapTotal, heapUsed + external, 1024 * 1024);

      return {
        rss,
        heapTotal,
        heapUsed,
        external,
        arrayBuffers,
      };
    }

    const perfMemory = (globalThis as any).performance?.memory;
    const heapTotal = typeof perfMemory?.totalJSHeapSize === 'number' ? perfMemory.totalJSHeapSize : 0;
    const heapUsed = typeof perfMemory?.usedJSHeapSize === 'number' ? perfMemory.usedJSHeapSize : 0;
    const arrayBuffers = typeof perfMemory?.arrayBuffers === 'number' ? perfMemory.arrayBuffers : 0;
    const rss = typeof perfMemory?.jsHeapSizeLimit === 'number'
      ? Math.max(perfMemory.jsHeapSizeLimit, heapTotal, heapUsed)
      : Math.max(heapTotal, heapUsed, 1024 * 1024);

    return {
      rss,
      heapTotal,
      heapUsed,
      external: 0,
      arrayBuffers,
    };
  }

  /**
   * CPU usage (not available on mobile, returns zeros).
   */
  cpuUsage(prevValue?: { user: number; system: number }): { user: number; system: number } {
    if (prevValue !== undefined) {
      if (typeof prevValue !== 'object' || prevValue === null || Array.isArray(prevValue)) {
        const e: any = new TypeError(`The "prevValue" argument must be of type object. Received type ${typeof prevValue} (${String(prevValue)})`);
        e.code = 'ERR_INVALID_ARG_TYPE';
        throw e;
      }
      if (typeof prevValue.user !== 'number') {
        const v = prevValue.user;
        const received = v == null ? ` Received ${v}` : typeof v === 'function' ? ` Received function ${(v as any).name}` : typeof v === 'object' ? (v.constructor && v.constructor.name ? ` Received an instance of ${v.constructor.name}` : ` Received ${String(v)}`) : ` Received type ${typeof v} (${String(v)})`;
        const e: any = new TypeError(`The "prevValue.user" property must be of type number.${received}`);
        e.code = 'ERR_INVALID_ARG_TYPE';
        throw e;
      }
      if (typeof prevValue.system !== 'number') {
        const v = prevValue.system;
        const received = v == null ? ` Received ${v}` : typeof v === 'function' ? ` Received function ${(v as any).name}` : typeof v === 'object' ? (v.constructor && v.constructor.name ? ` Received an instance of ${v.constructor.name}` : ` Received ${String(v)}`) : ` Received type ${typeof v} (${String(v)})`;
        const e: any = new TypeError(`The "prevValue.system" property must be of type number.${received}`);
        e.code = 'ERR_INVALID_ARG_TYPE';
        throw e;
      }
      if (prevValue.user < 0 || !Number.isFinite(prevValue.user)) {
        const e: any = new RangeError(`The property 'prevValue.user' is invalid. Received ${prevValue.user}`);
        e.code = 'ERR_INVALID_ARG_VALUE';
        throw e;
      }
      if (prevValue.system < 0 || !Number.isFinite(prevValue.system)) {
        const e: any = new RangeError(`The property 'prevValue.system' is invalid. Received ${prevValue.system}`);
        e.code = 'ERR_INVALID_ARG_VALUE';
        throw e;
      }
    }
    return { user: 0, system: 0 };
  }

  /**
   * Emit a warning (async like Node.js).
   */
  emitWarning(warning: string | Error, type?: string | { type?: string; code?: string; detail?: string; ctor?: Function }, code?: string | Function, ctor?: Function): void {
    let detail: string | undefined;
    if (typeof type === 'object' && type !== null && !Array.isArray(type)) {
      code = type.code;
      ctor = type.ctor;
      detail = type.detail;
      type = type.type || 'Warning';
    }
    if (typeof code === 'function') { ctor = code; code = undefined; }
    if (typeof type === 'function') { ctor = type as unknown as Function; type = 'Warning'; code = undefined; }
    // Validate
    if (warning === undefined || (typeof warning !== 'string' && !(warning instanceof Error))) {
      const e: any = new TypeError(`The "warning" argument must be of type string or an instance of Error. Received ${warning === undefined ? 'undefined' : 'type ' + typeof warning}`);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (type !== undefined && typeof type !== 'string') {
      const e: any = new TypeError(`The "type" argument must be of type string. Received type ${typeof type}`);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (code !== undefined && typeof code !== 'string') {
      const e: any = new TypeError(`The "code" argument must be of type string. Received type ${typeof code}`);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    // Suppress deprecation warnings if noDeprecation is set
    if ((type === 'DeprecationWarning' || (typeof type === 'undefined' && typeof warning === 'string' && warning.startsWith('DEP'))) && this.noDeprecation) {
      return;
    }
    let warningObj: any;
    if (typeof warning === 'string') {
      warningObj = new Error(warning);
      warningObj.name = type || 'Warning';
    } else {
      warningObj = warning;
    }
    if (code) warningObj.code = code;
    if (type && warningObj.name !== type) warningObj.name = type;
    if (typeof detail === 'string') warningObj.detail = detail;
    // Node.js emits warnings asynchronously via nextTick
    this.nextTick(() => { this.emit('warning', warningObj); });
  }

  /**
   * Process features flags.
   * Matches Node.js process.features structure.
   */
  features = {
    inspector: false,
    debug: false,
    uv: true,
    ipv6: true,
    tls_alpn: false,
    tls_sni: false,
    tls_ocsp: false,
    tls: false,
    cached_builtins: true,
    // Node.js 21+ moved to a nested structure
    typescript: false,
    require_module: false,
  };

  debugPort = 9229;

  getActiveResourcesInfo(): string[] { return []; }
  _getActiveRequests(): any[] { return []; }
  _getActiveHandles(): any[] { return []; }

  resourceUsage(): Record<string, number> {
    return {
      userCPUTime: 0, systemCPUTime: 0, maxRSS: 0,
      sharedMemorySize: 0, unsharedDataSize: 0, unsharedStackSize: 0,
      minorPageFault: 0, majorPageFault: 0, swappedOut: 0,
      fsRead: 0, fsWrite: 0, ipcSent: 0, ipcReceived: 0,
      signalsCount: 0, voluntaryContextSwitches: 0, involuntaryContextSwitches: 0,
    };
  }

  _umask = 0o022;
  umask = (mask?: number | string): number => {
    if (mask === undefined) {
      return this._umask;
    }
    const old = this._umask;
    if (typeof mask !== 'string' && typeof mask !== 'number') {
      const v = mask as any;
      const received = v == null ? ` Received ${v}` : typeof v === 'function' ? ` Received function ${v.name}` : typeof v === 'object' ? (v.constructor && v.constructor.name ? ` Received an instance of ${v.constructor.name}` : ` Received ${String(v)}`) : ` Received type ${typeof v} (${String(v)})`;
      const e: any = new TypeError(`The "mask" argument must be one of type string or number.${received}`);
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (typeof mask === 'string') {
      if (!/^(0o?)?[0-7]+$/.test(mask)) {
        const e: any = new RangeError(`The property 'mask' is invalid. Received '${mask}'`);
        e.code = 'ERR_INVALID_ARG_VALUE';
        throw e;
      }
      // Strip "0o" or "0" prefix before parsing as octal
      const stripped = mask.replace(/^0o/i, '').replace(/^0+(?=\d)/, '');
      mask = parseInt(stripped || '0', 8);
    }
    if (typeof mask === 'number' && mask === (mask | 0)) this._umask = mask & 0o777;
    return old;
  };

  private _uncaughtCaptureCb: ((err: Error) => void) | null = null;
  setUncaughtExceptionCaptureCallback(fn: ((err: Error) => void) | null): void {
    if (fn !== null && typeof fn !== 'function') {
      const e: any = new TypeError('The "fn" argument must be of type function or null. Received type ' + typeof fn + ' (' + String(fn) + ')');
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    if (fn !== null && this._uncaughtCaptureCb !== null) {
      const e: any = new Error('process.setupUncaughtExceptionCapture() was called while a capture callback was already active');
      e.code = 'ERR_UNCAUGHT_EXCEPTION_CAPTURE_ALREADY_SET';
      throw e;
    }
    this._uncaughtCaptureCb = fn;
  }

  hasUncaughtExceptionCaptureCallback(): boolean {
    return this._uncaughtCaptureCb !== null;
  }

  report = {
    writeReport: () => '',
    getReport: () => ({}),
    directory: '',
    filename: '',
    compact: false,
    signal: 'SIGUSR2',
    reportOnFatalError: false,
    reportOnSignal: false,
    reportOnUncaughtException: false,
  };

  allowedNodeEnvironmentFlags: Set<string> = createAllowedNodeEnvironmentFlags();

  /**
   * Uptime in seconds.
   */
  uptime(): number {
    const timeOrigin = performance?.timeOrigin ?? Date.now();
    return (Date.now() - timeOrigin) / 1000;
  }

  /**
   * Standard streams (minimal implementation with EventEmitter support).
   */
  private _stdin: any;
  private _stdout: any;
  private _stderr: any;

  get stdin() {
    if (!this._stdin) {
      this._stdin = _makeProcessStream(0, false);
    }
    return this._stdin;
  }

  get stdout() {
    if (!this._stdout) {
      this._stdout = _makeProcessStream(1, false, (data: string | Uint8Array) => {
        // Use native write to avoid circular console.log -> stdout.write -> console.log loop
        const g = globalThis as any;
        // Ensure fs host functions are loaded (they're registered lazily)
        if (typeof g.__exactFsWrite !== 'function' && typeof g.__exactEnsureFs === 'function') {
          g.__exactEnsureFs();
        }
        if (typeof g.__exactFsWrite === 'function') {
          // Uint8Array chunks reach native as raw bytes (no UTF-8 round trip).
          g.__exactFsWrite(1, data, -1);
          return true;
        }
        // Fallback to console.log only if native write is unavailable
        console.log(_decodeStreamChunkForConsole(data));
        return true;
      });
    }
    return this._stdout;
  }

  get stderr() {
    if (!this._stderr) {
      this._stderr = _makeProcessStream(2, false, (data: string | Uint8Array) => {
        // Use native write to avoid circular console.error -> stderr.write -> console.error loop
        const g = globalThis as any;
        // Ensure fs host functions are loaded (they're registered lazily)
        if (typeof g.__exactFsWrite !== 'function' && typeof g.__exactEnsureFs === 'function') {
          g.__exactEnsureFs();
        }
        if (typeof g.__exactFsWrite === 'function') {
          // Uint8Array chunks reach native as raw bytes (no UTF-8 round trip).
          g.__exactFsWrite(2, data, -1);
          return true;
        }
        // Fallback to console.error only if native write is unavailable
        console.error(_decodeStreamChunkForConsole(data));
        return true;
      });
    }
    return this._stderr;
  }

  /**
   * Execution arguments (empty in mobile context).
   */
  get argv(): string[] {
    return getRuntimeArgv();
  }

  /**
   * Execution arguments including node path.
   */
  get argv0(): string {
    return getRuntimeArgv0();
  }

  /**
   * Executable path.
   */
  get execPath(): string {
    return (typeof globalThis !== 'undefined' && (globalThis as any).__exactExecPath) || '/usr/bin/ibex';
  }

  set execPath(path: string) {
    if (typeof path === 'string') {
      if (typeof globalThis !== 'undefined') {
        (globalThis as any).__exactExecPath = path;
      }
    }
  }

  /**
   * Node-specific execution arguments (empty).
   */
  get execArgv(): string[] {
    if (typeof globalThis !== 'undefined' && Array.isArray((globalThis as any).__exactExecArgv)) {
      return (globalThis as any).__exactExecArgv;
    }
    return [];
  }

  /**
   * Whether running in browser (always false).
   */
  get browser(): boolean {
    return false;
  }

  // Real event emitter storage
  private _events: Map<string, Array<{ fn: (...args: any[]) => void; once: boolean }>> = new Map();

  on(event: string, listener: (...args: any[]) => void): this {
    const listeners = this._events.get(event) || [];
    listeners.push({ fn: listener, once: false });
    this._events.set(event, listeners);
    if (event === 'uncaughtException') {
      this._hookUncaughtException();
    }
    if (event === 'unhandledRejection') {
      this._hookUnhandledRejection();
    }
    _syncSignalTrap(event);
    return this;
  }

  off(event: string, listener: (...args: any[]) => void): this {
    return this.removeListener(event, listener);
  }

  addListener(event: string, listener: (...args: any[]) => void): this {
    return this.on(event, listener);
  }

  once(event: string, listener: (...args: any[]) => void): this {
    const listeners = this._events.get(event) || [];
    listeners.push({ fn: listener, once: true });
    this._events.set(event, listeners);
    if (event === 'uncaughtException') {
      this._hookUncaughtException();
    }
    if (event === 'unhandledRejection') {
      this._hookUnhandledRejection();
    }
    _syncSignalTrap(event);
    return this;
  }

  prependListener(event: string, listener: (...args: any[]) => void): this {
    const listeners = this._events.get(event) || [];
    listeners.unshift({ fn: listener, once: false });
    this._events.set(event, listeners);
    _syncSignalTrap(event);
    return this;
  }

  prependOnceListener(event: string, listener: (...args: any[]) => void): this {
    const listeners = this._events.get(event) || [];
    listeners.unshift({ fn: listener, once: true });
    this._events.set(event, listeners);
    _syncSignalTrap(event);
    return this;
  }

  emit(event: string, ...args: any[]): boolean {
    const listeners = this._events.get(event);
    if (!listeners || listeners.length === 0) return false;
    // Prune once-listeners BEFORE invoking (Node semantics). Rewriting the
    // list only after the loop meant a throwing handler left already-run
    // once-entries registered, double-firing them on the next emit (e.g. a
    // throwing process.once('warning') handler). Iterating a snapshot also
    // keeps listeners added during the emit out of the current dispatch,
    // matching Node. (ENG-23140)
    const snapshot = listeners.slice();
    this._events.set(
      event,
      listeners.filter((entry) => !entry.once),
    );
    for (const entry of snapshot) {
      entry.fn(...args);
    }
    return true;
  }

  removeListener(event: string, listener: (...args: any[]) => void): this {
    const listeners = this._events.get(event);
    if (listeners) {
      this._events.set(event, listeners.filter(e => e.fn !== listener));
    }
    _syncSignalTrap(event);
    return this;
  }

  removeAllListeners(event?: string): this {
    if (event) {
      this._events.delete(event);
    } else {
      this._events.clear();
    }
    // No argument = every event was cleared; sync every trapped signal.
    _syncSignalTrap(event);
    return this;
  }

  listeners(event: string): Array<(...args: any[]) => void> {
    return (this._events.get(event) || []).map(e => e.fn);
  }

  rawListeners(event: string): Array<(...args: any[]) => void> {
    return this.listeners(event);
  }

  listenerCount(event: string): number {
    return (this._events.get(event) || []).length;
  }

  eventNames(): string[] {
    return Array.from(this._events.keys()).filter((event) => this.listenerCount(event) > 0);
  }

  setMaxListeners(count: number): this {
    this._maxListeners = count;
    return this;
  }

  getMaxListeners(): number {
    return this._maxListeners;
  }

  private _uncaughtExceptionHooked = false;
  private _hookUncaughtException(): void {
    if (this._uncaughtExceptionHooked) return;
    this._uncaughtExceptionHooked = true;
    const g = globalThis as any;
    const self = this;
    const prev = g.onerror;
    g.onerror = function(msg: any, _src: any, _line: any, _col: any, err: any) {
      const error = err instanceof Error ? err : new Error(String(msg));
      if (self.listenerCount('uncaughtException') > 0) {
        self.emit('uncaughtException', error);
        return true; // suppress default
      }
      if (typeof prev === 'function') return prev(msg, _src, _line, _col, err);
      return false;
    };
  }

  private _unhandledRejectionHooked = false;
  private _hookUnhandledRejection(): void {
    if (this._unhandledRejectionHooked) return;
    this._unhandledRejectionHooked = true;
    const g = globalThis as any;
    const self = this;
    const addFn = g.addEventListener;
    if (typeof addFn === 'function') {
      addFn.call(g, 'unhandledrejection', (event: any) => {
        if (self.listenerCount('unhandledRejection') > 0) {
          self.emit('unhandledRejection', event.reason, event.promise);
          event.preventDefault?.();
        }
      });
    }
  }

  get [Symbol.toStringTag](): string {
    return 'process';
  }
}

// Singleton process instance
_installTimeZoneAwareDateToString();
export const process = new Process();
const exitCodeDescriptor = Object.getOwnPropertyDescriptor(Process.prototype, 'exitCode');
if (exitCodeDescriptor?.get && exitCodeDescriptor?.set) {
  Object.defineProperty(process, 'exitCode', {
    get: exitCodeDescriptor.get.bind(process),
    set: exitCodeDescriptor.set.bind(process),
    enumerable: true,
    configurable: false,
  });
}

export default process;
function getRuntimeArgv(): string[] {
  if (typeof __exactArgv === 'object' && Array.isArray(__exactArgv) && __exactArgv.length > 0) {
    return __exactArgv;
  }
  return ['ibex'];
}

function getRuntimeArgv0(): string {
  const argv = getRuntimeArgv();
  return argv[0] ?? 'ibex';
}

function readNativeProcessId(reader: (() => number) | undefined, fallback: number): number {
  if (typeof reader !== 'function') {
    return fallback;
  }
  try {
    const value = reader();
    return typeof value === 'number' && Number.isInteger(value) ? value : fallback;
  } catch {
    return fallback;
  }
}

function formatReceivedValue(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') return `type string ('${value}')`;
  if (typeof value === 'bigint') return `type bigint (${value}n)`;
  if (typeof value === 'function') return `function ${(value as Function).name || '<anonymous>'}`;
  if (typeof value !== 'object') return `type ${typeof value} (${String(value)})`;
  const ctorName = (value as { constructor?: { name?: string } }).constructor?.name;
  return ctorName ? `an instance of ${ctorName}` : String(value);
}

function makeCredentialTypeError(value: unknown): TypeError & { code: string } {
  const err = new TypeError(
    `The "id" argument must be one of type number or string. Received ${formatReceivedValue(value)}`,
  ) as TypeError & { code: string };
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function makeUnknownCredentialError(kind: 'user' | 'group', value: string): Error & { code: string } {
  const err = new Error(
    `${kind === 'user' ? 'User' : 'Group'} identifier does not exist: ${value}`,
  ) as Error & { code: string };
  err.code = 'ERR_UNKNOWN_CREDENTIAL';
  return err;
}

function makeCredentialPermissionError(): Error & { code: string } {
  const err = new Error('EPERM, Operation not permitted') as Error & { code: string };
  err.code = 'EPERM';
  return err;
}

function resolveCredentialId(id: number | string, kind: 'user' | 'group'): number {
  if (typeof id === 'number') {
    if (!Number.isFinite(id) || !Number.isInteger(id)) {
      throw makeCredentialTypeError(id);
    }
    return Object.is(id, -0) ? 0 : id;
  }
  if (typeof id !== 'string') {
    throw makeCredentialTypeError(id);
  }
  const table = kind === 'user' ? USER_CREDENTIALS : GROUP_CREDENTIALS;
  if (Object.prototype.hasOwnProperty.call(table, id)) {
    return table[id];
  }
  const numeric = Number(id);
  if (id.length > 0 && Number.isFinite(numeric) && Number.isInteger(numeric)) {
    return Object.is(numeric, -0) ? 0 : numeric;
  }
  throw makeUnknownCredentialError(kind, id);
}

function makeInvalidPidError(value: unknown): TypeError & { code: string } {
  const err = new TypeError(
    `The "pid" argument must be of type number. Received ${formatReceivedValue(value)}`,
  ) as TypeError & { code: string };
  err.code = 'ERR_INVALID_ARG_TYPE';
  return err;
}

function normalizeProcessId(pid: number | string): number {
  if (typeof pid === 'string') {
    const numeric = Number(pid);
    if (!Number.isFinite(numeric) || !Number.isInteger(numeric)) {
      throw makeInvalidPidError(pid);
    }
    return Object.is(numeric, -0) ? 0 : numeric;
  }
  if (typeof pid !== 'number' || !Number.isFinite(pid) || !Number.isInteger(pid)) {
    throw makeInvalidPidError(pid);
  }
  return Object.is(pid, -0) ? 0 : pid;
}

function normalizeSignal(signal?: string | number): number {
  const signalMap = currentSignalNameToNumberMap();
  if (signal === undefined) {
    return signalMap.SIGTERM;
  }
  if (typeof signal === 'string') {
    if (signal === '0') {
      return 0;
    }
    const numeric = signalMap[signal];
    if (numeric === undefined) {
      const err = new TypeError(`Unknown signal: ${signal}`) as TypeError & { code: string };
      err.code = 'ERR_UNKNOWN_SIGNAL';
      throw err;
    }
    return numeric;
  }
  if (typeof signal !== 'number' || !Number.isFinite(signal) || !Number.isInteger(signal)) {
    const err = new Error('kill EINVAL') as Error & { code: string };
    err.code = 'EINVAL';
    throw err;
  }
  if (signal < 0 || signal > 31) {
    const err = new Error('kill EINVAL') as Error & { code: string };
    err.code = 'EINVAL';
    throw err;
  }
  return signal;
}

function inspectExecveValue(value: unknown): string {
  if (typeof value === 'string') {
    return `'${value.replace(/\0/g, '\\x00')}'`;
  }
  return String(value);
}

function validateExecveArguments(
  execPath: unknown,
  args: unknown,
  envObj: unknown,
  hasEnvArgument: boolean,
): void {
  if (typeof execPath !== 'string') {
    const err = new TypeError(
      `The "execPath" argument must be of type string. Received type ${typeof execPath} (${String(execPath)})`,
    ) as TypeError & { code: string };
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  if (!Array.isArray(args)) {
    const err = new TypeError(
      `The "args" argument must be an instance of Array. Received type ${typeof args} (${inspectExecveValue(args)})`,
    ) as TypeError & { code: string };
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (typeof value !== 'string' || value.includes('\0')) {
      const err = new TypeError(
        `The argument 'args[${index}]' must be a string without null bytes. Received ${inspectExecveValue(value)}`,
      ) as TypeError & { code: string };
      err.code = 'ERR_INVALID_ARG_VALUE';
      throw err;
    }
  }

  if (!hasEnvArgument) {
    return;
  }

  if (typeof envObj !== 'object' || envObj === null || Array.isArray(envObj)) {
    const err = new TypeError(
      `The "env" argument must be of type object. Received type ${typeof envObj} (${inspectExecveValue(envObj)})`,
    ) as TypeError & { code: string };
    err.code = 'ERR_INVALID_ARG_TYPE';
    throw err;
  }

  const entries = Object.keys(envObj as Record<string, unknown>);
  for (const key of entries) {
    const value = (envObj as Record<string, unknown>)[key];
    if (typeof value !== 'string' || value.includes('\0')) {
      const pairs = entries.map((entryKey) => `${entryKey}: ${inspectExecveValue((envObj as Record<string, unknown>)[entryKey])}`);
      const err = new TypeError(
        `The argument 'env' must be an object with string keys and values without null bytes. Received { ${pairs.join(', ')} }`,
      ) as TypeError & { code: string };
      err.code = 'ERR_INVALID_ARG_VALUE';
      throw err;
    }
  }
}

function isChildProcessPermissionDenied(execArgv: readonly string[]): boolean {
  let permissionMode = false;
  let allowChildProcess = false;

  for (const rawArg of execArgv) {
    const arg = String(rawArg);
    if (arg === '--permission' || arg.startsWith('--permission=')) {
      permissionMode = true;
      continue;
    }
    if (arg === '--allow-child-process' || arg.startsWith('--allow-child-process=')) {
      allowChildProcess = true;
    }
  }

  return permissionMode && !allowChildProcess;
}
