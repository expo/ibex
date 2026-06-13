/**
 * Node.js-compatible fs/promises API.
 *
 * Built on the __exact* globals provided by the C++ Hermes bridge.
 */

import { join } from '../node/path';
import { Dirent } from './Dirent';
import { Stats } from './Stats';
import {
  accessNative,
  appendFileBytes,
  chmodNative,
  closeFileDescriptor,
  constants,
  copyFileNative,
  decodeBytes,
  mkdtempNative,
  mkdirNative,
  openFileDescriptor,
  parseReaddir,
  readFileBytes,
  readFileDescriptor,
  realpathNative,
  renameNative,
  rmdirNative,
  runAsync,
  statJson,
  toStats,
  toUint8Array,
  type FileData,
  unlinkNative,
  wrapBuffer,
  writeFileBytes,
  writeFileDescriptor,
  lstatJson,
  symlinkNative,
  linkNative,
  readlinkNative,
  truncateNative,
  utimesNative,
} from './shared';

export { Dirent, Stats, constants };

const VALID_SYMLINK_TYPES = new Set(['dir', 'file', 'junction']);

function describeArgValue(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (value === undefined) {
    return 'undefined';
  }
  if (Array.isArray(value)) {
    return 'an instance of Array';
  }
  if (typeof value === 'function') {
    return value.name ? `function ${value.name}` : 'function';
  }
  if (typeof value === 'object') {
    const ctorName = (value as { constructor?: { name?: string } }).constructor?.name ?? 'Object';
    return `an instance of ${ctorName}`;
  }
  if (typeof value === 'string') {
    return `type string (${value})`;
  }
  if (typeof value === 'number') {
    return `type number (${value})`;
  }
  if (typeof value === 'boolean') {
    return `type boolean (${value})`;
  }
  if (typeof value === 'symbol') {
    return `type symbol (${String(value)})`;
  }
  return `type ${typeof value}`;
}

function assignErrorCode<T extends Error>(error: T, code: string): T {
  (error as T & { code: string }).code = code;
  return error;
}

function makeInvalidArgTypeError(name: string, value: unknown): TypeError {
  return assignErrorCode(
    new TypeError(
      `The "${name}" argument must be of type string or an instance of Buffer or URL. Received ${describeArgValue(value)}`,
    ),
    'ERR_INVALID_ARG_TYPE',
  );
}

function makeInvalidArgValueError(name: string, value: unknown, reason: string): TypeError {
  let received: string;
  if (typeof value === 'string') {
    received = `'${value}'`;
  } else if (value === undefined) {
    received = 'undefined';
  } else if (value === null) {
    received = 'null';
  } else {
    received = String(value);
  }
  return assignErrorCode(
    new TypeError(`The argument "${name}" must be ${reason}. Received ${received}`),
    'ERR_INVALID_ARG_VALUE',
  );
}

function makeInvalidUrlSchemeError(): TypeError {
  return assignErrorCode(new TypeError('The URL must be of scheme file'), 'ERR_INVALID_URL_SCHEME');
}

function arrayBufferViewToString(view: ArrayBufferView): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString();
  }
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder().decode(bytes);
  }
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

function toPathString(value: unknown, name: string): string {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
    return value.toString();
  }
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(value)) {
    return arrayBufferViewToString(value);
  }
  if (value && typeof value === 'object' && typeof (value as { href?: unknown }).href === 'string') {
    const url = value as { protocol?: unknown; pathname?: unknown };
    if (url.protocol !== 'file:') {
      throw makeInvalidUrlSchemeError();
    }
    let pathname = typeof url.pathname === 'string' ? url.pathname : '';
    if (
      pathname.length >= 3 &&
      pathname[0] === '/' &&
      pathname[2] === ':' &&
      /[A-Za-z]/.test(pathname[1])
    ) {
      pathname = pathname.slice(1);
    }
    return decodeURIComponent(pathname);
  }
  throw makeInvalidArgTypeError(name, value);
}

function validateSymlinkType(type: unknown): void {
  if (type === undefined) {
    return;
  }
  if (typeof type !== 'string' || !VALID_SYMLINK_TYPES.has(type)) {
    throw makeInvalidArgValueError('type', type, "one of: 'dir', 'file', 'junction', or undefined");
  }
}

function normalizeUtimesValue(value: number | Date | string): number {
  if (value instanceof Date) {
    return value.getTime() / 1000;
  }
  if (typeof value === 'string') {
    return Number(value);
  }
  return value;
}

function normalizeRmError<T>(error: T, path?: string, recursive = false): T {
  if (!error || typeof error !== 'object') {
    return error;
  }
  const fsError = error as { syscall?: string; message?: string; code?: string; path?: string };
  if (fsError.syscall === 'rmdir' || fsError.syscall === 'unlink') {
    fsError.syscall = 'rm';
    if (typeof fsError.message === 'string') {
      fsError.message = fsError.message.replace(/, (?:rmdir|unlink) /, ', rm ');
    }
  }
  if (
    recursive &&
    typeof process !== 'undefined' &&
    process.platform === 'darwin' &&
    fsError.code === 'EACCES'
  ) {
    fsError.code = 'ENOTEMPTY';
    fsError.path = path ?? fsError.path;
    if (path) {
      fsError.message = `ENOTEMPTY: directory not empty, rm '${path}'`;
    }
  }
  return error;
}

function rmSyncLike(path: string, options?: { recursive?: boolean; force?: boolean }): void {
  const recursive = options?.recursive === true;
  const force = options?.force === true;

  try {
    const info = toStats(lstatJson(path));
    if (info.isDirectory()) {
      if (recursive) {
        const entries = parseReaddir(path, false) as string[];
        for (const entry of entries) {
          rmSyncLike(join(path, entry), options);
        }
      }
      try {
        rmdirNative(path);
      } catch (error) {
        throw normalizeRmError(error, path, recursive);
      }
    } else {
      try {
        unlinkNative(path);
      } catch (error) {
        throw normalizeRmError(error, path, recursive);
      }
    }
  } catch (error) {
    const normalizedError = normalizeRmError(error, path, recursive);
    if (
      force &&
      normalizedError &&
      typeof normalizedError === 'object' &&
      (normalizedError as { code?: string }).code === 'ENOENT'
    ) {
      return;
    }
    throw normalizedError;
  }
}

export async function readFile(path: string, options?: { encoding?: string } | string): Promise<Uint8Array | Buffer | string> {
  return runAsync(() => {
    const encoding = typeof options === 'string' ? options : options?.encoding;
    const bytes = readFileBytes(path);
    return encoding ? decodeBytes(bytes, encoding) : wrapBuffer(bytes);
  });
}

export async function writeFile(path: string, data: FileData, _options?: { encoding?: string } | string): Promise<void> {
  return runAsync(() => {
    writeFileBytes(path, toUint8Array(data));
  });
}

export async function appendFile(path: string, data: FileData, _options?: { encoding?: string } | string): Promise<void> {
  return runAsync(() => {
    appendFileBytes(path, toUint8Array(data));
  });
}

export async function stat(path: string): Promise<Stats> {
  return runAsync(() => toStats(statJson(path)));
}

export async function lstat(path: string): Promise<Stats> {
  return runAsync(() => toStats(lstatJson(path)));
}

export async function readdir(path: string, options?: { withFileTypes?: boolean }): Promise<string[] | Dirent[]> {
  return runAsync(() => parseReaddir(path, options?.withFileTypes) as string[] | Dirent[]);
}

export async function mkdir(path: string, options?: { recursive?: boolean } | number): Promise<void> {
  return runAsync(() => {
    const recursive = typeof options === 'object' && options !== null ? !!options.recursive : false;
    mkdirNative(path, recursive);
  });
}

export async function rmdir(path: string): Promise<void> {
  return runAsync(() => rmdirNative(path));
}

export async function rm(path: string, options?: { recursive?: boolean; force?: boolean }): Promise<void> {
  const targetPath = toPathString(path, 'path');
  return runAsync(() => {
    rmSyncLike(targetPath, options);
  });
}

export async function unlink(path: string): Promise<void> {
  return runAsync(() => unlinkNative(path));
}

export async function rename(oldPath: string, newPath: string): Promise<void> {
  return runAsync(() => renameNative(oldPath, newPath));
}

export async function copyFile(src: string, dest: string): Promise<void> {
  return runAsync(() => copyFileNative(src, dest));
}

export async function access(path: string, mode?: number): Promise<void> {
  return runAsync(() => accessNative(path, mode ?? constants.F_OK));
}

export async function chmod(path: string, mode: number): Promise<void> {
  return runAsync(() => chmodNative(path, mode));
}

export async function realpath(path: string): Promise<string> {
  return runAsync(() => realpathNative(path));
}

export async function mkdtemp(prefix: string): Promise<string> {
  return runAsync(() => mkdtempNative(prefix));
}

export async function open(path: string, flags?: string | number, mode?: number): Promise<number> {
  return runAsync(() => openFileDescriptor(path, flags, mode));
}

export async function close(fd: number): Promise<void> {
  return runAsync(() => closeFileDescriptor(fd));
}

export async function read(fd: number, buffer: Uint8Array, offset = 0, length = buffer.byteLength - offset, position?: number | null): Promise<{ bytesRead: number; buffer: Uint8Array }> {
  return runAsync(() => {
    const chunk = readFileDescriptor(fd, length, position);
    buffer.set(chunk, offset);
    return { bytesRead: chunk.byteLength, buffer };
  });
}

export async function write(
  fd: number,
  buffer: string | Uint8Array,
  offsetOrPosition = 0,
  lengthOrEncoding?: number | string,
  position?: number | null,
): Promise<{ bytesWritten: number; buffer: string | Uint8Array }> {
  return runAsync(() => {
    if (typeof buffer === 'string') {
      const writePosition = typeof offsetOrPosition === 'number' ? offsetOrPosition : position;
      return {
        bytesWritten: writeFileDescriptor(fd, toUint8Array(buffer), writePosition),
        buffer,
      };
    }

    const offset = offsetOrPosition;
    const length = typeof lengthOrEncoding === 'number' ? lengthOrEncoding : buffer.byteLength - offset;
    return {
      bytesWritten: writeFileDescriptor(fd, buffer.subarray(offset, offset + length), position),
      buffer,
    };
  });
}

export async function symlink(target: string, path: string, type?: string): Promise<void> {
  const targetPath = toPathString(target, 'target');
  const linkPath = toPathString(path, 'path');
  validateSymlinkType(type);
  return runAsync(() => symlinkNative(targetPath, linkPath));
}

export async function readlink(path: string): Promise<string> {
  return runAsync(() => readlinkNative(path));
}

export async function link(existingPath: string, newPath: string): Promise<void> {
  return runAsync(() => linkNative(existingPath, newPath));
}

export async function truncate(path: string, len = 0): Promise<void> {
  return runAsync(() => truncateNative(path, len));
}

export async function utimes(path: string, atime: number | Date, mtime: number | Date): Promise<void> {
  const targetPath = toPathString(path, 'path');
  return runAsync(() => {
    utimesNative(targetPath, normalizeUtimesValue(atime), normalizeUtimesValue(mtime));
  });
}
