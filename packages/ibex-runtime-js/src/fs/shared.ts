// @ts-nocheck
import { join } from '../node/path';
import { Dirent } from './Dirent';
import { Stats } from './Stats';

declare global {
  var __exactReadFile: ((path: string) => Uint8Array) | undefined;
  var __exactWriteFile: ((path: string, data: Uint8Array) => void) | undefined;
  var __exactAppendFile: ((path: string, data: Uint8Array) => void) | undefined;
  var __exactStat: ((path: string) => string) | undefined;
  var __exactLstat: ((path: string) => string) | undefined;
  var __exactReaddir: ((path: string) => string) | undefined;
  var __exactMkdir: ((path: string, recursive: boolean) => void) | undefined;
  var __exactRmdir: ((path: string) => void) | undefined;
  var __exactUnlink: ((path: string) => void) | undefined;
  var __exactRename: ((from: string, to: string) => void) | undefined;
  var __exactCopyFile: ((from: string, to: string) => void) | undefined;
  var __exactAccess: ((path: string, mode: number) => void) | undefined;
  var __exactChmod: ((path: string, mode: number) => void) | undefined;
  var __exactRealpath: ((path: string) => string) | undefined;
  var __exactMkdtemp: ((prefix: string) => string) | undefined;
  var __exactFsOpen: ((path: string, flags: number, mode?: number) => number) | undefined;
  var __exactFsClose: ((fd: number) => void) | undefined;
  var __exactFsRead: ((fd: number, length: number, position: number) => Uint8Array) | undefined;
  var __exactFsWrite: ((fd: number, data: Uint8Array, position: number) => number) | undefined;
  var __exactEnsureFs: (() => void) | undefined;
  var __exactSymlink: ((target: string, path: string) => void) | undefined;
  var __exactLink: ((existingPath: string, newPath: string) => void) | undefined;
  var __exactReadlink: ((path: string) => string) | undefined;
  var __exactTruncate: ((path: string, len: number) => void) | undefined;
  var __exactUtimes: ((path: string, atime: number, mtime: number) => void) | undefined;
}

export type BinaryData = Uint8Array | Buffer;
export type FileData = string | BinaryData;
export type Callback<T = void> = (err: Error | null, result?: T) => void;
export type ReadCallback = (err: Error | null, bytesRead: number, buffer: Uint8Array) => void;
export type WriteCallback = (err: Error | null, bytesWritten: number, buffer: string | Uint8Array) => void;

const UTF8_ENCODINGS = new Set(['utf8', 'utf-8']);

export const constants = Object.freeze({
  F_OK: 0,
  R_OK: 4,
  W_OK: 2,
  X_OK: 1,
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  O_CREAT: 0x40,
  O_EXCL: 0x80,
  O_TRUNC: 0x200,
  O_APPEND: 0x400,
  O_DIRECTORY: 0x10000,
  O_NOFOLLOW: 0x20000,
  O_NONBLOCK: 0x800,
  COPYFILE_EXCL: 1,
  S_IFMT: 0o170000,
  S_IFREG: 0o100000,
  S_IFDIR: 0o040000,
  S_IFCHR: 0o020000,
  S_IFBLK: 0o060000,
  S_IFIFO: 0o010000,
  S_IFLNK: 0o120000,
  S_IFSOCK: 0o140000,
});

export function coerceError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

export function queueTask(task: () => void): void {
  if (typeof queueMicrotask === 'function') {
    queueMicrotask(task);
    return;
  }
  Promise.resolve().then(task);
}

export function wrapCallback<T>(fn: () => T, callback: Callback<T>): void {
  queueTask(() => {
    try {
      callback(null, fn());
    } catch (err) {
      callback(coerceError(err));
    }
  });
}

export function runAsync<T>(fn: () => T): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    queueTask(() => {
      try {
        resolve(fn());
      } catch (err) {
        reject(coerceError(err));
      }
    });
  });
}

export function wrapBuffer(bytes: Uint8Array): BinaryData {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.isBuffer(bytes)
      ? bytes
      : Buffer.from(bytes);
  }
  return bytes;
}

export function toUint8Array(data: FileData): Uint8Array {
  if (typeof data === 'string') {
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(data);
    }
    const buf = new Uint8Array(data.length * 3);
    let offset = 0;
    for (let i = 0; i < data.length; i++) {
      const code = data.charCodeAt(i);
      if (code < 0x80) {
        buf[offset++] = code;
      } else if (code < 0x800) {
        buf[offset++] = 0xc0 | (code >> 6);
        buf[offset++] = 0x80 | (code & 0x3f);
      } else {
        buf[offset++] = 0xe0 | (code >> 12);
        buf[offset++] = 0x80 | ((code >> 6) & 0x3f);
        buf[offset++] = 0x80 | (code & 0x3f);
      }
    }
    return buf.slice(0, offset);
  }
  if (data instanceof Uint8Array) {
    return data;
  }
  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

export function decodeBytes(bytes: Uint8Array, encoding: string): string {
  const normalized = UTF8_ENCODINGS.has(encoding.toLowerCase()) ? 'utf-8' : encoding;
  if (typeof TextDecoder !== 'undefined') {
    const decoded = new TextDecoder(normalized).decode(bytes);
    if (
      normalized === 'utf-8' &&
      bytes.length >= 3 &&
      bytes[0] === 0xef &&
      bytes[1] === 0xbb &&
      bytes[2] === 0xbf &&
      decoded.charCodeAt(0) !== 0xfeff
    ) {
      return `\uFEFF${decoded}`;
    }
    return decoded;
  }
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
}

function ensureFsPrimitive<T extends Function>(name: string): T {
  const globalRef = globalThis as any;
  let fn = globalRef[name];
  if (typeof fn !== 'function' && typeof globalRef.__exactEnsureFs === 'function') {
    globalRef.__exactEnsureFs();
    fn = globalRef[name];
  }
  if (typeof fn !== 'function') {
    throw new Error(`${name} is not available in this runtime`);
  }
  return fn as T;
}

export function readFileBytes(path: string): Uint8Array {
  return ensureFsPrimitive<(path: string) => Uint8Array>('__exactReadFile')(path);
}

export function writeFileBytes(path: string, bytes: Uint8Array): void {
  ensureFsPrimitive<(path: string, data: Uint8Array) => void>('__exactWriteFile')(path, bytes);
}

export function appendFileBytes(path: string, bytes: Uint8Array): void {
  ensureFsPrimitive<(path: string, data: Uint8Array) => void>('__exactAppendFile')(path, bytes);
}

export function statJson(path: string): string {
  return ensureFsPrimitive<(path: string) => string>('__exactStat')(path);
}

export function lstatJson(path: string): string {
  return ensureFsPrimitive<(path: string) => string>('__exactLstat')(path);
}

export function readdirJson(path: string): string {
  return ensureFsPrimitive<(path: string) => string>('__exactReaddir')(path);
}

export function mkdirNative(path: string, recursive: boolean): void {
  ensureFsPrimitive<(path: string, recursive: boolean) => void>('__exactMkdir')(path, recursive);
}

export function rmdirNative(path: string): void {
  ensureFsPrimitive<(path: string) => void>('__exactRmdir')(path);
}

export function unlinkNative(path: string): void {
  ensureFsPrimitive<(path: string) => void>('__exactUnlink')(path);
}

export function renameNative(from: string, to: string): void {
  ensureFsPrimitive<(from: string, to: string) => void>('__exactRename')(from, to);
}

export function copyFileNative(from: string, to: string): void {
  ensureFsPrimitive<(from: string, to: string) => void>('__exactCopyFile')(from, to);
}

export function accessNative(path: string, mode: number): void {
  ensureFsPrimitive<(path: string, mode: number) => void>('__exactAccess')(path, mode);
}

export function chmodNative(path: string, mode: number): void {
  ensureFsPrimitive<(path: string, mode: number) => void>('__exactChmod')(path, mode);
}

export function realpathNative(path: string): string {
  return ensureFsPrimitive<(path: string) => string>('__exactRealpath')(path);
}

export function mkdtempNative(prefix: string): string {
  return ensureFsPrimitive<(prefix: string) => string>('__exactMkdtemp')(prefix);
}

export function toStats(json: string): Stats {
  return new Stats(JSON.parse(json));
}

export function parseReaddir(path: string, withFileTypes = false): string[] | Dirent[] {
  const entries = JSON.parse(readdirJson(path)) as string[];
  if (!withFileTypes) {
    return entries;
  }
  return entries.map((name) => new Dirent(name, toStats(lstatJson(join(path, name)))));
}

export function parseOpenFlags(flags?: string | number): number {
  if (typeof flags === 'number') {
    return flags;
  }

  switch (flags ?? 'r') {
    case 'r':
      return constants.O_RDONLY;
    case 'r+':
      return constants.O_RDWR;
    case 'w':
      return constants.O_TRUNC | constants.O_CREAT | constants.O_WRONLY;
    case 'w+':
      return constants.O_TRUNC | constants.O_CREAT | constants.O_RDWR;
    case 'wx':
      return constants.O_TRUNC | constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY;
    case 'wx+':
      return constants.O_TRUNC | constants.O_CREAT | constants.O_EXCL | constants.O_RDWR;
    case 'a':
      return constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY;
    case 'a+':
      return constants.O_APPEND | constants.O_CREAT | constants.O_RDWR;
    case 'ax':
      return constants.O_APPEND | constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY;
    case 'ax+':
      return constants.O_APPEND | constants.O_CREAT | constants.O_EXCL | constants.O_RDWR;
    default:
      throw new Error(`Unsupported fs open flag: ${flags}`);
  }
}

function normalizePosition(position?: number | null): number {
  return position == null ? -1 : position;
}

export function openFileDescriptor(path: string, flags?: string | number, mode = 0o666): number {
  return ensureFsPrimitive<(path: string, flags: number, mode?: number) => number>('__exactFsOpen')(
    path,
    parseOpenFlags(flags),
    mode,
  );
}

export function closeFileDescriptor(fd: number): void {
  ensureFsPrimitive<(fd: number) => void>('__exactFsClose')(fd);
}

export function readFileDescriptor(fd: number, length: number, position?: number | null): Uint8Array {
  return ensureFsPrimitive<(fd: number, length: number, position: number) => Uint8Array>('__exactFsRead')(
    fd,
    length,
    normalizePosition(position),
  );
}

export function writeFileDescriptor(fd: number, data: Uint8Array, position?: number | null): number {
  return ensureFsPrimitive<(fd: number, data: Uint8Array, position: number) => number>('__exactFsWrite')(
    fd,
    data,
    normalizePosition(position),
  );
}

export function symlinkNative(target: string, path: string): void {
  ensureFsPrimitive<(target: string, path: string) => void>('__exactSymlink')(target, path);
}

export function linkNative(existingPath: string, newPath: string): void {
  ensureFsPrimitive<(existingPath: string, newPath: string) => void>('__exactLink')(existingPath, newPath);
}

export function readlinkNative(path: string): string {
  return ensureFsPrimitive<(path: string) => string>('__exactReadlink')(path);
}

export function truncateNative(path: string, len: number): void {
  ensureFsPrimitive<(path: string, len: number) => void>('__exactTruncate')(path, len);
}

export function utimesNative(path: string, atime: number, mtime: number): void {
  ensureFsPrimitive<(path: string, atime: number, mtime: number) => void>('__exactUtimes')(path, atime, mtime);
}
