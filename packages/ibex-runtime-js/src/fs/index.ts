/**
 * Node.js-compatible fs module.
 *
 * Provides callback-based and sync variants of filesystem operations.
 * Built on the __exact* globals provided by the C++ Hermes bridge.
 */

import { join } from '../node/path';
import { Dirent } from './Dirent';
import { Stats } from './Stats';
import * as promises from './promises';
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
  queueTask,
  readFileBytes,
  readFileDescriptor,
  realpathNative,
  renameNative,
  rmdirNative,
  statJson,
  toStats,
  toUint8Array,
  type Callback,
  type FileData,
  type ReadCallback,
  type WriteCallback,
  unlinkNative,
  wrapBuffer,
  wrapCallback,
  writeFileBytes,
  writeFileDescriptor,
  lstatJson,
  symlinkNative,
  linkNative,
  readlinkNative,
  truncateNative,
  utimesNative,
  fstatJson,
  ftruncateFd,
  fchmodFd,
} from './shared';

export { Dirent, Stats, promises, constants };

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

class EventEmitter {
  private listeners: Record<string, Array<{ fn: (...args: any[]) => void; once: boolean }>> = {};

  on(event: string, listener: (...args: any[]) => void): this {
    (this.listeners[event] ??= []).push({ fn: listener, once: false });
    return this;
  }

  addListener(event: string, listener: (...args: any[]) => void): this {
    return this.on(event, listener);
  }

  once(event: string, listener: (...args: any[]) => void): this {
    (this.listeners[event] ??= []).push({ fn: listener, once: true });
    return this;
  }

  emit(event: string, ...args: any[]): boolean {
    const listeners = this.listeners[event];
    if (!listeners || listeners.length === 0) {
      return false;
    }
    this.listeners[event] = listeners.filter((entry) => {
      entry.fn(...args);
      return !entry.once;
    });
    return true;
  }

  removeListener(event: string, listener: (...args: any[]) => void): this {
    this.listeners[event] = (this.listeners[event] ?? []).filter((entry) => entry.fn !== listener);
    return this;
  }
}

class ReadStream extends EventEmitter {
  readonly path: string;
  readonly flags: string | number;
  readonly highWaterMark: number;
  readonly encoding?: string;
  readonly autoClose: boolean;
  private fd: number | null;
  private cursor: number;
  private readonly end: number | null;
  destroyed = false;

  constructor(path: string, options: { flags?: string | number; encoding?: string; fd?: number; autoClose?: boolean; highWaterMark?: number; start?: number; end?: number } = {}) {
    super();
    this.path = path;
    this.flags = options.flags ?? 'r';
    this.encoding = options.encoding;
    this.fd = options.fd ?? null;
    this.autoClose = options.autoClose ?? true;
    this.highWaterMark = options.highWaterMark ?? 64 * 1024;
    this.cursor = options.start ?? 0;
    this.end = options.end ?? null;

    queueTask(() => this.startReading());
  }

  pipe(destination: { write: (chunk: any) => any; end?: () => void; emit?: (...args: any[]) => void; destroy?: (err?: unknown) => void }): typeof destination {
    this.on('data', (chunk) => {
      destination.write(chunk);
    });
    this.once('end', () => {
      destination.end?.();
    });
    this.once('error', (error) => {
      if (typeof destination.emit === 'function') {
        destination.emit('error', error);
      } else {
        destination.destroy?.(error);
      }
    });
    return destination;
  }

  destroy(error?: unknown): this {
    if (this.destroyed) {
      return this;
    }
    this.destroyed = true;
    if (this.autoClose && this.fd !== null) {
      try {
        closeFileDescriptor(this.fd);
      } catch {}
      this.fd = null;
    }
    if (error !== undefined) {
      this.emit('error', error);
    }
    this.emit('close');
    return this;
  }

  private startReading(): void {
    if (this.destroyed) {
      return;
    }

    try {
      if (this.fd === null) {
        this.fd = openFileDescriptor(this.path, this.flags);
        this.emit('open', this.fd);
      }

      while (!this.destroyed) {
        let length = this.highWaterMark;
        if (this.end !== null) {
          const remaining = this.end - this.cursor + 1;
          if (remaining <= 0) {
            break;
          }
          length = Math.min(length, remaining);
        }

        const chunk = readFileDescriptor(this.fd, length, this.cursor);
        if (chunk.byteLength === 0) {
          break;
        }
        this.cursor += chunk.byteLength;
        this.emit('data', this.encoding ? decodeBytes(chunk, this.encoding) : wrapBuffer(chunk));
      }

      if (!this.destroyed) {
        this.emit('end');
      }
      this.destroy();
    } catch (error) {
      this.destroy(error);
    }
  }
}

class WriteStream extends EventEmitter {
  readonly path: string;
  readonly flags: string | number;
  readonly autoClose: boolean;
  private fd: number | null;
  private cursor: number | null;
  destroyed = false;

  constructor(path: string, options: { flags?: string | number; fd?: number; autoClose?: boolean; start?: number } = {}) {
    super();
    this.path = path;
    this.flags = options.flags ?? 'w';
    this.fd = options.fd ?? null;
    this.autoClose = options.autoClose ?? true;
    this.cursor = options.start ?? null;

    queueTask(() => {
      // If the stream was destroyed before this deferred open ran, do not open
      // the file: with flag 'w' that would truncate/create the target after
      // destruction, emit 'open' after 'close', and leak the never-closed fd.
      // (ENG-22975)
      if (this.destroyed) {
        return;
      }
      try {
        if (this.fd === null) {
          this.fd = openFileDescriptor(this.path, this.flags);
        }
        this.emit('open', this.fd);
      } catch (error) {
        this.destroy(error);
      }
    });
  }

  write(chunk: FileData, callback?: (err?: Error | null) => void): boolean {
    if (this.destroyed) {
      callback?.(new Error('WriteStream is destroyed'));
      return false;
    }

    try {
      if (this.fd === null) {
        this.fd = openFileDescriptor(this.path, this.flags);
        this.emit('open', this.fd);
      }
      const bytes = toUint8Array(chunk);
      const written = writeFileDescriptor(this.fd, bytes, this.cursor);
      if (this.cursor !== null) {
        this.cursor += written;
      }
      callback?.(null);
      this.emit('drain');
      return true;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      callback?.(err);
      this.destroy(err);
      return false;
    }
  }

  end(chunk?: FileData, callback?: () => void): this {
    if (chunk !== undefined) {
      this.write(chunk);
    }
    if (this.autoClose && this.fd !== null) {
      closeFileDescriptor(this.fd);
      this.fd = null;
    }
    this.emit('finish');
    this.emit('close');
    callback?.();
    this.destroyed = true;
    return this;
  }

  destroy(error?: unknown): this {
    if (this.destroyed) {
      return this;
    }
    this.destroyed = true;
    if (this.autoClose && this.fd !== null) {
      try {
        closeFileDescriptor(this.fd);
      } catch {}
      this.fd = null;
    }
    if (error !== undefined) {
      this.emit('error', error);
    }
    this.emit('close');
    return this;
  }
}

export function readFileSync(path: string, options?: { encoding?: string } | string): Uint8Array | Buffer | string {
  const encoding = typeof options === 'string' ? options : options?.encoding;
  const bytes = readFileBytes(path);
  return encoding ? decodeBytes(bytes, encoding) : wrapBuffer(bytes);
}

export function writeFileSync(path: string, data: FileData, _options?: { encoding?: string } | string): void {
  writeFileBytes(path, toUint8Array(data));
}

export function appendFileSync(path: string, data: FileData, _options?: { encoding?: string } | string): void {
  appendFileBytes(path, toUint8Array(data));
}

export function statSync(path: string): Stats {
  return toStats(statJson(path));
}

export function lstatSync(path: string): Stats {
  return toStats(lstatJson(path));
}

export function readdirSync(path: string, options?: { withFileTypes?: boolean }): string[] | Dirent[] {
  return parseReaddir(path, options?.withFileTypes) as string[] | Dirent[];
}

export function mkdirSync(path: string, options?: { recursive?: boolean } | number): void {
  const recursive = typeof options === 'object' && options !== null ? !!options.recursive : false;
  mkdirNative(path, recursive);
}

export function rmdirSync(path: string): void {
  rmdirNative(path);
}

export function unlinkSync(path: string): void {
  unlinkNative(path);
}

export function renameSync(oldPath: string, newPath: string): void {
  renameNative(oldPath, newPath);
}

export function copyFileSync(src: string, dest: string): void {
  copyFileNative(src, dest);
}

export function accessSync(path: string, mode?: number): void {
  accessNative(path, mode ?? constants.F_OK);
}

export function chmodSync(path: string, mode: number): void {
  chmodNative(path, mode);
}

export function realpathSync(path: string): string {
  return realpathNative(path);
}

export function mkdtempSync(prefix: string): string {
  return mkdtempNative(prefix);
}

export function existsSync(path: string): boolean {
  try {
    accessSync(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export function openSync(path: string, flags?: string | number, mode?: number): number {
  return openFileDescriptor(path, flags, mode);
}

export function closeSync(fd: number): void {
  closeFileDescriptor(fd);
}

export function readSync(fd: number, buffer: Uint8Array, offset = 0, length = buffer.byteLength - offset, position?: number | null): number {
  const chunk = readFileDescriptor(fd, length, position);
  buffer.set(chunk.subarray(0, chunk.byteLength), offset);
  return chunk.byteLength;
}

export function writeSync(
  fd: number,
  buffer: FileData,
  offsetOrPosition?: number,
  lengthOrEncoding?: number | string,
  position?: number | null,
): number {
  if (typeof buffer === 'string') {
    const encoded = toUint8Array(buffer);
    const writePosition = typeof offsetOrPosition === 'number' ? offsetOrPosition : position;
    return writeFileDescriptor(fd, encoded, writePosition);
  }

  const offset = typeof offsetOrPosition === 'number' ? offsetOrPosition : 0;
  const length = typeof lengthOrEncoding === 'number' ? lengthOrEncoding : buffer.byteLength - offset;
  const slice = buffer.subarray(offset, offset + length);
  return writeFileDescriptor(fd, slice, position);
}

export function createReadStream(path: string, options?: ConstructorParameters<typeof ReadStream>[1]): ReadStream {
  return new ReadStream(path, options);
}

export function createWriteStream(path: string, options?: ConstructorParameters<typeof WriteStream>[1]): WriteStream {
  return new WriteStream(path, options);
}

export function readFile(
  path: string,
  optionsOrCallback: { encoding?: string } | string | Callback<Uint8Array | Buffer | string>,
  callback?: Callback<Uint8Array | Buffer | string>,
): void {
  let options: { encoding?: string } | string | undefined;
  let cb: Callback<Uint8Array | Buffer | string>;
  if (typeof optionsOrCallback === 'function') {
    cb = optionsOrCallback;
  } else {
    options = optionsOrCallback;
    cb = callback!;
  }
  wrapCallback(() => readFileSync(path, options), cb);
}

export function writeFile(
  path: string,
  data: FileData,
  optionsOrCallback: { encoding?: string } | string | Callback,
  callback?: Callback,
): void {
  let options: { encoding?: string } | string | undefined;
  let cb: Callback;
  if (typeof optionsOrCallback === 'function') {
    cb = optionsOrCallback;
  } else {
    options = optionsOrCallback;
    cb = callback!;
  }
  wrapCallback(() => writeFileSync(path, data, options), cb);
}

export function appendFile(
  path: string,
  data: FileData,
  optionsOrCallback: { encoding?: string } | string | Callback,
  callback?: Callback,
): void {
  let options: { encoding?: string } | string | undefined;
  let cb: Callback;
  if (typeof optionsOrCallback === 'function') {
    cb = optionsOrCallback;
  } else {
    options = optionsOrCallback;
    cb = callback!;
  }
  wrapCallback(() => appendFileSync(path, data, options), cb);
}

export function stat(path: string, callback: Callback<Stats>): void {
  wrapCallback(() => statSync(path), callback);
}

export function lstat(path: string, callback: Callback<Stats>): void {
  wrapCallback(() => lstatSync(path), callback);
}

export function readdir(
  path: string,
  optionsOrCallback: { withFileTypes?: boolean } | Callback<string[] | Dirent[]>,
  callback?: Callback<string[] | Dirent[]>,
): void {
  let options: { withFileTypes?: boolean } | undefined;
  let cb: Callback<string[] | Dirent[]>;
  if (typeof optionsOrCallback === 'function') {
    cb = optionsOrCallback;
  } else {
    options = optionsOrCallback;
    cb = callback!;
  }
  wrapCallback(() => readdirSync(path, options), cb);
}

export function mkdir(path: string, optionsOrCallback: { recursive?: boolean } | number | Callback, callback?: Callback): void {
  let options: { recursive?: boolean } | number | undefined;
  let cb: Callback;
  if (typeof optionsOrCallback === 'function') {
    cb = optionsOrCallback;
  } else {
    options = optionsOrCallback;
    cb = callback!;
  }
  wrapCallback(() => mkdirSync(path, options), cb);
}

export function rmdir(path: string, callback: Callback): void {
  wrapCallback(() => rmdirSync(path), callback);
}

export function unlink(path: string, callback: Callback): void {
  wrapCallback(() => unlinkSync(path), callback);
}

export function rename(oldPath: string, newPath: string, callback: Callback): void {
  wrapCallback(() => renameSync(oldPath, newPath), callback);
}

export function copyFile(src: string, dest: string, callback: Callback): void {
  wrapCallback(() => copyFileSync(src, dest), callback);
}

export function access(path: string, modeOrCallback: number | Callback, callback?: Callback): void {
  let mode: number | undefined;
  let cb: Callback;
  if (typeof modeOrCallback === 'function') {
    cb = modeOrCallback;
  } else {
    mode = modeOrCallback;
    cb = callback!;
  }
  wrapCallback(() => accessSync(path, mode), cb);
}

export function chmod(path: string, mode: number, callback: Callback): void {
  wrapCallback(() => chmodSync(path, mode), callback);
}

export function realpath(path: string, callback: Callback<string>): void {
  wrapCallback(() => realpathSync(path), callback);
}

export function mkdtemp(prefix: string, callback: Callback<string>): void {
  wrapCallback(() => mkdtempSync(prefix), callback);
}

export function exists(path: string, callback: (exists: boolean) => void): void {
  queueTask(() => callback(existsSync(path)));
}

export function open(
  path: string,
  flagsOrCallback?: string | number | Callback<number>,
  modeOrCallback?: number | Callback<number>,
  callback?: Callback<number>,
): void {
  let flags: string | number | undefined;
  let mode: number | undefined;
  let cb: Callback<number>;

  if (typeof flagsOrCallback === 'function') {
    cb = flagsOrCallback;
  } else if (typeof modeOrCallback === 'function') {
    flags = flagsOrCallback;
    cb = modeOrCallback;
  } else {
    flags = flagsOrCallback;
    mode = modeOrCallback;
    cb = callback!;
  }

  wrapCallback(() => openSync(path, flags, mode), cb);
}

export function close(fd: number, callback: Callback): void {
  wrapCallback(() => closeSync(fd), callback);
}

export function read(
  fd: number,
  buffer: Uint8Array,
  offset: number,
  length: number,
  position: number | null,
  callback: ReadCallback,
): void {
  queueTask(() => {
    // Run only the read inside the try; invoke the success callback afterwards
    // so a throwing user callback is not re-invoked with an error. (ENG-22975)
    let bytesRead: number;
    try {
      bytesRead = readSync(fd, buffer, offset, length, position);
    } catch (error) {
      callback(error instanceof Error ? error : new Error(String(error)), 0, buffer);
      return;
    }
    callback(null, bytesRead, buffer);
  });
}

export function write(
  fd: number,
  buffer: string | Uint8Array,
  a?: number | string | WriteCallback | null,
  b?: number | string | WriteCallback | null,
  c?: number | null | WriteCallback,
  d?: WriteCallback,
): void {
  // Node exposes two overloads, both with the callback as the LAST argument:
  //   Buffer: fs.write(fd, buffer[, offset[, length[, position]]], callback)
  //   String: fs.write(fd, string[, position[, encoding]], callback)
  // Parse accordingly. Crucially, when the position is omitted it stays
  // undefined (→ write at the fd's current position), not 0 (absolute offset 0,
  // which would clobber earlier writes), and the callback is located wherever it
  // actually sits rather than being read only from the last slot. (ENG-22975)
  let cb: WriteCallback | undefined;
  let offsetOrPosition: number | undefined;
  let lengthOrEncoding: number | string | undefined;
  let position: number | null | undefined;

  if (typeof buffer === 'string') {
    // fs.write(fd, string[, position[, encoding]], callback)
    if (typeof a === 'function') {
      cb = a;
    } else if (typeof b === 'function') {
      offsetOrPosition = a == null ? undefined : (a as number);
      cb = b;
    } else {
      offsetOrPosition = a == null ? undefined : (a as number);
      lengthOrEncoding = (b ?? undefined) as string | undefined;
      cb = c as WriteCallback | undefined;
    }
  } else {
    // fs.write(fd, buffer[, offset[, length[, position]]], callback)
    if (typeof a === 'function') {
      cb = a;
    } else if (typeof b === 'function') {
      offsetOrPosition = a as number;
      cb = b;
    } else if (typeof c === 'function') {
      offsetOrPosition = a as number;
      lengthOrEncoding = b as number;
      cb = c;
    } else {
      offsetOrPosition = a as number;
      lengthOrEncoding = b as number;
      position = c as number | null;
      cb = d;
    }
  }

  if (typeof cb !== 'function') {
    throw assignErrorCode(
      new TypeError(`The "cb" argument must be of type function. Received ${describeArgValue(cb)}`),
      'ERR_INVALID_ARG_TYPE',
    );
  }

  const callback = cb;
  queueTask(() => {
    // Run only the write inside the try; invoke the success callback afterwards
    // so a throwing user callback is not re-invoked with an error. (ENG-22975)
    let bytesWritten: number;
    try {
      bytesWritten = writeSync(fd, buffer, offsetOrPosition, lengthOrEncoding, position);
    } catch (error) {
      callback(error instanceof Error ? error : new Error(String(error)), 0, buffer);
      return;
    }
    callback(null, bytesWritten, buffer);
  });
}

// --- symlink ---

export function symlinkSync(target: string, path: string, type?: string): void {
  const targetPath = toPathString(target, 'target');
  const linkPath = toPathString(path, 'path');
  validateSymlinkType(type);
  symlinkNative(targetPath, linkPath);
}

export function symlink(target: string, path: string, typeOrCallback: string | Callback, callback?: Callback): void {
  const type = typeof typeOrCallback === 'function' ? undefined : typeOrCallback;
  toPathString(target, 'target');
  toPathString(path, 'path');
  validateSymlinkType(type);
  const cb = typeof typeOrCallback === 'function' ? typeOrCallback : callback!;
  wrapCallback(() => symlinkSync(target, path, type), cb);
}

// --- readlink ---

export function readlinkSync(path: string): string {
  return readlinkNative(path);
}

export function readlink(path: string, callback: Callback<string>): void {
  wrapCallback(() => readlinkSync(path), callback);
}

// --- link ---

export function linkSync(existingPath: string, newPath: string): void {
  linkNative(existingPath, newPath);
}

export function link(existingPath: string, newPath: string, callback: Callback): void {
  wrapCallback(() => linkSync(existingPath, newPath), callback);
}

// --- truncate ---

export function truncateSync(path: string, len = 0): void {
  truncateNative(path, len);
}

export function truncate(path: string, lenOrCallback: number | Callback, callback?: Callback): void {
  let len: number;
  let cb: Callback;
  if (typeof lenOrCallback === 'function') {
    len = 0;
    cb = lenOrCallback;
  } else {
    len = lenOrCallback;
    cb = callback!;
  }
  wrapCallback(() => truncateSync(path, len), cb);
}

// --- ftruncate ---

export function ftruncateSync(fd: number, len = 0): void {
  // Truncate by fd via the native ftruncate syscall. (ENG-22975)
  ftruncateFd(fd, len);
}

export function ftruncate(fd: number, lenOrCallback: number | Callback, callback?: Callback): void {
  let len: number;
  let cb: Callback;
  if (typeof lenOrCallback === 'function') {
    len = 0;
    cb = lenOrCallback;
  } else {
    len = lenOrCallback;
    cb = callback!;
  }
  wrapCallback(() => ftruncateSync(fd, len), cb);
}

// --- utimes ---

export function utimesSync(path: string, atime: number | Date, mtime: number | Date): void {
  const targetPath = toPathString(path, 'path');
  utimesNative(targetPath, normalizeUtimesValue(atime), normalizeUtimesValue(mtime));
}

export function utimes(path: string, atime: number | Date, mtime: number | Date, callback: Callback): void {
  toPathString(path, 'path');
  wrapCallback(() => utimesSync(path, atime, mtime), callback);
}

// --- rm ---

export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void {
  const targetPath = toPathString(path, 'path');
  const recursive = options?.recursive === true;
  const force = options?.force === true;

  try {
    const info = lstatSync(targetPath);
    if (info.isDirectory()) {
      if (recursive) {
        const entries = readdirSync(targetPath) as string[];
        for (const entry of entries) {
          rmSync(join(targetPath, entry), options);
        }
      }
      try {
        rmdirSync(targetPath);
      } catch (error) {
        throw normalizeRmError(error, targetPath, recursive);
      }
    } else {
      try {
        unlinkSync(targetPath);
      } catch (error) {
        throw normalizeRmError(error, targetPath, recursive);
      }
    }
  } catch (error) {
    const normalizedError = normalizeRmError(error, targetPath, recursive);
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

export function rm(path: string, optionsOrCallback: { recursive?: boolean; force?: boolean } | Callback, callback?: Callback): void {
  let options: { recursive?: boolean; force?: boolean } | undefined;
  let cb: Callback;
  if (typeof optionsOrCallback === 'function') {
    cb = optionsOrCallback;
  } else {
    options = optionsOrCallback;
    cb = callback!;
  }
  toPathString(path, 'path');
  wrapCallback(() => rmSync(path, options), cb);
}

// --- fstat ---

export function fstatSync(fd: number): Stats {
  // Stat by fd via the native fstat syscall. (ENG-22975)
  return toStats(fstatJson(fd));
}

export function fstat(fd: number, callback: Callback<Stats>): void {
  wrapCallback(() => fstatSync(fd), callback);
}

// --- fchmod ---

export function fchmodSync(fd: number, mode: number): void {
  // chmod by fd via the native fchmod syscall. (ENG-22975)
  fchmodFd(fd, mode);
}

export function fchmod(fd: number, mode: number, callback: Callback): void {
  wrapCallback(() => fchmodSync(fd, mode), callback);
}

// --- watch stubs ---

export function watch(_filename: string, _options?: any, _listener?: any): any {
  const watcher: any = {
    close() {},
    on() { return watcher; },
    once() { return watcher; },
    addListener() { return watcher; },
    removeListener() { return watcher; },
    off() { return watcher; },
    emit() { return false; },
    ref() { return watcher; },
    unref() { return watcher; },
  };
  return watcher;
}

export function watchFile(_filename: string, _options?: any, _listener?: any): any {
  return watch(_filename);
}

export function unwatchFile(_filename: string, _listener?: any): void {
  // no-op
}
