// @ts-nocheck
/**
 * ExactFile - Bun.file() compatible lazy file handle.
 *
 * Like Bun.file(), this returns a lazy reference to a file on disk.
 * Nothing is read until you call .text(), .json(), .arrayBuffer(), .bytes(), etc.
 *
 * Usage:
 *   const f = Exact.file("package.json");
 *   const text = await f.text();
 *   const data = await f.json();
 *   const exists = await f.exists();
 *   console.log(f.name, f.size, f.type);
 */

declare const __exactReadFile: (path: string) => Uint8Array;
declare const __exactWriteFile: (path: string, data: Uint8Array) => void;
declare const __exactStat: (path: string) => string;
declare const __exactAccess: (path: string, mode: number) => void;
declare const __exactEnsureFs: (() => void) | undefined;

// Common extension → MIME type map
const MIME_TYPES: Record<string, string> = {
  '.txt': 'text/plain;charset=utf-8',
  '.html': 'text/html;charset=utf-8',
  '.htm': 'text/html;charset=utf-8',
  '.css': 'text/css;charset=utf-8',
  '.js': 'text/javascript;charset=utf-8',
  '.mjs': 'text/javascript;charset=utf-8',
  '.cjs': 'text/javascript;charset=utf-8',
  '.ts': 'text/typescript;charset=utf-8',
  '.tsx': 'text/typescript;charset=utf-8',
  '.jsx': 'text/javascript;charset=utf-8',
  '.json': 'application/json;charset=utf-8',
  '.jsonl': 'application/x-ndjson;charset=utf-8',
  '.xml': 'application/xml;charset=utf-8',
  '.svg': 'image/svg+xml;charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.bmp': 'image/bmp',
  '.tiff': 'image/tiff',
  '.tif': 'image/tiff',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.tar': 'application/x-tar',
  '.wasm': 'application/wasm',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.ogg': 'audio/ogg',
  '.wav': 'audio/wav',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.md': 'text/markdown;charset=utf-8',
  '.yaml': 'text/yaml;charset=utf-8',
  '.yml': 'text/yaml;charset=utf-8',
  '.toml': 'text/toml;charset=utf-8',
  '.csv': 'text/csv;charset=utf-8',
  '.sh': 'application/x-sh',
  '.sql': 'application/sql',
  '.wgsl': 'text/wgsl;charset=utf-8',
  '.glsl': 'text/plain;charset=utf-8',
};

function getMimeType(path: string): string {
  const dot = path.lastIndexOf('.');
  if (dot === -1) return 'application/octet-stream';
  const ext = path.slice(dot).toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}

function decodeBytes(bytes: Uint8Array): string {
  if (typeof TextDecoder !== 'undefined') {
    const decoded = new TextDecoder('utf-8').decode(bytes);
    if (
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

function toUint8Array(data: string | Uint8Array | ArrayBuffer | ArrayBufferView): Uint8Array {
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
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data as any);
}

let _exactFsInitialized = false;

function ensureExactFs(): void {
  if (_exactFsInitialized) {
    return;
  }

  const g = globalThis as any;
  const hasFsPrimitives =
    typeof g.__exactReadFile === 'function' &&
    typeof g.__exactWriteFile === 'function' &&
    typeof g.__exactStat === 'function' &&
    typeof g.__exactAccess === 'function';

  if (!hasFsPrimitives && typeof g.__exactEnsureFs === 'function') {
    g.__exactEnsureFs();
  }

  _exactFsInitialized =
    typeof g.__exactReadFile === 'function' ||
    typeof g.__exactWriteFile === 'function' ||
    typeof g.__exactStat === 'function' ||
    typeof g.__exactAccess === 'function';
}

export interface ExactFileOptions {
  type?: string;
}

type ExactFilePathLike =
  | string
  | {
      pathname?: string;
      href?: string;
    };

function normalizeExactFilePath(path: ExactFilePathLike): string {
  if (typeof path === 'string') {
    return path;
  }

  if (path && typeof path === 'object') {
    if (typeof path.pathname === 'string' && path.pathname) {
      return decodeURIComponent(path.pathname);
    }
    if (typeof path.href === 'string' && path.href.startsWith('file:')) {
      return decodeURIComponent(path.href.replace(/^file:\/\//, ''));
    }
  }

  return String(path);
}

/**
 * Lazy file reference compatible with Bun.file().
 *
 * Properties:
 * - name: string (the file path)
 * - size: number (file size in bytes, 0 if not found)
 * - type: string (MIME type inferred from extension)
 * - lastModified: number (mtime in ms since epoch)
 *
 * Methods:
 * - text(): Promise<string>
 * - json(): Promise<any>
 * - arrayBuffer(): Promise<ArrayBuffer>
 * - bytes(): Promise<Uint8Array>
 * - slice(begin?, end?): Blob
 * - exists(): Promise<boolean>
 * - stat(): Promise<{size, mtime_ms, ...} | null>
 */
export class ExactFile {
  readonly name: string;
  readonly type: string;

  constructor(path: ExactFilePathLike, options?: ExactFileOptions) {
    const normalizedPath = normalizeExactFilePath(path);
    this.name = normalizedPath;
    this.type = options?.type || getMimeType(normalizedPath);
  }

  get size(): number {
    ensureExactFs();
    try {
      const json = __exactStat(this.name);
      const info = JSON.parse(json);
      return info.size;
    } catch {
      return 0;
    }
  }

  get lastModified(): number {
    ensureExactFs();
    try {
      const json = __exactStat(this.name);
      const info = JSON.parse(json);
      return info.mtime_ms;
    } catch {
      return 0;
    }
  }

  async text(): Promise<string> {
    ensureExactFs();
    const bytes = __exactReadFile(this.name);
    return decodeBytes(bytes);
  }

  async json(): Promise<any> {
    const text = await this.text();
    return JSON.parse(text);
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    ensureExactFs();
    const bytes = __exactReadFile(this.name);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  async bytes(): Promise<Uint8Array> {
    ensureExactFs();
    return __exactReadFile(this.name);
  }

  _getBytes(): Uint8Array {
    ensureExactFs();
    return __exactReadFile(this.name);
  }

  async exists(): Promise<boolean> {
    ensureExactFs();
    try {
      __exactAccess(this.name, 0);
      return true;
    } catch {
      return false;
    }
  }

  async stat(): Promise<{
    size: number;
    mtime_ms: number;
    is_dir: boolean;
    is_file: boolean;
    mode: number;
  } | null> {
    ensureExactFs();
    try {
      const json = __exactStat(this.name);
      return JSON.parse(json);
    } catch {
      return null;
    }
  }

  slice(begin?: number, end?: number, contentType?: string): Blob {
    ensureExactFs();
    const bytes = __exactReadFile(this.name);
    const sliced = bytes.slice(begin ?? 0, end ?? bytes.length);
    return new Blob([sliced], { type: contentType || this.type });
  }

  // stream() returns a ReadableStream if available
  stream(): ReadableStream<Uint8Array> {
    ensureExactFs();
    const name = this.name;
    return new ReadableStream<Uint8Array>({
      start(controller) {
        try {
          const bytes = __exactReadFile(name);
          controller.enqueue(bytes);
          controller.close();
        } catch (err) {
          controller.error(err);
        }
      },
    });
  }

  // writer() returns a simple FileSink-like object
  writer(): { write(data: string | Uint8Array | ArrayBuffer): number; end(): void; flush(): void } {
    const name = this.name;
    let started = false;
    return {
      write(data: string | Uint8Array | ArrayBuffer): number {
        ensureExactFs();
        const bytes = toUint8Array(data);
        if (!started) {
          __exactWriteFile(name, bytes);
          started = true;
        } else {
          // Append after first write
          const g = globalThis as any;
          if (typeof g.__exactAppendFile === 'function') {
            g.__exactAppendFile(name, bytes);
          } else {
            // Fallback: read + concat + write
            const existing = __exactReadFile(name);
            const combined = new Uint8Array(existing.length + bytes.length);
            combined.set(existing);
            combined.set(bytes, existing.length);
            __exactWriteFile(name, combined);
          }
        }
        return bytes.length;
      },
      end() { /* no-op, writes are synchronous */ },
      flush() { /* no-op, writes are synchronous */ },
    };
  }

  toString(): string {
    return `ExactFile("${this.name}")`;
  }

  // Make it work with JSON.stringify
  toJSON(): { name: string; type: string; size: number; lastModified: number } {
    return {
      name: this.name,
      type: this.type,
      size: this.size,
      lastModified: this.lastModified,
    };
  }
}

/**
 * Exact.write(dest, data) - Write data to a file.
 * Compatible with Bun.write().
 *
 * @param dest - File path or ExactFile object
 * @param data - String, Uint8Array, ArrayBuffer, Blob, or Response
 * @returns Promise<number> - bytes written
 */
export async function exactWrite(
  dest: string | ExactFile,
  data: string | Uint8Array | ArrayBuffer | ArrayBufferView | Blob | Response,
): Promise<number> {
  ensureExactFs();
  const path = typeof dest === 'string' ? dest : dest.name;

  let bytes: Uint8Array;

  if (typeof data === 'string') {
    bytes = toUint8Array(data);
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else if (ArrayBuffer.isView(data)) {
    bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  } else if (typeof Blob !== 'undefined' && data instanceof Blob) {
    const ab = await data.arrayBuffer();
    bytes = new Uint8Array(ab);
  } else if (typeof Response !== 'undefined' && data instanceof Response) {
    const ab = await data.arrayBuffer();
    bytes = new Uint8Array(ab);
  } else {
    bytes = toUint8Array(String(data));
  }

  __exactWriteFile(path, bytes);
  return bytes.length;
}

function defineGlobalValue(target: any, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    value,
    configurable: true,
    enumerable: true,
    writable: true,
  });
}

export interface ExactGlobalInstallResult {
  file: (path: ExactFilePathLike, options?: ExactFileOptions) => ExactFile;
  write: typeof exactWrite;
}

/**
 * Install Exact and Bun globals with file() and write() methods.
 */
export function installExactGlobal(): ExactGlobalInstallResult {
  const g = globalThis as any;

  // Create or extend Exact object
  if (!g.Exact) {
    g.Exact = {};
  }

  const file = (path: ExactFilePathLike, options?: ExactFileOptions) => new ExactFile(path, options);
  const write = exactWrite;

  defineGlobalValue(g.Exact, 'file', file);
  defineGlobalValue(g.Exact, 'write', write);

  // Version info
  if (!g.Exact.version) g.Exact.version = '0.1.0';
  if (!g.Exact.platform) g.Exact.platform = 'cli';

  // Alias Bun to Exact (Bun may be read-only in Bun's own test runner)
  try {
    if (!g.Bun) {
      g.Bun = g.Exact;
    } else {
      // Augment existing Bun object with Exact.file and Exact.write
      const bunFileDescriptor = Object.getOwnPropertyDescriptor(g.Bun, 'file');
      if (!bunFileDescriptor || bunFileDescriptor.get || bunFileDescriptor.value == null) {
        defineGlobalValue(g.Bun, 'file', file);
      }
      const bunWriteDescriptor = Object.getOwnPropertyDescriptor(g.Bun, 'write');
      if (!bunWriteDescriptor || bunWriteDescriptor.get || bunWriteDescriptor.value == null) {
        defineGlobalValue(g.Bun, 'write', write);
      }
    }
  } catch (_e) {
    // Bun is read-only (e.g. in Bun's native test runner) — skip aliasing
  }

  return { file, write };
}
