// ENG-22963 — regression coverage for correctness bugs in the fs builtins
// (`src/builtins/fs.js` and `src/builtins/fs-promises.js`).
//
// Covered here (behavioral bugs, checked against Node/real-fs as the oracle):
//   #3  createReadStream emitted 'ready' synchronously in the constructor, so a
//       listener attached right after createReadStream(fd) never saw it.
//   #4  cpSync({force:false}) overwrote (truncated) an existing destination
//       instead of leaving it untouched; with errorOnExist it must throw EEXIST.
//   #5  readdirSync fabricated a "Maximum call stack size exceeded" after 256
//       same-path calls in one synchronous tick.
//   #6  ftruncateSync/fsyncSync/fdatasyncSync/futimesSync/chownSync/utimesSync
//       silently succeeded when their native hook was absent instead of ENOSYS.
//   #8  fs-promises writeFile dropped {encoding,mode,flag} and double-opened
//       with mode 0 ({flag:'a'} truncated, {flag:'wx'} never raised EEXIST).
//   #9  fs-promises FileHandle.read(buffer) always resolved {bytesRead:0}.
//
// fs.js talks to native host hooks (__exact*); we back them with Node's own fs
// (fd-based) before requiring the builtin. fs-promises.js requires node:fs
// directly, so it exercises the real fs backend with real temp files.

import { expect, test, describe, beforeAll, afterAll } from 'bun:test';
import { createRequire } from 'module';
import * as nodeFs from 'node:fs';
import * as os from 'node:os';
import * as nodePath from 'node:path';

const g = globalThis as Record<string, any>;

function statJson(s: nodeFs.Stats): string {
  return JSON.stringify({
    dev: s.dev, ino: Number(s.ino), mode: s.mode, nlink: s.nlink,
    uid: s.uid, gid: s.gid, rdev: s.rdev, size: s.size,
    blksize: s.blksize, blocks: s.blocks,
    atime_ms: s.atimeMs, mtime_ms: s.mtimeMs, ctime_ms: s.ctimeMs,
    birthtime_ms: s.birthtimeMs,
    is_file: s.isFile(), is_dir: s.isDirectory(), is_symlink: s.isSymbolicLink(),
    is_char_device: s.isCharacterDevice(), is_block_device: s.isBlockDevice(),
    is_fifo: s.isFIFO(), is_socket: s.isSocket(),
  });
}

// --- Node-backed stubs for the fs.js native host hooks. Deliberately DO NOT
//     stub ftruncate/fsync/fdatasync/futimes/chown/utimes so #6 can assert
//     their absent-hook ENOSYS behavior. ---
g.__exactEnsureFs = () => {};
g.__exactStat = (p: string) => statJson(nodeFs.statSync(p));
g.__exactLstat = (p: string) => statJson(nodeFs.lstatSync(p));
g.__exactFsFstatSync = (fd: number) => statJson(nodeFs.fstatSync(fd));
g.__exactFsOpen = (p: string, flags: number, mode: number) => nodeFs.openSync(p, flags, mode);
g.__exactFsClose = (fd: number) => nodeFs.closeSync(fd);
g.__exactFsRead = (fd: number, length: number, position: number) => {
  const buf = Buffer.allocUnsafe(length);
  const n = nodeFs.readSync(fd, buf, 0, length, position === -1 ? null : position);
  return new Uint8Array(buf.buffer, buf.byteOffset, n);
};
g.__exactFsWrite = (fd: number, bytes: Uint8Array, pos: number) =>
  nodeFs.writeSync(fd, bytes, 0, bytes.length, pos === -1 ? null : pos);
g.__exactAccess = (p: string, mode: number) => nodeFs.accessSync(p, mode);
g.__exactChmod = (p: string, mode: number) => nodeFs.chmodSync(p, mode);
g.__exactUnlink = (p: string) => nodeFs.unlinkSync(p);
g.__exactReaddir = (p: string) => JSON.stringify(nodeFs.readdirSync(p));
g.__exactMkdir = (p: string, recursive: boolean) => nodeFs.mkdirSync(p, { recursive });

// --- ENG-23497 — worker-pool async natives (__exactFs*Async). fs.js routes
//     the callback/promise/stream paths through these when present, so they
//     MUST be stubbed here or every fs test in this suite crashes (see the
//     __exactChmod incident fixed in ENG-23480). Backed by Node's sync fs:
//     the harness only needs the contract (resolve payload shape / reject
//     with Node's own errno errors), not real off-thread execution. `flags`
//     arrives numeric (fs.js normalizes flag strings before the native call).
function readAllFromFd(fd: number): Uint8Array {
  const chunks: Buffer[] = [];
  const buf = Buffer.allocUnsafe(65536);
  for (;;) {
    const n = nodeFs.readSync(fd, buf, 0, buf.length, null);
    if (n <= 0) break;
    chunks.push(Buffer.from(buf.subarray(0, n)));
  }
  const all = Buffer.concat(chunks);
  return new Uint8Array(all.buffer, all.byteOffset, all.length);
}
function writeAllToFd(fd: number, bytes: Uint8Array): void {
  let off = 0;
  while (off < bytes.length) {
    off += nodeFs.writeSync(fd, bytes, off, bytes.length - off, null);
  }
}
const asyncNativeCalls = { readv: 0, writev: 0, fd: [] as string[] };
const pathAsyncCalls: Record<string, number> = {};
function bufferLikeLength(value: any): number {
  return typeof value?.byteLength === 'number' ? value.byteLength : (value?.length ?? 0);
}
function asUint8Array(value: any): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value);
}
function recordPathAsyncCall(op: string): void {
  pathAsyncCalls[op] = (pathAsyncCalls[op] || 0) + 1;
}
g.__exactFsReadFileAsync = (target: string | number, flags: number, mode: number) => {
  try {
    if (typeof target === 'number') {
      return Promise.resolve(readAllFromFd(target));
    }
    const fd = nodeFs.openSync(target, flags, mode);
    try {
      return Promise.resolve(readAllFromFd(fd));
    } finally {
      nodeFs.closeSync(fd);
    }
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsWriteFileAsync = (
  target: string | number, bytes: Uint8Array, flags: number | null, mode: number, flush: boolean,
) => {
  try {
    if (typeof target === 'number') {
      writeAllToFd(target, bytes);
      if (flush) nodeFs.fsyncSync(target);
      return Promise.resolve(undefined);
    }
    const fd = nodeFs.openSync(target, flags ?? 'w', mode);
    try {
      writeAllToFd(fd, bytes);
      if (flush) nodeFs.fsyncSync(fd);
    } finally {
      nodeFs.closeSync(fd);
    }
    return Promise.resolve(undefined);
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsReadAsync = (fd: number, length: number, position: number) => {
  try {
    const buf = Buffer.allocUnsafe(length);
    const pos = typeof position === 'number' && position >= 0 ? position : null;
    const n = nodeFs.readSync(fd, buf, 0, length, pos);
    return Promise.resolve(new Uint8Array(buf.buffer, buf.byteOffset, n));
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsWriteAsync = (fd: number, bytes: Uint8Array, position: number) => {
  try {
    const pos = typeof position === 'number' && position >= 0 ? position : null;
    return Promise.resolve(nodeFs.writeSync(fd, bytes, 0, bytes.length, pos));
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsReadvAsync = (fd: number, buffers: ArrayBufferView[], position: number) => {
  asyncNativeCalls.readv += 1;
  try {
    const nativeBuffers = buffers.map((buffer) => Buffer.allocUnsafe(bufferLikeLength(buffer)));
    const pos = typeof position === 'number' && position >= 0 ? position : null;
    const n = nodeFs.readvSync(fd, nativeBuffers, pos);
    const out = Buffer.concat(nativeBuffers).subarray(0, n);
    return Promise.resolve(new Uint8Array(out.buffer, out.byteOffset, out.length));
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsWritevAsync = (fd: number, buffers: ArrayBufferView[], position: number) => {
  asyncNativeCalls.writev += 1;
  try {
    const pos = typeof position === 'number' && position >= 0 ? position : null;
    return Promise.resolve(nodeFs.writevSync(fd, buffers.map(asUint8Array), pos));
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsFdAsync = (op: string, fd: number, x?: number, y?: number) => {
  asyncNativeCalls.fd.push(op);
  try {
    switch (op) {
      case 'fchmod': nodeFs.fchmodSync(fd, x!); break;
      case 'fchown': nodeFs.fchownSync(fd, x!, y!); break;
      case 'ftruncate': nodeFs.ftruncateSync(fd, x!); break;
      case 'futimes': nodeFs.futimesSync(fd, x!, y!); break;
      case 'fsync': nodeFs.fsyncSync(fd); break;
      case 'fdatasync': nodeFs.fdatasyncSync(fd); break;
      default: throw new Error(`unsupported fd async op: ${op}`);
    }
    return Promise.resolve(undefined);
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsPathAsync = (op: string, a: string, b?: string | null, x?: number, y?: number) => {
  recordPathAsyncCall(op);
  try {
    switch (op) {
      case 'readdir':
        return Promise.resolve(JSON.stringify(nodeFs.readdirSync(a)));
      case 'mkdir':
        nodeFs.mkdirSync(a, { recursive: x !== 0 });
        return Promise.resolve(undefined);
      case 'rmdir':
        nodeFs.rmdirSync(a);
        return Promise.resolve(undefined);
      case 'unlink':
        nodeFs.unlinkSync(a);
        return Promise.resolve(undefined);
      case 'rename':
        nodeFs.renameSync(a, b as string);
        return Promise.resolve(undefined);
      case 'copyfile':
        nodeFs.copyFileSync(a, b as string);
        return Promise.resolve(undefined);
      case 'realpath':
        return Promise.resolve(nodeFs.realpathSync(a));
      case 'access':
        nodeFs.accessSync(a, x ?? 0);
        return Promise.resolve(undefined);
      case 'chmod':
        nodeFs.chmodSync(a, x ?? 0o666);
        return Promise.resolve(undefined);
      case 'mkdtemp':
        return Promise.resolve(nodeFs.mkdtempSync(a));
      case 'readlink':
        return Promise.resolve(nodeFs.readlinkSync(a));
      case 'truncate':
        nodeFs.truncateSync(a, x ?? 0);
        return Promise.resolve(undefined);
      case 'utime':
        nodeFs.utimesSync(a, x ?? Date.now() / 1000, y ?? Date.now() / 1000);
        return Promise.resolve(undefined);
      case 'statfs':
        return Promise.resolve(JSON.stringify({ type: 0, bsize: 4096, blocks: 1, bfree: 1, bavail: 1, files: 1, ffree: 1 }));
      default:
        throw new Error(`unsupported path async op: ${op}`);
    }
  } catch (e) {
    return Promise.reject(e);
  }
};
g.__exactFsStatAsync = (target: string | number, kind: string) => {
  try {
    if (kind === 'fstat') return Promise.resolve(statJson(nodeFs.fstatSync(target as number)));
    if (kind === 'lstat') return Promise.resolve(statJson(nodeFs.lstatSync(target as string)));
    return Promise.resolve(statJson(nodeFs.statSync(target as string)));
  } catch (e) {
    return Promise.reject(e);
  }
};

const require = createRequire(import.meta.url);
const fs = require('../../../src/builtins/fs.js');
const fsp = require('../../../src/builtins/fs-promises.js');

let dir: string;
beforeAll(() => {
  dir = nodeFs.mkdtempSync(nodePath.join(os.tmpdir(), 'eng22963-'));
});
afterAll(() => {
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch {}
});

describe('cpSync force:false (ENG-22963 #4)', () => {
  test('leaves an existing destination untouched', () => {
    const src = nodePath.join(dir, 'src4a.txt');
    const dest = nodePath.join(dir, 'dest4a.txt');
    nodeFs.writeFileSync(src, 'NEW-CONTENT');
    nodeFs.writeFileSync(dest, 'ORIGINAL');
    fs.cpSync(src, dest, { force: false });
    expect(nodeFs.readFileSync(dest, 'utf8')).toBe('ORIGINAL');
  });

  test('force:false + errorOnExist throws EEXIST', () => {
    const src = nodePath.join(dir, 'src4b.txt');
    const dest = nodePath.join(dir, 'dest4b.txt');
    nodeFs.writeFileSync(src, 'A');
    nodeFs.writeFileSync(dest, 'B');
    expect(() => fs.cpSync(src, dest, { force: false, errorOnExist: true }))
      .toThrow(/EEXIST/);
    expect(nodeFs.readFileSync(dest, 'utf8')).toBe('B');
  });

  test('force:true (default) still overwrites', () => {
    const src = nodePath.join(dir, 'src4c.txt');
    const dest = nodePath.join(dir, 'dest4c.txt');
    nodeFs.writeFileSync(src, 'FRESH');
    nodeFs.writeFileSync(dest, 'STALE');
    fs.cpSync(src, dest);
    expect(nodeFs.readFileSync(dest, 'utf8')).toBe('FRESH');
  });
});

describe('readdirSync burst (ENG-22963 #5)', () => {
  test('300 synchronous same-path calls do not fabricate a stack overflow', () => {
    const d = nodePath.join(dir, 'rd');
    nodeFs.mkdirSync(d, { recursive: true });
    nodeFs.writeFileSync(nodePath.join(d, 'a'), '');
    expect(() => {
      for (let i = 0; i < 300; i++) {
        const entries = fs.readdirSync(d);
        expect(entries).toContain('a');
      }
    }).not.toThrow();
  });
});

describe('absent-hook syscalls raise ENOSYS (ENG-22963 #6)', () => {
  const fd = 3; // arbitrary valid non-negative fd; hook is absent so no syscall runs
  test('ftruncateSync throws ENOSYS', () => {
    expect(() => fs.ftruncateSync(fd, 0)).toThrow(/ENOSYS/);
  });
  test('fsyncSync throws ENOSYS', () => {
    expect(() => fs.fsyncSync(fd)).toThrow(/ENOSYS/);
  });
  test('fdatasyncSync throws ENOSYS', () => {
    expect(() => fs.fdatasyncSync(fd)).toThrow(/ENOSYS/);
  });
  test('futimesSync throws ENOSYS', () => {
    expect(() => fs.futimesSync(fd, new Date(), new Date())).toThrow(/ENOSYS/);
  });
  test('chownSync throws ENOSYS', () => {
    expect(() => fs.chownSync(nodePath.join(dir, 'nope'), 0, 0)).toThrow(/ENOSYS/);
  });
  test('utimesSync throws ENOSYS', () => {
    expect(() => fs.utimesSync(nodePath.join(dir, 'nope'), new Date(), new Date())).toThrow(/ENOSYS/);
  });
  test('async fsync surfaces ENOSYS to its callback', async () => {
    const native = g.__exactFsFdAsync;
    g.__exactFsFdAsync = undefined;
    try {
      const err = await new Promise<any>((resolve) => fs.fsync(fd, resolve));
      expect(err && err.code).toBe('ENOSYS');
    } finally {
      g.__exactFsFdAsync = native;
    }
  });
});

describe('createReadStream ready event (ENG-22963 #3)', () => {
  test("'ready' fires asynchronously so a listener attached after construction sees it", async () => {
    const p = nodePath.join(dir, 'rs3.txt');
    nodeFs.writeFileSync(p, 'hello');
    const fd = nodeFs.openSync(p, 'r');
    const stream = fs.createReadStream(p, { fd, autoClose: false });
    // Attach AFTER the constructor returned: a synchronous emit would be missed.
    const fired = await new Promise<boolean>((resolve) => {
      stream.on('ready', () => resolve(true));
      setTimeout(() => resolve(false), 200);
    });
    try { stream.destroy(); } catch {}
    nodeFs.closeSync(fd);
    expect(fired).toBe(true);
  });
});

describe('fs-promises writeFile options (ENG-22963 #8)', () => {
  test("{flag:'a'} appends instead of truncating", async () => {
    const p = nodePath.join(dir, 'w8a.txt');
    await fsp.writeFile(p, 'AAA');
    await fsp.writeFile(p, 'BBB', { flag: 'a' });
    expect(nodeFs.readFileSync(p, 'utf8')).toBe('AAABBB');
  });

  test("{flag:'wx'} raises EEXIST for an existing file", async () => {
    const p = nodePath.join(dir, 'w8b.txt');
    await fsp.writeFile(p, 'x');
    const result = await fsp.writeFile(p, 'y', { flag: 'wx' }).then(
      () => ({ rejected: false as const }),
      (error) => ({ rejected: true as const, error }),
    );
    expect(result.rejected).toBe(true);
    if (result.rejected) {
      expect(result.error).toMatchObject({ code: 'EEXIST' });
    }
  });

  test('mode is honored when creating a new file (not 000)', async () => {
    const p = nodePath.join(dir, 'w8c.txt');
    await fsp.writeFile(p, 'z', { mode: 0o640 });
    const mode = nodeFs.statSync(p).mode & 0o777;
    expect(mode).toBe(0o640);
  });

  test('encoding option is respected', async () => {
    const p = nodePath.join(dir, 'w8d.txt');
    await fsp.writeFile(p, '68656c6c6f', { encoding: 'hex' });
    expect(nodeFs.readFileSync(p, 'utf8')).toBe('hello');
  });
});

describe('fs-promises FileHandle.read (ENG-22963 #9)', () => {
  test('read(buffer) fills the buffer with actual bytes', async () => {
    const p = nodePath.join(dir, 'r9a.txt');
    nodeFs.writeFileSync(p, 'ABCDE');
    const fh = await fsp.open(p, 'r');
    try {
      const buf = new Uint8Array(5);
      const { bytesRead, buffer } = await fh.read(buf);
      expect(bytesRead).toBe(5);
      expect(Buffer.from(buffer.buffer, buffer.byteOffset, bytesRead).toString('utf8')).toBe('ABCDE');
    } finally {
      await fh.close();
    }
  });

  test('read({buffer}) options form fills the provided buffer', async () => {
    const p = nodePath.join(dir, 'r9b.txt');
    nodeFs.writeFileSync(p, 'WXYZ');
    const fh = await fsp.open(p, 'r');
    try {
      const buf = new Uint8Array(4);
      const { bytesRead } = await fh.read({ buffer: buf });
      expect(bytesRead).toBe(4);
      expect(Buffer.from(buf).toString('utf8')).toBe('WXYZ');
    } finally {
      await fh.close();
    }
  });

  test('positional read(buffer, offset, length, position) still works', async () => {
    const p = nodePath.join(dir, 'r9c.txt');
    nodeFs.writeFileSync(p, '0123456789');
    const fh = await fsp.open(p, 'r');
    try {
      const buf = new Uint8Array(4);
      const { bytesRead } = await fh.read(buf, 0, 4, 2);
      expect(bytesRead).toBe(4);
      expect(Buffer.from(buf).toString('utf8')).toBe('2345');
    } finally {
      await fh.close();
    }
  });
});

describe('path async fs natives (ENG-23541)', () => {
  test('callback metadata and directory ops route through the path async native', async () => {
    const d = nodePath.join(dir, 'path-async-cb');
    const src = nodePath.join(d, 'a.txt');
    const renamed = nodePath.join(d, 'b.txt');
    for (const key of Object.keys(pathAsyncCalls)) delete pathAsyncCalls[key];

    await new Promise<void>((resolve, reject) => {
      fs.mkdir(d, (err: any) => err ? reject(err) : resolve());
    });
    nodeFs.writeFileSync(src, 'abcdef');

    const entries = await new Promise<string[]>((resolve, reject) => {
      fs.readdir(d, (err: any, result: string[]) => err ? reject(err) : resolve(result));
    });
    expect(entries).toEqual(['a.txt']);

    await new Promise<void>((resolve, reject) => {
      fs.rename(src, renamed, (err: any) => err ? reject(err) : resolve());
    });
    await new Promise<void>((resolve, reject) => {
      fs.access(renamed, (err: any) => err ? reject(err) : resolve());
    });
    await new Promise<void>((resolve, reject) => {
      fs.chmod(renamed, 0o600, (err: any) => err ? reject(err) : resolve());
    });
    const real = await new Promise<string>((resolve, reject) => {
      fs.realpath(renamed, (err: any, result: string) => err ? reject(err) : resolve(result));
    });
    expect(real).toBe(nodeFs.realpathSync(renamed));
    await new Promise<void>((resolve, reject) => {
      fs.truncate(renamed, 3, (err: any) => err ? reject(err) : resolve());
    });
    await new Promise<void>((resolve, reject) => {
      fs.utimes(renamed, 1, 2, (err: any) => err ? reject(err) : resolve());
    });
    await new Promise<void>((resolve, reject) => {
      fs.unlink(renamed, (err: any) => err ? reject(err) : resolve());
    });
    await new Promise<void>((resolve, reject) => {
      fs.rmdir(d, (err: any) => err ? reject(err) : resolve());
    });

    expect(pathAsyncCalls.mkdir).toBe(1);
    expect(pathAsyncCalls.readdir).toBe(1);
    expect(pathAsyncCalls.rename).toBe(1);
    expect(pathAsyncCalls.access).toBe(1);
    expect(pathAsyncCalls.chmod).toBe(1);
    expect(pathAsyncCalls.realpath).toBe(1);
    expect(pathAsyncCalls.truncate).toBe(1);
    expect(pathAsyncCalls.utime).toBe(1);
    expect(pathAsyncCalls.unlink).toBe(1);
    expect(pathAsyncCalls.rmdir).toBe(1);
  });

  test('fs.promises path ops route through the path async native', async () => {
    const d = nodePath.join(dir, 'path-async-promises');
    const src = nodePath.join(d, 'src.txt');
    const copy = nodePath.join(d, 'copy.txt');
    const tempPrefix = nodePath.join(dir, 'path-async-temp-');
    for (const key of Object.keys(pathAsyncCalls)) delete pathAsyncCalls[key];

    await fs.promises.mkdir(d);
    nodeFs.writeFileSync(src, 'hello');
    await fs.promises.copyFile(src, copy);
    expect(await fs.promises.readdir(d)).toEqual(['copy.txt', 'src.txt']);
    const statfs = await fs.promises.statfs(d);
    expect(Number(statfs.bsize)).toBe(4096);
    const linkPath = nodePath.join(d, 'link.txt');
    nodeFs.symlinkSync('copy.txt', linkPath);
    expect(await fs.promises.readlink(linkPath)).toBe('copy.txt');
    const temp = await fs.promises.mkdtemp(tempPrefix);
    expect(temp.startsWith(tempPrefix)).toBe(true);
    await fs.promises.unlink(linkPath);
    await fs.promises.unlink(copy);
    await fs.promises.unlink(src);
    await fs.promises.rmdir(d);
    nodeFs.rmSync(temp, { recursive: true, force: true });

    expect(pathAsyncCalls.mkdir).toBe(1);
    expect(pathAsyncCalls.copyfile).toBe(1);
    expect(pathAsyncCalls.readdir).toBe(1);
    expect(pathAsyncCalls.statfs).toBe(1);
    expect(pathAsyncCalls.readlink).toBe(1);
    expect(pathAsyncCalls.mkdtemp).toBe(1);
    expect(pathAsyncCalls.unlink).toBe(3);
    expect(pathAsyncCalls.rmdir).toBe(1);
  });

  test('recursive readdir and opendir use async readdir/stat natives', async () => {
    const root = nodePath.join(dir, 'async-tree');
    nodeFs.mkdirSync(nodePath.join(root, 'nested'), { recursive: true });
    nodeFs.writeFileSync(nodePath.join(root, 'nested', 'leaf'), 'x');
    for (const key of Object.keys(pathAsyncCalls)) delete pathAsyncCalls[key];
    const entries = await fs.promises.readdir(root, { recursive: true });
    expect(entries).toContain('nested');
    expect(entries).toContain(nodePath.join('nested', 'leaf'));
    const opened = await fs.promises.opendir(root);
    const first = await opened.read();
    await opened.close();
    expect(first && first.name).toBe('nested');
    expect(pathAsyncCalls.readdir).toBeGreaterThanOrEqual(3);
  });
});

describe('vectored async fs natives (ENG-23541)', () => {
  test('callback readv/writev route through async natives', async () => {
    const p = nodePath.join(dir, 'vec-async-cb.txt');
    nodeFs.writeFileSync(p, 'ABCDE');
    const fd = nodeFs.openSync(p, 'r+');
    asyncNativeCalls.readv = 0;
    asyncNativeCalls.writev = 0;
    try {
      const a = Buffer.alloc(2);
      const b = new Uint8Array(2);
      const read = await new Promise<{ bytesRead: number; buffers: any[] }>((resolve, reject) => {
        fs.readv(fd, [a, b], 0, (err: any, bytesRead: number, buffers: any[]) => {
          if (err) reject(err);
          else resolve({ bytesRead, buffers });
        });
      });
      expect(read.bytesRead).toBe(4);
      expect(Buffer.concat([a, Buffer.from(b)]).toString('utf8')).toBe('ABCD');

      const write = await new Promise<{ bytesWritten: number; buffers: any[] }>((resolve, reject) => {
        fs.writev(fd, [Buffer.from('xy'), new Uint8Array([122])], 1, (err: any, bytesWritten: number, buffers: any[]) => {
          if (err) reject(err);
          else resolve({ bytesWritten, buffers });
        });
      });
      expect(write.bytesWritten).toBe(3);
      expect(nodeFs.readFileSync(p, 'utf8')).toBe('AxyzE');
      expect(asyncNativeCalls.readv).toBe(1);
      expect(asyncNativeCalls.writev).toBe(1);
    } finally {
      nodeFs.closeSync(fd);
    }
  });

  test('promises and FileHandle readv/writev route through async natives', async () => {
    const p = nodePath.join(dir, 'vec-async-promises.txt');
    nodeFs.writeFileSync(p, '0123456789');
    const fd = nodeFs.openSync(p, 'r+');
    asyncNativeCalls.readv = 0;
    asyncNativeCalls.writev = 0;
    try {
      const first = Buffer.alloc(2);
      const second = new DataView(new ArrayBuffer(2));
      const third = new Uint16Array(1);
      const read = await fs.promises.readv(fd, [first, second, third], 2);
      expect(read.bytesRead).toBe(6);
      expect(first.toString('utf8')).toBe('23');
      expect(String.fromCharCode(second.getUint8(0), second.getUint8(1))).toBe('45');
      expect(Buffer.from(new Uint8Array(third.buffer)).toString('utf8')).toBe('67');

      const write = await fs.promises.writev(fd, [Buffer.from('AA'), new Uint8Array([66])], 5);
      expect(write.bytesWritten).toBe(3);
      expect(nodeFs.readFileSync(p, 'utf8')).toBe('01234AAB89');
    } finally {
      nodeFs.closeSync(fd);
    }

    const fh = await fs.promises.open(p, 'r+');
    try {
      const fhBuf = Buffer.alloc(3);
      const fhRead = await fh.readv([fhBuf], 4);
      expect(fhRead.bytesRead).toBe(3);
      expect(fhBuf.toString('utf8')).toBe('4AA');
      const fhWrite = await fh.writev([Buffer.from('zz')], 0);
      expect(fhWrite.bytesWritten).toBe(2);
      expect(nodeFs.readFileSync(p, 'utf8')).toBe('zz234AAB89');
    } finally {
      await fh.close();
    }
    expect(asyncNativeCalls.readv).toBe(2);
    expect(asyncNativeCalls.writev).toBe(2);
  });
});

describe('descriptor async fs native (ENG-23541)', () => {
  test('callbacks, promises, and FileHandle metadata route off-thread', async () => {
    const p = nodePath.join(dir, 'fd-async.txt');
    nodeFs.writeFileSync(p, 'abcdef');
    const fd = nodeFs.openSync(p, 'r+');
    asyncNativeCalls.fd = [];
    try {
      await new Promise<void>((resolve, reject) => fs.ftruncate(fd, 4, (e: any) => e ? reject(e) : resolve()));
      await fs.promises.fchmod(fd, 0o600);
      await fs.promises.fsync(fd);
      await fs.promises.fdatasync(fd);
    } finally { nodeFs.closeSync(fd); }
    const fh = await fs.promises.open(p, 'r+');
    try {
      await fh.truncate(3);
      await fh.utimes(1, 2);
      await fh.sync();
      await fh.datasync();
    } finally { await fh.close(); }
    expect(asyncNativeCalls.fd).toEqual([
      'ftruncate', 'fchmod', 'fsync', 'fdatasync',
      'ftruncate', 'futimes', 'fsync', 'fdatasync'
    ]);
    expect(nodeFs.readFileSync(p, 'utf8')).toBe('abc');
  });
});
