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
    const err = await new Promise<any>((resolve) => fs.fsync(fd, resolve));
    expect(err && err.code).toBe('ENOSYS');
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
    await expect(fsp.writeFile(p, 'y', { flag: 'wx' })).rejects.toThrow(/EEXIST/);
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
