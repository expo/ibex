// ENG-22975 — web fs bridge (packages/ibex-runtime-js/src/fs) correctness fixes:
//   1. fs.write(fd, string, cb) must write at the fd's current position, not
//      absolute offset 0, and the 5-arg buffer form must not lose its callback.
//   2. wrapCallback / fs.read / fs.write must not re-invoke a user callback that
//      throws on success (which would run the failure path for a successful op).
//   3. WriteStream's deferred open must respect destroy() (no truncate/fd leak).
//   4. fstatSync/ftruncateSync/fchmodSync must use fd syscalls, not the
//      Linux-only /proc/self/fd path (which ENOENTs on darwin/iOS).
// Run with: bun test.

import { afterEach, beforeEach, expect, test } from 'bun:test';
import {
  closeSync,
  createWriteStream,
  fchmodSync,
  fstatSync,
  ftruncateSync,
  openSync,
  write,
  writeSync,
} from './index.ts';
import { write as promisesWrite } from './promises.ts';
import { wrapCallback } from './shared.ts';

const O_CREAT = 0x40;
const O_TRUNC = 0x200;
const O_APPEND = 0x400;

interface MockFile {
  data: number[];
  mode: number;
}

const files = new Map<string, MockFile>();
const fds = new Map<number, { path: string; pos: number }>();
const openCalls: string[] = [];
let nextFd = 3;

function makeErr(message: string, code: string): Error {
  const err = new Error(message) as Error & { code: string };
  err.code = code;
  return err;
}

function statJsonFor(file: MockFile): string {
  return JSON.stringify({
    size: file.data.length,
    mode: file.mode,
    mtime_ms: 0,
    is_file: true,
    is_dir: false,
    is_symlink: false,
  });
}

function contentOf(path: string): string {
  const file = files.get(path);
  if (!file) {
    return '<missing>';
  }
  return new TextDecoder().decode(Uint8Array.from(file.data.map((b) => b ?? 0)));
}

function ensureNotProc(path: string, syscall: string): void {
  // Simulate darwin/iOS: /proc does not exist.
  if (path.startsWith('/proc/')) {
    throw makeErr(`ENOENT: no such file or directory, ${syscall} '${path}'`, 'ENOENT');
  }
}

function installMock(): void {
  const g = globalThis as any;

  g.__exactFsOpen = (path: string, flags: number, _mode?: number): number => {
    openCalls.push(path);
    let file = files.get(path);
    if (flags & O_TRUNC) {
      file = { data: [], mode: 0o644 };
      files.set(path, file);
    } else if (flags & O_CREAT) {
      if (!file) {
        file = { data: [], mode: 0o644 };
        files.set(path, file);
      }
    }
    if (!file) {
      throw makeErr(`ENOENT: no such file or directory, open '${path}'`, 'ENOENT');
    }
    const fd = nextFd++;
    fds.set(fd, { path, pos: flags & O_APPEND ? file.data.length : 0 });
    return fd;
  };

  g.__exactFsClose = (fd: number): void => {
    if (!fds.has(fd)) {
      throw makeErr('EBADF: bad file descriptor, close', 'EBADF');
    }
    fds.delete(fd);
  };

  g.__exactFsRead = (fd: number, length: number, position: number): Uint8Array => {
    const entry = fds.get(fd);
    if (!entry) {
      throw makeErr('EBADF: bad file descriptor, read', 'EBADF');
    }
    const file = files.get(entry.path)!;
    const start = position === -1 ? entry.pos : position;
    const slice = file.data.slice(start, start + length).map((b) => b ?? 0);
    if (position === -1) {
      entry.pos = start + slice.length;
    }
    return Uint8Array.from(slice);
  };

  g.__exactFsWrite = (fd: number, data: Uint8Array, position: number): number => {
    const entry = fds.get(fd);
    if (!entry) {
      throw makeErr('EBADF: bad file descriptor, write', 'EBADF');
    }
    const file = files.get(entry.path)!;
    const bytes = Array.from(data);
    const start = position === -1 ? entry.pos : position;
    for (let i = 0; i < bytes.length; i++) {
      file.data[start + i] = bytes[i];
    }
    // Only a write at the current position (-1) advances the fd offset; a
    // positioned write behaves like pwrite and leaves the offset untouched.
    if (position === -1) {
      entry.pos = start + bytes.length;
    }
    return bytes.length;
  };

  // Path-based primitives — reject /proc paths to model darwin.
  g.__exactStat = (path: string): string => {
    ensureNotProc(path, 'stat');
    const file = files.get(path);
    if (!file) {
      throw makeErr(`ENOENT: no such file or directory, stat '${path}'`, 'ENOENT');
    }
    return statJsonFor(file);
  };
  g.__exactTruncate = (path: string, len: number): void => {
    ensureNotProc(path, 'truncate');
    const file = files.get(path);
    if (!file) {
      throw makeErr(`ENOENT: no such file or directory, truncate '${path}'`, 'ENOENT');
    }
    file.data.length = len;
  };
  g.__exactChmod = (path: string, mode: number): void => {
    ensureNotProc(path, 'chmod');
    const file = files.get(path);
    if (!file) {
      throw makeErr(`ENOENT: no such file or directory, chmod '${path}'`, 'ENOENT');
    }
    file.mode = mode;
  };

  // fd-based metadata primitives — the correct path for finding #4.
  g.__exactFsFstatSync = (fd: number): string => {
    const entry = fds.get(fd);
    if (!entry) {
      throw makeErr('EBADF: bad file descriptor, fstat', 'EBADF');
    }
    return statJsonFor(files.get(entry.path)!);
  };
  g.__exactFsFtruncateSync = (fd: number, len: number): void => {
    const entry = fds.get(fd);
    if (!entry) {
      throw makeErr('EBADF: bad file descriptor, ftruncate', 'EBADF');
    }
    files.get(entry.path)!.data.length = len;
  };
  g.__exactFsFchmodSync = (fd: number, mode: number): void => {
    const entry = fds.get(fd);
    if (!entry) {
      throw makeErr('EBADF: bad file descriptor, fchmod', 'EBADF');
    }
    files.get(entry.path)!.mode = mode;
  };
}

function tick(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 15));
}

beforeEach(() => {
  files.clear();
  fds.clear();
  openCalls.length = 0;
  nextFd = 3;
  installMock();
});

afterEach(() => {
  files.clear();
  fds.clear();
});

// --- Finding #1: write offset / callback parsing ---

test('fs.write(fd, string, cb) chained writes append at current position (not offset 0)', async () => {
  const path = '/vfs/append.txt';
  const fd = openSync(path, 'w');
  await new Promise<void>((resolve, reject) => {
    write(fd, 'hello', (err) => {
      if (err) {
        reject(err);
        return;
      }
      write(fd, 'world', (err2) => {
        if (err2) {
          reject(err2);
          return;
        }
        resolve();
      });
    });
  });
  closeSync(fd);
  expect(contentOf(path)).toBe('helloworld');
});

test('fs.write(fd, buffer, offset, length, callback) does not drop the callback', async () => {
  const path = '/vfs/buf.txt';
  const fd = openSync(path, 'w');
  const buf = new Uint8Array([0x68, 0x69]); // "hi"
  const result = await new Promise<{ err: Error | null; n?: number }>((resolve) => {
    write(fd, buf, 0, 2, (err, n) => resolve({ err, n }));
  });
  closeSync(fd);
  expect(result.err).toBeNull();
  expect(result.n).toBe(2);
  expect(contentOf(path)).toBe('hi');
});

test('promises.write(fd, string) writes at current position (not offset 0)', async () => {
  const path = '/vfs/pappend.txt';
  const fd = openSync(path, 'w');
  await promisesWrite(fd, 'hello');
  await promisesWrite(fd, 'world');
  closeSync(fd);
  expect(contentOf(path)).toBe('helloworld');
});

// --- Finding #2: callback double-invoke on a throwing success callback ---

test('wrapCallback does not re-invoke the callback when it throws on success', async () => {
  const calls: Array<{ err: unknown; result: unknown }> = [];
  const boom = new Error('user callback boom');
  const uncaught: unknown[] = [];

  // queueTask() reads globalThis.queueMicrotask at call time, so wrap it to
  // observe (and contain) any exception that escapes the scheduled task. A
  // correct implementation lets the throwing success callback escape here; the
  // buggy one swallows it and re-invokes the callback with an error instead.
  const originalQueueMicrotask = globalThis.queueMicrotask;
  globalThis.queueMicrotask = (task: () => void): void => {
    originalQueueMicrotask(() => {
      try {
        task();
      } catch (err) {
        uncaught.push(err);
      }
    });
  };

  try {
    wrapCallback(
      () => 'ok',
      (err, result) => {
        calls.push({ err, result });
        if (calls.length === 1) {
          throw boom;
        }
      },
    );
    await tick();
  } finally {
    globalThis.queueMicrotask = originalQueueMicrotask;
  }

  // Exactly one invocation, the success one; the failure path never ran.
  expect(calls.length).toBe(1);
  expect(calls[0].err).toBeNull();
  expect(calls[0].result).toBe('ok');
  // The exception escaped the task (was not swallowed and re-dispatched).
  expect(uncaught).toContain(boom);
});

// --- Finding #3: WriteStream deferred open ignores destroy() ---

test('createWriteStream().destroy() before the deferred open does not open, truncate, or leak', async () => {
  const path = '/vfs/ws.txt';
  files.set(path, { data: Array.from(new TextEncoder().encode('KEEP')), mode: 0o644 });

  const opened: number[] = [];
  const ws = createWriteStream(path);
  ws.on('open', (fd: number) => opened.push(fd));
  ws.destroy();

  await tick();

  expect(opened.length).toBe(0); // no 'open' after 'close'
  expect(openCalls).not.toContain(path); // native open never invoked
  expect(fds.size).toBe(0); // no leaked fd
  expect(contentOf(path)).toBe('KEEP'); // target not truncated
});

// --- Finding #4: fstat/ftruncate/fchmod must not use /proc/self/fd ---

test('fstatSync/ftruncateSync/fchmodSync operate by fd on darwin (no /proc)', () => {
  const path = '/vfs/meta.txt';
  const fd = openSync(path, 'w');
  writeSync(fd, 'abcdef');

  // Would throw ENOENT if it routed through statSync('/proc/self/fd/N').
  expect(fstatSync(fd).size).toBe(6);

  ftruncateSync(fd, 3);
  expect(fstatSync(fd).size).toBe(3);

  fchmodSync(fd, 0o600);
  expect(fstatSync(fd).mode & 0o777).toBe(0o600);

  closeSync(fd);
});
