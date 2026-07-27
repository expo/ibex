import { expect, test } from 'bun:test';
import {
  captureAndroidStorageRoot,
  resolveNativeStorageRoot,
} from './native-root';

test('an empty Android projection is closed and never falls through to host env or /tmp', () => {
  let processReads = 0;
  const storage = { filesDir: '' };
  const g = {
    __exactAndroidStoragePaths: storage,
    get process() {
      processReads += 1;
      throw new Error('armed storage resolution consulted process.env');
    },
  };

  const snapshot = captureAndroidStorageRoot(g);
  storage.filesDir = '/data/user/0/dev.ibex/files';

  expect(snapshot).toEqual({
    present: true,
    root: null,
    fallbackClosed: true,
  });
  expect(resolveNativeStorageRoot(g, snapshot)).toBeNull();
  expect(processReads).toBe(0);
});

test('an unarmed Android projection preserves its initialized Context path', () => {
  let processReads = 0;
  const g = {
    __exactAndroidStoragePaths: {
      filesDir: '/data/user/0/dev.ibex/files///',
    },
    get process() {
      processReads += 1;
      return { env: { HOME: '/should/not/win' } };
    },
  };

  const snapshot = captureAndroidStorageRoot(g);
  expect(snapshot).toEqual({
    present: true,
    root: '/data/user/0/dev.ibex/files',
    fallbackClosed: false,
  });
  expect(resolveNativeStorageRoot(g, snapshot)).toBe(
    '/data/user/0/dev.ibex/files',
  );
  expect(processReads).toBe(0);
});

test('non-Android compatibility retains environment and /tmp fallback behavior', () => {
  const fromEnv = {} as any;
  fromEnv.process = {
    env: {
      EXACT_ANDROID_FILES_DIR: '/compat/files/',
      HOME: '/compat/home',
    },
  };
  const absent = captureAndroidStorageRoot(fromEnv);

  expect(absent).toEqual({
    present: false,
    root: null,
    fallbackClosed: false,
  });
  expect(resolveNativeStorageRoot(fromEnv, absent)).toBe('/compat/files');
  expect(resolveNativeStorageRoot({}, captureAndroidStorageRoot({}))).toBe(
    '/tmp',
  );
});

test('authenticated desktop storage stays closed when its environment is empty', () => {
  const compatModes = Object.freeze(['native-storage:closed']);
  const g = {} as any;
  Object.defineProperty(g, '__exactCompatModes', {
    value: compatModes,
    writable: false,
    configurable: true,
  });
  g.process = { env: {} };

  const snapshot = captureAndroidStorageRoot(g);
  expect(snapshot).toEqual({
    present: false,
    root: null,
    fallbackClosed: true,
  });

  Object.defineProperty(g, '__exactCompatModes', {
    value: [],
    writable: false,
    configurable: true,
  });
  g.process.env.HOME = '/tmp/attacker-selected-after-bootstrap';
  expect(resolveNativeStorageRoot(g, snapshot)).toBeNull();
});

test('production armed marker closes desktop storage without a compatibility carrier', () => {
  const g = {} as any;
  Object.defineProperty(g, '__exactSetEnv', {
    value: () => undefined,
    writable: false,
    configurable: true,
  });
  g.process = { env: { HOME: '/tmp/must-not-be-consumed' } };

  const snapshot = captureAndroidStorageRoot(g);
  expect(snapshot.fallbackClosed).toBe(true);
  expect(resolveNativeStorageRoot(g, snapshot)).toBeNull();
});

test('an explicit trusted Android root takes precedence over desktop closure', () => {
  const g = {} as any;
  Object.defineProperty(g, '__exactSetEnv', {
    value: () => undefined,
    writable: false,
    configurable: true,
  });
  Object.defineProperty(g, '__exactAndroidStoragePaths', {
    value: { filesDir: '/data/user/0/dev.ibex/files' },
    writable: false,
    configurable: false,
  });

  const snapshot = captureAndroidStorageRoot(g);
  expect(snapshot).toEqual({
    present: true,
    root: '/data/user/0/dev.ibex/files',
    fallbackClosed: true,
  });
  expect(resolveNativeStorageRoot(g, snapshot)).toBe(
    '/data/user/0/dev.ibex/files',
  );
});
