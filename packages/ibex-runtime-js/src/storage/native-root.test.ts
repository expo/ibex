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

  expect(snapshot).toEqual({ present: true, root: null });
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

  expect(absent).toEqual({ present: false, root: null });
  expect(resolveNativeStorageRoot(fromEnv, absent)).toBe('/compat/files');
  expect(resolveNativeStorageRoot({}, captureAndroidStorageRoot({}))).toBe(
    '/tmp',
  );
});
