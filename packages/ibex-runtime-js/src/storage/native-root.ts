/**
 * Snapshot the native Android storage projection before project JavaScript can
 * replace it. An own projection with an empty filesDir is an explicit closed
 * sentinel, not permission to fall through to host environment paths.
 *
 * @ref LLP 0023#6-path-bearing-observables — armed JavaScript never receives
 * or consumes a backing-host path.
 */

export interface AndroidStorageRootSnapshot {
  readonly present: boolean;
  readonly root: string | null;
}

function trimTrailingSlash(path: string): string {
  return path.replace(/\/+$/, '') || '/';
}

export function captureAndroidStorageRoot(g: any): AndroidStorageRootSnapshot {
  const projection = Object.getOwnPropertyDescriptor(
    g,
    '__exactAndroidStoragePaths',
  );
  if (!projection) {
    return Object.freeze({ present: false, root: null });
  }

  const storage = projection.value;
  const filesDir =
    storage !== null && typeof storage === 'object'
      ? Object.getOwnPropertyDescriptor(storage, 'filesDir')?.value
      : undefined;
  const root =
    typeof filesDir === 'string' && filesDir.length > 0
      ? trimTrailingSlash(filesDir)
      : null;
  return Object.freeze({ present: true, root });
}

export function resolveNativeStorageRoot(
  g: any,
  android: AndroidStorageRootSnapshot,
): string | null {
  if (android.present) {
    return android.root;
  }

  const env = g.process?.env;
  const envFilesDir = env?.EXACT_ANDROID_FILES_DIR ?? env?.HOME;
  if (typeof envFilesDir === 'string' && envFilesDir.length > 0) {
    return trimTrailingSlash(envFilesDir);
  }

  return '/tmp';
}
