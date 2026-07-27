/**
 * Snapshot the native-storage policy before project JavaScript can replace
 * its trusted-bootstrap inputs. An own Android projection with an empty
 * filesDir, or an authenticated runtime's temporary closed marker, is an
 * explicit closed sentinel, not permission to fall through to host environment
 * paths.
 *
 * @ref LLP 0023#6-path-bearing-observables — armed JavaScript never receives
 * or consumes a backing-host path.
 */

export interface AndroidStorageRootSnapshot {
  readonly present: boolean;
  readonly root: string | null;
  readonly fallbackClosed: boolean;
}

function trimTrailingSlash(path: string): string {
  return path.replace(/\/+$/, '') || '/';
}

export function captureAndroidStorageRoot(g: any): AndroidStorageRootSnapshot {
  const authenticatedMarker =
    Object.getOwnPropertyDescriptor(g, '__exactSetEnv')?.value;
  const compatModes =
    Object.getOwnPropertyDescriptor(g, '__exactCompatModes')?.value;
  const authenticatedStorageClosed =
    typeof authenticatedMarker === 'function' ||
    (Array.isArray(compatModes) &&
      compatModes.some(mode => mode === 'native-storage:closed'));
  const projection = Object.getOwnPropertyDescriptor(
    g,
    '__exactAndroidStoragePaths',
  );
  if (!projection) {
    return Object.freeze({
      present: false,
      root: null,
      fallbackClosed: authenticatedStorageClosed,
    });
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
  return Object.freeze({
    present: true,
    root,
    fallbackClosed: authenticatedStorageClosed || root === null,
  });
}

export function resolveNativeStorageRoot(
  g: any,
  android: AndroidStorageRootSnapshot,
): string | null {
  if (android.present) {
    return android.root;
  }
  if (android.fallbackClosed) {
    return null;
  }

  const env = g.process?.env;
  const envFilesDir = env?.EXACT_ANDROID_FILES_DIR ?? env?.HOME;
  if (typeof envFilesDir === 'string' && envFilesDir.length > 0) {
    return trimTrailingSlash(envFilesDir);
  }

  return '/tmp';
}
