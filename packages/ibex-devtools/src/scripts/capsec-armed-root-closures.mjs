/**
 * Reviewed root-global surfaces which armed exact runtimes physically remove
 * after trusted bootstrap capture and before project code can run.
 *
 * @ref LLP 0011#ambient-shared-runtime-boundaries — ambient messaging,
 * storage, and accessibility authority is absent from the armed root realm.
 * @ref LLP 0022#7-capabilities-principals-and-affordance-parity — sealed
 * installation rows remain in the registry join but are absent from the live
 * descriptor sweep.
 */

export const ARMED_SHARED_RUNTIME_SEALED_ROOTS = Object.freeze([
  "__exactMemoryDebug",
  "BroadcastChannel",
  "caches",
  "IDBCursor",
  "IDBCursorWithValue",
  "IDBDatabase",
  "IDBIndex",
  "IDBKeyRange",
  "IDBObjectStore",
  "IDBOpenDBRequest",
  "IDBRequest",
  "IDBTransaction",
  "indexedDB",
  "localStorage",
  "MessageChannel",
  "MessagePort",
  "sessionStorage",
]);

export const ARMED_SHARED_RUNTIME_SEALED_PATH_PREFIXES = Object.freeze([
  "global:Bun.accessibility",
  "global:Exact.accessibility",
]);

export const ARMED_NATIVE_SEALED_ROOTS = Object.freeze([
  "__exactGetGCStats",
  "__exactGetHeapInfo",
  "__exactGetSourceCacheStats",
  "__exactIpcRecvMsg",
  "__exactIpcSendMsg",
  "__exactPollSignal",
  "__exactResetSignal",
]);

const ARMED_NATIVE_PRIVATE_ROOTS = new Set([
  "__exactExit",
  "__exactSetCwd",
]);
const armedNativeSealedRoots = new Set(ARMED_NATIVE_SEALED_ROOTS);
const armedSharedRuntimeSealedRoots = new Set(
  ARMED_SHARED_RUNTIME_SEALED_ROOTS,
);

function isPathOrDescendant(surfaceName, prefix) {
  return surfaceName === prefix || surfaceName.startsWith(`${prefix}.`);
}

export function reviewedArmedSharedRuntimeSealedSurface(surfaceName) {
  if (typeof surfaceName !== "string") {
    return false;
  }
  // A root with both a shared-runtime installation and a native-operation
  // classification is projected into the disposition manifest under its
  // canonical native spelling. Accept that exact spelling as well as the
  // ordinary `global:` inventory name so the live-root seal cannot be lost
  // during dual-role reconciliation.
  const qualifiedName = surfaceName.startsWith("global:")
    ? surfaceName.slice("global:".length)
    : surfaceName;
  const root = qualifiedName.split(".", 1)[0];
  return (
    armedSharedRuntimeSealedRoots.has(root) ||
    (surfaceName.startsWith("global:") &&
      ARMED_SHARED_RUNTIME_SEALED_PATH_PREFIXES.some((prefix) =>
        isPathOrDescendant(surfaceName, prefix),
      ))
  );
}

export function reviewedArmedNativeAbsentSurface(surfaceName) {
  return (
    armedNativeSealedRoots.has(surfaceName) ||
    ARMED_NATIVE_PRIVATE_ROOTS.has(surfaceName)
  );
}

export function reviewedArmedRootGlobalSealedSurface(surfaceName) {
  return (
    armedNativeSealedRoots.has(surfaceName) ||
    reviewedArmedSharedRuntimeSealedSurface(surfaceName)
  );
}
