/**
 * Shared helper for looking up the host bridge function exposed on
 * `globalThis.__hostCall`.
 */

export function hostCallBridge():
  | ((operation: string, argsJson: string) => unknown)
  | null {
  const hostCall = (
    globalThis as {
      __hostCall?: ((operation: string, argsJson: string) => unknown) | undefined;
    }
  ).__hostCall;

  return typeof hostCall === 'function' ? hostCall : null;
}
