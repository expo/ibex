const DETACHED_ARRAY_BUFFERS = Symbol.for("exact.detachedArrayBuffers");
const NON_TRANSFERABLE_ARRAY_BUFFERS = Symbol.for("exact.nonTransferableArrayBuffers");
const PATCHED_ARRAY_BUFFER_BYTE_LENGTH = Symbol.for("exact.patchedArrayBufferByteLength");

// Capture the ENGINE-NATIVE ArrayBuffer.prototype.transfer at module-evaluation
// time. This module is evaluated as part of the static import graph, before any
// runtime call to installArrayBufferPolyfills(); on engines without native
// transfer that polyfill installs a JS `transfer` which itself calls
// markDetachedArrayBuffer(). Snapshotting here ensures markDetachedArrayBuffer
// only ever invokes a *real* native detach (never the polyfill), so it cannot
// recurse into itself.
const NATIVE_ARRAY_BUFFER_TRANSFER:
  | ((this: ArrayBuffer, newByteLength?: number) => ArrayBuffer)
  | undefined =
  typeof (ArrayBuffer.prototype as { transfer?: unknown }).transfer === "function"
    ? // Exact's newer ES lib declares a native `ArrayBuffer.prototype.transfer`
      // with a different signature, so a direct `as {...}` cast no longer
      // "sufficiently overlaps" (TS2352 under exact's DOM/ES lib). Route the
      // cast through `unknown` per TS's own hint. Compile-time only — runtime
      // behavior is unchanged. (ENG-23019)
      ((ArrayBuffer.prototype as unknown as { transfer: (this: ArrayBuffer, n?: number) => ArrayBuffer }).transfer)
    : undefined;

function getDetachedArrayBuffers(): WeakSet<ArrayBuffer> | null {
  if (typeof WeakSet !== "function") {
    return null;
  }
  const globalObject = globalThis as any;
  let detached = globalObject[DETACHED_ARRAY_BUFFERS] as WeakSet<ArrayBuffer> | undefined;
  if (!detached) {
    detached = new WeakSet<ArrayBuffer>();
    globalObject[DETACHED_ARRAY_BUFFERS] = detached;
  }
  return detached;
}

function getNonTransferableArrayBuffers(): WeakSet<ArrayBuffer> | null {
  if (typeof WeakSet !== "function") {
    return null;
  }
  const globalObject = globalThis as any;
  let buffers = globalObject[NON_TRANSFERABLE_ARRAY_BUFFERS] as WeakSet<ArrayBuffer> | undefined;
  if (!buffers) {
    buffers = new WeakSet<ArrayBuffer>();
    globalObject[NON_TRANSFERABLE_ARRAY_BUFFERS] = buffers;
  }
  return buffers;
}

function installDetachedArrayBufferByteLengthPatch(): void {
  const proto = ArrayBuffer.prototype as ArrayBuffer & {
    [PATCHED_ARRAY_BUFFER_BYTE_LENGTH]?: boolean;
  };
  if (proto[PATCHED_ARRAY_BUFFER_BYTE_LENGTH]) {
    return;
  }

  const descriptor = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength");
  if (!descriptor?.get) {
    return;
  }

  try {
    Object.defineProperty(ArrayBuffer.prototype, "byteLength", {
      get: function byteLength(this: ArrayBuffer): number {
        if (getDetachedArrayBuffers()?.has(this)) {
          return 0;
        }
        return descriptor.get!.call(this);
      },
      enumerable: descriptor.enumerable ?? false,
      configurable: descriptor.configurable ?? true,
    });
    Object.defineProperty(proto, PATCHED_ARRAY_BUFFER_BYTE_LENGTH, {
      value: true,
      configurable: true,
    });
  } catch (_error) {
    // Environments that refuse to patch the prototype will continue to rely
    // on the WeakSet-based detached tracking.
  }
}

installDetachedArrayBufferByteLengthPatch();

export function isDetachedArrayBuffer(buffer: ArrayBuffer): boolean {
  const detached = getDetachedArrayBuffers();
  if (detached?.has(buffer)) {
    return true;
  }
  if (buffer.byteLength !== 0) {
    return false;
  }
  try {
    new Uint8Array(buffer);
    return false;
  } catch (_error) {
    return true;
  }
}

export function markDetachedArrayBuffer(buffer: ArrayBuffer): void {
  const detached = getDetachedArrayBuffers();

  // Prefer a real detach via the engine-native ArrayBuffer.prototype.transfer
  // (ES2024). This clears the engine-internal [[ArrayBufferData]] slot, so
  // subsequent `new Uint8Array(buffer)` / `new DataView(buffer)` /
  // `buffer.slice()` correctly throw TypeError and existing views observe a
  // detached buffer — an own `byteLength: 0` property cannot do this because
  // those operations read the internal slot, not the prototype getter.
  // `transfer(0)` is also O(1): it hands off ownership instead of doing an O(n)
  // zero-fill memset, so "transferring" a large buffer no longer blocks the JS
  // thread on a full write pass. Only the native implementation is used (see
  // NATIVE_ARRAY_BUFFER_TRANSFER) so this never re-enters the JS polyfill.
  if (NATIVE_ARRAY_BUFFER_TRANSFER) {
    try {
      NATIVE_ARRAY_BUFFER_TRANSFER.call(buffer, 0); // detaches; discard the empty result
      detached?.add(buffer);
      return;
    } catch (_error) {
      // Fall through to the best-effort shadowing path below.
    }
  }

  // Best-effort fallback for engines without ArrayBuffer.prototype.transfer:
  // zero the bytes (so the detached buffer cannot leak its old contents), track
  // it in the WeakSet, and shadow byteLength with an own property.
  const byteLength = buffer.byteLength;
  if (byteLength > 0) {
    new Uint8Array(buffer).fill(0);
  }
  detached?.add(buffer);
  try {
    Object.defineProperty(buffer, "byteLength", {
      value: 0,
      writable: false,
      enumerable: false,
      configurable: true,
    });
  } catch (_error) {
    // Fall back to the WeakSet-based detached tracking when ArrayBuffer
    // instances reject own-property shadowing for byteLength.
  }
}

export function isNonTransferableArrayBuffer(buffer: ArrayBuffer): boolean {
  return getNonTransferableArrayBuffers()?.has(buffer) ?? false;
}

export function markNonTransferableArrayBuffer(buffer: ArrayBuffer): void {
  getNonTransferableArrayBuffers()?.add(buffer);
}
