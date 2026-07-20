const DETACHED_ARRAY_BUFFERS_MIRROR = Symbol.for("exact.detachedArrayBuffers");
const PATCHED_ARRAY_BUFFER_BYTE_LENGTH = Symbol.for("exact.patchedArrayBufferByteLength");

const INTRINSIC_WEAK_SET_HAS = WeakSet.prototype.has;
const INTRINSIC_WEAK_SET_ADD = WeakSet.prototype.add;
const INTRINSIC_WEAK_SET_CONSTRUCTOR = WeakSet;
const INTRINSIC_REFLECT_APPLY = Reflect.apply;
const INTRINSIC_REFLECT_CONSTRUCT = Reflect.construct;
const INTRINSIC_GLOBAL_OBJECT = globalThis;
const INTRINSIC_UINT8_ARRAY = Uint8Array;
const INTRINSIC_UINT8_ARRAY_FILL = Uint8Array.prototype.fill;
const INTRINSIC_OBJECT_DEFINE_PROPERTY = Object.defineProperty;
const INTRINSIC_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR =
  Object.getOwnPropertyDescriptor;
const INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_DESCRIPTOR =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength");

// These sets are runtime authority, so neither may be exposed through a
// public/global symbol that app code can replace, clear, or call delete() on.
// Capture their operations as well: resolving `.has` or `.add` dynamically
// would let app code poison WeakSet.prototype after bootstrap. The detached
// set is mirrored best-effort to the legacy symbol for the separate Buffer
// builtin, but that app-visible mirror is never trusted by this module.
const DETACHED_ARRAY_BUFFERS = new WeakSet<ArrayBuffer>();
const NON_TRANSFERABLE_ARRAY_BUFFERS = new WeakSet<ArrayBuffer>();

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

function isIntrinsicWeakSet(value: unknown): value is WeakSet<ArrayBuffer> {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) {
    return false;
  }
  try {
    INTRINSIC_REFLECT_APPLY(INTRINSIC_WEAK_SET_HAS, value, [value]);
    return true;
  } catch {
    return false;
  }
}

function getDetachedArrayBufferMirror(): WeakSet<ArrayBuffer> | null {
  const globalObject = INTRINSIC_GLOBAL_OBJECT as any;
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = INTRINSIC_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(
      globalObject,
      DETACHED_ARRAY_BUFFERS_MIRROR,
    );
  } catch {
    return null;
  }
  if (descriptor) {
    return 'value' in descriptor && isIntrinsicWeakSet(descriptor.value)
      ? descriptor.value
      : null;
  }

  let mirror: WeakSet<ArrayBuffer>;
  try {
    mirror = INTRINSIC_REFLECT_CONSTRUCT(
      INTRINSIC_WEAK_SET_CONSTRUCTOR,
      [],
    ) as WeakSet<ArrayBuffer>;
    INTRINSIC_OBJECT_DEFINE_PROPERTY(
      globalObject,
      DETACHED_ARRAY_BUFFERS_MIRROR,
      {
        value: mirror,
        writable: true,
        enumerable: false,
        configurable: true,
      },
    );
  } catch {
    return null;
  }
  return mirror;
}

function isTrackedDetachedArrayBuffer(buffer: ArrayBuffer): boolean {
  return INTRINSIC_REFLECT_APPLY(
    INTRINSIC_WEAK_SET_HAS,
    DETACHED_ARRAY_BUFFERS,
    [buffer],
  ) as boolean;
}

function trackDetachedArrayBuffer(buffer: ArrayBuffer): void {
  INTRINSIC_REFLECT_APPLY(
    INTRINSIC_WEAK_SET_ADD,
    DETACHED_ARRAY_BUFFERS,
    [buffer],
  );
  const mirror = getDetachedArrayBufferMirror();
  if (!mirror) return;
  try {
    INTRINSIC_REFLECT_APPLY(INTRINSIC_WEAK_SET_ADD, mirror, [buffer]);
  } catch {
    // The realm-visible compatibility mirror is never lifecycle authority.
  }
}

function getNonTransferableArrayBuffers(): WeakSet<ArrayBuffer> {
  return NON_TRANSFERABLE_ARRAY_BUFFERS;
}

function installDetachedArrayBufferByteLengthPatch(): void {
  const proto = ArrayBuffer.prototype as ArrayBuffer & {
    [PATCHED_ARRAY_BUFFER_BYTE_LENGTH]?: boolean;
  };
  if (proto[PATCHED_ARRAY_BUFFER_BYTE_LENGTH]) {
    return;
  }

  const descriptor = INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_DESCRIPTOR;
  if (!descriptor?.get) {
    return;
  }

  try {
    INTRINSIC_OBJECT_DEFINE_PROPERTY(ArrayBuffer.prototype, "byteLength", {
      get: function byteLength(this: ArrayBuffer): number {
        if (isTrackedDetachedArrayBuffer(this)) {
          return 0;
        }
        return INTRINSIC_REFLECT_APPLY(descriptor.get!, this, []) as number;
      },
      enumerable: descriptor.enumerable ?? false,
      configurable: descriptor.configurable ?? true,
    });
    INTRINSIC_OBJECT_DEFINE_PROPERTY(proto, PATCHED_ARRAY_BUFFER_BYTE_LENGTH, {
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
  if (isTrackedDetachedArrayBuffer(buffer)) {
    return true;
  }
  const byteLength = INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_DESCRIPTOR?.get
    ? INTRINSIC_REFLECT_APPLY(
        INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_DESCRIPTOR.get,
        buffer,
        [],
      ) as number
    : buffer.byteLength;
  if (byteLength !== 0) {
    return false;
  }
  try {
    INTRINSIC_REFLECT_CONSTRUCT(INTRINSIC_UINT8_ARRAY, [buffer]);
    return false;
  } catch (_error) {
    return true;
  }
}

export function markDetachedArrayBuffer(buffer: ArrayBuffer): void {
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
      INTRINSIC_REFLECT_APPLY(NATIVE_ARRAY_BUFFER_TRANSFER, buffer, [0]);
      trackDetachedArrayBuffer(buffer);
      return;
    } catch (_error) {
      // Fall through to the best-effort shadowing path below.
    }
  }

  // Best-effort fallback for engines without ArrayBuffer.prototype.transfer:
  // zero the bytes (so the detached buffer cannot leak its old contents), track
  // it in the WeakSet, and shadow byteLength with an own property.
  const byteLength = INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_DESCRIPTOR?.get
    ? INTRINSIC_REFLECT_APPLY(
        INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH_DESCRIPTOR.get,
        buffer,
        [],
      ) as number
    : buffer.byteLength;
  if (byteLength > 0) {
    const view = INTRINSIC_REFLECT_CONSTRUCT(
      INTRINSIC_UINT8_ARRAY,
      [buffer],
    ) as Uint8Array;
    INTRINSIC_REFLECT_APPLY(INTRINSIC_UINT8_ARRAY_FILL, view, [0]);
  }
  trackDetachedArrayBuffer(buffer);
  try {
    INTRINSIC_OBJECT_DEFINE_PROPERTY(buffer, "byteLength", {
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
  return INTRINSIC_REFLECT_APPLY(
    INTRINSIC_WEAK_SET_HAS,
    getNonTransferableArrayBuffers(),
    [buffer],
  ) as boolean;
}

export function markNonTransferableArrayBuffer(buffer: ArrayBuffer): void {
  INTRINSIC_REFLECT_APPLY(
    INTRINSIC_WEAK_SET_ADD,
    getNonTransferableArrayBuffers(),
    [buffer],
  );
}
