const DETACHED_ARRAY_BUFFERS = Symbol.for("exact.detachedArrayBuffers");
const NON_TRANSFERABLE_ARRAY_BUFFERS = Symbol.for("exact.nonTransferableArrayBuffers");
const PATCHED_ARRAY_BUFFER_BYTE_LENGTH = Symbol.for("exact.patchedArrayBufferByteLength");

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
  const byteLength = buffer.byteLength;
  if (byteLength > 0) {
    new Uint8Array(buffer).fill(0);
  }
  const detached = getDetachedArrayBuffers();
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
