// @ts-nocheck
/**
 * ES2024 ArrayBuffer transfer polyfills for Hermes engine
 *
 * - ArrayBuffer.prototype.transfer()
 * - ArrayBuffer.prototype.transferToFixedLength()
 */

import {
  isNonTransferableArrayBuffer,
  markDetachedArrayBuffer,
} from "../arraybuffer-detach";

const ARRAY_BUFFER_TRANSFER_FENCE = Symbol.for(
  'exact.arrayBufferTransferFence',
);
const ENGINE_ARRAY_BUFFER_TRANSFER =
  typeof (ArrayBuffer.prototype as any).transfer === 'function'
    ? (ArrayBuffer.prototype as any).transfer as (
      this: ArrayBuffer,
      newLength?: number,
    ) => ArrayBuffer
    : undefined;
const ENGINE_ARRAY_BUFFER_TRANSFER_TO_FIXED_LENGTH =
  typeof (ArrayBuffer.prototype as any).transferToFixedLength === 'function'
    ? (ArrayBuffer.prototype as any).transferToFixedLength as (
      this: ArrayBuffer,
      newLength?: number,
    ) => ArrayBuffer
    : undefined;

function installTransferFence(
  name: 'transfer' | 'transferToFixedLength',
  nativeTransfer: ((this: ArrayBuffer, newLength?: number) => ArrayBuffer) |
    undefined,
): void {
  const current = (ArrayBuffer.prototype as any)[name];
  if (typeof current === 'function' && current[ARRAY_BUFFER_TRANSFER_FENCE]) {
    return;
  }
  const fencedTransfer = function (
    this: ArrayBuffer,
    newLength?: number,
  ): ArrayBuffer {
    if (!(this instanceof ArrayBuffer)) {
      throw new TypeError(`${name} called on non-ArrayBuffer`);
    }
    if (isNonTransferableArrayBuffer(this)) {
      throw new TypeError('This ArrayBuffer is non-transferable');
    }
    if (nativeTransfer) {
      return newLength === undefined
        ? nativeTransfer.call(this)
        : nativeTransfer.call(this, newLength);
    }

    const oldLength = this.byteLength;
    const targetLength = newLength !== undefined ? Number(newLength) : oldLength;
    if (targetLength < 0 || !Number.isFinite(targetLength)) {
      throw new RangeError('Invalid array buffer length');
    }
    const newBuffer = new ArrayBuffer(targetLength);
    const copyLength = Math.min(oldLength, targetLength);
    if (copyLength > 0) {
      const source = new Uint8Array(this, 0, copyLength);
      const target = new Uint8Array(newBuffer, 0, copyLength);
      target.set(source);
    }
    // On engines without a native transfer intrinsic this remains Ibex's
    // tracked/zeroed fallback; it does not claim native Hermes detachment.
    markDetachedArrayBuffer(this);
    return newBuffer;
  };
  Object.defineProperty(fencedTransfer, ARRAY_BUFFER_TRANSFER_FENCE, {
    value: true,
  });
  Object.defineProperty(ArrayBuffer.prototype, name, {
    value: fencedTransfer,
    writable: true,
    enumerable: false,
    configurable: true,
  });
}

export function installArrayBufferPolyfills(): void {
  const NativeArrayBuffer = ArrayBuffer;

  // Resizable ArrayBuffers cannot be faithfully polyfilled in pure JS: growing a
  // buffer in place would require reallocating its backing store and rewiring
  // every existing TypedArray/DataView view to the new store, which the language
  // does not expose. A previous version advertised `resizable: true` (and a
  // matching `maxByteLength`) plus a `resize()` that ran every range check but
  // then returned without reallocating, copying, or updating any length — so
  // feature-detecting code (incremental parsers, growable-buffer logic) saw a
  // working growable buffer and silently corrupted data. We now refuse to
  // advertise a capability we cannot deliver: every buffer is reported as
  // fixed-length and `resize()` throws, matching the spec's behavior for
  // `resize()` on a non-resizable ArrayBuffer. (ENG-22984)
  if (!(NativeArrayBuffer as any).__exactResizableWrapped) {
    const WrappedArrayBuffer = function ArrayBuffer(
      this: ArrayBuffer,
      length: number,
      options?: { maxByteLength?: number },
    ): ArrayBuffer {
      const buffer = new NativeArrayBuffer(length);
      if (options && typeof options === 'object' && options.maxByteLength !== undefined) {
        // Validate the option the way the spec constructor would (a bad
        // maxByteLength must still throw), then discard it: we degrade to a
        // fixed-length buffer, which honestly reports `resizable === false`.
        const maxByteLength = Number(options.maxByteLength);
        if (!Number.isFinite(maxByteLength) || maxByteLength < buffer.byteLength) {
          throw new RangeError('Invalid array buffer max length');
        }
      }
      return buffer;
    } as unknown as typeof ArrayBuffer;

    WrappedArrayBuffer.prototype = NativeArrayBuffer.prototype;
    Object.setPrototypeOf(WrappedArrayBuffer, NativeArrayBuffer);
    Object.defineProperty(WrappedArrayBuffer, '__exactResizableWrapped', {
      value: true,
      configurable: true,
    });
    (globalThis as any).ArrayBuffer = WrappedArrayBuffer;
  }

  if (!Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')) {
    Object.defineProperty(ArrayBuffer.prototype, 'resizable', {
      get: function resizable(this: ArrayBuffer): boolean {
        if (!(this instanceof ArrayBuffer)) {
          throw new TypeError('resizable called on non-ArrayBuffer');
        }
        // Pure-JS ArrayBuffers are never resizable (see note above).
        return false;
      },
      enumerable: false,
      configurable: true,
    });
  }

  if (!Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'maxByteLength')) {
    Object.defineProperty(ArrayBuffer.prototype, 'maxByteLength', {
      get: function maxByteLength(this: ArrayBuffer): number {
        if (!(this instanceof ArrayBuffer)) {
          throw new TypeError('maxByteLength called on non-ArrayBuffer');
        }
        // For a non-resizable buffer, maxByteLength === byteLength.
        return this.byteLength;
      },
      enumerable: false,
      configurable: true,
    });
  }

  if (typeof (ArrayBuffer.prototype as any).resize !== 'function') {
    Object.defineProperty(ArrayBuffer.prototype, 'resize', {
      value: function resize(this: ArrayBuffer, _newLength: number): void {
        if (!(this instanceof ArrayBuffer)) {
          throw new TypeError('resize called on non-ArrayBuffer');
        }
        // Every buffer this polyfill produces is fixed-length; resizing in place
        // is not expressible in pure JS. Throw rather than silently no-op (which
        // would desync byteLength from the buffer's views and corrupt data).
        throw new TypeError(
          'ArrayBuffer.prototype.resize called on a non-resizable ArrayBuffer ' +
            '(resizable ArrayBuffers are not supported by this runtime)',
        );
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // Fence both engine-native and fallback transfer entry points. The runtime
  // installs these wrappers before app code can capture an unfenced native
  // method, while internal detachment continues to use its separately captured
  // engine intrinsic.
  installTransferFence('transfer', ENGINE_ARRAY_BUFFER_TRANSFER);
  installTransferFence(
    'transferToFixedLength',
    ENGINE_ARRAY_BUFFER_TRANSFER_TO_FIXED_LENGTH,
  );
}
