// @ts-nocheck
/**
 * ES2024 ArrayBuffer transfer polyfills for Hermes engine
 *
 * - ArrayBuffer.prototype.transfer()
 * - ArrayBuffer.prototype.transferToFixedLength()
 */

import { markDetachedArrayBuffer } from "../arraybuffer-detach";

export function installArrayBufferPolyfills(): void {
  const NativeArrayBuffer = ArrayBuffer;
  const resizableBuffers = new WeakSet<ArrayBuffer>();
  const maxByteLengthByBuffer = new WeakMap<ArrayBuffer, number>();

  if (!(NativeArrayBuffer as any).__exactResizableWrapped) {
    const WrappedArrayBuffer = function ArrayBuffer(
      this: ArrayBuffer,
      length: number,
      options?: { maxByteLength?: number },
    ): ArrayBuffer {
      const buffer = new NativeArrayBuffer(length);
      if (options && typeof options === 'object' && options.maxByteLength !== undefined) {
        const maxByteLength = Number(options.maxByteLength);
        if (!Number.isFinite(maxByteLength) || maxByteLength < buffer.byteLength) {
          throw new RangeError('Invalid array buffer max length');
        }
        resizableBuffers.add(buffer);
        maxByteLengthByBuffer.set(buffer, maxByteLength);
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
        return resizableBuffers.has(this);
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
        return maxByteLengthByBuffer.get(this) ?? this.byteLength;
      },
      enumerable: false,
      configurable: true,
    });
  }

  if (typeof (ArrayBuffer.prototype as any).resize !== 'function') {
    Object.defineProperty(ArrayBuffer.prototype, 'resize', {
      value: function resize(this: ArrayBuffer, newLength: number): void {
        if (!(this instanceof ArrayBuffer)) {
          throw new TypeError('resize called on non-ArrayBuffer');
        }
        if (!resizableBuffers.has(this)) {
          throw new TypeError('Cannot resize a fixed-length ArrayBuffer');
        }
        const targetLength = Number(newLength);
        if (!Number.isFinite(targetLength) || targetLength < 0) {
          throw new RangeError('Invalid array buffer length');
        }
        if (targetLength > (maxByteLengthByBuffer.get(this) ?? this.byteLength)) {
          throw new RangeError('Invalid array buffer length');
        }
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // ArrayBuffer.prototype.transfer (ES2024)
  // Creates a new ArrayBuffer with the same byte content, optionally resized,
  // and detaches (neuters) the original. Since we cannot truly detach in pure
  // JS, we zero the original buffer's bytes to simulate detachment.
  // --------------------------------------------------------------------------
  if (typeof ArrayBuffer.prototype.transfer !== 'function') {
    Object.defineProperty(ArrayBuffer.prototype, 'transfer', {
      value: function transfer(this: ArrayBuffer, newLength?: number): ArrayBuffer {
        if (!(this instanceof ArrayBuffer)) {
          throw new TypeError('transfer called on non-ArrayBuffer');
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

        markDetachedArrayBuffer(this);

        return newBuffer;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  // --------------------------------------------------------------------------
  // ArrayBuffer.prototype.transferToFixedLength (ES2024)
  // Same as transfer, but the result is always a non-resizable ArrayBuffer.
  // In our polyfill, all ArrayBuffers are fixed-length, so this is identical
  // to transfer.
  // --------------------------------------------------------------------------
  if (typeof ArrayBuffer.prototype.transferToFixedLength !== 'function') {
    Object.defineProperty(ArrayBuffer.prototype, 'transferToFixedLength', {
      value: function transferToFixedLength(
        this: ArrayBuffer,
        newLength?: number,
      ): ArrayBuffer {
        if (!(this instanceof ArrayBuffer)) {
          throw new TypeError('transferToFixedLength called on non-ArrayBuffer');
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

        markDetachedArrayBuffer(this);

        return newBuffer;
      },
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
