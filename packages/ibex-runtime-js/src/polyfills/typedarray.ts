function normalizeTypedArrayIndex(index: number | undefined, length: number): number {
  if (index === undefined) {
    return 0;
  }

  let value = Number(index);
  if (!Number.isFinite(value) || value === 0) {
    return 0;
  }

  value = value < 0 ? Math.ceil(value) : Math.floor(value);
  if (value < 0) {
    return Math.max(length + value, 0);
  }
  return Math.min(value, length);
}

export function installTypedArrayPolyfills(): void {
  const typedArrayNames = [
    'Int8Array',
    'Uint8Array',
    'Uint8ClampedArray',
    'Int16Array',
    'Uint16Array',
    'Int32Array',
    'Uint32Array',
    'Float32Array',
    'Float64Array',
  ];
  if (typeof (globalThis as any).BigInt64Array === 'function') {
    typedArrayNames.push('BigInt64Array');
  }
  if (typeof (globalThis as any).BigUint64Array === 'function') {
    typedArrayNames.push('BigUint64Array');
  }

  for (const ctorName of typedArrayNames) {
    const TypedArrayCtor = (globalThis as any)[ctorName] as
      | {
          prototype: { subarray?: (begin?: number, end?: number) => ArrayBufferView };
          BYTES_PER_ELEMENT?: number;
        }
      | undefined;
    if (!TypedArrayCtor || typeof TypedArrayCtor.prototype?.subarray !== 'function') {
      continue;
    }

    const originalSubarray = TypedArrayCtor.prototype.subarray as typeof Uint8Array.prototype.subarray & {
      __exactZeroLengthWrapped?: boolean;
    };
    if (originalSubarray.__exactZeroLengthWrapped) {
      continue;
    }

    const bytesPerElement =
      TypedArrayCtor.BYTES_PER_ELEMENT ??
      (TypedArrayCtor.prototype as { BYTES_PER_ELEMENT?: number }).BYTES_PER_ELEMENT ??
      1;

    const patchedSubarray = function (
      this: { buffer: ArrayBufferLike; byteOffset: number; byteLength: number; length?: number },
      begin?: number,
      end?: number
    ): ArrayBufferView {
      const result = originalSubarray.call(this as any, begin, end);
      if (
        result.byteLength !== 0 ||
        result.buffer !== this.buffer ||
        !(this.buffer instanceof ArrayBuffer)
      ) {
        return result;
      }

      const length = typeof this.length === 'number'
        ? this.length
        : Math.floor(this.byteLength / bytesPerElement);
      const start = normalizeTypedArrayIndex(begin, length);
      const finish = end === undefined ? length : normalizeTypedArrayIndex(end, length);
      if (finish !== start) {
        return result;
      }

      const correctedByteOffset = this.byteOffset + start * bytesPerElement;
      try {
        Object.defineProperty(result, 'byteOffset', {
          value: correctedByteOffset,
          configurable: true,
        });
        return result;
      } catch (_error) {
        return new (TypedArrayCtor as any)(
          this.buffer,
          correctedByteOffset,
          0
        );
      }
    };

    Object.defineProperty(patchedSubarray, '__exactZeroLengthWrapped', {
      value: true,
      configurable: true,
    });
    Object.defineProperty(TypedArrayCtor.prototype, 'subarray', {
      value: patchedSubarray,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }
}
