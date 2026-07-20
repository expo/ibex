// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// Cross-repo authority: Exact RFC 0115 §9 and LLP 0367 §§2.2-2.3, 8.

import { Blob } from '../blob/Blob';

const MAX_ENCODED_BYTES = 16 * 1024 * 1024;
const MAX_DECODED_BYTES = 64 * 1024 * 1024;
const MAX_DIMENSION = 8192;
const MAX_PENDING_DECODES = 8;
const MAX_PENDING_ENCODED_BYTES = 32 * 1024 * 1024;
const MAX_LIVE_DECODED_BYTES = 64 * 1024 * 1024;
const U64_MAX_DECIMAL = '18446744073709551615';

const INTRINSIC_ARRAY_BUFFER = ArrayBuffer;
const INTRINSIC_ARRAY_BUFFER_IS_VIEW = INTRINSIC_ARRAY_BUFFER.isView;
const INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH = Object.getOwnPropertyDescriptor(
  INTRINSIC_ARRAY_BUFFER.prototype,
  'byteLength',
)?.get;
const INTRINSIC_UINT8_ARRAY = Uint8Array;
const INTRINSIC_REFLECT_APPLY = Reflect.apply;
const INTRINSIC_BLOB_ARRAY_BUFFER = Blob.prototype.arrayBuffer;
const INTRINSIC_BLOB_SIZE = Object.getOwnPropertyDescriptor(
  Blob.prototype,
  'size',
)?.get;
const INTRINSIC_BLOB_TYPE = Object.getOwnPropertyDescriptor(
  Blob.prototype,
  'type',
)?.get;
const DECODED_PLANE_KEYS = Object.freeze([
  'runtimeAddress',
  'runtimeNonce',
  'sourceId',
  'sourceGeneration',
  'width',
  'height',
  'bytesPerRow',
  'encodedBytes',
  'decodedPremultipliedRgba8',
  'encodedContentSha256',
  'decodedContentSha256',
  'originClean',
  'colorSpace',
  'alphaMode',
  'orientation',
] as const);

export interface ProductionGpuDecodedImageIdentityV1 {
  readonly runtimeAddress: string;
  readonly runtimeNonce: string;
  readonly sourceId: string;
  readonly sourceGeneration: string;
}

/**
 * Immutable Apple-decoder result presented to the private binding. The
 * binding treats every field as untrusted comparison input and takes its own
 * byte owners before publishing an ImageBitmap object.
 */
export interface ProductionGpuDecodedImagePlaneV1 extends ProductionGpuDecodedImageIdentityV1 {
  readonly width: number;
  readonly height: number;
  readonly bytesPerRow: number;
  readonly encodedBytes: ArrayBuffer | ArrayBufferView;
  readonly decodedPremultipliedRgba8: ArrayBuffer | ArrayBufferView;
  readonly encodedContentSha256: string;
  readonly decodedContentSha256: string;
  readonly originClean: boolean;
  readonly colorSpace: 'srgb';
  readonly alphaMode: 'premultiplied';
  readonly orientation: 'top-left';
}

export interface ProductionGpuDecodedImageRequestV1 extends ProductionGpuDecodedImageIdentityV1 {
  readonly mimeType: 'image/png';
  readonly encodedBytes: Uint8Array;
}

/**
 * Construction-private host authority. Implementations decode away from the
 * UI thread and may resolve from any native queue; Promise adoption returns
 * control to the owning JS runtime before wrapper state changes.
 */
export interface ProductionGpuDecodedImageAuthorityV1 {
  readonly decodePng: (
    request: ProductionGpuDecodedImageRequestV1,
  ) => Promise<ProductionGpuDecodedImagePlaneV1>;
}

export interface ProductionGpuExternalImageSnapshotV1 extends ProductionGpuDecodedImageIdentityV1 {
  readonly width: number;
  readonly height: number;
  readonly bytesPerRow: number;
  readonly encodedBytes: Uint8Array;
  readonly decodedPremultipliedRgba8: Uint8Array;
  readonly encodedContentSha256: string;
  readonly decodedContentSha256: string;
  readonly originClean: true;
  readonly usability: 'good';
  readonly colorSpace: 'srgb';
  readonly alphaMode: 'premultiplied';
  readonly orientation: 'top-left';
}

export interface ProductionGpuPrivateImageBitmapFactoryV1 {
  readonly createImageBitmap: (source: Blob) => Promise<object>;
  readonly snapshotForCopy: (
    bitmap: unknown,
  ) => ProductionGpuExternalImageSnapshotV1;
  readonly snapshotForExternalCopy: (
    bitmap: unknown,
    sourceOrigin: Readonly<{ x: number; y: number }>,
    copySize: Readonly<{
      width: number;
      height: number;
      depthOrArrayLayers: number;
    }>,
  ) => ProductionGpuExternalImageSnapshotV1;
  readonly revoke: () => void;
}

interface BitmapState extends ProductionGpuExternalImageSnapshotV1 {
  closed: boolean;
}

function namedError(name: string, message: string): Error {
  const error = new Error(message);
  Object.defineProperty(error, 'name', {
    value: name,
    writable: false,
    enumerable: false,
    configurable: true,
  });
  return error;
}

function canonicalPositiveU64(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) return false;
  return (
    value.length < U64_MAX_DECIMAL.length ||
    (value.length === U64_MAX_DECIMAL.length && value <= U64_MAX_DECIMAL)
  );
}

function incrementU64(value: string): string | undefined {
  if (value === U64_MAX_DECIMAL) return undefined;
  const digits = value.split('');
  let carry = 1;
  for (let index = digits.length - 1; index >= 0 && carry; index -= 1) {
    const next = Number(digits[index]) + carry;
    digits[index] = String(next % 10);
    carry = next >= 10 ? 1 : 0;
  }
  if (carry) digits.unshift('1');
  return digits.join('');
}

function checkedMultiply(left: number, right: number, label: string): number {
  const result = left * right;
  if (!Number.isSafeInteger(result))
    throw new RangeError(`${label} exceeds its bound`);
  return result;
}

function ownedBytes(
  value: ArrayBuffer | ArrayBufferView,
  maximum: number,
  label: string,
): Uint8Array {
  let view: Uint8Array;
  let arrayBufferLength: number | undefined;
  if (INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH !== undefined) {
    try {
      arrayBufferLength = INTRINSIC_REFLECT_APPLY(
        INTRINSIC_ARRAY_BUFFER_BYTE_LENGTH,
        value,
        [],
      ) as number;
    } catch {
      arrayBufferLength = undefined;
    }
  }
  if (arrayBufferLength !== undefined) {
    view = new INTRINSIC_UINT8_ARRAY(value as ArrayBuffer);
  } else if (
    INTRINSIC_REFLECT_APPLY(
      INTRINSIC_ARRAY_BUFFER_IS_VIEW,
      INTRINSIC_ARRAY_BUFFER,
      [value],
    )
  ) {
    const source = value as ArrayBufferView;
    view = new INTRINSIC_UINT8_ARRAY(
      source.buffer,
      source.byteOffset,
      source.byteLength,
    );
  } else {
    throw new TypeError(`${label} must be bytes`);
  }
  if (view.byteLength > maximum)
    throw new RangeError(`${label} exceeds its bound`);
  return view.slice();
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function exactPngMimeType(value: string): 'image/png' {
  const normalized = value.trim().toLowerCase();
  if (normalized !== '' && normalized !== 'image/png') {
    throw namedError(
      'InvalidStateError',
      'createImageBitmap source is not PNG',
    );
  }
  return 'image/png';
}

function captureDecodedPlane(value: unknown): ProductionGpuDecodedImagePlaneV1 {
  if (typeof value !== 'object' || value === null) {
    throw namedError('SecurityError', 'Decoded image plane is not canonical');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== DECODED_PLANE_KEYS.length ||
    keys.some(
      (key) =>
        typeof key !== 'string' ||
        !DECODED_PLANE_KEYS.includes(
          key as (typeof DECODED_PLANE_KEYS)[number],
        ),
    )
  ) {
    throw namedError('SecurityError', 'Decoded image plane is not canonical');
  }
  for (const key of DECODED_PLANE_KEYS) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      throw namedError('SecurityError', 'Decoded image plane is not canonical');
    }
  }
  return Object.freeze({
    runtimeAddress: descriptors.runtimeAddress!.value,
    runtimeNonce: descriptors.runtimeNonce!.value,
    sourceId: descriptors.sourceId!.value,
    sourceGeneration: descriptors.sourceGeneration!.value,
    width: descriptors.width!.value,
    height: descriptors.height!.value,
    bytesPerRow: descriptors.bytesPerRow!.value,
    encodedBytes: descriptors.encodedBytes!.value,
    decodedPremultipliedRgba8: descriptors.decodedPremultipliedRgba8!.value,
    encodedContentSha256: descriptors.encodedContentSha256!.value,
    decodedContentSha256: descriptors.decodedContentSha256!.value,
    originClean: descriptors.originClean!.value,
    colorSpace: descriptors.colorSpace!.value,
    alphaMode: descriptors.alphaMode!.value,
    orientation: descriptors.orientation!.value,
  }) as ProductionGpuDecodedImagePlaneV1;
}

/**
 * Creates the checkpoint ImageBitmap carrier without installing a global,
 * WebGPU prototype member, codec, or support bit. The returned bitmap brand
 * is factory-local and therefore runtime-generation-local.
 */
export function createProductionGpuPrivateImageBitmapFactoryV1(
  runtime: Readonly<{ runtimeAddress: string; runtimeNonce: string }>,
  authority: ProductionGpuDecodedImageAuthorityV1,
): ProductionGpuPrivateImageBitmapFactoryV1 {
  if (
    !canonicalPositiveU64(runtime.runtimeAddress) ||
    !canonicalPositiveU64(runtime.runtimeNonce) ||
    typeof authority !== 'object' ||
    authority === null ||
    INTRINSIC_BLOB_SIZE === undefined ||
    INTRINSIC_BLOB_TYPE === undefined
  ) {
    throw new TypeError('Invalid private decoded-image construction authority');
  }
  const authorityDescriptors = Object.getOwnPropertyDescriptors(authority);
  const authorityKeys = Reflect.ownKeys(authorityDescriptors);
  const decodeDescriptor = authorityDescriptors.decodePng;
  if (
    authorityKeys.length !== 1 ||
    authorityKeys[0] !== 'decodePng' ||
    !decodeDescriptor?.enumerable ||
    !('value' in decodeDescriptor) ||
    typeof decodeDescriptor.value !== 'function'
  ) {
    throw new TypeError('Invalid private decoded-image construction authority');
  }
  const decodePng =
    decodeDescriptor.value as ProductionGpuDecodedImageAuthorityV1['decodePng'];
  const runtimeAddress = runtime.runtimeAddress;
  const runtimeNonce = runtime.runtimeNonce;
  const states = new WeakMap<object, BitmapState>();
  const liveStates = new Set<BitmapState>();
  let nextSourceId = '1';
  let exhausted = false;
  let active = true;
  let pendingCount = 0;
  let pendingEncodedBytes = 0;
  let liveDecodedBytes = 0;

  const prototype = Object.create(null) as object;
  const requireState = (value: unknown): BitmapState => {
    if (typeof value !== 'object' || value === null) {
      throw new TypeError('Incompatible ImageBitmap receiver');
    }
    const state = states.get(value);
    if (!state) throw new TypeError('Incompatible ImageBitmap receiver');
    return state;
  };
  Object.defineProperty(prototype, 'width', {
    get(this: object) {
      const state = requireState(this);
      return state.closed ? 0 : state.width;
    },
    enumerable: true,
    configurable: false,
  });
  Object.defineProperty(prototype, 'height', {
    get(this: object) {
      const state = requireState(this);
      return state.closed ? 0 : state.height;
    },
    enumerable: true,
    configurable: false,
  });
  Object.defineProperty(prototype, 'close', {
    value: function (this: object): void {
      const state = requireState(this);
      if (state.closed) return;
      state.closed = true;
      liveStates.delete(state);
      liveDecodedBytes -= state.decodedPremultipliedRgba8.byteLength;
    },
    writable: false,
    enumerable: true,
    configurable: false,
  });
  Object.freeze(prototype);

  const createImageBitmap = async (source: Blob): Promise<object> => {
    if (!active)
      throw namedError('SecurityError', 'Decoded-image realm is revoked');
    if (typeof source !== 'object' || source === null) {
      throw new TypeError(
        'createImageBitmap checkpoint source must be an Ibex Blob',
      );
    }
    const sourceSize = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_BLOB_SIZE,
      source,
      [],
    ) as number;
    const sourceType = INTRINSIC_REFLECT_APPLY(
      INTRINSIC_BLOB_TYPE,
      source,
      [],
    ) as string;
    const mimeType = exactPngMimeType(sourceType);
    if (!Number.isSafeInteger(sourceSize) || sourceSize <= 0) {
      throw namedError(
        'InvalidStateError',
        'createImageBitmap source is empty',
      );
    }
    if (sourceSize > MAX_ENCODED_BYTES) {
      throw new RangeError(
        'createImageBitmap encoded source exceeds its bound',
      );
    }
    if (
      pendingCount >= MAX_PENDING_DECODES ||
      pendingEncodedBytes > MAX_PENDING_ENCODED_BYTES - sourceSize
    ) {
      throw new RangeError(
        'createImageBitmap pending decode budget is exhausted',
      );
    }
    if (exhausted)
      throw new RangeError('ImageBitmap source identity space is exhausted');
    const sourceId = nextSourceId;
    const successor = incrementU64(sourceId);
    exhausted = successor === undefined;
    if (successor !== undefined) nextSourceId = successor;

    pendingCount += 1;
    pendingEncodedBytes += sourceSize;
    let encodedBytes: Uint8Array;
    let plane: ProductionGpuDecodedImagePlaneV1;
    try {
      const encodedBuffer = (await INTRINSIC_REFLECT_APPLY(
        INTRINSIC_BLOB_ARRAY_BUFFER,
        source,
        [],
      )) as ArrayBuffer;
      encodedBytes = ownedBytes(
        encodedBuffer,
        MAX_ENCODED_BYTES,
        'createImageBitmap encoded source',
      );
      if (encodedBytes.byteLength !== sourceSize) {
        throw namedError(
          'InvalidStateError',
          'createImageBitmap Blob snapshot changed size',
        );
      }
      if (!active) {
        throw namedError('SecurityError', 'Decoded-image realm is revoked');
      }
      plane = captureDecodedPlane(
        await INTRINSIC_REFLECT_APPLY(decodePng, authority, [
          Object.freeze({
            runtimeAddress,
            runtimeNonce,
            sourceId,
            sourceGeneration: '1',
            mimeType,
            encodedBytes: encodedBytes.slice(),
          }),
        ]),
      );
    } finally {
      pendingCount -= 1;
      pendingEncodedBytes -= sourceSize;
    }
    if (!active)
      throw namedError('SecurityError', 'Decoded-image realm is revoked');
    if (
      typeof plane !== 'object' ||
      plane === null ||
      plane.runtimeAddress !== runtimeAddress ||
      plane.runtimeNonce !== runtimeNonce ||
      plane.sourceId !== sourceId ||
      plane.sourceGeneration !== '1'
    ) {
      throw namedError(
        'SecurityError',
        'Decoded image identity does not match its request',
      );
    }
    if (
      !Number.isSafeInteger(plane.width) ||
      !Number.isSafeInteger(plane.height) ||
      plane.width <= 0 ||
      plane.height <= 0 ||
      plane.width > MAX_DIMENSION ||
      plane.height > MAX_DIMENSION
    ) {
      throw new RangeError('Decoded image dimensions exceed their bound');
    }
    const expectedBytesPerRow = checkedMultiply(
      plane.width,
      4,
      'Decoded image row bytes',
    );
    const expectedDecodedBytes = checkedMultiply(
      expectedBytesPerRow,
      plane.height,
      'Decoded image bytes',
    );
    if (
      plane.bytesPerRow !== expectedBytesPerRow ||
      expectedDecodedBytes > MAX_DECODED_BYTES
    ) {
      throw new RangeError('Decoded image plane shape exceeds its bound');
    }
    const returnedEncoded = ownedBytes(
      plane.encodedBytes,
      MAX_ENCODED_BYTES,
      'Decoded image encoded source',
    );
    const decoded = ownedBytes(
      plane.decodedPremultipliedRgba8,
      MAX_DECODED_BYTES,
      'Decoded image pixels',
    );
    if (
      !sameBytes(encodedBytes, returnedEncoded) ||
      decoded.byteLength !== expectedDecodedBytes
    ) {
      throw namedError(
        'SecurityError',
        'Decoded image bytes do not match their source plane',
      );
    }
    if (
      plane.originClean !== true ||
      plane.colorSpace !== 'srgb' ||
      plane.alphaMode !== 'premultiplied' ||
      plane.orientation !== 'top-left' ||
      typeof plane.encodedContentSha256 !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(plane.encodedContentSha256) ||
      typeof plane.decodedContentSha256 !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(plane.decodedContentSha256)
    ) {
      throw namedError(
        'SecurityError',
        'Decoded image metadata is not canonical',
      );
    }
    if (liveDecodedBytes > MAX_LIVE_DECODED_BYTES - decoded.byteLength) {
      throw new RangeError('Decoded image live-byte budget is exhausted');
    }
    const state: BitmapState = {
      runtimeAddress,
      runtimeNonce,
      sourceId,
      sourceGeneration: '1',
      width: plane.width,
      height: plane.height,
      bytesPerRow: plane.bytesPerRow,
      encodedBytes: returnedEncoded,
      decodedPremultipliedRgba8: decoded,
      encodedContentSha256: plane.encodedContentSha256,
      decodedContentSha256: plane.decodedContentSha256,
      originClean: true,
      usability: 'good',
      colorSpace: 'srgb',
      alphaMode: 'premultiplied',
      orientation: 'top-left',
      closed: false,
    };
    const bitmap = Object.create(prototype) as object;
    states.set(bitmap, state);
    liveStates.add(state);
    liveDecodedBytes += decoded.byteLength;
    return Object.preventExtensions(bitmap);
  };

  const snapshotState = (
    state: BitmapState,
  ): ProductionGpuExternalImageSnapshotV1 => Object.freeze({
    runtimeAddress: state.runtimeAddress,
    runtimeNonce: state.runtimeNonce,
    sourceId: state.sourceId,
    sourceGeneration: state.sourceGeneration,
    width: state.width,
    height: state.height,
    bytesPerRow: state.bytesPerRow,
    encodedBytes: state.encodedBytes.slice(),
    decodedPremultipliedRgba8: state.decodedPremultipliedRgba8.slice(),
    encodedContentSha256: state.encodedContentSha256,
    decodedContentSha256: state.decodedContentSha256,
    originClean: true,
    usability: 'good',
    colorSpace: 'srgb',
    alphaMode: 'premultiplied',
    orientation: 'top-left',
  });

  return Object.freeze({
    createImageBitmap,
    snapshotForCopy(bitmap: unknown): ProductionGpuExternalImageSnapshotV1 {
      if (!active)
        throw namedError('SecurityError', 'Decoded-image realm is revoked');
      const state = requireState(bitmap);
      if (state.closed)
        throw namedError('InvalidStateError', 'ImageBitmap is closed');
      // Queue content processing owns a fresh immutable plane. Later close(),
      // host mutation, or another upload cannot change the selected bytes.
      return snapshotState(state);
    },
    snapshotForExternalCopy(
      bitmap: unknown,
      sourceOrigin: Readonly<{ x: number; y: number }>,
      copySize: Readonly<{
        width: number;
        height: number;
        depthOrArrayLayers: number;
      }>,
    ): ProductionGpuExternalImageSnapshotV1 {
      if (!active)
        throw namedError('SecurityError', 'Decoded-image realm is revoked');
      const state = requireState(bitmap);
      // This checkpoint factory only mints origin-clean sources. Keep the
      // security predicate explicit and before every range/usability check so
      // expanding the private source profile cannot silently reorder it.
      if (state.originClean !== true) {
        throw namedError('SecurityError', 'ImageBitmap is not origin-clean');
      }
      if (
        sourceOrigin.x > state.width ||
        copySize.width > state.width - sourceOrigin.x ||
        sourceOrigin.y > state.height ||
        copySize.height > state.height - sourceOrigin.y ||
        copySize.depthOrArrayLayers > 1
      ) {
        throw namedError(
          'OperationError',
          'ImageBitmap copy source range is out of bounds',
        );
      }
      if (state.closed)
        throw namedError('InvalidStateError', 'ImageBitmap is closed');
      return snapshotState(state);
    },
    revoke(): void {
      if (!active) return;
      active = false;
      for (const state of liveStates) state.closed = true;
      liveStates.clear();
      liveDecodedBytes = 0;
    },
  });
}
