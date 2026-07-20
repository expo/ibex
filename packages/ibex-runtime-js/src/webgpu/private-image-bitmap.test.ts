import { describe, expect, test } from 'bun:test';

import { Blob } from '../blob/Blob';
import {
  createProductionGpuPrivateImageBitmapFactoryV1,
  type ProductionGpuDecodedImageAuthorityV1,
  type ProductionGpuDecodedImagePlaneV1,
  type ProductionGpuDecodedImageRequestV1,
} from './private-image-bitmap';

const ENCODED = Uint8Array.from([0x89, 0x50, 0x4e, 0x47]);
const ENCODED_SHA = '11'.repeat(32);
const DECODED_SHA = '22'.repeat(32);

function authority(
  mutate?: (
    plane: ProductionGpuDecodedImagePlaneV1,
    request: ProductionGpuDecodedImageRequestV1,
  ) => ProductionGpuDecodedImagePlaneV1,
): ProductionGpuDecodedImageAuthorityV1 {
  return Object.freeze({
    async decodePng(request: ProductionGpuDecodedImageRequestV1) {
      const plane: ProductionGpuDecodedImagePlaneV1 = Object.freeze({
        runtimeAddress: request.runtimeAddress,
        runtimeNonce: request.runtimeNonce,
        sourceId: request.sourceId,
        sourceGeneration: request.sourceGeneration,
        width: 2,
        height: 1,
        bytesPerRow: 8,
        encodedBytes: request.encodedBytes.slice(),
        decodedPremultipliedRgba8: Uint8Array.from([
          0xff, 0, 0, 0xff, 0, 0xff, 0, 0x80,
        ]),
        encodedContentSha256: ENCODED_SHA,
        decodedContentSha256: DECODED_SHA,
        originClean: true,
        colorSpace: 'srgb',
        alphaMode: 'premultiplied',
        orientation: 'top-left',
      });
      return mutate?.(plane, request) ?? plane;
    },
  });
}

function factory(decoder = authority()) {
  return createProductionGpuPrivateImageBitmapFactoryV1(
    { runtimeAddress: '73', runtimeNonce: '91' },
    decoder,
  );
}

describe('construction-private ImageBitmap carrier', () => {
  test('captures decoder authority without invoking accessors', () => {
    let getterRuns = 0;
    const accessor = Object.defineProperty({}, 'decodePng', {
      enumerable: true,
      get() {
        getterRuns += 1;
        return authority().decodePng;
      },
    });
    expect(() =>
      createProductionGpuPrivateImageBitmapFactoryV1(
        { runtimeAddress: '73', runtimeNonce: '91' },
        accessor as ProductionGpuDecodedImageAuthorityV1,
      ),
    ).toThrow(/construction authority/u);
    expect(getterRuns).toBe(0);
  });

  test('captures decoded planes without invoking accessors', async () => {
    let getterRuns = 0;
    const base = authority();
    const accessorPlane = Object.freeze({
      async decodePng(request: ProductionGpuDecodedImageRequestV1) {
        const plane = { ...(await base.decodePng(request)) };
        Object.defineProperty(plane, 'width', {
          enumerable: true,
          get() {
            getterRuns += 1;
            return 2;
          },
        });
        return plane as ProductionGpuDecodedImagePlaneV1;
      },
    });
    await expect(
      factory(accessorPlane).createImageBitmap(new Blob([ENCODED])),
    ).rejects.toMatchObject({ name: 'SecurityError' });
    expect(getterRuns).toBe(0);
  });

  test('debits pending decode budgets before the first async source read', async () => {
    const base = authority();
    const gates: Array<() => Promise<void>> = [];
    const deferred = Object.freeze({
      decodePng(request: ProductionGpuDecodedImageRequestV1) {
        return new Promise<ProductionGpuDecodedImagePlaneV1>((resolve) => {
          gates.push(async () => resolve(await base.decodePng(request)));
        });
      },
    });
    const images = factory(deferred);
    const admitted = Array.from({ length: 8 }, () =>
      images.createImageBitmap(new Blob([ENCODED])),
    );
    await expect(images.createImageBitmap(new Blob([ENCODED]))).rejects.toThrow(
      /pending decode budget/u,
    );
    expect(gates).toHaveLength(8);
    await Promise.all(gates.map((release) => release()));
    await expect(Promise.all(admitted)).resolves.toHaveLength(8);
  });

  test('captures a Blob through a runtime-qualified immutable plane', async () => {
    let retainedRequest: ProductionGpuDecodedImageRequestV1 | undefined;
    const decoder = authority((plane, request) => {
      retainedRequest = request;
      return plane;
    });
    const images = factory(decoder);
    const bitmap = await images.createImageBitmap(
      new Blob([ENCODED], { type: 'image/png' }),
    );

    expect((bitmap as { width: number }).width).toBe(2);
    expect((bitmap as { height: number }).height).toBe(1);
    expect(retainedRequest).toMatchObject({
      runtimeAddress: '73',
      runtimeNonce: '91',
      sourceId: '1',
      sourceGeneration: '1',
      mimeType: 'image/png',
    });

    const first = images.snapshotForCopy(bitmap);
    first.decodedPremultipliedRgba8[0] = 0;
    retainedRequest!.encodedBytes[0] = 0;
    const second = images.snapshotForCopy(bitmap);
    expect(second.encodedBytes).toEqual(ENCODED);
    expect(second.decodedPremultipliedRgba8[0]).toBe(0xff);
    expect(second).toMatchObject({
      runtimeAddress: '73',
      runtimeNonce: '91',
      sourceId: '1',
      sourceGeneration: '1',
      bytesPerRow: 8,
      originClean: true,
      colorSpace: 'srgb',
      alphaMode: 'premultiplied',
      orientation: 'top-left',
    });
  });

  test('brands bitmaps per construction and closes without reusing identity', async () => {
    const firstFactory = factory();
    const secondFactory = factory();
    const first = await firstFactory.createImageBitmap(new Blob([ENCODED]));
    const second = await firstFactory.createImageBitmap(new Blob([ENCODED]));

    expect(firstFactory.snapshotForCopy(first).sourceId).toBe('1');
    expect(firstFactory.snapshotForCopy(second).sourceId).toBe('2');
    expect(() => secondFactory.snapshotForCopy(first)).toThrow(TypeError);

    (first as { close(): void }).close();
    expect((first as { width: number }).width).toBe(0);
    expect(() => firstFactory.snapshotForCopy(first)).toThrow(/closed/u);
  });

  test('checks external-copy range before usability and snapshots only after both pass', async () => {
    const images = factory();
    const bitmap = await images.createImageBitmap(new Blob([ENCODED]));
    const snapshot = images.snapshotForExternalCopy(
      bitmap,
      { x: 0, y: 0 },
      { width: 2, height: 1, depthOrArrayLayers: 1 },
    );
    expect(snapshot).toMatchObject({ width: 2, height: 1, usability: 'good' });

    (bitmap as { close(): void }).close();
    expect(() => images.snapshotForExternalCopy(
      bitmap,
      { x: 2, y: 0 },
      { width: 1, height: 1, depthOrArrayLayers: 1 },
    )).toThrowError(expect.objectContaining({ name: 'OperationError' }));
    expect(() => images.snapshotForExternalCopy(
      bitmap,
      { x: 0, y: 0 },
      { width: 1, height: 1, depthOrArrayLayers: 1 },
    )).toThrowError(expect.objectContaining({ name: 'InvalidStateError' }));
  });

  test('fails closed on crossed runtime identity and non-source-derived bytes', async () => {
    const crossed = factory(
      authority((plane) =>
        Object.freeze({
          ...plane,
          runtimeNonce: '92',
        }),
      ),
    );
    await expect(
      crossed.createImageBitmap(new Blob([ENCODED])),
    ).rejects.toMatchObject({ name: 'SecurityError' });

    const substituted = factory(
      authority((plane) =>
        Object.freeze({
          ...plane,
          encodedBytes: Uint8Array.from([1, 2, 3, 4]),
        }),
      ),
    );
    await expect(
      substituted.createImageBitmap(new Blob([ENCODED])),
    ).rejects.toMatchObject({ name: 'SecurityError' });
  });

  test('enforces canonical shape, metadata, mime, and revocation', async () => {
    const malformed = factory(
      authority((plane) =>
        Object.freeze({
          ...plane,
          bytesPerRow: 12,
        }),
      ),
    );
    await expect(
      malformed.createImageBitmap(new Blob([ENCODED])),
    ).rejects.toThrow(/shape/u);

    await expect(
      factory().createImageBitmap(new Blob([ENCODED], { type: 'image/jpeg' })),
    ).rejects.toMatchObject({ name: 'InvalidStateError' });

    const revoked = factory();
    const bitmap = await revoked.createImageBitmap(new Blob([ENCODED]));
    revoked.revoke();
    expect(() => revoked.snapshotForCopy(bitmap)).toThrowError(
      expect.objectContaining({ name: 'SecurityError' }),
    );
    await expect(
      revoked.createImageBitmap(new Blob([ENCODED])),
    ).rejects.toMatchObject({ name: 'SecurityError' });
  });
});
