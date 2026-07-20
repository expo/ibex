import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

import { Blob } from '../blob/Blob';
import {
  installNativeGpuBridgeCapture as installRuntimeNativeGpuBridgeCapture,
  nativeGpuBridgeForGeneratedWrapper,
} from './runtime-internal';
import {
  installNativeGpuBridgeCapture as installNativeGpuBridgeCaptureSlot,
  isNativeGpuBridge,
  type NativeGpuBridge,
} from './native-bridge';

describe('construction-private GPU bridge capture', () => {
  test('the embedded entry authenticates codecs and publishes one revocable app surface', async () => {
    const occupiedGlobal = {
      __ibexCaptureGpuNativeBridge: () => undefined,
    } as unknown as typeof globalThis;
    expect(() => installNativeGpuBridgeCaptureSlot(occupiedGlobal)).toThrow(
      'capture name is already occupied',
    );

    const constructionGlobal = { navigator: {} } as unknown as typeof globalThis;
    const bridge: NativeGpuBridge = {
      abiVersion: 0x0002_0000,
      runtimeAddress: '11',
      runtimeNonce: '13',
      realmId: '17',
      realmGeneration: '19',
      rootAccountId: '23',
      rootAccountGeneration: '29',
      rootAuthorityDigest: new Uint8Array(32).fill(7),
      decodedImageAuthority: Object.freeze({
        async decodePng(request) {
          return Object.freeze({
            runtimeAddress: request.runtimeAddress,
            runtimeNonce: request.runtimeNonce,
            sourceId: request.sourceId,
            sourceGeneration: request.sourceGeneration,
            width: 1,
            height: 1,
            bytesPerRow: 4,
            encodedBytes: request.encodedBytes,
            decodedPremultipliedRgba8: new Uint8Array([1, 2, 3, 4]),
            encodedContentSha256: '12'.repeat(32),
            decodedContentSha256: '34'.repeat(32),
            originClean: true as const,
            colorSpace: 'srgb' as const,
            alphaMode: 'premultiplied' as const,
            orientation: 'top-left' as const,
          });
        },
      }),
      submit: () => ({
        operationInstanceId: '1',
        promiseId: '0',
        submissionStatus: 0,
      }),
      cancel: () => 0,
      retire: () => 0,
      createMappedRangeAlias: (source, offset, length) =>
        source.slice(offset, offset + length),
      detachMappedRange: () => true,
      setEventSink: () => undefined,
    };

    installRuntimeNativeGpuBridgeCapture(constructionGlobal);
    const capture = Object.getOwnPropertyDescriptor(
      constructionGlobal,
      '__ibexCaptureGpuNativeBridge',
    )?.value as ((candidate: NativeGpuBridge) => () => void) | undefined;
    expect(capture).toBeFunction();
    const revoke = capture!(bridge);

    expect(Reflect.ownKeys(constructionGlobal)).toContain('GPUDevice');
    expect('gpu' in constructionGlobal.navigator).toBe(true);
    const createImageBitmap = Object.getOwnPropertyDescriptor(
      constructionGlobal,
      'createImageBitmap',
    )?.value as ((source: Blob) => Promise<{
      readonly width: number;
      readonly height: number;
      close(): void;
    }>) | undefined;
    const bitmap = await createImageBitmap!(
      new Blob([new Uint8Array([137, 80, 78, 71])], { type: 'image/png' }),
    );
    expect({ width: bitmap.width, height: bitmap.height }).toEqual({
      width: 1,
      height: 1,
    });
    expect(nativeGpuBridgeForGeneratedWrapper()).toBe(bridge);
    revoke?.();
    expect(nativeGpuBridgeForGeneratedWrapper()).toBeUndefined();
    expect('gpu' in constructionGlobal.navigator).toBe(false);
    expect('GPUDevice' in constructionGlobal).toBe(false);
    expect('createImageBitmap' in constructionGlobal).toBe(false);
  });

  test('V2 capture validation requires the typed sink and mapped-buffer helpers', () => {
    const bridge: NativeGpuBridge = {
      abiVersion: 0x0002_0000,
      runtimeAddress: '11',
      runtimeNonce: '13',
      realmId: '17',
      realmGeneration: '19',
      rootAccountId: '23',
      rootAccountGeneration: '29',
      rootAuthorityDigest: new Uint8Array(32).fill(7),
      submit: () => ({
        operationInstanceId: '1',
        promiseId: '0',
        submissionStatus: 0,
      }),
      cancel: () => 0,
      retire: () => 0,
      createMappedRangeAlias: (source, offset, length) =>
        source.slice(offset, offset + length),
      detachMappedRange: () => true,
      setEventSink: () => undefined,
    };
    expect(isNativeGpuBridge(bridge)).toBe(true);
    const missingSink = { ...bridge, setEventSink: undefined };
    expect(isNativeGpuBridge(missingSink)).toBe(false);
    expect(isNativeGpuBridge({
      ...bridge,
      createMappedRangeAlias: undefined,
    })).toBe(false);
    expect(isNativeGpuBridge({
      ...bridge,
      detachMappedRange: undefined,
    })).toBe(false);
  });

  test('the committed runtime bundle contains one capture module instance', () => {
    const bundle = readFileSync(
      new URL('../../../../vendored-generated/embedded_runtime_bundle.js', import.meta.url),
      'utf8',
    );
    expect(bundle.match(/\blet capturedBridge;/g)?.length).toBe(1);
    expect(bundle.match(/__ibexCaptureGpuNativeBridge/g)?.length).toBe(1);
  });
});
