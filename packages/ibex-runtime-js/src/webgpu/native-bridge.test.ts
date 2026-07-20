import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

import { nativeGpuBridgeForGeneratedWrapper } from './runtime-internal';
import {
  installNativeGpuBridgeCapture,
  isNativeGpuBridge,
  type NativeGpuBridge,
} from './native-bridge';

describe('construction-private GPU bridge capture', () => {
  test('the embedded entry and generated-wrapper path share one module slot', () => {
    const occupiedGlobal = {
      __ibexCaptureGpuNativeBridge: () => undefined,
    } as unknown as typeof globalThis;
    expect(() => installNativeGpuBridgeCapture(occupiedGlobal)).toThrow(
      'capture name is already occupied',
    );

    const constructionGlobal = {} as typeof globalThis;
    const bridge: NativeGpuBridge = {
      realmToken: '17',
      accountToken: '23',
      submit: () => ({
        completionId: '1',
        admissionStatus: 0,
        receipt: Promise.resolve(),
      }),
      cancel: () => 0,
      retire: () => 0,
    };

    let installedSurface = false;
    let installedSurfaceRevoked = false;
    installNativeGpuBridgeCapture(constructionGlobal, (candidate) => {
      expect(candidate).toBe(bridge);
      installedSurface = true;
      return () => {
        installedSurfaceRevoked = true;
      };
    });
    const capture = Object.getOwnPropertyDescriptor(
      constructionGlobal,
      '__ibexCaptureGpuNativeBridge',
    )?.value as ((candidate: NativeGpuBridge) => () => void) | undefined;
    expect(capture).toBeFunction();
    const revoke = capture!(bridge);

    expect(Reflect.ownKeys(constructionGlobal)).toEqual([]);
    expect(nativeGpuBridgeForGeneratedWrapper()).toBe(bridge);
    expect(installedSurface).toBe(true);
    revoke();
    expect(nativeGpuBridgeForGeneratedWrapper()).toBeUndefined();
    expect(installedSurfaceRevoked).toBe(true);
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
