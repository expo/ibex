import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

import { nativeGpuBridgeForGeneratedWrapper } from './runtime-internal';
import {
  installNativeGpuBridgeCapture,
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
        receipt: Promise.resolve(undefined),
      }),
      cancel: () => 0,
      retire: () => 0,
    };

    installNativeGpuBridgeCapture(constructionGlobal);
    const capture = Object.getOwnPropertyDescriptor(
      constructionGlobal,
      '__ibexCaptureGpuNativeBridge',
    )?.value as ((candidate: NativeGpuBridge) => () => void) | undefined;
    expect(capture).toBeFunction();
    const revoke = capture!(bridge);

    expect(Reflect.ownKeys(constructionGlobal)).toEqual([]);
    expect(nativeGpuBridgeForGeneratedWrapper()).toBe(bridge);
    revoke();
    expect(nativeGpuBridgeForGeneratedWrapper()).toBeUndefined();
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
