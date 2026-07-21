import { beforeEach, describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

import { Blob } from '../blob/Blob';
import {
  installNativeGpuBridgeCapture as installRuntimeNativeGpuBridgeCapture,
  nativeGpuBridgeForGeneratedWrapper,
  resetExactGpuCanvasRuntimeIntegrationForTests,
} from './runtime-internal';
import {
  installNativeGpuBridgeCapture as installNativeGpuBridgeCaptureSlot,
  isNativeGpuBridge,
  resetNativeGpuBridgeCaptureForTests,
  type NativeGpuBridge,
  type NativeGpuBridgeCaptureInstallation,
} from './native-bridge';

describe('construction-private GPU bridge capture', () => {
  beforeEach(() => {
    resetExactGpuCanvasRuntimeIntegrationForTests();
    resetNativeGpuBridgeCaptureForTests();
  });

  test('does not publish WebGPU before an authenticated bridge capture', () => {
    const constructionGlobal = { navigator: {} } as unknown as typeof globalThis;

    installRuntimeNativeGpuBridgeCapture(constructionGlobal);

    expect('__ibexCaptureGpuNativeBridge' in constructionGlobal).toBe(true);
    expect('gpu' in constructionGlobal.navigator).toBe(false);
    expect('GPUDevice' in constructionGlobal).toBe(false);
    expect('createImageBitmap' in constructionGlobal).toBe(false);
  });

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
    )?.value as ((
      candidate: NativeGpuBridge,
    ) => NativeGpuBridgeCaptureInstallation) | undefined;
    expect(capture).toBeFunction();
    const captureResult = capture!(bridge);
    expect(typeof captureResult).toBe('object');
    if (typeof captureResult === 'function') {
      throw new Error('runtime capture unexpectedly returned legacy shape');
    }
    expect(Object.isFrozen(captureResult)).toBe(true);
    expect(Reflect.ownKeys(captureResult).sort()).toEqual([
      'beginCanvasAppBundle',
      'canvasReceiptSink',
      'checkpointHostTask',
      'finishCanvasAppBundle',
      'revoke',
    ]);
    expect(() => captureResult.checkpointHostTask()).not.toThrow();

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
    expect(() => captureResult.canvasReceiptSink(Object.freeze({}))).toThrow(
      'receipt integration is unavailable',
    );
    expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
    expect(captureResult.beginCanvasAppBundle(2)).toBeUndefined();
    expect('__ibexCaptureGpuCanvasRuntimeIntegration' in constructionGlobal)
      .toBe(false);
    expect(captureResult.finishCanvasAppBundle(true)).toBe(false);
    captureResult.revoke();
    expect(nativeGpuBridgeForGeneratedWrapper()).toBeUndefined();
    expect('gpu' in constructionGlobal.navigator).toBe(false);
    expect('GPUDevice' in constructionGlobal).toBe(false);
    expect('createImageBitmap' in constructionGlobal).toBe(false);
  });

  test('rearms the exact Canvas integration once per app bundle', async () => {
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
      const minters: object[] = [];
      const receipts: Array<{ bundle: number; receipt: unknown }> = [];
      let minterReleases = 0;
      let expectTerminalReduction = false;
      let terminalGlobalsClosed = false;
      let retainedWrapperClosed: Promise<boolean> | undefined;
      let priorReleaseSawCaptureAbsent: Promise<boolean> | undefined;
      const integration = (bundle: number) => Object.freeze({
        installCanvasContextMinter(minter) {
          minters.push(minter);
          const retainedGpu = constructionGlobal.navigator.gpu;
          return () => {
            minterReleases += 1;
            if (!expectTerminalReduction) {
              priorReleaseSawCaptureAbsent = Promise.resolve().then(
                () => !(
                  '__ibexCaptureGpuCanvasRuntimeIntegration' in
                  constructionGlobal
                ),
              );
            }
            if (expectTerminalReduction) {
              terminalGlobalsClosed =
                !('gpu' in constructionGlobal.navigator) &&
                !('GPUDevice' in constructionGlobal);
              try {
                retainedWrapperClosed = Promise.resolve(
                  retainedGpu.requestAdapter(),
                ).then(
                  () => false,
                  () => true,
                );
              } catch {
                retainedWrapperClosed = Promise.resolve(true);
              }
            }
          };
        },
        deliverCanvasAttachmentReceipt(receipt) {
          receipts.push({ bundle, receipt });
        },
      });

      installRuntimeNativeGpuBridgeCapture(constructionGlobal);
      const capture = Object.getOwnPropertyDescriptor(
        constructionGlobal,
        '__ibexCaptureGpuNativeBridge',
      )?.value as ((
        candidate: NativeGpuBridge,
      ) => NativeGpuBridgeCaptureInstallation) | undefined;
      const captureResult = capture!(bridge);
      if (typeof captureResult === 'function') {
        throw new Error('runtime capture unexpectedly returned legacy shape');
      }

      expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
      const firstCapture = captureResult.beginCanvasAppBundle(1)!;
      expect(Object.getOwnPropertyDescriptor(
        constructionGlobal,
        '__ibexCaptureGpuCanvasRuntimeIntegration',
      )).toMatchObject({
        value: firstCapture,
        writable: false,
        enumerable: false,
        configurable: true,
      });
      firstCapture(integration(1));
      expect('__ibexCaptureGpuCanvasRuntimeIntegration' in constructionGlobal)
        .toBe(false);
      expect(() => captureResult.canvasReceiptSink(Object.freeze({}))).toThrow(
        'receipt integration is unavailable',
      );
      expect(captureResult.finishCanvasAppBundle(true)).toBe(true);
      expect(minters).toHaveLength(1);
      expect(Object.isFrozen(minters[0])).toBe(true);
      expect(Reflect.ownKeys(minters[0])).toEqual(['mintCanvasContext']);

      const firstReceipt = Object.freeze({ kind: 'receipt-for-first-bundle' });
      captureResult.canvasReceiptSink(firstReceipt);
      expect(receipts).toEqual([{ bundle: 1, receipt: firstReceipt }]);

      expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
      await expect(priorReleaseSawCaptureAbsent).resolves.toBe(true);
      const secondCapture = captureResult.beginCanvasAppBundle(1)!;
      expect(minterReleases).toBe(1);
      expect(() => captureResult.canvasReceiptSink(firstReceipt)).toThrow(
        'receipt integration is unavailable',
      );
      expect(() => firstCapture(integration(99))).toThrow(
        'Invalid or repeated Exact GPU Canvas integration capture',
      );
      secondCapture(integration(2));
      expect(captureResult.finishCanvasAppBundle(true)).toBe(true);
      expect(minters).toHaveLength(2);
      const secondReceipt = Object.freeze({ kind: 'receipt-for-second-bundle' });
      captureResult.canvasReceiptSink(secondReceipt);
      expect(receipts).toEqual([
        { bundle: 1, receipt: firstReceipt },
        { bundle: 2, receipt: secondReceipt },
      ]);

      expectTerminalReduction = true;
      captureResult.revoke();
      captureResult.revoke();
      expect(minterReleases).toBe(2);
      expect(terminalGlobalsClosed).toBe(true);
      await expect(retainedWrapperClosed).resolves.toBe(true);
      expect(() => captureResult.canvasReceiptSink(secondReceipt)).toThrow(
        'receipt integration is unavailable',
      );
  });

  test('closes unused, malformed, replaced, and failed app-bundle handoffs', () => {
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
    const providerCapture = Object.getOwnPropertyDescriptor(
      constructionGlobal,
      '__ibexCaptureGpuNativeBridge',
    )?.value as ((
      candidate: NativeGpuBridge,
    ) => NativeGpuBridgeCaptureInstallation) | undefined;
    const captureResult = providerCapture!(bridge);
    if (typeof captureResult === 'function') {
      throw new Error('runtime capture unexpectedly returned legacy shape');
    }

    expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
    const malformedCapture = captureResult.beginCanvasAppBundle(1)!;
    expect(() => malformedCapture(Object.freeze({
      installCanvasContextMinter: () => () => undefined,
      deliverCanvasAttachmentReceipt: () => undefined,
      extra: true,
    }))).toThrow('Invalid or repeated Exact GPU Canvas integration capture');
    expect(captureResult.finishCanvasAppBundle(true)).toBe(false);
    expect('__ibexCaptureGpuCanvasRuntimeIntegration' in constructionGlobal)
      .toBe(false);

    expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
    captureResult.beginCanvasAppBundle(1);
    expect(() => captureResult.beginCanvasAppBundle(1)).toThrow(
      'app-bundle transaction is unavailable',
    );
    expect(captureResult.finishCanvasAppBundle(true)).toBe(false);

    expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
    const replacedCapture = captureResult.beginCanvasAppBundle(1)!;
    expect(Reflect.deleteProperty(
      constructionGlobal,
      '__ibexCaptureGpuCanvasRuntimeIntegration',
    )).toBe(true);
    Object.defineProperty(
      constructionGlobal,
      '__ibexCaptureGpuCanvasRuntimeIntegration',
      {
        value: replacedCapture,
        writable: true,
        enumerable: true,
        configurable: true,
      },
    );
    expect(() => captureResult.finishCanvasAppBundle(true)).toThrow(
      'integration handoff was replaced',
    );
    expect('__ibexCaptureGpuCanvasRuntimeIntegration' in constructionGlobal)
      .toBe(false);

    let releaseCalls = 0;
    expect(captureResult.beginCanvasAppBundle(0)).toBeUndefined();
    const failedEvaluationCapture = captureResult.beginCanvasAppBundle(1)!;
    failedEvaluationCapture(Object.freeze({
      installCanvasContextMinter: () => () => {
        releaseCalls += 1;
      },
      deliverCanvasAttachmentReceipt: () => undefined,
    }));
    expect(captureResult.finishCanvasAppBundle(false)).toBe(true);
    expect(releaseCalls).toBe(1);
    expect(() => captureResult.canvasReceiptSink(Object.freeze({}))).toThrow(
      'receipt integration is unavailable',
    );

    Object.defineProperty(
      constructionGlobal,
      '__ibexCaptureGpuCanvasRuntimeIntegration',
      {
        value: () => undefined,
        configurable: true,
      },
    );
    expect(() => captureResult.beginCanvasAppBundle(0)).toThrow(
      'preparation is unavailable',
    );
    Reflect.deleteProperty(
      constructionGlobal,
      '__ibexCaptureGpuCanvasRuntimeIntegration',
    );
    captureResult.revoke();
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
