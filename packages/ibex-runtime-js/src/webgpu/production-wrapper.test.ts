import { describe, expect, test } from 'bun:test';

import type {
  NativeGpuBridgeV2,
  NativeGpuCallMetadataV2,
  NativeGpuEventV2,
} from './native-bridge';
import type {
  ExecutableWebGpuCodecBundle,
  ProductionGpuServiceEncodingInput,
} from './production-codecs';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';
import {
  createProductionWebGpuPrivateBinding,
  describeProductionWebGpuWorkloadStaging,
  installProductionWebGpu,
} from './production-wrapper';

type OperationResultEvent = Extract<NativeGpuEventV2, { kind: 1 }>;

interface RecordedSubmission {
  readonly operationId: number;
  readonly wantsPromise: boolean;
  readonly metadata: NativeGpuCallMetadataV2;
  readonly payload: ArrayBuffer | ArrayBufferView;
}

function createFakeBridge(): NativeGpuBridgeV2 & {
  readonly submissions: RecordedSubmission[];
  emit(event: NativeGpuEventV2): void;
} {
  let sink: ((event: NativeGpuEventV2) => void) | undefined;
  let nextOperation = 1;
  let nextPromise = 1;
  const submissions: RecordedSubmission[] = [];
  const bridge: NativeGpuBridgeV2 & {
    readonly submissions: RecordedSubmission[];
    emit(event: NativeGpuEventV2): void;
  } = {
    abiVersion: 0x0002_0000,
    runtimeAddress: '11',
    runtimeNonce: '13',
    realmId: '17',
    realmGeneration: '19',
    rootAccountId: '23',
    rootAccountGeneration: '29',
    rootAuthorityDigest: new Uint8Array(32).fill(7),
    submissions,
    submit(operationId, wantsPromise, metadata, payload) {
      submissions.push({ operationId, wantsPromise, metadata, payload });
      const operationInstanceId = String(nextOperation++);
      const promiseId = wantsPromise ? String(nextPromise++) : '0';
      const receipt = wantsPromise
        ? Promise.resolve().then(() => {
          const event: OperationResultEvent = {
            kind: 1,
            runtimeAddress: bridge.runtimeAddress,
            runtimeNonce: bridge.runtimeNonce,
            topologyId: 1,
            operationId,
            operationInstanceId,
            promiseId,
            providerAdmission: 1,
            physicalSequence: operationInstanceId,
            capturedScopeId: metadata.capturedScopeId,
            realmId: bridge.realmId,
            realmGeneration: bridge.realmGeneration,
            accountId: bridge.rootAccountId,
            accountGeneration: bridge.rootAccountGeneration,
            accountAuthorityDigest: bridge.rootAuthorityDigest,
            logicalDeviceId: metadata.logicalDeviceId,
            logicalDeviceGeneration: metadata.logicalDeviceGeneration,
            providerGeneration: metadata.providerGeneration,
            ingressLogicalDeviceId: metadata.logicalDeviceId,
            ingressLogicalDeviceGeneration: metadata.logicalDeviceGeneration,
            ingressProviderGeneration: metadata.providerGeneration,
            deviceTransition: 0,
            operationProviderGeneration: metadata.operationProviderGeneration,
            authorityContextDigest: new Uint8Array(32).fill(9),
            adapterOrdinal: metadata.adapterOrdinal,
            deviceIngressOrdinal: metadata.deviceIngressOrdinal,
            queueIngressOrdinal: metadata.queueIngressOrdinal,
            receiverKind: metadata.receiverKind,
            receiverFlags: 0,
            receiverId: metadata.receiverId,
            receiverGeneration: metadata.receiverGeneration,
            targetKind: metadata.targetKind,
            targetFlags: 0,
            targetId: metadata.targetId,
            targetGeneration: metadata.targetGeneration,
            resultKind: 1,
            status: 0,
            payload: new Uint8Array([1]),
          };
          sink?.(event);
          return Object.freeze({ operationInstanceId, promiseId });
        })
        : undefined;
      return {
        operationInstanceId,
        promiseId,
        submissionStatus: 0,
        receipt,
      };
    },
    cancel: () => 0,
    retire: () => 0,
    setEventSink(nextSink) {
      if (sink) throw new TypeError('event sink is one-shot');
      sink = nextSink;
    },
    emit(event) {
      sink?.(event);
    },
  };
  return bridge;
}

function createFakeCodecs(
  log: string[] = [],
  options: Readonly<{
    detachedAdapters?: boolean;
    detachedDevices?: boolean;
    omitAdapterDetachedState?: boolean;
  }> = {},
): ExecutableWebGpuCodecBundle & {
  readonly encodings: ProductionGpuServiceEncodingInput[];
} {
  const encodings: ProductionGpuServiceEncodingInput[] = [];
  let nextDetachedIdentity = 1_000;
  return {
    schema: 'ibex/webgpu-executable-codecs/1',
    operationSetDigest: WEBGPU_PRODUCTION_PLAN.digests.operationSet,
    semanticProgramDigest: WEBGPU_PRODUCTION_PLAN.digests.semanticProgramSet,
    runtimeRoutingDigest: WEBGPU_PRODUCTION_PLAN.digests.runtimeRouting,
    webgpuCVocabularyDigest: WEBGPU_PRODUCTION_PLAN.digests.webgpuCVocabulary,
    operationIds: WEBGPU_PRODUCTION_PLAN.routes.map((route) => route.operationId),
    encodings,
    convertPublicArguments(operationId, args) {
      log.push(`convert:${operationId}`);
      if (operationId === 'GPU.requestAdapter') {
        const source = (args[0] ?? {}) as Record<string, unknown>;
        return Object.freeze({
          forceFallbackAdapter: Boolean(source.forceFallbackAdapter),
          featureLevel: source.featureLevel === undefined
            ? 'core'
            : String(source.featureLevel),
          xrCompatible: Boolean(source.xrCompatible),
          ...(source.powerPreference === undefined
            ? {}
            : { powerPreference: String(source.powerPreference) }),
        });
      }
      if (operationId === 'GPUQueue.submit') {
        return Array.from(args[0] as Iterable<unknown>);
      }
      if (operationId === 'GPUCanvasContext.configure') {
        return { ...(args[0] as Record<string, unknown>) };
      }
      if (operationId === 'GPUDevice.pushErrorScope') return String(args[0]);
      if (operationId === 'GPURenderPassEncoder.draw') {
        if (args[0] === undefined) throw new TypeError('vertexCount is required');
        return Object.freeze({
          vertexCount: Number(args[0]),
          instanceCount: args[1] === undefined ? 1 : Number(args[1]),
          firstVertex: args[2] === undefined ? 0 : Number(args[2]),
          firstInstance: args[3] === undefined ? 0 : Number(args[3]),
        });
      }
      if (args.length === 0 || args[0] === undefined) return Object.freeze({});
      return args[0];
    },
    encodeServiceRequest(input) {
      log.push(`encode:${input.operationId}`);
      encodings.push(input);
      return new Uint8Array([input.wireId & 0xff]);
    },
    decodeServiceResult(operationId) {
      log.push(`decode:${operationId}`);
      if (operationId === 'GPU.requestAdapter') {
        return {
          kind: 'object',
          object: {
            kind: 'GPUAdapter',
            objectId: '101',
            objectGeneration: '1',
            providerGeneration: '7',
            ...(options.omitAdapterDetachedState
              ? {}
              : {
                serviceDetachedExpired: Boolean(options.detachedAdapters),
              }),
          },
        };
      }
      if (operationId === 'GPUAdapter.requestDevice') {
        const objectId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : '201';
        const logicalDeviceId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : '301';
        const queueObjectId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : '202';
        return {
          kind: 'object',
          object: {
            kind: 'GPUDevice',
            objectId,
            objectGeneration: '1',
            logicalDeviceId,
            logicalDeviceGeneration: '1',
            providerGeneration: '7',
            features: ['timestamp-query'],
            limits: { maxBindGroups: 4 },
            queue: {
              objectId: queueObjectId,
              objectGeneration: '1',
            },
            alreadyLost: options.detachedDevices
              ? {
                reason: 'unknown' as const,
                message: 'The adapter is expired',
              }
              : undefined,
          },
        };
      }
      return { kind: 'value', value: null };
    },
    decodeDeviceLoss(event) {
      return {
        reason: event.kind === 4 && event.lossReason === 2 ? 'destroyed' : 'unknown',
        message: `loss-${event.kind}`,
      };
    },
  };
}

function isolatedGlobal(): typeof globalThis {
  return { navigator: Object.create(null) } as unknown as typeof globalThis;
}

describe('production-private WebGPU wrapper gate', () => {
  test('keeps generated codecs injection-only while the native decoder is not installed', () => {
    expect(WEBGPU_PRODUCTION_PLAN.codecReadiness).toBe(
      'generated-injection-and-request-adapter-request-device-device-destroy-payload-codegen-input-native-codec-not-installed',
    );
  });
  test('fails closed without a V2 provider and executable codec authority', () => {
    const globalObject = isolatedGlobal();
    expect(installProductionWebGpu(globalObject, undefined)).toEqual({
      status: 'not-installed',
      reason: 'provider-absent',
    });
    const bridge = createFakeBridge();
    expect(installProductionWebGpu(globalObject, bridge)).toEqual({
      status: 'not-installed',
      reason: 'executable-codecs-unavailable',
    });
    expect('gpu' in globalObject.navigator).toBe(false);
    expect('GPUDevice' in globalObject).toBe(false);
    expect('createImageBitmap' in globalObject).toBe(false);
    expect(bridge.submissions).toHaveLength(0);

    const mismatchedCodecs = {
      ...createFakeCodecs(),
      runtimeRoutingDigest: '0'.repeat(64),
    } as ExecutableWebGpuCodecBundle;
    expect(installProductionWebGpu(globalObject, bridge, mismatchedCodecs)).toEqual({
      status: 'not-installed',
      reason: 'executable-codecs-unavailable',
    });
    expect('gpu' in globalObject.navigator).toBe(false);
  });

  test('refuses worker installation and public-surface replacement', () => {
    const codecs = createFakeCodecs();
    const workerGlobal = isolatedGlobal();
    expect(
      installProductionWebGpu(workerGlobal, createFakeBridge(), codecs, 'worker'),
    ).toEqual({ status: 'not-installed', reason: 'not-app-realm' });
    expect('gpu' in workerGlobal.navigator).toBe(false);

    const occupied = isolatedGlobal();
    Object.defineProperty(occupied.navigator, 'gpu', { value: Object.freeze({}) });
    expect(
      installProductionWebGpu(occupied, createFakeBridge(), codecs),
    ).toEqual({ status: 'not-installed', reason: 'public-surface-conflict' });
  });
});

describe('production-private WebGPU wrapper factory', () => {
  test('settles an unknown post-WebIDL feature level to null without provider work', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      createFakeCodecs(log),
    );
    expect(installation.status).toBe('installed');
    const result = await (globalObject.navigator.gpu as {
      requestAdapter(options?: unknown): Promise<unknown>;
    }).requestAdapter({ featureLevel: 'future-profile' });
    expect(result).toBeNull();
    expect(log).toContain('convert:GPU.requestAdapter');
    expect(log).not.toContain('encode:GPU.requestAdapter');
    expect(bridge.submissions).toHaveLength(0);
    installation.status === 'installed' && installation.revoke();
  });

  test('runs Promise-operation conversion effects during the call and rejects conversion errors', async () => {
    const bridge = createFakeBridge();
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(
      globalObject,
      bridge,
      createFakeCodecs(),
    );
    expect(installation.status).toBe('installed');
    let getterObserved = false;
    const options = Object.defineProperty({}, 'forceFallbackAdapter', {
      enumerable: true,
      get() {
        getterObserved = true;
        throw new TypeError('conversion exploded');
      },
    });
    const pending = (globalObject.navigator.gpu as {
      requestAdapter(options?: unknown): Promise<unknown>;
    }).requestAdapter(options);
    expect(getterObserved).toBe(true);
    expect(pending).toBeInstanceOf(Promise);
    await expect(pending).rejects.toThrow('conversion exploded');
    expect(bridge.submissions).toHaveLength(0);
    installation.status === 'installed' && installation.revoke();
  });

  test('requires authenticated adapter attachment state without defaulting live', async () => {
    const log: string[] = [];
    const detached = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(log, { detachedAdapters: true }),
    );
    const adapter = await (detached.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter() as { requestDevice(): Promise<unknown> };
    await expect(adapter.requestDevice()).resolves.toBeObject();
    expect(log).toContain('convert:GPUAdapter.requestDevice');
    expect(log).toContain('encode:GPUAdapter.requestDevice');
    detached.revoke();

    const missing = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs([], { omitAdapterDetachedState: true }),
    );
    await expect((missing.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()).rejects.toThrow(
      'GPUAdapter result lacks authenticated detached state',
    );
    missing.revoke();
  });

  test('keeps the audited TypeGPU delta descriptive and absent from prototypes', () => {
    const staging = describeProductionWebGpuWorkloadStaging();
    expect(staging.supportClaim).toBe('none');
    expect(staging.nativeExecutionEvidence).toBe(
      'none-recording-provider-is-inventory-only',
    );
    expect(staging.typegpuVersion).toBe('0.11.9');
    expect(staging.activeRouteOperationCount).toBe(25);
    expect(staging.workloadOperationCount).toBe(51);
    expect(staging.additionalOperationCount).toBe(30);
    expect(staging.additionalOperations).toHaveLength(30);
    expect(staging.blockers).toHaveLength(5);
    expect(staging.embeddedCodecRule).toBe(
      'EMBEDDED_EXECUTABLE_WEBGPU_CODECS-remains-undefined',
    );
    expect(Object.isFrozen(staging)).toBe(true);
    expect(Object.isFrozen(staging.additionalOperations)).toBe(true);
    expect(Object.isFrozen(staging.blockers)).toBe(true);

    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    for (const operation of staging.additionalOperations) {
      const separator = operation.operationId.indexOf('.');
      const interfaceName = operation.operationId.slice(0, separator);
      const memberName = operation.operationId.slice(separator + 1);
      const interfaceObject = binding.interfaceObjects[interfaceName] as
        | { readonly prototype: object }
        | undefined;
      expect(
        interfaceObject === undefined
          ? undefined
          : Object.getOwnPropertyDescriptor(interfaceObject.prototype, memberName),
      ).toBeUndefined();
    }
    binding.revoke();
  });

  test('materializes exactly the reviewed 25-operation interface shape', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    expect(WEBGPU_PRODUCTION_PLAN.routes).toHaveLength(25);
    expect(Object.keys(binding.interfaceObjects)).toHaveLength(20);
    expect(Object.keys(binding.constantObjects)).toHaveLength(5);
    for (const selected of WEBGPU_PRODUCTION_PLAN.routes) {
      const interfaceObject = binding.interfaceObjects[selected.interfaceName] as {
        readonly prototype: object;
      };
      expect(interfaceObject).toBeDefined();
      const descriptor = Object.getOwnPropertyDescriptor(
        interfaceObject.prototype,
        selected.memberName,
      );
      expect(descriptor).toBeDefined();
      if (selected.memberKind === 'method') {
        expect(descriptor?.value).toBeFunction();
      } else {
        expect(descriptor?.get).toBeFunction();
      }
    }
    binding.revoke();
  });

  test('routes the app realm through V2 and preserves local recording semantics', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs(log);
    const globalObject = isolatedGlobal();
    const installation = installProductionWebGpu(globalObject, bridge, codecs);
    expect(installation.status).toBe('installed');
    const gpu = globalObject.navigator.gpu as {
      requestAdapter(options?: unknown): Promise<unknown>;
      getPreferredCanvasFormat(): string;
    };
    expect(gpu.getPreferredCanvasFormat()).toBe('bgra8unorm');
    expect('createBuffer' in gpu).toBe(false);

    const pendingAdapter = gpu.requestAdapter({ powerPreference: 'high-performance' });
    expect(log).toContain('convert:GPU.requestAdapter');
    const adapter = (await pendingAdapter) as {
      requestDevice(descriptor?: unknown): Promise<unknown>;
    };
    const pendingDevice = adapter.requestDevice({});
    expect(log).toContain('convert:GPUAdapter.requestDevice');
    const device = (await pendingDevice) as {
      readonly queue: { submit(buffers: Iterable<unknown>): void };
      readonly features: { has(value: string): boolean };
      readonly limits: Readonly<Record<string, number>>;
      readonly lost: Promise<unknown>;
      pushErrorScope(filter: unknown): void;
      popErrorScope(): Promise<unknown>;
      createShaderModule(descriptor: unknown): object;
      createRenderPipeline(descriptor: unknown): object;
      createCommandEncoder(descriptor?: unknown): {
        beginRenderPass(descriptor: unknown): {
          setPipeline(pipeline: unknown): void;
          draw(vertexCount: number): void;
          end(): void;
        };
        finish(descriptor?: unknown): object;
      };
    };
    expect(device.features.has('timestamp-query')).toBe(true);
    expect(device.limits.maxBindGroups).toBe(4);
    expect(device.queue).toBe(device.queue);
    expect(device.lost).toBe(device.lost);
    device.pushErrorScope('validation');
    const poppedScope = device.popErrorScope();
    expect(poppedScope).toBeInstanceOf(Promise);
    expect(await poppedScope).toBeNull();

    const shader = device.createShaderModule({ code: '@vertex fn main() {}' });
    const pipeline = device.createRenderPipeline({ vertex: { module: shader } });
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginRenderPass({ colorAttachments: [] });
    pass.setPipeline(pipeline);
    pass.draw(3);
    pass.end();
    const commandBuffer = encoder.finish();
    const submissionsBeforeQueue = bridge.submissions.length;
    device.queue.submit([commandBuffer]);
    expect(bridge.submissions).toHaveLength(submissionsBeforeQueue + 1);

    const requestAdapterWire = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPU.requestAdapter',
    )!.wireId;
    const requestDeviceWire = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUAdapter.requestDevice',
    )!.wireId;
    const adapterSubmission = bridge.submissions.find(
      (submission) => submission.operationId === requestAdapterWire,
    )!;
    const deviceSubmission = bridge.submissions.find(
      (submission) => submission.operationId === requestDeviceWire,
    )!;
    expect(adapterSubmission.metadata).toMatchObject({
      receiverKind: 1,
      receiverId: bridge.realmId,
      receiverGeneration: bridge.realmGeneration,
    });
    expect(deviceSubmission.metadata).toMatchObject({
      receiverKind: 2,
      receiverId: '101',
      receiverGeneration: '1',
    });
    const submitEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUQueue.submit',
    )!;
    expect(submitEncoding.sealedLocalTimeline.length).toBeGreaterThanOrEqual(5);
    expect(submitEncoding.receiver).toMatchObject({
      kind: 'GPUQueue',
      objectId: '202',
      logicalDeviceId: '301',
    });

    installation.status === 'installed' && installation.revoke();
    expect('gpu' in globalObject.navigator).toBe(false);
    expect('GPUDevice' in globalObject).toBe(false);
  });

  test('keeps canvas epochs stable and settles device loss exactly once', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs();
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const gpu = binding.gpu as { requestAdapter(): Promise<unknown> };
    const adapter = (await gpu.requestAdapter()) as {
      requestDevice(): Promise<unknown>;
    };
    const device = (await adapter.requestDevice()) as {
      readonly lost: Promise<unknown>;
    };
    const context = binding.mintCanvasContext({
      objectId: '401',
      objectGeneration: '1',
    }) as {
      configure(configuration: unknown): void;
      getConfiguration(): Record<string, unknown> | null;
      getCurrentTexture(): { createView(): object; destroy(): void };
      unconfigure(): void;
    };
    context.configure({ device, format: 'bgra8unorm' });
    const first = context.getCurrentTexture();
    expect(context.getCurrentTexture()).toBe(first);
    expect(first.createView()).toBeObject();
    const snapshot = context.getConfiguration();
    expect(snapshot?.format).toBe('bgra8unorm');
    expect(snapshot).not.toBe(context.getConfiguration());
    context.unconfigure();
    first.destroy();

    const lost = device.lost;
    bridge.emit({
      kind: 4,
      runtimeAddress: bridge.runtimeAddress,
      runtimeNonce: bridge.runtimeNonce,
      topologyId: 1,
      realmId: bridge.realmId,
      realmGeneration: bridge.realmGeneration,
      accountId: bridge.rootAccountId,
      accountGeneration: bridge.rootAccountGeneration,
      accountAuthorityDigest: bridge.rootAuthorityDigest,
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
      logicalLossOrdinal: '1',
      lastAcceptedPhysicalSequence: '9',
      backendClass: 1,
      lossReason: 1,
      hasInitiatingOperation: false,
      payload: new Uint8Array(),
    });
    expect(await lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('does not retain an unbounded series of service-detached lost devices', async () => {
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs([], { detachedDevices: true });
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const adapter = (await (binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()) as {
      requestDevice(): Promise<unknown>;
    };
    let firstLost: Promise<unknown> | undefined;
    for (let index = 0; index < 1_100; index += 1) {
      const device = (await adapter.requestDevice()) as {
        readonly lost: Promise<unknown>;
      };
      if (!firstLost) {
        firstLost = device.lost;
        expect(
          await Promise.race([
            device.lost,
            Promise.resolve('request-device-resolved-first'),
          ]),
        ).toEqual({
          reason: 'unknown',
          message: 'The adapter is expired',
        });
      }
      expect(await device.lost).toEqual({
        reason: 'unknown',
        message: 'The adapter is expired',
      });
    }
    binding.revoke();
    expect(firstLost).toBeDefined();
    expect(await firstLost!).toEqual({
      reason: 'unknown',
      message: 'The adapter is expired',
    });
  });
});
