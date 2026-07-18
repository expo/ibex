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
import {
  WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
  WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT,
} from './production-codecs.generated';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';
import {
  createProductionWebGpuPrivateBinding,
  describeProductionWebGpuWorkloadStaging,
  incrementCanonicalU64Decimal,
  installProductionWebGpu,
} from './production-wrapper';

const CANVAS_AUTHORITY = Object.freeze({
  attachmentGeneration: '31',
  contextGeneration: '37',
  targetAuthorityDigest: 'ab'.repeat(32),
  surfaceAccountToken: '41',
  surfaceAccountGeneration: '43',
});
const U64_MAX = '18446744073709551615';
const U64_MAX_MINUS_ONE = '18446744073709551614';
const U64_MAX_MINUS_TWO = '18446744073709551613';

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
  setSubmitHook(
    hook: ((operationId: number, metadata: NativeGpuCallMetadataV2) => void) |
      undefined,
  ): void;
} {
  let sink: ((event: NativeGpuEventV2) => void) | undefined;
  let submitHook:
    ((operationId: number, metadata: NativeGpuCallMetadataV2) => void) |
    undefined;
  let nextOperation = 1;
  let nextPromise = 1;
  const submissions: RecordedSubmission[] = [];
  const bridge: NativeGpuBridgeV2 & {
    readonly submissions: RecordedSubmission[];
    emit(event: NativeGpuEventV2): void;
    setSubmitHook(
      hook: ((operationId: number, metadata: NativeGpuCallMetadataV2) => void) |
        undefined,
    ): void;
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
      submitHook?.(operationId, metadata);
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
    setSubmitHook(hook) {
      submitHook = hook;
    },
  };
  return bridge;
}

function createFakeCodecs(
  log: string[] = [],
  options: Readonly<{
    detachedAdapters?: boolean;
    detachedDevices?: boolean;
    distinctLiveDevices?: boolean;
    omitAdapterDetachedState?: boolean;
  }> = {},
): ExecutableWebGpuCodecBundle & {
  readonly encodings: ProductionGpuServiceEncodingInput[];
} {
  const encodings: ProductionGpuServiceEncodingInput[] = [];
  let nextDetachedIdentity = 1_000;
  let nextLiveDeviceOffset = 0;
  return {
    schema: 'ibex/webgpu-executable-codecs/1',
    operationSetDigest: WEBGPU_PRODUCTION_PLAN.digests.operationSet,
    semanticProgramDigest: WEBGPU_PRODUCTION_PLAN.digests.semanticProgramSet,
    runtimeRoutingDigest: WEBGPU_PRODUCTION_PLAN.digests.runtimeRouting,
    webgpuCVocabularyDigest: WEBGPU_PRODUCTION_PLAN.digests.webgpuCVocabulary,
    operationIds: WEBGPU_PRODUCTION_PLAN.routes.map((route) => route.operationId),
    encodings,
    deriveTextureOriginDigest(input) {
      return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
        .deriveTextureOriginDigest(input);
    },
    convertPublicArguments(operationId, args, wrappers) {
      log.push(`convert:${operationId}`);
      if (
        operationId === 'GPUTexture.createView' ||
        operationId === 'GPUCanvasContext.configure'
      ) {
        return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          operationId,
          args,
          wrappers,
        );
      }
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
      if (input.operationId === 'GPUTexture.createView') {
        return WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
          .encodeServiceRequest(input);
      }
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
        const liveOffset = options.distinctLiveDevices
          ? nextLiveDeviceOffset++ * 10
          : 0;
        const objectId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : String(201 + liveOffset);
        const logicalDeviceId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : String(301 + liveOffset);
        const queueObjectId = options.detachedDevices
          ? String(nextDetachedIdentity++)
          : String(202 + liveOffset);
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

function emitDeviceLoss(
  bridge: ReturnType<typeof createFakeBridge>,
  logicalDeviceId: string,
  logicalLossOrdinal: string,
): void {
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
    logicalDeviceId,
    logicalDeviceGeneration: '1',
    providerGeneration: '7',
    logicalLossOrdinal,
    lastAcceptedPhysicalSequence: '9',
    backendClass: 1,
    lossReason: 1,
    hasInitiatingOperation: false,
    payload: new Uint8Array(),
  });
}

function emitProviderLoss(
  bridge: ReturnType<typeof createFakeBridge>,
): void {
  bridge.emit({
    kind: 3,
    runtimeAddress: bridge.runtimeAddress,
    runtimeNonce: bridge.runtimeNonce,
    topologyId: 1,
    realmId: bridge.realmId,
    realmGeneration: bridge.realmGeneration,
    logicalDeviceId: '301',
    logicalDeviceGeneration: '1',
    providerGeneration: '7',
    lastAcceptedPhysicalSequence: '9',
    backendClass: 1,
    lossReason: 1,
    hasInitiatingOperation: false,
    payload: new Uint8Array(),
  });
}

function inspectBinding(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
) {
  if (!binding.inspectForTest) throw new Error('state inspection was not enabled');
  return binding.inspectForTest();
}

function latestCanvasTextureOrigin(
  bridge: ReturnType<typeof createFakeBridge>,
): Readonly<Record<string, unknown>> {
  const createViewWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
    (route) => route.operationId === 'GPUTexture.createView',
  )?.wireId;
  if (createViewWireId === undefined) throw new Error('missing createView route');
  const submission = bridge.submissions.findLast(
    (candidate) => candidate.operationId === createViewWireId,
  );
  if (!submission) throw new Error('missing createView submission');
  const request = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
    .inspectServiceRequest(submission.payload) as Readonly<{
      convertedArguments: Readonly<{
        currentOrigin: Readonly<Record<string, unknown>>;
      }>;
    }>;
  return request.convertedArguments.currentOrigin;
}

interface TestGpuDevice {
  readonly lost: Promise<unknown>;
  destroy(): void;
}

interface TestCanvasTexture {
  createView(): object;
}

interface TestCanvasContext {
  configure(configuration: unknown): void;
  getConfiguration(): Record<string, unknown> | null;
  getCurrentTexture(): TestCanvasTexture;
  unconfigure(): void;
}

async function requestTestDevice(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
): Promise<TestGpuDevice> {
  const adapter = (await (binding.gpu as {
    requestAdapter(): Promise<unknown>;
  }).requestAdapter()) as {
    requestDevice(): Promise<unknown>;
  };
  return await adapter.requestDevice() as TestGpuDevice;
}

function mintTestCanvasContext(
  binding: ReturnType<typeof createProductionWebGpuPrivateBinding>,
  objectGeneration = '1',
): TestCanvasContext {
  return binding.mintCanvasContext({
    objectId: '401',
    objectGeneration,
    drawingBufferWidth: 640,
    drawingBufferHeight: 480,
    authority: CANVAS_AUTHORITY,
  }) as TestCanvasContext;
}

describe('production-private WebGPU wrapper gate', () => {
  test('increments private u64 counters exactly and rejects overflow before wrap', () => {
    expect(incrementCanonicalU64Decimal('18446744073709551614')).toBe(
      '18446744073709551615',
    );
    const state = { counter: '18446744073709551615' };
    expect(() => {
      state.counter = incrementCanonicalU64Decimal(state.counter);
    }).toThrow(RangeError);
    expect(state.counter).toBe('18446744073709551615');
    expect(() => incrementCanonicalU64Decimal('018')).toThrow(TypeError);
    expect(() => incrementCanonicalU64Decimal('18446744073709551616'))
      .toThrow(TypeError);
  });

  test('keeps generated codecs injection-only while the native decoder is not installed', () => {
    expect(WEBGPU_PRODUCTION_PLAN.codecReadiness).toBe(
      'generated-injection-and-request-adapter-request-device-create-bind-group-layout-create-buffer-create-pipeline-layout-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-payload-codegen-input-native-codec-not-installed',
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

  test('does not allocate or enqueue a texture view after an intermediate descriptor conversion throws', async () => {
    const log: string[] = [];
    const bridge = createFakeBridge();
    const codecs = createFakeCodecs(log);
    const binding = createProductionWebGpuPrivateBinding(bridge, codecs);
    const adapter = await (binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter() as { requestDevice(): Promise<unknown> };
    const device = await adapter.requestDevice() as {
      createTexture(descriptor: unknown): {
        createView(descriptor?: unknown): object;
      };
    };
    const texture = device.createTexture({
      format: 'rgba8unorm',
      size: [4, 4],
      usage: 4,
    });
    const before = texture.createView();
    const beforeTarget = codecs.encodings.at(-1)?.target;
    expect(beforeTarget).toMatchObject({ kind: 'GPUTextureView' });

    let laterGetterCount = 0;
    const hostile = Object.create({
      get label() {
        laterGetterCount += 1;
        return 'unseen';
      },
    }) as Record<string, unknown>;
    Object.defineProperty(hostile, 'arrayLayerCount', {
      enumerable: true,
      get() {
        return {
          valueOf() {
            throw new TypeError('array layer conversion exploded');
          },
        };
      },
    });
    Object.defineProperty(hostile, 'aspect', {
      enumerable: true,
      get() {
        laterGetterCount += 1;
        return 'all';
      },
    });
    const encodingCount = codecs.encodings.length;
    const submissionCount = bridge.submissions.length;
    expect(() => texture.createView(hostile)).toThrow(
      'array layer conversion exploded',
    );
    expect(laterGetterCount).toBe(0);
    expect(codecs.encodings).toHaveLength(encodingCount);
    expect(bridge.submissions).toHaveLength(submissionCount);

    const after = texture.createView();
    const afterTarget = codecs.encodings.at(-1)?.target;
    expect(after).not.toBe(before);
    expect(afterTarget).toMatchObject({ kind: 'GPUTextureView' });
    expect(
      BigInt((afterTarget as { objectId: string }).objectId),
    ).toBe(BigInt((beforeTarget as { objectId: string }).objectId) + 1n);
    binding.revoke();
  });

  test('keeps the unauthorised TypeGPU delta absent after resource graduation', () => {
    const staging = describeProductionWebGpuWorkloadStaging();
    expect(staging.supportClaim).toBe('none');
    expect(staging.nativeExecutionEvidence).toBe(
      'none-recording-provider-is-inventory-only',
    );
    expect(staging.typegpuVersion).toBe('0.11.9');
    expect(staging.activeRouteOperationCount).toBe(36);
    expect(staging.workloadOperationCount).toBe(51);
    expect(staging.additionalOperationCount).toBe(19);
    expect(staging.additionalOperations).toHaveLength(19);
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
      const descriptor = interfaceObject === undefined
        ? undefined
        : Object.getOwnPropertyDescriptor(interfaceObject.prototype, memberName);
      expect(operation.disposition).toBe('staged-unroutable-no-prototype-member');
      expect(descriptor).toBeUndefined();
    }
    binding.revoke();
  });

  test('materializes exactly the reviewed 36-operation interface shape', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    expect(WEBGPU_PRODUCTION_PLAN.routes).toHaveLength(36);
    expect(Object.keys(binding.interfaceObjects)).toHaveLength(24);
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
      createBindGroupLayout(descriptor: unknown): object;
      createBuffer(descriptor: unknown): {
        readonly usage: number;
        readonly mapState: 'mapped' | 'pending' | 'unmapped';
      };
      createPipelineLayout(descriptor: unknown): object;
      createSampler(descriptor?: unknown): object;
      createShaderModule(descriptor: unknown): object;
      createTexture(descriptor: unknown): {
        readonly dimension: '1d' | '2d' | '3d';
        readonly format: string;
        readonly height: number;
        readonly width: number;
      };
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

    const bindGroupLayout = device.createBindGroupLayout({
      entries: [{ binding: 0, visibility: 7, buffer: {} }],
    });
    expect(bindGroupLayout).toBeObject();
    expect(log).toContain('convert:GPUDevice.createBindGroupLayout');
    expect(log).toContain('encode:GPUDevice.createBindGroupLayout');
    const bindGroupLayoutEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createBindGroupLayout',
    )!;
    expect(bindGroupLayoutEncoding.target).toMatchObject({
      kind: 'GPUBindGroupLayout',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    const mappedBuffer = device.createBuffer({
      label: 'mapped-buffer',
      mappedAtCreation: true,
      size: 128,
      usage: 9,
    });
    const logBeforeMappedBufferMetadata = log.slice();
    const submissionsBeforeMappedBufferMetadata = bridge.submissions.length;
    expect(mappedBuffer.usage).toBe(9);
    expect(mappedBuffer.mapState).toBe('mapped');
    expect(log).toEqual(logBeforeMappedBufferMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeMappedBufferMetadata);
    const unmappedBuffer = device.createBuffer({
      label: 'unmapped-buffer',
      size: 72,
      usage: 76,
    });
    const logBeforeUnmappedBufferMetadata = log.slice();
    const submissionsBeforeUnmappedBufferMetadata = bridge.submissions.length;
    expect(unmappedBuffer.usage).toBe(76);
    expect(unmappedBuffer.mapState).toBe('unmapped');
    expect(log).toEqual(logBeforeUnmappedBufferMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeUnmappedBufferMetadata);
    expect(() => {
      (unmappedBuffer as { usage: number }).usage = 1;
    }).toThrow();
    expect(log.filter((entry) => entry === 'convert:GPUDevice.createBuffer')).toHaveLength(2);
    expect(log.filter((entry) => entry === 'encode:GPUDevice.createBuffer')).toHaveLength(2);
    const bufferEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createBuffer',
    )!;
    expect(bufferEncoding.target).toEqual({
      kind: 'GPUBuffer',
      objectId: expect.any(String),
      objectGeneration: '1',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    const pipelineLayout = device.createPipelineLayout({
      bindGroupLayouts: [bindGroupLayout],
      immediateSize: 0,
    });
    expect(pipelineLayout).toBeObject();
    expect(log).toContain('convert:GPUDevice.createPipelineLayout');
    expect(log).toContain('encode:GPUDevice.createPipelineLayout');
    const pipelineLayoutEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createPipelineLayout',
    )!;
    expect(pipelineLayoutEncoding.target).toMatchObject({
      kind: 'GPUPipelineLayout',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const sampler = device.createSampler({
      label: 'sampler',
      magFilter: 'linear',
      minFilter: 'linear',
    });
    expect(Object.getPrototypeOf(sampler)).toBe(
      (globalObject.GPUSampler as { prototype: object }).prototype,
    );
    const samplerEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createSampler',
    )!;
    expect(samplerEncoding.receiver).toMatchObject({
      kind: 'GPUDevice',
      objectId: '201',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(samplerEncoding.target).toMatchObject({
      kind: 'GPUSampler',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

    const texture = device.createTexture({
      dimension: '2d',
      format: 'rgba8unorm',
      label: 'texture',
      size: { width: 32, height: 16, depthOrArrayLayers: 1 },
      usage: 23,
    });
    const logBeforeTextureMetadata = log.slice();
    const submissionsBeforeTextureMetadata = bridge.submissions.length;
    expect(texture.dimension).toBe('2d');
    expect(texture.format).toBe('rgba8unorm');
    expect(texture.height).toBe(16);
    expect(texture.width).toBe(32);
    expect(log).toEqual(logBeforeTextureMetadata);
    expect(bridge.submissions).toHaveLength(submissionsBeforeTextureMetadata);
    expect(() => {
      (texture as { width: number }).width = 1;
    }).toThrow();
    const textureEncoding = codecs.encodings.find(
      (encoding) => encoding.operationId === 'GPUDevice.createTexture',
    )!;
    expect(textureEncoding.receiver).toMatchObject({
      kind: 'GPUDevice',
      objectId: '201',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    expect(textureEncoding.target).toMatchObject({
      kind: 'GPUTexture',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });

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
    const drawRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPURenderPassEncoder.draw',
    )!;
    const drawRecord = (submitEncoding.sealedLocalTimeline as ReadonlyArray<
      Readonly<Record<string, unknown>>
    >).find((record) => record.operationId === drawRoute.wireId)!;
    expect(drawRecord).toMatchObject({
      operationId: drawRoute.wireId,
      operationName: 'GPURenderPassEncoder.draw',
      deviceIngressOrdinal: expect.any(String),
      capturedScopeId: '0',
      receiverRef: { kind: 'GPURenderPassEncoder' },
      wrapperAllocatedTargetRef: null,
      argumentBody: {
        vertexCount: 3,
        instanceCount: 1,
        firstVertex: 0,
        firstInstance: 0,
      },
      logicalError: null,
    });
    expect(typeof drawRecord.operationInstanceId).toBe('string');
    expect(BigInt(drawRecord.operationInstanceId as string) >= (1n << 63n)).toBe(true);
    expect(drawRecord).not.toHaveProperty('wireId');
    expect(drawRecord).not.toHaveProperty('receiver');
    expect(drawRecord).not.toHaveProperty('convertedArguments');
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
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    }) as {
      configure(configuration: unknown): void;
      getConfiguration(): Record<string, unknown> | null;
      getCurrentTexture(): {
        readonly dimension: '2d';
        readonly format: string;
        readonly height: number;
        readonly width: number;
        createView(): object;
        destroy(): void;
      };
      unconfigure(): void;
    };
    context.configure({ device, format: 'bgra8unorm' });
    const first = context.getCurrentTexture();
    expect(context.getCurrentTexture()).toBe(first);
    expect(first.dimension).toBe('2d');
    expect(first.format).toBe('bgra8unorm');
    expect(first.height).toBe(480);
    expect(first.width).toBe(640);
    expect(first.createView()).toBeObject();
    const createViewWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (route) => route.operationId === 'GPUTexture.createView',
    )?.wireId;
    if (createViewWireId === undefined) throw new Error('missing createView route');
    const firstSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === createViewWireId,
    );
    if (!firstSubmission) throw new Error('missing createView submission');
    const firstRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(firstSubmission.payload) as Readonly<{
        receiver: Readonly<Record<string, unknown>>;
        convertedArguments: Readonly<{
          currentOrigin: Readonly<Record<string, unknown>>;
        }>;
      }>;
    const firstOrigin = firstRequest.convertedArguments.currentOrigin;
    expect(firstOrigin).toMatchObject({
      originClass: 'canvas-current',
      contextRef: {
        kind: 'GPUCanvasContext',
        objectId: '401',
        objectGeneration: '1',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      attachmentGeneration: '31',
      contextGeneration: '37',
      configurationGeneration: '1',
      currentEpoch: '1',
      mintOperationProvenance: {
        operationInstanceId: '9223372036854775808',
        deviceIngressOrdinal: '2',
      },
      configuredDeviceRef: {
        kind: 'GPUDevice',
        objectId: '201',
        objectGeneration: '1',
        logicalDeviceId: '301',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      format: 'bgra8unorm',
      usage: 16,
      alphaMode: 'opaque',
      colorSpace: 'srgb',
      targetAuthorityDigest: CANVAS_AUTHORITY.targetAuthorityDigest,
      surfaceAccountToken: '41',
      surfaceAccountGeneration: '43',
    });
    expect(firstOrigin.textureOriginDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(firstOrigin).not.toHaveProperty('receiverTextureRef');
    expect(firstRequest.receiver).toMatchObject({
      kind: 'GPUTexture',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    });
    const snapshot = context.getConfiguration();
    expect(snapshot?.format).toBe('bgra8unorm');
    expect(snapshot).not.toBe(context.getConfiguration());
    context.configure({ device, format: 'bgra8unorm' });
    const second = context.getCurrentTexture();
    expect(second).not.toBe(first);
    expect(second.createView()).toBeObject();
    const secondSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === createViewWireId,
    );
    if (!secondSubmission) throw new Error('missing second createView submission');
    const secondRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(secondSubmission.payload) as Readonly<{
        convertedArguments: Readonly<{
          currentOrigin: Readonly<Record<string, unknown>>;
        }>;
      }>;
    const secondOrigin = secondRequest.convertedArguments.currentOrigin;
    expect(secondOrigin.configurationGeneration).toBe('2');
    expect(secondOrigin.currentEpoch).toBe('2');
    expect(secondOrigin.mintOperationProvenance).not.toEqual(
      firstOrigin.mintOperationProvenance,
    );
    expect(secondOrigin.textureOriginDigest).not.toBe(
      firstOrigin.textureOriginDigest,
    );
    // The private codec may structurally encode an old canvas texture. It
    // must preserve the immutable origin so the eventual semantic executor,
    // rather than a silent wrapper rebind, rejects the stale generation.
    expect(first.createView()).toBeObject();
    const staleSubmission = bridge.submissions.findLast(
      (submission) => submission.operationId === createViewWireId,
    );
    if (!staleSubmission) throw new Error('missing stale createView submission');
    const staleRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(staleSubmission.payload) as Readonly<{
        convertedArguments: Readonly<{
          currentOrigin: Readonly<Record<string, unknown>>;
        }>;
      }>;
    expect(staleRequest.convertedArguments.currentOrigin).toEqual(firstOrigin);
    expect(staleRequest.convertedArguments.currentOrigin).toMatchObject({
      configurationGeneration: '1',
      currentEpoch: '1',
    });
    context.unconfigure();
    expect(() => context.getCurrentTexture()).toThrow('not configured');
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

  test('interns only exact unchanged host canvas identities and fences stale generations', async () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    const identity = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    } as const;
    const first = binding.mintCanvasContext(identity) as TestCanvasContext;
    expect(binding.mintCanvasContext({
      ...identity,
      authority: { ...CANVAS_AUTHORITY },
    })).toBe(first);
    expect(() => binding.mintCanvasContext({
      ...identity,
      drawingBufferWidth: 641,
    })).toThrow('conflicts with existing host authority or extent');
    expect(() => binding.mintCanvasContext({
      ...identity,
      authority: {
        ...CANVAS_AUTHORITY,
        surfaceAccountGeneration: '44',
      },
    })).toThrow('conflicts with existing host authority or extent');

    // Provider-result wrappers deliberately remain allocation-local. The two
    // fake adapter results carry the same service identity but are not drawn
    // into the host-only Canvas identity index.
    const gpu = binding.gpu as { requestAdapter(): Promise<unknown> };
    expect(await gpu.requestAdapter()).not.toBe(await gpu.requestAdapter());

    const successor = binding.mintCanvasContext({
      ...identity,
      objectGeneration: '2',
      authority: {
        ...CANVAS_AUTHORITY,
        attachmentGeneration: '32',
        contextGeneration: '38',
      },
    }) as TestCanvasContext;
    expect(successor).not.toBe(first);
    expect(() => first.getConfiguration()).toThrow('identity is stale');
    expect(() => binding.mintCanvasContext(identity)).toThrow('identity is stale');

    binding.revoke();
    expect(() => successor.getConfiguration()).toThrow('realm is revoked');
    expect(() => binding.mintCanvasContext({
      ...identity,
      objectGeneration: '2',
    })).toThrow('realm is revoked');
  });

  test('fences canvas authority lineage across object IDs with bounded live indexes', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const firstIdentity = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    } as const;
    const first = binding.mintCanvasContext(firstIdentity) as TestCanvasContext;

    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
    })).toThrow('authority aliases an existing live identity');
    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      authority: { ...CANVAS_AUTHORITY, contextGeneration: '38' },
    })).toThrow('lineage is stale or conflicting');
    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      authority: { ...CANVAS_AUTHORITY, attachmentGeneration: '32' },
    })).toThrow('lineage is stale or conflicting');
    expect(() => binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      authority: {
        ...CANVAS_AUTHORITY,
        attachmentGeneration: '32',
        contextGeneration: '36',
      },
    })).toThrow('lineage is stale or conflicting');
    expect(first.getConfiguration()).toBeNull();

    const resizedAuthority = Object.freeze({
      ...CANVAS_AUTHORITY,
      attachmentGeneration: '32',
      contextGeneration: '38',
      targetAuthorityDigest: 'cd'.repeat(32),
    });
    const resized = binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      drawingBufferWidth: 800,
      drawingBufferHeight: 600,
      authority: resizedAuthority,
    }) as TestCanvasContext;
    expect(() => first.getConfiguration()).toThrow('identity is stale');
    expect(binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '402',
      drawingBufferWidth: 800,
      drawingBufferHeight: 600,
      authority: { ...resizedAuthority },
    })).toBe(resized);
    expect(() => binding.mintCanvasContext(firstIdentity))
      .toThrow('lineage is stale or conflicting');

    const resetChildAuthority = Object.freeze({
      ...resizedAuthority,
      surfaceAccountGeneration: '44',
      attachmentGeneration: '1',
      contextGeneration: '1',
      targetAuthorityDigest: 'ef'.repeat(32),
    });
    const resetChild = binding.mintCanvasContext({
      ...firstIdentity,
      objectId: '403',
      objectGeneration: '1',
      drawingBufferWidth: 1024,
      drawingBufferHeight: 768,
      authority: resetChildAuthority,
    }) as TestCanvasContext;
    expect(() => resized.getConfiguration()).toThrow('identity is stale');

    const distinct = binding.mintCanvasContext({
      objectId: '501',
      objectGeneration: '1',
      drawingBufferWidth: 320,
      drawingBufferHeight: 240,
      authority: {
        ...CANVAS_AUTHORITY,
        surfaceAccountToken: '99',
        surfaceAccountGeneration: '1',
      },
    }) as TestCanvasContext;
    expect(resetChild.getConfiguration()).toBeNull();
    expect(distinct.getConfiguration()).toBeNull();
    expect(inspectBinding(binding).current).toMatchObject({
      indexedCanvasContextCount: 2,
      indexedCanvasObjectCount: 2,
      indexedCanvasSurfaceTokenCount: 2,
    });
    binding.revoke();
    expect(inspectBinding(binding).lastClose).toMatchObject({
      indexedCanvasContextCount: 2,
      indexedCanvasObjectCount: 2,
      indexedCanvasSurfaceTokenCount: 2,
    });
  });

  test('device destroy synchronously enters canvas LOST exactly once and preserves stale origin', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const beforeLoss = context.getCurrentTexture();
    beforeLoss.createView();
    const beforeLossOrigin = latestCanvasTextureOrigin(bridge);

    device.destroy();
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    const afterLoss = context.getCurrentTexture();
    expect(afterLoss).not.toBe(beforeLoss);
    expect(context.getCurrentTexture()).toBe(afterLoss);
    afterLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
    });

    beforeLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeLossOrigin);
    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('GPUDevice is unavailable');

    // A later duplicate native loss input cannot re-expire the post-loss
    // invalid-device identity or advance configuration generation again.
    emitDeviceLoss(bridge, '301', '2');
    expect(context.getCurrentTexture()).toBe(afterLoss);
    expect(await device.lost).toEqual({
      reason: 'destroyed',
      message: 'The device was destroyed',
    });
    binding.revoke();
  });

  test('asynchronous device loss expires a configured canvas without unconfigure', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
    );
    const device = await requestTestDevice(binding);
    const recoveryDevice = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const beforeLoss = context.getCurrentTexture();
    beforeLoss.createView();
    const beforeLossOrigin = latestCanvasTextureOrigin(bridge);

    emitDeviceLoss(bridge, '301', '1');
    const afterLoss = context.getCurrentTexture();
    expect(afterLoss).not.toBe(beforeLoss);
    afterLoss.createView();
    const afterLossOrigin = latestCanvasTextureOrigin(bridge);
    expect(afterLossOrigin).toMatchObject({
      configurationGeneration: '2',
      currentEpoch: '2',
      configuredDeviceRef: { logicalDeviceId: '301' },
    });
    emitDeviceLoss(bridge, '301', '2');
    expect(context.getCurrentTexture()).toBe(afterLoss);

    beforeLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeLossOrigin);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });

    context.configure({ device: recoveryDevice, format: 'bgra8unorm' });
    const recovered = context.getCurrentTexture();
    expect(recovered).not.toBe(afterLoss);
    recovered.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '3',
      configuredDeviceRef: { logicalDeviceId: '311' },
    });
    emitDeviceLoss(bridge, '301', '3');
    expect(context.getCurrentTexture()).toBe(recovered);
    afterLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(afterLossOrigin);
    expect(context.getCurrentTexture()).toBe(recovered);
    binding.revoke();
  });

  test('reconfigure and unconfigure unlink prior device loss registries', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
    );
    const firstDevice = await requestTestDevice(binding);
    const secondDevice = await requestTestDevice(binding);
    const thirdDevice = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);

    context.configure({ device: firstDevice, format: 'bgra8unorm' });
    context.configure({ device: secondDevice, format: 'bgra8unorm' });
    const secondTexture = context.getCurrentTexture();
    emitDeviceLoss(bridge, '301', '1');
    expect(context.getCurrentTexture()).toBe(secondTexture);
    expect(await firstDevice.lost).toEqual({ reason: 'unknown', message: 'loss-4' });

    context.unconfigure();
    emitDeviceLoss(bridge, '311', '1');
    expect(() => context.getCurrentTexture()).toThrow('not configured');
    context.configure({ device: thirdDevice, format: 'bgra8unorm' });
    context.getCurrentTexture().createView();
    // configure A, configure B, unconfigure, configure C. Loss of the two
    // unlinked devices contributes no extra generation transition.
    expect(latestCanvasTextureOrigin(bridge).configurationGeneration).toBe('4');
    binding.revoke();
  });

  test('keeps an initial configure LOST when device loss is delivered inside submit', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    let inlineLossCount = 0;
    bridge.setSubmitHook((operationId) => {
      if (operationId !== configureWireId) return;
      inlineLossCount += 1;
      emitDeviceLoss(bridge, '301', String(inlineLossCount));
    });

    context.configure({ device, format: 'bgra8unorm' });
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(context.getConfiguration()?.format).toBe('bgra8unorm');
    const invalidTexture = context.getCurrentTexture();
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(inspectBinding(binding).current).toMatchObject({
      routedDeviceCount: 0,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      invalidCurrentTextureCount: 1,
    });
    invalidTexture.createView();
    expect(latestCanvasTextureOrigin(bridge).configurationGeneration).toBe('2');

    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(invalidTexture);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('GPUDevice is unavailable');
    expect(inlineLossCount).toBe(1);
    binding.revoke();
  });

  test('does not let inline loss resurrect a reconfigured context', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    context.configure({ device, format: 'bgra8unorm' });
    const beforeLoss = context.getCurrentTexture();
    beforeLoss.createView();
    const beforeLossOrigin = latestCanvasTextureOrigin(bridge);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId === configureWireId) emitDeviceLoss(bridge, '301', '1');
    });

    context.configure({ device, format: 'rgba8unorm' });
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(context.getConfiguration()?.format).toBe('rgba8unorm');
    const afterLoss = context.getCurrentTexture();
    expect(afterLoss).not.toBe(beforeLoss);
    expect(context.getCurrentTexture()).toBe(afterLoss);
    afterLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toMatchObject({
      configurationGeneration: '3',
      currentEpoch: '2',
      format: 'rgba8unorm',
    });
    expect(inspectBinding(binding).current.invalidCurrentTextureCount).toBe(1);

    beforeLoss.createView();
    expect(latestCanvasTextureOrigin(bridge)).toEqual(beforeLossOrigin);
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(context.getCurrentTexture()).toBe(afterLoss);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    binding.revoke();
  });

  test('fails closed when inline configure loss cannot advance its installed generation', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      {
        counterSeeds: { canvasConfigurationGeneration: U64_MAX_MINUS_ONE },
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding);
    const context = mintTestCanvasContext(binding);
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    bridge.setSubmitHook((operationId) => {
      if (operationId === configureWireId) emitDeviceLoss(bridge, '301', '1');
    });

    expect(() => context.configure({ device, format: 'bgra8unorm' }))
      .toThrow('realm closed during GPUCanvasContext.configure');
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message:
        'The WebGPU realm closed because canvas configuration generation was exhausted',
    });
    expect(() => context.getCurrentTexture()).toThrow('realm is revoked');
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 0,
      indexedCanvasObjectCount: 0,
      indexedCanvasSurfaceTokenCount: 0,
      indexedCanvasObjectCount: 0,
      indexedCanvasSurfaceTokenCount: 0,
      invalidCurrentTextureCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(inspectBinding(binding).lastClose).toMatchObject({
      routedDeviceCount: 1,
      indexedCanvasContextCount: 1,
      indexedCanvasObjectCount: 1,
      indexedCanvasSurfaceTokenCount: 1,
      canvasLossTransitionCount: 0,
    });
    emitDeviceLoss(bridge, '301', '2');
    emitProviderLoss(bridge);
    expect(await device.lost).toMatchObject({ reason: 'unknown' });
    binding.revoke();
  });

  test('routes only unsettled live devices and forgets 1,100 destroyed terminals', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
      { enableStateInspection: true },
    );
    let firstLost: Promise<unknown> | undefined;
    for (let index = 0; index < 1_100; index += 1) {
      const device = await requestTestDevice(binding);
      firstLost ??= device.lost;
      device.destroy();
      expect(await device.lost).toEqual({
        reason: 'destroyed',
        message: 'The device was destroyed',
      });
    }
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(0);
    binding.revoke();
    binding.revoke();
    const inspection = inspectBinding(binding);
    expect(inspection.lastClose).toMatchObject({
      closeReason: 'realm-revoked',
      routedDeviceCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
    });
    expect(await firstLost!).toEqual({
      reason: 'destroyed',
      message: 'The device was destroyed',
    });
  });

  test('snapshots targeted and provider-wide loss routing with stable duplicate settlement', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs([], { distinctLiveDevices: true }),
      { enableStateInspection: true },
    );
    const first = await requestTestDevice(binding);
    const second = await requestTestDevice(binding);
    const third = await requestTestDevice(binding);

    emitDeviceLoss(bridge, '301', '1');
    expect(await first.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(2);
    emitDeviceLoss(bridge, '301', '2');
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(2);

    emitProviderLoss(bridge);
    expect(await second.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(await third.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(inspectBinding(binding).current.routedDeviceCount).toBe(0);

    emitDeviceLoss(bridge, '311', '3');
    emitProviderLoss(bridge);
    binding.revoke();
    expect(await first.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(await second.lost).toEqual({ reason: 'unknown', message: 'loss-3' });
    expect(inspectBinding(binding).lastClose?.routedDeviceCount).toBe(0);
  });

  test('makes local destroy win over a synchronous native loss callback', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const destroyWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUDevice.destroy',
    )?.wireId;
    if (destroyWireId === undefined) throw new Error('missing destroy route');
    let inlineLossCount = 0;
    bridge.setSubmitHook((operationId) => {
      if (operationId !== destroyWireId) return;
      inlineLossCount += 1;
      emitDeviceLoss(bridge, '301', String(inlineLossCount));
    });

    device.destroy();
    expect(await device.lost).toEqual({
      reason: 'destroyed',
      message: 'The device was destroyed',
    });
    const submissionCount = bridge.submissions.length;
    device.destroy();
    expect(bridge.submissions).toHaveLength(submissionCount);
    expect(inlineLossCount).toBe(1);
    binding.revoke();
  });

  test('submits destroy cleanup once after unknown loss without replacing the winner', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
    );
    const device = await requestTestDevice(binding);
    const stableLost = device.lost;
    emitDeviceLoss(bridge, '301', '1');
    expect(await stableLost).toEqual({ reason: 'unknown', message: 'loss-4' });
    expect(device.lost).toBe(stableLost);

    const beforeDestroy = bridge.submissions.length;
    device.destroy();
    expect(bridge.submissions).toHaveLength(beforeDestroy + 1);
    expect(device.lost).toBe(stableLost);
    expect(await device.lost).toEqual({ reason: 'unknown', message: 'loss-4' });
    device.destroy();
    expect(bridge.submissions).toHaveLength(beforeDestroy + 1);
    binding.revoke();
  });

  test('does not repopulate Promise bookkeeping after synchronous realm close in submit', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      { enableStateInspection: true },
    );
    const requestAdapterWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPU.requestAdapter',
    )?.wireId;
    if (requestAdapterWireId === undefined) {
      throw new Error('missing requestAdapter route');
    }
    bridge.setSubmitHook((operationId) => {
      if (operationId !== requestAdapterWireId) return;
      bridge.emit({
        kind: 6,
        runtimeAddress: bridge.runtimeAddress,
        runtimeNonce: bridge.runtimeNonce,
        realmId: bridge.realmId,
        realmGeneration: bridge.realmGeneration,
        closeOrdinal: '1',
        closeReason: 1,
        payload: new Uint8Array(),
      });
    });
    await expect((binding.gpu as {
      requestAdapter(): Promise<unknown>;
    }).requestAdapter()).rejects.toThrow('realm closed during GPU.requestAdapter');
    expect(inspectBinding(binding).current).toMatchObject({
      active: false,
      pendingPromiseCount: 0,
      pendingLocalRecordCount: 0,
      routedDeviceCount: 0,
    });
    binding.revoke();
  });

  test('rejects missing or malformed host canvas authority synchronously', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    const base = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
    };
    expect(() => binding.mintCanvasContext(base as never))
      .toThrow('identity is incomplete or malformed');
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: {
        ...CANVAS_AUTHORITY,
        targetAuthorityDigest: 'not-a-digest',
      },
    })).toThrow('authority is incomplete or malformed');
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: {
        ...CANVAS_AUTHORITY,
        attachmentGeneration: '18446744073709551616',
      },
    })).toThrow('authority is incomplete or malformed');
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: {
        ...CANVAS_AUTHORITY,
        unexpected: 'ambient-data-must-not-be-carried',
      },
    } as never)).toThrow('authority is incomplete or malformed');
    const symbolAuthority = { ...CANVAS_AUTHORITY } as Record<PropertyKey, unknown>;
    symbolAuthority[Symbol('ambient')] = 'ambient-data-must-not-be-carried';
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: symbolAuthority,
    } as never)).toThrow('authority is incomplete or malformed');
    const nonEnumerableExtraAuthority = { ...CANVAS_AUTHORITY };
    Object.defineProperty(nonEnumerableExtraAuthority, 'ambient', {
      value: 'ambient-data-must-not-be-carried',
      enumerable: false,
    });
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: nonEnumerableExtraAuthority,
    } as never)).toThrow('authority is incomplete or malformed');
    const nonEnumerableMemberAuthority = { ...CANVAS_AUTHORITY };
    Object.defineProperty(nonEnumerableMemberAuthority, 'attachmentGeneration', {
      value: CANVAS_AUTHORITY.attachmentGeneration,
      enumerable: false,
    });
    expect(() => binding.mintCanvasContext({
      ...base,
      authority: nonEnumerableMemberAuthority,
    })).toThrow('authority is incomplete or malformed');
    binding.revoke();
  });

  test('captures canvas envelopes and nested authority exactly once without getters', () => {
    const binding = createProductionWebGpuPrivateBinding(
      createFakeBridge(),
      createFakeCodecs(),
    );
    let outerOwnKeys = 0;
    let outerDescriptors = 0;
    let outerGets = 0;
    let authorityOwnKeys = 0;
    let authorityDescriptors = 0;
    let authorityGets = 0;
    const authorityTarget = { ...CANVAS_AUTHORITY };
    let outerTarget: Record<string, unknown>;
    const authority = new Proxy(authorityTarget, {
      ownKeys(target) {
        authorityOwnKeys += 1;
        outerTarget.objectId = '999';
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        authorityDescriptors += 1;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      get() {
        authorityGets += 1;
        throw new Error('authority getter trap must not run');
      },
    });
    outerTarget = {
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority,
    };
    const envelope = new Proxy(outerTarget, {
      ownKeys(target) {
        outerOwnKeys += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        outerDescriptors += 1;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      get() {
        outerGets += 1;
        throw new Error('outer getter trap must not run');
      },
    });
    const context = binding.mintCanvasContext(envelope as never);
    expect(outerOwnKeys).toBe(1);
    expect(outerDescriptors).toBe(5);
    expect(outerGets).toBe(0);
    expect(authorityOwnKeys).toBe(1);
    expect(authorityDescriptors).toBe(5);
    expect(authorityGets).toBe(0);

    authorityTarget.contextGeneration = '999';
    expect(binding.mintCanvasContext({
      objectId: '401',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: { ...CANVAS_AUTHORITY },
    })).toBe(context);

    let outerAccessorRuns = 0;
    const outerAccessor = {
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
    } as Record<string, unknown>;
    Object.defineProperty(outerAccessor, 'objectId', {
      enumerable: true,
      get() {
        outerAccessorRuns += 1;
        return '402';
      },
    });
    expect(() => binding.mintCanvasContext(outerAccessor as never))
      .toThrow('identity is incomplete or malformed');
    expect(outerAccessorRuns).toBe(0);

    let authorityAccessorRuns = 0;
    const authorityAccessor = { ...CANVAS_AUTHORITY } as Record<string, unknown>;
    Object.defineProperty(authorityAccessor, 'contextGeneration', {
      enumerable: true,
      get() {
        authorityAccessorRuns += 1;
        return '38';
      },
    });
    expect(() => binding.mintCanvasContext({
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: authorityAccessor,
    } as never)).toThrow('authority is incomplete or malformed');
    expect(authorityAccessorRuns).toBe(0);

    const outerSymbol = {
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 640,
      drawingBufferHeight: 480,
      authority: CANVAS_AUTHORITY,
      [Symbol('ambient')]: true,
    };
    expect(() => binding.mintCanvasContext(outerSymbol as never))
      .toThrow('identity is incomplete or malformed');
    const outerExtra = { ...outerSymbol } as Record<PropertyKey, unknown>;
    delete outerExtra[Reflect.ownKeys(outerExtra).find(
      (key) => typeof key === 'symbol',
    )!];
    outerExtra.ambient = true;
    expect(() => binding.mintCanvasContext(outerExtra as never))
      .toThrow('identity is incomplete or malformed');
    const inherited = Object.assign(
      Object.create({ authority: CANVAS_AUTHORITY }) as Record<string, unknown>,
      {
        objectId: '402',
        objectGeneration: '1',
        drawingBufferWidth: 640,
        drawingBufferHeight: 480,
      },
    );
    expect(() => binding.mintCanvasContext(inherited as never))
      .toThrow('identity is incomplete or malformed');
    binding.revoke();
  });

  test('uses the final local object identity exactly once and closes before orphan allocation', async () => {
    const createBufferWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUDevice.createBuffer',
    )?.wireId;
    if (createBufferWireId === undefined) throw new Error('missing createBuffer route');
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const counterSeeds = { nextLocalObjectId: seed as string };
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        { counterSeeds, enableStateInspection: true },
      );
      // Construction snapshots the seed; later caller mutation is irrelevant.
      counterSeeds.nextLocalObjectId = '1';
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        createBuffer(descriptor: unknown): object;
      };
      for (let index = 0; index < successCount; index += 1) {
        expect(device.createBuffer({ mappedAtCreation: false, usage: 1 }))
          .toBeObject();
      }
      const targets = bridge.submissions
        .filter((submission) => submission.operationId === createBufferWireId)
        .map((submission) => submission.metadata.targetId);
      expect(targets).toEqual(
        successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX],
      );
      const beforeFailure = inspectBinding(binding).current;
      const submissionCount = bridge.submissions.length;
      expect(() => device.createBuffer({ mappedAtCreation: false, usage: 1 }))
        .toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      expect(inspectBinding(binding).lastClose?.closeReason)
        .toBe('counter-exhausted:local object identity');
      binding.revoke();
      binding.revoke();
    }
  });

  test('uses the final adapter request ordinal exactly once before fail-closed exhaustion', async () => {
    const requestDeviceWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUAdapter.requestDevice',
    )?.wireId;
    if (requestDeviceWireId === undefined) {
      throw new Error('missing requestDevice route');
    }
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs([], { distinctLiveDevices: true }),
        {
          counterSeeds: { nextAdapterOrdinal: seed },
          enableStateInspection: true,
        },
      );
      const adapter = await (binding.gpu as {
        requestAdapter(): Promise<unknown>;
      }).requestAdapter() as {
        requestDevice(): Promise<unknown>;
      };
      const attempts = Array.from(
        { length: successCount + 1 },
        () => adapter.requestDevice(),
      );
      const outcomes = await Promise.allSettled(attempts);
      expect(outcomes.at(-1)?.status).toBe('rejected');
      expect((outcomes.at(-1) as PromiseRejectedResult).reason).toBeInstanceOf(
        RangeError,
      );
      expect(
        bridge.submissions
          .filter((submission) => submission.operationId === requestDeviceWireId)
          .map((submission) => submission.metadata.adapterOrdinal),
      ).toEqual(successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX]);
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        routedDeviceCount: 0,
        pendingPromiseCount: 0,
      });
      expect(inspectBinding(binding).lastClose?.closeReason)
        .toBe('counter-exhausted:adapter request ordinal');
      binding.revoke();
    }
  });

  test('uses the final error scope identity exactly once before fail-closed exhaustion', async () => {
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const codecs = createFakeCodecs();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        codecs,
        {
          counterSeeds: { nextScopeId: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        pushErrorScope(filter: string): void;
      };
      for (let index = 0; index < successCount; index += 1) {
        device.pushErrorScope('validation');
      }
      expect(
        codecs.encodings
          .filter((encoding) =>
            encoding.operationId === 'GPUDevice.pushErrorScope'
          )
          .map((encoding) =>
            (encoding.convertedArguments as { scopeId: string }).scopeId
          ),
      ).toEqual(successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX]);
      const submissionCount = bridge.submissions.length;
      expect(() => device.pushErrorScope('validation')).toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      expect(inspectBinding(binding).current).toMatchObject({
        active: false,
        routedDeviceCount: 0,
        pendingLocalRecordCount: 0,
        pendingPromiseCount: 0,
      });
      expect(inspectBinding(binding).lastClose?.closeReason)
        .toBe('counter-exhausted:error scope identity');
      binding.revoke();
    }
  });

  test('fails canvas generation and epoch exhaustion closed before submission or texture allocation', async () => {
    const configureWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUCanvasContext.configure',
    )?.wireId;
    if (configureWireId === undefined) throw new Error('missing configure route');
    for (const [seed, successfulConfigures] of [
      [U64_MAX_MINUS_ONE, 1],
      [U64_MAX, 0],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        {
          counterSeeds: { canvasConfigurationGeneration: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      for (let index = 0; index < successfulConfigures; index += 1) {
        context.configure({ device, format: 'bgra8unorm' });
      }
      const beforeFailure = inspectBinding(binding).current;
      const submissionCount = bridge.submissions.length;
      expect(() => context.configure({ device, format: 'bgra8unorm' }))
        .toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(
        bridge.submissions.filter(
          (submission) => submission.operationId === configureWireId,
        ),
      ).toHaveLength(successfulConfigures);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }

    for (const [seed, hasFirstTexture] of [
      [U64_MAX_MINUS_ONE, true],
      [U64_MAX, false],
    ] as const) {
      const binding = createProductionWebGpuPrivateBinding(
        createFakeBridge(),
        createFakeCodecs(),
        {
          counterSeeds: { canvasCurrentEpoch: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      if (hasFirstTexture) {
        expect(context.getCurrentTexture()).toBeObject();
        context.configure({ device, format: 'bgra8unorm' });
      }
      const beforeFailure = inspectBinding(binding).current;
      expect(() => context.getCurrentTexture()).toThrow(RangeError);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }
  });

  test('preflights every configured context before applying a batch loss transition', async () => {
    const bridge = createFakeBridge();
    const binding = createProductionWebGpuPrivateBinding(
      bridge,
      createFakeCodecs(),
      {
        counterSeeds: {
          canvasConfigurationGeneration: U64_MAX_MINUS_TWO,
        },
        enableStateInspection: true,
      },
    );
    const device = await requestTestDevice(binding);
    const first = mintTestCanvasContext(binding);
    const second = binding.mintCanvasContext({
      objectId: '402',
      objectGeneration: '1',
      drawingBufferWidth: 800,
      drawingBufferHeight: 600,
      authority: {
        ...CANVAS_AUTHORITY,
        surfaceAccountToken: '99',
        surfaceAccountGeneration: '1',
      },
    }) as TestCanvasContext;
    first.configure({ device, format: 'bgra8unorm' });
    second.configure({ device, format: 'bgra8unorm' });
    second.configure({ device, format: 'bgra8unorm' });
    expect(inspectBinding(binding).current.canvasLossTransitionCount).toBe(0);

    emitProviderLoss(bridge);
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message:
        'The WebGPU realm closed because canvas configuration generation was exhausted',
    });
    expect(() => first.getConfiguration()).toThrow('realm is revoked');
    expect(() => second.getConfiguration()).toThrow('realm is revoked');
    const inspection = inspectBinding(binding);
    expect(inspection.current).toMatchObject({
      active: false,
      routedDeviceCount: 0,
      indexedCanvasContextCount: 0,
      pendingLocalRecordCount: 0,
      pendingPromiseCount: 0,
      canvasLossTransitionCount: 0,
    });
    expect(inspection.lastClose).toMatchObject({
      routedDeviceCount: 1,
      indexedCanvasContextCount: 2,
      indexedCanvasObjectCount: 2,
      indexedCanvasSurfaceTokenCount: 2,
      canvasLossTransitionCount: 0,
    });
    emitProviderLoss(bridge);
    expect(await device.lost).toEqual({
      reason: 'unknown',
      message:
        'The WebGPU realm closed because canvas configuration generation was exhausted',
    });
    binding.revoke();
  });

  test('uses MAX once for local operation and device ingress identities, then clears timelines', async () => {
    for (const [seed, successfulRecords] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const binding = createProductionWebGpuPrivateBinding(
        createFakeBridge(),
        createFakeCodecs(),
        {
          counterSeeds: { nextLocalOperationInstanceId: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      let texture: TestCanvasTexture | undefined;
      for (let index = 0; index < successfulRecords; index += 1) {
        texture = context.getCurrentTexture();
      }
      expect(texture).toBeObject();
      expect(inspectBinding(binding).current.pendingLocalRecordCount)
        .toBe(successfulRecords);
      const beforeFailure = inspectBinding(binding).current;
      expect(() => context.getCurrentTexture()).toThrow(RangeError);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }

    for (const [seed, successfulLocalRecords] of [
      [U64_MAX_MINUS_ONE, 1],
      [U64_MAX, 0],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        {
          counterSeeds: { nextDeviceIngressOrdinal: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding);
      const context = mintTestCanvasContext(binding);
      context.configure({ device, format: 'bgra8unorm' });
      if (successfulLocalRecords === 1) context.getCurrentTexture();
      const beforeFailure = inspectBinding(binding).current;
      expect(() => context.getCurrentTexture()).toThrow(RangeError);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(beforeFailure.allocatedWrapperCount);
      expect(inspectBinding(binding).current.pendingLocalRecordCount).toBe(0);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }
  });

  test('uses MAX once for queue ingress and closes before a further service submission', async () => {
    const submitWireId = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === 'GPUQueue.submit',
    )?.wireId;
    if (submitWireId === undefined) throw new Error('missing queue submit route');
    for (const [seed, successCount] of [
      [U64_MAX_MINUS_ONE, 2],
      [U64_MAX, 1],
    ] as const) {
      const bridge = createFakeBridge();
      const binding = createProductionWebGpuPrivateBinding(
        bridge,
        createFakeCodecs(),
        {
          counterSeeds: { nextQueueIngressOrdinal: seed },
          enableStateInspection: true,
        },
      );
      const device = await requestTestDevice(binding) as TestGpuDevice & {
        readonly queue: { submit(commandBuffers: readonly unknown[]): void };
      };
      for (let index = 0; index < successCount; index += 1) {
        device.queue.submit([]);
      }
      expect(
        bridge.submissions
          .filter((submission) => submission.operationId === submitWireId)
          .map((submission) => submission.metadata.queueIngressOrdinal),
      ).toEqual(successCount === 2 ? [U64_MAX_MINUS_ONE, U64_MAX] : [U64_MAX]);
      const submissionCount = bridge.submissions.length;
      const allocationCount = inspectBinding(binding).current.allocatedWrapperCount;
      expect(() => device.queue.submit([])).toThrow(RangeError);
      expect(bridge.submissions).toHaveLength(submissionCount);
      expect(inspectBinding(binding).current.allocatedWrapperCount)
        .toBe(allocationCount);
      expect(await device.lost).toMatchObject({ reason: 'unknown' });
      binding.revoke();
    }
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
