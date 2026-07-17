import { describe, expect, test } from 'bun:test';

import type { NativeGpuEventV2 } from './native-bridge';
import {
  EMBEDDED_EXECUTABLE_WEBGPU_CODECS,
  WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
  type ProductionGpuCodecWrapperAccess,
  type ProductionGpuServiceEncodingInput,
  type ProductionGpuWrapperKind,
  validateExecutableWebGpuCodecs,
} from './production-codecs';
import {
  WEBGPU_EXECUTABLE_CODEC_MANIFEST,
  WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT,
} from './production-codecs.generated';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';

type ResultEvent = Extract<NativeGpuEventV2, { kind: 1 }>;
type LossEvent = Extract<NativeGpuEventV2, { kind: 3 | 4 | 5 | 6 }>;

const wrapperKinds = new WeakMap<object, ProductionGpuWrapperKind>();

function wrapper(kind: ProductionGpuWrapperKind): object {
  const value = Object.freeze({ marker: kind });
  wrapperKinds.set(value, kind);
  return value;
}

const gpuAdapter = wrapper('GPUAdapter');
const gpuDevice = wrapper('GPUDevice');
const canvasContext = wrapper('GPUCanvasContext');
const commandBuffer = wrapper('GPUCommandBuffer');
const commandEncoder = wrapper('GPUCommandEncoder');
const renderPass = wrapper('GPURenderPassEncoder');
const renderPipeline = wrapper('GPURenderPipeline');
const shaderModule = wrapper('GPUShaderModule');
const texture = wrapper('GPUTexture');
const textureView = wrapper('GPUTextureView');

const wrappers: ProductionGpuCodecWrapperAccess = {
  reference(value, expectedKind) {
    if (typeof value !== 'object' || value === null) {
      throw new TypeError('unbranded WebGPU object');
    }
    const kind = wrapperKinds.get(value);
    if (!kind || (expectedKind && kind !== expectedKind)) {
      throw new TypeError('wrong WebGPU object brand');
    }
    return Object.freeze({
      kind,
      objectId: '11',
      objectGeneration: '1',
      logicalDeviceId: kind === 'GPUAdapter' ? '0' : '17',
      logicalDeviceGeneration: kind === 'GPUAdapter' ? '0' : '1',
      providerGeneration: '7',
    });
  },
};

function conversionArguments(operationId: string): readonly unknown[] {
  switch (operationId) {
    case 'GPU.requestAdapter':
      return [{ powerPreference: 'low-power', forceFallbackAdapter: 1 }];
    case 'GPUAdapter.requestDevice':
      return [{
        label: 'device',
        requiredFeatures: new Set(['timestamp-query']),
        requiredLimits: { maxBindGroups: 4, ignoredUndefined: undefined },
        defaultQueue: { label: 'queue' },
      }];
    case 'GPUCanvasContext.configure':
      return [{ device: gpuDevice, format: 'bgra8unorm' }];
    case 'GPUCommandEncoder.beginRenderPass':
      return [{ colorAttachments: [{ view: textureView }] }];
    case 'GPUCommandEncoder.finish':
      return [{ label: 'buffer' }];
    case 'GPUDevice.createCommandEncoder':
      return [{ label: 'encoder' }];
    case 'GPUDevice.createRenderPipeline':
      return [{
        vertex: { module: shaderModule },
        fragment: { module: shaderModule },
      }];
    case 'GPUDevice.createShaderModule':
      return [{ label: 'shader', code: '@vertex fn main() {}' }];
    case 'GPUDevice.pushErrorScope':
      return ['validation'];
    case 'GPUQueue.submit':
      return [new Set([commandBuffer])];
    case 'GPURenderPassEncoder.draw':
      return [3];
    case 'GPURenderPassEncoder.setPipeline':
      return [renderPipeline];
    case 'GPUTexture.createView':
      return [{}];
    default:
      return [];
  }
}

function reference(kind: ProductionGpuWrapperKind) {
  return Object.freeze({
    kind,
    objectId: '11',
    objectGeneration: '1',
    logicalDeviceId: kind === 'GPU' || kind === 'GPUAdapter' ? '0' : '17',
    logicalDeviceGeneration: kind === 'GPU' || kind === 'GPUAdapter' ? '0' : '1',
    providerGeneration: kind === 'GPU' ? '0' : '7',
  });
}

function serviceInput(
  operationId: string,
  convertedArguments: unknown = Object.freeze({ sample: true }),
): ProductionGpuServiceEncodingInput {
  const route = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === operationId,
  );
  if (!route) throw new Error(`unknown test route: ${operationId}`);
  const receiverKind = (route.receiverHandleKind ?? 'GPU') as ProductionGpuWrapperKind;
  const targetKind = route.wrapperAllocatedTargetHandleKind as
    | ProductionGpuWrapperKind
    | null;
  return Object.freeze({
    operationId,
    wireId: route.wireId,
    convertedArguments,
    receiver: reference(receiverKind),
    target: targetKind ? reference(targetKind) : undefined,
    capturedScopeId: '0',
    adapterOrdinal: operationId === 'GPUAdapter.requestDevice' ? '1' : '0',
    deviceIngressOrdinal: receiverKind === 'GPU' || receiverKind === 'GPUAdapter'
      ? '0'
      : '3',
    queueIngressOrdinal: operationId === 'GPUQueue.submit' ? '2' : '0',
    sealedLocalTimeline: Object.freeze([
      Object.freeze({ operationId: 'local', deviceIngressOrdinal: 2 }),
    ]),
  });
}

function routeWireId(operationId: string): number {
  const route = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === operationId,
  );
  if (!route) throw new Error(`unknown test route: ${operationId}`);
  return route.wireId;
}

function resultEvent(
  operationId: string,
  resultKind: number,
  payload: ArrayBufferView,
  detachedAlreadyLost = false,
  lossReason?: number,
  backendClass?: number,
): ResultEvent {
  return {
    kind: 1,
    runtimeAddress: '1',
    runtimeNonce: '2',
    topologyId: 1,
    operationId: routeWireId(operationId),
    operationInstanceId: '3',
    promiseId: '4',
    providerAdmission: 1,
    physicalSequence: '5',
    capturedScopeId: '0',
    realmId: '6',
    realmGeneration: '1',
    accountId: '7',
    accountGeneration: '1',
    accountAuthorityDigest: new Uint8Array(32),
    logicalDeviceId: operationId === 'GPU.requestAdapter' ? '0' : '17',
    logicalDeviceGeneration: operationId === 'GPU.requestAdapter' ? '0' : '1',
    providerGeneration: '8',
    ingressLogicalDeviceId: '0',
    ingressLogicalDeviceGeneration: '0',
    ingressProviderGeneration: '0',
    deviceTransition: 0,
    operationProviderGeneration: '8',
    authorityContextDigest: new Uint8Array(32),
    adapterOrdinal: '1',
    deviceIngressOrdinal: '0',
    queueIngressOrdinal: '0',
    receiverKind: 1,
    receiverFlags: 0,
    receiverId: '6',
    receiverGeneration: '1',
    targetKind: 0,
    targetFlags: 0,
    targetId: '0',
    targetGeneration: '0',
    resultKind,
    status: 0,
    payload,
    detachedAlreadyLost,
    ...(lossReason === undefined ? {} : { lossReason }),
    ...(backendClass === undefined ? {} : { backendClass }),
  } as unknown as ResultEvent;
}

function withTrailingByte(value: Uint8Array): Uint8Array {
  const output = new Uint8Array(value.byteLength + 1);
  output.set(value);
  output[output.length - 1] = 0xff;
  return output;
}

function mutateU16(value: Uint8Array, offset: number, replacement: number): Uint8Array {
  const output = value.slice();
  new DataView(output.buffer).setUint16(offset, replacement, true);
  return output;
}

function completeLimits(value = 4): Record<string, number> {
  return Object.fromEntries(
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames.map((name) => [name, value]),
  );
}

describe('generated injection-only WebGPU executable codecs', () => {
  test('pins one generated catalog over the exact reviewed 25-operation profile', () => {
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationCount).toBe(
      WEBGPU_PRODUCTION_PLAN.routes.length,
    );
    expect(WEBGPU_PRODUCTION_PLAN.activeRouteSubset.operationCount).toBe(25);
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationIds).toEqual(
      WEBGPU_PRODUCTION_PLAN.routes.map((route) => route.operationId),
    );
    expect(new Set(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationIds).size).toBe(
      WEBGPU_PRODUCTION_PLAN.routes.length,
    );
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames).toHaveLength(36);
    expect(validateExecutableWebGpuCodecs(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
    )).toBe(true);
    expect(EMBEDDED_EXECUTABLE_WEBGPU_CODECS).toBeUndefined();
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.disposition).toBe(
      'reviewed-generated-injection-only-native-decoder-absent-no-support-claim',
    );

    const publicTags = new Set(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.publicArguments.map((codec) => codec.tag),
    );
    const serviceTags = new Set(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.map((codec) => codec.tag),
    );
    const completionTags = new Set(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceCompletions.map((codec) => codec.tag),
    );
    for (const route of WEBGPU_PRODUCTION_PLAN.routes) {
      expect(publicTags.has(route.publicArgumentCodec)).toBe(true);
      expect(serviceTags.has(route.serviceArgumentCodec)).toBe(true);
      expect(completionTags.has(route.serviceCompletionCodec)).toBe(true);
    }
  });

  test('executes the selected public conversion for every reviewed operation', () => {
    for (const route of WEBGPU_PRODUCTION_PLAN.routes) {
      expect(() =>
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          route.operationId,
          conversionArguments(route.operationId),
          wrappers,
        )).not.toThrow();
    }

    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUAdapter.requestDevice',
        conversionArguments('GPUAdapter.requestDevice'),
        wrappers,
      ),
    ).toEqual({
      label: 'device',
      requiredFeatures: ['timestamp-query'],
      requiredLimits: { maxBindGroups: 4 },
      defaultQueue: { label: 'queue' },
    });
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPURenderPassEncoder.draw',
        [3],
        wrappers,
      ),
    ).toEqual([3, 1, 0, 0]);
  });

  test('conversion failures are synchronous, branded, bounded, and codec-specific', () => {
    const invalid: ReadonlyArray<readonly [string, readonly unknown[]]> = [
      ['GPU.requestAdapter', [{ powerPreference: 'fastest' }]],
      ['GPUAdapter.requestDevice', [null]],
      ['GPUCanvasContext.configure', [{ device: {}, format: 'bgra8unorm' }]],
      ['GPUCommandEncoder.beginRenderPass', [{ colorAttachments: [{ view: {} }] }]],
      ['GPUCommandEncoder.finish', [null]],
      ['GPUDevice.createCommandEncoder', [null]],
      ['GPUDevice.createRenderPipeline', [{}]],
      ['GPUDevice.createShaderModule', [{}]],
      ['GPUDevice.pushErrorScope', ['network']],
      ['GPUQueue.submit', [[{}]]],
      ['GPURenderPassEncoder.draw', [-1]],
      ['GPURenderPassEncoder.setPipeline', [{}]],
      ['GPUTexture.createView', [null]],
    ];
    for (const [operationId, args] of invalid) {
      expect(() =>
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          operationId,
          args,
          wrappers,
        )).toThrow(TypeError);
    }
    expect(() =>
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUQueue.submit',
        [Array.from({ length: 1025 }, () => commandBuffer)],
        wrappers,
      )).toThrow('reviewed sequence bound');
    expect(() =>
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createShaderModule',
        [{ code: '\ud800' }],
        wrappers,
      )).not.toThrow();
    expect(() =>
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPU.unknown',
        [],
        wrappers,
      )).toThrow('Unreviewed WebGPU operation');
  });

  test('encodes every currently complete service codec and fails closed for all others', () => {
    for (const route of WEBGPU_PRODUCTION_PLAN.routes) {
      const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
        (candidate) => candidate.tag === route.serviceArgumentCodec,
      )!;
      if (route.providerSubmission === 'none') {
        expect(() =>
          WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
            serviceInput(route.operationId),
          )).toThrow('has no service request codec');
      } else if (!codec.executableFromCurrentAuthenticatedInputs) {
        expect(codec.unavailableSemanticFields.length).toBeGreaterThan(0);
        expect(() =>
          WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
            serviceInput(route.operationId),
          )).toThrow('missing authenticated semantic fields');
      } else {
        const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
          serviceInput(route.operationId),
        );
        expect(payload).toBeInstanceOf(Uint8Array);
        expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
          payload as Uint8Array,
        )).toMatchObject({
          operationId: route.operationId,
          codec: route.serviceArgumentCodec,
          convertedArguments: { sample: true },
        });
      }
    }
  });

  test('request encoding is canonical and rejects unknown tags, trailing bytes, and bounds', () => {
    const input = serviceInput('GPU.requestAdapter', Object.freeze({
      z: 1,
      a: 'first',
    }));
    const first = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input);
    const second = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input);
    expect([...new Uint8Array(first as Uint8Array)]).toEqual([
      ...new Uint8Array(second as Uint8Array),
    ]);
    const bytes = first as Uint8Array;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      mutateU16(bytes, 6, 0xffff),
    )).toThrow('Unknown WebGPU service request tag');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      withTrailingByte(bytes),
    )).toThrow('Trailing bytes');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      new Uint8Array(WEBGPU_EXECUTABLE_CODEC_MANIFEST.maxPayloadBytes + 1),
    )).toThrow('reviewed byte bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPU.requestAdapter', Array.from({ length: 1025 }, () => null)),
    )).toThrow('reviewed count bound');
    const tooManyFields: Record<string, number> = {};
    for (let index = 0; index < 129; index += 1) tooManyFields[`k${index}`] = index;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPU.requestAdapter', tooManyFields),
    )).toThrow('reviewed field bound');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPU.requestAdapter', cyclic),
    )).toThrow('contains a cycle');
    const nested: Record<string, unknown> = {};
    let cursor = nested;
    for (let depth = 0; depth < 18; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPU.requestAdapter', nested),
    )).toThrow('reviewed nesting bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPU.requestAdapter', '\ud800'),
    )).toThrow('not well-formed UTF-16');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPU.requestAdapter'),
      capturedScopeId: '18446744073709551616',
    })).toThrow('exceeds the binary range');
  });

  test('decodes nullable adapter results with authenticated operation/result tags', () => {
    const nullPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      { kind: 'null' },
    );
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 2, nullPayload),
    )).toEqual({ kind: 'null' });

    const adapterPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      {
        kind: 'adapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '9',
      },
    );
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, adapterPayload),
    )).toEqual({
      kind: 'object',
      object: {
        kind: 'GPUAdapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '9',
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 2, adapterPayload),
    )).toThrow('result');
  });

  test('derives detached device loss only from authenticated carrier fields', () => {
    const base = {
      kind: 'device' as const,
      objectId: '51',
      objectGeneration: '1',
      logicalDeviceId: '61',
      logicalDeviceGeneration: '1',
      providerGeneration: '9',
      queueObjectId: '52',
      queueObjectGeneration: '1',
      features: ['timestamp-query'],
      limits: completeLimits(),
    };
    const livePayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUAdapter.requestDevice',
      base,
    );
    const incompleteLimits = completeLimits();
    Reflect.deleteProperty(
      incompleteLimits,
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames[0],
    );
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUAdapter.requestDevice',
      { ...base, limits: incompleteLimits },
    )).toThrow('omits required limit');
    const live = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, livePayload),
    );
    expect(live).toMatchObject({
      kind: 'object',
      object: {
        kind: 'GPUDevice',
        alreadyLost: undefined,
        limits: { maxBindGroups: 4 },
      },
    });

    const detachedPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUAdapter.requestDevice',
      { ...base, diagnosticMessage: 'adapter expired' },
    );
    const detached = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, detachedPayload, true, 1, 0),
    );
    expect(detached).toMatchObject({
      kind: 'object',
      object: {
        alreadyLost: { reason: 'unknown', message: 'adapter expired' },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, detachedPayload, false, 0, 0),
    )).toThrow('detached-only diagnostics');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, detachedPayload, true, 2, 0),
    )).toThrow('invalid authenticated loss fields');
    const missingCarrierFields = resultEvent(
      'GPUAdapter.requestDevice',
      3,
      livePayload,
    ) as ResultEvent & Record<string, unknown>;
    Reflect.deleteProperty(missingCarrierFields, 'detachedAlreadyLost');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      missingCarrierFields,
    )).toThrow('lacks authenticated detached state');
  });

  test('decodes nullable typed GPU errors and rejects unknown completion data', () => {
    const nullPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.popErrorScope',
      { kind: 'null' },
    );
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUDevice.popErrorScope',
      resultEvent('GPUDevice.popErrorScope', 2, nullPayload),
    )).toEqual({ kind: 'null' });
    const errorPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.popErrorScope',
      { kind: 'error', errorKind: 1, message: 'validation failed' },
    );
    const decoded = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUDevice.popErrorScope',
      resultEvent('GPUDevice.popErrorScope', 4, errorPayload),
    );
    expect(decoded.kind).toBe('value');
    expect(decoded.kind === 'value' && decoded.value).toBeInstanceOf(Error);
    expect(decoded.kind === 'value' && (decoded.value as Error).name).toBe(
      'GPUValidationError',
    );
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUDevice.popErrorScope',
      resultEvent(
        'GPUDevice.popErrorScope',
        4,
        mutateU16(errorPayload, 6, 0xffff),
      ),
    )).toThrow('Unexpected WebGPU codec tag');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUDevice.popErrorScope',
      resultEvent('GPUDevice.popErrorScope', 4, withTrailingByte(errorPayload)),
    )).toThrow('Trailing bytes');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.unknown',
      resultEvent('GPUDevice.popErrorScope', 4, errorPayload),
    )).toThrow('Unreviewed WebGPU operation');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.popErrorScope',
      { kind: 'error', errorKind: 1, message: 'x'.repeat(4097) },
    )).toThrow('reviewed byte bound');
  });

  test('device-loss decoding authenticates reason enums and rejects trailing bytes', () => {
    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeDeviceLoss(
      'device destroyed',
    );
    const base: LossEvent = {
      kind: 4,
      runtimeAddress: '1',
      runtimeNonce: '2',
      topologyId: 1,
      realmId: '3',
      realmGeneration: '1',
      accountId: '4',
      accountGeneration: '1',
      accountAuthorityDigest: new Uint8Array(32),
      logicalDeviceId: '5',
      logicalDeviceGeneration: '1',
      providerGeneration: '6',
      logicalLossOrdinal: '1',
      lastAcceptedPhysicalSequence: '7',
      backendClass: 0,
      lossReason: 2,
      hasInitiatingOperation: false,
      payload,
    };
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeDeviceLoss(base)).toEqual({
      reason: 'destroyed',
      message: 'device destroyed',
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeDeviceLoss({
      ...base,
      lossReason: 99,
    })).toThrow('device-loss reason');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeDeviceLoss({
      ...base,
      payload: withTrailingByte(payload),
    })).toThrow('Trailing bytes');
  });
});
