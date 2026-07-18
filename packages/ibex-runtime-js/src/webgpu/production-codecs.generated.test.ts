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
  WEBGPU_OBJECT_KIND_TAGS,
} from './production-codecs.generated';
import {
  createExecutableWebGpuCodecs,
  type ExecutableWebGpuCodecManifest,
} from './production-codec-runtime';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';

type ResultEvent = Extract<NativeGpuEventV2, { kind: 1 }>;
type LossEvent = Extract<NativeGpuEventV2, { kind: 3 | 4 | 5 | 6 }>;

const wrapperKinds = new WeakMap<object, ProductionGpuWrapperKind>();

function bytesHex(bytes: Uint8Array): string {
  return Array.from(
    bytes,
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('');
}

function wrapper(kind: ProductionGpuWrapperKind): object {
  const value = Object.freeze({ marker: kind });
  wrapperKinds.set(value, kind);
  return value;
}

const gpuAdapter = wrapper('GPUAdapter');
const gpuDevice = wrapper('GPUDevice');
const bindGroupLayout = wrapper('GPUBindGroupLayout');
const canvasContext = wrapper('GPUCanvasContext');
const commandBuffer = wrapper('GPUCommandBuffer');
const commandEncoder = wrapper('GPUCommandEncoder');
const renderPass = wrapper('GPURenderPassEncoder');
const renderPipeline = wrapper('GPURenderPipeline');
const shaderModule = wrapper('GPUShaderModule');
const texture = wrapper('GPUTexture');
const textureView = wrapper('GPUTextureView');

function bindGroupLayoutDescriptor(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    label: 'corpus-layout',
    entries: Object.freeze([
      Object.freeze({ binding: 0, visibility: 7, buffer: Object.freeze({}) }),
      Object.freeze({
        binding: 1,
        visibility: 7,
        sampler: Object.freeze({ type: 'non-filtering' }),
      }),
      Object.freeze({ binding: 2, visibility: 7, texture: Object.freeze({}) }),
      Object.freeze({
        binding: 3,
        visibility: 6,
        storageTexture: Object.freeze({ format: 'rgba16float' }),
      }),
    ]),
  });
}

function convertedBindGroupLayoutDescriptor(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    label: 'corpus-layout',
    entries: Object.freeze([
      Object.freeze({
        binding: 0,
        visibility: 7,
        buffer: Object.freeze({
          type: 'uniform',
          hasDynamicOffset: false,
          minBindingSize: 0,
        }),
      }),
      Object.freeze({
        binding: 1,
        visibility: 7,
        sampler: Object.freeze({ type: 'non-filtering' }),
      }),
      Object.freeze({
        binding: 2,
        visibility: 7,
        texture: Object.freeze({
          sampleType: 'float',
          viewDimension: '2d',
          multisampled: false,
        }),
      }),
      Object.freeze({
        binding: 3,
        visibility: 6,
        storageTexture: Object.freeze({
          access: 'write-only',
          format: 'rgba16float',
          viewDimension: '2d',
        }),
      }),
    ]),
  });
}

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
    case 'GPUDevice.createBindGroupLayout':
      return [bindGroupLayoutDescriptor()];
    case 'GPUDevice.createBuffer':
      return [{ label: 'corpus-buffer', mappedAtCreation: false, size: 128, usage: 76 }];
    case 'GPUDevice.createPipelineLayout':
      return [{
        label: 'pipeline-layout',
        bindGroupLayouts: [bindGroupLayout],
        immediateSize: 0,
      }];
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
  convertedArguments: unknown = operationId === 'GPU.requestAdapter'
    ? Object.freeze({
      featureLevel: 'core',
      forceFallbackAdapter: false,
      xrCompatible: false,
    })
    : operationId === 'GPUAdapter.requestDevice'
    ? Object.freeze({
      label: 'device',
      requiredFeatures: Object.freeze(['timestamp-query']),
      requiredLimits: Object.freeze({ maxBindGroups: 4 }),
      defaultQueue: Object.freeze({ label: 'queue' }),
    })
    : operationId === 'GPUDevice.createBindGroupLayout'
    ? convertedBindGroupLayoutDescriptor()
    : operationId === 'GPUDevice.createBuffer'
    ? Object.freeze({
      label: 'corpus-buffer',
      mappedAtCreation: false,
      size: 128,
      usage: 76,
    })
    : operationId === 'GPUDevice.createPipelineLayout'
    ? Object.freeze({
      label: 'pipeline-layout',
      bindGroupLayouts: Object.freeze([reference('GPUBindGroupLayout')]),
      immediateSize: 0,
    })
    : operationId === 'GPUDevice.createCommandEncoder'
    ? Object.freeze({ label: 'encoder' })
    : operationId === 'GPUDevice.createShaderModule'
    ? Object.freeze({ label: 'shader', code: '@vertex fn main() {}' })
    : operationId === 'GPUDevice.destroy'
    ? null
    : Object.freeze({ sample: true }),
): ProductionGpuServiceEncodingInput {
  const route = WEBGPU_PRODUCTION_PLAN.routes.find(
    (candidate) => candidate.operationId === operationId,
  );
  if (!route) throw new Error(`unknown test route: ${operationId}`);
  const receiverKind = (route.receiverHandleKind ?? 'GPU') as ProductionGpuWrapperKind;
  const targetKind = route.wrapperAllocatedTargetHandleKind as
    | ProductionGpuWrapperKind
    | null;
  const requestAdapter = operationId === 'GPU.requestAdapter';
  const requestDevice = operationId === 'GPUAdapter.requestDevice';
  const deviceDestroy = operationId === 'GPUDevice.destroy';
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
    sealedLocalTimeline: requestAdapter || requestDevice
      ? Object.freeze([])
      : deviceDestroy
      ? Object.freeze([
        Object.freeze({
          operationId: routeWireId('GPURenderPassEncoder.draw'),
          operationName: 'GPURenderPassEncoder.draw',
          operationInstanceId: '12',
          deviceIngressOrdinal: '2',
          capturedScopeId: '0',
          receiverRef: reference('GPURenderPassEncoder'),
          wrapperAllocatedTargetRef: null,
          argumentBody: Object.freeze({
            vertexCount: 3,
            instanceCount: 1,
            firstVertex: 0,
            firstInstance: 0,
          }),
          logicalError: null,
        }),
      ])
      : Object.freeze([
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
  detachedProviderAdmission: 0 | 1 = 0,
): ResultEvent {
  const requestAdapter = operationId === 'GPU.requestAdapter';
  const requestDevice = operationId === 'GPUAdapter.requestDevice';
  const serviceDetached = requestDevice && detachedAlreadyLost;
  const resultLogicalDeviceId = requestAdapter ? '0' : '17';
  const resultLogicalDeviceGeneration = requestAdapter ? '0' : '1';
  const resultProviderGeneration = requestAdapter ? '0' : '8';
  const ingressHasDevice = !requestAdapter && !requestDevice;
  const accountAuthorityDigest = new Uint8Array(32);
  accountAuthorityDigest[0] = 1;
  const authorityContextDigest = new Uint8Array(32);
  authorityContextDigest[0] = 2;
  return {
    kind: 1,
    runtimeAddress: '1',
    runtimeNonce: '2',
    topologyId: 1,
    operationId: routeWireId(operationId),
    operationInstanceId: '3',
    promiseId: '4',
    providerAdmission: serviceDetached ? detachedProviderAdmission : 1,
    physicalSequence:
      serviceDetached && detachedProviderAdmission === 0 ? '0' : '5',
    capturedScopeId: '0',
    realmId: '6',
    realmGeneration: '1',
    accountId: '7',
    accountGeneration: '1',
    accountAuthorityDigest,
    logicalDeviceId: resultLogicalDeviceId,
    logicalDeviceGeneration: resultLogicalDeviceGeneration,
    providerGeneration: resultProviderGeneration,
    ingressLogicalDeviceId: ingressHasDevice ? '17' : '0',
    ingressLogicalDeviceGeneration: ingressHasDevice ? '1' : '0',
    ingressProviderGeneration: ingressHasDevice ? '8' : '0',
    deviceTransition: requestDevice ? (serviceDetached ? 2 : 1) : 0,
    operationProviderGeneration: '8',
    authorityContextDigest,
    adapterOrdinal: requestAdapter ? '0' : '1',
    deviceIngressOrdinal: '0',
    queueIngressOrdinal: '0',
    receiverKind: requestDevice ? 2 : 1,
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

function mutateU32(value: Uint8Array, offset: number, replacement: number): Uint8Array {
  const output = value.slice();
  new DataView(output.buffer).setUint32(offset, replacement, true);
  return output;
}

function completeLimits(value = 4): Record<string, number> {
  return Object.fromEntries(
    WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames.map((name) => [name, value]),
  );
}

describe('generated injection-only WebGPU executable codecs', () => {
  test('pins one generated catalog over the exact reviewed 28-operation profile', () => {
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationCount).toBe(
      WEBGPU_PRODUCTION_PLAN.routes.length,
    );
    expect(WEBGPU_PRODUCTION_PLAN.activeRouteSubset.operationCount).toBe(28);
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
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.schema).toBe(
      'ibex/webgpu-executable-codec-manifest/2',
    );
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.disposition).toBe(
      'reviewed-generated-injection-and-request-adapter-request-device-create-bind-group-layout-create-buffer-create-pipeline-layout-create-command-encoder-create-shader-module-device-destroy-payload-codegen-input-native-codec-not-installed-no-support-claim',
    );
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms).toMatchObject({
      schema: 'ibex/webgpu-native-codec-programs/2',
      scope: {
        excluded:
          'full-call-or-event-construction-and-global-v2-carrier-validation',
      },
      carrierValidationDependency: {
        authority: 'ExactGpuSemanticCallV2-and-ExactGpuServiceEventV2',
        programOwns:
          'selected-payload-layout-plus-operation-specific-carrier-joins-and-constraints-only',
      },
      constants: { providerTopologyId: 1 },
      routes: [
        { operationId: 'GPU.requestAdapter', wireId: 1660448199 },
        { operationId: 'GPUAdapter.requestDevice', wireId: 194635792 },
        { operationId: 'GPUDevice.createBindGroupLayout', wireId: 2544948076 },
        { operationId: 'GPUDevice.createBuffer', wireId: 3212558232 },
        { operationId: 'GPUDevice.createPipelineLayout', wireId: 3373402978 },
        { operationId: 'GPUDevice.createCommandEncoder', wireId: 4055478657 },
        { operationId: 'GPUDevice.createShaderModule', wireId: 599085487 },
        { operationId: 'GPUDevice.destroy', wireId: 206890944 },
      ],
    });
    const destroyProgram = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.find(
      (route) => route.operationId === 'GPUDevice.destroy',
    )!;
    expect(destroyProgram.completion.semanticTerminalMapping.terminals).toMatchObject([
      {
        terminalId: 'repeat-cleanup-noop',
        providerTokenCount: 0,
        physicalSequenceCount: 0,
        event: {
          kind: 'operation-result',
          completionVariant: 'repeat-cleanup-noop',
        },
      },
      {
        terminalId: 'first-cleanup-rejection',
        providerTokenCount: 0,
        physicalSequenceCount: 0,
        event: {
          kind: 'device-error',
          kindValue: 2,
          completionPayloadEncoderEligibility: 'excluded-not-an-operation-result',
        },
      },
      {
        terminalId: 'first-cleanup-provider',
        providerTokenCount: 1,
        physicalSequenceCount: 1,
        event: {
          kind: 'operation-result',
          completionVariant: 'first-cleanup-provider',
        },
      },
    ]);
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.carrierConstants).toEqual({
      EXACT_GPU_SERVICE_EVENT_OPERATION_RESULT_V2: 1,
      EXACT_GPU_SERVICE_EVENT_DEVICE_ERROR_V2: 2,
      EXACT_GPU_DEVICE_UNCHANGED_V2: 0,
      EXACT_GPU_DEVICE_ASSIGNED_V2: 1,
      EXACT_GPU_DEVICE_ASSIGNED_DETACHED_V2: 2,
      EXACT_GPU_PROVIDER_NOT_ADMITTED_V2: 0,
      EXACT_GPU_PROVIDER_ADMITTED_V2: 1,
      EXACT_GPU_DEVICE_LOSS_UNKNOWN_V2: 1,
      EXACT_GPU_BACKEND_NONE_V2: 0,
      EXACT_GPU_RESULT_NONE_V2: 0,
      EXACT_GPU_RESULT_NULL_V2: 2,
      EXACT_GPU_RESULT_OBJECT_V2: 3,
    });
    expect(() => createExecutableWebGpuCodecs(
      {
        ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
        objectKindTags: {
          ...WEBGPU_EXECUTABLE_CODEC_MANIFEST.objectKindTags,
          GPU: WEBGPU_OBJECT_KIND_TAGS.GPUAdapter,
          GPUAdapter: WEBGPU_OBJECT_KIND_TAGS.GPU,
        },
      },
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('cross-link');

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

  test('fails closed on native codec program and carrier-constant mutations', () => {
    const program = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms;
    const route = program.routes.find(
      (candidate) => candidate.operationId === 'GPU.requestAdapter',
    )!;
    const reversedRequestFields = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: [{
          ...route,
          request: {
            ...route.request,
            payload: {
              ...route.request.payload,
              fields: route.request.payload.fields.slice().reverse(),
            },
          },
        }],
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      reversedRequestFields,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const numericU64Zero = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: [{
          ...route,
          request: {
            ...route.request,
            carrierConstraints: route.request.carrierConstraints.map(
              (constraint) => constraint.carrierPath === 'provider_generation'
                ? { ...constraint, value: 0 }
                : constraint,
            ),
          },
        }],
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      numericU64Zero,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const changedTopology = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        constants: { providerTopologyId: 2 },
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedTopology,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const expandedProgramScope = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        scope: {
          ...program.scope,
          excluded: 'none',
        },
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      expandedProgramScope,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const createCommandEncoderRoute = program.routes.find(
      (candidate) =>
        candidate.operationId === 'GPUDevice.createCommandEncoder',
    )!;
    const duplicatedCreateCommandEncoderRoute = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: [...program.routes, createCommandEncoderRoute],
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      duplicatedCreateCommandEncoderRoute,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const changedCreateCommandEncoderTarget = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: program.routes.map((candidate) =>
          candidate.operationId === 'GPUDevice.createCommandEncoder'
            ? {
              ...candidate,
              request: {
                ...candidate.request,
                carrierConstraints: candidate.request.carrierConstraints.map(
                  (constraint) => constraint.carrierPath === 'target.kind'
                    ? { ...constraint, valueFrom: 'objectKindTags.GPUTexture' }
                    : constraint,
                ),
              },
            }
            : candidate
        ),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedCreateCommandEncoderTarget,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const createShaderModuleRoute = program.routes.find(
      (candidate) => candidate.operationId === 'GPUDevice.createShaderModule',
    )!;
    const reorderedShaderValidation =
      createShaderModuleRoute.request.semanticServiceBoundary.requiredAfterDecode.slice();
    reorderedShaderValidation.splice(
      4,
      2,
      reorderedShaderValidation[5]!,
      reorderedShaderValidation[4]!,
    );
    const changedShaderValidationOrder = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: program.routes.map((candidate) =>
          candidate.operationId === 'GPUDevice.createShaderModule'
            ? {
              ...createShaderModuleRoute,
              request: {
                ...createShaderModuleRoute.request,
                semanticServiceBoundary: {
                  ...createShaderModuleRoute.request.semanticServiceBoundary,
                  requiredAfterDecode: reorderedShaderValidation,
                },
              },
            }
            : candidate
        ),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedShaderValidationOrder,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const createPipelineLayoutRoute = program.routes.find(
      (candidate) => candidate.operationId === 'GPUDevice.createPipelineLayout',
    )!;
    const reorderedPipelineValidation =
      createPipelineLayoutRoute.request.semanticServiceBoundary
        .requiredAfterDecode.slice();
    reorderedPipelineValidation.splice(
      4,
      2,
      reorderedPipelineValidation[5]!,
      reorderedPipelineValidation[4]!,
    );
    const changedPipelineValidationOrder = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: program.routes.map((candidate) =>
          candidate.operationId === 'GPUDevice.createPipelineLayout'
            ? {
              ...createPipelineLayoutRoute,
              request: {
                ...createPipelineLayoutRoute.request,
                semanticServiceBoundary: {
                  ...createPipelineLayoutRoute.request.semanticServiceBoundary,
                  requiredAfterDecode: reorderedPipelineValidation,
                },
              },
            }
            : candidate
        ),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedPipelineValidationOrder,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const changedResultKind = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      carrierConstants: {
        ...WEBGPU_EXECUTABLE_CODEC_MANIFEST.carrierConstants,
        EXACT_GPU_RESULT_NULL_V2: 3,
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedResultKind,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const changedDestroyPayload = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: program.routes.map((candidate) =>
          candidate.operationId === 'GPUDevice.destroy'
            ? {
              ...candidate,
              completion: {
                ...candidate.completion,
                payload: { kind: 'empty', exactLengthBytes: 1 },
              },
            }
            : candidate
        ),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedDestroyPayload,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const changedDestroyTerminalMapping = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      nativeCodecPrograms: {
        ...program,
        routes: program.routes.map((candidate) =>
          candidate.operationId === 'GPUDevice.destroy'
            ? {
              ...candidate,
              completion: {
                ...candidate.completion,
                semanticTerminalMapping: {
                  ...candidate.completion.semanticTerminalMapping,
                  terminals: candidate.completion.semanticTerminalMapping.terminals.map(
                    (terminal) => terminal.terminalId === 'first-cleanup-rejection'
                      ? {
                        ...terminal,
                        event: {
                          ...terminal.event,
                          kind: 'operation-result',
                        },
                      }
                      : terminal,
                  ),
                },
              },
            }
            : candidate
        ),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedDestroyTerminalMapping,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('native codec program');

    const requestDeviceCodecIndex =
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.findIndex(
        (codec) => codec.tag === 'gpu-request-device-service-request-v1',
      );
    expect(requestDeviceCodecIndex).toBeGreaterThanOrEqual(0);
    const omittedRequestDevicePrerequisites = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      serviceArguments: WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.map(
        (codec, index) => index === requestDeviceCodecIndex
          ? { ...codec, nativeProgramPrerequisitesRepresented: false }
          : codec,
      ),
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      omittedRequestDevicePrerequisites,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('cross-link');

    const renamedCompleteLimit = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      completeLimitNames: WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames.map(
        (name, index) => index === 0 ? `${name}Renamed` : name,
      ),
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      renamedCompleteLimit,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('Invalid generated WebGPU executable codec manifest');

    const duplicatedCompleteLimit = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      completeLimitNames: WEBGPU_EXECUTABLE_CODEC_MANIFEST.completeLimitNames.map(
        (name, index, names) => index === names.length - 1 ? names[0] : name,
      ),
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      duplicatedCompleteLimit,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('Invalid generated WebGPU executable codec manifest');

    const substitutedTextureFormat = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      webIdlVocabulary: {
        ...WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary,
        gpuTextureFormats:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary.gpuTextureFormats.map(
            (format, index) => index === 50 ? 'not-a-gpu-texture-format' : format,
          ),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      substitutedTextureFormat,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('Invalid generated WebGPU executable codec manifest');
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

    const hostileRequiredLimits = Object.defineProperty({}, '__proto__', {
      value: 4,
      writable: true,
      enumerable: true,
      configurable: true,
    });
    const convertedHostileDescriptor =
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUAdapter.requestDevice',
        [{ requiredLimits: hostileRequiredLimits }],
        wrappers,
      ) as Readonly<{ requiredLimits: Readonly<Record<string, number>> }>;
    expect(Object.getPrototypeOf(convertedHostileDescriptor.requiredLimits)).toBeNull();
    expect(Object.keys(convertedHostileDescriptor.requiredLimits)).toContain('__proto__');
    expect(Object.prototype.hasOwnProperty.call(
      convertedHostileDescriptor.requiredLimits,
      '__proto__',
    )).toBe(true);
    expect(Object.getOwnPropertyDescriptor(
      convertedHostileDescriptor.requiredLimits,
      '__proto__',
    )).toMatchObject({ value: 4, enumerable: true });
    const hostileRequestInput = {
      ...serviceInput('GPUAdapter.requestDevice'),
      convertedArguments: convertedHostileDescriptor,
    };
    const hostilePayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(hostileRequestInput);
    const inspectedHostileRequest = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(hostilePayload) as Readonly<{
        convertedArguments: Readonly<{
          requiredLimits: Readonly<Record<string, number>>;
        }>;
      }>;
    expect(Object.getPrototypeOf(
      inspectedHostileRequest.convertedArguments.requiredLimits,
    )).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(
      inspectedHostileRequest.convertedArguments.requiredLimits,
      '__proto__',
    )).toBe(true);
    expect(inspectedHostileRequest.convertedArguments.requiredLimits.__proto__)
      .toBe(4);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      hostileRequestInput,
    )).toThrow('missing authenticated semantic fields');

    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPURenderPassEncoder.draw',
        [3],
        wrappers,
      ),
    ).toEqual([3, 1, 0, 0]);
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPU.requestAdapter',
        [{ featureLevel: 'future-profile' }],
        wrappers,
      ),
    ).toMatchObject({
      featureLevel: 'future-profile',
      forceFallbackAdapter: false,
      xrCompatible: false,
    });
    let featureLevelReads = 0;
    const changingFeatureLevel = Object.defineProperty({}, 'featureLevel', {
      enumerable: true,
      get() {
        featureLevelReads += 1;
        return featureLevelReads === 1 ? 'future-profile' : 'core';
      },
    });
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPU.requestAdapter',
        [changingFeatureLevel],
        wrappers,
      ),
    ).toMatchObject({ featureLevel: 'future-profile' });
    expect(featureLevelReads).toBe(1);
    let powerPreferenceReads = 0;
    const changingPowerPreference = Object.defineProperty({}, 'powerPreference', {
      enumerable: true,
      get() {
        powerPreferenceReads += 1;
        return powerPreferenceReads === 1 ? 'high-performance' : 'fastest';
      },
    });
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPU.requestAdapter',
        [changingPowerPreference],
        wrappers,
      ),
    ).toMatchObject({ powerPreference: 'high-performance' });
    expect(powerPreferenceReads).toBe(1);
    const dictionaryReadOrder: string[] = [];
    const orderedOptions = Object.create(null) as Record<string, unknown>;
    for (const name of [
      'xrCompatible',
      'powerPreference',
      'forceFallbackAdapter',
      'featureLevel',
    ]) {
      Object.defineProperty(orderedOptions, name, {
        enumerable: true,
        get() {
          dictionaryReadOrder.push(name);
          if (name === 'featureLevel') return 'core';
          if (name === 'powerPreference') return 'low-power';
          return false;
        },
      });
    }
    WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPU.requestAdapter',
      [orderedOptions],
      wrappers,
    );
    expect(dictionaryReadOrder).toEqual([
      'featureLevel',
      'forceFallbackAdapter',
      'powerPreference',
      'xrCompatible',
    ]);
    const interleavedTrace: string[] = [];
    let featureConverted = false;
    const interleavedOptions = Object.create(null) as Record<string, unknown>;
    Object.defineProperties(interleavedOptions, {
      featureLevel: {
        enumerable: true,
        get() {
          interleavedTrace.push('feature:get');
          return {
            toString() {
              interleavedTrace.push('feature:convert');
              featureConverted = true;
              return 'core';
            },
          };
        },
      },
      forceFallbackAdapter: {
        enumerable: true,
        get() {
          interleavedTrace.push('force:get');
          return featureConverted;
        },
      },
      powerPreference: {
        enumerable: true,
        get() {
          interleavedTrace.push('power:get');
          return undefined;
        },
      },
      xrCompatible: {
        enumerable: true,
        get() {
          interleavedTrace.push('xr:get');
          return false;
        },
      },
    });
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPU.requestAdapter',
        [interleavedOptions],
        wrappers,
      ),
    ).toMatchObject({ forceFallbackAdapter: true, featureLevel: 'core' });
    expect(interleavedTrace).toEqual([
      'feature:get',
      'feature:convert',
      'force:get',
      'power:get',
      'xr:get',
    ]);
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPU.requestAdapter',
        [null],
        wrappers,
      ),
    ).toEqual({
      forceFallbackAdapter: false,
      featureLevel: 'core',
      xrCompatible: false,
    });
    let inheritedDefaultReads = 0;
    Object.defineProperty(Object.prototype, 'featureLevel', {
      configurable: true,
      get() {
        inheritedDefaultReads += 1;
        return 'future-profile';
      },
    });
    try {
      expect(
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          'GPU.requestAdapter',
          [undefined],
          wrappers,
        ),
      ).toMatchObject({ featureLevel: 'core' });
      expect(inheritedDefaultReads).toBe(0);
    } finally {
      Reflect.deleteProperty(Object.prototype, 'featureLevel');
    }
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUAdapter.requestDevice',
        [null],
        wrappers,
      ),
    ).toEqual({
      label: '',
      requiredFeatures: [],
      requiredLimits: {},
      defaultQueue: { label: '' },
    });
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUTexture.createView',
        [null],
        wrappers,
      ),
    ).toMatchObject({
      label: '',
      aspect: 'all',
      baseMipLevel: 0,
      baseArrayLayer: 0,
    });
  });

  test('conversion failures are synchronous, branded, bounded, and codec-specific', () => {
    const invalid: ReadonlyArray<readonly [string, readonly unknown[]]> = [
      ['GPU.requestAdapter', [{ powerPreference: 'fastest' }]],
      ['GPUCanvasContext.configure', [{ device: {}, format: 'bgra8unorm' }]],
      ['GPUCommandEncoder.beginRenderPass', [{ colorAttachments: [{ view: {} }] }]],
      ['GPUDevice.createBindGroupLayout', [{}]],
      ['GPUDevice.createBuffer', [{}]],
      ['GPUDevice.createPipelineLayout', [{}]],
      ['GPUDevice.createRenderPipeline', [{}]],
      ['GPUDevice.createShaderModule', [{}]],
      ['GPUDevice.pushErrorScope', ['network']],
      ['GPUQueue.submit', [[{}]]],
      ['GPURenderPassEncoder.draw', [-1]],
      ['GPURenderPassEncoder.setPipeline', [{}]],
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
          convertedArguments: route.operationId === 'GPU.requestAdapter'
            ? {
              featureLevel: 'core',
              forceFallbackAdapter: false,
              xrCompatible: false,
            }
            : route.operationId === 'GPUDevice.destroy'
            ? null
            : route.operationId === 'GPUDevice.createBindGroupLayout'
            ? convertedBindGroupLayoutDescriptor()
            : route.operationId === 'GPUDevice.createBuffer'
            ? {
              label: 'corpus-buffer',
              mappedAtCreation: false,
              size: 128,
              usage: 76,
            }
            : route.operationId === 'GPUDevice.createPipelineLayout'
            ? {
              label: 'pipeline-layout',
              bindGroupLayouts: [reference('GPUBindGroupLayout')],
              immediateSize: 0,
            }
            : route.operationId === 'GPUDevice.createCommandEncoder'
            ? { label: 'encoder' }
            : route.operationId === 'GPUDevice.createShaderModule'
            ? { label: 'shader', code: '@vertex fn main() {}' }
            : { sample: true },
        });
      }
    }
  });

  test('request encoding is canonical and rejects unknown tags, trailing bytes, and bounds', () => {
    const input = serviceInput('GPUDevice.createRenderPipeline', Object.freeze({
      z: 1,
      a: 'first',
    }));
    const first = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input);
    const second = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input);
    expect([...new Uint8Array(first as Uint8Array)]).toEqual([
      ...new Uint8Array(second as Uint8Array),
    ]);
    const bytes = first as Uint8Array;
    const utf8Ordered = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPUDevice.createRenderPipeline', Object.freeze({
        '\u{10000}': 'supplementary-plane',
        '\ue000': 'basic-multilingual-plane',
      })),
    );
    const inspectedUtf8Order = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(utf8Ordered as Uint8Array) as {
        convertedArguments: Record<string, unknown>;
      };
    expect(Object.keys(inspectedUtf8Order.convertedArguments)).toEqual([
      '\ue000',
      '\u{10000}',
    ]);
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
      serviceInput(
        'GPUDevice.createRenderPipeline',
        Array.from({ length: 1025 }, () => null),
      ),
    )).toThrow('reviewed count bound');
    const tooManyFields: Record<string, number> = {};
    for (let index = 0; index < 129; index += 1) tooManyFields[`k${index}`] = index;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPUDevice.createRenderPipeline', tooManyFields),
    )).toThrow('reviewed field bound');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPUDevice.createRenderPipeline', cyclic),
    )).toThrow('contains a cycle');
    const nested: Record<string, unknown> = {};
    let cursor = nested;
    for (let depth = 0; depth < 18; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPUDevice.createRenderPipeline', nested),
    )).toThrow('reviewed nesting bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput('GPUDevice.createRenderPipeline', '\ud800'),
    )).toThrow('not well-formed UTF-16');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUDevice.createCommandEncoder'),
      capturedScopeId: '18446744073709551616',
    })).toThrow('exceeds the binary range');
  });

  test('enforces the requestAdapter native program before encoding and on inspection', () => {
    const defaults = serviceInput('GPU.requestAdapter');
    const defaultPayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(defaults) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      defaultPayload,
    )).toMatchObject({
      operationId: 'GPU.requestAdapter',
      receiver: {
        kind: 'GPU',
        logicalDeviceId: '0',
        logicalDeviceGeneration: '0',
        providerGeneration: '0',
      },
      target: null,
      capturedScopeId: '0',
      adapterOrdinal: '0',
      deviceIngressOrdinal: '0',
      queueIngressOrdinal: '0',
      sealedLocalTimeline: [],
      convertedArguments: {
        featureLevel: 'core',
        forceFallbackAdapter: false,
        xrCompatible: false,
      },
    });

    const compatibility = serviceInput('GPU.requestAdapter', Object.freeze({
      featureLevel: 'compatibility',
      forceFallbackAdapter: true,
      powerPreference: 'low-power',
      xrCompatible: false,
    }));
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
        compatibility,
      ) as Uint8Array,
    )).toMatchObject({
      convertedArguments: {
        featureLevel: 'compatibility',
        forceFallbackAdapter: true,
        powerPreference: 'low-power',
        xrCompatible: false,
      },
    });

    for (const convertedArguments of [
      {
        featureLevel: 'core',
        forceFallbackAdapter: false,
      },
      {
        featureLevel: 'future-profile',
        forceFallbackAdapter: false,
        xrCompatible: false,
      },
      {
        featureLevel: 'core',
        forceFallbackAdapter: 0,
        xrCompatible: false,
      },
      {
        featureLevel: 'core',
        forceFallbackAdapter: false,
        powerPreference: 'balanced',
        xrCompatible: false,
      },
      {
        featureLevel: 'core',
        forceFallbackAdapter: false,
        xrCompatible: false,
        unreviewed: true,
      },
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
        serviceInput('GPU.requestAdapter', Object.freeze(convertedArguments)),
      )).toThrow();
    }

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...defaults,
      receiver: reference('GPUAdapter'),
    })).toThrow('GPU singleton');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...defaults,
      receiver: { ...defaults.receiver, objectId: '0' },
    })).toThrow('positive identity');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...defaults,
      receiver: { ...defaults.receiver, logicalDeviceId: '17' },
    })).toThrow('zero device/provider provenance');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...defaults,
      target: reference('GPUAdapter'),
    })).toThrow('must not carry a target');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...defaults,
      capturedScopeId: '1',
    })).toThrow('must be zero');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...defaults,
      sealedLocalTimeline: [{ operationId: 'local' }],
    })).toThrow('exactly empty');

    const nonzeroScopePayload = defaultPayload.slice();
    nonzeroScopePayload[54] = 1;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      nonzeroScopePayload,
    )).toThrow('must be zero');
  });

  test('executes requestDevice payload codegen only through test support while production stays blocked', () => {
    const input = serviceInput('GPUAdapter.requestDevice');
    const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === 'gpu-request-device-service-request-v1',
    )!;
    expect(codec.nativeProgramPrerequisitesRepresented).toBe(true);
    expect(codec.executableFromCurrentAuthenticatedInputs).toBe(false);
    expect(codec.unavailableSemanticFields).toEqual([
      'generatedLogicalProviderDescriptor',
      'authenticatedResultSelectionIdentity',
    ]);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      input,
    )).toThrow('missing authenticated semantic fields');

    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId: 'GPUAdapter.requestDevice',
      codec: 'gpu-request-device-service-request-v1',
      receiver: {
        kind: 'GPUAdapter',
        logicalDeviceId: '0',
        logicalDeviceGeneration: '0',
        providerGeneration: '7',
      },
      target: null,
      capturedScopeId: '0',
      adapterOrdinal: '1',
      deviceIngressOrdinal: '0',
      queueIngressOrdinal: '0',
      sealedLocalTimeline: [],
      convertedArguments: {
        label: 'device',
        requiredFeatures: ['timestamp-query'],
        requiredLimits: { maxBindGroups: 4 },
        defaultQueue: { label: 'queue' },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        receiver: { ...input.receiver, providerGeneration: '0' },
      })).toThrow('positive identity');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        convertedArguments: {
          ...(input.convertedArguments as Record<string, unknown>),
          generatedLogicalProviderDescriptor: {},
        },
      })).toThrow('reviewed descriptor shape');
  });

  test('executes the private createCommandEncoder request program and empty terminal receipt', () => {
    const input = serviceInput('GPUDevice.createCommandEncoder');
    const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === 'gpu-create-command-encoder-service-request-v1',
    )!;
    expect(codec.nativeProgramPrerequisitesRepresented).toBe(true);
    expect(codec.executableFromCurrentAuthenticatedInputs).toBe(true);
    expect(codec.unavailableSemanticFields).toEqual([]);

    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    expect(bytesHex(payload)).toBe(
      '494247510100050081b1b9f1030b000000000000000100000000000000110000000000000001000000000000000700000000000000010f0b00000000000000010000000000000011000000000000000100000000000000070000000000000000000000000000000000000000000000030000000000000000000000000000000601000000070200000014000000646576696365496e67726573734f7264696e616c03020000000b0000006f7065726174696f6e496405050000006c6f63616c0701000000050000006c6162656c0507000000656e636f646572',
    );
    expect(Array.from(payload.slice(53, 55))).toEqual([
      1,
      WEBGPU_OBJECT_KIND_TAGS.GPUCommandEncoder,
    ]);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input))
      .toEqual(payload);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId: 'GPUDevice.createCommandEncoder',
      codec: 'gpu-create-command-encoder-service-request-v1',
      receiver: {
        kind: 'GPUDevice',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      target: {
        kind: 'GPUCommandEncoder',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      adapterOrdinal: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '0',
      convertedArguments: { label: 'encoder' },
    });
    const wrongTargetKindPayload = payload.slice();
    wrongTargetKindPayload[54] = WEBGPU_OBJECT_KIND_TAGS.GPUTexture;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      wrongTargetKindPayload,
    )).toThrow('authenticated device provenance');
    for (const length of [0, 1, 4, 11, 12, payload.byteLength - 1]) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        payload.slice(0, length),
      )).toThrow();
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({ ...input, target: undefined }))
      .toThrow('wrapper-allocated target');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: reference('GPUTexture'),
      })).toThrow('authenticated device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: {
          ...input.target!,
          logicalDeviceId: '18',
        },
      })).toThrow('authenticated device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        deviceIngressOrdinal: '0',
      })).toThrow('positive identity');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        convertedArguments: { label: 'encoder', extra: true },
      })).toThrow('reviewed descriptor shape');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        sealedLocalTimeline: null,
      })).toThrow('bounded sequence');

    const completion = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPUDevice.createCommandEncoder', { kind: 'none' });
    expect(completion.byteLength).toBe(0);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.createCommandEncoder',
      { kind: 'null' },
    )).toThrow('wrong shape');
  });

  test('executes the private createBindGroupLayout request program and defers the workload closure', () => {
    const operationId = 'GPUDevice.createBindGroupLayout';
    const input = serviceInput(operationId);
    const nativeRoute = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
      .find((candidate) => candidate.operationId === operationId)!;
    const planRoute = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === operationId,
    )!;
    const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === 'gpu-create-bind-group-layout-service-request-v1',
    )!;
    expect(nativeRoute.wireId).toBe(planRoute.wireId);
    expect(nativeRoute.request.catalog.wireTag).toBe(15);
    expect(nativeRoute.completion.catalog.wireTag).toBe(2);
    expect(nativeRoute.request.executablePrerequisites).toEqual([]);
    expect(nativeRoute.request.semanticServiceBoundary.requiredAfterDecode).toEqual([
      'authenticate-contiguous-sealed-local-timeline-prefix',
      'validate-current-live-device-generation',
      'validate-operation-coverage',
      'validate-authorized-live-account',
      'validate-bind-group-layout-descriptor-under-logical-device-capabilities',
      'reserve-bind-group-layout-handle-and-aggregate-envelope',
      'authenticate-wrapper-allocated-bind-group-layout-target',
      'select-provider-admission-and-physical-sequence',
    ]);
    expect(codec.nativeProgramPrerequisitesRepresented).toBe(true);
    expect(codec.executableFromCurrentAuthenticatedInputs).toBe(true);
    expect(codec.unavailableSemanticFields).toEqual([]);

    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [bindGroupLayoutDescriptor()],
      wrappers,
    )).toEqual(convertedBindGroupLayoutDescriptor());

    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    expect(new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint16(6, true)).toBe(15);
    expect(new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint32(8, true)).toBe(nativeRoute.wireId);
    expect(Array.from(payload.slice(53, 55))).toEqual([
      1,
      WEBGPU_OBJECT_KIND_TAGS.GPUBindGroupLayout,
    ]);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input))
      .toEqual(payload);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId,
      codec: 'gpu-create-bind-group-layout-service-request-v1',
      receiver: {
        kind: 'GPUDevice',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      target: {
        kind: 'GPUBindGroupLayout',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      adapterOrdinal: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '0',
      convertedArguments: convertedBindGroupLayoutDescriptor(),
    });

    const convertedComparison = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(operationId, [{
        entries: [{ binding: 0, visibility: 7, sampler: { type: 'comparison' } }],
      }], wrappers);
    expect(convertedComparison).toMatchObject({
      entries: [{ sampler: { type: 'comparison' } }],
    });
    const comparisonPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, convertedComparison));
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      comparisonPayload,
    )).toMatchObject({ convertedArguments: convertedComparison });

    const convertedExternalTexture = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(operationId, [{
        entries: [{ binding: 0, visibility: 7, externalTexture: {} }],
      }], wrappers);
    expect(convertedExternalTexture).toMatchObject({
      entries: [{ externalTexture: {} }],
    });
    const externalTexturePayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, convertedExternalTexture));
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      externalTexturePayload,
    )).toMatchObject({ convertedArguments: convertedExternalTexture });

    const base = convertedBindGroupLayoutDescriptor() as Readonly<{
      label: string;
      entries: ReadonlyArray<Readonly<Record<string, unknown>>>;
    }>;
    const bufferEntry = (binding: number) => ({
      binding,
      visibility: 7,
      buffer: { type: 'uniform', hasDynamicOffset: false, minBindingSize: 0 },
    });
    const semanticallyRejectedDescriptors: readonly unknown[] = [
      { ...base, entries: [] },
      { ...base, label: '💡'.repeat(15) },
      { ...base, entries: [...base.entries, bufferEntry(4), bufferEntry(5)] },
      { ...base, entries: base.entries.map((entry, index) =>
        index === 1 ? { ...entry, binding: 2 } : entry) },
      { ...base, entries: base.entries.map((entry, index) =>
        index === 1 ? { ...entry, binding: 0 } : entry) },
      { ...base, entries: base.entries.map((entry, index) =>
        index === 1 ? { ...entry, visibility: 1 } : entry) },
      { ...base, entries: base.entries.map((entry, index) => index === 0
        ? {
          ...entry,
          buffer: { type: 'uniform', hasDynamicOffset: true, minBindingSize: 0 },
        }
        : entry) },
      { ...base, entries: base.entries.map((entry, index) => index === 0
        ? {
          ...entry,
          buffer: { type: 'uniform', hasDynamicOffset: false, minBindingSize: 1 },
        }
        : entry) },
      { ...base, entries: base.entries.map((entry, index) => index === 2
        ? {
          ...entry,
          texture: {
            sampleType: 'depth',
            viewDimension: 'cube',
            multisampled: true,
          },
        }
        : entry) },
      { ...base, entries: base.entries.map((entry, index) => index === 3
        ? {
          ...entry,
          storageTexture: {
            access: 'read-only',
            format: 'rgba8unorm',
            viewDimension: '3d',
          },
        }
        : entry) },
      { ...base, entries: base.entries.map((entry, index) => index === 0
        ? { ...entry, sampler: { type: 'filtering' } }
        : entry) },
      { ...base, entries: base.entries.map((entry, index) => index === 0
        ? { binding: entry.binding, visibility: entry.visibility }
        : entry) },
    ];
    for (const convertedArguments of semanticallyRejectedDescriptors) {
      const semanticBoundaryPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(serviceInput(operationId, convertedArguments));
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        semanticBoundaryPayload,
      )).toMatchObject({ convertedArguments });
    }

    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, {
        ...base,
        extra: true,
      }))).toThrow('canonical descriptor');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, {
        ...base,
        entries: [{ binding: 0, visibility: 7, sampler: { type: 'invalid' } }],
      }))).toThrow('canonical WebIDL dictionary');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, {
        ...base,
        entries: Array.from(
          { length: WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount + 1 },
          (_, binding) => bufferEntry(binding),
        ),
      }))).toThrow('structural transport bounds');

    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({ ...input, target: undefined }))
      .toThrow('wrapper-allocated target');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        receiver: reference('GPUAdapter'),
      })).toThrow('authenticated GPUDevice receiver');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: reference('GPUShaderModule'),
      })).toThrow('authenticated device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: { ...input.target!, logicalDeviceId: '18' },
      })).toThrow('authenticated device provenance');

    const completion = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult(operationId, { kind: 'none' });
    expect(completion.byteLength).toBe(0);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      operationId,
      { kind: 'null' },
    )).toThrow('wrong shape');
  });

  test('carries the complete createBindGroupLayout structural domain before semantic narrowing', () => {
    const operationId = 'GPUDevice.createBindGroupLayout';
    const viewDimensions = [
      '1d',
      '2d',
      '2d-array',
      'cube',
      'cube-array',
      '3d',
    ] as const;
    const rawEntries: Array<Record<string, unknown>> = [];
    let binding = 0;
    for (const type of ['uniform', 'storage', 'read-only-storage'] as const) {
      rawEntries.push({
        binding: binding++,
        visibility: 0xffff_ffff,
        buffer: {
          hasDynamicOffset: true,
          minBindingSize: type === 'uniform' ? Number.MAX_SAFE_INTEGER : 1,
          type,
        },
      });
    }
    for (const type of ['filtering', 'non-filtering', 'comparison'] as const) {
      rawEntries.push({ binding: binding++, visibility: 0, sampler: { type } });
    }
    for (const sampleType of [
      'float',
      'unfilterable-float',
      'depth',
      'sint',
      'uint',
    ] as const) {
      rawEntries.push({
        binding: binding++,
        visibility: 1,
        texture: { multisampled: true, sampleType },
      });
    }
    for (const viewDimension of viewDimensions) {
      rawEntries.push({
        binding: binding++,
        visibility: 2,
        texture: { viewDimension },
      });
    }
    for (const access of ['write-only', 'read-only', 'read-write'] as const) {
      rawEntries.push({
        binding: binding++,
        visibility: 4,
        storageTexture: { access, format: 'rgba16float' },
      });
    }
    for (const viewDimension of viewDimensions) {
      rawEntries.push({
        binding: binding++,
        visibility: 7,
        storageTexture: { format: 'rgba16float', viewDimension },
      });
    }
    rawEntries.push({
      binding: 0xffff_ffff,
      visibility: 0xffff_ffff,
      buffer: {},
      externalTexture: {},
      sampler: {},
      storageTexture: { format: 'astc-12x12-unorm-srgb', viewDimension: 'cube' },
      texture: { viewDimension: 'cube-array' },
    });
    rawEntries.push({ binding: 0, visibility: 0 });

    const convertedArguments = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        operationId,
        [{ label: 'x'.repeat(65_536), entries: rawEntries }],
        wrappers,
      ) as Readonly<{
        label: string;
        entries: ReadonlyArray<Readonly<Record<string, unknown>>>;
      }>;
    expect(convertedArguments.label).toHaveLength(65_536);
    expect(convertedArguments.entries).toHaveLength(rawEntries.length);
    expect(convertedArguments.entries[0]).toMatchObject({
      visibility: 0xffff_ffff,
      buffer: { minBindingSize: Number.MAX_SAFE_INTEGER, type: 'uniform' },
    });
    expect(convertedArguments.entries.at(-2)).toMatchObject({
      binding: 0xffff_ffff,
      externalTexture: {},
      sampler: { type: 'filtering' },
      storageTexture: { viewDimension: 'cube' },
      texture: { viewDimension: 'cube-array' },
    });
    expect(convertedArguments.entries.at(-1)).toEqual({
      binding: 0,
      visibility: 0,
    });
    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, convertedArguments));
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(payload))
      .toMatchObject({ convertedArguments });

    const sequenceMaximum = WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount;
    expect(sequenceMaximum).toBe(1024);
    const maximumConvertedArguments = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        operationId,
        [{
          entries: Array.from({ length: sequenceMaximum }, (_, index) => ({
            binding: index,
            visibility: 0,
          })),
        }],
        wrappers,
      ) as Readonly<{ entries: ReadonlyArray<unknown> }>;
    expect(maximumConvertedArguments.entries).toHaveLength(sequenceMaximum);
    const maximumPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(
        serviceInput(operationId, maximumConvertedArguments),
      );
    const inspectedMaximum = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(maximumPayload) as Readonly<{
        convertedArguments: Readonly<{
          label: string;
          entries: ReadonlyArray<unknown>;
        }>;
      }>;
    expect(inspectedMaximum.convertedArguments.label).toBe('');
    expect(inspectedMaximum.convertedArguments.entries)
      .toHaveLength(sequenceMaximum);
  });

  test('executes createBuffer with exact WebIDL order, six-field targets, and structural-only narrowing', () => {
    const operationId = 'GPUDevice.createBuffer';
    const nativeRoute = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
      .find((candidate) => candidate.operationId === operationId)!;
    const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === 'gpu-create-buffer-service-request-v1',
    )!;
    expect(nativeRoute.wireId).toBe(3212558232);
    expect(nativeRoute.request.catalog.wireTag).toBe(17);
    expect(nativeRoute.completion.catalog.wireTag).toBe(2);
    expect(nativeRoute.request.executablePrerequisites).toEqual([]);
    expect(nativeRoute.request.semanticServiceBoundary.requiredAfterDecode).toEqual([
      'authenticate-contiguous-sealed-local-timeline-prefix',
      'validate-current-live-device-generation',
      'validate-operation-coverage',
      'validate-authorized-live-account-and-aggregate-envelope',
      'validate-buffer-descriptor-under-reviewed-workload',
      'validate-buffer-size-under-logical-max-and-structural-ceiling',
      'validate-buffer-usage-closed-bits',
      'validate-buffer-map-usage-combination',
      'validate-buffer-mapped-at-creation-alignment',
      'authenticate-wrapper-allocated-buffer-target-provenance',
      'validate-wrapper-allocated-buffer-target-generation',
      'reserve-buffer-table-and-dual-ledger-capacity',
      'reserve-buffer-provider-request-completion-and-physical-sequence',
      'validate-buffer-label-under-reviewed-workload',
    ]);
    expect(codec.nativeProgramPrerequisitesRepresented).toBe(true);
    expect(codec.executableFromCurrentAuthenticatedInputs).toBe(true);
    expect(codec.unavailableSemanticFields).toEqual([]);
    expect(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.types.bufferDescriptorV1
        .fields[0],
    ).toEqual({
      name: 'label',
      required: true,
      value: {
        kind: 'string',
        constraints: [
          'maximum-utf8-bytes-16777017',
          'shares-total-payload-budget-with-sealed-local-timeline',
        ],
      },
    });

    const effects: string[] = [];
    const counts = { label: 0, mappedAtCreation: 0, size: 0, usage: 0 };
    const descriptor = Object.defineProperties({}, {
      label: {
        enumerable: true,
        get() {
          counts.label += 1;
          effects.push('get-label');
          return {
            toString() {
              effects.push('convert-label');
              return 'ordered-buffer';
            },
          };
        },
      },
      mappedAtCreation: {
        enumerable: true,
        get() {
          counts.mappedAtCreation += 1;
          effects.push('get-mappedAtCreation');
          return 1;
        },
      },
      size: {
        enumerable: true,
        get() {
          counts.size += 1;
          effects.push('get-size');
          return {
            [Symbol.toPrimitive]() {
              effects.push('convert-size');
              return 128.9;
            },
          };
        },
      },
      usage: {
        enumerable: true,
        get() {
          counts.usage += 1;
          effects.push('get-usage');
          return {
            [Symbol.toPrimitive]() {
              effects.push('convert-usage');
              return 76.9;
            },
          };
        },
      },
    });
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(operationId, [descriptor], wrappers);
    expect(converted).toEqual({
      label: 'ordered-buffer',
      mappedAtCreation: true,
      size: 128,
      usage: 76,
    });
    expect(counts).toEqual({ label: 1, mappedAtCreation: 1, size: 1, usage: 1 });
    expect(effects).toEqual([
      'get-label',
      'convert-label',
      'get-mappedAtCreation',
      'get-size',
      'convert-size',
      'get-usage',
      'convert-usage',
    ]);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{ size: 4, usage: 9 }],
      wrappers,
    )).toEqual({ label: '', mappedAtCreation: false, size: 4, usage: 9 });

    let laterGetCount = 0;
    const missingSize = Object.defineProperty({}, 'usage', {
      get() {
        laterGetCount += 1;
        return 9;
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [missingSize],
      wrappers,
    )).toThrow('size is required');
    expect(laterGetCount).toBe(0);
    const overCeiling = Object.defineProperties({}, {
      size: { get: () => 268_435_457 },
      usage: {
        get() {
          laterGetCount += 1;
          return 9;
        },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [overCeiling],
      wrappers,
    )).toThrow('structural ceiling');
    expect(laterGetCount).toBe(0);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{ size: 4n, usage: 9 }],
      wrappers,
    )).toThrow(TypeError);

    const input = serviceInput(operationId, converted);
    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    expect(new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint16(6, true)).toBe(17);
    expect(new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint32(8, true)).toBe(3212558232);
    expect(Array.from(payload.slice(53, 55))).toEqual([
      1,
      WEBGPU_OBJECT_KIND_TAGS.GPUBuffer,
    ]);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId,
      codec: 'gpu-create-buffer-service-request-v1',
      receiver: {
        kind: 'GPUDevice',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      target: {
        kind: 'GPUBuffer',
        objectId: '11',
        objectGeneration: '1',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      convertedArguments: converted,
    });

    const maximumLabelInput = {
      ...input,
      sealedLocalTimeline: Object.freeze([]),
      convertedArguments: Object.freeze({
        label: 'x'.repeat(16_777_017),
        mappedAtCreation: false,
        size: 4,
        usage: 9,
      }),
    };
    expect(
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        maximumLabelInput,
      ).byteLength,
    ).toBe(16_777_216);
    expect(() =>
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest({
        ...maximumLabelInput,
        convertedArguments: Object.freeze({
          ...maximumLabelInput.convertedArguments,
          label: 'x'.repeat(16_777_018),
        }),
      })).toThrow('structural transport bounds');

    for (const semanticOnlyDescriptor of [
      { label: '', mappedAtCreation: false, size: 0, usage: 9 },
      { label: '', mappedAtCreation: false, size: 4, usage: 0 },
      { label: '', mappedAtCreation: true, size: 12, usage: 3 },
      { label: 'x'.repeat(44), mappedAtCreation: false, size: 128, usage: 76 },
    ]) {
      const semanticPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(serviceInput(operationId, semanticOnlyDescriptor));
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        semanticPayload,
      )).toMatchObject({ convertedArguments: semanticOnlyDescriptor });
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, {
        label: '', mappedAtCreation: false, size: 268_435_457, usage: 9,
      }))).toThrow('structural transport bounds');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, {
        label: '', mappedAtCreation: false, size: 4, usage: 9, extra: true,
      }))).toThrow('canonical descriptor');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({ ...input, target: undefined }))
      .toThrow('wrapper-allocated target');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({ ...input, target: reference('GPUTexture') }))
      .toThrow('authenticated device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: { ...input.target!, logicalDeviceGeneration: '2' },
      })).toThrow('authenticated device provenance');

    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult(operationId, { kind: 'none' }).byteLength).toBe(0);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      operationId,
      { kind: 'null' },
    )).toThrow('wrong shape');
  });

  test('converts createBindGroupLayout dictionaries in observable WebIDL order with one Get each', () => {
    const log: string[] = [];
    let labelRead = false;
    let labelConverted = false;
    let firstEntryConverted = false;
    let bufferType = 'uniform';
    let storageFormat = 'rgba16float';
    let storageViewDimension = '2d';
    let textureViewDimension = '2d';

    const buffer = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(buffer, {
      hasDynamicOffset: {
        get() {
          log.push('buffer.hasDynamicOffset:get');
          return false;
        },
      },
      minBindingSize: {
        get() {
          log.push('buffer.minBindingSize:get');
          return {
            valueOf() {
              log.push('buffer.minBindingSize:convert');
              bufferType = 'storage';
              return 3.9;
            },
          };
        },
      },
      type: {
        get() {
          log.push('buffer.type:get');
          return bufferType;
        },
      },
    });
    const sampler = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(sampler, 'type', {
      get() {
        log.push('sampler.type:get');
        return 'comparison';
      },
    });
    const storageTexture = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(storageTexture, {
      access: {
        get() {
          log.push('storage.access:get');
          return {
            toString() {
              log.push('storage.access:convert');
              storageFormat = 'rgba8unorm';
              return 'read-only';
            },
          };
        },
      },
      format: {
        get() {
          log.push('storage.format:get');
          return {
            toString() {
              log.push('storage.format:convert');
              storageViewDimension = '3d';
              return storageFormat;
            },
          };
        },
      },
      viewDimension: {
        get() {
          log.push('storage.viewDimension:get');
          return storageViewDimension;
        },
      },
    });
    const textureLayout = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(textureLayout, {
      multisampled: {
        get() {
          log.push('texture.multisampled:get');
          return 1;
        },
      },
      sampleType: {
        get() {
          log.push('texture.sampleType:get');
          return {
            toString() {
              log.push('texture.sampleType:convert');
              textureViewDimension = 'cube';
              return 'depth';
            },
          };
        },
      },
      viewDimension: {
        get() {
          log.push('texture.viewDimension:get');
          return textureViewDimension;
        },
      },
    });
    const entry = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(entry, {
      binding: {
        get() {
          log.push('entry.binding:get');
          return {
            valueOf() {
              log.push('entry.binding:convert');
              return 0.9;
            },
          };
        },
      },
      buffer: {
        get() {
          log.push('entry.buffer:get');
          return buffer;
        },
      },
      externalTexture: {
        get() {
          log.push('entry.externalTexture:get');
          return Object.create(null);
        },
      },
      sampler: {
        get() {
          log.push('entry.sampler:get');
          return sampler;
        },
      },
      storageTexture: {
        get() {
          log.push('entry.storageTexture:get');
          return storageTexture;
        },
      },
      texture: {
        get() {
          log.push('entry.texture:get');
          return textureLayout;
        },
      },
      visibility: {
        get() {
          log.push('entry.visibility:get');
          firstEntryConverted = true;
          return 7;
        },
      },
    });

    let nextIndex = 0;
    const sourceIterator = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(sourceIterator, 'next', {
      get() {
        log.push('iterator.next:get');
        return () => {
          log.push(`iterator.next:${nextIndex}`);
          if (nextIndex === 0) {
            nextIndex += 1;
            return { done: false, value: entry };
          }
          if (!firstEntryConverted) {
            throw new Error('sequence consumed the next member before conversion');
          }
          return { done: true, value: undefined };
        };
      },
    });
    const entries = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(entries, Symbol.iterator, {
      get() {
        log.push('entries.iterator:get');
        return () => {
          log.push('entries.iterator:call');
          return sourceIterator;
        };
      },
    });
    const descriptorPrototype = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(descriptorPrototype, 'label', {
      get() {
        log.push('descriptor.label:get');
        labelRead = true;
        return {
          toString() {
            log.push('descriptor.label:convert');
            labelConverted = true;
            return 'observable-layout';
          },
        };
      },
    });
    const descriptor = Object.create(descriptorPrototype) as Record<PropertyKey, unknown>;
    Object.defineProperty(descriptor, 'entries', {
      get() {
        log.push('descriptor.entries:get');
        if (!labelRead || !labelConverted) {
          throw new Error('inherited label was not converted first');
        }
        return entries;
      },
    });

    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [descriptor],
      wrappers,
    )).toEqual({
      label: 'observable-layout',
      entries: [{
        binding: 0,
        buffer: {
          hasDynamicOffset: false,
          minBindingSize: 3,
          type: 'storage',
        },
        externalTexture: {},
        sampler: { type: 'comparison' },
        storageTexture: {
          access: 'read-only',
          format: 'rgba8unorm',
          viewDimension: '3d',
        },
        texture: {
          multisampled: true,
          sampleType: 'depth',
          viewDimension: 'cube',
        },
        visibility: 7,
      }],
    });
    expect(log).toEqual([
      'descriptor.label:get',
      'descriptor.label:convert',
      'descriptor.entries:get',
      'entries.iterator:get',
      'entries.iterator:call',
      'iterator.next:get',
      'iterator.next:0',
      'entry.binding:get',
      'entry.binding:convert',
      'entry.buffer:get',
      'buffer.hasDynamicOffset:get',
      'buffer.minBindingSize:get',
      'buffer.minBindingSize:convert',
      'buffer.type:get',
      'entry.externalTexture:get',
      'entry.sampler:get',
      'sampler.type:get',
      'entry.storageTexture:get',
      'storage.access:get',
      'storage.access:convert',
      'storage.format:get',
      'storage.format:convert',
      'storage.viewDimension:get',
      'entry.texture:get',
      'texture.multisampled:get',
      'texture.sampleType:get',
      'texture.sampleType:convert',
      'texture.viewDimension:get',
      'entry.visibility:get',
      'iterator.next:1',
    ]);
  });

  test('closes the createBindGroupLayout iterator when element conversion throws', () => {
    const failure = new Error('binding getter failed');
    let returnGets = 0;
    let returnCalls = 0;
    let nextCalls = 0;
    const entry = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(entry, 'binding', {
      get() {
        throw failure;
      },
    });
    const iterator = {
      next() {
        nextCalls += 1;
        return { done: false, value: entry };
      },
      get return() {
        returnGets += 1;
        return () => {
          returnCalls += 1;
          throw new Error('iterator close failed');
        };
      },
    };
    const entries = {
      [Symbol.iterator]() {
        return iterator;
      },
    };

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{ entries }],
      wrappers,
    )).toThrow(failure);
    expect(nextCalls).toBe(1);
    expect(returnGets).toBe(1);
    expect(returnCalls).toBe(1);
  });

  test('converts createPipelineLayout in inherited Web IDL order with one Get each', () => {
    const log: string[] = [];
    const descriptor = Object.create(null) as Record<PropertyKey, unknown>;
    const layouts = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(layouts, Symbol.iterator, {
      get() {
        log.push('bindGroupLayouts.iterator:get');
        return function () {
          log.push('bindGroupLayouts.iterator:call');
          let yielded = false;
          return {
            next() {
              log.push(`bindGroupLayouts.next:${yielded ? 1 : 0}`);
              if (yielded) return { done: true, value: undefined };
              yielded = true;
              return { done: false, value: bindGroupLayout };
            },
          };
        };
      },
    });
    Object.defineProperties(descriptor, {
      label: {
        get() {
          log.push('descriptor.label:get');
          return {
            toString() {
              log.push('descriptor.label:convert');
              return 'ordered';
            },
          };
        },
      },
      bindGroupLayouts: {
        get() {
          log.push('descriptor.bindGroupLayouts:get');
          return layouts;
        },
      },
      immediateSize: {
        get() {
          log.push('descriptor.immediateSize:get');
          return {
            valueOf() {
              log.push('descriptor.immediateSize:convert');
              return 4.9;
            },
          };
        },
      },
    });
    const observingWrappers: ProductionGpuCodecWrapperAccess = {
      reference(value, kind) {
        log.push(`reference:${String(kind)}`);
        return wrappers.reference(value, kind);
      },
    };

    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createPipelineLayout',
      [descriptor],
      observingWrappers,
    )).toEqual({
      label: 'ordered',
      bindGroupLayouts: [reference('GPUBindGroupLayout')],
      immediateSize: 4,
    });
    expect(log).toEqual([
      'descriptor.label:get',
      'descriptor.label:convert',
      'descriptor.bindGroupLayouts:get',
      'bindGroupLayouts.iterator:get',
      'bindGroupLayouts.iterator:call',
      'bindGroupLayouts.next:0',
      'reference:GPUBindGroupLayout',
      'bindGroupLayouts.next:1',
      'descriptor.immediateSize:get',
      'descriptor.immediateSize:convert',
    ]);

    const missingLog: string[] = [];
    const missing = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(missing, {
      label: { get() { missingLog.push('label'); return ''; } },
      bindGroupLayouts: {
        get() { missingLog.push('bindGroupLayouts'); return undefined; },
      },
      immediateSize: { get() { missingLog.push('immediateSize'); return 0; } },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createPipelineLayout',
      [missing],
      wrappers,
    )).toThrow('bindGroupLayouts is required');
    expect(missingLog).toEqual(['label', 'bindGroupLayouts']);
  });

  test('closes the createPipelineLayout iterator when branded reference conversion throws', () => {
    const failure = new TypeError('foreign bind group layout');
    let returnGets = 0;
    let returnCalls = 0;
    let nextCalls = 0;
    const layouts = {
      [Symbol.iterator]() {
        return {
          next() {
            nextCalls += 1;
            return { done: false, value: {} };
          },
          get return() {
            returnGets += 1;
            return () => {
              returnCalls += 1;
              return { done: true, value: undefined };
            };
          },
        };
      },
    };
    const rejectingWrappers: ProductionGpuCodecWrapperAccess = {
      reference() {
        throw failure;
      },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createPipelineLayout',
      [{ bindGroupLayouts: layouts }],
      rejectingWrappers,
    )).toThrow(failure);
    expect(nextCalls).toBe(1);
    expect(returnGets).toBe(1);
    expect(returnCalls).toBe(1);
  });

  test('preserves the complete createPipelineLayout structural domain before semantic narrowing', () => {
    const operationId = 'GPUDevice.createPipelineLayout';
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(operationId, [{
        label: 'x'.repeat(65_536),
        bindGroupLayouts: [null, undefined, bindGroupLayout, bindGroupLayout],
        immediateSize: 3.9,
      }], wrappers) as Readonly<Record<string, unknown>>;
    expect(converted).toEqual({
      label: 'x'.repeat(65_536),
      bindGroupLayouts: [
        null,
        null,
        reference('GPUBindGroupLayout'),
        reference('GPUBindGroupLayout'),
      ],
      immediateSize: 3,
    });
    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, converted));
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(payload))
      .toMatchObject({ convertedArguments: converted });

    const empty = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{ bindGroupLayouts: [] }],
      wrappers,
    );
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
        serviceInput(operationId, empty),
      ),
    )).toMatchObject({ convertedArguments: {
      label: '',
      bindGroupLayouts: [],
      immediateSize: 0,
    } });

    const live = reference('GPUBindGroupLayout');
    for (const bindGroupLayouts of [
      [null],
      [live, live, live],
      [{ ...live, logicalDeviceId: '99' }],
      [{ ...live, objectGeneration: '2' }],
      [{ ...live, providerGeneration: '8' }],
    ]) {
      const structurallyValid = {
        label: 'semantic-boundary-witness',
        bindGroupLayouts,
        immediateSize: 0xffff_ffff,
      };
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
          serviceInput(operationId, structurallyValid),
        ),
      )).toMatchObject({ convertedArguments: structurallyValid });
    }

    const program = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
      .find((route) => route.operationId === operationId)!;
    expect(program.request.semanticServiceBoundary.requiredAfterDecode).toEqual([
      'authenticate-contiguous-sealed-local-timeline-prefix',
      'validate-current-live-device-generation',
      'validate-operation-coverage',
      'validate-authorized-live-account',
      'validate-pipeline-layout-group-count-under-reviewed-workload',
      'validate-pipeline-layout-count-under-logical-max-bind-groups',
      'validate-pipeline-layout-non-null-group-positions',
      'authenticate-pipeline-layout-bind-group-layout-full-references',
      'validate-current-live-nonexclusive-bind-group-layout-generations',
      'validate-pipeline-layout-aggregate-binding-slots-under-logical-limits',
      'validate-pipeline-layout-immediate-alignment',
      'validate-pipeline-layout-immediate-size-under-logical-limit',
      'validate-pipeline-layout-label-under-reviewed-workload',
      'reserve-pipeline-layout-handle-and-aggregate-envelope',
      'authenticate-wrapper-allocated-pipeline-layout-target',
      'select-provider-admission-and-physical-sequence',
    ]);
  });

  test('reads earlier optional entry members before rejecting missing visibility', () => {
    const gets: string[] = [];
    let returnCalls = 0;
    const entry = new Proxy(Object.create(null) as Record<PropertyKey, unknown>, {
      get(_target, property) {
        if (typeof property === 'string') gets.push(property);
        if (property === 'binding') return 0;
        if (property === 'sampler') return Object.freeze({});
        return undefined;
      },
    });
    const entries = {
      [Symbol.iterator]() {
        let yielded = false;
        return {
          next() {
            if (yielded) return { done: true, value: undefined };
            yielded = true;
            return { done: false, value: entry };
          },
          return() {
            returnCalls += 1;
            return { done: true, value: undefined };
          },
        };
      },
    };

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{ entries }],
      wrappers,
    )).toThrow('visibility is required');
    expect(gets).toEqual([
      'binding',
      'buffer',
      'externalTexture',
      'sampler',
      'storageTexture',
      'texture',
      'visibility',
    ]);
    expect(returnCalls).toBe(1);
  });

  test('closes bounded bind-group-layout iteration before converting the overflow member', () => {
    const maximum = WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount;
    let nextCalls = 0;
    let returnCalls = 0;
    let poisonGets = 0;
    const validEntry = { binding: 0, visibility: 7, buffer: {} };
    const poisonEntry = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(poisonEntry, 'binding', {
      get() {
        poisonGets += 1;
        return 0;
      },
    });
    const entries = {
      [Symbol.iterator]() {
        return {
          next() {
            const index = nextCalls;
            nextCalls += 1;
            return {
              done: false,
              value: index < maximum ? validEntry : poisonEntry,
            };
          },
          return() {
            returnCalls += 1;
            return { done: true, value: undefined };
          },
        };
      },
    };

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{ entries }],
      wrappers,
    )).toThrow('reviewed sequence bound');
    expect(nextCalls).toBe(maximum + 1);
    expect(returnCalls).toBe(1);
    expect(poisonGets).toBe(0);

    for (const nonSequence of ['entry', { 0: validEntry, length: 1 }]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createBindGroupLayout',
        [{ entries: nonSequence }],
        wrappers,
      )).toThrow('must be iterable');
    }
  });

  test('applies EnforceRange truncation and rejects BigInt for bind-group-layout integers', () => {
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{
        entries: [{
          binding: 1.9,
          visibility: 7.8,
          buffer: { minBindingSize: -0.5 },
        }],
      }],
      wrappers,
    ) as Readonly<{ entries: ReadonlyArray<Readonly<Record<string, unknown>>> }>;
    expect(converted.entries[0]).toMatchObject({
      binding: 1,
      visibility: 7,
      buffer: { minBindingSize: 0 },
    });

    const large = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{
        entries: [{
          binding: -0.5,
          visibility: 7,
          buffer: { minBindingSize: Number.MAX_SAFE_INTEGER },
        }],
      }],
      wrappers,
    ) as Readonly<{ entries: ReadonlyArray<Readonly<Record<string, unknown>>> }>;
    expect(large.entries[0]).toMatchObject({
      binding: 0,
      buffer: { minBindingSize: Number.MAX_SAFE_INTEGER },
    });

    const u32Edge = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{
        entries: [{
          binding: 0xffff_ffff + 0.9,
          visibility: 7,
          buffer: {},
        }],
      }],
      wrappers,
    ) as Readonly<{ entries: ReadonlyArray<Readonly<Record<string, unknown>>> }>;
    expect(u32Edge.entries[0]).toMatchObject({ binding: 0xffff_ffff });

    for (const binding of [Number.NaN, Number.POSITIVE_INFINITY, -1, 2 ** 32]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createBindGroupLayout',
        [{ entries: [{ binding, visibility: 7, buffer: {} }] }],
        wrappers,
      )).toThrow(TypeError);
    }

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{
        entries: [{
          binding: 0,
          visibility: 7,
          buffer: { minBindingSize: Number.MAX_SAFE_INTEGER + 1 },
        }],
      }],
      wrappers,
    )).toThrow(TypeError);

    for (const binding of [BigInt(1), Object(BigInt(1))]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createBindGroupLayout',
        [{ entries: [{ binding, visibility: 7, buffer: {} }] }],
        wrappers,
      )).toThrow(TypeError);
    }
    for (const minBindingSize of [BigInt(1), Object(BigInt(1))]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createBindGroupLayout',
        [{ entries: [{ binding: 0, visibility: 7, buffer: { minBindingSize } }] }],
        wrappers,
      )).toThrow(TypeError);
    }
  });

  test('carries the complete pinned storage-texture format vocabulary before semantic validation', () => {
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary).toMatchObject({
      bindingPackage: '@webgpu/types',
      bindingPackageVersion: '0.1.71',
      declarationPath: 'node_modules/@webgpu/types/dist/index.d.ts',
    });
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary.gpuTextureFormats)
      .toHaveLength(101);

    for (const format of
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary.gpuTextureFormats) {
      const convertedArguments = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
        .convertPublicArguments(
          'GPUDevice.createBindGroupLayout',
          [{
            entries: [{
              binding: 0,
              visibility: 7,
              storageTexture: { format },
            }],
          }],
          wrappers,
        );
      expect(convertedArguments).toMatchObject({
        entries: [{
          storageTexture: {
            access: 'write-only',
            format,
            viewDimension: '2d',
          },
        }],
      });
      const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(serviceInput(
          'GPUDevice.createBindGroupLayout',
          convertedArguments,
        ));
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(payload))
        .toMatchObject({ convertedArguments });
    }
  });

  test('rejects an unknown storage-texture format at its single observable conversion point', () => {
    const log: string[] = [];
    const storageTexture = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperties(storageTexture, {
      access: {
        get() {
          log.push('storage.access:get');
          return undefined;
        },
      },
      format: {
        get() {
          log.push('storage.format:get');
          return {
            toString() {
              log.push('storage.format:convert');
              return 'not-a-gpu-texture-format';
            },
          };
        },
      },
      viewDimension: {
        get() {
          log.push('storage.viewDimension:get');
          return '2d';
        },
      },
    });
    const entry = new Proxy(Object.create(null) as Record<PropertyKey, unknown>, {
      get(_target, property) {
        if (typeof property === 'string') log.push(`entry.${property}:get`);
        if (property === 'binding') return 0;
        if (property === 'storageTexture') return storageTexture;
        if (property === 'visibility') return 7;
        return undefined;
      },
    });
    let returnCalls = 0;
    const entries = {
      [Symbol.iterator]() {
        let yielded = false;
        return {
          next() {
            if (yielded) return { done: true, value: undefined };
            yielded = true;
            return { done: false, value: entry };
          },
          return() {
            returnCalls += 1;
            log.push('iterator.return:call');
            return { done: true, value: undefined };
          },
        };
      },
    };

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroupLayout',
      [{ entries }],
      wrappers,
    )).toThrow('not a supported enum value');
    expect(returnCalls).toBe(1);
    expect(log).toEqual([
      'entry.binding:get',
      'entry.buffer:get',
      'entry.externalTexture:get',
      'entry.sampler:get',
      'entry.storageTexture:get',
      'storage.access:get',
      'storage.format:get',
      'storage.format:convert',
      'iterator.return:call',
    ]);
  });

  test('executes the private createShaderModule request program and rejects hostile inputs', () => {
    const input = serviceInput('GPUDevice.createShaderModule');
    const nativeRoute = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
      .find((candidate) => candidate.operationId === 'GPUDevice.createShaderModule')!;
    const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) =>
        candidate.tag === 'gpu-create-shader-module-service-request-v1',
    )!;
    expect(nativeRoute.wireId).toBe(599085487);
    expect(nativeRoute.request.catalog.wireTag).toBe(7);
    expect(nativeRoute.completion.catalog.wireTag).toBe(2);
    expect(nativeRoute.request.executablePrerequisites).toEqual([]);
    expect(nativeRoute.request.semanticServiceBoundary.requiredAfterDecode).toEqual([
      'authenticate-contiguous-sealed-local-timeline-prefix',
      'validate-current-live-device-generation',
      'validate-operation-coverage',
      'validate-authorized-live-account',
      'validate-wgsl-with-naga-under-logical-capabilities',
      'reserve-shader-module-handle-and-aggregate-envelope',
      'authenticate-wrapper-allocated-shader-module-target',
      'select-provider-admission-and-physical-sequence',
    ]);
    expect(nativeRoute.completion.semanticTerminalMapping.terminals.map(
      (terminal) => ({
        terminalId: terminal.terminalId,
        kind: terminal.event.kind,
      }),
    )).toEqual([
      { terminalId: 'webidl-rejection', kind: 'no-service-call' },
      { terminalId: 'later-predicate-rejection', kind: 'device-error' },
      { terminalId: 'operation-success', kind: 'operation-result' },
    ]);
    expect(codec.nativeProgramPrerequisitesRepresented).toBe(true);
    expect(codec.executableFromCurrentAuthenticatedInputs).toBe(true);
    expect(codec.unavailableSemanticFields).toEqual([]);

    const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(input);
    expect(new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint16(6, true)).toBe(7);
    expect(new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    ).getUint32(8, true)).toBe(599085487);
    expect(Array.from(payload.slice(53, 55))).toEqual([
      1,
      WEBGPU_OBJECT_KIND_TAGS.GPUShaderModule,
    ]);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input))
      .toEqual(payload);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId: 'GPUDevice.createShaderModule',
      codec: 'gpu-create-shader-module-service-request-v1',
      receiver: {
        kind: 'GPUDevice',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      target: {
        kind: 'GPUShaderModule',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      adapterOrdinal: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '0',
      convertedArguments: {
        label: 'shader',
        code: '@vertex fn main() {}',
      },
    });

    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({ ...input, target: undefined }))
      .toThrow('wrapper-allocated target');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        receiver: reference('GPUAdapter'),
      })).toThrow('authenticated GPUDevice receiver');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: reference('GPUCommandEncoder'),
      })).toThrow('authenticated device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        target: { ...input.target!, logicalDeviceId: '18' },
      })).toThrow('authenticated device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        convertedArguments: { label: 'shader', code: 'wgsl', extra: true },
      })).toThrow('reviewed descriptor shape');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        convertedArguments: { label: 'shader' },
      })).toThrow('reviewed descriptor shape');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        sealedLocalTimeline: [cyclic],
      })).toThrow('contains a cycle');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        sealedLocalTimeline: Array.from(
          {
            length:
              WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount + 1,
          },
          () => null,
        ),
      })).toThrow('bounded sequence');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...input,
        wireId: routeWireId('GPUDevice.createCommandEncoder'),
      })).toThrow('wire identity mismatch');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      mutateU32(payload, 8, routeWireId('GPUDevice.createCommandEncoder')),
    )).toThrow('operation/codec mismatch');

    const completion = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPUDevice.createShaderModule', { kind: 'none' });
    expect(completion.byteLength).toBe(0);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.createShaderModule',
      { kind: 'null' },
    )).toThrow('wrong shape');
  });

  test('executes the private GPUDevice.destroy request program and empty terminal receipt', () => {
    const input = serviceInput('GPUDevice.destroy', null);
    const codec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === 'gpu-device-cleanup-service-request-v1',
    )!;
    expect(codec.nativeProgramPrerequisitesRepresented).toBe(true);
    expect(codec.executableFromCurrentAuthenticatedInputs).toBe(true);
    expect(codec.unavailableSemanticFields).toEqual([]);

    const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId: 'GPUDevice.destroy',
      codec: 'gpu-device-cleanup-service-request-v1',
      receiver: {
        kind: 'GPUDevice',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      target: null,
      adapterOrdinal: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '0',
      sealedLocalTimeline: [{
        operationId: routeWireId('GPURenderPassEncoder.draw'),
        operationName: 'GPURenderPassEncoder.draw',
        operationInstanceId: '12',
        deviceIngressOrdinal: '2',
        capturedScopeId: '0',
        receiverRef: {
          kind: 'GPURenderPassEncoder',
          objectId: '11',
          logicalDeviceId: '17',
        },
        wrapperAllocatedTargetRef: null,
        argumentBody: {
          vertexCount: 3,
          instanceCount: 1,
          firstVertex: 0,
          firstInstance: 0,
        },
        logicalError: null,
      }],
      convertedArguments: null,
    });

    for (const length of [0, 1, 4, 11, 12, payload.byteLength - 1]) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        payload.slice(0, length),
      )).toThrow();
    }
    const wrongTag = payload.slice();
    wrongTag[6] = wrongTag[6]! ^ 1;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      wrongTag,
    )).toThrow();
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      withTrailingByte(payload),
    )).toThrow();
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...input,
      convertedArguments: [],
    })).toThrow('exactly null');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...input,
      target: reference('GPUTexture'),
    })).toThrow('must not carry a target');

    const completion = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPUDevice.destroy', { kind: 'none' });
    expect(completion.byteLength).toBe(0);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.destroy',
      { kind: 'null' },
    )).toThrow('wrong shape');
  });

  test('decodes nullable adapter results with authenticated operation/result tags', () => {
    const nullPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      { kind: 'null' },
    );
    expect(nullPayload.byteLength).toBe(0);
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
        providerGeneration: '8',
        serviceDetachedExpired: false,
      },
    );
    expect(adapterPayload.byteLength).toBe(38);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, adapterPayload),
    )).toEqual({
      kind: 'object',
      object: {
        kind: 'GPUAdapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '8',
        serviceDetachedExpired: false,
      },
    });
    const detachedPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPU.requestAdapter', {
        kind: 'adapter',
        objectId: '42',
        objectGeneration: '3',
        providerGeneration: '8',
        serviceDetachedExpired: true,
      });
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, detachedPayload),
    )).toEqual({
      kind: 'object',
      object: {
        kind: 'GPUAdapter',
        objectId: '42',
        objectGeneration: '3',
        providerGeneration: '8',
        serviceDetachedExpired: true,
      },
    });
    const mismatchedProviderPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPU.requestAdapter', {
        kind: 'adapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '9',
        serviceDetachedExpired: false,
      });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, mismatchedProviderPayload),
    )).toThrow('provider provenance mismatch');
    const assignedDeviceCarrier = {
      ...resultEvent('GPU.requestAdapter', 3, adapterPayload),
      deviceTransition: 1,
      logicalDeviceId: '17',
      logicalDeviceGeneration: '1',
      providerGeneration: '8',
    } as unknown as ResultEvent;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      assignedDeviceCarrier,
    )).toThrow('invalid authenticated carrier');
    for (const carrierMutation of [
      { status: -1 },
      { kind: 2 },
      { ingressLogicalDeviceId: '17' },
      { ingressLogicalDeviceGeneration: '1' },
      { ingressProviderGeneration: '8' },
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
        'GPU.requestAdapter',
        {
          ...resultEvent('GPU.requestAdapter', 3, adapterPayload),
          ...carrierMutation,
        } as unknown as ResultEvent,
      )).toThrow('invalid authenticated carrier');
    }
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 2, adapterPayload),
    )).toThrow('zero payload bytes');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      {
        kind: 'adapter',
        objectId: '0',
        objectGeneration: '2',
        providerGeneration: '8',
        serviceDetachedExpired: false,
      },
    )).toThrow('positive identity');

    const invalidDetachedState = adapterPayload.slice();
    invalidDetachedState[37] = 2;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, invalidDetachedState),
    )).toThrow('invalid authenticated detached state');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, adapterPayload.slice(0, 37)),
    )).toThrow();
    const trailing = new Uint8Array(adapterPayload.byteLength + 1);
    trailing.set(adapterPayload);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, trailing),
    )).toThrow('Trailing bytes in WebGPU payload');
    const oldCodecTag = adapterPayload.slice();
    oldCodecTag[6] = 3;
    oldCodecTag[7] = 0;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, oldCodecTag),
    )).toThrow('Unexpected WebGPU codec tag: 3');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      {
        kind: 'adapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '8',
      } as never,
    )).toThrow('lacks authenticated detached state');
  });

  test('derives detached device loss only from authenticated carrier fields', () => {
    const detachedTransitionTypeAssertion: ResultEvent['deviceTransition'] = 2;
    expect(detachedTransitionTypeAssertion).toBe(2);
    const base = {
      kind: 'device' as const,
      objectId: '51',
      objectGeneration: '1',
      logicalDeviceId: '17',
      logicalDeviceGeneration: '1',
      providerGeneration: '8',
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
    const mismatchedDevicePayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPUAdapter.requestDevice', {
        ...base,
        providerGeneration: '9',
      });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, mismatchedDevicePayload),
    )).toThrow('result provenance mismatch');

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
    const admittedDetached = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .decodeServiceResult(
        'GPUAdapter.requestDevice',
        resultEvent(
          'GPUAdapter.requestDevice',
          3,
          detachedPayload,
          true,
          1,
          0,
          1,
        ),
      );
    expect(admittedDetached).toMatchObject({
      kind: 'object',
      object: {
        alreadyLost: { reason: 'unknown', message: 'adapter expired' },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, detachedPayload),
    )).toThrow('detached-only diagnostics');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, detachedPayload, false, 0, 0),
    )).toThrow('Live GPUDevice result has invalid transition fields');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      resultEvent('GPUAdapter.requestDevice', 3, detachedPayload, true, 2, 0),
    )).toThrow('Detached GPUDevice result has invalid transition fields');
    const missingCarrierFields = resultEvent(
      'GPUAdapter.requestDevice',
      3,
      livePayload,
    ) as ResultEvent & Record<string, unknown>;
    Reflect.deleteProperty(missingCarrierFields, 'detachedAlreadyLost');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      missingCarrierFields,
    )).toThrow('Live GPUDevice result has invalid transition fields');

    const detachedWrongReceiver = {
      ...resultEvent(
        'GPUAdapter.requestDevice',
        3,
        detachedPayload,
        true,
        1,
        0,
      ),
      receiverKind: 3,
    } as unknown as ResultEvent;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      detachedWrongReceiver,
    )).toThrow('invalid requestDevice authenticated carrier');

    const detachedAdmittedZeroSequence = {
      ...resultEvent(
        'GPUAdapter.requestDevice',
        3,
        detachedPayload,
        true,
        1,
        0,
        1,
      ),
      physicalSequence: '0',
    } as unknown as ResultEvent;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUAdapter.requestDevice',
      detachedAdmittedZeroSequence,
    )).toThrow('admission/physical-sequence provenance mismatch');
  });

  test('decodes nullable typed GPU errors and rejects unknown completion data', () => {
    const nullPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUDevice.popErrorScope',
      { kind: 'null' },
    );
    expect(nullPayload.byteLength).toBe(0);
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
