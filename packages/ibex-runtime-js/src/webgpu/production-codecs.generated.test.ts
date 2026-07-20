import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';

import {
  default as computePipelineConversionFixtures,
} from '../../../../tests/fixtures/webgpu-compute-pipeline-conversion-v1.json';
import {
  default as renderPipelineConversionFixtures,
} from '../../../../tests/fixtures/webgpu-render-pipeline-conversion-v1.json';

import type { NativeGpuEventV2 } from './native-bridge';
import {
  EMBEDDED_EXECUTABLE_WEBGPU_CODECS,
  WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION,
  type ProductionGpuCodecWrapperAccess,
  type ProductionGpuCanvasServiceEncoding,
  type ProductionGpuServiceEncodingInput,
  type ProductionGpuTextureOriginDigestInput,
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

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(
        (value as Readonly<Record<string, unknown>>)[key],
      )}`)
      .join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError('value is not JSON-safe');
  return encoded;
}

function wrapper(kind: ProductionGpuWrapperKind): object {
  const value = Object.freeze({ marker: kind });
  wrapperKinds.set(value, kind);
  return value;
}

const gpuAdapter = wrapper('GPUAdapter');
const gpuBuffer = wrapper('GPUBuffer');
const gpuDevice = wrapper('GPUDevice');
const bindGroup = wrapper('GPUBindGroup');
const bindGroupLayout = wrapper('GPUBindGroupLayout');
const canvasContext = wrapper('GPUCanvasContext');
const commandBuffer = wrapper('GPUCommandBuffer');
const commandEncoder = wrapper('GPUCommandEncoder');
const pipelineLayout = wrapper('GPUPipelineLayout');
const computePipeline = wrapper('GPUComputePipeline');
const renderPass = wrapper('GPURenderPassEncoder');
const renderPipeline = wrapper('GPURenderPipeline');
const sampler = wrapper('GPUSampler');
const shaderModule = wrapper('GPUShaderModule');
const texture = wrapper('GPUTexture');
const textureView = wrapper('GPUTextureView');
const externalTexture = wrapper('GPUExternalTexture');
const externalImage = Object.freeze({ marker: 'ImageBitmap' });

function externalImageSnapshot() {
  return Object.freeze({
    runtimeAddress: '73',
    runtimeNonce: '91',
    sourceId: '1',
    sourceGeneration: '1',
    width: 1,
    height: 1,
    bytesPerRow: 4,
    encodedBytes: new Uint8Array([137, 80, 78, 71]),
    decodedPremultipliedRgba8: new Uint8Array([1, 2, 3, 4]),
    encodedContentSha256: 'a'.repeat(64),
    decodedContentSha256: 'b'.repeat(64),
    originClean: true as const,
    usability: 'good' as const,
    colorSpace: 'srgb' as const,
    alphaMode: 'premultiplied' as const,
    orientation: 'top-left' as const,
  });
}

interface RenderPipelineFixtureBlendComponent {
  readonly dstFactor: string;
  readonly operation: string;
  readonly srcFactor: string;
}

interface ComputePipelineFixtureRow {
  readonly workloadId:
    | 'typegpu-genetic-racing'
    | 'typegpu-jelly-slider';
  readonly label: string;
  readonly layoutKind: 'explicit';
  readonly sourceConstantsPresence: 'omitted';
  readonly entryPointPresence: 'omitted';
  readonly shaderSourceSha256: string;
}

const computePipelineFixtureRows = computePipelineConversionFixtures.rows as unknown as
  readonly ComputePipelineFixtureRow[];

interface RenderPipelineFixtureRow {
  readonly workload: string;
  readonly label: string;
  readonly sourceVertexBuffersPresence: 'omitted' | 'present';
  readonly vertexBuffers?: readonly Readonly<{
    arrayStride: number;
    attributes: readonly Readonly<{
      format: string;
      offset: number;
      shaderLocation: number;
    }>[];
    stepMode?: string;
  }>[];
  readonly sourcePrimitivePresence: 'omitted' | 'present';
  readonly primitive?: Readonly<{ topology?: string }>;
  readonly targetFormat: string;
  readonly blend?: Readonly<{
    alpha: RenderPipelineFixtureBlendComponent;
    color: RenderPipelineFixtureBlendComponent;
  }>;
}

const renderPipelineFixtureRows = renderPipelineConversionFixtures.rows as unknown as
  readonly RenderPipelineFixtureRow[];

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

function bindGroupDescriptor(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    label: 'corpus-bind-group',
    entries: Object.freeze([
      Object.freeze({
        binding: 0,
        resource: Object.freeze({ buffer: gpuBuffer, offset: 0, size: 128 }),
      }),
      Object.freeze({ binding: 1, resource: sampler }),
      Object.freeze({ binding: 2, resource: textureView }),
    ]),
    layout: bindGroupLayout,
  });
}

function convertedBindGroupDescriptor(): Readonly<Record<string, unknown>> {
  return Object.freeze({
    label: 'corpus-bind-group',
    entries: Object.freeze([
      Object.freeze({
        binding: 0,
        resource: Object.freeze({
          resourceKind: 'GPUBufferBinding',
          buffer: reference('GPUBuffer'),
          offset: 0,
          size: 128,
        }),
      }),
      Object.freeze({
        binding: 1,
        resource: Object.freeze({
          resourceKind: 'GPUSampler',
          reference: reference('GPUSampler'),
        }),
      }),
      Object.freeze({
        binding: 2,
        resource: Object.freeze({
          resourceKind: 'GPUTextureView',
          reference: reference('GPUTextureView'),
        }),
      }),
    ]),
    layout: reference('GPUBindGroupLayout'),
  });
}

const wrappers: ProductionGpuCodecWrapperAccess = {
  referenceIfBranded(value, expectedKind) {
    if (
      typeof value !== 'object' ||
      value === null ||
      !wrapperKinds.has(value)
    ) {
      return undefined;
    }
    return wrappers.reference(value, expectedKind);
  },
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
  snapshotExternalImageForCopy(value, sourceOrigin, copySize) {
    if (value !== externalImage) throw new TypeError('unbranded ImageBitmap');
    if (
      sourceOrigin.x + copySize.width > 1 ||
      sourceOrigin.y + copySize.height > 1 ||
      copySize.depthOrArrayLayers > 1
    ) {
      throw new DOMException('source range', 'OperationError');
    }
    return externalImageSnapshot();
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
    case 'GPUCommandEncoder.beginComputePass':
      return [{ label: 'compute-pass' }];
    case 'GPUCommandEncoder.clearBuffer':
      return [gpuBuffer, 0, 4];
    case 'GPUCommandEncoder.copyBufferToBuffer':
      return [gpuBuffer, gpuBuffer, 4];
    case 'GPUCommandEncoder.copyTextureToTexture':
      return [{ texture }, { texture }, [1, 1, 1]];
    case 'GPUCommandEncoder.finish':
      return [{ label: 'buffer' }];
    case 'GPUBuffer.getMappedRange':
      return [0, 4];
    case 'GPUBuffer.mapAsync':
      return [1, 0, 4];
    case 'GPUDevice.createBindGroup':
      return [bindGroupDescriptor()];
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
    case 'GPUDevice.createComputePipeline':
      return [{
        label: 'compute-pipeline',
        layout: pipelineLayout,
        compute: { module: shaderModule },
      }];
    case 'GPUDevice.createSampler':
      return [{ label: 'sampler', magFilter: 'linear', minFilter: 'linear' }];
    case 'GPUDevice.createTexture':
      return [{
        label: 'texture',
        format: 'rgba8unorm',
        size: [32, 64],
        usage: 23,
      }];
    case 'GPUDevice.createCommandEncoder':
      return [{ label: 'encoder' }];
    case 'GPUDevice.createRenderPipeline':
      return [{
        layout: pipelineLayout,
        vertex: { module: shaderModule },
        fragment: { module: shaderModule, targets: [{ format: 'bgra8unorm' }] },
      }];
    case 'GPUDevice.createShaderModule':
      return [{ label: 'shader', code: '@vertex fn main() {}' }];
    case 'GPUDevice.pushErrorScope':
      return ['validation'];
    case 'GPUQueue.submit':
      return [new Set([commandBuffer])];
    case 'GPUQueue.writeBuffer':
      return [gpuBuffer, 0, new Uint8Array([1, 2, 3, 4])];
    case 'GPUComputePassEncoder.dispatchWorkgroups':
      return [1];
    case 'GPUComputePassEncoder.setBindGroup':
    case 'GPURenderPassEncoder.setBindGroup':
      return [0, bindGroup, []];
    case 'GPUComputePassEncoder.setPipeline':
      return [computePipeline];
    case 'GPUQueue.writeTexture':
      return [
        { texture },
        new Uint8Array([1, 2, 3, 4]),
        { bytesPerRow: 256 },
        { width: 1, height: 1, depthOrArrayLayers: 1 },
      ];
    case 'GPUQueue.copyExternalImageToTexture':
      return [
        { source: externalImage },
        { texture },
        { width: 1, height: 1, depthOrArrayLayers: 1 },
      ];
    case 'GPURenderPassEncoder.draw':
      return [3];
    case 'GPURenderPassEncoder.setPipeline':
      return [renderPipeline];
    case 'GPURenderPassEncoder.setVertexBuffer':
      return [0, gpuBuffer, 0, 4];
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

function convertedTextureViewRequest(
  currentOrigin?: Readonly<Record<string, unknown>>,
) {
  return Object.freeze({
    converted: Object.freeze({
      aspect: 'all',
      baseArrayLayer: 0,
      baseMipLevel: 0,
      label: 'view',
      swizzle: 'rgba',
      usage: 0,
    }),
    ...(currentOrigin === undefined ? {} : { currentOrigin }),
  });
}

function convertedRenderPipelineDescriptor(
  vertexConstants: Readonly<Record<string, number>> = Object.freeze({}),
) {
  return Object.freeze({
    label: 'render-pipeline',
    layout: reference('GPUPipelineLayout'),
    fragment: Object.freeze({
      constants: Object.freeze({}),
      module: reference('GPUShaderModule'),
      targets: Object.freeze([
        Object.freeze({ format: 'bgra8unorm', writeMask: 0x0f }),
      ]),
    }),
    multisample: Object.freeze({
      alphaToCoverageEnabled: false,
      count: 1,
      mask: 0xffff_ffff,
    }),
    primitive: Object.freeze({
      cullMode: 'none',
      frontFace: 'ccw',
      topology: 'triangle-list',
      unclippedDepth: false,
    }),
    vertex: Object.freeze({
      buffers: Object.freeze([]),
      constants: vertexConstants,
      module: reference('GPUShaderModule'),
    }),
  });
}

function convertedComputePipelineDescriptor(
  constants: Readonly<Record<string, number>> = Object.freeze({}),
) {
  return Object.freeze({
    compute: Object.freeze({
      constants,
      module: reference('GPUShaderModule'),
    }),
    label: 'compute-pipeline',
    layout: reference('GPUPipelineLayout'),
  });
}

function completeTextureViewCurrentOrigin() {
  const digestInput: ProductionGpuTextureOriginDigestInput = Object.freeze({
    originClass: 'canvas-current',
    receiverTextureRef: reference('GPUTexture'),
    contextRef: reference('GPUCanvasContext'),
    attachmentGeneration: '3',
    contextGeneration: '5',
    configurationGeneration: '7',
    currentEpoch: '11',
    mintOperationProvenance: Object.freeze({
      operationInstanceId: '13',
      deviceIngressOrdinal: '17',
    }),
    configuredDeviceRef: reference('GPUDevice'),
    format: 'bgra8unorm',
    usage: 16,
    alphaMode: 'premultiplied',
    colorSpace: 'srgb',
    targetAuthorityDigest: '2'.repeat(64),
    surfaceAccountToken: '19',
    surfaceAccountGeneration: '23',
  });
  const {
    receiverTextureRef: _receiverTextureRef,
    ...currentOrigin
  } = digestInput;
  return Object.freeze({
    ...currentOrigin,
    textureOriginDigest: WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .deriveTextureOriginDigest(digestInput),
  });
}

function canvasConfigureServiceBody(): ProductionGpuCanvasServiceEncoding {
  return Object.freeze({
    kind: 'canvas-configure-v1',
    receiverContextRef: reference('GPUCanvasContext'),
    attachmentGeneration: '3',
    contextGeneration: '5',
    configurationGeneration: '7',
    configuredDeviceRef: reference('GPUDevice'),
    format: 'bgra8unorm',
    usage: 16,
    viewFormats: Object.freeze([]),
    alphaMode: 'opaque',
    colorSpace: 'srgb',
    toneMappingMode: 'standard',
    targetAuthorityDigest: '2'.repeat(64),
    surfaceAccountToken: '19',
    surfaceAccountGeneration: '23',
  });
}

function canvasUnconfigureServiceBody(): ProductionGpuCanvasServiceEncoding {
  return Object.freeze({
    kind: 'canvas-unconfigure-v1',
    receiverContextRef: reference('GPUCanvasContext'),
    attachmentGeneration: '3',
    contextGeneration: '5',
    configurationGeneration: '7',
    terminalIntent: 'first-cleanup',
    targetAuthorityDigest: '2'.repeat(64),
    surfaceAccountToken: '19',
    surfaceAccountGeneration: '23',
  });
}

function textureDestroyServiceBody(
  terminalIntent:
    | 'first-cleanup'
    | 'first-expired-cleanup'
    | 'repeat-cleanup-noop' = 'first-cleanup',
  origin: 'device-created' | 'canvas-current' = 'device-created',
): ProductionGpuCanvasServiceEncoding {
  const currentOrigin = completeTextureViewCurrentOrigin();
  return Object.freeze({
    kind: 'texture-destroy-v1',
    receiverTextureRef: reference('GPUTexture'),
    terminalIntent,
    materializationState: origin === 'canvas-current'
      ? 'materialized'
      : 'unmaterialized',
    origin: origin === 'device-created'
      ? Object.freeze({ kind: 'device-created-v1' as const })
      : Object.freeze({
          kind: 'canvas-current-v1' as const,
          contextRef: currentOrigin.contextRef,
          attachmentGeneration: currentOrigin.attachmentGeneration,
          contextGeneration: currentOrigin.contextGeneration,
          configurationGeneration: currentOrigin.configurationGeneration,
          currentEpoch: currentOrigin.currentEpoch,
          mintOperationProvenance: currentOrigin.mintOperationProvenance,
          textureOriginDigest: currentOrigin.textureOriginDigest,
        }),
  });
}

function textureExpireServiceBody(): ProductionGpuCanvasServiceEncoding {
  const currentOrigin = completeTextureViewCurrentOrigin();
  return Object.freeze({
    kind: 'texture-expire-v1',
    receiverTextureRef: reference('GPUTexture'),
    expiryIntent: 'host-task-expiry',
    materializationState: 'materialized',
    origin: Object.freeze({
      kind: 'canvas-current-v1',
      contextRef: currentOrigin.contextRef,
      attachmentGeneration: currentOrigin.attachmentGeneration,
      contextGeneration: currentOrigin.contextGeneration,
      configurationGeneration: currentOrigin.configurationGeneration,
      currentEpoch: currentOrigin.currentEpoch,
      mintOperationProvenance: currentOrigin.mintOperationProvenance,
      textureOriginDigest: currentOrigin.textureOriginDigest,
    }),
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
    : operationId === 'GPUDevice.createBindGroup'
    ? convertedBindGroupDescriptor()
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
    : operationId === 'GPUDevice.createComputePipeline'
    ? convertedComputePipelineDescriptor()
    : operationId === 'GPUDevice.createRenderPipeline'
    ? convertedRenderPipelineDescriptor()
    : operationId === 'GPUDevice.createSampler'
    ? Object.freeze({
      addressModeU: 'clamp-to-edge',
      addressModeV: 'clamp-to-edge',
      addressModeW: 'clamp-to-edge',
      label: 'sampler',
      lodMaxClamp: 32,
      lodMinClamp: 0,
      magFilter: 'linear',
      maxAnisotropy: 1,
      minFilter: 'linear',
      mipmapFilter: 'nearest',
    })
    : operationId === 'GPUDevice.createTexture'
    ? Object.freeze({
      dimension: '2d',
      format: 'rgba8unorm',
      label: 'texture',
      mipLevelCount: 1,
      sampleCount: 1,
      size: Object.freeze({ width: 32, height: 32, depthOrArrayLayers: 1 }),
      usage: 23,
      viewFormats: Object.freeze([]),
    })
    : operationId === 'GPUTexture.createView'
    ? convertedTextureViewRequest()
    : operationId === 'GPUCanvasContext.configure'
    ? Object.freeze({
      format: 'bgra8unorm',
      usage: 16,
      viewFormats: Object.freeze([]),
      alphaMode: 'opaque',
      colorSpace: 'srgb',
      toneMapping: Object.freeze({ mode: 'standard' }),
    })
    : operationId === 'GPUCanvasContext.unconfigure' ||
        operationId === 'GPUTexture.destroy'
    ? null
    : operationId === 'GPUDevice.createCommandEncoder'
    ? Object.freeze({ label: 'encoder' })
    : operationId === 'GPUDevice.createShaderModule'
    ? Object.freeze({ label: 'shader', code: '@vertex fn main() {}' })
    : operationId === 'GPUDevice.destroy'
    ? null
    : operationId === 'GPUBuffer.destroy' || operationId === 'GPUBuffer.unmap'
    ? null
    : operationId === 'GPUBuffer.mapAsync'
    ? Object.freeze({ mode: 1, offset: 0 })
    : operationId === 'GPUQueue.writeBuffer'
    ? Object.freeze({
      buffer: reference('GPUBuffer'),
      bufferOffset: 0,
      bytes: new Uint8Array([1, 2, 3, 4]),
    })
    : operationId === 'GPUQueue.writeTexture'
    ? Object.freeze({
      destination: Object.freeze({
        texture: reference('GPUTexture'),
        mipLevel: 0,
        origin: Object.freeze({ x: 0, y: 0, z: 0, iterableLength: null }),
        aspect: 'all',
      }),
      dataLayout: Object.freeze({ offset: 0, bytesPerRow: 256 }),
      size: Object.freeze({
        width: 1,
        height: 1,
        depthOrArrayLayers: 1,
        iterableLength: null,
      }),
      bytes: new Uint8Array([1, 2, 3, 4]),
    })
    : operationId === 'GPUQueue.copyExternalImageToTexture'
    ? Object.freeze({
      source: Object.freeze({
        origin: Object.freeze({ x: 0, y: 0, iterableLength: null }),
        snapshot: externalImageSnapshot(),
        flipY: false,
      }),
      destination: Object.freeze({
        texture: reference('GPUTexture'),
        mipLevel: 0,
        origin: Object.freeze({ x: 0, y: 0, z: 0, iterableLength: null }),
        aspect: 'all',
        colorSpace: 'srgb',
        premultipliedAlpha: false,
      }),
      copySize: Object.freeze({
        width: 1,
        height: 1,
        depthOrArrayLayers: 1,
        iterableLength: null,
      }),
    })
    : operationId === 'GPUQueue.submit'
    ? Object.freeze({ commandBuffers: Object.freeze([]) })
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
  const canvasService = operationId === 'GPUCanvasContext.configure'
    ? canvasConfigureServiceBody()
    : operationId === 'GPUCanvasContext.unconfigure'
    ? canvasUnconfigureServiceBody()
    : operationId === 'GPUTexture.destroy'
    ? textureDestroyServiceBody()
    : undefined;
  const bufferLifecycle = operationId === 'GPUBuffer.destroy' ||
    operationId === 'GPUBuffer.mapAsync' || operationId === 'GPUBuffer.unmap';
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
    queueIngressOrdinal: receiverKind === 'GPUQueue' ? '2' : '0',
    sealedLocalTimeline: requestAdapter || requestDevice || bufferLifecycle ||
        canvasService !== undefined ||
        operationId === 'GPUQueue.writeBuffer' ||
        operationId === 'GPUQueue.writeTexture' ||
        operationId === 'GPUQueue.copyExternalImageToTexture' ||
        operationId === 'GPUQueue.submit'
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
    ...(operationId === 'GPUBuffer.mapAsync'
      ? {
          bufferLifecycle: Object.freeze({
            kind: 'map-async-v1',
            pendingMapGeneration: '1',
            mode: 1,
            offset: '0',
            requestedSizePresent: 0,
            requestedSize: '0',
          }),
        }
      : operationId === 'GPUBuffer.destroy' || operationId === 'GPUBuffer.unmap'
      ? {
          bufferLifecycle: Object.freeze({
            kind: 'cleanup-v1',
            cleanupAction: 0,
            cleanupGeneration: '0',
            cancelledMapGeneration: '0',
            activeMapGeneration: '0',
            activeMapMode: 0,
            mappedOffset: '0',
            mappedSize: '0',
            writeback: new Uint8Array(0),
          }),
        }
      : {}),
    ...(canvasService === undefined ? {} : { canvasService }),
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

function bufferMapResultEvent(
  payload: ArrayBufferView,
  overrides: Readonly<Record<string, unknown>> = {},
): ResultEvent {
  return {
    ...resultEvent('GPUBuffer.mapAsync', 4, payload),
    adapterOrdinal: '0',
    deviceIngressOrdinal: '3',
    receiverKind: WEBGPU_OBJECT_KIND_TAGS.GPUBuffer,
    ...overrides,
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
  test('pins one generated catalog over the append-only reviewed operation profile', () => {
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationCount).toBe(
      WEBGPU_PRODUCTION_PLAN.routes.length,
    );
    expect(WEBGPU_PRODUCTION_PLAN.activeRouteSubset.operationCount).toBe(
      WEBGPU_PRODUCTION_PLAN.routes.length,
    );
    expect(WEBGPU_PRODUCTION_PLAN.routes.length).toBeGreaterThanOrEqual(41);
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationIds).toEqual(
      WEBGPU_PRODUCTION_PLAN.routes.map((route) => route.operationId),
    );
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.operationIds).toContain(
      'GPUDevice.createComputePipeline',
    );
    expect(WEBGPU_PRODUCTION_PLAN.routes).toContainEqual(
      expect.objectContaining({ operationId: 'GPUDevice.createComputePipeline' }),
    );
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.postWebIdlPayloadCodegenInputs)
      .toEqual(
        WEBGPU_PRODUCTION_PLAN.stagedWorkloadClosure
          .postWebIdlPayloadCodegenInputs,
      );
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.postWebIdlPayloadCodegenInputs)
      .toEqual([]);
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.authenticatedPromotions[0])
      .toEqual(expect.objectContaining({
        operationId: 'GPUDevice.createComputePipeline',
        sourceDisposition: 'staged-unroutable-no-prototype-member',
        activeDisposition: 'active-private-graduated-route',
        disposition:
          'construction-private-route-and-native-codec-public-install-and-support-absent',
      }));
    expect(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.authenticatedPromotions
        .slice(1)
        .map((promotion) => promotion.operationId),
    ).toEqual([
      'GPUCommandEncoder.beginComputePass',
      'GPUCommandEncoder.clearBuffer',
      'GPUCommandEncoder.copyBufferToBuffer',
      'GPUCommandEncoder.copyTextureToTexture',
      'GPUComputePassEncoder.dispatchWorkgroups',
      'GPUComputePassEncoder.end',
      'GPUComputePassEncoder.setBindGroup',
      'GPUComputePassEncoder.setPipeline',
      'GPURenderPassEncoder.setBindGroup',
      'GPURenderPassEncoder.setVertexBuffer',
    ]);
    expect(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.authenticatedPromotions
        .slice(1)
        .every((promotion) =>
          promotion.sourceDisposition ===
            'private-wrapper-local-recording-no-dispatch' &&
          promotion.activeDisposition === 'active-private-graduated-route' &&
          promotion.disposition ===
            'construction-private-command-program-route-and-queue-submit-codec-public-install-and-support-absent'),
    ).toBe(true);
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
      'reviewed-generated-injection-and-request-adapter-request-device-create-bind-group-create-bind-group-layout-create-buffer-create-pipeline-layout-create-compute-pipeline-create-render-pipeline-create-sampler-create-texture-create-texture-view-create-command-encoder-create-shader-module-device-destroy-buffer-destroy-map-async-unmap-canvas-configure-canvas-unconfigure-texture-destroy-queue-write-buffer-queue-write-texture-queue-copy-external-image-to-texture-queue-submit-native-codec-not-installed-no-support-claim',
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
        { operationId: 'GPUDevice.createBindGroup', wireId: 1199806466 },
        { operationId: 'GPUDevice.createBindGroupLayout', wireId: 2544948076 },
        { operationId: 'GPUDevice.createBuffer', wireId: 1869756926 },
        { operationId: 'GPUDevice.createPipelineLayout', wireId: 3373402978 },
        { operationId: 'GPUDevice.createComputePipeline', wireId: 797909431 },
        { operationId: 'GPUDevice.createRenderPipeline', wireId: 2407151159 },
        { operationId: 'GPUDevice.createSampler', wireId: 3285037552 },
        { operationId: 'GPUDevice.createTexture', wireId: 4177957718 },
        { operationId: 'GPUTexture.createView', wireId: 1853125118 },
        { operationId: 'GPUDevice.createCommandEncoder', wireId: 4055478657 },
        { operationId: 'GPUDevice.createShaderModule', wireId: 599085487 },
        { operationId: 'GPUDevice.destroy', wireId: 206890944 },
        { operationId: 'GPUBuffer.destroy', wireId: 3314731466 },
        { operationId: 'GPUBuffer.mapAsync', wireId: 1760273919 },
        { operationId: 'GPUBuffer.unmap', wireId: 1228615721 },
        { operationId: 'GPUCanvasContext.configure', wireId: 56177326 },
        { operationId: 'GPUCanvasContext.unconfigure', wireId: 935342475 },
        { operationId: 'GPUTexture.destroy', wireId: 2933046788 },
        { operationId: 'GPUQueue.writeBuffer', wireId: 404589710 },
        { operationId: 'GPUQueue.writeTexture', wireId: 3114133342 },
        {
          operationId: 'GPUQueue.copyExternalImageToTexture',
          wireId: 2735509416,
        },
        { operationId: 'GPUQueue.submit', wireId: 308839175 },
      ],
    });
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes)
      .toHaveLength(24);
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
      EXACT_GPU_RESULT_BYTES_V2: 4,
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

  test('rejects drift in the authenticated compute route promotion', () => {
    const changed = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      authenticatedPromotions:
        WEBGPU_EXECUTABLE_CODEC_MANIFEST.authenticatedPromotions.map(
          (promotion) => ({
            ...promotion,
            sourceOperationSemanticSha256: '0'.repeat(64),
          }),
        ),
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changed,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('Invalid generated WebGPU executable codec manifest');
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

    const changedBindGroupBound = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      typeGpuBindGroupWorkloadEvidence: {
        ...WEBGPU_EXECUTABLE_CODEC_MANIFEST.typeGpuBindGroupWorkloadEvidence,
        maximumEntriesPerDescriptor: 6,
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedBindGroupBound,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('bind-group workload evidence');

    const changedBindGroupWitness = {
      ...WEBGPU_EXECUTABLE_CODEC_MANIFEST,
      typeGpuBindGroupWorkloadEvidence: {
        ...WEBGPU_EXECUTABLE_CODEC_MANIFEST.typeGpuBindGroupWorkloadEvidence,
        acceptedWitnesses:
          WEBGPU_EXECUTABLE_CODEC_MANIFEST.typeGpuBindGroupWorkloadEvidence
            .acceptedWitnesses.map((witness, index) => index === 0
              ? {
                  ...witness,
                  convertedDescriptorCanonicalJson:
                    `${witness.convertedDescriptorCanonicalJson} `,
                }
              : witness),
      },
    } as unknown as ExecutableWebGpuCodecManifest;
    expect(() => createExecutableWebGpuCodecs(
      changedBindGroupWitness,
      WEBGPU_OBJECT_KIND_TAGS,
    )).toThrow('bind-group full witness digest');
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
    ).toEqual({
      label: '',
      aspect: 'all',
      baseMipLevel: 0,
      baseArrayLayer: 0,
      swizzle: 'rgba',
      usage: 0,
    });
  });

  test('converts promoted command-record arguments with exact overload copies and bounds', () => {
    const convert = (operationId: string, args: readonly unknown[]) =>
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        operationId,
        args,
        wrappers,
      );

    expect(convert('GPUCommandEncoder.beginComputePass', [
      { label: 'compute-\ud800' },
    ])).toEqual({ label: 'compute-\ufffd', timestampWrites: null });
    expect(convert('GPUComputePassEncoder.dispatchWorkgroups', [2]))
      .toEqual({ workgroupCountX: 2, workgroupCountY: 1, workgroupCountZ: 1 });
    expect(convert('GPUCommandEncoder.clearBuffer', [gpuBuffer]))
      .toMatchObject({ offset: 0, size: null });
    expect(convert('GPUCommandEncoder.copyBufferToBuffer', [
      gpuBuffer,
      4,
      gpuBuffer,
      8,
      12,
    ])).toMatchObject({
      sourceOffset: 4,
      destinationOffset: 8,
      size: 12,
      overload: 'full',
    });

    const offsets = new Uint32Array([7, 8, 9]);
    const convertedOffsets = convert('GPUComputePassEncoder.setBindGroup', [
      2,
      bindGroup,
      offsets,
      1,
      2,
    ]) as Readonly<Record<string, unknown>>;
    offsets[1] = 99;
    expect(convertedOffsets).toMatchObject({
      index: 2,
      dynamicOffsets: [8, 9],
      overload: 'uint32-range',
    });
    expect(() => convert('GPURenderPassEncoder.setBindGroup', [
      0,
      bindGroup,
      offsets,
      2,
      2,
    ])).toThrow(RangeError);
    const tooManyOffsets = new Uint32Array(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount + 1,
    );
    expect(() => convert('GPUComputePassEncoder.setBindGroup', [
      0,
      bindGroup,
      tooManyOffsets,
      0,
      tooManyOffsets.length,
    ])).toThrow(RangeError);
    expect(() => convert('GPUCommandEncoder.copyTextureToTexture', [
      { texture },
      { texture },
      [1, 1, 1, 1],
    ])).toThrow(TypeError);
    expect(() => convert('GPUCommandEncoder.clearBuffer', [
      gpuBuffer,
      Number.MAX_SAFE_INTEGER + 1,
    ])).toThrow(TypeError);
  });

  test('materializes WebIDL defaults for all four authenticated TypeGPU render cohorts', () => {
    expect(renderPipelineConversionFixtures.schema).toBe(
      'ibex/webgpu-render-pipeline-conversion-fixtures/1',
    );
    expect(renderPipelineConversionFixtures.source.exactSemanticJoinSha256).toBe(
      'bb69afa17dabd7c7d7508d077d4c8fe4b1e19344d8b86518b696f4076d638713',
    );
    expect(renderPipelineConversionFixtures.source.projectionCanonicalization).toBe(
      'recursive-key-sorted-json-utf8',
    );
    expect(createHash('sha256')
      .update(canonicalJson(renderPipelineFixtureRows))
      .digest('hex')).toBe(
      renderPipelineConversionFixtures.source.projectionSha256,
    );
    expect(renderPipelineFixtureRows.map((row) => row.workload)).toEqual([
      'GeneticTextureUtility',
      'GeneticTrack',
      'GeneticCar',
      'JellySlider',
    ]);

    for (const row of renderPipelineFixtureRows) {
      const vertex: Record<string, unknown> = { module: shaderModule };
      if (row.sourceVertexBuffersPresence === 'present') {
        vertex.buffers = row.vertexBuffers ?? [];
      }
      const colorTarget: Record<string, unknown> = { format: row.targetFormat };
      if (row.blend !== undefined) colorTarget.blend = row.blend;
      const descriptor: Record<string, unknown> = {
        label: row.label,
        layout: pipelineLayout,
        fragment: { module: shaderModule, targets: [colorTarget] },
        vertex,
      };
      if (row.sourcePrimitivePresence === 'present') {
        descriptor.primitive = row.primitive ?? {};
      }

      const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
        .convertPublicArguments(
          'GPUDevice.createRenderPipeline',
          [descriptor],
          wrappers,
        ) as Readonly<Record<string, unknown>>;
      const convertedVertex = converted.vertex as Readonly<Record<string, unknown>>;
      const convertedFragment = converted.fragment as Readonly<Record<string, unknown>>;
      const convertedTargets = convertedFragment.targets as readonly Readonly<
        Record<string, unknown>
      >[];

      expect(converted).toEqual({
        label: row.label,
        layout: reference('GPUPipelineLayout'),
        fragment: {
          constants: {},
          module: reference('GPUShaderModule'),
          targets: [{
            ...(row.blend === undefined ? {} : { blend: row.blend }),
            format: row.targetFormat,
            writeMask: 0x0f,
          }],
        },
        multisample: {
          alphaToCoverageEnabled: false,
          count: 1,
          mask: 0xffff_ffff,
        },
        primitive: {
          cullMode: 'none',
          frontFace: 'ccw',
          topology: row.primitive?.topology ?? 'triangle-list',
          unclippedDepth: false,
        },
        vertex: {
          constants: {},
          module: reference('GPUShaderModule'),
          buffers: (row.vertexBuffers ?? []).map((buffer) => ({
            arrayStride: buffer.arrayStride,
            attributes: buffer.attributes.map((attribute) => ({ ...attribute })),
            stepMode: buffer.stepMode ?? 'vertex',
          })),
        },
      });
      expect(Object.hasOwn(converted, 'depthStencil')).toBe(false);
      expect(Object.hasOwn(converted, 'multisample')).toBe(true);
      expect(Object.hasOwn(converted, 'primitive')).toBe(true);
      expect(Object.hasOwn(convertedVertex, 'buffers')).toBe(true);
      expect(Object.hasOwn(convertedVertex, 'constants')).toBe(true);
      expect(Object.hasOwn(convertedVertex, 'entryPoint')).toBe(false);
      expect(Object.hasOwn(convertedFragment, 'constants')).toBe(true);
      expect(Object.hasOwn(convertedFragment, 'entryPoint')).toBe(false);
      expect(Object.hasOwn(convertedTargets[0], 'writeMask')).toBe(true);
      expect(Object.hasOwn(
        converted.primitive as Readonly<Record<string, unknown>>,
        'stripIndexFormat',
      )).toBe(false);
      expect(Object.isFrozen(converted)).toBe(true);
      expect(Object.isFrozen(convertedVertex)).toBe(true);
      expect(Object.isFrozen(convertedTargets)).toBe(true);
    }
  });

  test('preserves the exact seven authenticated TypeGPU compute cohorts', () => {
    expect(computePipelineConversionFixtures.schema).toBe(
      'ibex/webgpu-compute-pipeline-conversion-fixtures/1',
    );
    expect(computePipelineConversionFixtures.source).toEqual({
      typegpuVersion: '0.11.9',
      exactSemanticJoinSha256:
        'bb69afa17dabd7c7d7508d077d4c8fe4b1e19344d8b86518b696f4076d638713',
      projectionSha256:
        'ec8b168944cc45636078973d06554916d730084f000926bf3e4c51ef5b11f6fe',
      projectionCanonicalization: 'recursive-key-sorted-json-utf8',
      disposition:
        'authenticated-workload-cohort-conversion-only-no-native-or-install-claim',
    });
    expect(computePipelineFixtureRows).toHaveLength(7);
    expect(computePipelineFixtureRows.filter(
      (row) => row.workloadId === 'typegpu-genetic-racing',
    )).toHaveLength(6);
    expect(computePipelineFixtureRows.filter(
      (row) => row.workloadId === 'typegpu-jelly-slider',
    )).toHaveLength(1);
    expect(new Set(computePipelineFixtureRows.map(
      (row) => row.shaderSourceSha256,
    )).size).toBe(7);
    expect(createHash('sha256')
      .update(canonicalJson(computePipelineFixtureRows))
      .digest('hex')).toBe(
      computePipelineConversionFixtures.source.projectionSha256,
    );

    for (const row of computePipelineFixtureRows) {
      const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
        .convertPublicArguments(
          'GPUDevice.createComputePipeline',
          [{
            label: row.label,
            layout: pipelineLayout,
            compute: { module: shaderModule },
          }],
          wrappers,
        ) as Readonly<Record<string, unknown>>;
      const compute = converted.compute as Readonly<Record<string, unknown>>;
      expect(converted).toEqual({
        label: row.label,
        layout: reference('GPUPipelineLayout'),
        compute: {
          constants: {},
          module: reference('GPUShaderModule'),
        },
      });
      expect(row.layoutKind).toBe('explicit');
      expect(row.sourceConstantsPresence).toBe('omitted');
      expect(row.entryPointPresence).toBe('omitted');
      expect(Object.hasOwn(compute, 'constants')).toBe(true);
      expect(Object.hasOwn(compute, 'entryPoint')).toBe(false);
      expect(Object.isFrozen(converted)).toBe(true);
      expect(Object.isFrozen(compute)).toBe(true);
    }
  });

  test('converts compute descriptors in exact WebIDL order and preserves optional presence', () => {
    const trace: string[] = [];
    const observed = (
      label: string,
      values: Readonly<Record<string, unknown>>,
    ): Record<string, unknown> => {
      const result: Record<string, unknown> = {};
      for (const [name, value] of Object.entries(values)) {
        Object.defineProperty(result, name, {
          enumerable: true,
          get() {
            trace.push(`${label}.${name}`);
            return value;
          },
        });
      }
      return result;
    };
    const constants = observed('constants', { zeta: 2, alpha: 1 });
    const compute = observed('compute', {
      constants,
      entryPoint: 'item',
      module: shaderModule,
    });
    const descriptor = observed('pipeline', {
      label: 'ordered',
      layout: 'auto',
      compute,
    });
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [descriptor],
        wrappers,
      ) as Readonly<Record<string, unknown>>;

    expect(trace).toEqual([
      'pipeline.label',
      'pipeline.layout',
      'pipeline.compute',
      'compute.constants',
      'constants.zeta',
      'constants.alpha',
      'compute.entryPoint',
      'compute.module',
    ]);
    expect(converted).toEqual({
      label: 'ordered',
      layout: 'auto',
      compute: {
        constants: { alpha: 1, zeta: 2 },
        entryPoint: 'item',
        module: reference('GPUShaderModule'),
      },
    });
    const convertedCompute = converted.compute as Readonly<Record<string, unknown>>;
    expect(Object.hasOwn(convertedCompute, 'constants')).toBe(true);
    expect(Object.hasOwn(convertedCompute, 'entryPoint')).toBe(true);

    let laterReads = 0;
    const rejectingCompute = {
      constants: { bad: 1n },
      get entryPoint() {
        laterReads += 1;
        return 'item';
      },
      get module() {
        laterReads += 1;
        return shaderModule;
      },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: 'auto', compute: rejectingCompute }],
      wrappers,
    )).toThrow(TypeError);
    expect(laterReads).toBe(0);

    let nullLaterReads = 0;
    const nullConstantsCompute = {
      constants: null,
      get entryPoint() {
        nullLaterReads += 1;
        return 'item';
      },
      get module() {
        nullLaterReads += 1;
        return shaderModule;
      },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: 'auto', compute: nullConstantsCompute }],
      wrappers,
    )).toThrow(TypeError);
    expect(nullLaterReads).toBe(0);
  });

  test('discriminates pipeline layout brands before the enum string fallback', () => {
    const convertComputeLayout = (layout: unknown) => (
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [{ layout, compute: { module: shaderModule } }],
        wrappers,
      ) as Readonly<Record<string, unknown>>
    ).layout;
    const convertRenderLayout = (layout: unknown) => (
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUDevice.createRenderPipeline',
        [{ layout, vertex: { module: shaderModule } }],
        wrappers,
      ) as Readonly<Record<string, unknown>>
    ).layout;

    let ordinaryCalls = 0;
    const ordinary = {
      toString() {
        ordinaryCalls += 1;
        return 'auto';
      },
    };
    expect(convertComputeLayout(ordinary)).toBe('auto');
    expect(convertRenderLayout(ordinary)).toBe('auto');
    expect(ordinaryCalls).toBe(2);
    expect(convertComputeLayout(new String('auto'))).toBe('auto');

    let functionCalls = 0;
    const callable = function () {};
    Object.defineProperty(callable, Symbol.toPrimitive, {
      value() {
        functionCalls += 1;
        return 'auto';
      },
    });
    expect(convertComputeLayout(callable)).toBe('auto');
    expect(functionCalls).toBe(1);

    const sentinel = new Error('layout conversion sentinel');
    expect(() => convertComputeLayout({
      toString() {
        throw sentinel;
      },
    })).toThrow(sentinel);

    let brandedStringCalls = 0;
    const brandedLayout = {
      toString() {
        brandedStringCalls += 1;
        throw new Error('branded layout must not stringify');
      },
    };
    wrapperKinds.set(brandedLayout, 'GPUPipelineLayout');
    expect(convertComputeLayout(brandedLayout)).toEqual(reference('GPUPipelineLayout'));
    expect(brandedStringCalls).toBe(0);

    let wrongBrandStringCalls = 0;
    const wrongBrand = {
      toString() {
        wrongBrandStringCalls += 1;
        return 'auto';
      },
    };
    wrapperKinds.set(wrongBrand, 'GPUShaderModule');
    expect(() => convertComputeLayout(wrongBrand)).toThrow(TypeError);
    expect(wrongBrandStringCalls).toBe(0);
    expect(() => convertComputeLayout(Symbol('auto'))).toThrow(TypeError);

    const proxyTrace: string[] = [];
    const proxy = new Proxy({
      toString() {
        proxyTrace.push('call:toString');
        return 'auto';
      },
    }, {
      get(target, key, receiver) {
        proxyTrace.push(`get:${String(key)}`);
        return Reflect.get(target, key, receiver);
      },
    });
    expect(convertComputeLayout(proxy)).toBe('auto');
    expect(proxyTrace).toEqual([
      'get:Symbol(Symbol.toPrimitive)',
      'get:toString',
      'call:toString',
    ]);

    const revocable = Proxy.revocable({}, {});
    revocable.revoke();
    expect(() => convertComputeLayout(revocable.proxy)).toThrow(TypeError);
  });

  test('interleaves record traps and preserves every legal constants key', () => {
    const trace: string[] = [];
    const rawConstants = Object.create(null) as Record<string, number>;
    Object.defineProperties(rawConstants, {
      zeta: { configurable: true, enumerable: true, value: 2 },
      alpha: { configurable: true, enumerable: true, value: 1 },
    });
    const constants = new Proxy(rawConstants, {
      ownKeys(target) {
        trace.push('ownKeys');
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        trace.push(`descriptor:${String(key)}`);
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      get(target, key, receiver) {
        trace.push(`get:${String(key)}`);
        return Reflect.get(target, key, receiver);
      },
    });
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [{ layout: 'auto', compute: { constants, module: shaderModule } }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const convertedConstants = (
      converted.compute as Readonly<Record<string, unknown>>
    ).constants as Readonly<Record<string, number>>;

    expect(trace).toEqual([
      'ownKeys',
      'descriptor:zeta',
      'get:zeta',
      'descriptor:alpha',
      'get:alpha',
    ]);
    expect(Object.keys(convertedConstants)).toEqual(['alpha', 'zeta']);

    const unicodeOrder = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [{
          layout: 'auto',
          compute: {
            constants: { '\u{10000}': 1, '\ue000': 2 },
            module: shaderModule,
          },
        }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const unicodeConstants = (
      unicodeOrder.compute as Readonly<Record<string, unknown>>
    ).constants as Readonly<Record<string, number>>;
    expect(Object.keys(unicodeConstants)).toEqual(['\ue000', '\u{10000}']);

    const special = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(special, '__proto__', {
      enumerable: true,
      value: 3,
    });
    const specialConverted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [{ layout: 'auto', compute: { constants: special, module: shaderModule } }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const specialConstants = (
      specialConverted.compute as Readonly<Record<string, unknown>>
    ).constants as Readonly<Record<string, number>>;
    expect(Object.hasOwn(specialConstants, '__proto__')).toBe(true);
    expect(specialConstants.__proto__).toBe(3);
    expect(Object.getPrototypeOf(specialConstants)).toBe(Object.prototype);

    const enumerableSymbol = Symbol('constant');
    let symbolValueReads = 0;
    const symbolConstants = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(symbolConstants, enumerableSymbol, {
      enumerable: true,
      get() {
        symbolValueReads += 1;
        return 4;
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: 'auto', compute: { constants: symbolConstants, module: shaderModule } }],
      wrappers,
    )).toThrow(TypeError);
    expect(symbolValueReads).toBe(0);
  });

  test('converts WebGPU USVString fields and collapsing record keys exactly', () => {
    const loneSurrogate = '\ud800';
    const replacement = '\ufffd';
    const constants = Object.create(null) as Record<string, number>;
    Object.defineProperty(constants, loneSurrogate, {
      enumerable: true,
      value: 1,
    });
    Object.defineProperty(constants, replacement, {
      enumerable: true,
      value: 2,
    });
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [{
          label: `pipeline-${loneSurrogate}`,
          layout: 'auto',
          compute: {
            constants,
            entryPoint: `entry-${loneSurrogate}`,
            module: shaderModule,
          },
        }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const compute = converted.compute as Readonly<Record<string, unknown>>;
    const convertedConstants = compute.constants as Readonly<Record<string, number>>;
    expect(converted.label).toBe(`pipeline-${replacement}`);
    expect(compute.entryPoint).toBe(`entry-${replacement}`);
    expect(Object.keys(convertedConstants)).toEqual([replacement]);
    expect(convertedConstants[replacement]).toBe(2);

    const shader = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createShaderModule',
        [{ code: `source-${loneSurrogate}` }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    expect(shader.code).toBe(`source-${replacement}`);
  });

  test('retains same-realm cross-device compute lineage for service rejection', () => {
    const crossDeviceLayout = Object.freeze({ marker: 'cross-device-layout' });
    const receiverDeviceShader = Object.freeze({ marker: 'receiver-device-shader' });
    const lineageRefs = new WeakMap<object, ReturnType<
      ProductionGpuCodecWrapperAccess['reference']
    >>();
    const knownLineageBrands = new WeakSet<object>();
    knownLineageBrands.add(crossDeviceLayout);
    knownLineageBrands.add(receiverDeviceShader);
    lineageRefs.set(crossDeviceLayout, Object.freeze({
      kind: 'GPUPipelineLayout',
      objectId: '41',
      objectGeneration: '1',
      logicalDeviceId: '311',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    }));
    lineageRefs.set(receiverDeviceShader, Object.freeze({
      kind: 'GPUShaderModule',
      objectId: '42',
      objectGeneration: '1',
      logicalDeviceId: '301',
      logicalDeviceGeneration: '1',
      providerGeneration: '7',
    }));
    const lineageWrappers: ProductionGpuCodecWrapperAccess = {
      referenceIfBranded(value, expectedKind) {
        if (
          typeof value !== 'object' ||
          value === null ||
          !knownLineageBrands.has(value)
        ) {
          return undefined;
        }
        return lineageWrappers.reference(value, expectedKind);
      },
      reference(value, expectedKind) {
        if (typeof value !== 'object' || value === null) {
          throw new TypeError('unbranded WebGPU object');
        }
        const ref = lineageRefs.get(value);
        if (!ref) throw new TypeError('foreign WebGPU realm');
        if (expectedKind !== undefined && ref.kind !== expectedKind) {
          throw new TypeError('wrong WebGPU object brand');
        }
        return ref;
      },
    };
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createComputePipeline',
        [{
          layout: crossDeviceLayout,
          compute: { module: receiverDeviceShader },
        }],
        lineageWrappers,
      ) as Readonly<Record<string, unknown>>;
    expect(converted).toMatchObject({
      layout: {
        kind: 'GPUPipelineLayout',
        logicalDeviceId: '311',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      compute: {
        module: {
          kind: 'GPUShaderModule',
          logicalDeviceId: '301',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
      },
    });

    const foreignLayout = Object.freeze({ marker: 'foreign-layout' });
    knownLineageBrands.add(foreignLayout);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: foreignLayout, compute: { module: receiverDeviceShader } }],
      lineageWrappers,
    )).toThrow('foreign WebGPU realm');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: bindGroupLayout, compute: { module: shaderModule } }],
      wrappers,
    )).toThrow('wrong WebGPU object brand');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: pipelineLayout, compute: { module: pipelineLayout } }],
      wrappers,
    )).toThrow('wrong WebGPU object brand');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ compute: { module: shaderModule } }],
      wrappers,
    )).toThrow('layout is required');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: 'auto' }],
      wrappers,
    )).toThrow('compute is required');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createComputePipeline',
      [{ layout: 'auto', compute: {} }],
      wrappers,
    )).toThrow('module is required');
  });

  test('converts bounded depth-stencil state without erasing presence', () => {
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createRenderPipeline',
        [{
          layout: 'auto',
          depthStencil: {
            depthBias: -2.9,
            depthBiasClamp: 1.25,
            depthBiasSlopeScale: 0.5,
            depthCompare: 'greater',
            depthWriteEnabled: 1,
            format: 'depth24plus-stencil8',
            stencilBack: {
              compare: 'less',
              depthFailOp: 'replace',
              failOp: 'zero',
              passOp: 'invert',
            },
            stencilFront: {},
            stencilReadMask: 0x00ff,
            stencilWriteMask: 0xff00,
          },
          fragment: {
            constants: {},
            entryPoint: 'fs',
            module: shaderModule,
            targets: [{ format: 'rgba8unorm', writeMask: 0 }],
          },
          multisample: {
            alphaToCoverageEnabled: 1,
            count: 4,
            mask: 3,
          },
          primitive: { stripIndexFormat: 'uint16' },
          vertex: {
            constants: { beta: 2, alpha: 1 },
            entryPoint: 'vs',
            module: shaderModule,
            buffers: [undefined, null],
          },
        }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;

    expect(converted).toEqual({
      label: '',
      layout: 'auto',
      depthStencil: {
        depthBias: -2,
        depthBiasClamp: 1.25,
        depthBiasSlopeScale: 0.5,
        depthCompare: 'greater',
        depthWriteEnabled: true,
        format: 'depth24plus-stencil8',
        stencilBack: {
          compare: 'less',
          depthFailOp: 'replace',
          failOp: 'zero',
          passOp: 'invert',
        },
        stencilFront: {
          compare: 'always',
          depthFailOp: 'keep',
          failOp: 'keep',
          passOp: 'keep',
        },
        stencilReadMask: 0x00ff,
        stencilWriteMask: 0xff00,
      },
      fragment: {
        constants: {},
        entryPoint: 'fs',
        module: reference('GPUShaderModule'),
        targets: [{ format: 'rgba8unorm', writeMask: 0 }],
      },
      multisample: {
        alphaToCoverageEnabled: true,
        count: 4,
        mask: 3,
      },
      primitive: {
        cullMode: 'none',
        frontFace: 'ccw',
        stripIndexFormat: 'uint16',
        topology: 'triangle-list',
        unclippedDepth: false,
      },
      vertex: {
        constants: { alpha: 1, beta: 2 },
        entryPoint: 'vs',
        module: reference('GPUShaderModule'),
        buffers: [null, null],
      },
    });
    expect(Object.keys(
      (converted.vertex as Readonly<Record<string, unknown>>).constants as object,
    )).toEqual(['alpha', 'beta']);

    const omittedOptionals = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createRenderPipeline',
        [{
          layout: 'auto',
          depthStencil: { format: 'depth24plus' },
          vertex: { module: shaderModule },
        }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const omittedDepth = omittedOptionals.depthStencil as Readonly<
      Record<string, unknown>
    >;
    expect(Object.hasOwn(omittedDepth, 'depthCompare')).toBe(false);
    expect(Object.hasOwn(omittedDepth, 'depthWriteEnabled')).toBe(false);
    expect(omittedDepth).toMatchObject({
      depthBias: 0,
      depthBiasClamp: 0,
      depthBiasSlopeScale: 0,
      stencilReadMask: 0xffff_ffff,
      stencilWriteMask: 0xffff_ffff,
    });
  });

  test('observes programmable constants before canonicalizing and rejects BigInt', () => {
    const trace: string[] = [];
    const constants: Record<string, unknown> = {};
    for (const [key, value] of [['zeta', 2], ['alpha', 1]] as const) {
      Object.defineProperty(constants, key, {
        enumerable: true,
        get() {
          trace.push(key);
          return value;
        },
      });
    }
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUDevice.createRenderPipeline',
        [{
          layout: 'auto',
          vertex: { constants, module: shaderModule },
        }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const convertedConstants = (
      converted.vertex as Readonly<Record<string, unknown>>
    ).constants as Readonly<Record<string, number>>;

    expect(trace).toEqual(['zeta', 'alpha']);
    expect(Object.keys(convertedConstants)).toEqual(['alpha', 'zeta']);
    expect(convertedConstants).toEqual({ alpha: 1, zeta: 2 });

    let moduleReads = 0;
    const stage = {
      constants: { bad: 1n },
      get module() {
        moduleReads += 1;
        return shaderModule;
      },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{ layout: 'auto', vertex: stage }],
      wrappers,
    )).toThrow(TypeError);
    expect(moduleReads).toBe(0);
  });

  test('orders render WebIDL conversion and fails brands or bounds synchronously', () => {
    const trace: string[] = [];
    const observed = (
      label: string,
      values: Readonly<Record<string, unknown>>,
    ): Record<string, unknown> => {
      const result: Record<string, unknown> = {};
      for (const [name, value] of Object.entries(values)) {
        Object.defineProperty(result, name, {
          enumerable: true,
          get() {
            trace.push(`${label}.${name}`);
            return value;
          },
        });
      }
      return result;
    };
    const vertex = observed('vertex', {
      constants: undefined,
      entryPoint: undefined,
      module: shaderModule,
      buffers: undefined,
    });
    const descriptor = observed('pipeline', {
      label: 'ordered',
      layout: pipelineLayout,
      depthStencil: undefined,
      fragment: undefined,
      multisample: undefined,
      primitive: undefined,
      vertex,
    });
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [descriptor],
      wrappers,
    )).toMatchObject({ label: 'ordered', layout: reference('GPUPipelineLayout') });
    expect(trace).toEqual([
      'pipeline.label',
      'pipeline.layout',
      'pipeline.depthStencil',
      'pipeline.fragment',
      'pipeline.multisample',
      'pipeline.primitive',
      'pipeline.vertex',
      'vertex.constants',
      'vertex.entryPoint',
      'vertex.module',
      'vertex.buffers',
    ]);

    const base = {
      layout: pipelineLayout,
      vertex: { module: shaderModule },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{ vertex: { module: shaderModule } }],
      wrappers,
    )).toThrow('layout is required');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{ ...base, layout: bindGroupLayout }],
      wrappers,
    )).toThrow('wrong WebGPU object brand');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{ ...base, vertex: { module: pipelineLayout } }],
      wrappers,
    )).toThrow('wrong WebGPU object brand');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{ ...base, vertex: { module: shaderModule, buffers: null } }],
      wrappers,
    )).toThrow('GPUVertexState.buffers must be iterable');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{ ...base, vertex: { module: shaderModule, buffers: Array(1025).fill(null) } }],
      wrappers,
    )).toThrow('reviewed sequence bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{
        ...base,
        vertex: {
          module: shaderModule,
          buffers: [{ arrayStride: 4, attributes: Array(1025).fill({
            format: 'float32',
            offset: 0,
            shaderLocation: 0,
          }) }],
        },
      }],
      wrappers,
    )).toThrow('reviewed sequence bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{
        ...base,
        fragment: {
          module: shaderModule,
          targets: Array(1025).fill(null),
        },
      }],
      wrappers,
    )).toThrow('reviewed sequence bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{
        ...base,
        depthStencil: { depthBias: 0x8000_0000, format: 'depth24plus' },
      }],
      wrappers,
    )).toThrow('signed 32-bit integer');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createRenderPipeline',
      [{
        ...base,
        depthStencil: { depthBiasClamp: Infinity, format: 'depth24plus' },
      }],
      wrappers,
    )).toThrow('finite float');
  });

  test('converts buffer lifecycle arguments and snapshots queue uploads synchronously', () => {
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUBuffer.getMappedRange',
      [],
      wrappers,
    )).toEqual({ offset: 0 });
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUBuffer.mapAsync',
      [2, 8, 16],
      wrappers,
    )).toEqual({ mode: 2, offset: 8, size: 16 });

    const source = new Uint16Array([10, 20, 30, 40]);
    const sourceBuffer = source.buffer;
    const sourceByteOffset = source.byteOffset;
    const sourceByteLength = source.byteLength;
    let shadowedMetadataReads = 0;
    for (const [name, value] of [
      ['buffer', sourceBuffer],
      ['byteOffset', sourceByteOffset],
      ['byteLength', sourceByteLength],
      ['BYTES_PER_ELEMENT', 99],
    ] as const) {
      Object.defineProperty(source, name, {
        configurable: true,
        get() {
          shadowedMetadataReads += 1;
          return value;
        },
      });
    }
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUQueue.writeBuffer',
        [gpuBuffer, 12, source, 1, 2],
        wrappers,
      ) as Readonly<{
        buffer: Readonly<Record<string, unknown>>;
        bufferOffset: number;
        bytes: Uint8Array;
      }>;
    expect(converted.buffer).toMatchObject({ kind: 'GPUBuffer' });
    expect(converted.bufferOffset).toBe(12);
    expect(Array.from(converted.bytes)).toEqual([20, 0, 30, 0]);
    expect(shadowedMetadataReads).toBe(0);
    source[1] = 99;
    expect(Array.from(converted.bytes)).toEqual([20, 0, 30, 0]);

    for (const args of [
      [gpuBuffer, 0, new Uint8Array(4), 5],
      [gpuBuffer, 0, new Uint8Array(3)],
    ] as const) {
      let synchronousError: unknown;
      try {
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          'GPUQueue.writeBuffer',
          args,
          wrappers,
        );
      } catch (error) {
        synchronousError = error;
      }
      expect(synchronousError).toMatchObject({ name: 'OperationError' });
    }
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUQueue.writeBuffer',
      [gpuBuffer, 0n, new Uint8Array(4)],
      wrappers,
    )).toThrow(TypeError);

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUBuffer.mapAsync',
      [1n],
      wrappers,
    )).toThrow(TypeError);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUQueue.writeBuffer',
      [gpuBuffer, 0, {}],
      wrappers,
    )).toThrow('AllowSharedBufferSource');
  });

  test('converts writeTexture in exact argument order and snapshots the whole BufferSource', () => {
    const reads: string[] = [];
    const destination = Object.create(null);
    for (const [name, value] of [
      ['aspect', 'stencil-only'],
      ['mipLevel', 2],
      ['origin', [3, 4, 5]],
      ['texture', texture],
    ] as const) {
      Object.defineProperty(destination, name, {
        get() {
          reads.push(`destination.${name}`);
          return value;
        },
      });
    }
    const layout = Object.create(null);
    for (const [name, value] of [
      ['bytesPerRow', 256],
      ['offset', 1],
      ['rowsPerImage', 2],
    ] as const) {
      Object.defineProperty(layout, name, {
        get() {
          reads.push(`layout.${name}`);
          return value;
        },
      });
    }
    const size = Object.create(null);
    for (const [name, value] of [
      ['depthOrArrayLayers', 1],
      ['height', 1],
      ['width', 1],
    ] as const) {
      Object.defineProperty(size, name, {
        get() {
          reads.push(`size.${name}`);
          return value;
        },
      });
    }
    const backing = Uint8Array.from([9, 8, 7, 6, 5, 4]);
    const data = new Uint8Array(backing.buffer, 1, 4);
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUQueue.writeTexture',
        [destination, data, layout, size],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    expect(reads).toEqual([
      'destination.aspect',
      'destination.mipLevel',
      'destination.origin',
      'destination.texture',
      'layout.bytesPerRow',
      'layout.offset',
      'layout.rowsPerImage',
      'size.depthOrArrayLayers',
      'size.height',
      'size.width',
    ]);
    expect(converted).toMatchObject({
      destination: {
        texture: { kind: 'GPUTexture' },
        mipLevel: 2,
        origin: { x: 3, y: 4, z: 5, iterableLength: 3 },
        aspect: 'stencil-only',
      },
      dataLayout: { bytesPerRow: 256, offset: 1, rowsPerImage: 2 },
      size: {
        width: 1,
        height: 1,
        depthOrArrayLayers: 1,
        iterableLength: null,
      },
    });
    expect(Array.from(converted.bytes as Uint8Array)).toEqual([8, 7, 6, 5]);
    data.fill(99);
    expect(Array.from(converted.bytes as Uint8Array)).toEqual([8, 7, 6, 5]);

    const deferredReads: string[] = [];
    const invalidDestination = {
      get aspect() { deferredReads.push('aspect'); return 'all'; },
      get mipLevel() { deferredReads.push('mipLevel'); return 0; },
      get origin() { deferredReads.push('origin'); return [0, 0, 0, 0]; },
      get texture() { deferredReads.push('texture'); return texture; },
    };
    const laterLayout = {
      get bytesPerRow() { deferredReads.push('bytesPerRow'); return 256; },
      get offset() { deferredReads.push('offset'); return 0; },
      get rowsPerImage() { deferredReads.push('rowsPerImage'); return 1; },
    };
    const laterSize = {
      get depthOrArrayLayers() { deferredReads.push('depth'); return 1; },
      get height() { deferredReads.push('height'); return 1; },
      get width() { deferredReads.push('width'); return 1; },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUQueue.writeTexture',
      [invalidDestination, new Uint8Array(4), laterLayout, laterSize],
      wrappers,
    )).toThrow('at most three');
    expect(deferredReads).toEqual([
      'aspect', 'mipLevel', 'origin', 'texture', 'bytesPerRow', 'offset',
      'rowsPerImage', 'depth', 'height', 'width',
    ]);

    const oversizeReads: string[] = [];
    const oversizeLayout = {
      get bytesPerRow() { oversizeReads.push('bytesPerRow'); return 256; },
      get offset() { oversizeReads.push('offset'); return 0; },
      get rowsPerImage() { oversizeReads.push('rowsPerImage'); return 1; },
    };
    const oversizeSize = {
      get depthOrArrayLayers() { oversizeReads.push('depth'); return 1; },
      get height() { oversizeReads.push('height'); return 1; },
      get width() { oversizeReads.push('width'); return 1; },
    };
    const oversizeSource = new Uint8Array(16_777_025);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUQueue.writeTexture',
      [
        { texture },
        oversizeSource,
        oversizeLayout,
        oversizeSize,
      ],
      wrappers,
    )).toThrow('exact payload bound');
    expect(oversizeReads).toEqual([
      'bytesPerRow', 'offset', 'rowsPerImage', 'depth', 'height', 'width',
    ]);
  });

  test('authenticates copyExternalImageToTexture only after complete Web IDL and shape conversion', () => {
    const reads: string[] = [];
    const source = Object.create(null);
    for (const [name, value] of [
      ['flipY', true],
      ['origin', [0, 0]],
      ['source', externalImage],
    ] as const) {
      Object.defineProperty(source, name, {
        get() { reads.push(`source.${name}`); return value; },
      });
    }
    const destination = Object.create(null);
    for (const [name, value] of [
      ['aspect', 'all'],
      ['colorSpace', 'display-p3'],
      ['mipLevel', 1],
      ['origin', [2, 3, 0]],
      ['premultipliedAlpha', true],
      ['texture', texture],
    ] as const) {
      Object.defineProperty(destination, name, {
        get() { reads.push(`destination.${name}`); return value; },
      });
    }
    const copySize = {
      get depthOrArrayLayers() { reads.push('size.depth'); return 1; },
      get height() { reads.push('size.height'); return 1; },
      get width() { reads.push('size.width'); return 1; },
    };
    const authenticatedWrappers: ProductionGpuCodecWrapperAccess = {
      reference: wrappers.reference,
      referenceIfBranded: wrappers.referenceIfBranded,
      snapshotExternalImageForCopy(value, origin, size) {
        reads.push('content.snapshot');
        expect(value).toBe(externalImage);
        expect(origin).toMatchObject({ x: 0, y: 0 });
        expect(size).toMatchObject({ width: 1, height: 1, depthOrArrayLayers: 1 });
        return externalImageSnapshot();
      },
    };
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUQueue.copyExternalImageToTexture',
        [source, destination, copySize],
        authenticatedWrappers,
      ) as Readonly<Record<string, unknown>>;
    expect(reads).toEqual([
      'source.flipY',
      'source.origin',
      'source.source',
      'destination.aspect',
      'destination.colorSpace',
      'destination.mipLevel',
      'destination.origin',
      'destination.premultipliedAlpha',
      'destination.texture',
      'size.depth',
      'size.height',
      'size.width',
      'content.snapshot',
    ]);
    expect(converted).toMatchObject({
      source: {
        origin: { x: 0, y: 0, iterableLength: 2 },
        flipY: true,
        snapshot: { usability: 'good', decodedContentSha256: 'b'.repeat(64) },
      },
      destination: {
        texture: { kind: 'GPUTexture' },
        mipLevel: 1,
        origin: { x: 2, y: 3, z: 0, iterableLength: 3 },
        colorSpace: 'display-p3',
        premultipliedAlpha: true,
      },
      copySize: { width: 1, height: 1, depthOrArrayLayers: 1 },
    });

    let contentChecks = 0;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUQueue.copyExternalImageToTexture',
      [
        { source: externalImage, origin: [0, 0, 0] },
        { texture },
        [1, 1, 1],
      ],
      {
        ...authenticatedWrappers,
        snapshotExternalImageForCopy() {
          contentChecks += 1;
          return externalImageSnapshot();
        },
      },
    )).toThrow('at most two');
    expect(contentChecks).toBe(0);
  });

  test('converts createView in inherited lexicographic order exactly once', () => {
    const reads: string[] = [];
    const descriptor = Object.create(Object.defineProperty({}, 'label', {
      get() {
        reads.push('label');
        return 'ordered-view';
      },
    }));
    for (const [name, value] of [
      ['arrayLayerCount', 2],
      ['aspect', 'all'],
      ['baseArrayLayer', 1],
      ['baseMipLevel', 3],
      ['dimension', '2d-array'],
      ['format', 'rgba8unorm'],
      ['mipLevelCount', 4],
      ['swizzle', 'bgra'],
      ['usage', 4],
    ] as const) {
      Object.defineProperty(descriptor, name, {
        get() {
          reads.push(name);
          return value;
        },
      });
    }
    expect(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUTexture.createView',
        [descriptor],
        wrappers,
      ),
    ).toEqual({
      arrayLayerCount: 2,
      aspect: 'all',
      baseArrayLayer: 1,
      baseMipLevel: 3,
      dimension: '2d-array',
      format: 'rgba8unorm',
      label: 'ordered-view',
      mipLevelCount: 4,
      swizzle: 'bgra',
      usage: 4,
    });
    expect(reads).toEqual([
      'arrayLayerCount',
      'aspect',
      'baseArrayLayer',
      'baseMipLevel',
      'dimension',
      'format',
      'label',
      'mipLevelCount',
      'swizzle',
      'usage',
    ]);
  });

  test('stops createView Web IDL observation at the first throwing member', () => {
    const reads: string[] = [];
    const descriptor = Object.create(null);
    for (const name of [
      'arrayLayerCount',
      'aspect',
      'baseArrayLayer',
      'baseMipLevel',
      'dimension',
      'format',
      'label',
      'mipLevelCount',
      'swizzle',
      'usage',
    ]) {
      Object.defineProperty(descriptor, name, {
        get() {
          reads.push(name);
          if (name === 'dimension') throw new Error('dimension getter failed');
          return undefined;
        },
      });
    }
    expect(() =>
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUTexture.createView',
        [descriptor],
        wrappers,
      )).toThrow('dimension getter failed');
    expect(reads).toEqual([
      'arrayLayerCount',
      'aspect',
      'baseArrayLayer',
      'baseMipLevel',
      'dimension',
    ]);
    expect(() =>
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        'GPUTexture.createView',
        [{ swizzle: 'rgb' }],
        wrappers,
      )).toThrow('exactly four');
  });

  test('conversion failures are synchronous, branded, bounded, and codec-specific', () => {
    const invalid: ReadonlyArray<readonly [string, readonly unknown[]]> = [
      ['GPU.requestAdapter', [{ powerPreference: 'fastest' }]],
      ['GPUCanvasContext.configure', [{ device: {}, format: 'bgra8unorm' }]],
      ['GPUCommandEncoder.beginRenderPass', [{ colorAttachments: [{ view: {} }] }]],
      ['GPUDevice.createBindGroup', [{}]],
      ['GPUDevice.createBindGroupLayout', [{}]],
      ['GPUDevice.createBuffer', [{}]],
      ['GPUDevice.createPipelineLayout', [{}]],
      ['GPUDevice.createComputePipeline', [{}]],
      ['GPUDevice.createRenderPipeline', [{}]],
      ['GPUDevice.createSampler', [{ magFilter: 'cubic' }]],
      ['GPUDevice.createShaderModule', [{}]],
      ['GPUDevice.createTexture', [{}]],
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
            : route.operationId === 'GPUDevice.destroy' ||
                route.operationId === 'GPUBuffer.destroy' ||
                route.operationId === 'GPUBuffer.unmap'
            ? null
            : route.operationId === 'GPUBuffer.mapAsync'
            ? { mode: 1, offset: 0 }
            : route.operationId === 'GPUQueue.writeBuffer'
            ? {
              buffer: reference('GPUBuffer'),
              bufferOffset: 0,
              bytes: [1, 2, 3, 4],
            }
            : route.operationId === 'GPUQueue.writeTexture'
            ? {
              destination: {
                texture: reference('GPUTexture'),
                mipLevel: 0,
                origin: { x: 0, y: 0, z: 0, iterableLength: null },
                aspect: 'all',
              },
              dataLayout: { offset: '0', bytesPerRow: 256 },
              size: {
                width: 1,
                height: 1,
                depthOrArrayLayers: 1,
                iterableLength: null,
              },
              bytes: [1, 2, 3, 4],
            }
            : route.operationId === 'GPUQueue.copyExternalImageToTexture'
            ? {
              source: {
                origin: { x: 0, y: 0, iterableLength: null },
                snapshot: {
                  runtimeAddress: '73',
                  runtimeNonce: '91',
                  sourceId: '1',
                  sourceGeneration: '1',
                  width: 1,
                  height: 1,
                  bytesPerRow: 4,
                  encodedBytes: [137, 80, 78, 71],
                  decodedPremultipliedRgba8: [1, 2, 3, 4],
                  encodedContentSha256: 'a'.repeat(64),
                  decodedContentSha256: 'b'.repeat(64),
                  originClean: true,
                  usability: 'good',
                  colorSpace: 'srgb',
                  alphaMode: 'premultiplied',
                  orientation: 'top-left',
                },
                flipY: false,
              },
              destination: {
                texture: reference('GPUTexture'),
                mipLevel: 0,
                origin: { x: 0, y: 0, z: 0, iterableLength: null },
                aspect: 'all',
                colorSpace: 'srgb',
                premultipliedAlpha: false,
              },
              copySize: {
                width: 1,
                height: 1,
                depthOrArrayLayers: 1,
                iterableLength: null,
              },
            }
            : route.operationId === 'GPUQueue.submit'
            ? { commandBuffers: [], wrapperValidationError: undefined }
            : route.operationId === 'GPUDevice.createBindGroup'
            ? convertedBindGroupDescriptor()
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
            : route.operationId === 'GPUDevice.createComputePipeline'
            ? convertedComputePipelineDescriptor()
            : route.operationId === 'GPUDevice.createRenderPipeline'
            ? convertedRenderPipelineDescriptor()
            : route.operationId === 'GPUDevice.createSampler'
            ? {
              addressModeU: 'clamp-to-edge',
              addressModeV: 'clamp-to-edge',
              addressModeW: 'clamp-to-edge',
              label: 'sampler',
              lodMaxClamp: 32,
              lodMinClamp: 0,
              magFilter: 'linear',
              maxAnisotropy: 1,
              minFilter: 'linear',
              mipmapFilter: 'nearest',
            }
            : route.operationId === 'GPUDevice.createTexture'
            ? {
              dimension: '2d',
              format: 'rgba8unorm',
              label: 'texture',
              mipLevelCount: 1,
              sampleCount: 1,
              size: { width: 32, height: 32, depthOrArrayLayers: 1 },
              usage: 23,
              viewFormats: [],
            }
            : route.operationId === 'GPUTexture.createView'
            ? convertedTextureViewRequest()
            : route.operationId === 'GPUCanvasContext.configure'
            ? {
              format: 'bgra8unorm',
              usage: 16,
              viewFormats: Object.freeze([]),
              alphaMode: 'opaque',
              colorSpace: 'srgb',
              toneMapping: Object.freeze({ mode: 'standard' }),
            }
            : route.operationId === 'GPUCanvasContext.unconfigure' ||
                route.operationId === 'GPUTexture.destroy'
            ? null
            : route.operationId === 'GPUDevice.createCommandEncoder'
            ? { label: 'encoder' }
            : route.operationId === 'GPUDevice.createShaderModule'
            ? { label: 'shader', code: '@vertex fn main() {}' }
            : { sample: true },
        });
      }
    }
  });

  test('encodes closed canvas lifecycle authority and rejects retargeting, stale shapes, and malformed bytes', () => {
    const configureInput = serviceInput('GPUCanvasContext.configure');
    const configurePayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(configureInput) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      configurePayload,
    )).toMatchObject({
      operationId: 'GPUCanvasContext.configure',
      codec: 'gpu-canvas-configure-service-request-v1',
      receiver: reference('GPUCanvasContext'),
      target: null,
      adapterOrdinal: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '0',
      sealedLocalTimeline: [],
      convertedArguments: {
        format: 'bgra8unorm',
        usage: 16,
        viewFormats: [],
        alphaMode: 'opaque',
        colorSpace: 'srgb',
        toneMapping: { mode: 'standard' },
      },
      canvasService: canvasConfigureServiceBody(),
    });

    const unconfigureInput = serviceInput('GPUCanvasContext.unconfigure');
    const unconfigurePayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(unconfigureInput) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      unconfigurePayload,
    )).toMatchObject({
      operationId: 'GPUCanvasContext.unconfigure',
      codec: 'gpu-canvas-unconfigure-service-request-v1',
      convertedArguments: null,
      canvasService: canvasUnconfigureServiceBody(),
    });

    const expiredDestroyInput = Object.freeze({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: textureDestroyServiceBody(
        'first-expired-cleanup',
        'canvas-current',
      ),
    });
    const expiredDestroyPayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(expiredDestroyInput) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      expiredDestroyPayload,
    )).toMatchObject({
      operationId: 'GPUTexture.destroy',
      codec: 'gpu-texture-cleanup-service-request-v1',
      convertedArguments: null,
      canvasService: expiredDestroyInput.canvasService,
    });

    const hostTaskExpiryInput = Object.freeze({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: textureExpireServiceBody(),
    });
    const hostTaskExpiryPayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(hostTaskExpiryInput) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      hostTaskExpiryPayload,
    )).toMatchObject({
      operationId: 'GPUTexture.destroy',
      codec: 'gpu-texture-cleanup-service-request-v1',
      convertedArguments: null,
      canvasService: {
        kind: 'texture-expire-v1',
        expiryIntent: 'host-task-expiry',
        materializationState: 'materialized',
        origin: { kind: 'canvas-current-v1' },
      },
    });

    for (const terminalIntent of [
      'first-cleanup',
      'repeat-cleanup-noop',
    ] as const) {
      const input = Object.freeze({
        ...serviceInput('GPUTexture.destroy'),
        canvasService: textureDestroyServiceBody(terminalIntent),
      });
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input) as Uint8Array,
      )).toMatchObject({
        canvasService: {
          kind: 'texture-destroy-v1',
          terminalIntent,
          materializationState: 'unmaterialized',
          origin: { kind: 'device-created-v1' },
        },
      });
    }

    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUCanvasContext.configure',
      { kind: 'canvas-terminal', terminal: 'operation-success' },
    ).byteLength).toBe(0);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUCanvasContext.unconfigure',
      { kind: 'canvas-terminal', terminal: 'first-cleanup-provider' },
    ).byteLength).toBe(0);
    for (const terminal of [
      'repeat-cleanup-noop',
      'first-cleanup-provider',
    ] as const) {
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        'GPUTexture.destroy',
        { kind: 'canvas-terminal', terminal },
      ).byteLength).toBe(0);
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUCanvasContext.configure',
      { kind: 'canvas-terminal', terminal: 'repeat-cleanup-noop' },
    )).toThrow('canvas terminal is invalid');

    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: undefined,
    })).toThrow('wrapper authority is missing');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      sealedLocalTimeline: [{ injected: true }],
    })).toThrow('canvas carrier projection');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: {
        ...canvasConfigureServiceBody(),
        receiverContextRef: {
          ...reference('GPUCanvasContext'),
          objectId: '12',
        },
      },
    })).toThrow('retargeted');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: {
        ...canvasConfigureServiceBody(),
        configuredDeviceRef: {
          ...reference('GPUDevice'),
          logicalDeviceId: '18',
        },
      },
    })).toThrow('retargeted');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: {
        ...canvasConfigureServiceBody(),
        configurationGeneration: '0',
      },
    })).toThrow('must be a positive identity');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: {
        ...canvasConfigureServiceBody(),
        alphaMode: 'discard',
      } as never,
    })).toThrow('disagrees with converted configuration');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: {
        ...canvasConfigureServiceBody(),
        viewFormats: ['rgba8unorm'],
      },
    })).toThrow('disagrees with converted configuration');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      convertedArguments: {
        ...(configureInput.convertedArguments as Record<string, unknown>),
        toneMapping: { mode: 'extended' },
      },
      canvasService: {
        ...canvasConfigureServiceBody(),
        toneMappingMode: 'extended',
      } as never,
    })).toThrow('must be standard');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...configureInput,
      canvasService: {
        ...canvasConfigureServiceBody(),
        unexpected: true,
      } as never,
    })).toThrow('closed lifecycle body');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...unconfigureInput,
      canvasService: {
        ...canvasUnconfigureServiceBody(),
        terminalIntent: 'repeat-cleanup-noop',
      } as never,
    })).toThrow('retargeted');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: textureDestroyServiceBody(
        'first-expired-cleanup',
        'device-created',
      ),
    })).toThrow('cannot carry canvas expiry');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: {
        ...textureExpireServiceBody(),
        origin: { kind: 'device-created-v1' },
      } as never,
    })).toThrow('requires a canvas-current origin');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: {
        ...textureExpireServiceBody(),
        terminalIntent: 'first-expired-cleanup',
      } as never,
    })).toThrow('closed lifecycle body');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: {
        ...textureExpireServiceBody(),
        expiryIntent: 'manual-destroy',
      } as never,
    })).toThrow('invalid intent');
    const canvasDestroyBody = textureDestroyServiceBody(
      'first-expired-cleanup',
      'canvas-current',
    );
    if (
      canvasDestroyBody.kind !== 'texture-destroy-v1' ||
      canvasDestroyBody.origin.kind !== 'canvas-current-v1'
    ) {
      throw new Error('invalid canvas destroy fixture');
    }
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: {
        ...canvasDestroyBody,
        origin: {
          ...canvasDestroyBody.origin,
          contextRef: {
            ...canvasDestroyBody.origin.contextRef,
            providerGeneration: '8',
          },
        },
      },
    })).toThrow('foreign device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUTexture.destroy'),
      canvasService: {
        ...canvasDestroyBody,
        origin: {
          ...canvasDestroyBody.origin,
          textureOriginDigest: 'A'.repeat(64),
        },
      },
    })).toThrow('lowercase SHA-256 digest');

    const textureBodyTagOffset = 12 + 41 + 1 + 32 + 5 + 41;
    expect(Array.from(expiredDestroyPayload.slice(
      textureBodyTagOffset,
      textureBodyTagOffset + 3,
    ))).toEqual([2, 1, 2]);
    expect(Array.from(hostTaskExpiryPayload.slice(
      textureBodyTagOffset,
      textureBodyTagOffset + 3,
    ))).toEqual([3, 1, 2]);
    for (const offset of [
      textureBodyTagOffset,
      textureBodyTagOffset + 1,
      textureBodyTagOffset + 2,
    ]) {
      const unknownTag = expiredDestroyPayload.slice();
      unknownTag[offset] = 0xff;
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        unknownTag,
      )).toThrow('body tag is unknown');
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      expiredDestroyPayload.slice(0, -1),
    )).toThrow();
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      withTrailingByte(expiredDestroyPayload),
    )).toThrow('Trailing bytes');

    const configureAlphaModeOffset = 12 + 41 + 1 + 32 + 5 + 41 + 24 +
      41 + 4 + 'bgra8unorm'.length + 4 + 4;
    expect(Array.from(configurePayload.slice(
      configureAlphaModeOffset,
      configureAlphaModeOffset + 3,
    ))).toEqual([1, 1, 1]);
    for (const offset of [
      configureAlphaModeOffset,
      configureAlphaModeOffset + 1,
      configureAlphaModeOffset + 2,
    ]) {
      const unknownConfigureEnum = configurePayload.slice();
      unknownConfigureEnum[offset] = 0xff;
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        unknownConfigureEnum,
      )).toThrow('enum tag is unknown');
    }
  });

  test('request encoding is canonical and rejects unknown tags, trailing bytes, and bounds', () => {
    const input = serviceInput(
      'GPUDevice.createRenderPipeline',
      convertedRenderPipelineDescriptor(Object.freeze({ z: 1, a: 2 })),
    );
    const first = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input);
    const second = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(input);
    expect([...new Uint8Array(first as Uint8Array)]).toEqual([
      ...new Uint8Array(second as Uint8Array),
    ]);
    const bytes = first as Uint8Array;
    const utf8Ordered = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput(
        'GPUDevice.createRenderPipeline',
        convertedRenderPipelineDescriptor(Object.freeze({
          '\u{10000}': 1,
          '\ue000': 2,
        })),
      ),
    );
    const inspectedUtf8Order = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(utf8Ordered as Uint8Array) as {
        convertedArguments: Record<string, unknown>;
      };
    expect(Object.keys(
      (inspectedUtf8Order.convertedArguments.vertex as {
        constants: Record<string, number>;
      }).constants,
    )).toEqual([
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
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeCanonicalValue(
      Array.from({ length: 1025 }, () => null),
    )).toThrow('reviewed count bound');
    const tooManyFields: Record<string, number> = {};
    for (let index = 0; index < 129; index += 1) tooManyFields[`k${index}`] = index;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeCanonicalValue(
      tooManyFields,
    )).toThrow('reviewed field bound');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeCanonicalValue(
      cyclic,
    )).toThrow('contains a cycle');
    const nested: Record<string, unknown> = {};
    let cursor = nested;
    for (let depth = 0; depth < 18; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeCanonicalValue(
      nested,
    )).toThrow('reviewed nesting bound');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeCanonicalValue(
      '\ud800',
    )).toThrow('not well-formed UTF-16');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...serviceInput('GPUDevice.createCommandEncoder'),
      capturedScopeId: '18446744073709551616',
    })).toThrow('exceeds the binary range');
  });

  test('executes the authenticated private compute-pipeline request and empty result codecs', () => {
    const operationId = 'GPUDevice.createComputePipeline';
    const route = WEBGPU_PRODUCTION_PLAN.routes.find(
      (candidate) => candidate.operationId === operationId,
    )!;
    const requestCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (candidate) => candidate.tag === route.serviceArgumentCodec,
    )!;
    const nativeRoute = WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes
      .find((candidate) => candidate.operationId === operationId)!;
    expect(requestCodec).toMatchObject({
      tag: 'gpu-create-compute-pipeline-service-request-v1',
      wireTag: 25,
      nativeProgramPrerequisitesRepresented: true,
      executableFromCurrentAuthenticatedInputs: true,
      unavailableSemanticFields: [],
    });
    expect(nativeRoute).toMatchObject({
      operationId,
      wireId: 797909431,
      request: {
        catalog: {
          tag: 'gpu-create-compute-pipeline-service-request-v1',
          wireTag: 25,
        },
      },
    });
    expect(nativeRoute.request.payload.fields[0]).toMatchObject({
      name: 'header',
      constants: { codecTag: 25, operationWireId: 797909431 },
    });
    expect(nativeRoute.request.payload.fields.at(-1)).toMatchObject({
      name: 'convertedArguments',
      constraintType: 'computePipelineDescriptorV1',
    });
    expect(nativeRoute.request.semanticServiceBoundary.requiredAfterDecode)
      .toHaveLength(19);

    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        operationId,
        [{
          label: 'compute-present',
          layout: 'auto',
          compute: {
            constants: { zeta: 2, alpha: 1 },
            entryPoint: 'main',
            module: shaderModule,
          },
        }],
        wrappers,
      ) as Readonly<Record<string, unknown>>;
    const input = serviceInput(operationId, converted);
    const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input) as Uint8Array;
    const header = new DataView(
      payload.buffer,
      payload.byteOffset,
      payload.byteLength,
    );
    expect(header.getUint16(6, true)).toBe(25);
    expect(header.getUint32(8, true)).toBe(797909431);
    expect(Array.from(payload.slice(53, 55))).toEqual([
      1,
      WEBGPU_OBJECT_KIND_TAGS.GPUComputePipeline,
    ]);
    const inspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    ) as Readonly<Record<string, unknown>>;
    expect(inspected).toMatchObject({
      operationId,
      codec: 'gpu-create-compute-pipeline-service-request-v1',
      receiver: { kind: 'GPUDevice' },
      target: { kind: 'GPUComputePipeline' },
      convertedArguments: {
        label: 'compute-present',
        layout: 'auto',
        compute: {
          constants: { alpha: 1, zeta: 2 },
          entryPoint: 'main',
          module: { kind: 'GPUShaderModule' },
        },
      },
    });
    const inspectedCompute = (
      inspected.convertedArguments as Readonly<Record<string, unknown>>
    ).compute as Readonly<Record<string, unknown>>;
    expect(Object.hasOwn(inspectedCompute, 'constants')).toBe(true);
    expect(Object.hasOwn(inspectedCompute, 'entryPoint')).toBe(true);

    const omittedInput = serviceInput(
      operationId,
      convertedComputePipelineDescriptor(),
    );
    const omittedInspected = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
          omittedInput,
        ) as Uint8Array,
      ) as Readonly<Record<string, unknown>>;
    const omittedCompute = (
      omittedInspected.convertedArguments as Readonly<Record<string, unknown>>
    ).compute as Readonly<Record<string, unknown>>;
    expect(omittedCompute.constants).toEqual({});
    expect(Object.hasOwn(omittedCompute, 'entryPoint')).toBe(false);

    for (const invalid of [
      {
        ...convertedComputePipelineDescriptor(),
        compute: { module: reference('GPUShaderModule') },
      },
      {
        ...convertedComputePipelineDescriptor(),
        compute: { constants: {}, module: undefined },
      },
      {
        ...convertedComputePipelineDescriptor(),
        compute: {
          constants: { invalid: Number.POSITIVE_INFINITY },
          module: reference('GPUShaderModule'),
        },
      },
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(serviceInput(operationId, invalid)))
        .toThrow(TypeError);
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...omittedInput,
        target: reference('GPURenderPipeline'),
      })).toThrow('authenticated device provenance');

    const semanticBoundary = structuredClone(
      convertedComputePipelineDescriptor(),
    ) as Record<string, unknown>;
    (semanticBoundary.layout as Record<string, unknown>).logicalDeviceId = '18';
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput(operationId, semanticBoundary)))
      .not.toThrow();

    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      operationId,
      { kind: 'none' },
    )).toHaveLength(0);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      operationId,
      { kind: 'null' },
    )).toThrow('wrong shape');
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

  test('converts createBindGroup in inherited Web IDL order and preserves optional size presence', () => {
    const reads: string[] = [];
    const property = (target: object, name: string, value: unknown) => {
      Object.defineProperty(target, name, {
        enumerable: true,
        get() {
          reads.push(name);
          return value;
        },
      });
    };
    const binding: Record<string, unknown> = {};
    property(binding, 'buffer', gpuBuffer);
    property(binding, 'offset', 4);
    property(binding, 'size', 64);
    const entry: Record<string, unknown> = {};
    property(entry, 'binding', 0);
    property(entry, 'resource', binding);
    const descriptor: Record<string, unknown> = {};
    property(descriptor, 'label', 'ordered');
    property(descriptor, 'entries', [entry]);
    property(descriptor, 'layout', bindGroupLayout);
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroup',
      [descriptor],
      wrappers,
    );
    expect(reads).toEqual([
      'label',
      'entries',
      'binding',
      'resource',
      'buffer',
      'offset',
      'size',
      'layout',
    ]);
    expect(converted).toEqual({
      label: 'ordered',
      entries: [{
        binding: 0,
        resource: {
          resourceKind: 'GPUBufferBinding',
          buffer: reference('GPUBuffer'),
          offset: 4,
          size: 64,
        },
      }],
      layout: reference('GPUBindGroupLayout'),
    });

    const zeroSizeConverted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments('GPUDevice.createBindGroup', [{
        label: 'zero-size-is-structural',
        entries: [{
          binding: 0,
          resource: { buffer: gpuBuffer, offset: 0, size: 0 },
        }],
        layout: bindGroupLayout,
      }], wrappers);
    expect(zeroSizeConverted).toMatchObject({
      entries: [{ resource: { offset: 0, size: 0 } }],
    });
    const zeroSizeBytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(
        serviceInput('GPUDevice.createBindGroup', zeroSizeConverted),
      );
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(zeroSizeBytes))
      .toMatchObject({ convertedArguments: zeroSizeConverted });
  });

  test('stops createBindGroup conversion before later getters, allocation, ingress, or provider work', () => {
    let layoutReads = 0;
    let targetAllocations = 0;
    let ingressCalls = 0;
    let providerCalls = 0;
    const entry = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(entry, 'binding', { get: () => 0 });
    Object.defineProperty(entry, 'resource', {
      get() {
        throw new TypeError('early resource conversion failure');
      },
    });
    const descriptor = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(descriptor, 'label', { get: () => 'early' });
    Object.defineProperty(descriptor, 'entries', { get: () => [entry] });
    Object.defineProperty(descriptor, 'layout', {
      get() {
        layoutReads += 1;
        return bindGroupLayout;
      },
    });
    const convertThenContinue = () => {
      const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
        .convertPublicArguments('GPUDevice.createBindGroup', [descriptor], wrappers);
      targetAllocations += 1;
      ingressCalls += 1;
      providerCalls += 1;
      return converted;
    };
    expect(convertThenContinue).toThrow('early resource conversion failure');
    expect({ layoutReads, targetAllocations, ingressCalls, providerCalls }).toEqual({
      layoutReads: 0,
      targetAllocations: 0,
      ingressCalls: 0,
      providerCalls: 0,
    });
  });

  test('keeps createBindGroup structural transport broad before the exact 18-witness predicate', () => {
    const descriptor = Object.freeze({
      label: 'x'.repeat(58),
      entries: Object.freeze([
        ...Array.from({ length: 5 }, (_, binding) => Object.freeze({
          binding,
          resource: Object.freeze({
            buffer: gpuBuffer,
            offset: 0,
          }),
        })),
        Object.freeze({
          binding: 5,
          resource: externalTexture,
        }),
      ]),
      layout: bindGroupLayout,
    });
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      'GPUDevice.createBindGroup',
      [descriptor],
      wrappers,
    );
    expect(converted).toMatchObject({ label: 'x'.repeat(58) });
    expect(Array.isArray((converted as { entries?: unknown }).entries)).toBe(true);
    expect((converted as { entries: readonly unknown[] }).entries.length).toBe(6);
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.layout.sequenceMaxCount).toBe(1024);
    expect((converted as { entries: readonly unknown[] }).entries.at(-1)).toEqual({
      binding: 5,
      resource: {
        resourceKind: 'GPUExternalTexture',
        reference: reference('GPUExternalTexture'),
      },
    });
    const bytes = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeNativeCodegenRequest(
      serviceInput('GPUDevice.createBindGroup', converted),
    );
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(bytes))
      .toMatchObject({ convertedArguments: converted });
    const wrongTargetKind = bytes.slice();
    wrongTargetKind[54] = 5;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(wrongTargetKind))
      .toThrow('authenticated device provenance');
    for (const identityOffset of [13, 21, 29, 37, 45, 55, 63, 71, 79, 87]) {
      const zeroIdentity = bytes.slice();
      zeroIdentity.fill(0, identityOffset, identityOffset + 8);
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .inspectServiceRequest(zeroIdentity)).toThrow();
    }
    const foreignTargetDevice = bytes.slice();
    foreignTargetDevice[71] ^= 1;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .inspectServiceRequest(foreignTargetDevice))
      .toThrow('authenticated device provenance');
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.typeGpuBindGroupWorkloadEvidence)
      .toMatchObject({
        callCount: 18,
        entryCount: 47,
        maximumEntriesPerDescriptor: 5,
        maximumLabelUtf8Bytes: 57,
      });
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
    expect(nativeRoute.wireId).toBe(1869756926);
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
          return {
            valueOf() {
              laterGetCount += 1;
              return 9;
            },
          };
        },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [overCeiling],
      wrappers,
    )).toThrow('structural ceiling');
    expect(laterGetCount).toBe(2);
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
    ).getUint32(8, true)).toBe(1869756926);
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

  test('converts createSampler in exact inherited dictionary order with pinned defaults and vocabularies', () => {
    const operationId = 'GPUDevice.createSampler';
    const effects: string[] = [];
    const counts = new Map<string, number>();
    const enumToken = (name: string, value: string) => ({
      toString() {
        effects.push(`convert-${name}`);
        return value;
      },
    });
    const numberToken = (name: string, value: number) => ({
      [Symbol.toPrimitive]() {
        effects.push(`convert-${name}`);
        return value;
      },
    });
    const values: Readonly<Record<string, unknown>> = {
      addressModeU: enumToken('addressModeU', 'repeat'),
      addressModeV: enumToken('addressModeV', 'mirror-repeat'),
      addressModeW: enumToken('addressModeW', 'clamp-to-edge'),
      compare: enumToken('compare', 'less-equal'),
      label: enumToken('label', 'ordered-sampler'),
      lodMaxClamp: numberToken('lodMaxClamp', 12.25),
      lodMinClamp: numberToken('lodMinClamp', 1.5),
      magFilter: enumToken('magFilter', 'linear'),
      maxAnisotropy: numberToken('maxAnisotropy', 2.5),
      minFilter: enumToken('minFilter', 'linear'),
      mipmapFilter: enumToken('mipmapFilter', 'linear'),
    };
    const descriptor = Object.create(null) as Record<string, unknown>;
    for (const name of Object.keys(values)) {
      Object.defineProperty(descriptor, name, {
        enumerable: true,
        get() {
          counts.set(name, (counts.get(name) ?? 0) + 1);
          effects.push(`get-${name}`);
          return values[name];
        },
      });
    }
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [descriptor],
      wrappers,
    )).toEqual({
      addressModeU: 'repeat',
      addressModeV: 'mirror-repeat',
      addressModeW: 'clamp-to-edge',
      compare: 'less-equal',
      label: 'ordered-sampler',
      lodMaxClamp: 12.25,
      lodMinClamp: 1.5,
      magFilter: 'linear',
      maxAnisotropy: 2,
      minFilter: 'linear',
      mipmapFilter: 'linear',
    });
    expect([...counts.values()]).toEqual(Array(11).fill(1));
    expect(effects).toEqual([
      'get-addressModeU', 'convert-addressModeU',
      'get-addressModeV', 'convert-addressModeV',
      'get-addressModeW', 'convert-addressModeW',
      'get-compare', 'convert-compare',
      'get-label', 'convert-label',
      'get-lodMaxClamp', 'convert-lodMaxClamp',
      'get-lodMinClamp', 'convert-lodMinClamp',
      'get-magFilter', 'convert-magFilter',
      'get-maxAnisotropy', 'convert-maxAnisotropy',
      'get-minFilter', 'convert-minFilter',
      'get-mipmapFilter', 'convert-mipmapFilter',
    ]);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [undefined],
      wrappers,
    )).toEqual({
      addressModeU: 'clamp-to-edge',
      addressModeV: 'clamp-to-edge',
      addressModeW: 'clamp-to-edge',
      label: '',
      lodMaxClamp: 32,
      lodMinClamp: 0,
      magFilter: 'nearest',
      maxAnisotropy: 1,
      minFilter: 'nearest',
      mipmapFilter: 'nearest',
    });
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{ maxAnisotropy: Number.POSITIVE_INFINITY }],
      wrappers,
    )).toMatchObject({ maxAnisotropy: 0xffff });

    let laterReads = 0;
    const invalidMagFilter = Object.defineProperties({}, {
      magFilter: { get: () => 'cubic' },
      maxAnisotropy: {
        get() {
          laterReads += 1;
          return 1;
        },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [invalidMagFilter],
      wrappers,
    )).toThrow('magFilter is not a supported enum value');
    expect(laterReads).toBe(0);
    for (const invalidDescriptor of [
      { addressModeU: 'border' },
      { compare: 'approximately-equal' },
      { lodMaxClamp: Number.NaN },
      { lodMinClamp: 4e38 },
      { mipmapFilter: 'cubic' },
      { maxAnisotropy: 1n },
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        operationId,
        [invalidDescriptor],
        wrappers,
      )).toThrow(TypeError);
    }

    expect(wrappers.reference(sampler, 'GPUSampler')).toMatchObject({
      kind: 'GPUSampler',
      logicalDeviceId: '17',
    });
    const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput(operationId),
    );
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(payload))
      .toMatchObject({
        operationId,
        codec: 'gpu-create-sampler-service-request-v1',
        receiver: { kind: 'GPUDevice', logicalDeviceId: '17' },
        target: { kind: 'GPUSampler', logicalDeviceId: '17' },
      });
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.some(
      (route) => route.operationId === operationId,
    )).toBe(true);
  });

  test('converts createTexture in exact descriptor and extent order with one-shot iterables', () => {
    const operationId = 'GPUDevice.createTexture';
    const effects: string[] = [];
    const enumToken = (name: string, value: string) => ({
      toString() {
        effects.push(`convert-${name}`);
        return value;
      },
    });
    const numberToken = (name: string, value: number) => ({
      [Symbol.toPrimitive]() {
        effects.push(`convert-${name}`);
        return value;
      },
    });
    const extent = Object.create(null) as Record<string, unknown>;
    for (const [name, value] of [
      ['depthOrArrayLayers', 1],
      ['height', 128],
      ['width', 256],
    ] as const) {
      Object.defineProperty(extent, name, {
        get() {
          effects.push(`get-size.${name}`);
          return numberToken(`size.${name}`, value);
        },
      });
    }
    let viewFormatIteratorGets = 0;
    let viewFormatIteratorCalls = 0;
    const viewFormats = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(viewFormats, Symbol.iterator, {
      get() {
        viewFormatIteratorGets += 1;
        effects.push('get-viewFormats.@@iterator');
        return function () {
          viewFormatIteratorCalls += 1;
          effects.push('call-viewFormats.@@iterator');
          let done = false;
          return {
            next() {
              if (done) return { done: true };
              done = true;
              return {
                done: false,
                value: enumToken('viewFormats[0]', 'rgba8unorm'),
              };
            },
          };
        };
      },
    });
    const values: Readonly<Record<string, unknown>> = {
      dimension: enumToken('dimension', '2d'),
      format: enumToken('format', 'rgba16float'),
      label: enumToken('label', 'ordered-texture'),
      mipLevelCount: numberToken('mipLevelCount', 1.9),
      sampleCount: numberToken('sampleCount', 1.9),
      size: extent,
      textureBindingViewDimension: enumToken('textureBindingViewDimension', '2d-array'),
      usage: numberToken('usage', 31.9),
      viewFormats,
    };
    const descriptor = Object.create(null) as Record<string, unknown>;
    for (const name of Object.keys(values)) {
      Object.defineProperty(descriptor, name, {
        get() {
          effects.push(`get-${name}`);
          return values[name];
        },
      });
    }
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [descriptor],
      wrappers,
    )).toEqual({
      dimension: '2d',
      format: 'rgba16float',
      label: 'ordered-texture',
      mipLevelCount: 1,
      sampleCount: 1,
      size: { width: 256, height: 128, depthOrArrayLayers: 1 },
      textureBindingViewDimension: '2d-array',
      usage: 31,
      viewFormats: ['rgba8unorm'],
    });
    expect(viewFormatIteratorGets).toBe(1);
    expect(viewFormatIteratorCalls).toBe(1);
    expect(effects).toEqual([
      'get-dimension', 'convert-dimension',
      'get-format', 'convert-format',
      'get-label', 'convert-label',
      'get-mipLevelCount', 'convert-mipLevelCount',
      'get-sampleCount', 'convert-sampleCount',
      'get-size',
      'get-size.depthOrArrayLayers', 'convert-size.depthOrArrayLayers',
      'get-size.height', 'convert-size.height',
      'get-size.width', 'convert-size.width',
      'get-textureBindingViewDimension', 'convert-textureBindingViewDimension',
      'get-usage', 'convert-usage',
      'get-viewFormats',
      'get-viewFormats.@@iterator', 'call-viewFormats.@@iterator',
      'convert-viewFormats[0]',
    ]);

    let extentIteratorGets = 0;
    const iterableExtent = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(iterableExtent, Symbol.iterator, {
      get() {
        extentIteratorGets += 1;
        return function* () {
          yield 64;
          yield 32;
        };
      },
    });
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{ format: 'rgba8unorm', size: iterableExtent, usage: 23 }],
      wrappers,
    )).toMatchObject({
      dimension: '2d',
      label: '',
      mipLevelCount: 1,
      sampleCount: 1,
      size: { width: 64, height: 32, depthOrArrayLayers: 1 },
      viewFormats: [],
    });
    expect(extentIteratorGets).toBe(1);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{
        format: 'rgba8unorm',
        size: { [Symbol.iterator]: null, width: 8 },
        usage: 17,
      }],
      wrappers,
    )).toMatchObject({ size: { width: 8, height: 1, depthOrArrayLayers: 1 } });

    let postFormatReads = 0;
    const missingFormat = Object.defineProperty({}, 'label', {
      get() {
        postFormatReads += 1;
        return 'never';
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [missingFormat],
      wrappers,
    )).toThrow('format is required');
    expect(postFormatReads).toBe(0);
    let postSizeReads = 0;
    const missingExtentWidth = Object.defineProperties({}, {
      format: { get: () => 'rgba8unorm' },
      size: { get: () => ({ height: 2 }) },
      usage: {
        get() {
          postSizeReads += 1;
          return 17;
        },
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [missingExtentWidth],
      wrappers,
    )).toThrow('size.width is required');
    expect(postSizeReads).toBe(0);

    let iteratorClosed = 0;
    const invalidViewFormats = {
      [Symbol.iterator]() {
        let done = false;
        return {
          next() {
            if (done) return { done: true };
            done = true;
            return { done: false, value: 'not-a-format' };
          },
          return() {
            iteratorClosed += 1;
            return { done: true };
          },
        };
      },
    };
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
      operationId,
      [{ format: 'rgba8unorm', size: [1], usage: 17, viewFormats: invalidViewFormats }],
      wrappers,
    )).toThrow('viewFormats member is not a supported enum value');
    expect(iteratorClosed).toBe(1);
    for (const invalidDescriptor of [
      { dimension: '4d', format: 'rgba8unorm', size: [1], usage: 17 },
      { format: 'not-a-format', size: [1], usage: 17 },
      { format: 'rgba8unorm', size: [], usage: 17 },
      { format: 'rgba8unorm', size: [1, 2, 3, 4], usage: 17 },
      { format: 'rgba8unorm', size: [1], textureBindingViewDimension: '4d', usage: 17 },
      { format: 'rgba8unorm', size: [1n], usage: 17 },
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
        operationId,
        [invalidDescriptor],
        wrappers,
      )).toThrow(TypeError);
    }

    const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      serviceInput(operationId),
    );
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(payload))
      .toMatchObject({
        operationId,
        codec: 'gpu-create-texture-service-request-v1',
        receiver: { kind: 'GPUDevice', logicalDeviceId: '17' },
        target: { kind: 'GPUTexture', logicalDeviceId: '17' },
      });
    expect(WEBGPU_EXECUTABLE_CODEC_MANIFEST.nativeCodecPrograms.routes.some(
      (route) => route.operationId === operationId,
    )).toBe(true);
  });

  test('encodes createView device and canvas origins with closed structural and source-affine joins', () => {
    const operationId = 'GPUTexture.createView';
    const deviceRequest = convertedTextureViewRequest();
    const canvasRequest = convertedTextureViewRequest(
      completeTextureViewCurrentOrigin(),
    );
    for (const request of [deviceRequest, canvasRequest]) {
      const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(serviceInput(operationId, request));
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(payload))
        .toMatchObject({
          operationId,
          codec: 'gpu-create-texture-view-service-request-v1',
          receiver: { kind: 'GPUTexture', logicalDeviceId: '17' },
          target: { kind: 'GPUTextureView', logicalDeviceId: '17' },
          convertedArguments: request,
        });
    }

    const currentOrigin = completeTextureViewCurrentOrigin();
    const {
      textureOriginDigest,
      ...originDigestFacts
    } = currentOrigin;
    const digestInput = Object.freeze({
      receiverTextureRef: reference('GPUTexture'),
      ...originDigestFacts,
    }) as ProductionGpuTextureOriginDigestInput;
    const nodeDigest = createHash('sha256')
      .update(`exact.webgpu.texture-origin.v1\0${canonicalJson(digestInput)}`)
      .digest('hex');
    expect(textureOriginDigest).toBe(nodeDigest);
    expect(WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .deriveTextureOriginDigest(digestInput)).toBe(nodeDigest);
    const {
      textureOriginDigest: _omittedTextureOriginDigest,
      ...missingTextureOriginDigest
    } = currentOrigin;
    const malformedRequests: unknown[] = [
      Object.freeze({ ...deviceRequest, unexpected: true }),
      Object.freeze({
        converted: Object.freeze({
          ...(deviceRequest.converted as Readonly<Record<string, unknown>>),
          unexpected: true,
        }),
      }),
      Object.freeze({
        converted: Object.freeze({
          aspect: 'all',
          baseArrayLayer: 0,
          baseMipLevel: 0,
          swizzle: 'rgba',
          usage: 0,
        }),
      }),
      Object.freeze({
        converted: Object.freeze({
          ...(deviceRequest.converted as Readonly<Record<string, unknown>>),
          swizzle: 'rgbx',
        }),
      }),
      Object.freeze({
        converted: Object.freeze({
          ...(deviceRequest.converted as Readonly<Record<string, unknown>>),
          arrayLayerCount: -1,
        }),
      }),
      Object.freeze({
        ...deviceRequest,
        currentOrigin: undefined,
      }),
      convertedTextureViewRequest(Object.freeze(missingTextureOriginDigest)),
      convertedTextureViewRequest(Object.freeze({
        ...currentOrigin,
        contextRef: reference('GPUDevice'),
      })),
      convertedTextureViewRequest(Object.freeze({
        ...currentOrigin,
        configuredDeviceRef: Object.freeze({
          ...reference('GPUDevice'),
          objectId: '0',
        }),
      })),
      convertedTextureViewRequest(Object.freeze({
        ...currentOrigin,
        textureOriginDigest: 'not-a-digest',
      })),
      convertedTextureViewRequest(Object.freeze({
        ...currentOrigin,
        configurationGeneration: '0',
      })),
    ];
    for (const request of malformedRequests) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
        .encodeNativeCodegenRequest(serviceInput(operationId, request)))
        .toThrow(TypeError);
    }

    const validInput = serviceInput(operationId, canvasRequest);
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(Object.freeze({
        ...validInput,
        receiver: reference('GPUDevice'),
      }))).toThrow('authenticated GPUTexture receiver');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(Object.freeze({
        ...validInput,
        target: Object.freeze({
          ...reference('GPUTextureView'),
          logicalDeviceId: '99',
        }),
      }))).toThrow('source texture device provenance');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(Object.freeze({
        ...validInput,
        sealedLocalTimeline: Array.from({ length: 1_025 }, () => null),
      }))).toThrow('bounded sequence');
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      operationId,
      { kind: 'none' },
    )).toHaveLength(0);
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
      referenceIfBranded(value, kind) {
        return wrappers.referenceIfBranded(value, kind);
      },
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
      referenceIfBranded() {
        return undefined;
      },
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
    expect(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary
        .gpuTextureFormatCapabilityRowsSha256,
    ).toMatch(/^[0-9a-f]{64}$/u);
    expect(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary
        .gpuTextureFormatRequiredFeatures,
    ).toMatchObject({
      rgba8unorm: null,
      r16unorm: 'texture-formats-tier1',
      'bc7-rgba-unorm': 'texture-compression-bc',
      'astc-12x12-unorm-srgb': 'texture-compression-astc',
    });
    expect(
      Object.keys(
        WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary
          .gpuTextureFormatRequiredFeatures,
      ),
    ).toEqual(
      WEBGPU_EXECUTABLE_CODEC_MANIFEST.webIdlVocabulary.gpuTextureFormats,
    );

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

  test('encodes closed source-affine GPUBuffer cleanup and mapAsync request bodies', () => {
    const writeBody = Object.freeze({
      kind: 'cleanup-v1' as const,
      cleanupAction: 2 as const,
      cleanupGeneration: '7',
      cancelledMapGeneration: '6',
      activeMapGeneration: '5',
      activeMapMode: 2 as const,
      mappedOffset: '16',
      mappedSize: '4',
      writeback: Uint8Array.from([1, 2, 3, 4]),
    });
    const destroyInput = Object.freeze({
      ...serviceInput('GPUBuffer.destroy', null),
      bufferLifecycle: writeBody,
    });
    const destroyPayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(destroyInput) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      destroyPayload,
    )).toMatchObject({
      operationId: 'GPUBuffer.destroy',
      codec: 'gpu-buffer-destroy-service-request-v1',
      receiver: {
        kind: 'GPUBuffer',
        objectId: '11',
        objectGeneration: '1',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      target: null,
      adapterOrdinal: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '0',
      sealedLocalTimeline: [],
      convertedArguments: null,
      bufferLifecycle: {
        ...writeBody,
        writeback: [1, 2, 3, 4],
      },
    });
    for (let length = 0; length < destroyPayload.byteLength; length += 1) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        destroyPayload.slice(0, length),
      )).toThrow();
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      withTrailingByte(destroyPayload),
    )).toThrow('Trailing');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      mutateU32(
        destroyPayload,
        131,
        WEBGPU_EXECUTABLE_CODEC_MANIFEST.maxPayloadBytes + 1,
      ),
    )).toThrow('byte bound');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...destroyInput,
      bufferLifecycle: { ...writeBody, activeMapMode: 1 },
    })).toThrow('MAP_READ');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...destroyInput,
      bufferLifecycle: { ...writeBody, mappedSize: '5' },
    })).toThrow('exact mapped extent');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...destroyInput,
      bufferLifecycle: { ...writeBody, unexpected: true } as never,
    })).toThrow('closed lifecycle body');

    const convertedMap = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments('GPUBuffer.mapAsync', [2, 16, 4], wrappers);
    const mapBody = Object.freeze({
      kind: 'map-async-v1' as const,
      pendingMapGeneration: '9',
      mode: 2 as const,
      offset: '16',
      requestedSizePresent: 1 as const,
      requestedSize: '4',
    });
    const mapInput = Object.freeze({
      ...serviceInput('GPUBuffer.mapAsync', convertedMap),
      bufferLifecycle: mapBody,
    });
    const mapPayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(mapInput) as Uint8Array;
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      mapPayload,
    )).toMatchObject({
      operationId: 'GPUBuffer.mapAsync',
      convertedArguments: { mode: 2, offset: 16, size: 4 },
      bufferLifecycle: mapBody,
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...mapInput,
      bufferLifecycle: { ...mapBody, pendingMapGeneration: '0' },
    })).toThrow('positive');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...mapInput,
      bufferLifecycle: { ...mapBody, mode: 1 },
    })).toThrow('disagrees');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest({
      ...mapInput,
      bufferLifecycle: {
        ...mapBody,
        requestedSizePresent: 0,
        requestedSize: '4',
      },
    })).toThrow('mode/range');

    const unmapInput = Object.freeze({
      ...serviceInput('GPUBuffer.unmap', null),
      bufferLifecycle: Object.freeze({
        ...writeBody,
        cleanupAction: 1 as const,
      }),
    });
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(unmapInput),
    )).toMatchObject({
      operationId: 'GPUBuffer.unmap',
      bufferLifecycle: { cleanupAction: 1, cleanupGeneration: '7' },
    });
  });

  test('encodes one affine GPUQueue.writeBuffer snapshot and an empty queue submit', () => {
    const source = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUQueue.writeBuffer',
        [gpuBuffer, 12, source, 4, 4],
        wrappers,
      );
    source.fill(99);
    const input = serviceInput('GPUQueue.writeBuffer', converted);
    const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input) as Uint8Array;
    expect(payload.byteLength).toBe(147);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId: 'GPUQueue.writeBuffer',
      codec: 'gpu-queue-write-buffer-service-request-v1',
      receiver: {
        kind: 'GPUQueue',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      capturedScopeId: '0',
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '2',
      sealedLocalTimeline: [],
      convertedArguments: {
        buffer: {
          kind: 'GPUBuffer',
          logicalDeviceId: '17',
          logicalDeviceGeneration: '1',
          providerGeneration: '7',
        },
        bufferOffset: 12,
        bytes: [5, 6, 7, 8],
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      input,
    )).toThrow('already consumed');

    for (const length of [0, 1, 12, 53, 86, 135, 143, 146]) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        payload.slice(0, length),
      )).toThrow();
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      withTrailingByte(payload),
    )).toThrow('Trailing');
    for (const invalid of [
      mutateU32(payload, 12, WEBGPU_OBJECT_KIND_TAGS.GPUDevice),
      mutateU32(payload, 78, 0),
      mutateU32(payload, 86, WEBGPU_OBJECT_KIND_TAGS.GPUDevice),
      mutateU32(payload, 103, 18),
      mutateU32(payload, 119, 8),
      mutateU32(payload, 131, 0x0020_0000),
      mutateU32(payload, 135, 3),
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        invalid,
      )).toThrow();
    }

    const zeroPayload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(serviceInput(
        'GPUQueue.writeBuffer',
        WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.convertPublicArguments(
          'GPUQueue.writeBuffer',
          [gpuBuffer, 1, new Uint8Array(0)],
          wrappers,
        ),
      ));
    expect(zeroPayload.byteLength).toBe(143);
    for (const terminal of [
      'later-predicate-rejection',
      'operation-success',
    ] as const) {
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        'GPUQueue.writeBuffer',
        { kind: 'queue-write-buffer', terminal },
      ).byteLength).toBe(0);
    }

    const submitCodec = WEBGPU_EXECUTABLE_CODEC_MANIFEST.serviceArguments.find(
      (codec) =>
        codec.tag ===
          'gpu-sealed-command-program-sequence-service-request-v1',
    );
    expect(submitCodec).toMatchObject({
      nativeProgramPrerequisitesRepresented: true,
      executableFromCurrentAuthenticatedInputs: true,
      unavailableSemanticFields: [],
    });
    const submitPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(serviceInput('GPUQueue.submit'));
    expect(submitPayload.slice(0, 12)).toEqual(Uint8Array.from([
      0x49, 0x42, 0x47, 0x51,
      1, 0,
      11, 0,
      7, 0x83, 0x68, 0x12,
    ]));
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      submitPayload,
    )).toMatchObject({
      operationId: 'GPUQueue.submit',
      codec: 'gpu-sealed-command-program-sequence-service-request-v1',
      sealedLocalTimeline: [],
      recordTable: [],
      convertedArguments: {
        commandBuffers: [],
        wrapperValidationError: undefined,
      },
    });

    const currentOrigin = completeTextureViewCurrentOrigin();
    const canvasCurrentRecord = Object.freeze({
      recordIdentityClass: 'active-route',
      operationId: routeWireId('GPUCanvasContext.getCurrentTexture'),
      operationName: 'GPUCanvasContext.getCurrentTexture',
      operationIdentitySha256: null,
      operationInstanceId: '13',
      deviceIngressOrdinal: '17',
      capturedScopeId: '0',
      receiverRef: reference('GPUCanvasContext'),
      commandEncoderRef: null,
      passRef: null,
      wrapperAllocatedTargetRef: reference('GPUTexture'),
      argumentBody: Object.freeze({ currentOrigin }),
      logicalError: null,
    });
    const canvasSubmitInput = Object.freeze({
      ...serviceInput('GPUQueue.submit'),
      deviceIngressOrdinal: '18',
      sealedLocalTimeline: Object.freeze([canvasCurrentRecord]),
    });
    const canvasSubmitPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest(canvasSubmitInput);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      canvasSubmitPayload,
    )).toMatchObject({
      operationId: 'GPUQueue.submit',
      sealedLocalTimeline: [{
        operationName: 'GPUCanvasContext.getCurrentTexture',
        wrapperAllocatedTargetRef: reference('GPUTexture'),
        argumentBody: { currentOrigin },
      }],
    });
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...canvasSubmitInput,
        sealedLocalTimeline: [{
          ...canvasCurrentRecord,
          argumentBody: {
            currentOrigin: {
              ...currentOrigin,
              contextRef: {
                ...currentOrigin.contextRef,
                objectId: '99',
              },
            },
          },
        }],
      })).toThrow('source-affine record');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeNativeCodegenRequest({
        ...canvasSubmitInput,
        sealedLocalTimeline: [{
          ...canvasCurrentRecord,
          wrapperAllocatedTargetRef: {
            ...reference('GPUTexture'),
            objectId: '99',
          },
        }],
      })).toThrow('digest does not bind');
  });

  test('encodes one affine GPUQueue.writeTexture snapshot with closed shape tags', () => {
    const source = Uint8Array.from([1, 2, 3, 4]);
    const converted = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .convertPublicArguments(
        'GPUQueue.writeTexture',
        [
          {
            texture,
            mipLevel: 2,
            origin: [3, 4, 5],
            aspect: 'depth-only',
          },
          source,
          { offset: 1, bytesPerRow: 256, rowsPerImage: 2 },
          [1, 1, 1],
        ],
        wrappers,
      );
    source.fill(99);
    const input = serviceInput('GPUQueue.writeTexture', converted);
    const payload = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION
      .encodeServiceRequest(input) as Uint8Array;
    expect(payload.byteLength).toBe(196);
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      payload,
    )).toMatchObject({
      operationId: 'GPUQueue.writeTexture',
      codec: 'gpu-queue-write-texture-service-request-v1',
      receiver: {
        kind: 'GPUQueue',
        logicalDeviceId: '17',
        logicalDeviceGeneration: '1',
        providerGeneration: '7',
      },
      deviceIngressOrdinal: '3',
      queueIngressOrdinal: '2',
      sealedLocalTimeline: [],
      convertedArguments: {
        destination: {
          texture: {
            kind: 'GPUTexture',
            logicalDeviceId: '17',
            logicalDeviceGeneration: '1',
            providerGeneration: '7',
          },
          mipLevel: 2,
          origin: { x: 3, y: 4, z: 5, iterableLength: 3 },
          aspect: 'depth-only',
        },
        dataLayout: { offset: '1', bytesPerRow: 256, rowsPerImage: 2 },
        size: {
          width: 1,
          height: 1,
          depthOrArrayLayers: 1,
          iterableLength: 3,
        },
        bytes: [1, 2, 3, 4],
      },
    });
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.encodeServiceRequest(
      input,
    )).toThrow('already consumed');

    for (const invalid of [
      mutateU32(payload, 86, WEBGPU_OBJECT_KIND_TAGS.GPUDevice),
      mutateU32(payload, 143, 2),
      mutateU32(payload, 148, 3),
      mutateU32(payload, 153, 0x0020_0000),
      mutateU32(payload, 184, 16_777_025),
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
        invalid,
      )).toThrow();
    }
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      mutateU32(payload, 103, 18),
    )).toMatchObject({
      convertedArguments: {
        destination: { texture: { logicalDeviceId: '18' } },
      },
    });
    expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      mutateU32(payload, 119, 8),
    )).toMatchObject({
      convertedArguments: {
        destination: { texture: { providerGeneration: '8' } },
      },
    });
    const absentWithValue = payload.slice();
    absentWithValue[157] = 0;
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      absentWithValue,
    )).toThrow('optional layout');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.inspectServiceRequest(
      withTrailingByte(payload),
    )).toThrow('Trailing');
    for (const terminal of [
      'later-predicate-rejection',
      'operation-success',
    ] as const) {
      expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        'GPUQueue.writeTexture',
        { kind: 'queue-write-texture', terminal },
      ).byteLength).toBe(0);
    }
  });

  test('encodes all typed mapAsync completions and rejects carrier, variant, extent, truncation, and trailing-byte drift', () => {
    const variants = [
      {
        variant: 'mapped-bytes' as const,
        pendingMapGeneration: '8',
        mode: 1 as const,
        offset: '0',
        size: '4',
        ownedBytes: Uint8Array.from([9, 10, 11, 12]),
      },
      ...[
        'provider-operation-error',
        'allocation-range-error',
        'late-cancelled-cleanup',
      ].map((variant) => ({
        variant: variant as
          | 'provider-operation-error'
          | 'allocation-range-error'
          | 'late-cancelled-cleanup',
        pendingMapGeneration: '9',
        mode: 2 as const,
        offset: '16',
        size: '4',
        ownedBytes: new Uint8Array(0),
      })),
    ];
    const payloads = variants.map((variant) => {
      const payload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
        'GPUBuffer.mapAsync',
        { kind: 'buffer-map', ...variant },
      );
      const decoded = WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
        'GPUBuffer.mapAsync',
        bufferMapResultEvent(payload),
      );
      expect(decoded).toMatchObject({
        kind: 'value',
        value: {
          variant: variant.variant,
          pendingMapGeneration: variant.pendingMapGeneration,
          mode: variant.mode,
          offset: variant.offset,
          size: variant.size,
        },
      });
      return payload;
    });
    const mappedPayload = payloads[0]!;
    for (let length = 0; length < mappedPayload.byteLength; length += 1) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
        'GPUBuffer.mapAsync',
        bufferMapResultEvent(mappedPayload.slice(0, length)),
      )).toThrow();
    }
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUBuffer.mapAsync',
      bufferMapResultEvent(withTrailingByte(mappedPayload)),
    )).toThrow('Trailing');
    const unknownVariant = mappedPayload.slice();
    unknownVariant[12] = 0;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUBuffer.mapAsync',
      bufferMapResultEvent(unknownVariant),
    )).toThrow('variant');
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPUBuffer.mapAsync',
      bufferMapResultEvent(mutateU32(mappedPayload, 33, 5)),
    )).toThrow('extent');
    for (const overrides of [
      { resultKind: 0 },
      { promiseId: '0' },
      { providerAdmission: 0 },
      { physicalSequence: '0' },
      { receiverKind: WEBGPU_OBJECT_KIND_TAGS.GPUDevice },
      { targetKind: WEBGPU_OBJECT_KIND_TAGS.GPUBuffer },
      { adapterOrdinal: '1' },
      { deviceIngressOrdinal: '0' },
      { queueIngressOrdinal: '1' },
      { ingressProviderGeneration: '0' },
    ]) {
      expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
        'GPUBuffer.mapAsync',
        bufferMapResultEvent(mappedPayload, overrides),
      )).toThrow('carrier');
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUBuffer.mapAsync',
      {
        kind: 'buffer-map',
        ...variants[0]!,
        size: '5',
      },
    )).toThrow('ownership');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUBuffer.mapAsync',
      {
        kind: 'buffer-map',
        ...variants[1]!,
        ownedBytes: Uint8Array.from([1]),
      },
    )).toThrow('ownership');
  });

  test('selects every service-owned cleanup terminal without exposing payload bytes', () => {
    for (const [operationId, terminals] of [
      [
        'GPUBuffer.destroy',
        ['repeat-cleanup-noop', 'first-cleanup-rejection', 'first-cleanup-provider'],
      ],
      [
        'GPUBuffer.unmap',
        ['unmapped-noop', 'cleanup-rejection', 'cleanup-provider'],
      ],
    ] as const) {
      for (const terminal of terminals) {
        expect(WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
          operationId,
          { kind: 'buffer-cleanup', terminal },
        ).byteLength).toBe(0);
      }
    }
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUBuffer.destroy',
      { kind: 'buffer-cleanup', terminal: 'cleanup-provider' },
    )).toThrow('terminal');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPUBuffer.unmap',
      { kind: 'buffer-cleanup', terminal: 'first-cleanup-provider' },
    )).toThrow('terminal');
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
        features: ['timestamp-query'],
      },
    );
    expect(adapterPayload.byteLength).toBeGreaterThan(42);
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
        features: ['timestamp-query'],
      },
    });
    const detachedPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPU.requestAdapter', {
        kind: 'adapter',
        objectId: '42',
        objectGeneration: '3',
        providerGeneration: '8',
        serviceDetachedExpired: true,
        features: ['core-features-and-limits'],
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
        features: ['core-features-and-limits'],
      },
    });
    const mismatchedProviderPayload = WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT
      .encodeServiceResult('GPU.requestAdapter', {
        kind: 'adapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '9',
        serviceDetachedExpired: false,
        features: ['timestamp-query'],
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
        features: ['timestamp-query'],
      },
    )).toThrow('positive identity');

    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      {
        kind: 'adapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '8',
        serviceDetachedExpired: false,
        features: ['not-a-webgpu-feature'],
      },
    )).toThrow('known, sorted, and unique');
    expect(() => WEBGPU_EXECUTABLE_CODEC_TEST_SUPPORT.encodeServiceResult(
      'GPU.requestAdapter',
      {
        kind: 'adapter',
        objectId: '41',
        objectGeneration: '2',
        providerGeneration: '8',
        serviceDetachedExpired: false,
        features: ['timestamp-query', 'core-features-and-limits'],
      },
    )).toThrow('known, sorted, and unique');

    const invalidDetachedState = adapterPayload.slice();
    invalidDetachedState[37] = 2;
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, invalidDetachedState),
    )).toThrow('invalid authenticated detached state');
    const excessiveFeatureCount = adapterPayload.slice();
    new DataView(
      excessiveFeatureCount.buffer,
      excessiveFeatureCount.byteOffset,
      excessiveFeatureCount.byteLength,
    ).setUint32(38, 1_025, true);
    expect(() => WEBGPU_EXECUTABLE_CODECS_FOR_INJECTION.decodeServiceResult(
      'GPU.requestAdapter',
      resultEvent('GPU.requestAdapter', 3, excessiveFeatureCount),
    )).toThrow('feature sequence exceeds the reviewed bound');
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
        features: ['timestamp-query'],
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
