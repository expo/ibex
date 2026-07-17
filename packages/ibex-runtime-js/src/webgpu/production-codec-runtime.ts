// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
// The normalized operation/catalog artifact selects every codec. This module
// implements those selected conversions and the private injection-only binary
// layout without introducing a second hand-authored operation registry.

import type { NativeGpuEventV2 } from './native-bridge';
import type {
  ExecutableWebGpuCodecBundle,
  ProductionGpuCodecWrapperAccess,
  ProductionGpuDecodedResult,
  ProductionGpuServiceEncodingInput,
  ProductionGpuWrapperKind,
} from './production-codecs';
import { WEBGPU_PRODUCTION_PLAN } from './production-plan.generated';

interface CodecCatalogRow {
  readonly wireTag: number;
  readonly tag: string;
  readonly wireShape: string;
}

interface ServiceCodecCatalogRow extends CodecCatalogRow {
  readonly executableFromCurrentAuthenticatedInputs: boolean;
  readonly unavailableSemanticFields: readonly string[];
}

export interface ExecutableWebGpuCodecManifest {
  readonly schema: 'ibex/webgpu-executable-codec-manifest/1';
  readonly disposition: string;
  readonly profileId: string;
  readonly scopeId: string;
  readonly operationCount: number;
  readonly operationIds: readonly string[];
  readonly maxPayloadBytes: number;
  readonly byteOrder: string;
  readonly scalarRules: Readonly<Record<string, string>>;
  readonly digests: Readonly<{
    operationSet: string;
    semanticProgramSet: string;
    runtimeRouting: string;
    webgpuCVocabulary: string;
    projection: string;
  }>;
  readonly layout: Readonly<{
    requestMagic: string;
    resultMagic: string;
    lossMagic: string;
    version: number;
    header: string;
    reference: string;
    target: string;
    requestTail: string;
    nullableNullResult: string;
    catalogWireTagRule: string;
    objectKindTagRule: string;
    valueTags: Readonly<{
      null: number;
      false: number;
      true: number;
      u32: number;
      f64: number;
      string: number;
      sequence: number;
      dictionary: number;
    }>;
    diagnosticMaxBytes: number;
    sequenceMaxCount: number;
    dictionaryMaxFields: number;
    nestingMaxDepth: number;
  }>;
  readonly objectKindAuthority: Readonly<{
    path: string;
    sha256: string;
  }>;
  readonly objectKindTags: Readonly<Record<string, number>>;
  readonly publicArguments: readonly CodecCatalogRow[];
  readonly serviceArguments: readonly ServiceCodecCatalogRow[];
  readonly serviceCompletions: readonly CodecCatalogRow[];
  readonly completeLimitNames: readonly string[];
}

type ProductionRoute = (typeof WEBGPU_PRODUCTION_PLAN.routes)[number];
type OperationResultEvent = Extract<NativeGpuEventV2, { kind: 1 }>;

type DetachedOperationResultEvent = OperationResultEvent & Readonly<{
  detachedAlreadyLost?: unknown;
  lossReason?: unknown;
  backendClass?: unknown;
}>;

const PRODUCTION_WRAPPER_KINDS = Object.freeze([
  'GPU',
  'GPUAdapter',
  'GPUDevice',
  'GPUQueue',
  'GPUTexture',
  'GPUTextureView',
  'GPUShaderModule',
  'GPURenderPipeline',
  'GPUCommandEncoder',
  'GPURenderPassEncoder',
  'GPUCommandBuffer',
  'GPUCanvasContext',
] as const satisfies readonly ProductionGpuWrapperKind[]);

const TEXTURE_FORMATS = Object.freeze([
  'r8unorm',
  'r8snorm',
  'r8uint',
  'r8sint',
  'r16uint',
  'r16sint',
  'r16float',
  'rg8unorm',
  'rg8snorm',
  'rg8uint',
  'rg8sint',
  'r32uint',
  'r32sint',
  'r32float',
  'rg16uint',
  'rg16sint',
  'rg16float',
  'rgba8unorm',
  'rgba8unorm-srgb',
  'rgba8snorm',
  'rgba8uint',
  'rgba8sint',
  'bgra8unorm',
  'bgra8unorm-srgb',
  'rgb10a2uint',
  'rgb10a2unorm',
  'rg11b10ufloat',
  'rgb9e5ufloat',
  'rg32uint',
  'rg32sint',
  'rg32float',
  'rgba16uint',
  'rgba16sint',
  'rgba16float',
  'rgba32uint',
  'rgba32sint',
  'rgba32float',
  'stencil8',
  'depth16unorm',
  'depth24plus',
  'depth24plus-stencil8',
  'depth32float',
  'depth32float-stencil8',
]);

const VERTEX_FORMATS = Object.freeze([
  'uint8',
  'uint8x2',
  'uint8x4',
  'sint8',
  'sint8x2',
  'sint8x4',
  'unorm8',
  'unorm8x2',
  'unorm8x4',
  'snorm8',
  'snorm8x2',
  'snorm8x4',
  'uint16',
  'uint16x2',
  'uint16x4',
  'sint16',
  'sint16x2',
  'sint16x4',
  'unorm16',
  'unorm16x2',
  'unorm16x4',
  'snorm16',
  'snorm16x2',
  'snorm16x4',
  'float16',
  'float16x2',
  'float16x4',
  'float32',
  'float32x2',
  'float32x3',
  'float32x4',
  'uint32',
  'uint32x2',
  'uint32x3',
  'uint32x4',
  'sint32',
  'sint32x2',
  'sint32x3',
  'sint32x4',
  'unorm10-10-10-2',
  'unorm8x4-bgra',
]);

function isObjectLike(value: unknown): value is Record<PropertyKey, unknown> {
  return (typeof value === 'object' && value !== null) ||
    typeof value === 'function';
}

function dictionary(value: unknown, label: string): Record<PropertyKey, unknown> {
  if (value === undefined || value === null) return Object.create(null);
  if (!isObjectLike(value)) {
    throw new TypeError(`${label} must be a dictionary`);
  }
  return value;
}

function webIdlString(value: unknown, label: string): string {
  if (typeof value === 'symbol') throw new TypeError(`${label} cannot be a Symbol`);
  return String(value);
}

function enumValue(
  value: unknown,
  values: readonly string[],
  label: string,
): string {
  const converted = webIdlString(value, label);
  if (!values.includes(converted)) {
    throw new TypeError(`${label} is not a supported enum value`);
  }
  return converted;
}

function u32(value: unknown, label: string, defaultValue?: number): number {
  if (value === undefined && defaultValue !== undefined) return defaultValue;
  const converted = Number(value);
  if (
    !Number.isFinite(converted) ||
    !Number.isInteger(converted) ||
    converted < 0 ||
    converted > 0xffff_ffff
  ) {
    throw new TypeError(`${label} must be an unsigned 32-bit integer`);
  }
  return converted;
}

function u64Number(value: unknown, label: string): number {
  const converted = Number(value);
  if (
    !Number.isSafeInteger(converted) ||
    converted < 0
  ) {
    throw new TypeError(`${label} must be a safe nonnegative integer`);
  }
  return converted;
}

function finiteNumber(value: unknown, label: string): number {
  const converted = Number(value);
  if (!Number.isFinite(converted)) {
    throw new TypeError(`${label} must be finite`);
  }
  return converted;
}

function sequence(
  value: unknown,
  label: string,
  maximum: number,
): readonly unknown[] {
  if (value === null || value === undefined) {
    throw new TypeError(`${label} must be iterable`);
  }
  const iterator = (value as { [Symbol.iterator]?: unknown })[Symbol.iterator];
  if (typeof iterator !== 'function') {
    throw new TypeError(`${label} must be iterable`);
  }
  const output: unknown[] = [];
  const iterable = Reflect.apply(iterator, value, []) as Iterator<unknown>;
  while (true) {
    const step = iterable.next();
    if (step.done) break;
    if (output.length >= maximum) {
      throw new TypeError(`${label} exceeds the reviewed sequence bound`);
    }
    output.push(step.value);
  }
  return output;
}

function frozenRecord(
  entries: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return Object.freeze(entries);
}

function optionalLabel(value: Record<PropertyKey, unknown>): string {
  return value.label === undefined
    ? ''
    : webIdlString(value.label, 'label');
}

function convertConstants(
  value: unknown,
  label: string,
): Readonly<Record<string, number>> {
  const source = dictionary(value, label);
  const result: Record<string, number> = {};
  for (const key of Object.keys(source).sort()) {
    result[key] = finiteNumber(source[key], `${label}.${key}`);
  }
  return Object.freeze(result);
}

function convertRequestAdapterOptions(value: unknown): unknown {
  const source = dictionary(value, 'GPURequestAdapterOptions');
  const featureLevelSource = source.featureLevel;
  const featureLevel = featureLevelSource === undefined
    ? 'core'
    : webIdlString(
      featureLevelSource,
      'GPURequestAdapterOptions.featureLevel',
    );
  const forceFallbackAdapter = Boolean(source.forceFallbackAdapter);
  const powerPreferenceSource = source.powerPreference;
  const powerPreference = powerPreferenceSource === undefined
    ? undefined
    : enumValue(
      powerPreferenceSource,
      ['low-power', 'high-performance'],
      'GPURequestAdapterOptions.powerPreference',
    );
  const xrCompatible = Boolean(source.xrCompatible);
  const result: Record<string, unknown> = {
    forceFallbackAdapter,
    featureLevel,
    xrCompatible,
  };
  if (powerPreference !== undefined) {
    result.powerPreference = powerPreference;
  }
  return frozenRecord(result);
}

function convertDeviceDescriptor(value: unknown, maximum: number): unknown {
  const source = dictionary(value, 'GPUDeviceDescriptor');
  const requestedFeatures = source.requiredFeatures === undefined
    ? []
    : sequence(source.requiredFeatures, 'requiredFeatures', maximum);
  const features = requestedFeatures.map((feature) =>
    webIdlString(feature, 'requiredFeatures member'));
  const requiredLimits = dictionary(
    source.requiredLimits,
    'GPUDeviceDescriptor.requiredLimits',
  );
  const limits: Record<string, number> = {};
  for (const key of Object.keys(requiredLimits).sort()) {
    const requested = requiredLimits[key];
    if (requested !== undefined) {
      limits[key] = u64Number(requested, `requiredLimits.${key}`);
    }
  }
  const defaultQueue = dictionary(
    source.defaultQueue,
    'GPUQueueDescriptor',
  );
  return frozenRecord({
    label: optionalLabel(source),
    requiredFeatures: Object.freeze(features),
    requiredLimits: Object.freeze(limits),
    defaultQueue: frozenRecord({ label: optionalLabel(defaultQueue) }),
  });
}

function convertCanvasConfiguration(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const source = dictionary(value, 'GPUCanvasConfiguration');
  const device = source.device;
  wrappers.reference(device, 'GPUDevice');
  if (source.format === undefined) {
    throw new TypeError('GPUCanvasConfiguration.format is required');
  }
  const result: Record<string, unknown> = {
    device,
    format: enumValue(source.format, TEXTURE_FORMATS, 'GPUCanvasConfiguration.format'),
    usage: u32(source.usage, 'GPUCanvasConfiguration.usage', 0x10),
    viewFormats: Object.freeze(
      (source.viewFormats === undefined
        ? []
        : sequence(source.viewFormats, 'GPUCanvasConfiguration.viewFormats', maximum)
      ).map((format) =>
        enumValue(format, TEXTURE_FORMATS, 'GPUCanvasConfiguration.viewFormats member')),
    ),
    colorSpace: source.colorSpace === undefined
      ? 'srgb'
      : enumValue(
        source.colorSpace,
        ['srgb', 'display-p3'],
        'GPUCanvasConfiguration.colorSpace',
      ),
    alphaMode: source.alphaMode === undefined
      ? 'opaque'
      : enumValue(
        source.alphaMode,
        ['opaque', 'premultiplied'],
        'GPUCanvasConfiguration.alphaMode',
      ),
  };
  if (source.toneMapping !== undefined) {
    const toneMapping = dictionary(
      source.toneMapping,
      'GPUCanvasToneMapping',
    );
    result.toneMapping = frozenRecord({
      mode: toneMapping.mode === undefined
        ? 'standard'
        : enumValue(
          toneMapping.mode,
          ['standard', 'extended'],
          'GPUCanvasToneMapping.mode',
        ),
    });
  }
  return frozenRecord(result);
}

function convertColor(value: unknown): Readonly<Record<string, number>> {
  if (Array.isArray(value)) {
    if (value.length !== 4) throw new TypeError('GPUColor sequence must have four members');
    return frozenRecord({
      r: finiteNumber(value[0], 'GPUColor.r'),
      g: finiteNumber(value[1], 'GPUColor.g'),
      b: finiteNumber(value[2], 'GPUColor.b'),
      a: finiteNumber(value[3], 'GPUColor.a'),
    }) as Readonly<Record<string, number>>;
  }
  const source = dictionary(value, 'GPUColor');
  return frozenRecord({
    r: finiteNumber(source.r, 'GPUColor.r'),
    g: finiteNumber(source.g, 'GPUColor.g'),
    b: finiteNumber(source.b, 'GPUColor.b'),
    a: finiteNumber(source.a, 'GPUColor.a'),
  }) as Readonly<Record<string, number>>;
}

function convertRenderPassDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const source = dictionary(value, 'GPURenderPassDescriptor');
  const sourceAttachments = source.colorAttachments === undefined
    ? []
    : sequence(source.colorAttachments, 'colorAttachments', maximum);
  const attachments = sourceAttachments.map((attachment, index) => {
    if (attachment === null) return null;
    const row = dictionary(attachment, `colorAttachments[${index}]`);
    const result: Record<string, unknown> = {
      view: wrappers.reference(row.view, 'GPUTextureView'),
      loadOp: row.loadOp === undefined
        ? 'load'
        : enumValue(row.loadOp, ['load', 'clear'], 'GPURenderPassColorAttachment.loadOp'),
      storeOp: row.storeOp === undefined
        ? 'store'
        : enumValue(
          row.storeOp,
          ['store', 'discard'],
          'GPURenderPassColorAttachment.storeOp',
        ),
    };
    if (row.resolveTarget !== undefined) {
      result.resolveTarget = wrappers.reference(
        row.resolveTarget,
        'GPUTextureView',
      );
    }
    if (row.clearValue !== undefined) result.clearValue = convertColor(row.clearValue);
    if (row.depthSlice !== undefined) {
      result.depthSlice = u32(row.depthSlice, 'GPURenderPassColorAttachment.depthSlice');
    }
    return frozenRecord(result);
  });
  return frozenRecord({
    label: optionalLabel(source),
    colorAttachments: Object.freeze(attachments),
  });
}

function convertObjectDescriptor(value: unknown, label: string): unknown {
  const source = dictionary(value, label);
  return frozenRecord({ label: optionalLabel(source) });
}

function convertVertexBuffers(value: unknown, maximum: number): readonly unknown[] {
  if (value === undefined) return Object.freeze([]);
  const buffers = sequence(value, 'GPUVertexState.buffers', maximum);
  return Object.freeze(buffers.map((buffer, bufferIndex) => {
    if (buffer === null) return null;
    const source = dictionary(buffer, `GPUVertexBufferLayout[${bufferIndex}]`);
    const attributes = sequence(
      source.attributes,
      `GPUVertexBufferLayout[${bufferIndex}].attributes`,
      maximum,
    );
    return frozenRecord({
      arrayStride: u64Number(source.arrayStride, 'GPUVertexBufferLayout.arrayStride'),
      stepMode: source.stepMode === undefined
        ? 'vertex'
        : enumValue(
          source.stepMode,
          ['vertex', 'instance'],
          'GPUVertexBufferLayout.stepMode',
        ),
      attributes: Object.freeze(attributes.map((attribute) => {
        const row = dictionary(attribute, 'GPUVertexAttribute');
        return frozenRecord({
          format: enumValue(row.format, VERTEX_FORMATS, 'GPUVertexAttribute.format'),
          offset: u64Number(row.offset, 'GPUVertexAttribute.offset'),
          shaderLocation: u32(row.shaderLocation, 'GPUVertexAttribute.shaderLocation'),
        });
      })),
    });
  }));
}

function convertProgrammableStage(
  value: unknown,
  label: string,
  wrappers: ProductionGpuCodecWrapperAccess,
): Record<string, unknown> {
  const source = dictionary(value, label);
  const result: Record<string, unknown> = {
    module: wrappers.reference(source.module, 'GPUShaderModule'),
    constants: convertConstants(source.constants, `${label}.constants`),
  };
  if (source.entryPoint !== undefined) {
    result.entryPoint = webIdlString(source.entryPoint, `${label}.entryPoint`);
  }
  return result;
}

function convertBlendComponent(
  value: unknown,
  label: string,
): Readonly<Record<string, unknown>> {
  const source = dictionary(value, label);
  return frozenRecord({
    operation: source.operation === undefined
      ? 'add'
      : enumValue(
        source.operation,
        ['add', 'subtract', 'reverse-subtract', 'min', 'max'],
        `${label}.operation`,
      ),
    srcFactor: source.srcFactor === undefined
      ? 'one'
      : webIdlString(source.srcFactor, `${label}.srcFactor`),
    dstFactor: source.dstFactor === undefined
      ? 'zero'
      : webIdlString(source.dstFactor, `${label}.dstFactor`),
  });
}

function convertRenderPipelineDescriptor(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const source = dictionary(value, 'GPURenderPipelineDescriptor');
  if (source.vertex === undefined) {
    throw new TypeError('GPURenderPipelineDescriptor.vertex is required');
  }
  const vertexSource = dictionary(source.vertex, 'GPUVertexState');
  const vertex = convertProgrammableStage(
    vertexSource,
    'GPUVertexState',
    wrappers,
  );
  vertex.buffers = convertVertexBuffers(vertexSource.buffers, maximum);
  const result: Record<string, unknown> = {
    label: optionalLabel(source),
    layout: source.layout === undefined
      ? 'auto'
      : enumValue(source.layout, ['auto'], 'GPUPipelineDescriptorBase.layout'),
    vertex: frozenRecord(vertex),
  };
  if (source.fragment !== undefined) {
    const fragmentSource = dictionary(source.fragment, 'GPUFragmentState');
    const fragment = convertProgrammableStage(
      fragmentSource,
      'GPUFragmentState',
      wrappers,
    );
    const targets = fragmentSource.targets === undefined
      ? []
      : sequence(
        fragmentSource.targets,
        'GPUFragmentState.targets',
        maximum,
      );
    fragment.targets = Object.freeze(targets.map((target) => {
      if (target === null) return null;
      const row = dictionary(target, 'GPUColorTargetState');
      const targetResult: Record<string, unknown> = {
        format: enumValue(row.format, TEXTURE_FORMATS, 'GPUColorTargetState.format'),
        writeMask: u32(row.writeMask, 'GPUColorTargetState.writeMask', 0xf),
      };
      if (row.blend !== undefined) {
        const blend = dictionary(row.blend, 'GPUBlendState');
        targetResult.blend = frozenRecord({
          color: convertBlendComponent(blend.color, 'GPUBlendState.color'),
          alpha: convertBlendComponent(blend.alpha, 'GPUBlendState.alpha'),
        });
      }
      return frozenRecord(targetResult);
    }));
    result.fragment = frozenRecord(fragment);
  }
  const primitive = dictionary(source.primitive, 'GPUPrimitiveState');
  result.primitive = frozenRecord({
    topology: primitive.topology === undefined
      ? 'triangle-list'
      : enumValue(
        primitive.topology,
        ['point-list', 'line-list', 'line-strip', 'triangle-list', 'triangle-strip'],
        'GPUPrimitiveState.topology',
      ),
    stripIndexFormat: primitive.stripIndexFormat === undefined
      ? undefined
      : enumValue(
        primitive.stripIndexFormat,
        ['uint16', 'uint32'],
        'GPUPrimitiveState.stripIndexFormat',
      ),
    frontFace: primitive.frontFace === undefined
      ? 'ccw'
      : enumValue(primitive.frontFace, ['ccw', 'cw'], 'GPUPrimitiveState.frontFace'),
    cullMode: primitive.cullMode === undefined
      ? 'none'
      : enumValue(
        primitive.cullMode,
        ['none', 'front', 'back'],
        'GPUPrimitiveState.cullMode',
      ),
    unclippedDepth: Boolean(primitive.unclippedDepth),
  });
  const multisample = dictionary(source.multisample, 'GPUMultisampleState');
  result.multisample = frozenRecord({
    count: u32(multisample.count, 'GPUMultisampleState.count', 1),
    mask: u32(multisample.mask, 'GPUMultisampleState.mask', 0xffff_ffff),
    alphaToCoverageEnabled: Boolean(multisample.alphaToCoverageEnabled),
  });
  return frozenRecord(result);
}

function convertShaderModuleDescriptor(value: unknown): unknown {
  const source = dictionary(value, 'GPUShaderModuleDescriptor');
  if (source.code === undefined) {
    throw new TypeError('GPUShaderModuleDescriptor.code is required');
  }
  return frozenRecord({
    label: optionalLabel(source),
    code: webIdlString(source.code, 'GPUShaderModuleDescriptor.code'),
  });
}

function convertErrorFilter(value: unknown): unknown {
  return enumValue(
    value,
    ['validation', 'out-of-memory', 'internal'],
    'GPUErrorFilter',
  );
}

function convertCommandBufferSequence(
  value: unknown,
  wrappers: ProductionGpuCodecWrapperAccess,
  maximum: number,
): unknown {
  const values = sequence(value, 'GPUQueue.submit commandBuffers', maximum);
  for (const buffer of values) wrappers.reference(buffer, 'GPUCommandBuffer');
  // The wrapper needs the branded values to seal their private command records.
  return Object.freeze(values.slice());
}

function convertDrawArguments(args: readonly unknown[]): unknown {
  return Object.freeze([
    u32(args[0], 'vertexCount'),
    u32(args[1], 'instanceCount', 1),
    u32(args[2], 'firstVertex', 0),
    u32(args[3], 'firstInstance', 0),
  ]);
}

function convertTextureViewDescriptor(value: unknown): unknown {
  const source = dictionary(value, 'GPUTextureViewDescriptor');
  const result: Record<string, unknown> = {
    label: optionalLabel(source),
    aspect: source.aspect === undefined
      ? 'all'
      : enumValue(
        source.aspect,
        ['all', 'stencil-only', 'depth-only'],
        'GPUTextureViewDescriptor.aspect',
      ),
    baseMipLevel: u32(source.baseMipLevel, 'GPUTextureViewDescriptor.baseMipLevel', 0),
    baseArrayLayer: u32(
      source.baseArrayLayer,
      'GPUTextureViewDescriptor.baseArrayLayer',
      0,
    ),
  };
  if (source.format !== undefined) {
    result.format = enumValue(
      source.format,
      TEXTURE_FORMATS,
      'GPUTextureViewDescriptor.format',
    );
  }
  if (source.dimension !== undefined) {
    result.dimension = enumValue(
      source.dimension,
      ['1d', '2d', '2d-array', 'cube', 'cube-array', '3d'],
      'GPUTextureViewDescriptor.dimension',
    );
  }
  if (source.mipLevelCount !== undefined) {
    result.mipLevelCount = u32(
      source.mipLevelCount,
      'GPUTextureViewDescriptor.mipLevelCount',
    );
  }
  if (source.arrayLayerCount !== undefined) {
    result.arrayLayerCount = u32(
      source.arrayLayerCount,
      'GPUTextureViewDescriptor.arrayLayerCount',
    );
  }
  if (source.usage !== undefined) {
    result.usage = u32(source.usage, 'GPUTextureViewDescriptor.usage');
  }
  return frozenRecord(result);
}

function encodeUtf8(value: string): Uint8Array {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    let codePoint = value.charCodeAt(index);
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      if (index + 1 >= value.length) throw new TypeError('String is not well-formed UTF-16');
      const trail = value.charCodeAt(++index);
      if (trail < 0xdc00 || trail > 0xdfff) {
        throw new TypeError('String is not well-formed UTF-16');
      }
      codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (trail - 0xdc00);
    } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
      throw new TypeError('String is not well-formed UTF-16');
    }
    if (codePoint <= 0x7f) {
      bytes.push(codePoint);
    } else if (codePoint <= 0x7ff) {
      bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint <= 0xffff) {
      bytes.push(
        0xe0 | (codePoint >> 12),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    } else {
      bytes.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f),
      );
    }
  }
  return Uint8Array.from(bytes);
}

function compareCanonicalUtf8(left: string, right: string): number {
  const leftBytes = encodeUtf8(left);
  const rightBytes = encodeUtf8(right);
  const sharedLength = Math.min(leftBytes.byteLength, rightBytes.byteLength);
  for (let index = 0; index < sharedLength; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) {
      return leftBytes[index] - rightBytes[index];
    }
  }
  return leftBytes.byteLength - rightBytes.byteLength;
}

function decodeUtf8(bytes: Uint8Array): string {
  const codeUnits: number[] = [];
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index++];
    let codePoint: number;
    let remaining: number;
    let minimum: number;
    if (first <= 0x7f) {
      codePoint = first;
      remaining = 0;
      minimum = 0;
    } else if (first >= 0xc2 && first <= 0xdf) {
      codePoint = first & 0x1f;
      remaining = 1;
      minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
      codePoint = first & 0x0f;
      remaining = 2;
      minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codePoint = first & 0x07;
      remaining = 3;
      minimum = 0x10000;
    } else {
      throw new TypeError('Malformed UTF-8 in WebGPU payload');
    }
    for (let part = 0; part < remaining; part += 1) {
      if (index >= bytes.length) throw new TypeError('Truncated UTF-8 in WebGPU payload');
      const continuation = bytes[index++];
      if ((continuation & 0xc0) !== 0x80) {
        throw new TypeError('Malformed UTF-8 in WebGPU payload');
      }
      codePoint = (codePoint << 6) | (continuation & 0x3f);
    }
    if (
      codePoint < minimum ||
      codePoint > 0x10ffff ||
      (codePoint >= 0xd800 && codePoint <= 0xdfff)
    ) {
      throw new TypeError('Non-canonical UTF-8 in WebGPU payload');
    }
    if (codePoint <= 0xffff) {
      codeUnits.push(codePoint);
    } else {
      const scalar = codePoint - 0x10000;
      codeUnits.push(0xd800 + (scalar >> 10), 0xdc00 + (scalar & 0x3ff));
    }
  }
  let result = '';
  for (let offset = 0; offset < codeUnits.length; offset += 4096) {
    result += String.fromCharCode(...codeUnits.slice(offset, offset + 4096));
  }
  return result;
}

function parseU64Decimal(value: string): readonly [number, number] {
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new TypeError('WebGPU u64 value must be canonical decimal');
  }
  let high = 0;
  let low = 0;
  for (const character of value) {
    const digit = character.charCodeAt(0) - 48;
    const lowProduct = low * 10 + digit;
    const nextLow = lowProduct % 0x1_0000_0000;
    const carry = Math.floor(lowProduct / 0x1_0000_0000);
    const highProduct = high * 10 + carry;
    if (highProduct >= 0x1_0000_0000) {
      throw new TypeError('WebGPU u64 value exceeds the binary range');
    }
    low = nextLow;
    high = highProduct;
  }
  return [low, high];
}

function u64Decimal(high: number, low: number): string {
  const digits = [0];
  for (let bit = 63; bit >= 0; bit -= 1) {
    let carry = bit >= 32
      ? (high >>> (bit - 32)) & 1
      : (low >>> bit) & 1;
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      const value = digits[index] * 2 + carry;
      digits[index] = value % 10;
      carry = Math.floor(value / 10);
    }
    if (carry) digits.unshift(carry);
  }
  return digits.join('');
}

class Writer {
  private bytes = new Uint8Array(256);
  private view = new DataView(this.bytes.buffer);
  private offset = 0;

  constructor(private readonly maximum: number) {}

  private reserve(count: number): void {
    const required = this.offset + count;
    if (required > this.maximum) {
      throw new TypeError('WebGPU payload exceeds the reviewed byte bound');
    }
    if (required <= this.bytes.length) return;
    let capacity = this.bytes.length;
    while (capacity < required) capacity = Math.min(this.maximum, capacity * 2);
    const replacement = new Uint8Array(capacity);
    replacement.set(this.bytes);
    this.bytes = replacement;
    this.view = new DataView(replacement.buffer);
  }

  u8(value: number): void {
    this.reserve(1);
    this.view.setUint8(this.offset, value);
    this.offset += 1;
  }

  u16(value: number): void {
    this.reserve(2);
    this.view.setUint16(this.offset, value, true);
    this.offset += 2;
  }

  u32(value: number): void {
    this.reserve(4);
    this.view.setUint32(this.offset, value, true);
    this.offset += 4;
  }

  f64(value: number): void {
    this.reserve(8);
    this.view.setFloat64(this.offset, value, true);
    this.offset += 8;
  }

  u64(value: string): void {
    const [low, high] = parseU64Decimal(value);
    this.u32(low);
    this.u32(high);
  }

  raw(value: Uint8Array): void {
    this.reserve(value.byteLength);
    this.bytes.set(value, this.offset);
    this.offset += value.byteLength;
  }

  ascii4(value: string): void {
    if (!/^[\x20-\x7e]{4}$/u.test(value)) throw new Error('Codec magic must be four ASCII bytes');
    for (let index = 0; index < value.length; index += 1) {
      this.u8(value.charCodeAt(index));
    }
  }

  string(value: string, maximumBytes = this.maximum): void {
    const encoded = encodeUtf8(value);
    if (encoded.byteLength > maximumBytes) {
      throw new TypeError('WebGPU string exceeds its reviewed byte bound');
    }
    this.u32(encoded.byteLength);
    this.raw(encoded);
  }

  value(
    value: unknown,
    limits: ExecutableWebGpuCodecManifest['layout'],
    depth = 0,
    seen = new WeakSet<object>(),
  ): void {
    if (depth > limits.nestingMaxDepth) {
      throw new TypeError('WebGPU value exceeds the reviewed nesting bound');
    }
    if (value === null) {
      this.u8(limits.valueTags.null);
      return;
    }
    if (value === false) {
      this.u8(limits.valueTags.false);
      return;
    }
    if (value === true) {
      this.u8(limits.valueTags.true);
      return;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new TypeError('WebGPU numbers must be finite');
      if (Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff) {
        this.u8(limits.valueTags.u32);
        this.u32(value);
      } else {
        this.u8(limits.valueTags.f64);
        this.f64(value);
      }
      return;
    }
    if (typeof value === 'string') {
      this.u8(limits.valueTags.string);
      this.string(value);
      return;
    }
    if (typeof value !== 'object' || value === null) {
      throw new TypeError('WebGPU payload contains a non-canonical value');
    }
    if (seen.has(value)) throw new TypeError('WebGPU payload contains a cycle');
    seen.add(value);
    if (Array.isArray(value)) {
      if (value.length > limits.sequenceMaxCount) {
        throw new TypeError('WebGPU sequence exceeds the reviewed count bound');
      }
      this.u8(limits.valueTags.sequence);
      this.u32(value.length);
      for (const item of value) this.value(item, limits, depth + 1, seen);
    } else {
      const keys = Object.keys(value)
        .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
        .sort(compareCanonicalUtf8);
      if (keys.length > limits.dictionaryMaxFields) {
        throw new TypeError('WebGPU dictionary exceeds the reviewed field bound');
      }
      this.u8(limits.valueTags.dictionary);
      this.u32(keys.length);
      for (const key of keys) {
        this.string(key);
        this.value(
          (value as Record<string, unknown>)[key],
          limits,
          depth + 1,
          seen,
        );
      }
    }
    seen.delete(value);
  }

  finish(): Uint8Array {
    return this.bytes.slice(0, this.offset);
  }
}

class Reader {
  private readonly bytes: Uint8Array;
  private readonly view: DataView;
  private offset = 0;

  constructor(value: ArrayBufferView, maximum: number) {
    if (value.byteLength > maximum) {
      throw new TypeError('WebGPU payload exceeds the reviewed byte bound');
    }
    this.bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    this.view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  }

  private require(count: number): void {
    if (count < 0 || this.offset + count > this.bytes.byteLength) {
      throw new TypeError('Truncated WebGPU payload');
    }
  }

  u8(): number {
    this.require(1);
    return this.view.getUint8(this.offset++);
  }

  u16(): number {
    this.require(2);
    const value = this.view.getUint16(this.offset, true);
    this.offset += 2;
    return value;
  }

  u32(): number {
    this.require(4);
    const value = this.view.getUint32(this.offset, true);
    this.offset += 4;
    return value;
  }

  f64(): number {
    this.require(8);
    const value = this.view.getFloat64(this.offset, true);
    this.offset += 8;
    if (!Number.isFinite(value)) throw new TypeError('Non-finite WebGPU payload number');
    return value;
  }

  u64(): string {
    const low = this.u32();
    const high = this.u32();
    return u64Decimal(high, low);
  }

  ascii4(): string {
    return String.fromCharCode(this.u8(), this.u8(), this.u8(), this.u8());
  }

  string(maximumBytes: number): string {
    const length = this.u32();
    if (length > maximumBytes) {
      throw new TypeError('WebGPU string exceeds its reviewed byte bound');
    }
    this.require(length);
    const result = decodeUtf8(this.bytes.subarray(this.offset, this.offset + length));
    this.offset += length;
    return result;
  }

  value(
    limits: ExecutableWebGpuCodecManifest['layout'],
    depth = 0,
  ): unknown {
    if (depth > limits.nestingMaxDepth) {
      throw new TypeError('WebGPU value exceeds the reviewed nesting bound');
    }
    const tag = this.u8();
    if (tag === limits.valueTags.null) return null;
    if (tag === limits.valueTags.false) return false;
    if (tag === limits.valueTags.true) return true;
    if (tag === limits.valueTags.u32) return this.u32();
    if (tag === limits.valueTags.f64) return this.f64();
    if (tag === limits.valueTags.string) return this.string(this.bytes.byteLength);
    if (tag === limits.valueTags.sequence) {
      const count = this.u32();
      if (count > limits.sequenceMaxCount) {
        throw new TypeError('WebGPU sequence exceeds the reviewed count bound');
      }
      const result: unknown[] = [];
      for (let index = 0; index < count; index += 1) {
        result.push(this.value(limits, depth + 1));
      }
      return result;
    }
    if (tag === limits.valueTags.dictionary) {
      const count = this.u32();
      if (count > limits.dictionaryMaxFields) {
        throw new TypeError('WebGPU dictionary exceeds the reviewed field bound');
      }
      const result = Object.create(null) as Record<string, unknown>;
      let previous = '';
      for (let index = 0; index < count; index += 1) {
        const key = this.string(this.bytes.byteLength);
        if (
          (index > 0 && compareCanonicalUtf8(key, previous) <= 0) ||
          Object.prototype.hasOwnProperty.call(result, key)
        ) {
          throw new TypeError('WebGPU dictionary keys are not canonical');
        }
        previous = key;
        result[key] = this.value(limits, depth + 1);
      }
      return result;
    }
    throw new TypeError(`Unknown WebGPU value tag: ${tag}`);
  }

  done(): void {
    if (this.offset !== this.bytes.byteLength) {
      throw new TypeError('Trailing bytes in WebGPU payload');
    }
  }
}

function writeReference(
  writer: Writer,
  reference: ProductionGpuServiceEncodingInput['receiver'],
  objectKinds: Readonly<Record<ProductionGpuWrapperKind, number>>,
): void {
  const kind = objectKinds[reference.kind];
  if (!kind) throw new TypeError(`Unknown WebGPU object kind: ${reference.kind}`);
  writer.u8(kind);
  writer.u64(reference.objectId);
  writer.u64(reference.objectGeneration);
  writer.u64(reference.logicalDeviceId);
  writer.u64(reference.logicalDeviceGeneration);
  writer.u64(reference.providerGeneration);
}

function readReference(
  reader: Reader,
  objectKindsByTag: ReadonlyMap<number, ProductionGpuWrapperKind>,
): Readonly<Record<string, string | number>> {
  const kindTag = reader.u8();
  const kind = objectKindsByTag.get(kindTag);
  if (!kind) throw new TypeError(`Unknown WebGPU object kind tag: ${kindTag}`);
  return Object.freeze({
    kind,
    objectId: reader.u64(),
    objectGeneration: reader.u64(),
    logicalDeviceId: reader.u64(),
    logicalDeviceGeneration: reader.u64(),
    providerGeneration: reader.u64(),
  });
}

function writeHeader(
  writer: Writer,
  magic: string,
  version: number,
  codecTag: number,
  wireId: number,
): void {
  writer.ascii4(magic);
  writer.u16(version);
  writer.u16(codecTag);
  writer.u32(wireId);
}

function readHeader(
  reader: Reader,
  magic: string,
  version: number,
  expectedCodecTag: number,
  expectedWireId: number,
): void {
  if (reader.ascii4() !== magic) throw new TypeError('Unknown WebGPU payload magic');
  if (reader.u16() !== version) throw new TypeError('Unknown WebGPU codec version');
  const codecTag = reader.u16();
  if (codecTag !== expectedCodecTag) {
    throw new TypeError(`Unexpected WebGPU codec tag: ${codecTag}`);
  }
  if (reader.u32() !== expectedWireId) {
    throw new TypeError('WebGPU payload operation identity mismatch');
  }
}

function positiveIdentity(value: string, label: string): string {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new TypeError(`${label} must be a positive identity`);
  }
  return value;
}

function makeGpuError(kind: number, message: string): Error {
  const names: Readonly<Record<number, string>> = Object.freeze({
    1: 'GPUValidationError',
    2: 'GPUOutOfMemoryError',
    3: 'GPUInternalError',
  });
  const name = names[kind];
  if (!name) throw new TypeError(`Unknown GPU error kind: ${kind}`);
  const error = new Error(message);
  Object.defineProperty(error, 'name', {
    value: name,
    writable: false,
    enumerable: false,
    configurable: true,
  });
  return Object.freeze(error);
}

export interface WebGpuCodecTestAdapterResult {
  readonly kind: 'adapter';
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly providerGeneration: string;
}

export interface WebGpuCodecTestDeviceResult {
  readonly kind: 'device';
  readonly objectId: string;
  readonly objectGeneration: string;
  readonly logicalDeviceId: string;
  readonly logicalDeviceGeneration: string;
  readonly providerGeneration: string;
  readonly queueObjectId: string;
  readonly queueObjectGeneration: string;
  readonly features: readonly string[];
  readonly limits: Readonly<Record<string, number>>;
  readonly diagnosticMessage?: string;
}

export interface WebGpuCodecTestErrorResult {
  readonly kind: 'error';
  readonly errorKind: 1 | 2 | 3;
  readonly message: string;
}

export type WebGpuCodecTestServiceResult =
  | Readonly<{ kind: 'null' }>
  | WebGpuCodecTestAdapterResult
  | WebGpuCodecTestDeviceResult
  | WebGpuCodecTestErrorResult;

export function createExecutableWebGpuCodecs(
  manifest: ExecutableWebGpuCodecManifest,
  expectedObjectKindTags: Readonly<Record<string, number>>,
): Readonly<{
  bundle: ExecutableWebGpuCodecBundle;
  testSupport: Readonly<{
    inspectServiceRequest: (payload: ArrayBufferView) => unknown;
    encodeServiceResult: (
      operationId: string,
      result: WebGpuCodecTestServiceResult,
    ) => Uint8Array;
    encodeDeviceLoss: (message: string) => Uint8Array;
    encodeCanonicalValue: (value: unknown) => Uint8Array;
  }>;
}> {
  if (
    manifest.schema !== 'ibex/webgpu-executable-codec-manifest/1' ||
    manifest.disposition !==
      'reviewed-generated-injection-only-native-decoder-absent-no-support-claim' ||
    manifest.operationCount !== WEBGPU_PRODUCTION_PLAN.routes.length ||
    manifest.byteOrder !== 'little-endian' ||
    manifest.completeLimitNames.length !== 36 ||
    manifest.layout.requestMagic !== 'IBGQ' ||
    manifest.layout.resultMagic !== 'IBGR' ||
    manifest.layout.lossMagic !== 'IBGL' ||
    manifest.layout.version !== 1 ||
    manifest.layout.catalogWireTagRule !==
      'one-based-index-in-authority-catalog-order' ||
    manifest.layout.objectKindTagRule !==
      'ExactGpuObjectKindV2-numeric-values-from-include-exact_runtime.h' ||
    manifest.layout.header !==
      'ascii4-magic-plus-u16-le-version-plus-u16-le-codec-tag-plus-u32-le-operation-wire-id' ||
    manifest.layout.reference !==
      'u8-object-kind-plus-five-u64-le-identity-fields' ||
    manifest.layout.target !==
      'u8-zero-or-one-presence-plus-optional-reference' ||
    manifest.layout.requestTail !==
      'four-u64-le-ordinals-plus-generic-sealed-local-timeline-plus-generic-converted-arguments' ||
    manifest.layout.nullableNullResult !==
      'authenticated-result-kind-null-plus-zero-payload-bytes' ||
    manifest.maxPayloadBytes !== 16_777_216 ||
    manifest.layout.diagnosticMaxBytes !== 4_096 ||
    manifest.layout.sequenceMaxCount !== 1_024 ||
    manifest.layout.dictionaryMaxFields !== 128 ||
    manifest.layout.nestingMaxDepth !== 16 ||
    JSON.stringify(manifest.layout.valueTags) !==
      JSON.stringify({
        null: 0,
        false: 1,
        true: 2,
        u32: 3,
        f64: 4,
        string: 5,
        sequence: 6,
        dictionary: 7,
      }) ||
    manifest.objectKindAuthority.path !== 'include/exact_runtime.h' ||
    !/^[0-9a-f]{64}$/u.test(manifest.objectKindAuthority.sha256) ||
    manifest.publicArguments.some((row, index) => row.wireTag !== index + 1) ||
    manifest.serviceArguments.some((row, index) => row.wireTag !== index + 1) ||
    manifest.serviceCompletions.some((row, index) => row.wireTag !== index + 1)
  ) {
    throw new Error('Invalid generated WebGPU executable codec manifest');
  }
  const objectKindEntries = Object.entries(manifest.objectKindTags);
  const expectedObjectKindEntries = Object.entries(expectedObjectKindTags);
  if (
    objectKindEntries.length !== 23 ||
    expectedObjectKindEntries.length !== 23 ||
    manifest.objectKindTags.None !== 0 ||
    expectedObjectKindEntries.some(
      ([name, tag]) => manifest.objectKindTags[name] !== tag,
    ) ||
    objectKindEntries.some(
      ([name, tag]) => expectedObjectKindTags[name] !== tag,
    )
  ) {
    throw new Error('Invalid generated WebGPU object-kind table');
  }
  const objectKinds = Object.fromEntries(
    PRODUCTION_WRAPPER_KINDS.map((kind) => [kind, manifest.objectKindTags[kind]]),
  ) as Record<ProductionGpuWrapperKind, number>;
  if (
    Object.values(objectKinds).some(
      (tag) => !Number.isInteger(tag) || tag <= 0 || tag > 0xff,
    ) ||
    new Set(Object.values(objectKinds)).size !== PRODUCTION_WRAPPER_KINDS.length
  ) {
    throw new Error('Generated WebGPU wrapper object kinds are incomplete');
  }
  const objectKindsByTag = new Map<number, ProductionGpuWrapperKind>(
    Object.entries(objectKinds).map(([kind, tag]) => [
      tag,
      kind as ProductionGpuWrapperKind,
    ]),
  );
  const routes = new Map<string, ProductionRoute>(
    WEBGPU_PRODUCTION_PLAN.routes.map((route) => [route.operationId, route]),
  );
  const publicCodecs = new Map(
    manifest.publicArguments.map((codec) => [codec.tag, codec]),
  );
  const serviceCodecs = new Map(
    manifest.serviceArguments.map((codec) => [codec.tag, codec]),
  );
  const completionCodecs = new Map(
    manifest.serviceCompletions.map((codec) => [codec.tag, codec]),
  );
  if (
    routes.size !== WEBGPU_PRODUCTION_PLAN.routes.length ||
    manifest.operationIds.length !== WEBGPU_PRODUCTION_PLAN.routes.length ||
    manifest.operationIds.some((operationId, index) =>
      WEBGPU_PRODUCTION_PLAN.routes[index]?.operationId !== operationId)
  ) {
    throw new Error('Generated WebGPU codec operation inventory drifted');
  }
  for (const route of routes.values()) {
    if (
      !publicCodecs.has(route.publicArgumentCodec) ||
      !serviceCodecs.has(route.serviceArgumentCodec) ||
      !completionCodecs.has(route.serviceCompletionCodec)
    ) {
      throw new Error(`Generated WebGPU codec catalog omits ${route.operationId}`);
    }
  }

  const selectedRoute = (operationId: string): ProductionRoute => {
    const route = routes.get(operationId);
    if (!route) throw new TypeError(`Unreviewed WebGPU operation: ${operationId}`);
    return route;
  };

  const convertPublicArguments = (
    operationId: string,
    args: readonly unknown[],
    wrappers: ProductionGpuCodecWrapperAccess,
  ): unknown => {
    const codec = selectedRoute(operationId).publicArgumentCodec;
    switch (codec) {
      case 'none-v1':
        return null;
      case 'gpu-request-adapter-options-v1':
        return convertRequestAdapterOptions(args[0]);
      case 'gpu-device-descriptor-v1':
        return convertDeviceDescriptor(args[0], manifest.layout.sequenceMaxCount);
      case 'gpu-canvas-configuration-v1':
        return convertCanvasConfiguration(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-render-pass-descriptor-v1':
        return convertRenderPassDescriptor(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-command-buffer-descriptor-v1':
        return convertObjectDescriptor(args[0], 'GPUCommandBufferDescriptor');
      case 'gpu-command-encoder-descriptor-v1':
        return convertObjectDescriptor(args[0], 'GPUCommandEncoderDescriptor');
      case 'gpu-render-pipeline-descriptor-v1':
        return convertRenderPipelineDescriptor(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-shader-module-descriptor-v1':
        return convertShaderModuleDescriptor(args[0]);
      case 'gpu-error-filter-v1':
        return convertErrorFilter(args[0]);
      case 'gpu-command-buffer-handle-sequence-v1':
        return convertCommandBufferSequence(
          args[0],
          wrappers,
          manifest.layout.sequenceMaxCount,
        );
      case 'gpu-draw-arguments-v1':
        return convertDrawArguments(args);
      case 'gpu-render-pipeline-handle-v1':
        return wrappers.reference(args[0], 'GPURenderPipeline');
      case 'gpu-texture-view-descriptor-v1':
        return convertTextureViewDescriptor(args[0]);
      default:
        throw new TypeError(`Unknown WebGPU public argument codec: ${codec}`);
    }
  };

  const encodeServiceRequest = (
    input: ProductionGpuServiceEncodingInput,
  ): Uint8Array => {
    const route = selectedRoute(input.operationId);
    if (input.wireId !== route.wireId) {
      throw new TypeError('WebGPU request wire identity mismatch');
    }
    if (route.providerSubmission === 'none') {
      throw new TypeError(`${input.operationId} has no service request codec`);
    }
    const codec = serviceCodecs.get(route.serviceArgumentCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service request codec');
    if (!codec.executableFromCurrentAuthenticatedInputs) {
      throw new TypeError(
        `${route.serviceArgumentCodec} is injection-incomplete; missing authenticated semantic fields: ` +
          codec.unavailableSemanticFields.join(', '),
      );
    }
    const writer = new Writer(manifest.maxPayloadBytes);
    writeHeader(
      writer,
      manifest.layout.requestMagic,
      manifest.layout.version,
      codec.wireTag,
      route.wireId,
    );
    writeReference(writer, input.receiver, objectKinds);
    writer.u8(input.target ? 1 : 0);
    if (input.target) writeReference(writer, input.target, objectKinds);
    writer.u64(input.capturedScopeId);
    writer.u64(input.adapterOrdinal);
    writer.u64(input.deviceIngressOrdinal);
    writer.u64(input.queueIngressOrdinal);
    writer.value(input.sealedLocalTimeline, manifest.layout);
    writer.value(input.convertedArguments, manifest.layout);
    return writer.finish();
  };

  const decodeServiceResult = (
    operationId: string,
    event: OperationResultEvent,
  ): ProductionGpuDecodedResult => {
    const route = selectedRoute(operationId);
    if (event.operationId !== route.wireId) {
      throw new TypeError('WebGPU result operation identity mismatch');
    }
    const codec = completionCodecs.get(route.serviceCompletionCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service completion codec');
    const adapterCompletion = route.serviceCompletionCodec ===
      'nullable-gpu-adapter-service-completion-v1';
    if (
      adapterCompletion &&
      (event.deviceTransition !== 0 ||
        event.logicalDeviceId !== '0' ||
        event.logicalDeviceGeneration !== '0' ||
        event.providerGeneration !== '0')
    ) {
      throw new TypeError('GPUAdapter result carries invalid device provenance');
    }
    const nullableCompletion =
      adapterCompletion ||
      route.serviceCompletionCodec ===
        'nullable-gpu-error-service-completion-v1';
    if (nullableCompletion && event.resultKind === 2) {
      if (event.payload.byteLength !== 0) {
        throw new TypeError('WebGPU null result must carry zero payload bytes');
      }
      return Object.freeze({ kind: 'null' });
    }
    const reader = new Reader(event.payload, manifest.maxPayloadBytes);
    readHeader(
      reader,
      manifest.layout.resultMagic,
      manifest.layout.version,
      codec.wireTag,
      route.wireId,
    );
    if (route.serviceCompletionCodec === 'nullable-gpu-adapter-service-completion-v1') {
      const present = reader.u8();
      if (present !== 1 || event.resultKind !== 3) {
        throw new TypeError('Invalid nullable adapter result');
      }
      const objectId = positiveIdentity(reader.u64(), 'GPUAdapter.objectId');
      const objectGeneration = positiveIdentity(
        reader.u64(),
        'GPUAdapter.objectGeneration',
      );
      const providerGeneration = positiveIdentity(
        reader.u64(),
        'GPUAdapter.providerGeneration',
      );
      if (providerGeneration !== event.operationProviderGeneration) {
        throw new TypeError('GPUAdapter result provider provenance mismatch');
      }
      reader.done();
      return Object.freeze({
        kind: 'object',
        object: Object.freeze({
          kind: 'GPUAdapter',
          objectId,
          objectGeneration,
          providerGeneration,
        }),
      });
    }
    if (route.serviceCompletionCodec === 'gpu-device-service-completion-v1') {
      if (event.resultKind !== 3) throw new TypeError('GPUDevice result kind mismatch');
      const objectId = positiveIdentity(reader.u64(), 'GPUDevice.objectId');
      const objectGeneration = positiveIdentity(
        reader.u64(),
        'GPUDevice.objectGeneration',
      );
      const logicalDeviceId = positiveIdentity(
        reader.u64(),
        'GPUDevice.logicalDeviceId',
      );
      const logicalDeviceGeneration = positiveIdentity(
        reader.u64(),
        'GPUDevice.logicalDeviceGeneration',
      );
      const providerGeneration = positiveIdentity(
        reader.u64(),
        'GPUDevice.providerGeneration',
      );
      if (
        logicalDeviceId !== event.logicalDeviceId ||
        logicalDeviceGeneration !== event.logicalDeviceGeneration ||
        providerGeneration !== event.providerGeneration
      ) {
        throw new TypeError('GPUDevice result provenance mismatch');
      }
      const queueObjectId = positiveIdentity(reader.u64(), 'GPUQueue.objectId');
      const queueObjectGeneration = positiveIdentity(
        reader.u64(),
        'GPUQueue.objectGeneration',
      );
      const featureCount = reader.u32();
      if (featureCount > manifest.layout.sequenceMaxCount) {
        throw new TypeError('GPUDevice feature sequence exceeds the reviewed bound');
      }
      const features: string[] = [];
      for (let index = 0; index < featureCount; index += 1) {
        const feature = reader.string(manifest.maxPayloadBytes);
        if (index > 0 && feature <= features[index - 1]) {
          throw new TypeError('GPUDevice features are not sorted and unique');
        }
        features.push(feature);
      }
      const limits: Record<string, number> = {};
      for (const name of manifest.completeLimitNames) {
        const decimal = reader.u64();
        const value = Number(decimal);
        if (!Number.isSafeInteger(value)) {
          throw new TypeError(`GPUDevice limit ${name} is not JS-safe`);
        }
        limits[name] = value;
      }
      const message = reader.string(manifest.layout.diagnosticMaxBytes);
      reader.done();
      const carrier = event as DetachedOperationResultEvent;
      if (typeof carrier.detachedAlreadyLost !== 'boolean') {
        throw new TypeError('GPUDevice result lacks authenticated detached state');
      }
      let alreadyLost: Readonly<{ reason: 'unknown'; message: string }> | undefined;
      if (carrier.detachedAlreadyLost) {
        if (carrier.lossReason !== 1 || carrier.backendClass !== 0) {
          throw new TypeError('GPUDevice detached result has invalid authenticated loss fields');
        }
        alreadyLost = Object.freeze({ reason: 'unknown', message });
      } else if (
        carrier.lossReason !== undefined ||
        carrier.backendClass !== undefined ||
        message !== ''
      ) {
        throw new TypeError('Live GPUDevice result carries detached-only diagnostics');
      }
      return Object.freeze({
        kind: 'object',
        object: Object.freeze({
          kind: 'GPUDevice',
          objectId,
          objectGeneration,
          logicalDeviceId,
          logicalDeviceGeneration,
          providerGeneration,
          features: Object.freeze(features),
          limits: Object.freeze(limits),
          queue: Object.freeze({
            objectId: queueObjectId,
            objectGeneration: queueObjectGeneration,
          }),
          alreadyLost,
        }),
      });
    }
    if (route.serviceCompletionCodec === 'nullable-gpu-error-service-completion-v1') {
      const present = reader.u8();
      if (present !== 1 || event.resultKind !== 4) {
        throw new TypeError('Invalid nullable GPUError result');
      }
      const errorKind = reader.u8();
      const message = reader.string(manifest.layout.diagnosticMaxBytes);
      reader.done();
      return Object.freeze({ kind: 'value', value: makeGpuError(errorKind, message) });
    }
    throw new TypeError(
      `${operationId} does not have a Promise-bearing service result codec`,
    );
  };

  const decodeDeviceLoss = (
    event: Extract<NativeGpuEventV2, { kind: 3 | 4 | 5 | 6 }>,
  ): Readonly<{ reason: 'destroyed' | 'unknown'; message: string }> => {
    const reader = new Reader(event.payload, manifest.maxPayloadBytes);
    if (reader.ascii4() !== manifest.layout.lossMagic) {
      throw new TypeError('Unknown WebGPU device-loss payload magic');
    }
    if (reader.u16() !== manifest.layout.version || reader.u16() !== 0) {
      throw new TypeError('Unknown WebGPU device-loss codec version');
    }
    const message = reader.string(manifest.layout.diagnosticMaxBytes);
    reader.done();
    if (event.kind === 3 || event.kind === 4) {
      if (!Number.isInteger(event.backendClass) || event.backendClass < 0 || event.backendClass > 5) {
        throw new TypeError('Unknown authenticated WebGPU backend class');
      }
      if (![1, 2, 3, 4, 5].includes(event.lossReason)) {
        throw new TypeError('Unknown authenticated WebGPU device-loss reason');
      }
      return Object.freeze({
        reason: event.lossReason === 2 ? 'destroyed' : 'unknown',
        message,
      });
    }
    return Object.freeze({ reason: 'unknown', message });
  };

  const inspectServiceRequest = (payload: ArrayBufferView): unknown => {
    const reader = new Reader(payload, manifest.maxPayloadBytes);
    if (reader.ascii4() !== manifest.layout.requestMagic) {
      throw new TypeError('Unknown WebGPU request payload magic');
    }
    if (reader.u16() !== manifest.layout.version) {
      throw new TypeError('Unknown WebGPU request codec version');
    }
    const codecTag = reader.u16();
    const codec = manifest.serviceArguments.find((row) => row.wireTag === codecTag);
    if (!codec) throw new TypeError(`Unknown WebGPU service request tag: ${codecTag}`);
    const wireId = reader.u32();
    const route = WEBGPU_PRODUCTION_PLAN.routes.find((row) => row.wireId === wireId);
    if (!route || route.serviceArgumentCodec !== codec.tag) {
      throw new TypeError('WebGPU request operation/codec mismatch');
    }
    const receiver = readReference(reader, objectKindsByTag);
    const targetPresence = reader.u8();
    if (targetPresence !== 0 && targetPresence !== 1) {
      throw new TypeError('Invalid WebGPU target presence tag');
    }
    const target = targetPresence === 1
      ? readReference(reader, objectKindsByTag)
      : null;
    const result = frozenRecord({
      operationId: route.operationId,
      codec: codec.tag,
      receiver,
      target,
      capturedScopeId: reader.u64(),
      adapterOrdinal: reader.u64(),
      deviceIngressOrdinal: reader.u64(),
      queueIngressOrdinal: reader.u64(),
      sealedLocalTimeline: reader.value(manifest.layout),
      convertedArguments: reader.value(manifest.layout),
    });
    reader.done();
    return result;
  };

  const encodeServiceResult = (
    operationId: string,
    result: WebGpuCodecTestServiceResult,
  ): Uint8Array => {
    const route = selectedRoute(operationId);
    const codec = completionCodecs.get(route.serviceCompletionCodec);
    if (!codec) throw new TypeError('Unknown WebGPU service completion codec');
    if (
      result.kind === 'null' &&
      (route.serviceCompletionCodec ===
        'nullable-gpu-adapter-service-completion-v1' ||
        route.serviceCompletionCodec ===
          'nullable-gpu-error-service-completion-v1')
    ) {
      return new Uint8Array(0);
    }
    const writer = new Writer(manifest.maxPayloadBytes);
    writeHeader(
      writer,
      manifest.layout.resultMagic,
      manifest.layout.version,
      codec.wireTag,
      route.wireId,
    );
    if (route.serviceCompletionCodec === 'nullable-gpu-adapter-service-completion-v1') {
      if (result.kind === 'adapter') {
        writer.u8(1);
        writer.u64(result.objectId);
        writer.u64(result.objectGeneration);
        writer.u64(result.providerGeneration);
      } else {
        throw new TypeError('Adapter completion test value has the wrong shape');
      }
      return writer.finish();
    }
    if (route.serviceCompletionCodec === 'gpu-device-service-completion-v1') {
      if (result.kind !== 'device') {
        throw new TypeError('Device completion test value has the wrong shape');
      }
      writer.u64(result.objectId);
      writer.u64(result.objectGeneration);
      writer.u64(result.logicalDeviceId);
      writer.u64(result.logicalDeviceGeneration);
      writer.u64(result.providerGeneration);
      writer.u64(result.queueObjectId);
      writer.u64(result.queueObjectGeneration);
      const features = [...result.features];
      if (
        features.length > manifest.layout.sequenceMaxCount ||
        features.some((feature, index) => index > 0 && feature <= features[index - 1])
      ) {
        throw new TypeError('Device completion features must be sorted and unique');
      }
      writer.u32(features.length);
      for (const feature of features) writer.string(feature);
      for (const name of manifest.completeLimitNames) {
        if (!Object.prototype.hasOwnProperty.call(result.limits, name)) {
          throw new TypeError(`Device completion omits required limit: ${name}`);
        }
        writer.u64(String(u64Number(result.limits[name], `GPUDevice limit ${name}`)));
      }
      writer.string(
        result.diagnosticMessage ?? '',
        manifest.layout.diagnosticMaxBytes,
      );
      return writer.finish();
    }
    if (route.serviceCompletionCodec === 'nullable-gpu-error-service-completion-v1') {
      if (result.kind === 'error') {
        writer.u8(1);
        writer.u8(result.errorKind);
        writer.string(result.message, manifest.layout.diagnosticMaxBytes);
      } else {
        throw new TypeError('GPUError completion test value has the wrong shape');
      }
      return writer.finish();
    }
    throw new TypeError(`${operationId} has no decodable service result`);
  };

  const encodeDeviceLoss = (message: string): Uint8Array => {
    const writer = new Writer(manifest.maxPayloadBytes);
    writer.ascii4(manifest.layout.lossMagic);
    writer.u16(manifest.layout.version);
    writer.u16(0);
    writer.string(message, manifest.layout.diagnosticMaxBytes);
    return writer.finish();
  };

  const encodeCanonicalValue = (value: unknown): Uint8Array => {
    const writer = new Writer(manifest.maxPayloadBytes);
    writer.value(value, manifest.layout);
    return writer.finish();
  };

  const bundle: ExecutableWebGpuCodecBundle = Object.freeze({
    schema: 'ibex/webgpu-executable-codecs/1',
    operationSetDigest: manifest.digests.operationSet,
    semanticProgramDigest: manifest.digests.semanticProgramSet,
    runtimeRoutingDigest: manifest.digests.runtimeRouting,
    webgpuCVocabularyDigest: manifest.digests.webgpuCVocabulary,
    operationIds: Object.freeze(manifest.operationIds.slice()),
    convertPublicArguments,
    encodeServiceRequest,
    decodeServiceResult,
    decodeDeviceLoss,
  });

  return Object.freeze({
    bundle,
    testSupport: Object.freeze({
      inspectServiceRequest,
      encodeServiceResult,
      encodeDeviceLoss,
      encodeCanonicalValue,
    }),
  });
}
